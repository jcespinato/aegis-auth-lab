import os
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "authlab.db")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS auth_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            success INTEGER NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            occurred_at TEXT NOT NULL
        );
        """
    )
    db.commit()
    db.close()


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


def validate_csrf():
    form_token = request.form.get("csrf_token", "")
    session_token = session.get("csrf_token", "")
    return bool(form_token and session_token and secrets.compare_digest(form_token, session_token))


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_auth_event(username, success):
    db = get_db()
    forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    ip = forwarded or request.remote_addr or "unknown"
    db.execute(
        """
        INSERT INTO auth_events (username, success, ip_address, user_agent, occurred_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (username, int(success), ip, request.headers.get("User-Agent", "")[:255], now_iso()),
    )
    db.commit()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


@app.before_request
def load_logged_in_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id:
        g.user = get_db().execute(
            "SELECT id, name, username, created_at FROM users WHERE id = ?", (user_id,)
        ).fetchone()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        if not validate_csrf():
            flash("Sessão expirada. Atualize a página e tente novamente.", "error")
            return redirect(url_for("register"))

        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        error = None
        if len(name) < 2:
            error = "Informe um nome com pelo menos 2 caracteres."
        elif len(username) < 3:
            error = "O usuário deve ter pelo menos 3 caracteres."
        elif len(password) < 8:
            error = "A senha deve ter pelo menos 8 caracteres."

        if error is None:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (name, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (name, username, generate_password_hash(password), now_iso()),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = "Esse usuário já existe."
            else:
                flash("Conta criada. Agora você pode entrar no ambiente.", "success")
                return redirect(url_for("login"))

        flash(error, "error")

    return render_template("register.html")


@app.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        if not validate_csrf():
            flash("Sessão expirada. Atualize a página e tente novamente.", "error")
            return redirect(url_for("login"))

        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        success = bool(user and check_password_hash(user["password_hash"], password))
        log_auth_event(username, success)

        if not success:
            flash("Usuário ou senha inválidos.", "error")
            return render_template("login.html"), 401

        session.clear()
        session["user_id"] = user["id"]
        session["csrf_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    events = db.execute(
        """
        SELECT success, ip_address, occurred_at
        FROM auth_events
        WHERE username = ?
        ORDER BY id DESC
        LIMIT 8
        """,
        (g.user["username"],),
    ).fetchall()

    attempts = db.execute(
        "SELECT COUNT(*) AS total FROM auth_events WHERE username = ?",
        (g.user["username"],),
    ).fetchone()["total"]
    failures = db.execute(
        "SELECT COUNT(*) AS total FROM auth_events WHERE username = ? AND success = 0",
        (g.user["username"],),
    ).fetchone()["total"]

    return render_template(
        "dashboard.html", events=events, attempts=attempts, failures=failures
    )


@app.route("/logout", methods=("POST",))
@login_required
def logout():
    if not validate_csrf():
        flash("Sessão expirada.", "error")
        return redirect(url_for("dashboard"))
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
