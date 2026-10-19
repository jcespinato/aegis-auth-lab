import hashlib
import math
import os
import re
import secrets
import time
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, Response, flash, g, make_response, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
SECRET_KEY = os.environ.get("SECRET_KEY", "").strip()
ADMIN_USERNAMES = {
    item.strip().lower()
    for item in os.environ.get("ADMIN_USERNAMES", "").split(",")
    if item.strip()
}


def env_int(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


LOGIN_MAX_FAILURES = env_int("LOGIN_MAX_FAILURES", 5, 3, 20)
LOGIN_WINDOW_SECONDS = env_int("LOGIN_WINDOW_SECONDS", 300, 30, 3600)
LOGIN_LOCK_SECONDS = env_int("LOGIN_LOCK_SECONDS", 60, 15, 1800)

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

if not DATABASE_URL:
    DATABASE_URL = "sqlite:///" + os.path.join(BASE_DIR, "authlab.db")

if DATABASE_URL.startswith("postgresql+") and not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is required when using PostgreSQL.")

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(
    SECRET_KEY=SECRET_KEY or secrets.token_hex(32),
    SQLALCHEMY_DATABASE_URI=DATABASE_URL,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
    SESSION_COOKIE_NAME="aegis_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=DATABASE_URL.startswith("postgresql+"),
    MAX_CONTENT_LENGTH=32 * 1024,
)

db = SQLAlchemy(app)
USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,32}$")


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False)


class AuthEvent(db.Model):
    __tablename__ = "auth_events"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), nullable=True, index=True)
    success = db.Column(db.Boolean, nullable=False, index=True)
    source_id = db.Column(db.String(16), nullable=False, index=True)
    user_agent = db.Column(db.String(255), nullable=True)
    occurred_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)


class AuditRun(db.Model):
    __tablename__ = "audit_runs"

    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(120), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    grade = db.Column(db.String(24), nullable=False)
    findings = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)


class LoginThrottle(db.Model):
    __tablename__ = "login_throttles"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), nullable=False, index=True)
    source_id = db.Column(db.String(16), nullable=False, index=True)
    failure_count = db.Column(db.Integer, nullable=False, default=0)
    window_started_at = db.Column(db.Float, nullable=False)
    locked_until = db.Column(db.Float, nullable=True, index=True)
    updated_at = db.Column(db.Float, nullable=False)
    __table_args__ = (db.UniqueConstraint("username", "source_id", name="uq_login_throttle_username_source"),)


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(32), nullable=False, index=True)
    username = db.Column(db.String(32), nullable=True, index=True)
    source_id = db.Column(db.String(16), nullable=False, index=True)
    detail = db.Column(db.JSON, nullable=False)
    occurred_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)


def utc_now():
    return datetime.now(timezone.utc)


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


def source_identifier():
    ip = request.remote_addr or "unknown"
    salt = app.config["SECRET_KEY"]
    digest = hashlib.sha256(f"{salt}:{ip}".encode("utf-8")).hexdigest()
    return digest[:16]


def log_auth_event(username, success):
    event = AuthEvent(
        username=username[:32] if username else None,
        success=bool(success),
        source_id=source_identifier(),
        user_agent=(request.headers.get("User-Agent", "") or "")[:255],
        occurred_at=utc_now(),
    )
    db.session.add(event)
    db.session.commit()


def log_security_event(kind, username, source_id, detail):
    event = SecurityEvent(
        kind=kind[:32],
        username=username[:32] if username else None,
        source_id=source_id,
        detail=detail,
        occurred_at=utc_now(),
    )
    db.session.add(event)
    db.session.commit()


def get_throttle(username, source_id, lock_row=False):
    statement = select(LoginThrottle).where(
        LoginThrottle.username == username,
        LoginThrottle.source_id == source_id,
    )
    if lock_row and DATABASE_URL.startswith("postgresql+"):
        statement = statement.with_for_update()
    return db.session.execute(statement).scalar_one_or_none()


def normalize_throttle(throttle, now):
    if throttle is None:
        return None
    if throttle.locked_until and throttle.locked_until <= now:
        throttle.failure_count = 0
        throttle.window_started_at = now
        throttle.locked_until = None
        throttle.updated_at = now
        db.session.commit()
    elif now - throttle.window_started_at > LOGIN_WINDOW_SECONDS:
        throttle.failure_count = 0
        throttle.window_started_at = now
        throttle.locked_until = None
        throttle.updated_at = now
        db.session.commit()
    return throttle


def current_lock(username, source_id):
    now = time.time()
    throttle = normalize_throttle(get_throttle(username, source_id), now)
    if throttle and throttle.locked_until and throttle.locked_until > now:
        return throttle, max(1, math.ceil(throttle.locked_until - now))
    return throttle, 0


def register_failure(username, source_id):
    now = time.time()
    throttle = normalize_throttle(get_throttle(username, source_id, lock_row=True), now)
    if throttle is None:
        throttle = LoginThrottle(
            username=username,
            source_id=source_id,
            failure_count=0,
            window_started_at=now,
            locked_until=None,
            updated_at=now,
        )
        db.session.add(throttle)
        try:
            db.session.flush()
        except IntegrityError:
            db.session.rollback()
            throttle = normalize_throttle(get_throttle(username, source_id, lock_row=True), now)
    throttle.failure_count += 1
    throttle.updated_at = now
    locked = throttle.failure_count >= LOGIN_MAX_FAILURES
    retry_after = 0
    if locked:
        throttle.locked_until = now + LOGIN_LOCK_SECONDS
        retry_after = LOGIN_LOCK_SECONDS
    db.session.commit()
    return throttle.failure_count, locked, retry_after


def clear_throttle(username, source_id):
    throttle = get_throttle(username, source_id, lock_row=True)
    if throttle:
        db.session.delete(throttle)
        db.session.commit()


def rate_limit_response(username, source_id, retry_after):
    log_auth_event(username, False)
    log_security_event(
        "RATE_LIMITED",
        username,
        source_id,
        {"retry_after": retry_after, "limit": LOGIN_MAX_FAILURES, "window": LOGIN_WINDOW_SECONDS},
    )
    flash("Muitas tentativas consecutivas. Aguarde antes de tentar novamente.", "error")
    response = make_response(render_template("login.html"), 429)
    response.headers["Retry-After"] = str(retry_after)
    response.headers["X-RateLimit-Limit"] = str(LOGIN_MAX_FAILURES)
    response.headers["X-RateLimit-Remaining"] = "0"
    return response


def is_admin_user():
    return bool(g.user and g.user.username in ADMIN_USERNAMES)


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        if not is_admin_user():
            return Response("Forbidden", status=403)
        return view(*args, **kwargs)

    return wrapped_view


def build_auth_assessment():
    checks = [
        {"key": "https", "label": "HTTPS ativo", "passed": bool(request.is_secure), "weight": 12, "category": "Transporte"},
        {"key": "password_hash", "label": "Senhas armazenadas com hash", "passed": True, "weight": 18, "category": "Credenciais"},
        {"key": "cookie_secure", "label": "Cookie Secure", "passed": bool(app.config["SESSION_COOKIE_SECURE"]), "weight": 10, "category": "Sessão"},
        {"key": "cookie_httponly", "label": "Cookie HttpOnly", "passed": bool(app.config["SESSION_COOKIE_HTTPONLY"]), "weight": 8, "category": "Sessão"},
        {"key": "cookie_samesite", "label": "Cookie SameSite", "passed": app.config["SESSION_COOKIE_SAMESITE"] in {"Lax", "Strict"}, "weight": 6, "category": "Sessão"},
        {"key": "csrf", "label": "Proteção CSRF", "passed": True, "weight": 10, "category": "Requisições"},
        {"key": "generic_error", "label": "Mensagem genérica de autenticação", "passed": True, "weight": 6, "category": "Autenticação"},
        {"key": "event_logging", "label": "Registro de eventos de autenticação", "passed": True, "weight": 8, "category": "Monitoramento"},
        {"key": "source_id", "label": "Origem pseudonimizada", "passed": True, "weight": 5, "category": "Privacidade"},
        {"key": "rate_limit", "label": "Limitação de tentativas", "passed": True, "weight": 8, "category": "Resiliência"},
        {"key": "temporary_lock", "label": "Bloqueio temporário", "passed": True, "weight": 5, "category": "Resiliência"},
        {"key": "mfa", "label": "Autenticação multifator", "passed": False, "weight": 4, "category": "Autenticação"},
    ]
    score = sum(item["weight"] for item in checks if item["passed"])
    if score >= 90:
        grade = "Excelente"
    elif score >= 75:
        grade = "Bom"
    elif score >= 60:
        grade = "Moderado"
    else:
        grade = "Crítico"
    return score, grade, checks


@app.before_request
def load_logged_in_user():
    g.user = None
    g.is_admin = False
    user_id = session.get("user_id")
    if user_id:
        g.user = db.session.get(User, user_id)
        if g.user is None:
            session.clear()
        else:
            g.is_admin = is_admin_user()


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"
    return response


@app.template_filter("event_time")
def event_time(value):
    if not value:
        return ""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /\n", mimetype="text/plain")


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
        if len(name) < 2 or len(name) > 80:
            error = "Informe um nome entre 2 e 80 caracteres."
        elif not USERNAME_RE.fullmatch(username):
            error = "Use de 3 a 32 caracteres: letras minúsculas, números, ponto, hífen ou sublinhado."
        elif len(password) < 8 or len(password) > 128:
            error = "A senha deve ter entre 8 e 128 caracteres."

        if error is None:
            user = User(
                name=name,
                username=username,
                password_hash=generate_password_hash(password),
                created_at=utc_now(),
            )
            db.session.add(user)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
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

        username = request.form.get("username", "").strip().lower()[:32]
        password = request.form.get("password", "")
        source_id = source_identifier()
        _, retry_after = current_lock(username, source_id)

        if retry_after:
            return rate_limit_response(username, source_id, retry_after)

        user = None
        if USERNAME_RE.fullmatch(username) and 1 <= len(password) <= 128:
            user = db.session.execute(select(User).where(User.username == username)).scalar_one_or_none()

        success = bool(user and check_password_hash(user.password_hash, password))

        if success:
            log_auth_event(username, True)
            clear_throttle(username, source_id)
            session.clear()
            session["user_id"] = user.id
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))

        log_auth_event(username, False)
        failures, locked, retry_after = register_failure(username, source_id)
        if locked:
            detail = {"failures": failures, "retry_after": retry_after, "window": LOGIN_WINDOW_SECONDS}
            log_security_event("LOCK_STARTED", username, source_id, detail)
            log_security_event("RATE_LIMITED", username, source_id, detail)
            flash("Muitas tentativas consecutivas. O acesso foi temporariamente limitado.", "error")
            response = make_response(render_template("login.html"), 429)
            response.headers["Retry-After"] = str(retry_after)
            response.headers["X-RateLimit-Limit"] = str(LOGIN_MAX_FAILURES)
            response.headers["X-RateLimit-Remaining"] = "0"
            return response

        flash("Usuário ou senha inválidos.", "error")
        response = make_response(render_template("login.html"), 401)
        response.headers["X-RateLimit-Limit"] = str(LOGIN_MAX_FAILURES)
        response.headers["X-RateLimit-Remaining"] = str(max(0, LOGIN_MAX_FAILURES - failures))
        return response

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    events = db.session.execute(
        select(AuthEvent)
        .where(AuthEvent.username == g.user.username)
        .order_by(AuthEvent.id.desc())
        .limit(8)
    ).scalars().all()

    attempts = db.session.query(AuthEvent).filter_by(username=g.user.username).count()
    failures = db.session.query(AuthEvent).filter_by(username=g.user.username, success=False).count()

    return render_template("dashboard.html", events=events, attempts=attempts, failures=failures)


@app.route("/admin")
@admin_required
def admin_dashboard():
    total_events = db.session.query(func.count(AuthEvent.id)).scalar() or 0
    successes = db.session.query(func.count(AuthEvent.id)).filter(AuthEvent.success.is_(True)).scalar() or 0
    failures = total_events - successes
    unique_sources = db.session.query(func.count(func.distinct(AuthEvent.source_id))).scalar() or 0
    success_rate = round((successes / total_events) * 100, 1) if total_events else 0.0
    blocked_events = db.session.query(func.count(SecurityEvent.id)).filter(SecurityEvent.kind == "RATE_LIMITED").scalar() or 0
    lock_events = db.session.query(func.count(SecurityEvent.id)).filter(SecurityEvent.kind == "LOCK_STARTED").scalar() or 0
    active_locks = db.session.query(func.count(LoginThrottle.id)).filter(LoginThrottle.locked_until > time.time()).scalar() or 0
    events = db.session.execute(select(AuthEvent).order_by(AuthEvent.id.desc()).limit(40)).scalars().all()
    security_events = db.session.execute(select(SecurityEvent).order_by(SecurityEvent.id.desc()).limit(20)).scalars().all()
    latest_audit = db.session.execute(select(AuditRun).order_by(AuditRun.id.desc()).limit(1)).scalar_one_or_none()
    audit_history = db.session.execute(select(AuditRun).order_by(AuditRun.id.desc()).limit(8)).scalars().all()

    return render_template(
        "admin.html",
        total_events=total_events,
        successes=successes,
        failures=failures,
        unique_sources=unique_sources,
        success_rate=success_rate,
        blocked_events=blocked_events,
        lock_events=lock_events,
        active_locks=active_locks,
        events=events,
        security_events=security_events,
        latest_audit=latest_audit,
        audit_history=audit_history,
        rate_limit_max=LOGIN_MAX_FAILURES,
        rate_limit_window=LOGIN_WINDOW_SECONDS,
        rate_limit_lock=LOGIN_LOCK_SECONDS,
    )


@app.route("/admin/audit/run", methods=("POST",))
@admin_required
def run_audit():
    if not validate_csrf():
        flash("Sessão expirada.", "error")
        return redirect(url_for("admin_dashboard"))

    score, grade, findings = build_auth_assessment()
    audit = AuditRun(
        target="Aegis Auth Lab",
        score=score,
        grade=grade,
        findings=findings,
        created_at=utc_now(),
    )
    db.session.add(audit)
    db.session.commit()
    flash("Avaliação concluída.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/logout", methods=("POST",))
@login_required
def logout():
    if not validate_csrf():
        flash("Sessão expirada.", "error")
        return redirect(url_for("dashboard"))
    session.clear()
    return redirect(url_for("index"))


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
