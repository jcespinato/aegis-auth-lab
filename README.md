# Aegis Auth Lab

Ambiente web controlado para validação de mecanismos de autenticação e contramedidas defensivas.

## Recursos

- Cadastro e autenticação com hash de senha
- Sessão protegida por cookies Secure, HttpOnly e SameSite
- Proteção CSRF
- Cabeçalhos HTTP de segurança e HSTS
- Registro de eventos de autenticação
- Pseudonimização da origem das requisições
- Rate limiting por combinação de conta e origem
- Bloqueio temporário após falhas consecutivas
- Resposta HTTP 429 com Retry-After
- Console administrativo com métricas, histórico e eventos de proteção
- PostgreSQL em produção e SQLite em ambiente local

## Stack

- Python
- Flask
- SQLAlchemy
- PostgreSQL
- Gunicorn
- HTML
- CSS

## Variáveis de ambiente

| Variável | Finalidade | Padrão |
|---|---|---|
| `DATABASE_URL` | Conexão PostgreSQL | SQLite local |
| `SECRET_KEY` | Proteção de sessão e pseudonimização | Gerada localmente |
| `ADMIN_USERNAMES` | Usuários com acesso ao console administrativo | vazio |
| `LOGIN_MAX_FAILURES` | Falhas permitidas antes do bloqueio | `5` |
| `LOGIN_WINDOW_SECONDS` | Janela de contagem das falhas | `300` |
| `LOGIN_LOCK_SECONDS` | Duração do bloqueio temporário | `60` |

## Execução

```bash
pip install -r requirements.txt
python app.py
```

Em produção, o processo pode ser iniciado com:

```bash
gunicorn app:app
```

## Escopo

O projeto foi desenvolvido para ambientes próprios ou formalmente autorizados. Os mecanismos de teste devem utilizar contas e credenciais sintéticas ou dedicadas ao laboratório.
