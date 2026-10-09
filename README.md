# Commonplace Books

A static storefront with a small Python account API. The account backend uses only the Python standard library and stores users and sessions in SQLite.

## Run locally

Python 3.7 or newer is required for local development. From this folder, run:

```powershell
py -3.7-32 server.py
```

This command selects the working 32-bit Python 3.7 installation in this workspace. On another machine, replace `-3.7-32` with an installed Python launcher target (for example, `-3.11`). Then open <http://127.0.0.1:8000/>. The first run creates `store.sqlite3` in this folder. Set `STORE_HOST` and `STORE_PORT` to change the bind address and port, or `STORE_DATABASE` to choose a database path.

## Account API

- `POST /api/register` creates an account and signs it in. JSON fields: `name`, `email`, `password`.
- `POST /api/login` signs in. JSON fields: `email`, `password`.
- `POST /api/logout` signs out.
- `GET /api/me` returns the current session's account, or `null`.
- `GET /api/health` is a health check.

Passwords are hashed with PBKDF2-HMAC-SHA256. Session identifiers are random, stored hashed in SQLite, and sent only in HttpOnly, SameSite cookies. The cookie is marked Secure when `COOKIE_SECURE=1`.

## Before production

This built-in HTTP server is for local development and previews; do not expose it directly to the public internet. Deploy on a currently supported Python release (3.11 or newer), behind a production-grade HTTPS server/reverse proxy, and set `COOKIE_SECURE=1`. Add persistent backups, rate limiting, email verification, and password-reset flows before accepting public registrations. This account API does not process orders or payments.
