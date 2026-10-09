import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.environ.get("STORE_DATABASE", str(BASE_DIR / "store.sqlite3")))
HOST = os.environ.get("STORE_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", os.environ.get("STORE_PORT", "8000")))
COOKIE_NAME = "commonplace_session"
SESSION_SECONDS = 7 * 24 * 60 * 60
EMAIL_VERIFICATION_SECONDS = 24 * 60 * 60
PASSWORD_RESET_SECONDS = 60 * 60
PBKDF2_ITERATIONS = 310000
MAX_REQUEST_BYTES = 4096
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 5
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s.]+(?:\.[^@\s.]+)+$")
RATE_LIMIT_BUCKETS = defaultdict(list)
RATE_LIMIT_LOCK = threading.Lock()


def connect_database():
    connection = sqlite3.connect(str(DATABASE_PATH), timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect_database() as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email_verified INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            )"""
        )
        user_columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
        if "email_verified" not in user_columns:
            connection.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS email_verification_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS password_reset_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at)")


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS,
        salt.hex(),
        digest.hex(),
    )


def verify_password(password, encoded):
    try:
        algorithm, iterations, salt_hex, digest_hex = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(actual.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def token_digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


class StoreHandler(BaseHTTPRequestHandler):
    server_version = "CommonplaceStore/1.0"

    def send_json(self, status, payload, extra_headers=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra_headers:
            for name, value in extra_headers:
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status, message):
        self.send_json(status, {"error": message})

    def read_json(self):
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Send this request as JSON.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid request size.")
        if length < 1 or length > MAX_REQUEST_BYTES:
            raise ValueError("Request is empty or too large.")
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Invalid JSON request.")
        if not isinstance(data, dict):
            raise ValueError("Invalid JSON request.")
        return data

    def check_same_origin(self):
        origin = self.headers.get("Origin")
        if origin:
            parsed = urlsplit(origin)
            forwarded_proto = self.headers.get("X-Forwarded-Proto", "http").split(",")[0].strip()
            if parsed.netloc != self.headers.get("Host") or parsed.scheme != forwarded_proto:
                self.send_error_json(403, "Request origin was not accepted.")
                return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            self.send_error_json(403, "Cross-site requests are not accepted.")
            return False
        return True

    def client_ip(self):
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.address_string()

    def check_rate_limit(self):
        if self.path not in ("/api/login", "/api/register"):
            return True
        now = time.time()
        client = self.client_ip()
        with RATE_LIMIT_LOCK:
            bucket = RATE_LIMIT_BUCKETS[client]
            bucket[:] = [stamp for stamp in bucket if now - stamp < RATE_LIMIT_WINDOW_SECONDS]
            if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
                self.send_error_json(429, "Too many requests. Please wait a moment and try again.")
                return False
            bucket.append(now)
        return True

    def session_token(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return None
        morsel = cookie.get(COOKIE_NAME)
        return morsel.value if morsel else None

    def current_user(self):
        token = self.session_token()
        if not token:
            return None
        with connect_database() as connection:
            row = connection.execute(
                """SELECT users.id, users.name, users.email, users.email_verified
                   FROM sessions JOIN users ON users.id = sessions.user_id
                   WHERE sessions.token_hash = ? AND sessions.expires_at > ?""",
                (token_digest(token), int(time.time())),
            ).fetchone()
        return dict(row) if row else None

    def create_token_record(self, table_name, user_id, lifetime_seconds):
        token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + lifetime_seconds
        with connect_database() as connection:
            connection.execute(
                f"INSERT INTO {table_name}(token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_digest(token), user_id, expires_at),
            )
        return token

    def create_session(self, user_id):
        token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + SESSION_SECONDS
        with connect_database() as connection:
            connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))
            connection.execute(
                "INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_digest(token), user_id, expires_at),
            )
        secure = "; Secure" if os.environ.get("COOKIE_SECURE", "0") == "1" else ""
        cookie = "{}={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax{}".format(
            COOKIE_NAME, token, SESSION_SECONDS, secure
        )
        return [("Set-Cookie", cookie)]

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/health":
            self.send_json(200, {"ok": True})
            return
        if path == "/api/me":
            user = self.current_user()
            if user:
                self.send_json(200, {"user": user})
            else:
                self.send_json(200, {"user": None})
            return
        if path in ("/", "/index.html"):
            try:
                page = (BASE_DIR / "index.html").read_bytes()
            except OSError:
                self.send_error_json(500, "The storefront page could not be loaded.")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(page)
            return
        self.send_error_json(404, "Not found.")

    def do_POST(self):
        path = urlsplit(self.path).path
        allowed_paths = (
            "/api/register",
            "/api/login",
            "/api/logout",
            "/api/verify-email",
            "/api/request-password-reset",
            "/api/reset-password",
            "/api/resend-verification",
        )
        if path not in allowed_paths:
            self.send_error_json(404, "Not found.")
            return
        if not self.check_rate_limit():
            return
        if not self.check_same_origin():
            return
        try:
            data = self.read_json()
        except ValueError as error:
            self.send_error_json(400, str(error))
            return

        if path == "/api/register":
            self.register(data)
        elif path == "/api/login":
            self.login(data)
        elif path == "/api/verify-email":
            self.verify_email(data)
        elif path == "/api/request-password-reset":
            self.request_password_reset(data)
        elif path == "/api/reset-password":
            self.reset_password(data)
        elif path == "/api/resend-verification":
            self.resend_verification(data)
        else:
            self.logout()

    def register(self, data):
        name = data.get("name", "")
        email = data.get("email", "")
        password = data.get("password", "")
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80:
            self.send_error_json(400, "Enter your name (up to 80 characters).")
            return
        if not isinstance(email, str) or len(email) > 254 or not EMAIL_PATTERN.fullmatch(email.strip()):
            self.send_error_json(400, "Enter a valid email address.")
            return
        if not isinstance(password, str) or len(password) < 10 or len(password) > 128:
            self.send_error_json(400, "Your password must be between 10 and 128 characters.")
            return
        normalized_email = email.strip().lower()
        try:
            with connect_database() as connection:
                cursor = connection.execute(
                    "INSERT INTO users(name, email, password_hash, email_verified, created_at) VALUES (?, ?, ?, ?, ?)",
                    (name.strip(), normalized_email, hash_password(password), 0, int(time.time())),
                )
                user_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            self.send_error_json(409, "An account with that email already exists. Try signing in.")
            return
        verification_token = self.create_token_record("email_verification_tokens", user_id, EMAIL_VERIFICATION_SECONDS)
        headers = self.create_session(user_id)
        self.send_json(
            201,
            {
                "user": {"id": user_id, "name": name.strip(), "email": normalized_email, "email_verified": 0},
                "verification_required": True,
                "verification_token": verification_token,
            },
            headers,
        )

    def verify_email(self, data):
        token = data.get("token", "")
        if not isinstance(token, str) or not token:
            self.send_error_json(400, "Verification token is required.")
            return
        token_hash = token_digest(token)
        with connect_database() as connection:
            row = connection.execute(
                "SELECT user_id, expires_at FROM email_verification_tokens WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if not row:
                self.send_error_json(400, "Your verification link is invalid or has expired.")
                return
            if row["expires_at"] <= int(time.time()):
                connection.execute("DELETE FROM email_verification_tokens WHERE token_hash = ?", (token_hash,))
                self.send_error_json(400, "Your verification link has expired.")
                return
            connection.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (row["user_id"],))
            connection.execute("DELETE FROM email_verification_tokens WHERE token_hash = ?", (token_hash,))
        self.send_json(200, {"ok": True, "email_verified": True})

    def resend_verification(self, data):
        user = self.current_user()
        if not user:
            self.send_error_json(401, "You are not signed in.")
            return
        with connect_database() as connection:
            existing = connection.execute(
                "SELECT id FROM users WHERE id = ? AND email_verified = 0",
                (user["id"],),
            ).fetchone()
            if not existing:
                self.send_json(200, {"ok": True, "email_verified": True})
                return
        token = self.create_token_record("email_verification_tokens", user["id"], EMAIL_VERIFICATION_SECONDS)
        self.send_json(200, {"ok": True, "verification_token": token, "verification_required": True})

    def request_password_reset(self, data):
        email = data.get("email", "")
        if not isinstance(email, str) or len(email) > 254 or not EMAIL_PATTERN.fullmatch(email.strip()):
            self.send_error_json(400, "Enter a valid email address.")
            return
        normalized_email = email.strip().lower()
        with connect_database() as connection:
            user = connection.execute("SELECT id FROM users WHERE email = ?", (normalized_email,)).fetchone()
            if not user:
                self.send_json(200, {"ok": True})
                return
        token = self.create_token_record("password_reset_tokens", user["id"], PASSWORD_RESET_SECONDS)
        self.send_json(200, {"ok": True, "reset_token": token})

    def reset_password(self, data):
        token = data.get("token", "")
        password = data.get("password", "")
        if not isinstance(token, str) or not token:
            self.send_error_json(400, "Reset token is required.")
            return
        if not isinstance(password, str) or len(password) < 10 or len(password) > 128:
            self.send_error_json(400, "Your password must be between 10 and 128 characters.")
            return
        token_hash = token_digest(token)
        with connect_database() as connection:
            row = connection.execute(
                "SELECT user_id, expires_at FROM password_reset_tokens WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if not row:
                self.send_error_json(400, "Your reset link is invalid or has expired.")
                return
            if row["expires_at"] <= int(time.time()):
                connection.execute("DELETE FROM password_reset_tokens WHERE token_hash = ?", (token_hash,))
                self.send_error_json(400, "Your reset link has expired.")
                return
            connection.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(password), row["user_id"]),
            )
            connection.execute("DELETE FROM password_reset_tokens WHERE token_hash = ?", (token_hash,))
        self.send_json(200, {"ok": True})

    def login(self, data):
        email = data.get("email", "")
        password = data.get("password", "")
        if not isinstance(email, str) or len(email) > 254 or not isinstance(password, str) or len(password) > 128:
            self.send_error_json(400, "Enter your email and password.")
            return
        normalized_email = email.strip().lower()
        with connect_database() as connection:
            user = connection.execute(
                "SELECT id, name, email, email_verified, password_hash FROM users WHERE email = ?",
                (normalized_email,),
            ).fetchone()
        if not user:
            hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), b"commonplace-dummy-salt", PBKDF2_ITERATIONS)
            self.send_error_json(401, "Email or password is incorrect.")
            return
        if not verify_password(password, user["password_hash"]):
            self.send_error_json(401, "Email or password is incorrect.")
            return
        headers = self.create_session(user["id"])
        self.send_json(
            200,
            {"user": {"id": user["id"], "name": user["name"], "email": user["email"], "email_verified": user["email_verified"]}},
            headers,
        )

    def logout(self):
        token = self.session_token()
        if token:
            with connect_database() as connection:
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_digest(token),))
        expired_cookie = "{}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{}".format(
            COOKIE_NAME,
            "; Secure" if os.environ.get("COOKIE_SECURE", "0") == "1" else "",
        )
        self.send_json(200, {"ok": True}, [("Set-Cookie", expired_cookie)])

    def log_message(self, format_string, *args):
        print("{} - {}".format(self.address_string(), format_string % args))


def main():
    initialize_database()
    server = ThreadingHTTPServer((HOST, PORT), StoreHandler)
    server.daemon_threads = True
    print("Commonplace Books running at http://{}:{}/".format(HOST, PORT))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping bookstore server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
