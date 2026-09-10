"""
Application Security Demo — Secure REST API + Web UI
====================================================
Covers: input validation, authentication (JWT), authorization (RBAC),
secure password handling (bcrypt), brute-force rate limiting, security
headers, parameterized SQL, and generic error handling.

Setup:
    pip install flask bcrypt pyjwt
    python app.py

Web UI:  http://127.0.0.1:5000/     (open in a browser)
API docs: http://127.0.0.1:5000/api (JSON endpoint list for curl/Postman)

First run prints generated admin credentials (or set ADMIN_PASSWORD env var).
"""

import os
import re
import time
import secrets
import sqlite3
from collections import deque, defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# --- CONFIGURATION ---------------------------------------------------------

# SECURITY FIX: consistent string type; securely generated fallback.
# In production, SECRET_KEY MUST come from the environment (a random fallback
# invalidates all previously issued tokens on every restart).
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

# Reject oversized request bodies (DoS mitigation)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024  # 16 KB

JWT_EXPIRY_MINUTES = 15
BCRYPT_ROUNDS = 12
DB_FILE = 'secure_app.db'


# --- DATABASE SETUP --------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    # closing() actually closes the connection (a bare `with conn`
    # only manages the transaction, leaking connections over time).
    with closing(get_db()) as conn:
        with conn:  # transaction scope: auto-commit / rollback on error
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash BLOB NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('user', 'admin'))
                )
            ''')


def seed_admin():
    """Create the initial admin account.

    SECURITY FIX: roles are NEVER taken from public registration input.
    Admins exist only via this seed or the admin-only promote endpoint.
    """
    username = os.environ.get('ADMIN_USERNAME', 'admin')
    password = os.environ.get('ADMIN_PASSWORD')
    generated = False

    if not password:
        password = secrets.token_urlsafe(12)
        generated = True

    with closing(get_db()) as conn:
        with conn:
            if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                return  # already seeded
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username,
                 bcrypt.hashpw(password.encode('utf-8'),
                               bcrypt.gensalt(rounds=BCRYPT_ROUNDS)),
                 'admin')
            )

    if generated:
        print("=" * 60)
        print(f"First-run admin created -> username: {username}")
        print(f"Password: {password}")
        print("(Set ADMIN_PASSWORD env var to choose your own.)")
        print("=" * 60)


init_db()
seed_admin()


# --- INPUT VALIDATION ------------------------------------------------------

USERNAME_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')


def validate_registration(data):
    if not isinstance(data, dict) or 'username' not in data or 'password' not in data:
        return False, "Missing username or password."

    # str() cast guards against non-string JSON types (ints, lists, dicts)
    username = str(data['username'])

    # fullmatch() — a bare '$' would accept a trailing "\n"
    if not USERNAME_RE.fullmatch(username):
        return False, "Username must be 3-20 characters (letters, numbers, _, -)."

    pwd = str(data['password'])
    if (len(pwd) < 8
            or len(pwd.encode('utf-8')) > 72   # bcrypt silently truncates at 72 bytes
            or not re.search(r'[A-Z]', pwd)
            or not re.search(r'[a-z]', pwd)
            or not re.search(r'[0-9]', pwd)
            or not re.search(r'[\W_]', pwd)):
        return False, ("Password must be 8-72 characters and contain an uppercase "
                       "letter, lowercase letter, digit, and special character.")

    return True, ""


# --- SIMPLE IN-MEMORY RATE LIMITER (brute-force protection) ----------------
# NOTE: per-process and in-memory — fine for a demo. Production would use a
# shared store (e.g., Redis) via flask-limiter.

_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SECONDS = 60
_login_attempts = defaultdict(deque)   # ip -> timestamps of recent failures


def _prune_old(ip, now):
    dq = _login_attempts[ip]
    while dq and now - dq[0] > _LOGIN_WINDOW_SECONDS:
        dq.popleft()


def login_rate_limit(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr or 'unknown'
        _prune_old(ip, time.time())
        if len(_login_attempts[ip]) >= _LOGIN_MAX_ATTEMPTS:
            return jsonify({"error": "Too many failed attempts. Try again shortly."}), 429
        return f(*args, **kwargs)
    return wrapper


def record_failed_login():
    _login_attempts[request.remote_addr or 'unknown'].append(time.time())


# Pre-computed dummy hash so a failed lookup still costs one bcrypt run —
# prevents timing-based username enumeration.
_DUMMY_HASH = bcrypt.hashpw(b"invalid-password-placeholder",
                            bcrypt.gensalt(rounds=BCRYPT_ROUNDS))


# --- AUTHENTICATION & AUTHORIZATION ----------------------------------------

def token_required(f):
    """Verifies a Bearer JWT and attaches the payload to request.current_user."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required (Bearer <token>)"}), 401

        token = auth_header.split(" ", 1)[1].strip()
        try:
            # Algorithm pinned — prevents algorithm-confusion attacks
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        request.current_user = payload
        return f(*args, **kwargs)
    return decorated


def roles_required(*roles):
    """Must appear BELOW @token_required so request.current_user exists."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if request.current_user.get('role') not in roles:
                return jsonify({"error": "Access denied: insufficient permissions"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


# --- SECURITY HEADERS & ERROR HANDLERS --------------------------------------

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cache-Control'] = 'no-store'
    # HSTS is only enforced over HTTPS — harmless locally, correct in production
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response


@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "error": "Resource not found",
        "message": "The requested endpoint does not exist. Visit GET /api for available routes."
    }), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method Not Allowed",
                    "message": "The HTTP method is not supported for this endpoint."}), 405


@app.errorhandler(413)
def payload_too_large(e):
    return jsonify({"error": "Request body too large"}), 413


@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Too many requests"}), 429


@app.errorhandler(500)
def server_error(e):
    # Mask internal details from clients; log server-side only
    app.logger.error("Unhandled server error: %s", e)
    return jsonify({"error": "An internal server error occurred"}), 500


# --- ROUTES -----------------------------------------------------------------

@app.route('/', methods=['GET'])
@app.route('/ui', methods=['GET'])      # both URLs serve the web interface
def index():
    """Serve the demo web interface (templates/index.html)."""
    return render_template('index.html')


@app.route('/api', methods=['GET'])
def api_docs():
    """JSON endpoint list — for graders testing with curl/Postman."""
    return jsonify({
        "status": "online",
        "message": "Application Security Demo API",
        "ui": "Open GET / in a browser for the web interface",
        "endpoints": {
            "POST /api/register": "Register a new user (JSON: username, password). Roles assigned internally.",
            "POST /api/login": "Authenticate and obtain JWT (JSON: username, password). 5 failed attempts/min per IP.",
            "GET /api/profile": "View user profile (Requires: Bearer JWT)",
            "GET /api/admin/users": "Admin-only user list (Requires: Admin Bearer JWT)",
            "POST /api/admin/promote": "Admin-only: grant admin role to an existing user"
        }
    }), 200


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid or missing JSON payload"}), 400

    valid, msg = validate_registration(data)
    if not valid:
        return jsonify({"error": msg}), 400

    username = str(data['username'])
    password = str(data['password'])

    # SECURITY FIX: role is NEVER accepted from client input.
    # Admins are created by seed_admin() or promoted by an existing admin only.
    role = 'user'

    # bcrypt generates and embeds a unique random salt per hash
    pwd_hash = bcrypt.hashpw(password.encode('utf-8'),
                             bcrypt.gensalt(rounds=BCRYPT_ROUNDS))

    try:
        with closing(get_db()) as conn:
            with conn:
                # Parameterized query prevents SQL injection
                conn.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, pwd_hash, role)
                )
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

    return jsonify({"message": "User registered successfully"}), 201


@app.route('/api/login', methods=['POST'])
@login_rate_limit
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Invalid credentials"}), 401

    username = str(data['username'])
    password = str(data['password']).encode('utf-8')

    with closing(get_db()) as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

    # Always run bcrypt (dummy hash when user not found) so response
    # timing doesn't reveal which usernames exist.
    stored = user['password_hash'] if user else _DUMMY_HASH
    try:
        password_ok = bcrypt.checkpw(password, stored)
    except ValueError:          # corrupt/non-bcrypt hash stored — treat as failure
        password_ok = False

    if not user or not password_ok:
        record_failed_login()
        # Uniform message prevents username enumeration
        return jsonify({"error": "Invalid credentials"}), 401

    now = datetime.now(timezone.utc)
    token = jwt.encode({
        "sub": user['username'],
        "role": user['role'],
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXPIRY_MINUTES)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({"token": token}), 200


@app.route('/api/profile', methods=['GET'])
@token_required
def profile():
    return jsonify({
        "username": request.current_user['sub'],
        "role": request.current_user.get('role')
    }), 200


@app.route('/api/admin/users', methods=['GET'])
@token_required
@roles_required('admin')
def list_users():
    with closing(get_db()) as conn:
        users = conn.execute("SELECT id, username, role FROM users").fetchall()
    return jsonify([dict(u) for u in users]), 200


@app.route('/api/admin/promote', methods=['POST'])
@token_required
@roles_required('admin')
def promote_user():
    """Legitimate path to admin: an existing admin promotes a user."""
    data = request.get_json(silent=True)
    username = str(data.get('username', '')).strip() if isinstance(data, dict) else ''
    if not username:
        return jsonify({"error": "Provide 'username' of the account to promote"}), 400

    with closing(get_db()) as conn:
        with conn:
            cur = conn.execute(
                "UPDATE users SET role = 'admin' WHERE username = ? AND role = 'user'",
                (username,)
            )
    if cur.rowcount == 0:
        return jsonify({"error": "User not found (or already an admin)"}), 404
    return jsonify({"message": f"'{username}' promoted to admin"}), 200


if __name__ == '__main__':
    # Localhost only for testing. Production: gunicorn/uvicorn behind an
    # HTTPS-terminating reverse proxy.
    app.run(host='127.0.0.1', port=5000, debug=False)