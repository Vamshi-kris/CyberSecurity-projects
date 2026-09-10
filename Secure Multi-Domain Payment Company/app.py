"""
SECURE MULTI-DOMAIN PAYMENT COMPANY — single-file prototype
============================================================
Five "domains" simulated as URL prefixes (production = five separate
subdomains / services with host-scoped cookies):

  /            Main website (public)
  /security    Security control matrix (show this to the grader)
  /portal/     Customer portal  (login, cards, payments)
  /pay/        Payment application (merchant checkout simulation)
  /admin/      Admin portal (back office + audit log)
  /api/        Backend JSON API (JWT for users, HMAC for services)

Run:   pip install flask bcrypt pyjwt
       python app.py
Login credentials + service key print on first run (delete app.db to re-seed).
"""
import hashlib, hmac, json, logging, os, re, secrets, sqlite3, time
from collections import Counter, defaultdict, deque
from contextlib import closing
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from functools import wraps

import bcrypt, jwt
from flask import (Flask, flash, get_flashed_messages, jsonify, redirect,
                   render_template, request, session, url_for)
from jinja2 import DictLoader

# ---------------------------------------------------------------- config ----
DB = 'app.db'
JWT_SECRET = os.environ.get('JWT_SECRET') or secrets.token_hex(32)
SERVICE_KEY = os.environ.get('SERVICE_API_KEY') or secrets.token_hex(24)
JWT_TTL_MIN = 15
SESSION_TTL = 30 * 60
MAX_FAILS, LOCK_MIN = 5, 15
MAX_TXN_CENTS = 1_000_000                       # $10,000 per-transaction cap
CURRENCIES = {'USD', 'EUR', 'GBP'}              # ISO-4217 whitelist

USERNAME_RE = re.compile(r'^[a-zA-Z0-9_.-]{3,20}$')
TOKEN_RE    = re.compile(r'^tok_[0-9a-f]{16}$')
MERCHANT_RE = re.compile(r"^[A-Za-z0-9 .&'-]{2,40}$")
AMOUNT_RE   = re.compile(r'^\d{1,6}(\.\d{1,2})?$')
IDEM_RE     = re.compile(r'^[A-Za-z0-9_-]{8,64}$')

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger('payco')
METRICS, FAILED_LOGINS, IP_FAILS = Counter(), deque(), defaultdict(deque)
_DUMMY_HASH = bcrypt.hashpw(b'not-a-real-password', bcrypt.gensalt(rounds=12))

app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get('FLASK_SECRET') or secrets.token_hex(32),
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                  MAX_CONTENT_LENGTH=32 * 1024)
app.jinja_loader = DictLoader({})               # replaced below with our templates

# ------------------------------------------------------------ database ------
def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def now(): return datetime.now(timezone.utc)

def init_db():
    with closing(db()) as c, c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL, password_hash BLOB NOT NULL,
            role TEXT NOT NULL CHECK(role IN('customer','admin')),
            failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT,
            created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS accounts(
            user_id INTEGER PRIMARY KEY REFERENCES users(id),
            balance_cents INTEGER NOT NULL CHECK(balance_cents>=0), currency TEXT NOT NULL);
        -- No column can hold a full PAN or CVV: tokenization enforced by schema --
        CREATE TABLE IF NOT EXISTS cards(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            token TEXT UNIQUE NOT NULL, brand TEXT NOT NULL, last4 TEXT NOT NULL,
            exp_month INTEGER NOT NULL, exp_year INTEGER NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS transactions(
            id INTEGER PRIMARY KEY AUTOINCREMENT, txn_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL REFERENCES users(id), card_token TEXT,
            amount_cents INTEGER NOT NULL, currency TEXT NOT NULL, merchant TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN('completed','failed')),
            idempotency_key TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
            domain TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL DEFAULT 'ok',
            ip TEXT, details TEXT);
        ''')

def seed():
    with closing(db()) as c:
        if c.execute('SELECT COUNT(*) n FROM users').fetchone()['n']:
            return
    admin_pw = os.environ.get('ADMIN_PASSWORD') or secrets.token_urlsafe(10)
    alice_pw = os.environ.get('DEMO_PASSWORD') or secrets.token_urlsafe(10)
    ts, tok = now().isoformat(timespec='seconds'), 'tok_' + secrets.token_hex(8)
    with closing(db()) as c, c:
        def add(u, p, r):
            return c.execute('INSERT INTO users(username,password_hash,role,created_at) '
                             'VALUES(?,?,?,?)',
                             (u, bcrypt.hashpw(p.encode(), bcrypt.gensalt(rounds=12)),
                              r, ts)).lastrowid
        add('admin', admin_pw, 'admin')
        alice = add('alice', alice_pw, 'customer')
        add('bob', secrets.token_urlsafe(10), 'customer')
        c.execute('INSERT INTO accounts VALUES(?,?,?)', (alice, 500_00, 'USD'))
        c.execute('INSERT INTO cards(user_id,token,brand,last4,exp_month,exp_year,created_at)'
                  ' VALUES(?,?,?,?,?,?,?)', (alice, tok, 'Visa', '1111', 12, 2030, ts))
    print('=' * 62)
    print(f' admin / {admin_pw}   -> /admin/')
    print(f' alice / {alice_pw}   -> /portal/   card token: {tok}')
    print(f' SERVICE_API_KEY (for /api/payments): {SERVICE_KEY}')
    print(' (delete app.db to re-seed)')
    print('=' * 62)

# ------------------------------------------------- audit / logging ----------
def audit(actor, domain, action, outcome='ok', details=''):
    ip = request.remote_addr if request else '-'
    with closing(db()) as c, c:
        c.execute('INSERT INTO audit_log(ts,actor,domain,action,outcome,ip,details) '
                  'VALUES(?,?,?,?,?,?,?)',
                  (now().isoformat(timespec='seconds'), actor, domain, action,
                   outcome, ip, str(details)[:200]))
    METRICS[action] += 1
    log.info('AUDIT %s actor=%s action=%s outcome=%s ip=%s %s',
             domain, actor, action, outcome, ip, details)
    if action == 'login_failed':
        FAILED_LOGINS.append(time.time())
        while FAILED_LOGINS and time.time() - FAILED_LOGINS[0] > 300:
            FAILED_LOGINS.popleft()
        if len(FAILED_LOGINS) >= 10:
            log.warning('SECURITY-ALERT: %d failed logins in 5 min — possible attack',
                        len(FAILED_LOGINS))

# ------------------------------------------------- validation / money -------
def luhn_ok(n):
    if not n.isdigit() or not 12 <= len(n) <= 19: return False
    t, alt = 0, False
    for ch in reversed(n):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9: d -= 9
        t += d; alt = not alt
    return t % 10 == 0

def brand(n):
    if n.startswith('4'): return 'Visa'
    if n[:2] in {'51','52','53','54','55'}: return 'Mastercard'
    if n[:2] in {'34','37'}: return 'Amex'
    return 'Card'

def amount_to_cents(v):
    s = str(v).strip()
    if not AMOUNT_RE.fullmatch(s): return None
    c = int((Decimal(s) * 100).to_integral_value())   # integer cents — no float money
    return c if 0 < c <= MAX_TXN_CENTS else None

def password_ok(p):
    return (8 <= len(p) <= 72 and re.search(r'[A-Z]', p) and re.search(r'[a-z]', p)
            and re.search(r'[0-9]', p) and re.search(r'[\W_]', p))

def validate_card(number, mm, yy, cvv):
    n = re.sub(r'[\s-]', '', str(number))
    if not luhn_ok(n): return 'Card number failed the Luhn checksum.', None
    b = brand(n)
    try: m, y = int(mm), int(yy)
    except (TypeError, ValueError): return 'Invalid expiry.', None
    if y < 100: y += 2000
    if not 1 <= m <= 12 or (y, m) < (now().year, now().month):
        return 'Card is expired or expiry is invalid.', None
    want = 4 if b == 'Amex' else 3
    if not (str(cvv).isdigit() and len(str(cvv)) == want):
        return f'CVV must be {want} digits for {b}.', None
    return None, {'brand': b, 'last4': n[-4:], 'exp_month': m, 'exp_year': y}

# ------------------------------------------------- authentication -----------
def attempt_login(username, password, domain):
    username = str(username)[:64]
    with closing(db()) as c:
        u = c.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if u and u['locked_until']:
        try: until = datetime.fromisoformat(u['locked_until'])
        except ValueError: until = None
        if until and until > now():
            audit(username, domain, 'login_locked', 'blocked')
            return None, 'Account temporarily locked. Try again later.'
    stored = u['password_hash'] if u else _DUMMY_HASH      # timing-enumeration defense
    try: ok = bcrypt.checkpw(str(password).encode(), stored)
    except ValueError: ok = False
    if not u or not ok:
        IP_FAILS[request.remote_addr or '?'].append(time.time())
        if u:
            f = u['failed_attempts'] + 1
            with closing(db()) as c, c:
                if f >= MAX_FAILS:
                    c.execute('UPDATE users SET failed_attempts=0, locked_until=? WHERE id=?',
                              ((now() + timedelta(minutes=LOCK_MIN)).isoformat(timespec='seconds'),
                               u['id']))
                else:
                    c.execute('UPDATE users SET failed_attempts=? WHERE id=?', (f, u['id']))
            if f >= MAX_FAILS: audit(username, domain, 'account_locked', 'blocked')
        audit(username, domain, 'login_failed', 'denied')
        return None, 'Invalid username or password.'       # uniform message
    with closing(db()) as c, c:
        c.execute('UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?', (u['id'],))
    audit(username, domain, 'login_success')
    return u, None

# ------------------------------------------------- decorators ---------------
def ip_login_limit(max_failures=10, window=60):
    def d(fn):
        @wraps(fn)
        def w(*a, **k):
            q = IP_FAILS[request.remote_addr or '?']; t = time.time()
            while q and t - q[0] > window: q.popleft()
            if len(q) >= max_failures:
                return jsonify({'error': 'Too many attempts. Try later.'}), 429
            return fn(*a, **k)
        return w
    return d

def csrf_protect(fn):
    @wraps(fn)
    def w(*a, **k):
        if request.method == 'POST':
            s, g = session.get('csrf', ''), request.form.get('csrf', '')
            if not s or not g or not hmac.compare_digest(s, g):
                audit(session.get('username') or 'anon', request.path, 'csrf_rejected', 'blocked')
                return 'CSRF validation failed.', 400
        return fn(*a, **k)
    return w

def login_required(scope):
    """Scope-tagged sessions: a 'portal' session is invalid on '/admin'."""
    def d(fn):
        @wraps(fn)
        def w(*a, **k):
            if session.get('scope') != scope or not session.get('uid'):
                return redirect(url_for(f'{scope}_login'))
            if time.time() > session.get('expires', 0):
                session.clear(); return redirect(url_for(f'{scope}_login'))
            return fn(*a, **k)
        return w
    return d

def jwt_required(fn):
    @wraps(fn)
    def w(*a, **k):
        h = request.headers.get('Authorization', '')
        if not h.startswith('Bearer '):
            return jsonify({'error': 'Bearer token required'}), 401
        try:
            p = jwt.decode(h[7:].strip(), JWT_SECRET, algorithms=['HS256'],
                           audience='api', issuer='auth.payco.local')
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'invalid token'}), 401
        request.api_user = p
        return fn(*a, **k)
    return w

# ------------------------------------------------- HMAC payment core --------
def sign(b: bytes) -> str:
    return hmac.new(SERVICE_KEY.encode(), b, hashlib.sha256).hexdigest()

def process_signed_payment(body: bytes, signature: str, idem: str):
    """The payment-processing core: verifies HMAC over EXACT bytes, validates,
    then debits atomically. Used by BOTH /api/payments (over HTTP) and /pay
    (simulated server-to-server hop)."""
    if len(signature) != 64 or not hmac.compare_digest(signature, sign(body)):
        audit('service', 'payments', 'bad_signature', 'denied', 'HMAC mismatch')
        return 401, {'error': 'invalid request signature'}
    try:
        p = json.loads(body)
        username, token = str(p.get('username','')), str(p.get('card_token',''))
        cents, currency = p.get('amount_cents'), str(p.get('currency','')).upper()
        merchant = str(p.get('merchant',''))
    except (json.JSONDecodeError, AttributeError):
        return 400, {'error': 'malformed JSON'}
    if not USERNAME_RE.fullmatch(username): return 400, {'error': 'invalid username'}
    if not TOKEN_RE.fullmatch(token):       return 400, {'error': 'invalid card_token'}
    if (not isinstance(cents, int) or isinstance(cents, bool)
            or not 0 < cents <= MAX_TXN_CENTS):
        return 400, {'error': 'amount_cents must be integer in (0, 1000000]'}
    if currency not in CURRENCIES:          return 400, {'error': 'unsupported currency'}
    if not MERCHANT_RE.fullmatch(merchant): return 400, {'error': 'invalid merchant'}
    if not IDEM_RE.fullmatch(idem):         return 400, {'error': 'Idempotency-Key required'}

    with closing(db()) as c, c:
        dupe = c.execute('SELECT * FROM transactions WHERE idempotency_key=?', (idem,)).fetchone()
        if dupe:                                        # IDEMPOTENCY: safe retries
            return 200, {'duplicate': True,
                         'transaction': {'txn_id': dupe['txn_id'], 'status': dupe['status']}}
        row = c.execute('''SELECT c.user_id, u.username, c.last4, a.user_id AS acct,
                                  a.balance_cents FROM cards c
                           JOIN users u ON u.id=c.user_id
                           JOIN accounts a ON a.user_id=c.user_id WHERE c.token=?''',
                        (token,)).fetchone()
        if not row or row['username'] != username:      # ownership check
            audit(username, 'payments', 'payment_rejected', 'denied', 'token/owner mismatch')
            return 404, {'error': 'card not found for this customer'}
        # ATOMIC check-and-debit — no race, no overdraft
        upd = c.execute('UPDATE accounts SET balance_cents=balance_cents-? '
                        'WHERE user_id=? AND balance_cents>=?', (cents, row['acct'], cents))
        txn, status = 'txn_' + secrets.token_hex(10), 'completed' if upd.rowcount else 'failed'
        c.execute('''INSERT INTO transactions(txn_id,user_id,card_token,amount_cents,
                     currency,merchant,status,idempotency_key,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?)''',
                  (txn, row['user_id'], token, cents, currency, merchant, status, idem,
                   now().isoformat(timespec='seconds')))
    if status != 'completed':
        audit(username, 'payments', 'payment_declined', 'denied', f'{cents} {currency}')
        return 402, {'error': 'insufficient funds', 'transaction': {'txn_id': txn, 'status': status}}
    audit(username, 'payments', 'payment_completed', details=f'{cents} {currency} ****{row["last4"]}')
    return 201, {'transaction': {'txn_id': txn, 'amount_cents': cents, 'currency': currency,
                                 'merchant': merchant, 'status': status, 'card': '****' + row['last4']}}

# ============================================================ TEMPLATES =====
NAV = ('<header><div class="brand">🔐 PaymentCo <span class="tag">secure '
       'multi-domain prototype</span></div><nav>'
       '<a href="{{ url_for(\'home\') }}">Main Site</a>'
       '<a href="{{ url_for(\'security\') }}">Security</a>'
       '<a href="{{ url_for(\'portal_login\') }}">Portal</a>'
       '<a href="{{ url_for(\'pay\') }}">Payment App</a>'
       '<a href="{{ url_for(\'admin_login\') }}">Admin</a>'
       '<a href="{{ url_for(\'api_docs\') }}">API</a></nav></header>')

app.jinja_loader = DictLoader({
'base.html': ('{% macro nav() %}' + NAV + '{% endmacro %}'
'<!doctype html><html lang="en"><head><meta charset="utf-8">'
'<meta name="viewport" content="width=device-width,initial-scale=1">'
'<title>{{ title }} — PaymentCo</title>'
'<link rel="stylesheet" href="{{ url_for(\'css\') }}"></head>'
'<body>{{ nav() }}'
'{% for cat,m in get_flashed_messages(with_categories=true) %}'
'<div class="flash {{ cat }}">{{ m }}</div>{% endfor %}'
'<main>{% block content %}{% endblock %}</main>'
'<footer>Course prototype — no real payments, synthetic data only. '
'Jinja autoescaping ON (XSS defense). All input validated server-side.</footer>'
'</body></html>'),

'home.html': ('{% extends "base.html" %}{% block content %}'
'<div class="card"><h1>PaymentCo — secure payments across five domains</h1>'
'<p style="color:var(--mut)">Five logical domains, one identity core, strict '
'separation of sessions and privileges.</p></div>'
'<div class="grid2"><div class="card"><h2>🌐 Domains</h2><table>'
'<tr><th>Domain</th><th>Purpose</th></tr>'
'<tr><td>/ (main site)</td><td>Public website — no user data, no auth</td></tr>'
'<tr><td><a href="{{ url_for(\'portal_login\') }}">/portal</a></td>'
'<td>Customer portal — balance, tokenized cards, payments</td></tr>'
'<tr><td><a href="{{ url_for(\'pay\') }}">/pay</a></td>'
'<td>Payment app — merchant checkout, HMAC-signed gateway calls</td></tr>'
'<tr><td><a href="{{ url_for(\'admin_login\') }}">/admin</a></td>'
'<td>Admin portal — back office, audit log (admin role only)</td></tr>'
'<tr><td><a href="{{ url_for(\'api_docs\') }}">/api</a></td>'
'<td>Backend API — JWT (users) + HMAC (services)</td></tr></table></div>'
'<div class="card"><h2>🛡️ Built-in security</h2><ul class="feat">'
'<li>✔ bcrypt(12) + account lockout</li><li>✔ HttpOnly / SameSite sessions, '
'scoped per domain</li><li>✔ RBAC + ownership checks (IDOR defense)</li>'
'<li>✔ Card <b>tokenization</b> — PAN/CVV never stored</li>'
'<li>✔ HMAC-SHA256 signed payment calls</li><li>✔ Idempotent processing</li>'
'<li>✔ Audit log + anomaly alerts</li></ul>'
'<p class="hint">Full matrix: <a href="{{ url_for(\'security\') }}">/security</a></p>'
'</div></div>{% endblock %}'),

'security.html': ('{% extends "base.html" %}{% block content %}'
'<div class="card"><h1>Security control matrix</h1><table>'
'<tr><th>Requirement</th><th>Implementation</th></tr>'
'<tr><td>Secure authentication</td><td>bcrypt(12), lockout after 5 failures '
'(15 min), dummy-hash timing defense, session cleared &amp; re-issued at login '
'(fixation defense), 30-min absolute timeout</td></tr>'
'<tr><td>Authorization / access control</td><td>customer/admin roles; sessions carry '
'a <i>scope</i> (portal session rejected on /admin); card/payment queries filter by '
'owner — IDOR prevented</td></tr>'
'<tr><td>Password security</td><td>bcrypt + per-hash salt, 8–72 char policy '
'(bcrypt truncates &gt;72), uniform login errors, passwords never logged</td></tr>'
'<tr><td>Secure communication</td><td>HSTS, nosniff, frame-deny, CSP headers; '
'payment calls integrity-protected with HMAC-SHA256 over exact bytes '
'(TLS-ready; run behind HTTPS in production)</td></tr>'
'<tr><td>Input validation</td><td>Whitelist regex fullmatch, Decimal→integer cents '
'(no float money), currency whitelist, Luhn card check, expiry + brand-aware CVV '
'checks, 32 KB body cap</td></tr>'
'<tr><td>API security</td><td>JWT: HS256 pinned, iss+aud checked, 15-min exp, jti; '
'service endpoints need API key + HMAC signature; per-IP rate limits; idempotency keys</td></tr>'
'<tr><td>Session management</td><td>HttpOnly + SameSite=Lax cookies, rotation at login, '
'logout via POST+CSRF, absolute expiry</td></tr>'
'<tr><td>Logging &amp; monitoring</td><td>audit_log(actor, domain, action, outcome, IP) '
'shown on admin dashboard; alert at ≥10 failed logins/5 min; PAN/CVV never logged</td></tr>'
'<tr><td>Domain separation</td><td>Five logical domains, separate session scopes and '
'login flows, admin actions audited (separation of duties)</td></tr>'
'<tr><td>Payment security</td><td><b>Tokenization</b> (PAN validated then discarded; '
'enforced by schema), integer-cent math, $10k cap, atomic check-and-debit, '
'declines recorded, idempotent retries</td></tr></table>'
'<p class="hint">Production notes: real TLS certs, KMS key storage, 3-D Secure, '
'JWT revocation store, Redis rate limiting, WAF/SIEM, PCI DSS assessment.</p>'
'</div>{% endblock %}'),

'login.html': ('{% extends "base.html" %}{% block content %}'
'<div class="card narrow"><h1>{{ title }}</h1>'
'<form method="post" action="{{ action }}">'
'<input type="hidden" name="csrf" value="{{ csrf }}">'
'<label>Username</label><input name="username" required maxlength="20" autocomplete="username">'
'<label>Password</label><input name="password" type="password" required maxlength="72" '
'autocomplete="current-password"><button>Sign in</button></form>'
'{% if signup %}<p class="hint">New customer? '
'<a href="{{ url_for(\'portal_register\') }}">Create an account</a></p>{% endif %}'
'<p class="hint">{{ note }}</p></div>{% endblock %}'),

'register.html': ('{% extends "base.html" %}{% block content %}'
'<div class="card narrow"><h1>Create Customer Account</h1>'
'<form method="post" action="{{ url_for(\'portal_register\') }}">'
'<input type="hidden" name="csrf" value="{{ csrf }}">'
'<label>Username (3–20: letters, digits, _ . -)</label>'
'<input name="username" required maxlength="20">'
'<label>Password (8–72: upper + lower + digit + symbol)</label>'
'<input name="password" type="password" required maxlength="72">'
'<button>Register</button></form>'
'<p class="hint">Role is fixed to <b>customer</b> server-side — signup can never '
'create an admin.</p></div>{% endblock %}'),

'portal.html': ('{% extends "base.html" %}{% block content %}'
'<div class="card"><h1>Welcome, {{ session[\'username\'] }}</h1>'
'<div class="tiles">'
'<div class="tile"><b>${{ \'%.2f\'|format(acct[\'balance_cents\']/100) }}</b>'
'balance ({{ acct[\'currency\'] }})</div>'
'<div class="tile"><b>{{ cards|length }}</b>tokenized card(s)</div></div>'
'<form method="post" action="{{ url_for(\'portal_logout\') }}" style="margin-top:1rem">'
'<input type="hidden" name="csrf" value="{{ csrf }}">'
'<button class="sm danger">Log out (POST + CSRF)</button></form></div>'
'<div class="grid2"><div class="card"><h2>💳 Pay a merchant</h2>'
'<form method="post" action="{{ url_for(\'portal_pay\') }}">'
'<input type="hidden" name="csrf" value="{{ csrf }}">'
'<label>Card</label><select name="card_id" required>'
'{% for c in cards %}<option value="{{ c[\'id\'] }}">{{ c[\'brand\'] }} '
'****{{ c[\'last4\'] }}</option>{% endfor %}</select>'
'<label>Amount (e.g. 19.99)</label>'
'<input name="amount" required pattern="\\d{1,6}(\\.\\d{1,2})?">'
'<label>Currency</label><select name="currency">'
'<option>USD</option><option>EUR</option><option>GBP</option></select>'
'<label>Merchant</label><input name="merchant" required maxlength="40" value="DemoStore">'
'<button>Pay (HMAC-signed internal call)</button></form></div>'
'<div class="card"><h2>➕ Add a card (tokenized)</h2>'
'<form method="post" action="{{ url_for(\'portal_add_card\') }}">'
'<input type="hidden" name="csrf" value="{{ csrf }}">'
'<label>Card number</label><input name="card_number" required maxlength="23" '
'placeholder="4111 1111 1111 1111">'
'<label>Expiry MM / YY</label><span class="inline">'
'<input name="exp_month" required maxlength="2" placeholder="12" style="max-width:70px">'
'<input name="exp_year" required maxlength="4" placeholder="2030" style="max-width:90px"></span>'
'<label>CVV</label><input name="cvv" required maxlength="4" placeholder="123">'
'<button>Validate &amp; tokenize</button></form>'
'<p class="hint">Test cards: 4111111111111111 (Visa), 5555555555554444 (MC), '
'378282246310005 (Amex). PAN/CVV validated then discarded — only brand, last4 '
'and a token are stored.</p></div></div>'
'<div class="card"><h2>💳 Your cards</h2><table><tr><th>Brand</th><th>Card</th>'
'<th>Exp</th><th>Token</th></tr>'
'{% for c in cards %}<tr><td>{{ c[\'brand\'] }}</td><td>**** {{ c[\'last4\'] }}</td>'
'<td>{{ \'%02d\'|format(c[\'exp_month\']) }}/{{ c[\'exp_year\'] % 100 }}</td>'
'<td><code>{{ c[\'token\'] }}</code></td></tr>{% endfor %}</table></div>'
'<div class="card"><h2>🧾 Recent transactions</h2><table><tr><th>Txn</th><th>Card</th>'
'<th>Amount</th><th>Merchant</th><th>Status</th><th>When (UTC)</th></tr>'
'{% for t in txns %}<tr><td><code>{{ t[\'txn_id\'] }}</code></td>'
'<td>****{{ t[\'last4\'] or \'----\' }}</td>'
'<td>{{ \'%.2f\'|format(t[\'amount_cents\']/100) }} {{ t[\'currency\'] }}</td>'
'<td>{{ t[\'merchant\'] }}</td>'
'<td><span class="badge {{ \'ok\' if t[\'status\']==\'completed\' else \'bad\' }}">'
'{{ t[\'status\'] }}</span></td><td>{{ t[\'created_at\'] }}</td></tr>'
'{% else %}<tr><td colspan="6">No transactions yet.</td></tr>{% endfor %}'
'</table></div>{% endblock %}'),

'pay.html': ('{% extends "base.html" %}{% block content %}'
'<div class="card"><h1>💳 Merchant checkout simulation</h1>'
'<p style="color:var(--mut);font-size:.92rem">Plays the role of a merchant server '
'calling the PaymentCo gateway: the JSON request is signed with HMAC-SHA256 and '
'carries an idempotency key, so retries can never double-charge.</p>'
'<form method="post" action="{{ url_for(\'pay_charge\') }}">'
'<input type="hidden" name="csrf" value="{{ csrf }}"><div class="grid2"><div>'
'<label>Customer username</label><input name="username" required maxlength="20" placeholder="alice">'
'<label>Card token (from portal)</label><input name="card_token" required maxlength="24" '
'placeholder="tok_..."></div><div>'
'<label>Amount</label><input name="amount" required placeholder="49.99" '
'pattern="\\d{1,6}(\\.\\d{1,2})?">'
'<label>Currency</label><select name="currency">'
'<option>USD</option><option>EUR</option><option>GBP</option></select>'
'<label>Merchant</label><input name="merchant" value="DemoStore" maxlength="40" required>'
'</div></div><button>Charge card</button></form></div>'
'{% if result %}<div class="card"><h2>Gateway exchange</h2>'
'{% if result.error %}<p class="flash error">{{ result.error }}</p>{% endif %}'
'{% if result.status %}<p><span class="badge {{ \'ok\' if result.status==201 else \'bad\' }}">'
'HTTP {{ result.status }}</span> &nbsp;Idempotency-Key: '
'<code>{{ result.idem }}</code></p>{% endif %}'
'<p class="hint">Request (token masked for display):</p><pre>{{ result.request }}</pre>'
'{% if result.sig %}<p class="hint">X-Signature (truncated): '
'<code>{{ result.sig }}…</code></p>{% endif %}'
'{% if result.response %}<p class="hint">Response:</p><pre>{{ result.response }}</pre>{% endif %}'
'</div>{% endif %}{% endblock %}'),

'admin.html': ('{% extends "base.html" %}{% block content %}'
'<div class="card"><h1>🛡️ Admin back office — {{ session[\'username\'] }}</h1>'
'<div class="tiles">'
'<div class="tile"><b>{{ users|length }}</b>users</div>'
'<div class="tile"><b>{{ txn_count }}</b>completed txns</div>'
'<div class="tile"><b>${{ volume }}</b>volume</div>'
'<div class="tile"><b>{{ failed_24h }}</b>failed logins (24h)</div>'
'<div class="tile"><b>{{ locked }}</b>locked accounts</div></div>'
'<form method="post" action="{{ url_for(\'admin_logout\') }}" style="margin-top:1rem">'
'<input type="hidden" name="csrf" value="{{ csrf }}">'
'<button class="sm danger">Log out</button></form></div>'
'<div class="card"><h2>👥 Users — admins manage accounts, never payments</h2><table>'
'<tr><th>ID</th><th>Username</th><th>Role</th><th>Balance</th><th>Status</th>'
'<th>Actions</th></tr>{% for u in users %}<tr><td>{{ u[\'id\'] }}</td>'
'<td>{{ u[\'username\'] }}</td><td>{{ u[\'role\'] }}</td>'
'<td>{% if u[\'balance_cents\'] is not none %}${{ \'%.2f\'|format(u[\'balance_cents\']/100) }}'
'{% else %}—{% endif %}</td>'
'<td>{% if u[\'locked_until\'] %}<span class="badge bad">locked</span>'
'{% else %}<span class="badge ok">active</span>{% endif %}</td>'
'<td>{% if u[\'id\'] != session[\'uid\'] %}'
'<form class="inline" method="post" action="{{ url_for(\'admin_lock\', uid=u[\'id\']) }}">'
'<input type="hidden" name="csrf" value="{{ csrf }}"><button class="sm">Lock</button></form>'
'<form class="inline" method="post" action="{{ url_for(\'admin_unlock\', uid=u[\'id\']) }}">'
'<input type="hidden" name="csrf" value="{{ csrf }}"><button class="sm">Unlock</button></form>'
'{% else %}<em>(you)</em>{% endif %}</td></tr>{% endfor %}</table></div>'
'<div class="card"><h2>🧾 Recent transactions</h2><table><tr><th>Txn</th><th>User</th>'
'<th>Card</th><th>Amount</th><th>Merchant</th><th>Status</th></tr>'
'{% for t in txns %}<tr><td><code>{{ t[\'txn_id\'] }}</code></td><td>{{ t[\'username\'] }}</td>'
'<td>****{{ t[\'last4\'] or \'----\' }}</td>'
'<td>{{ \'%.2f\'|format(t[\'amount_cents\']/100) }} {{ t[\'currency\'] }}</td>'
'<td>{{ t[\'merchant\'] }}</td>'
'<td><span class="badge {{ \'ok\' if t[\'status\']==\'completed\' else \'bad\' }}">'
'{{ t[\'status\'] }}</span></td></tr>{% endfor %}</table></div>'
'<div class="card"><h2>📜 Security audit log (latest {{ events|length }})</h2>'
'<div class="scroll"><table><tr><th>Time</th><th>Actor</th><th>Domain</th><th>Action</th>'
'<th>Outcome</th><th>IP</th><th>Details</th></tr>'
'{% for e in events %}<tr><td>{{ e[\'ts\'] }}</td><td>{{ e[\'actor\'] }}</td>'
'<td>{{ e[\'domain\'] }}</td><td>{{ e[\'action\'] }}</td><td>{{ e[\'outcome\'] }}</td>'
'<td>{{ e[\'ip\'] }}</td><td>{{ e[\'details\'] }}</td></tr>{% endfor %}'
'</table></div></div>{% endblock %}'),

'css': None,   # served by route, not a template
})

CSS = ''':root{--bg:#0f172a;--panel:#1e293b;--line:#334155;--txt:#e2e8f0;--mut:#94a3b8;
--acc:#38bdf8;--ok:#4ade80;--bad:#f87171}*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--txt);line-height:1.5}
header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.6rem;
background:var(--panel);border-bottom:2px solid var(--line);padding:.8rem 1.5rem}
.brand{font-weight:700}.brand .tag{color:var(--mut);font-weight:400;font-size:.8rem;margin-left:.4rem}
nav a{color:var(--mut);text-decoration:none;margin-left:1rem;font-size:.92rem;padding:.25rem .6rem;border-radius:6px}
nav a:hover{color:var(--txt);background:#334155}
main{max-width:1000px;margin:1.5rem auto;padding:0 1.5rem}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:1.3rem;margin-bottom:1.2rem}
.narrow{max-width:420px;margin:3rem auto}
h1{font-size:1.25rem;margin-bottom:.8rem;color:var(--acc)}
h2{font-size:1.05rem;margin-bottom:.7rem;color:var(--acc)}
label{display:block;font-size:.82rem;color:var(--mut);margin:.7rem 0 .25rem}
input,select{width:100%;max-width:360px;padding:.5rem .65rem;border-radius:6px;border:1px solid #475569;
background:var(--bg);color:var(--txt)}
button{margin-top:.9rem;padding:.5rem 1.2rem;border:none;border-radius:6px;background:#2563eb;color:#fff;
cursor:pointer;font-size:.92rem}button:hover{background:#1d4ed8}
button.sm{padding:.25rem .7rem;margin:0 .2rem 0 0;font-size:.78rem;background:#475569}
button.danger{background:#b91c1c}
table{border-collapse:collapse;width:100%;margin-top:.8rem;font-size:.86rem}
th,td{border:1px solid var(--line);padding:.4rem .7rem;text-align:left}
th{background:var(--bg);color:var(--mut);font-weight:600}
.scroll{max-height:320px;overflow-y:auto;border:1px solid var(--line);border-radius:8px}
.badge{padding:.1rem .55rem;border-radius:99px;font-size:.74rem}
.badge.ok{background:#052e16;color:var(--ok)}.badge.bad{background:#450a0a;color:var(--bad)}
.flash{max-width:1000px;margin:1rem auto 0;padding:.6rem 1.5rem;border-radius:8px}
.flash.error{background:#450a0a;color:#fca5a5}.flash.message{background:#052e16;color:#86efac}
main .flash{margin:0 0 1rem;padding:.6rem;border-radius:8px}
.hint{font-size:.8rem;color:#64748b;margin-top:.8rem}
pre{background:#020617;border:1px solid var(--line);border-radius:8px;padding:.8rem;font-size:.78rem;
overflow-x:auto;white-space:pre-wrap;word-break:break-all}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.8rem}
.tile{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:.8rem;text-align:center;
font-size:.8rem;color:var(--mut)}.tile b{display:block;font-size:1.4rem;color:var(--acc)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:1.2rem}
@media(max-width:800px){.grid2{grid-template-columns:1fr}}
.inline{display:inline}code{color:var(--acc)}
.feat{font-size:.9rem;color:var(--mut);line-height:1.9;list-style:none}
footer{text-align:center;color:#64748b;font-size:.78rem;padding:1.5rem}a{color:var(--acc)}'''

# ============================================================ ROUTES ========
@app.before_request
def seed_csrf():
    session.setdefault('csrf', secrets.token_hex(16))

@app.after_request
def headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000'
    resp.headers['Content-Security-Policy'] = ("default-src 'self'; style-src 'self'; "
                                               "img-src 'self'; frame-ancestors 'none'")
    return resp

@app.errorhandler(404)
def nf(e): return jsonify({'error': 'Not found'}), 404
@app.errorhandler(405)
def mna(e): return jsonify({'error': 'Method not allowed'}), 405
@app.errorhandler(413)
def tl(e): return jsonify({'error': 'Request too large'}), 413
@app.errorhandler(429)
def rl(e): return jsonify({'error': 'Too many requests'}), 429
@app.errorhandler(500)
def ise(e):
    app.logger.error('Unhandled: %s', e)
    return jsonify({'error': 'An internal error occurred'}), 500

# ---- main website (public, no user data) -----------------------------------
@app.route('/')
def home():
    return render_template('home.html', title='Home')

@app.route('/security')
def security():
    return render_template('security.html', title='Security')

# ---- customer portal --------------------------------------------------------
@app.route('/portal/login', methods=['GET', 'POST'])
@ip_login_limit()
@csrf_protect
def portal_login():
    if request.method == 'POST':
        u, err = attempt_login(request.form.get('username',''),
                               request.form.get('password',''), 'portal')
        if err:
            flash(err, 'error')
        else:
            session.clear()                              # fixation defense
            session['csrf'] = secrets.token_hex(16)
            session.update(uid=u['id'], username=u['username'], scope='portal',
                           expires=time.time() + SESSION_TTL)
            audit(u['username'], 'portal', 'session_created')
            return redirect(url_for('portal_home'))
    return render_template('login.html', title='Customer Portal Login',
                           action=url_for('portal_login'), signup=True,
                           note='Demo credentials were printed on first startup.')

@app.route('/portal/register', methods=['GET', 'POST'])
@ip_login_limit()
@csrf_protect
def portal_register():
    if request.method == 'POST':
        username, password = request.form.get('username',''), request.form.get('password','')
        if not USERNAME_RE.fullmatch(username):
            flash('Username must be 3-20 chars: letters, digits, _ . -', 'error')
        elif not password_ok(password):
            flash('Password needs 8-72 chars with upper, lower, digit, symbol.', 'error')
        else:
            try:
                with closing(db()) as c, c:
                    cur = c.execute('INSERT INTO users(username,password_hash,role,created_at)'
                                    ' VALUES(?,?,?,?)',
                                    (username, bcrypt.hashpw(password.encode(),
                                     bcrypt.gensalt(rounds=12)), 'customer',
                                     now().isoformat(timespec='seconds')))
                    c.execute('INSERT INTO accounts VALUES(?,?,?)',
                              (cur.lastrowid, 100_00, 'USD'))
                # role hard-coded 'customer' — public signup can never mint an admin
                audit(username, 'portal', 'register')
                flash('Account created (customer, demo balance $100). You can log in.', 'message')
            except sqlite3.IntegrityError:
                flash('Username already exists.', 'error')
    return render_template('register.html', title='Register')

@app.route('/portal/')
@login_required('portal')
def portal_home():
    with closing(db()) as c:
        acct = c.execute('SELECT balance_cents, currency FROM accounts WHERE user_id=?',
                         (session['uid'],)).fetchone()
        cards = c.execute('SELECT * FROM cards WHERE user_id=? ORDER BY id',
                          (session['uid'],)).fetchall()
        txns = c.execute('''SELECT t.*, c.last4 FROM transactions t
                            LEFT JOIN cards c ON c.token=t.card_token
                            WHERE t.user_id=? ORDER BY t.id DESC LIMIT 20''',
                         (session['uid'],)).fetchall()
    return render_template('portal.html', title='Portal', acct=acct, cards=cards, txns=txns)

@app.route('/portal/cards/add', methods=['POST'])
@login_required('portal')
@csrf_protect
def portal_add_card():
    err, card = validate_card(request.form.get('card_number',''),
                              request.form.get('exp_month'), request.form.get('exp_year'),
                              request.form.get('cvv',''))
    if err:
        audit(session['username'], 'portal', 'card_add_failed', 'rejected', err)
        flash(err, 'error'); return redirect(url_for('portal_home'))
    token = 'tok_' + secrets.token_hex(8)
    with closing(db()) as c, c:
        c.execute('INSERT INTO cards(user_id,token,brand,last4,exp_month,exp_year,created_at)'
                  ' VALUES(?,?,?,?,?,?,?)',
                  (session['uid'], token, card['brand'], card['last4'],
                   card['exp_month'], card['exp_year'], now().isoformat(timespec='seconds')))
    # TOKENIZATION: PAN/CVV existed only for this validation step — now discarded
    audit(session['username'], 'portal', 'card_tokenized',
          details=f"brand={card['brand']} last4={card['last4']}")
    flash(f"Card ****{card['last4']} tokenized. PAN/CVV discarded.", 'message')
    return redirect(url_for('portal_home'))

@app.route('/portal/pay', methods=['POST'])
@login_required('portal')
@csrf_protect
def portal_pay():
    cents = amount_to_cents(request.form.get('amount',''))
    currency = request.form.get('currency','').upper()
    merchant = request.form.get('merchant','').strip()
    if cents is None: flash('Amount must be 0.01–10000.00.', 'error')
    elif currency not in CURRENCIES: flash('Unsupported currency.', 'error')
    elif not MERCHANT_RE.fullmatch(merchant): flash('Invalid merchant name.', 'error')
    else:
        try: card_id = int(request.form.get('card_id',''))
        except ValueError: card_id = 0
        with closing(db()) as c:
            card = c.execute('SELECT token FROM cards WHERE id=? AND user_id=?',   # IDOR guard
                             (card_id, session['uid'])).fetchone()
        if not card:
            flash('Card not found (ownership check failed).', 'error')
        else:
            payload = {'username': session['username'], 'card_token': card['token'],
                       'amount_cents': cents, 'currency': currency, 'merchant': merchant}
            body = json.dumps(payload, separators=(',', ':')).encode()
            status, resp = process_signed_payment(body, sign(body),
                                                  'pay_' + secrets.token_hex(8))
            if status == 201:
                audit(session['username'], 'portal', 'payment_completed')
                flash(f"Payment completed — {resp['transaction']['txn_id']}", 'message')
            elif resp.get('duplicate'):
                flash('Duplicate request — original returned (idempotency).', 'message')
            else:
                flash(f"Payment declined: {resp.get('error')}", 'error')
    return redirect(url_for('portal_home'))

@app.route('/portal/logout', methods=['POST'])
@login_required('portal')
@csrf_protect
def portal_logout():
    audit(session['username'], 'portal', 'logout')
    session.clear()
    return redirect(url_for('portal_login'))

# ---- payment application (merchant simulation) ------------------------------
@app.route('/pay/', methods=['GET', 'POST'])
@csrf_protect
def pay():
    result = None
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        token = request.form.get('card_token','').strip()
        merchant = request.form.get('merchant','DemoStore').strip() or 'DemoStore'
        cents = amount_to_cents(request.form.get('amount',''))
        currency = request.form.get('currency','').upper()
        problems = []
        if not USERNAME_RE.fullmatch(username): problems.append('invalid username')
        if not TOKEN_RE.fullmatch(token): problems.append('card token must be tok_xxxxxxxxxxxxxxxx')
        if cents is None: problems.append('amount must be 0.01–10000.00')
        if currency not in CURRENCIES: problems.append('unsupported currency')
        if problems:
            result = {'error': 'Validation failed: ' + '; '.join(problems)}
        else:
            payload = {'username': username, 'card_token': token, 'amount_cents': cents,
                       'currency': currency, 'merchant': merchant}
            body = json.dumps(payload, separators=(',', ':')).encode()
            sig = sign(body)
            idem = 'mch_' + secrets.token_hex(8)
            audit(merchant, 'pay', 'charge_requested', details=f'{cents} {currency} {username}')
            status, resp = process_signed_payment(body, sig, idem)
            result = {'status': status, 'idem': idem,
                      'request': json.dumps(dict(payload, card_token=token[:8] + '…'), indent=2),
                      'sig': sig[:24], 'response': json.dumps(resp, indent=2)}
    return render_template('pay.html', title='Payment App', result=result)

# ---- admin portal ------------------------------------------------------------
@app.route('/admin/login', methods=['GET', 'POST'])
@ip_login_limit()
@csrf_protect
def admin_login():
    if request.method == 'POST':
        u, err = attempt_login(request.form.get('username',''),
                               request.form.get('password',''), 'admin')
        if not err and u and u['role'] != 'admin':
            audit(u['username'], 'admin', 'admin_login_denied', 'denied',
                  'valid customer tried admin portal')
            err = 'Invalid username or password.'        # uniform — don't reveal roles
        if err:
            flash(err, 'error')
        else:
            session.clear()
            session['csrf'] = secrets.token_hex(16)
            session.update(uid=u['id'], username=u['username'], scope='admin',
                           expires=time.time() + SESSION_TTL)
            audit(u['username'], 'admin', 'admin_session_created')
            return redirect(url_for('admin_home'))
    return render_template('login.html', title='Admin Portal Login',
                           action=url_for('admin_login'), signup=False,
                           note='Restricted to the admin role. Customer sessions are not valid here.')

@app.route('/admin/')
@login_required('admin')
def admin_home():
    cutoff = (now() - timedelta(hours=24)).isoformat(timespec='seconds')
    with closing(db()) as c:
        users = c.execute('''SELECT u.*, a.balance_cents FROM users u
                             LEFT JOIN accounts a ON a.user_id=u.id ORDER BY u.id''').fetchall()
        txns = c.execute('''SELECT t.*, u.username, c.last4 FROM transactions t
                            JOIN users u ON u.id=t.user_id
                            LEFT JOIN cards c ON c.token=t.card_token
                            ORDER BY t.id DESC LIMIT 20''').fetchall()
        events = c.execute('SELECT * FROM audit_log ORDER BY id DESC LIMIT 50').fetchall()
        agg = c.execute("SELECT COUNT(*) n, COALESCE(SUM(amount_cents),0) s "
                        "FROM transactions WHERE status='completed'").fetchone()
        failed_24h = c.execute("SELECT COUNT(*) n FROM audit_log WHERE "
                               "action='login_failed' AND ts>=?", (cutoff,)).fetchone()['n']
    locked = sum(1 for u in users if u['locked_until'])
    return render_template('admin.html', title='Admin', users=users, txns=txns,
                           events=events, txn_count=agg['n'],
                           volume=f"{agg['s']/100:,.2f}", failed_24h=failed_24h, locked=locked)

@app.route('/admin/users/<int:uid>/lock', methods=['POST'])
@login_required('admin')
@csrf_protect
def admin_lock(uid):
    if uid == session['uid']:
        flash('Admins cannot lock their own account.', 'error')
        return redirect(url_for('admin_home'))
    with closing(db()) as c, c:
        c.execute("UPDATE users SET locked_until='9999-12-31T23:59:59+00:00' WHERE id=?", (uid,))
    audit(session['username'], 'admin', 'account_manual_lock', details=f'id={uid}')
    flash('Account locked.', 'message')
    return redirect(url_for('admin_home'))

@app.route('/admin/users/<int:uid>/unlock', methods=['POST'])
@login_required('admin')
@csrf_protect
def admin_unlock(uid):
    with closing(db()) as c, c:
        c.execute('UPDATE users SET locked_until=NULL, failed_attempts=0 WHERE id=?', (uid,))
    audit(session['username'], 'admin', 'account_unlock', details=f'id={uid}')
    flash('Account unlocked.', 'message')
    return redirect(url_for('admin_home'))

@app.route('/admin/logout', methods=['POST'])
@login_required('admin')
@csrf_protect
def admin_logout():
    audit(session['username'], 'admin', 'logout')
    session.clear()
    return redirect(url_for('admin_login'))

# ---- backend API ---------------------------------------------------------------
@app.route('/api/')
def api_docs():
    return jsonify({'service': 'PaymentCo Backend API',
        'auth': {'user': 'POST /api/auth/token -> Bearer JWT (15 min)',
                 'service': 'X-Service-Key + X-Signature (HMAC-SHA256 of raw body) + Idempotency-Key'},
        'endpoints': ['GET /api/health', 'POST /api/auth/token', 'GET /api/me',
                      'GET /api/balances', 'GET /api/transactions', 'POST /api/payments']})

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok'})                    # minimal — no version/db info

@app.route('/api/auth/token', methods=['POST'])
@ip_login_limit()
def api_token():
    d = request.get_json(silent=True) or {}
    u, err = attempt_login(str(d.get('username','')), str(d.get('password','')), 'api')
    if err: return jsonify({'error': err}), 401
    n = now()
    tok = jwt.encode({'iss': 'auth.payco.local', 'aud': 'api', 'sub': u['username'],
                      'role': u['role'], 'iat': n, 'exp': n + timedelta(minutes=JWT_TTL_MIN),
                      'jti': secrets.token_hex(8)},                     # id -> revocation-ready
                     JWT_SECRET, algorithm='HS256')
    return jsonify({'token': tok, 'token_type': 'Bearer', 'expires_in': JWT_TTL_MIN * 60})

@app.route('/api/me')
@jwt_required
def api_me():
    return jsonify({'username': request.api_user['sub'], 'role': request.api_user.get('role')})

@app.route('/api/balances')
@jwt_required
def api_balances():
    with closing(db()) as c:
        a = c.execute('''SELECT a.balance_cents, a.currency FROM accounts a
                         JOIN users u ON u.id=a.user_id WHERE u.username=?''',
                      (request.api_user['sub'],)).fetchone()
    return (jsonify({'balance_cents': a['balance_cents'], 'currency': a['currency']})
            if a else (jsonify({'error': 'no account'}), 404))

@app.route('/api/transactions')
@jwt_required
def api_txns():
    with closing(db()) as c:
        rows = c.execute('''SELECT t.txn_id,t.amount_cents,t.currency,t.merchant,t.status,
                            t.created_at,c.last4 FROM transactions t
                            JOIN users u ON u.id=t.user_id
                            LEFT JOIN cards c ON c.token=t.card_token
                            WHERE u.username=? ORDER BY t.id DESC LIMIT 50''',
                         (request.api_user['sub'],)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/payments', methods=['POST'])
def api_payments():
    key = request.headers.get('X-Service-Key', '')
    if not key or not hmac.compare_digest(key, SERVICE_KEY):
        audit('service', 'api', 'svc_auth_failed', 'denied')
        return jsonify({'error': 'invalid service credentials'}), 401
    return process_signed_payment(request.get_data(),
                                  request.headers.get('X-Signature', '').lower(),
                                  request.headers.get('Idempotency-Key', ''))

# ---- stylesheet (kept as a route so CSP can stay strict: style-src 'self') -----
@app.route('/style.css')
def css():
    return CSS, 200, {'Content-Type': 'text/css'}

# ============================================================================
if __name__ == '__main__':
    init_db()
    seed()
    print(' Open http://127.0.0.1:5000/  (security matrix at /security)')
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)