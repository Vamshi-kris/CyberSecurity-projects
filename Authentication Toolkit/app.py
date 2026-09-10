from flask import Flask, render_template_string, request, session, redirect, url_for
import string
import secrets
from collections import defaultdict

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # needed for session management

# Predefined credentials (Module 2)
VALID_USERNAME = "admin"
VALID_PASSWORD = "SecureP@ss123"
MAX_ATTEMPTS = 3

# HTML template for the entire app (single page)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure Authentication Simulator</title>
    <style>
        body { font-family: Arial; max-width: 700px; margin: auto; padding: 20px; }
        .module { border: 1px solid #ccc; border-radius: 8px; padding: 15px; margin: 15px 0; }
        h2 { color: #2c3e50; }
        .alert { background: #f8d7da; padding: 10px; border-radius: 5px; }
        .success { background: #d4edda; padding: 10px; border-radius: 5px; }
        button { padding: 8px 16px; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #2980b9; }
        input[type="text"], input[type="password"], input[type="number"] { padding: 6px; width: 200px; }
        label { display: inline-block; width: 200px; margin: 4px 0; }
        .locked { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <h1>🔐 Secure Authentication Simulator</h1>

    <!-- Module 1: Password Strength Checker -->
    <div class="module">
        <h2>1. Password Strength Checker</h2>
        <form method="POST" action="/check_strength">
            <input type="text" name="password" placeholder="Enter password" required>
            <button type="submit">Check Strength</button>
        </form>
        {% if strength_result %}
        <p>Strength: <strong>{{ strength_result }}</strong> (Score: {{ score }})</p>
        {% endif %}
    </div>

    <!-- Module 2: Login Lockout Simulator -->
    <div class="module">
        <h2>2. Login Lockout Simulator</h2>
        {% if session.get('account_locked') %}
        <p class="locked">🔒 ACCOUNT LOCKED. No further login attempts allowed.</p>
        <form method="POST" action="/reset_lockout">
            <button type="submit">Reset Lockout (Admin)</button>
        </form>
        {% else %}
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required><br><br>
            <input type="password" name="password" placeholder="Password" required><br><br>
            <button type="submit">Login</button>
        </form>
        <p>Attempts remaining: {{ remaining_attempts }}</p>
        {% endif %}
        {% if login_message %}
        <p class="{% if 'successful' in login_message %}success{% else %}alert{% endif %}">{{ login_message }}</p>
        {% endif %}
    </div>

    <!-- Module 3: Secure Password Generator -->
    <div class="module">
        <h2>3. Secure Password Generator</h2>
        <form method="POST" action="/generate">
            <label>Length:</label> <input type="number" name="length" min="4" value="16" required><br>
            <input type="checkbox" name="upper" checked> Uppercase<br>
            <input type="checkbox" name="lower" checked> Lowercase<br>
            <input type="checkbox" name="digits" checked> Numbers<br>
            <input type="checkbox" name="special" checked> Special<br><br>
            <button type="submit">Generate</button>
        </form>
        {% if generated_password %}
        <p>Your password: <strong>{{ generated_password }}</strong></p>
        {% endif %}
        {% if gen_error %}
        <p class="alert">{{ gen_error }}</p>
        {% endif %}
    </div>

    <!-- Module 4: Brute Force Attack Detection -->
    <div class="module">
        <h2>4. Brute Force Attack Detection</h2>
        <form method="POST" action="/detect_brute">
            <button type="submit">Run Detection on Sample Data</button>
        </form>
        {% if brute_result %}
        <h3>Results:</h3>
        {% if brute_result|length == 0 %}
        <p>No suspicious IPs detected.</p>
        {% else %}
        <ul>
        {% for ip, count in brute_result.items() %}
            <li>🚨 IP: {{ ip }} – {{ count }} failed attempts</li>
        {% endfor %}
        </ul>
        <p>Total flagged IPs: {{ brute_result|length }}</p>
        {% endif %}
        {% endif %}
    </div>

    <!-- Module 5: Password Guessing Detection -->
    <div class="module">
        <h2>5. Password Guessing Detection</h2>
        <form method="POST" action="/detect_guessing">
            <button type="submit">Run Detection on Sample Data</button>
        </form>
        {% if guess_result %}
        <h3>Results:</h3>
        {% if guess_result|length == 0 %}
        <p>No password guessing attacks detected.</p>
        {% else %}
        <ul>
        {% for user, distinct in guess_result.items() %}
            <li>🚨 User: {{ user }} – {{ distinct }} different passwords tried</li>
        {% endfor %}
        </ul>
        <p>Total targeted users: {{ guess_result|length }}</p>
        {% endif %}
        {% endif %}
    </div>
</body>
</html>
"""

# ---------- Helper functions (reuse from original) ----------
def password_strength_checker(password):
    score = 0
    length = len(password)
    if length >= 12: score += 2
    elif length >= 8: score += 1
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    if has_upper: score += 1
    if has_lower: score += 1
    if has_digit: score += 1
    if has_special: score += 1
    if score <= 2: strength = "Weak"
    elif score <= 4: strength = "Moderate"
    else: strength = "Strong"
    return strength, score

def generate_secure_password(length, upper, lower, digits, special):
    pool = ""
    mandatory = []
    if upper:
        pool += string.ascii_uppercase
        mandatory.append(secrets.choice(string.ascii_uppercase))
    if lower:
        pool += string.ascii_lowercase
        mandatory.append(secrets.choice(string.ascii_lowercase))
    if digits:
        pool += string.digits
        mandatory.append(secrets.choice(string.digits))
    if special:
        pool += string.punctuation
        mandatory.append(secrets.choice(string.punctuation))
    if not pool:
        raise ValueError("Select at least one character type")
    if length < len(mandatory):
        raise ValueError(f"Length must be at least {len(mandatory)}")
    remaining = [secrets.choice(pool) for _ in range(length - len(mandatory))]
    pwd_list = mandatory + remaining
    secrets.SystemRandom().shuffle(pwd_list)
    return ''.join(pwd_list)

def detect_brute_force(attempts):
    failed = defaultdict(int)
    for a in attempts:
        if not a.get('success', True):
            ip = a.get('ip')
            if ip: failed[ip] += 1
    return {ip: cnt for ip, cnt in failed.items() if cnt >= 3}

def detect_password_guessing(attempts):
    user_pwds = defaultdict(set)
    for a in attempts:
        if not a.get('success', True):
            user = a.get('username')
            pwd = a.get('password')
            if user and pwd:
                user_pwds[user].add(pwd)
    return {u: len(passwords) for u, passwords in user_pwds.items() if len(passwords) > 1}

# ---------- Routes ----------
@app.route('/')
def index():
    # Initial / default template values
    return render_template_string(HTML_TEMPLATE,
                                  remaining_attempts=MAX_ATTEMPTS - session.get('failed', 0),
                                  login_message=None,
                                  strength_result=None,
                                  score=None,
                                  generated_password=None,
                                  gen_error=None,
                                  brute_result=None,
                                  guess_result=None)

@app.route('/check_strength', methods=['POST'])
def check_strength():
    pwd = request.form.get('password', '')
    strength, score = password_strength_checker(pwd) if pwd else ("N/A", 0)
    return render_template_string(HTML_TEMPLATE,
                                  strength_result=strength,
                                  score=score,
                                  remaining_attempts=MAX_ATTEMPTS - session.get('failed', 0),
                                  login_message=None,
                                  generated_password=None,
                                  gen_error=None,
                                  brute_result=None,
                                  guess_result=None)

@app.route('/login', methods=['POST'])
def login():
    if session.get('account_locked'):
        msg = "🔒 Account locked."
        rem = 0
        return render_template_string(HTML_TEMPLATE, login_message=msg, remaining_attempts=rem,
                                      strength_result=None, generated_password=None, gen_error=None,
                                      brute_result=None, guess_result=None)
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    if username == VALID_USERNAME and password == VALID_PASSWORD:
        session['failed'] = 0
        msg = "✅ Login successful!"
        rem = MAX_ATTEMPTS
        return render_template_string(HTML_TEMPLATE, login_message=msg, remaining_attempts=rem,
                                      strength_result=None, generated_password=None, gen_error=None,
                                      brute_result=None, guess_result=None)
    else:
        session['failed'] = session.get('failed', 0) + 1
        remaining = MAX_ATTEMPTS - session['failed']
        if remaining <= 0:
            session['account_locked'] = True
            msg = "❌ Account locked after too many failures."
            rem = 0
        else:
            msg = f"❌ Login failed. {remaining} attempt(s) left."
            rem = remaining
        return render_template_string(HTML_TEMPLATE, login_message=msg, remaining_attempts=rem,
                                      strength_result=None, generated_password=None, gen_error=None,
                                      brute_result=None, guess_result=None)

@app.route('/reset_lockout', methods=['POST'])
def reset_lockout():
    session.pop('account_locked', None)
    session['failed'] = 0
    return redirect(url_for('index'))

@app.route('/generate', methods=['POST'])
def generate():
    try:
        length = int(request.form.get('length', 16))
        upper = 'upper' in request.form
        lower = 'lower' in request.form
        digits = 'digits' in request.form
        special = 'special' in request.form
        pwd = generate_secure_password(length, upper, lower, digits, special)
        return render_template_string(HTML_TEMPLATE, generated_password=pwd,
                                      remaining_attempts=MAX_ATTEMPTS - session.get('failed', 0),
                                      login_message=None, strength_result=None, gen_error=None,
                                      brute_result=None, guess_result=None)
    except ValueError as e:
        return render_template_string(HTML_TEMPLATE, gen_error=str(e),
                                      remaining_attempts=MAX_ATTEMPTS - session.get('failed', 0),
                                      login_message=None, strength_result=None, generated_password=None,
                                      brute_result=None, guess_result=None)

@app.route('/detect_brute', methods=['POST'])
def detect_brute():
    sample = [
        {"ip": "192.168.1.10", "username": "alice", "success": False},
        {"ip": "192.168.1.10", "username": "alice", "success": False},
        {"ip": "192.168.1.10", "username": "alice", "success": False},
        {"ip": "192.168.1.10", "username": "bob",   "success": True},
        {"ip": "10.0.0.5",     "username": "carol", "success": False},
        {"ip": "10.0.0.5",     "username": "carol", "success": False},
        {"ip": "10.0.0.5",     "username": "carol", "success": False},
        {"ip": "10.0.0.5",     "username": "carol", "success": False},
        {"ip": "172.16.0.1",   "username": "dave",  "success": False},
        {"ip": "172.16.0.1",   "username": "dave",  "success": True},
        {"ip": "192.168.1.20", "username": "eve",   "success": True},
    ]
    flagged = detect_brute_force(sample)
    return render_template_string(HTML_TEMPLATE, brute_result=flagged,
                                  remaining_attempts=MAX_ATTEMPTS - session.get('failed', 0),
                                  login_message=None, strength_result=None, generated_password=None,
                                  gen_error=None, guess_result=None)

@app.route('/detect_guessing', methods=['POST'])
def detect_guessing():
    sample = [
        {"username": "alice", "password": "pass1", "success": False},
        {"username": "alice", "password": "pass2", "success": False},
        {"username": "alice", "password": "pass3", "success": False},
        {"username": "bob",   "password": "123456", "success": False},
        {"username": "bob",   "password": "123456", "success": False},
        {"username": "carol", "password": "abc",    "success": True},
        {"username": "dave",  "password": "qwerty", "success": False},
        {"username": "dave",  "password": "asdfgh", "success": False},
        {"username": "dave",  "password": "zxcvbn", "success": False},
    ]
    flagged = detect_password_guessing(sample)
    return render_template_string(HTML_TEMPLATE, guess_result=flagged,
                                  remaining_attempts=MAX_ATTEMPTS - session.get('failed', 0),
                                  login_message=None, strength_result=None, generated_password=None,
                                  gen_error=None, brute_result=None)

if __name__ == '__main__':
    app.run(debug=True)