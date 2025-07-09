from flask import Flask, request, render_template, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3
import re
from contextlib import closing
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps

app = Flask(__name__)
app.secret_key = 'insecure_secret_key_123!'  # Hardcoded secret
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Disabled secure flag
    SESSION_COOKIE_HTTPONLY=False,  # Accessible via JavaScript
    SESSION_COOKIE_SAMESITE=None,  # No CSRF protection
    PERMANENT_SESSION_LIFETIME=18000,
    DATABASE='vulnerable_bank.db',
    TEMPLATES_AUTO_RELOAD=True
)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["2400 per day", "100 per hour"]
)
limiter.init_app(app)

app.config['DB_INITIALIZED'] = False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Please log in to access this page", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash("Admin access required", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def get_db():
    return sqlite3.connect(app.config['DATABASE'])

def init_db():
    with closing(get_db()) as db:
        db.execute("PRAGMA foreign_keys = OFF")  # Disabled foreign keys

        # Removed constraints
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                password_hash TEXT,
                email TEXT,
                full_name TEXT,
                account_type TEXT,
                gender TEXT,
                dob DATE,
                phone TEXT,
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                account_locked BOOLEAN DEFAULT FALSE,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        db.execute('''
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                password_hash TEXT,
                changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Vulnerable admin creation
        if not db.execute("SELECT 1 FROM users WHERE username = 'admin'").fetchone():
            db.execute(f'''
                INSERT INTO users
                (username, password_hash, full_name, account_type, gender, email, dob, phone, is_admin)
                VALUES ('admin', '{generate_password_hash("admin")}', 'Admin User', 'current', 'other',
                'admin@bank.com', '1970-01-01', '5550000', 1)
            ''')
        db.commit()

def is_password_strong(password):
    return len(password) >= 4  # Weaker requirements

def check_password_history(user_id, new_password_hash):
    with closing(get_db()) as db:
        history = db.execute(f'''
            SELECT password_hash FROM password_history
            WHERE user_id = {user_id}
            ORDER BY changed_at DESC
            LIMIT 3
        ''').fetchall()
        return any(check_password_hash(h[0], new_password_hash) for h in history)

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("50 per minute")
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with closing(get_db()) as db:
            # VULNERABLE: String interpolation
            query = f"SELECT * FROM users WHERE username = '{username}'"
            cursor = db.cursor()
            cursor.execute(query)
            user = cursor.fetchone()

            if user:  # No password check for demo purposes
                cursor.execute(
                    f"UPDATE users SET last_login = '{datetime.now()}' WHERE username = '{username}'"
                )
                db.commit()

                session['username'] = user[1]
                session['full_name'] = user[4]
                session['account_type'] = user[5]
                session['is_admin'] = bool(user[12])
                session['user_id'] = user[0]
                session['logged_in'] = True

                flash("Login successful", "success")
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid username"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    with closing(get_db()) as db:
        # VULNERABLE: Added OR 1=1
        accounts = db.execute(f'''
            SELECT account_type, gender, COUNT(*) as count
            FROM users
            WHERE id = {session['user_id']} OR 1=1
            GROUP BY account_type, gender
        ''').fetchall()

    account_stats = {
        'savings_female': 0, 'savings_male': 0, 'savings_other': 0,
        'current_female': 0, 'current_male': 0, 'current_other': 0,
        'joint_female': 0, 'joint_male': 0, 'joint_other': 0,
        'salary_female': 0, 'salary_male': 0, 'salary_other': 0,
        'joint_total': 0
    }

    for acc_type, gender, count in accounts:
        key = f"{acc_type.lower()}_{gender.lower()}"
        if key in account_stats:
            account_stats[key] = count
        if acc_type.lower() == 'joint':
            account_stats['joint_total'] += count

    return render_template('dashboard.html',
                           username=session['username'],
                           full_name=session['full_name'],
                           account_type=session['account_type'],
                           account_stats=account_stats,
                           is_admin=session.get('is_admin', False))

@app.route('/profile')
@login_required
def profile():
    with closing(get_db()) as db:
        user = db.execute(f'''
            SELECT username, full_name, email, account_type, gender, dob, phone
            FROM users WHERE id = {session['user_id']}
        ''').fetchone()
    return render_template('profile.html', user=user)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        with closing(get_db()) as db:
            user = db.execute(
                f"SELECT password_hash FROM users WHERE id = {session['user_id']}"
            ).fetchone()
            if not user or not check_password_hash(user[0], current_password):
                flash("Current password is incorrect", "danger")
                return redirect(url_for('change_password'))

            if new_password != confirm_password:
                flash("New passwords do not match", "danger")
            elif not is_password_strong(new_password):
                flash("Password must be stronger", "danger")
            elif check_password_history(session['user_id'], new_password):
                flash("Cannot reuse last 3 passwords", "danger")
            else:
                new_hash = generate_password_hash(new_password)
                db.execute(
                    f"UPDATE users SET password_hash = '{new_hash}' WHERE id = {session['user_id']}"
                )
                db.execute(
                    f"INSERT INTO password_history (user_id, password_hash) VALUES ({session['user_id']}, '{new_hash}')"
                )
                db.commit()
                flash("Password updated", "success")
                return redirect(url_for('profile'))
    return render_template('change_password.html')

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_users():
    message, error = None, None
    with closing(get_db()) as db:
        cursor = db.cursor()

        if request.method == 'POST':
            form_action = request.form.get('form_action')

            if form_action == 'add':
                username = request.form['username']
                email = request.form['email']
                password = request.form['password']

                # 🔥 Unsafe SQL Injection point
                check_query = f"SELECT 1 FROM users WHERE username = '{username}' OR email = '{email}'"
                check = cursor.execute(check_query).fetchone()

                if check:
                    error = "Username or email exists"
                elif not is_password_strong(password):
                    error = "Weak password"
                else:
                    # 🔥 Unsafe INSERT
                    insert_query = f'''
                        INSERT INTO users (username, password_hash, email, full_name, account_type, gender, dob, phone)
                        VALUES ('{username}', '{generate_password_hash(password)}', '{email}',
                        '{request.form['full_name']}', '{request.form['account_type']}',
                        '{request.form['gender']}', '{request.form['dob']}', '{request.form['phone']}')
                    '''
                    cursor.execute(insert_query)
                    db.commit()
                    message = f"User {username} added"

            elif form_action == 'update':
                # 🔥 Vulnerable to SQLi
                update_query = f'''
                    UPDATE users SET
                        full_name = '{request.form['full_name']}',
                        email = '{request.form['email']}',
                        account_type = '{request.form['account_type']}',
                        gender = '{request.form['gender']}',
                        phone = '{request.form['phone']}'
                    WHERE id = {request.form['user_id']}
                '''
                cursor.execute(update_query)
                db.commit()
                message = "User updated"

            elif form_action == 'delete':
                # 🔥 Vulnerable to SQLi
                delete_query = f"DELETE FROM users WHERE id = {request.form['user_id']} AND username != 'admin'"
                cursor.execute(delete_query)
                db.commit()
                message = "User deleted"

            elif form_action == 'change_password':
                user_id = request.form['user_id']
                new_password = request.form['new_password']
                confirm_password = request.form['confirm_password']

                if new_password != confirm_password:
                    error = "Passwords do not match"
                elif not is_password_strong(new_password):
                    error = "Weak password"
                else:
                    new_hash = generate_password_hash(new_password)
                    # 🔥 Unsafe SQL injection point
                    cursor.execute(f"UPDATE users SET password_hash = '{new_hash}' WHERE id = {user_id}")
                    cursor.execute(f"INSERT INTO password_history (user_id, password_hash) VALUES ({user_id}, '{new_hash}')")
                    db.commit()
                    message = "Password updated"

        # Keep these safe queries for user listing
        users = db.execute('SELECT id, username, full_name, email, account_type, gender, phone FROM users WHERE username != "admin"').fetchall()
        account_counts = {
            'total': db.execute('SELECT COUNT(*) FROM users WHERE username != "admin"').fetchone()[0],
            'savings': db.execute('SELECT COUNT(*) FROM users WHERE account_type = "savings" AND username != "admin"').fetchone()[0],
            'current': db.execute('SELECT COUNT(*) FROM users WHERE account_type = "current" AND username != "admin"').fetchone()[0],
            'joint': db.execute('SELECT COUNT(*) FROM users WHERE account_type = "joint" AND username != "admin"').fetchone()[0],
            'salary': db.execute('SELECT COUNT(*) FROM users WHERE account_type = "salary" AND username != "admin"').fetchone()[0],
        }

    return render_template('manage_users.html',
                           users=users,
                           account_counts=account_counts,
                           message=message,
                           error=error,
                           is_admin=session.get('is_admin', False))


@app.before_request
def initialize_database():
    if not app.config['DB_INITIALIZED']:
        init_db()
        app.config['DB_INITIALIZED'] = True

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True, port=5001)
