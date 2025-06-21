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
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800,
    DATABASE='bank_portal.db',
    TEMPLATES_AUTO_RELOAD=True
)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["2000 per day", "100 per hour"]
)
limiter.init_app(app)

# Decorator for login required
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Please log in to access this page", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator for admin required
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
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                full_name TEXT,
                account_type TEXT CHECK(account_type IN ('savings', 'current', 'joint', 'salary')),
                gender TEXT CHECK(gender IN ('male', 'female', 'other')),
                dob DATE,
                phone TEXT,
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                account_locked BOOLEAN DEFAULT FALSE,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create password history table
        db.execute('''
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                password_hash TEXT NOT NULL,
                changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        
        if not db.execute('SELECT 1 FROM users WHERE username = ?', ('admin',)).fetchone():
            db.execute('''
                INSERT INTO users 
                (username, password_hash, full_name, account_type, gender, email, dob, phone, is_admin)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', ('admin', generate_password_hash('admin123'), 'Admin User', 'current', 'other',
                  'admin@bank.com', '1970-01-01', '5550000', True))
        db.commit()

def is_password_strong(password):
    return (len(password) >= 8 and
            re.search(r'[A-Z]', password) and
            re.search(r'[a-z]', password) and
            re.search(r'[0-9]', password) and
            re.search(r'[^A-Za-z0-9]', password))

def check_password_history(user_id, new_password_hash):
    """Check if password was used before"""
    with closing(get_db()) as db:
        history = db.execute('''
            SELECT password_hash FROM password_history 
            WHERE user_id = ? 
            ORDER BY changed_at DESC 
            LIMIT 3
        ''', (user_id,)).fetchall()
        
        return any(check_password_hash(h[0], new_password_hash) for h in history)

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with closing(get_db()) as db:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            
            if user and check_password_hash(user[2], password):
                # Update last login
                db.execute(
                    "UPDATE users SET last_login = ? WHERE username = ?",
                    (datetime.now(), username)
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
            
            flash("Invalid username or password", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    with closing(get_db()) as db:
        accounts = db.execute('''
            SELECT account_type, gender, COUNT(*) as count
            FROM users
            GROUP BY account_type, gender
        ''').fetchall()

    account_stats = {
        'savings_female': 0,
        'savings_male': 0,
        'savings_other': 0,
        'current_female': 0,
        'current_male': 0,
        'current_other': 0,
        'joint_female': 0,
        'joint_male': 0,
        'joint_other': 0,
        'salary_female': 0,
        'salary_male': 0,
        'salary_other': 0,
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
        user = db.execute('''
            SELECT username, full_name, email, account_type, gender, dob, phone
            FROM users WHERE id = ?
        ''', (session['user_id'],)).fetchone()
        
    return render_template('profile.html', user=user)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        with closing(get_db()) as db:
            # Get user's current password hash
            user = db.execute(
                "SELECT password_hash FROM users WHERE id = ?", 
                (session['user_id'],)
            ).fetchone()
            
            if not user or not check_password_hash(user[0], current_password):
                flash("Current password is incorrect", "danger")
                return redirect(url_for('change_password'))
            
            # Validate new password
            if new_password != confirm_password:
                flash("New passwords do not match", "danger")
            elif not is_password_strong(new_password):
                flash("Password must contain 8+ chars with uppercase, lowercase, number and symbol", "danger")
            else:
                new_hash = generate_password_hash(new_password)
                
                # Check password history
                if check_password_history(session['user_id'], new_password):
                    flash("Cannot reuse one of your last 3 passwords", "danger")
                    return redirect(url_for('change_password'))
                
                # Update password
                db.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (new_hash, session['user_id'])
                )
                
                # Record in password history
                db.execute(
                    "INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)",
                    (session['user_id'], new_hash)
                )
                
                db.commit()
                flash("Password updated successfully!", "success")
                return redirect(url_for('profile'))
        
    return render_template('change_password.html')

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_users():
    message = None
    error = None

    with closing(get_db()) as db:
        if request.method == 'POST':
            form_action = request.form.get('form_action')

            if form_action == 'add':
                username = request.form['username']
                email = request.form['email']
                cursor = db.cursor()
                cursor.execute("SELECT 1 FROM users WHERE username = ? OR email = ?", (username, email))
                if cursor.fetchone():
                    error = "Username or email already exists"
                else:
                    password = request.form['password']
                    if not is_password_strong(password):
                        error = "Password must be strong"
                    else:
                        db.execute('''
                            INSERT INTO users (username, password_hash, email, full_name, account_type, gender, dob, phone)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            username,
                            generate_password_hash(password),
                            email,
                            request.form['full_name'],
                            request.form['account_type'],
                            request.form['gender'],
                            request.form['dob'],
                            request.form['phone']
                        ))
                        db.commit()
                        message = f"User {username} added successfully"

            elif form_action == 'update':
                user_id = request.form['user_id']
                cursor = db.cursor()
                cursor.execute('''
                    UPDATE users SET
                        full_name = ?,
                        email = ?,
                        account_type = ?,
                        gender = ?,
                        phone = ?
                    WHERE id = ?
                ''', (
                    request.form['full_name'],
                    request.form['email'],
                    request.form['account_type'],
                    request.form['gender'],
                    request.form['phone'],
                    user_id
                ))
                db.commit()
                if cursor.rowcount == 0:
                    error = "Update failed: user not found or no changes made"
                else:
                    message = "User updated successfully"

            elif form_action == 'delete':
                user_id = request.form['user_id']
                db.execute("DELETE FROM users WHERE id = ? AND username != 'admin'", (user_id,))
                db.commit()
                message = "User deleted successfully"

            elif form_action == 'change_password':
                user_id = request.form['user_id']
                new_password = request.form['new_password']
                confirm_password = request.form['confirm_password']
                cursor = db.cursor()
                cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
                user = cursor.fetchone()

                if not user:
                    error = "User not found"
                elif new_password != confirm_password:
                    error = "New passwords do not match"
                elif not is_password_strong(new_password):
                    error = "Password must be strong"
                else:
                    new_hash = generate_password_hash(new_password)
                    db.execute(
                        'UPDATE users SET password_hash = ? WHERE id = ?',
                        (new_hash, user_id)
                    )
                    
                    # Record in password history
                    db.execute(
                        "INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)",
                        (user_id, new_hash)
                    )
                    
                    db.commit()
                    message = "Password updated successfully"

        users = db.execute('''
            SELECT id, username, full_name, email, account_type, gender, phone 
            FROM users 
            WHERE username != 'admin'
        ''').fetchall()

        account_counts = {
            'total': db.execute("SELECT COUNT(*) FROM users WHERE username != 'admin'").fetchone()[0],
            'savings': db.execute("SELECT COUNT(*) FROM users WHERE account_type = 'savings' AND username != 'admin'").fetchone()[0],
            'current': db.execute("SELECT COUNT(*) FROM users WHERE account_type = 'current' AND username != 'admin'").fetchone()[0],
            'joint': db.execute("SELECT COUNT(*) FROM users WHERE account_type = 'joint' AND username != 'admin'").fetchone()[0],
            'salary': db.execute("SELECT COUNT(*) FROM users WHERE account_type = 'salary' AND username != 'admin'").fetchone()[0]
        }

    return render_template('manage_users.html',
                         users=users,
                         account_counts=account_counts,
                         message=message,
                         error=error,
                         is_admin=session.get('is_admin', False))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)