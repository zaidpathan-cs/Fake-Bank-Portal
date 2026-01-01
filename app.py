from flask import Flask, request, render_template, session, redirect, url_for, flash, jsonify, g, Blueprint
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3
import re
import json
import time
from contextlib import closing
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from collections import defaultdict
import html

app = Flask(__name__)
app.secret_key = 'insecure_secret_key_123!'  # Hardcoded secret
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Disabled secure flag
    SESSION_COOKIE_HTTPONLY=False,  # Accessible via JavaScript
    SESSION_COOKIE_SAMESITE=None,  # No CSRF protection
    PERMANENT_SESSION_LIFETIME=18000,
    DATABASE='vulnerable_bank.db',
    TEMPLATES_AUTO_RELOAD=True,
    WAF_LOG_FILE='waf_logs.json',
    WAF_ALERT_FILE='waf_alerts.json',
    WAF_LEARNING_MODE=True,
    WAF_PROTECTION_MODE=False,
    WAF_SQLI_SENSITIVITY=7,
    WAF_XSS_SENSITIVITY=8,
    REQUESTS_PER_MINUTE=100,
    REQUESTS_PER_HOUR=1000
)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["2400 per day", "100 per hour"]
)
limiter.init_app(app)

app.config['DB_INITIALIZED'] = False

# ============================
# WAF CONFIGURATION
# ============================
class WAFConfig:
    LEARNING_MODE = app.config['WAF_LEARNING_MODE']
    PROTECTION_MODE = app.config['WAF_PROTECTION_MODE']
    SQLI_SENSITIVITY = app.config['WAF_SQLI_SENSITIVITY']
    XSS_SENSITIVITY = app.config['WAF_XSS_SENSITIVITY']
    LOG_FILE = app.config['WAF_LOG_FILE']
    ALERT_FILE = app.config['WAF_ALERT_FILE']
    ADMIN_IPS = ["127.0.0.1", "::1"]
    BLOCKED_IPS = []
    REQUESTS_PER_MINUTE = app.config['REQUESTS_PER_MINUTE']
    REQUESTS_PER_HOUR = app.config['REQUESTS_PER_HOUR']

# ============================
# INPUT SANITIZER
# ============================
class InputSanitizer:
    @staticmethod
    def sanitize_sql(input_str):
        """Basic SQL injection prevention"""
        if not input_str:
            return input_str
        
        # Remove SQL comments
        input_str = re.sub(r'--.*$', '', input_str, flags=re.MULTILINE)
        input_str = re.sub(r'/\*.*?\*/', '', input_str, flags=re.DOTALL)
        
        # Escape single quotes (basic protection)
        input_str = input_str.replace("'", "''")
        
        # Remove common SQL keywords (for educational WAF)
        dangerous = ['UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 
                    'EXEC', 'EXECUTE', 'TRUNCATE', 'MERGE']
        
        for keyword in dangerous:
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            input_str = pattern.sub('[BLOCKED]', input_str)
        
        return input_str
    
    @staticmethod
    def sanitize_xss(input_str):
        """XSS prevention"""
        if not input_str:
            return input_str
        
        # HTML escape
        sanitized = html.escape(input_str)
        
        # Remove script tags and event handlers
        patterns = [
            (r'<script.*?>.*?</script>', '', re.IGNORECASE | re.DOTALL),
            (r'javascript:', '', re.IGNORECASE),
            (r'on\w+\s*=', '', re.IGNORECASE),
            (r'expression\s*\(', '', re.IGNORECASE),
            (r'vbscript:', '', re.IGNORECASE),
        ]
        
        for pattern, replacement, flags in patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=flags)
        
        return sanitized
    
    @staticmethod
    def validate_email(email):
        """Simple email validation"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_password(password):
        """Password strength validation"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain digit"
        
        return True, "Password is strong"

# ============================
# WAF MIDDLEWARE
# ============================
class WAFMiddleware:
    def __init__(self, app):
        self.app = app
        self.config = WAFConfig()
        self.request_log = defaultdict(list)
        self.patterns = self._load_patterns()
        self._setup_middleware()
    
    def _load_patterns(self):
        """Load attack patterns for SQLi and XSS detection"""
        return {
            'sql_injection': [
                (r'(\%27)|(\')|(\-\-)|(\%23)|(#)', 5),
                (r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))', 8),
                (r'\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))', 10),
                (r'(\%27)|(\')|(\-\-)|(\%00)|(/\*)|(\*/)|(<[>]?[xs]sscript)', 7),
                (r'union(\s|\+)+select', 10),
                (r'(\s|\+)+(or|and)(\s|\+)+[\w\s=]+(>|<|=|(\s|\+)+like(\s|\+)|\s+in\s*)', 9),
                (r'exec(\s|\+)+(s|x)p\w+', 10),
                (r'waitfor\s+delay', 9),
                (r'benchmark\s*\(', 8),
            ],
            'xss': [
                (r'<(script|iframe|embed|object|frameset|frame|svg)', 10),
                (r'javascript:', 8),
                (r'on\w+\s*=', 7),
                (r'<\s*img[^>]+src\s*=\s*[^>]+javascript:', 9),
                (r'<\s*a[^>]+href\s*=\s*[^>]+javascript:', 9),
                (r'<\s*body[^>]*onload', 10),
                (r'<\s*input[^>]*onfocus', 7),
                (r'expression\s*\(', 6),
                (r'vbscript:', 8),
                (r'alert\s*\(', 5),
                (r'document\.(cookie|location|domain)', 8),
            ],
            'path_traversal': [
                (r'\.\./(\.\./)*', 8),
                (r'etc/passwd', 9),
                (r'windows/win\.ini', 9),
                (r'\.\.\\', 8),
                (r'%2e%2e%2f', 8),
            ],
            'command_injection': [
                (r';\s*\w+', 7),
                (r'\|\s*\w+', 7),
                (r'&\s*\w+', 7),
                (r'\$\s*\(', 8),
                (r'`.*`', 9),
            ]
        }
    
    def _setup_middleware(self):
        """Setup Flask middleware hooks"""
        @self.app.before_request
        def before_request():
            g.waf_start_time = time.time()
            threats = self._check_request()
            if threats:
                g.waf_threats = threats
    
    def _check_request(self):
        """Analyze incoming request for threats"""
        threats = []
        ip = request.remote_addr
        
        # Check IP against blacklist
        if self._is_ip_blocked(ip):
            threats.append({'type': 'blocked_ip', 'severity': 10, 'source': 'ip', 'input': ip})
            if self.config.PROTECTION_MODE:
                return self._block_request("IP Blocked", 403)
        
        # Rate limiting
        if not self._check_rate_limit(ip):
            threats.append({'type': 'rate_limit', 'severity': 8, 'source': 'ip', 'input': ip})
            if self.config.PROTECTION_MODE:
                return self._block_request("Rate limit exceeded", 429)
        
        # SQL Injection detection
        sql_threats = self._detect_sql_injection()
        threats.extend(sql_threats)
        
        # XSS detection
        xss_threats = self._detect_xss()
        threats.extend(xss_threats)
        
        # Path traversal detection
        path_threats = self._detect_path_traversal()
        threats.extend(path_threats)
        
        # Command injection detection
        cmd_threats = self._detect_command_injection()
        threats.extend(cmd_threats)
        
        # Log threats if any
        if threats:
            self._log_threats(threats, ip)
            
            # Block if in protection mode
            if self.config.PROTECTION_MODE:
                total_severity = sum(t['severity'] for t in threats)
                if total_severity > self.config.SQLI_SENSITIVITY * len(threats):
                    return self._block_request(f"WAF Protection: {len(threats)} threats detected", 403)
        
        return threats
    
    def _detect_sql_injection(self):
        """Detect SQL injection attempts"""
        threats = []
        data_sources = [
            ('args', request.args),
            ('form', request.form),
            ('values', request.values),
            ('json', request.get_json(silent=True) or {}),
            ('headers', dict(request.headers)),
            ('cookies', request.cookies)
        ]
        
        for source_name, data in data_sources:
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, str):
                        threats.extend(self._check_patterns(value, 'sql_injection', 
                                                          f"{source_name}.{key}"))
        return threats
    
    def _detect_xss(self):
        """Detect XSS attempts"""
        threats = []
        data_sources = [
            ('args', request.args),
            ('form', request.form),
            ('values', request.values),
            ('json', request.get_json(silent=True) or {}),
            ('headers', dict(request.headers)),
            ('cookies', request.cookies)
        ]
        
        for source_name, data in data_sources:
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, str):
                        threats.extend(self._check_patterns(value, 'xss', 
                                                          f"{source_name}.{key}"))
        return threats
    
    def _detect_path_traversal(self):
        """Detect path traversal attempts"""
        threats = []
        if request.path:
            threats.extend(self._check_patterns(request.path, 'path_traversal', 'path'))
        return threats
    
    def _detect_command_injection(self):
        """Detect command injection attempts"""
        threats = []
        data_sources = [
            ('args', request.args),
            ('form', request.form),
            ('values', request.values),
            ('json', request.get_json(silent=True) or {}),
        ]
        
        for source_name, data in data_sources:
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, str):
                        threats.extend(self._check_patterns(value, 'command_injection', 
                                                          f"{source_name}.{key}"))
        return threats
    
    def _check_patterns(self, input_string, pattern_type, source):
        """Check input against attack patterns"""
        threats = []
        if not input_string:
            return threats
            
        for pattern, severity in self.patterns.get(pattern_type, []):
            if re.search(pattern, input_string, re.IGNORECASE):
                threat = {
                    'type': pattern_type,
                    'severity': severity,
                    'source': source,
                    'input': input_string[:100],  # Truncate for logging
                    'pattern': pattern,
                    'timestamp': time.time()
                }
                threats.append(threat)
        return threats
    
    def _check_rate_limit(self, ip):
        """Implement rate limiting"""
        current_time = time.time()
        minute_window = current_time - 60
        hour_window = current_time - 3600
        
        # Clean old entries
        self.request_log[ip] = [t for t in self.request_log[ip] if t > hour_window]
        
        # Check limits
        minute_count = sum(1 for t in self.request_log[ip] if t > minute_window)
        hour_count = len(self.request_log[ip])
        
        if minute_count > self.config.REQUESTS_PER_MINUTE:
            return False
        if hour_count > self.config.REQUESTS_PER_HOUR:
            return False
        
        self.request_log[ip].append(current_time)
        return True
    
    def _block_request(self, reason, status_code):
        """Block the request"""
        response = jsonify({
            'error': 'Request blocked by WAF',
            'reason': reason,
            'timestamp': time.time(),
            'mode': 'PROTECTION' if self.config.PROTECTION_MODE else 'LEARNING'
        })
        response.status_code = status_code
        return response
    
    def _log_threats(self, threats, ip):
        """Log detected threats"""
        log_entry = {
            'timestamp': time.time(),
            'ip': ip,
            'method': request.method,
            'path': request.path,
            'user_agent': request.user_agent.string if request.user_agent else None,
            'threats': threats,
            'blocked': self.config.PROTECTION_MODE
        }
        
        try:
            with open(self.config.LOG_FILE, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            # Also log to database
            self._log_to_db(log_entry)
        except Exception as e:
            print(f"Failed to log threat: {e}")
    
    def _log_to_db(self, log_entry):
        """Log to SQLite database"""
        try:
            conn = sqlite3.connect('vulnerable_bank.db')
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS waf_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    ip TEXT,
                    method TEXT,
                    path TEXT,
                    user_agent TEXT,
                    threat_type TEXT,
                    threat_details TEXT,
                    blocked INTEGER
                )
            ''')
            
            for threat in log_entry.get('threats', []):
                cursor.execute('''
                    INSERT INTO waf_logs 
                    (timestamp, ip, method, path, user_agent, threat_type, threat_details, blocked)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (log_entry['timestamp'], log_entry['ip'], log_entry['method'],
                      log_entry['path'], log_entry['user_agent'], 
                      threat['type'], json.dumps(threat), log_entry['blocked']))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Failed to log to DB: {e}")
    
    def _is_ip_blocked(self, ip):
        """Check if IP is in blacklist"""
        return ip in self.config.BLOCKED_IPS

# ============================
# DECORATORS & HELPER FUNCTIONS
# ============================
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

def waf_protected(f):
    """Decorator to add WAF protection to specific routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if hasattr(g, 'waf_threats') and g.waf_threats:
            if WAFConfig.PROTECTION_MODE:
                flash("Request blocked by WAF protection", "danger")
                return redirect(url_for('waf_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ============================
# DATABASE FUNCTIONS
# ============================
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

        # Create WAF logs table
        db.execute('''
            CREATE TABLE IF NOT EXISTS waf_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                ip TEXT,
                method TEXT,
                path TEXT,
                user_agent TEXT,
                threat_type TEXT,
                threat_details TEXT,
                blocked INTEGER
            )
        ''')

        # Create blocked IPs table
        db.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reason TEXT,
                blocked_by TEXT
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
        
        # Add test user for WAF testing
        if not db.execute("SELECT 1 FROM users WHERE username = 'waf_test'").fetchone():
            db.execute(f'''
                INSERT INTO users (username, password_hash, full_name, email, account_type, gender, dob, phone)
                VALUES ('waf_test', '{generate_password_hash("test123")}', 'WAF Test User', 'test@example.com', 'savings', 'male', '1990-01-01', '5551234')
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

# ============================
# WAF DASHBOARD BLUEPRINT
# ============================
waf_dashboard_bp = Blueprint('waf', __name__, url_prefix='/waf')

@waf_dashboard_bp.route('/admin')
@login_required
@admin_required
def waf_admin():
    """WAF Admin Dashboard"""
    with closing(get_db()) as db:
        # Get WAF statistics
        stats = db.execute('''
            SELECT 
                COUNT(*) as total_logs,
                SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_logs,
                COUNT(DISTINCT ip) as unique_ips,
                threat_type,
                COUNT(*) as count
            FROM waf_logs
            GROUP BY threat_type
        ''').fetchall()
        
        recent_logs = db.execute('''
            SELECT * FROM waf_logs 
            ORDER BY timestamp DESC 
            LIMIT 50
        ''').fetchall()
        
        blocked_ips = db.execute('SELECT * FROM blocked_ips ORDER BY blocked_at DESC').fetchall()
        
    return render_template('waf_dashboard.html', 
                         stats=stats, 
                         recent_logs=recent_logs, 
                         blocked_ips=blocked_ips,
                         config=WAFConfig())

@waf_dashboard_bp.route('/stats')
@login_required
@admin_required
def waf_stats():
    """Get WAF statistics in JSON format"""
    with closing(get_db()) as db:
        # Get stats for last 24 hours
        twenty_four_hours_ago = time.time() - 86400
        
        total_logs = db.execute('SELECT COUNT(*) FROM waf_logs WHERE timestamp > ?', 
                               (twenty_four_hours_ago,)).fetchone()[0]
        blocked_logs = db.execute('SELECT COUNT(*) FROM waf_logs WHERE blocked = 1 AND timestamp > ?', 
                                 (twenty_four_hours_ago,)).fetchone()[0]
        
        threat_types = db.execute('''
            SELECT threat_type, COUNT(*) as count 
            FROM waf_logs 
            WHERE timestamp > ? 
            GROUP BY threat_type
        ''', (twenty_four_hours_ago,)).fetchall()
        
        top_ips = db.execute('''
            SELECT ip, COUNT(*) as count 
            FROM waf_logs 
            WHERE timestamp > ? 
            GROUP BY ip 
            ORDER BY count DESC 
            LIMIT 10
        ''', (twenty_four_hours_ago,)).fetchall()
    
    return jsonify({
        'total_logs': total_logs,
        'blocked_logs': blocked_logs,
        'threat_types': dict(threat_types),
        'top_ips': dict(top_ips),
        'learning_mode': WAFConfig.LEARNING_MODE,
        'protection_mode': WAFConfig.PROTECTION_MODE
    })

@waf_dashboard_bp.route('/block_ip', methods=['POST'])
@login_required
@admin_required
def block_ip():
    """Block an IP address"""
    ip = request.json.get('ip')
    reason = request.json.get('reason', 'Manual block by admin')
    
    if ip:
        WAFConfig.BLOCKED_IPS.append(ip)
        with closing(get_db()) as db:
            db.execute('''
                INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_by)
                VALUES (?, ?, ?)
            ''', (ip, reason, session.get('username', 'admin')))
            db.commit()
        
        return jsonify({'status': 'success', 'message': f'IP {ip} blocked'})
    
    return jsonify({'status': 'error', 'message': 'No IP provided'}), 400

@waf_dashboard_bp.route('/unblock_ip', methods=['POST'])
@login_required
@admin_required
def unblock_ip():
    """Unblock an IP address"""
    ip = request.json.get('ip')
    
    if ip and ip in WAFConfig.BLOCKED_IPS:
        WAFConfig.BLOCKED_IPS.remove(ip)
        with closing(get_db()) as db:
            db.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
            db.commit()
        
        return jsonify({'status': 'success', 'message': f'IP {ip} unblocked'})
    
    return jsonify({'status': 'error', 'message': 'IP not found'}), 400

@waf_dashboard_bp.route('/toggle_mode', methods=['POST'])
@login_required
@admin_required
def toggle_waf_mode():
    """Toggle between learning and protection mode"""
    mode = request.json.get('mode')
    
    if mode == 'learning':
        WAFConfig.LEARNING_MODE = True
        WAFConfig.PROTECTION_MODE = False
    elif mode == 'protection':
        WAFConfig.LEARNING_MODE = False
        WAFConfig.PROTECTION_MODE = True
    elif mode == 'off':
        WAFConfig.LEARNING_MODE = False
        WAFConfig.PROTECTION_MODE = False
    else:
        return jsonify({'status': 'error', 'message': 'Invalid mode'}), 400
    
    return jsonify({
        'status': 'success',
        'message': f'WAF switched to {mode} mode',
        'learning_mode': WAFConfig.LEARNING_MODE,
        'protection_mode': WAFConfig.PROTECTION_MODE
    })

@waf_dashboard_bp.route('/test')
@login_required
@admin_required
def waf_test_page():
    """WAF test page"""
    test_cases = {
        'SQL Injection': [
            {"url": "/login", "method": "POST", "payload": {"username": "admin' OR '1'='1", "password": "test"}},
            {"url": "/dashboard", "method": "GET", "payload": {"user_id": "1 OR 1=1"}},
            {"url": "/profile", "method": "GET", "payload": {"id": "1'; DROP TABLE users; --"}},
        ],
        'XSS Attacks': [
            {"url": "/search", "method": "GET", "payload": {"q": "<script>alert('XSS')</script>"}},
            {"url": "/profile", "method": "POST", "payload": {"name": "<img src=x onerror=alert(1)>"}},
            {"url": "/dashboard", "method": "GET", "payload": {"query": "javascript:alert('XSS')"}},
        ],
        'Path Traversal': [
            {"url": "/../../etc/passwd", "method": "GET", "payload": {}},
            {"url": "/static/../../../config.py", "method": "GET", "payload": {}},
        ]
    }
    
    return render_template('waf_test.html', test_cases=test_cases)

# ============================
# APPLICATION ROUTES
# ============================
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("50 per minute")
@waf_protected
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Optional: Sanitize inputs in learning mode
        if not WAFConfig.PROTECTION_MODE:
            username = InputSanitizer.sanitize_sql(username)
            password = InputSanitizer.sanitize_sql(password)
        
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
@waf_protected
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
                           is_admin=session.get('is_admin', False),
                           waf_mode="PROTECTION" if WAFConfig.PROTECTION_MODE else "LEARNING")

@app.route('/profile')
@login_required
@waf_protected
def profile():
    with closing(get_db()) as db:
        user = db.execute(f'''
            SELECT username, full_name, email, account_type, gender, dob, phone
            FROM users WHERE id = {session['user_id']}
        ''').fetchone()
    return render_template('profile.html', user=user)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
@waf_protected
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Optional: Sanitize inputs
        if not WAFConfig.PROTECTION_MODE:
            current_password = InputSanitizer.sanitize_sql(current_password)
            new_password = InputSanitizer.sanitize_sql(new_password)
            confirm_password = InputSanitizer.sanitize_sql(confirm_password)
        
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
@waf_protected
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
                
                # Optional sanitization
                if not WAFConfig.PROTECTION_MODE:
                    username = InputSanitizer.sanitize_sql(username)
                    email = InputSanitizer.sanitize_sql(email)
                    password = InputSanitizer.sanitize_sql(password)

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
                
                # Optional sanitization
                if not WAFConfig.PROTECTION_MODE:
                    new_password = InputSanitizer.sanitize_sql(new_password)
                    confirm_password = InputSanitizer.sanitize_sql(confirm_password)

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

@app.route('/waf/status')
@login_required
def waf_status():
    """Check WAF status"""
    return jsonify({
        'learning_mode': WAFConfig.LEARNING_MODE,
        'protection_mode': WAFConfig.PROTECTION_MODE,
        'blocked_ips_count': len(WAFConfig.BLOCKED_IPS),
        'requests_per_minute': WAFConfig.REQUESTS_PER_MINUTE,
        'sqli_sensitivity': WAFConfig.SQLI_SENSITIVITY,
        'xss_sensitivity': WAFConfig.XSS_SENSITIVITY
    })

@app.before_request
def initialize_database():
    if not app.config['DB_INITIALIZED']:
        init_db()
        app.config['DB_INITIALIZED'] = True

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# ============================
# TEMPLATE CONTEXT PROCESSOR
# ============================
@app.context_processor
def inject_waf_status():
    """Inject WAF status into all templates"""
    return dict(
        waf_learning_mode=WAFConfig.LEARNING_MODE,
        waf_protection_mode=WAFConfig.PROTECTION_MODE,
        waf_blocked_count=len(WAFConfig.BLOCKED_IPS)
    )

# ============================
# INITIALIZE WAF & REGISTER BLUEPRINT
# ============================
waf = WAFMiddleware(app)
app.register_blueprint(waf_dashboard_bp)

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True, port=5001)
