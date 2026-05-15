import os
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, AuditLog
from security import hash_password, verify_password, validate_password_complexity, verify_totp
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-7281928374')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Security Headers Configuration
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_event(action, user_id=None, status='success'):
    ip = request.remote_addr
    log = AuditLog(user_id=user_id, action=action, ip_address=ip, status=status)
    db.session.add(log)
    db.session.commit()

# ── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
            
        if not validate_password_complexity(password):
            flash('Password must be 12+ chars with upper, lower, digits, and symbols', 'warning')
            return redirect(url_for('register'))
            
        new_user = User(
            username=username,
            email=email,
            password_hash=hash_password(password)
        )
        db.session.add(new_user)
        db.session.commit()
        
        log_event(f"User registered: {username}", user_id=new_user.id)
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and verify_password(user.password_hash, password):
            if user.mfa_enabled:
                session['mfa_user_id'] = user.id
                return redirect(url_for('mfa_verify'))
            
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            log_event("User logged in", user_id=user.id)
            return redirect(url_for('dashboard'))
        else:
            log_event(f"Failed login attempt: {username}", status='failure')
            flash('Invalid credentials', 'danger')
            
    return render_template('login.html')

@app.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    user_id = session.get('mfa_user_id')
    if not user_id:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        token = request.form.get('token')
        user = User.query.get(user_id)
        if verify_totp(user.mfa_secret, token):
            login_user(user)
            session.pop('mfa_user_id')
            return redirect(url_for('dashboard'))
        flash('Invalid MFA token', 'danger')
        
    return render_template('mfa_verify.html')

@app.route('/dashboard')
@login_required
def dashboard():
    logs = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).limit(10).all()
    return render_template('dashboard.html', user=current_user, logs=logs)

@app.route('/logout')
@login_required
def logout():
    log_event("User logged out", user_id=current_user.id)
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
