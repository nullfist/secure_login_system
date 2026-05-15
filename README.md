# 🔐 Secure Authentication Platform

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Web: Security](https://img.shields.io/badge/Web-Security-orange.svg)]()

An enterprise-grade Secure Authentication Platform implementing modern web security principles, OWASP best practices, and identity protection mechanisms.

Developed by **Syed**.

## 🛡️ Security Implementations

- **Argon2id Hashing**: Industry-standard password storage resistant to GPU cracking and side-channel attacks.
- **MFA (2FA)**: TOTP-based Multi-Factor Authentication with QR code provisioning.
- **Session Security**: HttpOnly, Secure, and SameSite cookie policies with automatic expiration.
- **Defensive Controls**: CSRF protection, SQL injection prevention (ORM), and XSS sanitization.
- **Audit Logging**: Comprehensive tracking of login success, failures, and system events for forensics.
- **RBAC**: Role-Based Access Control framework for administrative management.

## 🚀 Features

- Secure User Registration with complexity validation.
- Interactive Dashboard for account security monitoring.
- Login Threat Detection for multiple failed attempts.
- Modern Cybersecurity-inspired UI.

## 🛠️ Tech Stack

- **Backend**: Flask 3.0+
- **Database**: SQLite / SQLAlchemy
- **Security**: `argon2-cffi`, `pyotp`, `flask-login`
- **UI**: CSS3 (Cyber-dark theme), HTML5

## 📦 Installation

```bash
git clone https://github.com/Syed/secure-login.git
cd secure-login
python -m venv venv
source venv/bin/activate # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 🖥️ Usage

Run the application:
```bash
python app.py
```
*Note: The database is initialized automatically on the first run.*

## 📋 Security Compliance
- ✅ **OWASP A01:2021** - Broken Access Control Prevention
- ✅ **OWASP A07:2021** - Identification and Authentication Failures Prevention
- ✅ **OWASP A03:2021** - Injection Prevention

## 🤝 Contributing
Contributions are encouraged. Please follow the security coding standards.
