"""
security.py – Core Security Engine for Secure Login System
  Implements Argon2 hashing, TOTP MFA, and password validation.
"""

import re
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

def hash_password(password: str) -> str:
    """Hash a password using Argon2id."""
    return ph.hash(password)

def verify_password(hashed: str, password: str) -> bool:
    """Verify a password against an Argon2 hash."""
    try:
        return ph.verify(hashed, password)
    except VerifyMismatchError:
        return False

def validate_password_complexity(password: str) -> bool:
    """
    Enforce strong password policy:
    - Min 12 characters
    - At least one uppercase
    - At least one lowercase
    - At least one digit
    - At least one special character
    """
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def generate_totp_secret() -> str:
    """Generate a random base32 secret for TOTP MFA."""
    return pyotp.random_base32()

def get_totp_uri(username: str, secret: str) -> str:
    """Get the provisioning URI for QR code generation."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureAuth")

def verify_totp(secret: str, token: str) -> bool:
    """Verify a TOTP token."""
    totp = pyotp.TOTP(secret)
    return totp.verify(token)
