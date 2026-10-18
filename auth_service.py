"""Authentication service for QM-5: Customer Registration with Email Verification."""
import hashlib
import os
import re

USERS = {}  # in-memory store: email -> {"password_hash": str, "status": str}
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def hash_password(password, salt=None):
    """Return 'salt:hash' using PBKDF2-HMAC-SHA256."""
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return salt.hex() + ":" + digest.hex()


def verify_password(password, stored):
    salt_hex, _ = stored.split(":")
    return hash_password(password, bytes.fromhex(salt_hex)) == stored


def register_user(email, password):
    """Register a user. Returns (http_status, payload)."""
    if not EMAIL_PATTERN.match(email) or len(password) < 12:
        return 400, {"error": "Invalid email or password too short"}
    if email in USERS:
        return 409, {"error": "An account with this email already exists"}
    USERS[email] = {"password_hash": hash_password(password),
                    "status": "pending_verification"}
    return 201, {"status": "pending_verification"}
