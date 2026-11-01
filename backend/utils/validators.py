"""
AegisDNS - Input Validation Utilities
Validates emails, usernames, passwords, and sanitizes user input.
"""

import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_]{3,30}$')


def validate_email(email: str) -> bool:
    """Verifies email structure"""
    if not email or not isinstance(email, str):
        return False
    return bool(EMAIL_REGEX.match(email.strip()))


def validate_username(username: str) -> tuple[bool, str]:
    """Validates alphanumeric username of length 3-30"""
    if not username or not isinstance(username, str):
        return False, "Username is required."
    clean = username.strip()
    if len(clean) < 3:
        return False, "Username must be at least 3 characters long."
    if len(clean) > 30:
        return False, "Username cannot exceed 30 characters."
    if not USERNAME_REGEX.match(clean):
        return False, "Username can only contain alphanumeric characters and underscores."
    return True, ""


def validate_password(password: str) -> tuple[bool, str]:
    """
    Enforces cybersecurity password complexity:
    - Minimum 8 characters
    - Must contain at least one letter and at least one digit or special character
    """
    if not password or not isinstance(password, str):
        return False, "Password is required."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(c.isalpha() for c in password):
        return False, "Password must contain at least one alphabetical letter."
    if not (any(c.isdigit() for c in password) or any(not c.isalnum() for c in password)):
        return False, "Password must contain at least one number or special symbol."
    return True, ""


def sanitize_string(text: str, max_length: int = 255) -> str:
    """Strips leading/trailing whitespace and limits length"""
    if not text:
        return ""
    return str(text).strip()[:max_length]

