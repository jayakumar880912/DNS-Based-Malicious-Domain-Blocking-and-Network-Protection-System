"""
AegisDNS - User Model
Database model for authentication and role-based user management.
"""

from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    full_name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='Cybersecurity Incident Lead')
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    def set_password(self, password: str):
        """Hashes password using secure PBKDF2/SHA256 via Werkzeug"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verifies password against stored cryptographic hash"""
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        initials = ''.join([part[0] for part in self.full_name.split() if part])[:2].upper() if self.full_name else 'SA'
        return {
            'id': self.id,
            'name': self.full_name,
            'fullName': self.full_name,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'avatarInitials': initials,
            'isActive': self.is_active,
            'lastLogin': self.last_login_at.isoformat() if self.last_login_at else None,
            'createdAt': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f"<User {self.username} ({self.email})>"

