"""
AegisDNS - Authentication Service
Handles registration, login, JWT issuance, profile updates, and password changes.
"""

from datetime import datetime, timezone
from flask_jwt_extended import create_access_token, get_jwt
from extensions import db, jwt_blocklist
from models.user import User
from services.activity_service import ActivityService
from utils.validators import validate_email, validate_username, validate_password, sanitize_string


class AuthService:
    @staticmethod
    def register(full_name: str, email: str, username: str, password: str, role: str = 'Security Analyst') -> dict:
        """
        Validates inputs, prevents duplicates, hashes password, and creates user.
        """
        # Validate Full Name
        if not full_name or len(full_name.strip()) < 2:
            raise ValueError("Full Name is required and must be at least 2 characters.")

        # Validate Email
        clean_email = email.strip().lower() if email else ""
        if not validate_email(clean_email):
            raise ValueError("Invalid email format.")

        # Check duplicate email
        if User.query.filter_by(email=clean_email).first():
            raise ValueError(f"Email '{clean_email}' is already registered.")

        # Validate Username
        valid_u, u_err = validate_username(username)
        if not valid_u:
            raise ValueError(u_err)
        clean_username = username.strip().lower()

        # Check duplicate username
        if User.query.filter_by(username=clean_username).first():
            raise ValueError(f"Username '{clean_username}' is already taken.")

        # Validate Password
        valid_p, p_err = validate_password(password)
        if not valid_p:
            raise ValueError(p_err)

        user = User(
            full_name=sanitize_string(full_name, 120),
            email=clean_email,
            username=clean_username,
            role=role,
            is_active=True,
            created_at=datetime.now(timezone.utc)
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        # Log Activity
        ActivityService.log(
            activity_type='User Registration',
            target=f"User: {clean_username}",
            status='SUCCESS',
            details=f"New security analyst profile registered: {clean_email}"
        )

        # Issue JWT Token
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={'username': user.username, 'role': user.role, 'email': user.email}
        )

        return {
            'success': True,
            'message': 'Registration successful.',
            'token': access_token,
            'user': user.to_dict()
        }

    @staticmethod
    def login(identifier: str, password: str) -> dict:
        """
        Authenticates user via username or email and issues JWT.
        """
        if not identifier or not password:
            raise ValueError("Username/Email and password are required.")

        clean_id = identifier.strip().lower()

        user = User.query.filter(
            (User.email == clean_id) | (User.username == clean_id)
        ).first()

        if not user or not user.check_password(password):
            ActivityService.log(
                activity_type='Failed Login Attempt',
                target=f"Account: {clean_id}",
                status='SUSPICIOUS',
                details="Invalid credentials provided during console sign in."
            )
            raise ValueError("Invalid credentials. Please verify your username/email and password.")

        if not user.is_active:
            raise ValueError("Account is deactivated. Please contact your Security Administrator.")

        # Update last login timestamp
        user.last_login_at = datetime.now(timezone.utc)
        db.session.commit()

        ActivityService.log(
            activity_type='User Authentication',
            target='Web Security Console',
            status='SUCCESS',
            actor=user.full_name,
            details=f"Successful analyst login session initiated."
        )

        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={'username': user.username, 'role': user.role, 'email': user.email}
        )

        return {
            'success': True,
            'message': 'Login successful.',
            'token': access_token,
            'user': user.to_dict()
        }

    @staticmethod
    def update_profile(user: User, full_name: str = None, email: str = None, role: str = None) -> dict:
        """Updates user profile information"""
        if full_name:
            user.full_name = sanitize_string(full_name, 120)
        if email:
            clean_email = email.strip().lower()
            if not validate_email(clean_email):
                raise ValueError("Invalid email format.")
            existing = User.query.filter_by(email=clean_email).first()
            if existing and existing.id != user.id:
                raise ValueError(f"Email '{clean_email}' is already in use by another account.")
            user.email = clean_email
        if role:
            user.role = sanitize_string(role, 50)

        db.session.commit()

        ActivityService.log(
            activity_type='Profile Updated',
            target=f"User: {user.username}",
            status='UPDATED',
            details='Analyst profile attributes modified.'
        )

        return user.to_dict()

    @staticmethod
    def change_password(user: User, current_password: str, new_password: str) -> bool:
        """Verifies current password and updates to new password"""
        if not user.check_password(current_password):
            raise ValueError("Current password is incorrect.")

        valid_p, p_err = validate_password(new_password)
        if not valid_p:
            raise ValueError(p_err)

        user.set_password(new_password)
        db.session.commit()

        ActivityService.log(
            activity_type='Password Changed',
            target=f"User: {user.username}",
            status='SUCCESS',
            details='Account master password updated with PBKDF2 cryptographic hash.'
        )
        return True

    @staticmethod
    def logout() -> bool:
        """Revokes the current JWT token by adding its jti to the blocklist"""
        try:
            jwt_data = get_jwt()
            jti = jwt_data.get('jti')
            if jti:
                jwt_blocklist.add(jti)
            return True
        except Exception:
            return False

