"""
AegisDNS - Security & Authorization Utilities
Role-based access decorators and token inspection helpers.
"""

from functools import wraps
from flask import jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
from models.user import User


def get_current_user_obj():
    """Returns current authenticated User instance or None"""
    try:
        verify_jwt_in_request(optional=True)
        identity = get_jwt_identity()
        if not identity:
            return None
        return User.query.filter((User.id == identity) | (User.username == identity)).first()
    except Exception:
        return None


def admin_required():
    """
    Decorator to restrict access to administrator or incident lead roles.
    """
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            role = claims.get('role', '')
            user = get_current_user_obj()
            if not user or ('admin' not in user.role.lower() and 'lead' not in user.role.lower() and 'admin' not in role.lower()):
                return jsonify({
                    'success': False,
                    'error': 'Forbidden',
                    'message': 'Administrative privileges required to perform this action.'
                }), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper

