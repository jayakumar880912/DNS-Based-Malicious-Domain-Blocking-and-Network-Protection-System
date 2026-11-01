"""
AegisDNS - Authentication Routes Blueprint
Endpoints for registration, login, profile retrieval, password updates, and logout.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from services.auth_service import AuthService
from utils.security import get_current_user_obj

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    POST /api/auth/register
    Registers a new security analyst account.
    """
    data = request.get_json() or {}
    full_name = data.get('fullName') or data.get('name')
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'Security Analyst')

    try:
        result = AuthService.register(
            full_name=full_name,
            email=email,
            username=username,
            password=password,
            role=role
        )
        return jsonify(result), 201
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e), 'error': 'Validation Error'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': 'Internal registration error.', 'error': str(e)}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    POST /api/auth/login
    Authenticates user and returns JWT access token.
    """
    data = request.get_json() or {}
    identifier = data.get('identifier') or data.get('username') or data.get('email')
    password = data.get('password')

    try:
        result = AuthService.login(identifier=identifier, password=password)
        return jsonify(result), 200
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e), 'error': 'Unauthorized'}), 401
    except Exception as e:
        return jsonify({'success': False, 'message': 'Authentication failed.', 'error': str(e)}), 500


@auth_bp.route('/profile', methods=['GET', 'PUT'])
def profile():
    """
    GET /api/auth/profile: Returns currently authenticated analyst profile.
    PUT /api/auth/profile: Updates profile details.
    """
    user = get_current_user_obj()
    if not user:
        return jsonify({'success': False, 'message': 'Authentication required.'}), 401

    if request.method == 'GET':
        return jsonify({'success': True, 'user': user.to_dict()}), 200

    # PUT update
    data = request.get_json() or {}
    full_name = data.get('fullName') or data.get('name')
    email = data.get('email')
    role = data.get('role')

    try:
        updated_dict = AuthService.update_profile(user, full_name=full_name, email=email, role=role)
        return jsonify({'success': True, 'message': 'Profile updated successfully.', 'user': updated_dict}), 200
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400


@auth_bp.route('/change-password', methods=['POST'])
def change_password():
    """
    POST /api/auth/change-password
    Changes master password.
    """
    user = get_current_user_obj()
    if not user:
        return jsonify({'success': False, 'message': 'Authentication required.'}), 401

    data = request.get_json() or {}
    current_pass = data.get('currentPassword')
    new_pass = data.get('newPassword')

    try:
        AuthService.change_password(user, current_password=current_pass, new_password=new_pass)
        return jsonify({'success': True, 'message': 'Password updated successfully.'}), 200
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400


@auth_bp.route('/logout', methods=['POST'])
@jwt_required(optional=True)
def logout():
    """
    POST /api/auth/logout
    Invalidates current JWT token.
    """
    AuthService.logout()
    return jsonify({'success': True, 'message': 'Successfully logged out.'}), 200

