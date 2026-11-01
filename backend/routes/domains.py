"""
AegisDNS - Domain Security Checker Routes
Endpoints for inspecting domain security posture, entropy scoring, and retrieval of inspection history.
"""

from flask import Blueprint, request, jsonify
from services.domain_checker_service import DomainCheckerService
from utils.security import get_current_user_obj

domains_bp = Blueprint('domains', __name__)


@domains_bp.route('/api/domains/check', methods=['POST'])
@domains_bp.route('/api/check-domain', methods=['POST']) # Compatibility alias for frontend
def check_domain():
    """
    POST /api/domains/check or POST /api/check-domain
    Receives a domain name, analyzes threat intel, checks blocklist, runs dnspython,
    and returns SAFE, MALICIOUS, or SUSPICIOUS security evaluation.
    """
    data = request.get_json() or {}
    domain = data.get('domain')

    if not domain:
        return jsonify({'success': False, 'message': 'Domain parameter is required.', 'error': 'Bad Request'}), 400

    user = get_current_user_obj()
    user_id = user.id if user else None
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1').split(',')[0].strip()

    try:
        result = DomainCheckerService.check_domain(
            raw_domain=domain,
            user_id=user_id,
            client_ip=client_ip
        )
        return jsonify(result), 200
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e), 'error': 'Validation Error'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': 'Domain security check failed.', 'error': str(e)}), 500


@domains_bp.route('/api/domains/history', methods=['GET'])
def get_history():
    """
    GET /api/domains/history
    Returns recent domain security evaluations.
    """
    limit = request.args.get('limit', 20, type=int)
    history = DomainCheckerService.get_history(limit=limit)
    return jsonify({'success': True, 'history': history, 'count': len(history)}), 200

