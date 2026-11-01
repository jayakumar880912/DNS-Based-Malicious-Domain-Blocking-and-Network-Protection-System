"""
AegisDNS - Blocked Domains Management Routes
Endpoints for managing the active DNS sinkhole blocklist (viewing, adding, removing).
"""

from datetime import datetime, timezone
import uuid
from flask import Blueprint, request, jsonify
from extensions import db
from models.domain import BlockedDomain
from services.activity_service import ActivityService
from utils.domain_utils import normalize_domain, is_valid_domain
from utils.security import get_current_user_obj

blocked_bp = Blueprint('blocked', __name__, url_prefix='/api/blocked-domains')


@blocked_bp.route('', methods=['GET'])
def get_blocked_domains():
    """
    GET /api/blocked-domains
    Returns list of all active sinkholed blocked domains with optional category filtering.
    """
    category = request.args.get('category')
    search = request.args.get('search') or request.args.get('q')

    query = BlockedDomain.query

    if category and category.upper() != 'ALL':
        query = query.filter(BlockedDomain.threat_category == category)

    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            (BlockedDomain.domain.ilike(s)) |
            (BlockedDomain.blocking_reason.ilike(s)) |
            (BlockedDomain.policy_code.ilike(s))
        )

    domains = query.order_by(BlockedDomain.created_at.desc()).all()
    return jsonify([d.to_dict() for d in domains]), 200


@blocked_bp.route('', methods=['POST'])
def add_blocked_domain():
    """
    POST /api/blocked-domains
    Adds a new domain to the active DNS sinkhole blocklist.
    """
    data = request.get_json() or {}
    raw_domain = data.get('domain')
    threat_category = data.get('threatCategory') or data.get('category', 'Custom Admin Policy')
    blocking_reason = data.get('blockingReason') or data.get('reason', 'Blocked by administrator')
    severity = data.get('severity', 'High')

    domain = normalize_domain(raw_domain)
    if not domain or not is_valid_domain(domain):
        return jsonify({'success': False, 'message': f"Invalid domain format: '{raw_domain}'"}), 400

    # Prevent duplicate entries
    existing = BlockedDomain.query.filter_by(domain=domain).first()
    if existing:
        return jsonify({'success': False, 'message': f"Domain '{domain}' is already in the blocklist."}), 409

    user = get_current_user_obj()
    policy_code = f"BLK-{uuid.uuid4().hex[:4].upper()}"

    new_block = BlockedDomain(
        policy_code=policy_code,
        domain=domain,
        threat_category=threat_category,
        blocking_reason=blocking_reason,
        blocking_status='Active Blocked',
        severity=severity,
        source='Manual Administrator Rule',
        blocked_by_user_id=user.id if user else None,
        created_at=datetime.now(timezone.utc)
    )

    db.session.add(new_block)
    db.session.commit()

    # Log activity
    ActivityService.log(
        activity_type='Domain Block Added',
        target=domain,
        status='BLOCKED',
        details=f"Sinkhole block rule created: {blocking_reason} ({threat_category})"
    )

    return jsonify(new_block.to_dict()), 201


@blocked_bp.route('/<domain_identifier>', methods=['DELETE'])
def remove_blocked_domain(domain_identifier: str):
    """
    DELETE /api/blocked-domains/<id>
    Unblocks / whitelists a domain by ID, policy_code, or domain name.
    """
    target = None

    # Check by policy code or domain name
    clean_identifier = domain_identifier.strip().lower()
    target = BlockedDomain.query.filter(
        (BlockedDomain.domain == clean_identifier) |
        (BlockedDomain.policy_code == domain_identifier.strip())
    ).first()

    # Check by numeric ID if still not found
    if not target and domain_identifier.isdigit():
        target = BlockedDomain.query.get(int(domain_identifier))

    if not target:
        return jsonify({'success': False, 'message': f"Blocked domain '{domain_identifier}' not found."}), 404

    domain_name = target.domain
    db.session.delete(target)
    db.session.commit()

    # Log activity
    ActivityService.log(
        activity_type='Domain Unblocked / Whitelisted',
        target=domain_name,
        status='ALLOWED',
        details=f"Removed {domain_name} from active sinkhole blocklist."
    )

    return jsonify({'success': True, 'message': f"Domain '{domain_name}' successfully removed from blocklist."}), 200

