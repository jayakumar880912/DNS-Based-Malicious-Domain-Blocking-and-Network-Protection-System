"""
AegisDNS - Threat Detection Routes
Endpoints for querying detected threats, severity breakdowns, and threat forensics.
"""

from flask import Blueprint, request, jsonify
from models.threat import ThreatDetection
from extensions import db
from sqlalchemy import func

threats_bp = Blueprint('threats', __name__, url_prefix='/api/threats')


@threats_bp.route('', methods=['GET'])
def get_threats():
    """
    GET /api/threats
    Returns threat detection records with severity and category filtering.
    """
    severity = request.args.get('severity')
    category = request.args.get('category')
    search = request.args.get('search') or request.args.get('q')

    query = ThreatDetection.query

    if severity and severity.upper() != 'ALL':
        query = query.filter(ThreatDetection.severity == severity.upper())

    if category and category.upper() != 'ALL':
        query = query.filter(ThreatDetection.category.ilike(f"%{category}%"))

    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            (ThreatDetection.domain.ilike(s)) |
            (ThreatDetection.incident_id.ilike(s)) |
            (ThreatDetection.ioc_details.ilike(s)) |
            (ThreatDetection.client_origin.ilike(s))
        )

    threats = query.order_by(ThreatDetection.detected_at.desc()).all()
    return jsonify([t.to_dict() for t in threats]), 200


@threats_bp.route('/statistics', methods=['GET'])
def get_threat_statistics():
    """
    GET /api/threats/statistics
    Returns breakdown by threat severity and category.
    """
    total = ThreatDetection.query.count()
    critical = ThreatDetection.query.filter_by(severity='CRITICAL').count()
    high = ThreatDetection.query.filter_by(severity='HIGH').count()
    medium = ThreatDetection.query.filter_by(severity='MEDIUM').count()
    low = ThreatDetection.query.filter_by(severity='LOW').count()

    cat_counts = db.session.query(
        ThreatDetection.category, func.count(ThreatDetection.id)
    ).group_by(ThreatDetection.category).all()

    return jsonify({
        'success': True,
        'totalThreats': total,
        'bySeverity': {
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low
        },
        'byCategory': {cat: count for cat, count in cat_counts}
    }), 200

