"""
AegisDNS - DNS Monitoring Routes
Endpoints for querying live DNS resolution telemetry and query statistics.
"""

from flask import Blueprint, request, jsonify
from services.dns_service import DnsService
from models.dns_log import DnsLog
from extensions import db
from sqlalchemy import func

dns_bp = Blueprint('dns', __name__, url_prefix='/api/dns')


@dns_bp.route('/logs', methods=['GET'])
def get_dns_logs():
    """
    GET /api/dns/logs
    Returns DNS query logs with filtering by status, queryType, search query, and sorting.
    Supports both paginated JSON and flat array matching frontend expectations.
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 100, type=int)
    status = request.args.get('status')
    query_type = request.args.get('query_type') or request.args.get('type')
    search = request.args.get('search') or request.args.get('q')
    sort_by = request.args.get('sort_by', 'time_desc')
    flat = request.args.get('flat', 'true').lower() in ('true', '1')

    data = DnsService.get_logs(
        page=page,
        per_page=per_page,
        status=status,
        query_type=query_type,
        search=search,
        sort_by=sort_by
    )

    if flat:
        # Frontend directly accepts array of logs
        return jsonify(data['logs']), 200

    return jsonify(data), 200


@dns_bp.route('/statistics', methods=['GET'])
def get_dns_statistics():
    """
    GET /api/dns/statistics
    Returns aggregated metrics on DNS latency, status counts, and query types.
    """
    total = DnsLog.query.count()
    allowed = DnsLog.query.filter_by(status='ALLOWED').count()
    blocked = DnsLog.query.filter_by(status='BLOCKED').count()
    suspicious = DnsLog.query.filter_by(status='SUSPICIOUS').count()
    avg_latency = db.session.query(func.avg(DnsLog.response_time_ms)).scalar() or 0.0

    return jsonify({
        'success': True,
        'totalQueries': total,
        'allowedQueries': allowed,
        'blockedQueries': blocked,
        'suspiciousQueries': suspicious,
        'averageResponseTimeMs': round(float(avg_latency), 2)
    }), 200

