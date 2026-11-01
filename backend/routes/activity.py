"""
AegisDNS - Activity Logs Route Blueprint
Endpoint for retrieving the immutable system audit trail with filtering and pagination.
"""

from flask import Blueprint, request, jsonify
from services.activity_service import ActivityService

activity_bp = Blueprint('activity', __name__, url_prefix='/api/activity-logs')


@activity_bp.route('', methods=['GET'])
def get_activity_logs():
    """
    GET /api/activity-logs
    Retrieves chronological activity audit trail.
    Supports ?flat=true to return raw array directly for frontend consumption.
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    activity_type = request.args.get('activity_type') or request.args.get('type')
    status = request.args.get('status')
    search = request.args.get('search') or request.args.get('q')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    flat = request.args.get('flat', 'true').lower() in ('true', '1')

    result = ActivityService.get_logs(
        page=page,
        per_page=per_page,
        activity_type=activity_type,
        status=status,
        search=search,
        start_date=start_date,
        end_date=end_date
    )

    if flat:
        return jsonify(result['logs']), 200

    return jsonify(result), 200

