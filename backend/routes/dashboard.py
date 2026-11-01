"""
AegisDNS - Dashboard Routes Blueprint
Endpoints for high-level security metrics, 24-hour DNS query activity, and threat distribution.
"""

from flask import Blueprint, jsonify
from services.stats_service import StatsService

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/api/dashboard/statistics', methods=['GET'])
@dashboard_bp.route('/api/dashboard/stats', methods=['GET']) # Compatibility alias for frontend api-service.js
def get_dashboard_statistics():
    """
    GET /api/dashboard/statistics or GET /api/dashboard/stats
    Returns complete dashboard overview metrics dynamically calculated from MySQL.
    """
    stats = StatsService.get_dashboard_summary()
    return jsonify(stats), 200


@dashboard_bp.route('/api/dashboard/recent-activities', methods=['GET'])
def get_recent_activities():
    """
    GET /api/dashboard/recent-activities
    Returns latest resolution and policy events for dashboard display.
    """
    recent = StatsService.get_recent_activities(limit=8)
    return jsonify(recent), 200


@dashboard_bp.route('/api/dashboard/charts', methods=['GET'])
def get_dashboard_charts():
    """
    GET /api/dashboard/charts
    Returns traffic and threat category distribution datasets for Chart.js.
    """
    traffic = StatsService.get_hourly_traffic()
    categories = StatsService.get_threat_categories_distribution()
    return jsonify({
        'trafficHourly': traffic,
        'threatCategories': categories
    }), 200

