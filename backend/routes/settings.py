"""
AegisDNS - System Settings Routes
Endpoints for updating protection policies, DNS resolvers, and alert channels.
"""

from flask import Blueprint, request, jsonify
from extensions import db
from models.setting import SystemSetting
from services.activity_service import ActivityService

settings_bp = Blueprint('settings', __name__, url_prefix='/api/settings')


@settings_bp.route('', methods=['GET'])
def get_settings():
    """
    GET /api/settings
    Retrieves all current runtime protection parameters.
    """
    protection_enabled = SystemSetting.get_val('protection_enabled', True)
    dns_status = 'ACTIVE' if protection_enabled else 'PAUSED'
    upstream_dns = SystemSetting.get_val('upstream_dns', '1.1.1.1 (Cloudflare DNS)')
    doh_enabled = SystemSetting.get_val('doh_enabled', True)
    dot_enabled = SystemSetting.get_val('dot_enabled', False)
    auto_block = SystemSetting.get_val('auto_block', True)
    sensitivity = SystemSetting.get_val('blocking_sensitivity', 'Strict')
    email_alerts = SystemSetting.get_val('email_alerts', True)
    alert_email = SystemSetting.get_val('alert_email', 'secops@enterprise-domain.local')
    webhook_url = SystemSetting.get_val('webhook_url', '')

    return jsonify({
        'protectionEnabled': protection_enabled,
        'dnsProtectionStatus': dns_status,
        'primaryDnsResolver': '127.0.0.1:53 (AegisDNS Sinkhole)',
        'upstreamDns': upstream_dns,
        'dohEnabled': doh_enabled,
        'dotEnabled': dot_enabled,
        'autoBlock': auto_block,
        'blockingSensitivity': sensitivity,
        'threatNotifications': email_alerts,
        'emailAlerts': email_alerts,
        'alertEmail': alert_email,
        'webhookUrl': webhook_url
    }), 200


@settings_bp.route('', methods=['PUT'])
def update_settings():
    """
    PUT /api/settings
    Updates runtime settings and persists changes to database.
    """
    data = request.get_json() or {}

    if 'protectionEnabled' in data:
        SystemSetting.set_val('protection_enabled', bool(data['protectionEnabled']), 'boolean')

    if 'upstreamDns' in data:
        SystemSetting.set_val('upstream_dns', str(data['upstreamDns']), 'string')

    if 'dohEnabled' in data:
        SystemSetting.set_val('doh_enabled', bool(data['dohEnabled']), 'boolean')

    if 'dotEnabled' in data:
        SystemSetting.set_val('dot_enabled', bool(data['dotEnabled']), 'boolean')

    if 'autoBlock' in data:
        SystemSetting.set_val('auto_block', bool(data['autoBlock']), 'boolean')

    if 'blockingSensitivity' in data:
        SystemSetting.set_val('blocking_sensitivity', str(data['blockingSensitivity']), 'string')

    if 'emailAlerts' in data:
        SystemSetting.set_val('email_alerts', bool(data['emailAlerts']), 'boolean')

    if 'alertEmail' in data:
        SystemSetting.set_val('alert_email', str(data['alertEmail']), 'string')

    if 'webhookUrl' in data:
        SystemSetting.set_val('webhook_url', str(data['webhookUrl']), 'string')

    db.session.commit()

    ActivityService.log(
        activity_type='Policy Change',
        target='System Configuration',
        status='UPDATED',
        details='Network protection parameters modified by administrator.'
    )

    return get_settings()


@settings_bp.route('/protection-toggle', methods=['POST'])
def toggle_protection():
    """
    POST /api/settings/protection-toggle
    Quick-toggle master network protection state.
    """
    data = request.get_json() or {}
    current = SystemSetting.get_val('protection_enabled', True)
    target = data.get('targetStatus') if 'targetStatus' in data else not current

    SystemSetting.set_val('protection_enabled', bool(target), 'boolean')
    db.session.commit()

    status_str = 'ACTIVE' if target else 'PAUSED'
    ActivityService.log(
        activity_type='Policy Change',
        target='Master Protection Switch',
        status='UPDATED' if target else 'WARNING',
        details=f"Master DNS sinkhole protection state toggled to {status_str}."
    )

    return jsonify({
        'success': True,
        'protectionEnabled': bool(target),
        'dnsProtectionStatus': status_str,
        'message': f"Network protection {status_str}."
    }), 200

