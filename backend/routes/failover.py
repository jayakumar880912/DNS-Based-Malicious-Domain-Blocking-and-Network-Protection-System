"""
AegisDNS - Self-Recovering DNS Failover & Recovery Routes
REST API endpoints for resolver pool management, health checks, automated failover,
controlled outage drills, anti-flapping recovery, and forensic recovery audit reports.
"""

import ipaddress
import logging
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from extensions import db
from models.failover import DnsResolverConfig, FailoverEvent
from models.setting import SystemSetting
from services.failover_service import FailoverService
from utils.validators import sanitize_string

logger = logging.getLogger('AegisDNS.FailoverRoutes')

failover_bp = Blueprint('failover', __name__, url_prefix='/api/failover')


@failover_bp.route('/status', methods=['GET'])
@jwt_required(optional=True)
def get_status():
    """
    Returns real-time failover telemetry, active resolver, system state,
    primary health, backup availability, and MTTR metrics.
    """
    try:
        status_data = FailoverService.get_failover_status()
        return jsonify({'success': True, **status_data}), 200
    except Exception as e:
        logger.error(f"Error fetching failover status: {e}")
        return jsonify({'success': False, 'error': 'STATUS_ERROR', 'message': str(e)}), 500


@failover_bp.route('/resolvers', methods=['GET'])
@jwt_required(optional=True)
def list_resolvers():
    """Returns all configured DNS resolvers in priority order"""
    try:
        resolvers = DnsResolverConfig.query.order_by(DnsResolverConfig.priority.asc()).all()
        return jsonify({
            'success': True,
            'resolvers': [r.to_dict() for r in resolvers],
            'count': len(resolvers)
        }), 200
    except Exception as e:
        logger.error(f"Error listing resolvers: {e}")
        return jsonify({'success': False, 'error': 'FETCH_ERROR', 'message': str(e)}), 500


@failover_bp.route('/resolvers', methods=['POST'])
@jwt_required()
def add_resolver():
    """Adds a new backup DNS resolver to the pool"""
    try:
        data = request.get_json() or {}
        name = sanitize_string(data.get('name', '').strip(), max_length=100)
        ip = sanitize_string(data.get('ipAddress', '').strip(), max_length=64)
        port = int(data.get('port', 53))
        priority = int(data.get('priority', 2))
        protocol = data.get('protocol', 'UDP').upper()

        if not name or not ip:
            return jsonify({'success': False, 'error': 'MISSING_FIELDS', 'message': 'Resolver name and IP address are required.'}), 400

        # Validate IP format
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'success': False, 'error': 'INVALID_IP', 'message': f"'{ip}' is not a valid IPv4/IPv6 address."}), 400

        # Check duplicate IP
        existing = DnsResolverConfig.query.filter_by(ip_address=ip).first()
        if existing:
            return jsonify({'success': False, 'error': 'DUPLICATE_IP', 'message': f"A resolver with IP {ip} already exists ({existing.name})."}), 409

        # Pre-verify resolver security before allowing addition
        is_valid, probe_details = FailoverService.verify_resolver_security(
            ip_address=ip,
            port=port,
            canary_domain='cloudflare.com'
        )

        resolver = DnsResolverConfig(
            name=name,
            ip_address=ip,
            port=port,
            protocol=protocol,
            priority=priority,
            is_active=True,
            is_primary=(priority == 1),
            health_status='HEALTHY' if is_valid else 'UNVERIFIED',
            latency_ms=probe_details.get('latencyMs', 0.0),
            is_verified_secure=is_valid,
            verification_details=probe_details.get('reason', '')
        )
        db.session.add(resolver)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f"DNS Resolver '{name}' added successfully. Initial verification: {'Passed' if is_valid else 'Warning - Unverified'}",
            'resolver': resolver.to_dict(),
            'verification': probe_details
        }), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding resolver: {e}")
        return jsonify({'success': False, 'error': 'CREATE_ERROR', 'message': str(e)}), 500


@failover_bp.route('/resolvers/<int:resolver_id>', methods=['PUT'])
@jwt_required()
def update_resolver(resolver_id):
    """Updates resolver configuration"""
    try:
        resolver = db.session.get(DnsResolverConfig, resolver_id)
        if not resolver:
            return jsonify({'success': False, 'error': 'NOT_FOUND', 'message': 'Resolver not found.'}), 404

        data = request.get_json() or {}
        if 'name' in data:
            resolver.name = sanitize_string(data['name'].strip(), max_length=100)
        if 'port' in data:
            resolver.port = int(data['port'])
        if 'priority' in data:
            resolver.priority = int(data['priority'])
            resolver.is_primary = (resolver.priority == 1)
        if 'isActive' in data:
            resolver.is_active = bool(data['isActive'])
        if 'protocol' in data:
            resolver.protocol = data['protocol'].upper()

        db.session.commit()
        FailoverService.refresh_active_resolver_cache()

        return jsonify({
            'success': True,
            'message': f"Resolver '{resolver.name}' updated successfully.",
            'resolver': resolver.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating resolver: {e}")
        return jsonify({'success': False, 'error': 'UPDATE_ERROR', 'message': str(e)}), 500


@failover_bp.route('/resolvers/<int:resolver_id>', methods=['DELETE'])
@jwt_required()
def delete_resolver(resolver_id):
    """Deletes a custom resolver from pool"""
    try:
        resolver = db.session.get(DnsResolverConfig, resolver_id)
        if not resolver:
            return jsonify({'success': False, 'error': 'NOT_FOUND', 'message': 'Resolver not found.'}), 404

        if resolver.is_primary or resolver.priority == 1:
            return jsonify({'success': False, 'error': 'CANNOT_DELETE_PRIMARY', 'message': 'Cannot delete Primary DNS resolver. Designate a new primary first.'}), 400

        name = resolver.name
        db.session.delete(resolver)
        db.session.commit()
        FailoverService.refresh_active_resolver_cache()

        return jsonify({'success': True, 'message': f"Resolver '{name}' removed from pool."}), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting resolver: {e}")
        return jsonify({'success': False, 'error': 'DELETE_ERROR', 'message': str(e)}), 500


@failover_bp.route('/resolvers/<int:resolver_id>/verify', methods=['POST'])
@jwt_required(optional=True)
def verify_single_resolver(resolver_id):
    """
    Performs on-demand canary integrity & security verification for a specific resolver.
    """
    try:
        resolver = db.session.get(DnsResolverConfig, resolver_id)
        if not resolver:
            return jsonify({'success': False, 'error': 'NOT_FOUND', 'message': 'Resolver not found.'}), 404

        probe_res = FailoverService.probe_resolver(resolver)
        return jsonify({
            'success': True,
            'resolver': resolver.to_dict(),
            'probe': probe_res
        }), 200

    except Exception as e:
        logger.error(f"Error verifying resolver {resolver_id}: {e}")
        return jsonify({'success': False, 'error': 'VERIFY_ERROR', 'message': str(e)}), 500


@failover_bp.route('/probe-all', methods=['POST'])
@jwt_required(optional=True)
def probe_all_resolvers():
    """
    Runs health check across all active resolvers in the pool.
    Evaluates failure triggers and auto-recovery.
    """
    try:
        res = FailoverService.run_health_checks()
        return jsonify({'success': True, **res}), 200
    except Exception as e:
        logger.error(f"Error probing resolvers: {e}")
        return jsonify({'success': False, 'error': 'PROBE_ERROR', 'message': str(e)}), 500


@failover_bp.route('/simulate-outage', methods=['POST'])
@jwt_required()
def simulate_outage():
    """
    Triggers a controlled outage drill in simulation mode.
    Tests end-to-end failover, backup verification, and security preservation.
    """
    try:
        data = request.get_json() or {}
        drill_type = data.get('drillType', 'TIMEOUT_SIMULATION')
        result = FailoverService.simulate_primary_outage(drill_type=drill_type)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error initiating outage drill: {e}")
        return jsonify({'success': False, 'error': 'SIMULATION_ERROR', 'message': str(e)}), 500


@failover_bp.route('/recover', methods=['POST'])
@jwt_required()
def recover_primary():
    """
    Triggers safe recovery / failback to primary resolver.
    Evaluates canary domain verification before switching back.
    """
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'MANUAL_OPERATOR_RESTORE')
        result = FailoverService.execute_recovery(reason=reason)
        status_code = 200 if result.get('success') else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error(f"Error executing recovery: {e}")
        return jsonify({'success': False, 'error': 'RECOVERY_ERROR', 'message': str(e)}), 500


@failover_bp.route('/events', methods=['GET'])
@jwt_required(optional=True)
def get_events():
    """Returns failover incident history, MTTR, and telemetry"""
    try:
        limit = min(int(request.args.get('limit', 50)), 100)
        events = FailoverEvent.query.order_by(FailoverEvent.id.desc()).limit(limit).all()
        return jsonify({
            'success': True,
            'events': [e.to_dict() for e in events],
            'count': len(events)
        }), 200
    except Exception as e:
        logger.error(f"Error fetching failover events: {e}")
        return jsonify({'success': False, 'error': 'EVENTS_ERROR', 'message': str(e)}), 500


@failover_bp.route('/reports/<int:event_id>', methods=['GET'])
@jwt_required(optional=True)
def get_recovery_report(event_id):
    """Generates comprehensive forensic recovery report for a failover incident"""
    try:
        report_data = FailoverService.generate_recovery_report(event_id)
        if not report_data.get('success'):
            return jsonify(report_data), 404
        return jsonify(report_data), 200
    except Exception as e:
        logger.error(f"Error generating recovery report {event_id}: {e}")
        return jsonify({'success': False, 'error': 'REPORT_ERROR', 'message': str(e)}), 500


@failover_bp.route('/settings', methods=['GET'])
@jwt_required(optional=True)
def get_failover_settings():
    """Returns failover parameters and thresholds"""
    return jsonify({
        'success': True,
        'settings': {
            'timeoutSec': FailoverService.DEFAULT_TIMEOUT_SEC,
            'failureThreshold': FailoverService.CONSECUTIVE_FAILURE_THRESHOLD,
            'recoveryThreshold': FailoverService.CONSECUTIVE_RECOVERY_THRESHOLD,
            'canaryDomains': FailoverService.CANARY_DOMAINS,
            'autoFailbackEnabled': True,
            'securityPreservationMode': 'STRICT_SINKHOLE_ZERO_TRUST'
        }
    }), 200
