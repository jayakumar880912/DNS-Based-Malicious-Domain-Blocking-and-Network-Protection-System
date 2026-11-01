"""
AegisDNS - Attack Replay & Counterfactual Security Forensics Routes
REST API endpoints for replaying recorded DNS attack timelines,
evaluating counterfactual policy rules, and generating forensic incident audit reports.
"""

from flask import Blueprint, request, jsonify, abort
from extensions import db
from models.forensics import SecurityIncident, CounterfactualAnalysis
from services.forensics_service import ForensicsService
from utils.security import get_current_user_obj

forensics_bp = Blueprint('forensics', __name__, url_prefix='/api/forensics')


# =============================================================================
# Incident Records & Replay Endpoints
# =============================================================================

@forensics_bp.route('/incidents', methods=['GET'])
def list_incidents():
    """
    GET /api/forensics/incidents
    Returns all archived historical security attack incidents.
    """
    try:
        incidents = ForensicsService.get_incidents()
        return jsonify({
            'success': True,
            'incidents': incidents,
            'count': len(incidents)
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f"Error retrieving incidents: {str(e)}"}), 500


@forensics_bp.route('/incidents/<int:incident_id>', methods=['GET'])
def get_incident(incident_id: int):
    """
    GET /api/forensics/incidents/<id>
    Returns complete chronological timeline events and forensic details for an incident.
    """
    try:
        incident = ForensicsService.get_incident_details(incident_id)
        return jsonify({
            'success': True,
            'incident': incident
        }), 200
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@forensics_bp.route('/replay', methods=['POST'])
def replay_incident():
    """
    POST /api/forensics/replay
    Loads and stages an incident for animated step-by-step attack playback.
    Payload: { incidentId: int }
    """
    data = request.get_json() or {}
    incident_id = data.get('incidentId')

    if not incident_id:
        return jsonify({'success': False, 'message': 'incidentId is required.'}), 400

    try:
        incident = ForensicsService.get_incident_details(int(incident_id))
        return jsonify({
            'success': True,
            'message': f"Incident '{incident['title']}' staged for playback.",
            'incident': incident,
            'totalSteps': len(incident.get('timelineEvents', []))
        }), 200
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# =============================================================================
# Counterfactual Analysis Endpoints
# =============================================================================

@forensics_bp.route('/counterfactual', methods=['POST'])
def run_counterfactual():
    """
    POST /api/forensics/counterfactual
    Executes counterfactual 'what-if' simulation against an incident timeline using a candidate VirtualPolicy.
    Payload: { incidentId: int, policyId: int }
    """
    data = request.get_json() or {}
    incident_id = data.get('incidentId')
    policy_id = data.get('policyId')

    if not incident_id or not policy_id:
        return jsonify({'success': False, 'message': 'incidentId and policyId are required.'}), 400

    user = get_current_user_obj()
    user_id = user.id if user else None

    try:
        result = ForensicsService.run_counterfactual_analysis(
            incident_id=int(incident_id),
            policy_id=int(policy_id),
            user_id=user_id
        )
        return jsonify(result), 200
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f"Counterfactual analysis failed: {str(e)}"}), 500


@forensics_bp.route('/analyses', methods=['GET'])
def list_analyses():
    """
    GET /api/forensics/analyses
    Returns history of executed counterfactual policy analyses.
    """
    limit = request.args.get('limit', 20, type=int)
    analyses = CounterfactualAnalysis.query.order_by(CounterfactualAnalysis.created_at.desc()).limit(limit).all()
    return jsonify({
        'success': True,
        'analyses': [a.to_dict() for a in analyses],
        'count': len(analyses)
    }), 200


@forensics_bp.route('/analyses/<int:analysis_id>', methods=['GET'])
def get_analysis_details(analysis_id: int):
    """
    GET /api/forensics/analyses/<id>
    """
    analysis = db.session.get(CounterfactualAnalysis, analysis_id)
    if not analysis:
        abort(404, description=f"Counterfactual Analysis {analysis_id} not found.")
    return jsonify({'success': True, 'analysis': analysis.to_dict()}), 200


@forensics_bp.route('/analyses/<int:analysis_id>/export', methods=['GET'])
def export_analysis_report(analysis_id: int):
    """
    GET /api/forensics/analyses/<id>/export
    Exports formal forensic security report package.
    """
    try:
        report = ForensicsService.get_analysis_report(analysis_id)
        return jsonify({'success': True, 'report': report}), 200
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

