"""
AegisDNS - Digital Twin & Policy Simulation Routes
Endpoints for managing virtual policies, attack scenarios, executing simulations,
A/B policy comparison, and exporting audit reports.
"""

from flask import Blueprint, request, jsonify, abort
from extensions import db
from models.digital_twin import VirtualPolicy, SimulationScenario, SimulationRun, SimulationItem
from services.digital_twin_service import DigitalTwinService
from utils.security import get_current_user_obj

digital_twin_bp = Blueprint('digital_twin', __name__, url_prefix='/api/digital-twin')


# =============================================================================
# Virtual Policies Endpoints
# =============================================================================

@digital_twin_bp.route('/policies', methods=['GET'])
def list_policies():
    """
    GET /api/digital-twin/policies
    Lists all virtual DNS security policies. Ensures baseline policy exists.
    """
    DigitalTwinService.get_or_create_baseline_policy()
    policies = VirtualPolicy.query.order_by(VirtualPolicy.is_baseline.desc(), VirtualPolicy.id.asc()).all()
    return jsonify({
        'success': True,
        'policies': [p.to_dict() for p in policies],
        'count': len(policies)
    }), 200


@digital_twin_bp.route('/policies', methods=['POST'])
def create_policy():
    """
    POST /api/digital-twin/policies
    Creates a new virtual DNS security policy.
    """
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()

    if not name:
        return jsonify({'success': False, 'message': 'Policy name is required.'}), 400

    if VirtualPolicy.query.filter_by(name=name).first():
        return jsonify({'success': False, 'message': f"A policy named '{name}' already exists."}), 409

    user = get_current_user_obj()
    creator = user.full_name if user else 'SecOps Administrator'

    policy = VirtualPolicy(
        name=name,
        description=data.get('description', ''),
        entropy_threshold=float(data.get('entropyThreshold', 3.90)),
        blocked_tlds=data.get('blockedTlds', ['top', 'xyz', 'cc', 'ru', 'biz', 'online', 'loan', 'work', 'vip']),
        blocked_categories=data.get('blockedCategories', ['Phishing', 'Malware C2', 'Ransomware Dropper', 'Cryptomining', 'DGA Anomaly']),
        dga_protection_mode=data.get('dgaProtectionMode', 'Balanced'),
        ai_heuristic_weight=float(data.get('aiHeuristicWeight', 1.0)),
        min_confidence_score=int(data.get('minConfidenceScore', 80)),
        action_malicious=data.get('actionMalicious', 'SINKHOLE_0_0_0_0'),
        action_suspicious=data.get('actionSuspicious', 'CHALLENGE_FLAG'),
        custom_whitelist=data.get('customWhitelist', []),
        custom_blacklist=data.get('customBlacklist', []),
        is_baseline=False,
        created_by=creator
    )

    db.session.add(policy)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f"Virtual Policy '{policy.name}' created successfully.",
        'policy': policy.to_dict()
    }), 201


@digital_twin_bp.route('/policies/<int:policy_id>', methods=['GET'])
def get_policy(policy_id: int):
    """
    GET /api/digital-twin/policies/<id>
    """
    policy = db.session.get(VirtualPolicy, policy_id)
    if not policy:
        abort(404, description=f"Virtual policy {policy_id} not found.")
    return jsonify({'success': True, 'policy': policy.to_dict()}), 200


@digital_twin_bp.route('/policies/<int:policy_id>', methods=['PUT'])
def update_policy(policy_id: int):
    """
    PUT /api/digital-twin/policies/<id>
    Updates parameters of a virtual policy.
    """
    policy = db.session.get(VirtualPolicy, policy_id)
    if not policy:
        abort(404, description=f"Virtual policy {policy_id} not found.")
    data = request.get_json() or {}

    if 'name' in data and data['name'].strip():
        new_name = data['name'].strip()
        existing = VirtualPolicy.query.filter_by(name=new_name).first()
        if existing and existing.id != policy.id:
            return jsonify({'success': False, 'message': f"A policy named '{new_name}' already exists."}), 409
        policy.name = new_name

    if 'description' in data:
        policy.description = data['description']
    if 'entropyThreshold' in data:
        policy.entropy_threshold = float(data['entropyThreshold'])
    if 'blockedTlds' in data:
        policy.blocked_tlds = data['blockedTlds']
    if 'blockedCategories' in data:
        policy.blocked_categories = data['blockedCategories']
    if 'dgaProtectionMode' in data:
        policy.dga_protection_mode = data['dgaProtectionMode']
    if 'aiHeuristicWeight' in data:
        policy.ai_heuristic_weight = float(data['aiHeuristicWeight'])
    if 'minConfidenceScore' in data:
        policy.min_confidence_score = int(data['minConfidenceScore'])
    if 'actionMalicious' in data:
        policy.action_malicious = data['actionMalicious']
    if 'actionSuspicious' in data:
        policy.action_suspicious = data['actionSuspicious']
    if 'customWhitelist' in data:
        policy.custom_whitelist = data['customWhitelist']
    if 'customBlacklist' in data:
        policy.custom_blacklist = data['customBlacklist']

    db.session.commit()

    return jsonify({
        'success': True,
        'message': f"Virtual Policy '{policy.name}' updated successfully.",
        'policy': policy.to_dict()
    }), 200


@digital_twin_bp.route('/policies/<int:policy_id>', methods=['DELETE'])
def delete_policy(policy_id: int):
    """
    DELETE /api/digital-twin/policies/<id>
    Deletes a virtual policy (baseline policy cannot be deleted).
    """
    policy = db.session.get(VirtualPolicy, policy_id)
    if not policy:
        abort(404, description=f"Virtual policy {policy_id} not found.")
    if policy.is_baseline:
        return jsonify({'success': False, 'message': 'The Production Baseline Policy cannot be deleted.'}), 400

    name = policy.name
    db.session.delete(policy)
    db.session.commit()

    return jsonify({'success': True, 'message': f"Virtual policy '{name}' deleted successfully."}), 200


@digital_twin_bp.route('/policies/<int:policy_id>/clone', methods=['POST'])
def clone_policy(policy_id: int):
    """
    POST /api/digital-twin/policies/<id>/clone
    Clones an existing virtual policy for rapid sandbox experimentation.
    """
    source = db.session.get(VirtualPolicy, policy_id)
    if not source:
        abort(404, description=f"Virtual policy {policy_id} not found.")
    data = request.get_json() or {}
    new_name = data.get('name') or f"Copy of {source.name}"

    # Ensure unique name
    counter = 1
    candidate_name = new_name
    while VirtualPolicy.query.filter_by(name=candidate_name).first():
        candidate_name = f"{new_name} ({counter})"
        counter += 1

    user = get_current_user_obj()
    creator = user.full_name if user else 'SecOps Administrator'

    cloned = VirtualPolicy(
        name=candidate_name,
        description=f"Cloned from {source.name}. " + (source.description or ""),
        entropy_threshold=source.entropy_threshold,
        blocked_tlds=source.blocked_tlds,
        blocked_categories=source.blocked_categories,
        dga_protection_mode=source.dga_protection_mode,
        ai_heuristic_weight=source.ai_heuristic_weight,
        min_confidence_score=source.min_confidence_score,
        action_malicious=source.action_malicious,
        action_suspicious=source.action_suspicious,
        custom_whitelist=source.custom_whitelist,
        custom_blacklist=source.custom_blacklist,
        is_baseline=False,
        created_by=creator
    )

    db.session.add(cloned)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f"Policy successfully cloned as '{cloned.name}'.",
        'policy': cloned.to_dict()
    }), 201
    data = request.get_json() or {}
    new_name = data.get('name') or f"Copy of {source.name}"

    # Ensure unique name
    counter = 1
    candidate_name = new_name
    while VirtualPolicy.query.filter_by(name=candidate_name).first():
        candidate_name = f"{new_name} ({counter})"
        counter += 1

    user = get_current_user_obj()
    creator = user.full_name if user else 'SecOps Administrator'

    cloned = VirtualPolicy(
        name=candidate_name,
        description=f"Cloned from {source.name}. " + (source.description or ""),
        entropy_threshold=source.entropy_threshold,
        blocked_tlds=source.blocked_tlds,
        blocked_categories=source.blocked_categories,
        dga_protection_mode=source.dga_protection_mode,
        ai_heuristic_weight=source.ai_heuristic_weight,
        min_confidence_score=source.min_confidence_score,
        action_malicious=source.action_malicious,
        action_suspicious=source.action_suspicious,
        custom_whitelist=source.custom_whitelist,
        custom_blacklist=source.custom_blacklist,
        is_baseline=False,
        created_by=creator
    )

    db.session.add(cloned)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f"Policy successfully cloned as '{cloned.name}'.",
        'policy': cloned.to_dict()
    }), 201


@digital_twin_bp.route('/policies/<int:policy_id>/promote-to-live', methods=['POST'])
def promote_policy(policy_id: int):
    """
    POST /api/digital-twin/policies/<id>/promote-to-live
    Promotes virtual policy parameters to live production DNS protection.
    """
    try:
        result = DigitalTwinService.promote_policy_to_live(policy_id)
        return jsonify(result), 200
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': f"Policy promotion failed: {str(e)}"}), 500


# =============================================================================
# Attack Scenarios Endpoints
# =============================================================================

@digital_twin_bp.route('/scenarios', methods=['GET'])
def list_scenarios():
    """
    GET /api/digital-twin/scenarios
    Returns available attack scenario datasets.
    """
    DigitalTwinService.seed_default_scenarios()
    scenarios = SimulationScenario.query.order_by(SimulationScenario.id.asc()).all()
    include_dataset = request.args.get('includeDataset', 'false').lower() == 'true'
    return jsonify({
        'success': True,
        'scenarios': [s.to_dict(include_dataset=include_dataset) for s in scenarios],
        'count': len(scenarios)
    }), 200


@digital_twin_bp.route('/scenarios/<int:scenario_id>', methods=['GET'])
def get_scenario(scenario_id: int):
    """
    GET /api/digital-twin/scenarios/<id>
    """
    scenario = db.session.get(SimulationScenario, scenario_id)
    if not scenario:
        abort(404, description=f"Scenario {scenario_id} not found.")
    return jsonify({'success': True, 'scenario': scenario.to_dict(include_dataset=True)}), 200


# =============================================================================
# Simulation Execution Endpoints
# =============================================================================

@digital_twin_bp.route('/simulate', methods=['POST'])
def run_simulation():
    """
    POST /api/digital-twin/simulate
    Executes an isolated simulation of a virtual policy against an attack scenario.
    Payload: { policyId: int, scenarioId?: int, customDataset?: list }
    """
    data = request.get_json() or {}
    policy_id = data.get('policyId')

    if not policy_id:
        return jsonify({'success': False, 'message': 'policyId is required.'}), 400

    scenario_id = data.get('scenarioId')
    custom_dataset = data.get('customDataset')

    user = get_current_user_obj()
    user_id = user.id if user else None

    try:
        result = DigitalTwinService.run_simulation(
            policy_id=int(policy_id),
            scenario_id=int(scenario_id) if scenario_id else None,
            custom_dataset=custom_dataset,
            user_id=user_id
        )
        return jsonify(result), 200
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f"Simulation failed: {str(e)}"}), 500


@digital_twin_bp.route('/compare', methods=['POST'])
def compare_policies():
    """
    POST /api/digital-twin/compare
    Executes comparative A/B analysis between baseline and candidate virtual policy.
    Payload: { baselinePolicyId: int, candidatePolicyId: int, scenarioId: int }
    """
    data = request.get_json() or {}
    base_id = data.get('baselinePolicyId')
    cand_id = data.get('candidatePolicyId')
    scen_id = data.get('scenarioId')

    if not base_id or not cand_id or not scen_id:
        return jsonify({
            'success': False,
            'message': 'baselinePolicyId, candidatePolicyId, and scenarioId are all required.'
        }), 400

    try:
        result = DigitalTwinService.compare_policies(
            baseline_policy_id=int(base_id),
            candidate_policy_id=int(cand_id),
            scenario_id=int(scen_id)
        )
        return jsonify(result), 200
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f"Policy comparison failed: {str(e)}"}), 500


# =============================================================================
# History, Results & Export Endpoints
# =============================================================================

@digital_twin_bp.route('/runs', methods=['GET'])
def list_runs():
    """
    GET /api/digital-twin/runs
    Returns history of executed simulation runs.
    """
    limit = request.args.get('limit', 20, type=int)
    runs = SimulationRun.query.order_by(SimulationRun.created_at.desc()).limit(limit).all()
    return jsonify({
        'success': True,
        'runs': [r.to_dict(include_items=False) for r in runs],
        'count': len(runs)
    }), 200


@digital_twin_bp.route('/runs/<int:run_id>', methods=['GET'])
def get_run_details(run_id: int):
    """
    GET /api/digital-twin/runs/<id>
    Retrieves complete metrics and per-domain forensic breakdown for a simulation run.
    """
    run_record = db.session.get(SimulationRun, run_id)
    if not run_record:
        abort(404, description=f"Simulation run {run_id} not found.")
    return jsonify({
        'success': True,
        'run': run_record.to_dict(include_items=True)
    }), 200


@digital_twin_bp.route('/runs/<int:run_id>/export', methods=['GET'])
def export_run_report(run_id: int):
    """
    GET /api/digital-twin/runs/<id>/export
    Exports comprehensive simulation audit report with metadata, metrics, and items.
    """
    run_record = db.session.get(SimulationRun, run_id)
    if not run_record:
        abort(404, description=f"Simulation run {run_id} not found.")
    policy = db.session.get(VirtualPolicy, run_record.policy_id) if run_record.policy_id else None

    report = {
        'reportTitle': 'AegisDNS Digital Twin - Security Policy Simulation Audit Report',
        'generatedAt': run_record.created_at.strftime('%Y-%m-%d %H:%M:%S UTC'),
        'runId': run_record.id,
        'runUuid': run_record.run_uuid,
        'policy': policy.to_dict() if policy else {'name': run_record.policy_name},
        'scenario': {
            'id': run_record.scenario_id,
            'name': run_record.scenario_name
        },
        'executiveSummary': {
            'totalSimulatedQueries': run_record.total_queries,
            'policyEffectivenessScore': f"{run_record.effectiveness_score:.2f}%",
            'detectionRateRecall': f"{run_record.recall:.2f}%",
            'falsePositiveRate': f"{run_record.fpr:.2f}%",
            'precision': f"{run_record.precision:.2f}%",
            'f1Score': f"{run_record.f1_score:.2f}",
            'overallAccuracy': f"{run_record.accuracy:.2f}%",
            'executionLatency': f"{run_record.execution_time_ms:.2f} ms"
        },
        'confusionMatrix': {
            'truePositives': run_record.true_positives,
            'falsePositives': run_record.false_positives,
            'trueNegatives': run_record.true_negatives,
            'falseNegatives': run_record.false_negatives
        },
        'aiRecommendations': run_record.recommendations,
        'domainEvaluations': [item.to_dict() for item in run_record.items.all()]
    }

    return jsonify({'success': True, 'report': report}), 200
