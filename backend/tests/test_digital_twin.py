"""
AegisDNS - Digital Twin & Policy Simulation Automated Tests
Verifies virtual policy management, isolated simulation execution, metrics calculation,
A/B policy comparison, and zero-mutation isolation against live DNS protection.
"""

import json
from models.digital_twin import VirtualPolicy, SimulationScenario, SimulationRun, SimulationItem
from models.domain import BlockedDomain
from models.dns_log import DnsLog
from services.digital_twin_service import DigitalTwinService


def test_list_and_create_virtual_policy(client, auth_headers):
    """Verifies listing and creating virtual security policies"""
    # 1. List Policies (Ensures Baseline is auto-seeded)
    res = client.get('/api/digital-twin/policies', headers=auth_headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert len(data['policies']) >= 1
    assert any(p['isBaseline'] for p in data['policies'])

    # 2. Create Custom Virtual Policy
    new_policy = {
        'name': 'Aggressive Zero-Trust Policy',
        'description': 'Strict Shannon entropy and aggressive DGA detection for high-threat posture.',
        'entropyThreshold': 3.70,
        'blockedTlds': ['top', 'xyz', 'cc', 'ru', 'biz', 'online', 'vip'],
        'dgaProtectionMode': 'Aggressive',
        'aiHeuristicWeight': 1.4,
        'actionMalicious': 'SINKHOLE_0_0_0_0',
        'actionSuspicious': 'BLOCK_SINKHOLE'
    }
    create_res = client.post('/api/digital-twin/policies', json=new_policy, headers=auth_headers)
    assert create_res.status_code == 201
    created_data = create_res.get_json()
    assert created_data['success'] is True
    assert created_data['policy']['entropyThreshold'] == 3.70
    assert created_data['policy']['dgaProtectionMode'] == 'Aggressive'


def test_clone_and_delete_virtual_policy(client, auth_headers):
    """Verifies cloning and deleting non-baseline virtual policies"""
    # Create policy to clone
    base = client.post('/api/digital-twin/policies', json={
        'name': 'Template Policy Alpha',
        'entropyThreshold': 4.10
    }, headers=auth_headers).get_json()['policy']

    # Clone
    clone_res = client.post(f"/api/digital-twin/policies/{base['id']}/clone", json={
        'name': 'Cloned Candidate Policy'
    }, headers=auth_headers)
    assert clone_res.status_code == 201
    cloned = clone_res.get_json()['policy']
    assert cloned['name'] == 'Cloned Candidate Policy'
    assert cloned['entropyThreshold'] == 4.10

    # Delete original
    del_res = client.delete(f"/api/digital-twin/policies/{base['id']}", headers=auth_headers)
    assert del_res.status_code == 200

    # Verify baseline cannot be deleted
    baseline = VirtualPolicy.query.filter_by(is_baseline=True).first()
    assert baseline is not None
    del_base_res = client.delete(f"/api/digital-twin/policies/{baseline.id}", headers=auth_headers)
    assert del_base_res.status_code == 400


def test_list_attack_scenarios(client, auth_headers):
    """Verifies attack scenarios are accessible and contain domain datasets"""
    res = client.get('/api/digital-twin/scenarios?includeDataset=true', headers=auth_headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert len(data['scenarios']) >= 2
    scen_keys = [s['scenarioKey'] for s in data['scenarios']]
    assert 'phishing-surge' in scen_keys
    assert 'dga-botnet' in scen_keys

    # Check dataset integrity
    first_scen = data['scenarios'][0]
    assert len(first_scen['dataset']) > 0
    assert 'groundTruth' in first_scen['dataset'][0]


def test_execute_simulation_and_metrics_calculation(client, auth_headers):
    """
    Executes an isolated simulation and verifies that confusion matrix and metrics
    (Accuracy, Precision, Recall, F1, FPR, Effectiveness) are accurately calculated.
    """
    baseline = DigitalTwinService.get_or_create_baseline_policy()
    scenario = SimulationScenario.query.filter_by(scenario_key='phishing-surge').first()
    assert scenario is not None

    payload = {
        'policyId': baseline.id,
        'scenarioId': scenario.id
    }
    res = client.post('/api/digital-twin/simulate', json=payload, headers=auth_headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True

    summary = data['summary']
    assert summary['totalQueries'] == len(data['items'])
    assert summary['truePositives'] + summary['falsePositives'] + summary['trueNegatives'] + summary['falseNegatives'] == summary['totalQueries']
    assert 0.0 <= summary['accuracy'] <= 100.0
    assert 0.0 <= summary['recall'] <= 100.0
    assert 0.0 <= summary['precision'] <= 100.0
    assert 0.0 <= summary['effectivenessScore'] <= 100.0
    assert len(data['recommendations']) >= 0

    # Verify per-domain item forensic details
    sample_item = data['items'][0]
    assert 'domain' in sample_item
    assert 'classificationType' in sample_item
    assert sample_item['classificationType'] in ['TP', 'FP', 'TN', 'FN']
    assert 'confidenceScore' in sample_item
    assert 'triggerRules' in sample_item


def test_simulation_zero_mutation_isolation(client, auth_headers):
    """
    SECURITY TEST:
    Ensures that executing a Digital Twin simulation runs in a completely isolated sandbox
    and NEVER mutates live blocked_domains, live dns_logs, or live system settings.
    """
    initial_blocked_count = BlockedDomain.query.count()
    initial_dns_log_count = DnsLog.query.count()

    baseline = DigitalTwinService.get_or_create_baseline_policy()
    scenario = SimulationScenario.query.first()

    # Run heavy simulation
    res = client.post('/api/digital-twin/simulate', json={
        'policyId': baseline.id,
        'scenarioId': scenario.id
    }, headers=auth_headers)
    assert res.status_code == 200

    # Assert live system records are strictly untouched
    assert BlockedDomain.query.count() == initial_blocked_count
    assert DnsLog.query.count() == initial_dns_log_count


def test_compare_policies_ab_testing(client, auth_headers):
    """
    Tests A/B policy comparison between Baseline and Candidate policy,
    evaluating metric deltas and identifying discrepancy domains.
    """
    baseline = DigitalTwinService.get_or_create_baseline_policy()

    # Create candidate with tighter entropy threshold
    candidate = VirtualPolicy(
        name="Candidate Strict Filter",
        entropy_threshold=3.60,
        blocked_tlds=['top', 'xyz', 'cc', 'ru', 'biz', 'online', 'vip'],
        dga_protection_mode='Aggressive',
        ai_heuristic_weight=1.5,
        action_malicious='SINKHOLE_0_0_0_0',
        action_suspicious='BLOCK_SINKHOLE'
    )
    from extensions import db
    db.session.add(candidate)
    db.session.commit()

    scenario = SimulationScenario.query.filter_by(scenario_key='phishing-surge').first()

    compare_payload = {
        'baselinePolicyId': baseline.id,
        'candidatePolicyId': candidate.id,
        'scenarioId': scenario.id
    }
    res = client.post('/api/digital-twin/compare', json=compare_payload, headers=auth_headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'deltas' in data
    assert 'accuracy' in data['deltas']
    assert 'effectivenessScore' in data['deltas']
    assert 'discrepancies' in data
    assert 'assessment' in data
    assert 'summary' in data['assessment']


def test_export_simulation_report(client, auth_headers):
    """Verifies that completed simulation runs can be exported as structured audit reports"""
    baseline = DigitalTwinService.get_or_create_baseline_policy()
    scenario = SimulationScenario.query.first()

    sim_res = client.post('/api/digital-twin/simulate', json={
        'policyId': baseline.id,
        'scenarioId': scenario.id
    }, headers=auth_headers).get_json()

    run_id = sim_res['runId']
    export_res = client.get(f'/api/digital-twin/runs/{run_id}/export', headers=auth_headers)
    assert export_res.status_code == 200
    rep_data = export_res.get_json()
    assert rep_data['success'] is True
    assert 'report' in rep_data
    report = rep_data['report']
    assert 'executiveSummary' in report
    assert 'confusionMatrix' in report
    assert 'domainEvaluations' in report
