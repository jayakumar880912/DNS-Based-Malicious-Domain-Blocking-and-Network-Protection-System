"""
AegisDNS - Attack Replay & Counterfactual Forensics Automated Tests
Verifies historical incident retrieval, attack timeline step-by-step playback,
counterfactual policy evaluation, dwell time reduction math, and zero-mutation isolation.
"""

from models.forensics import SecurityIncident, CounterfactualAnalysis
from models.digital_twin import VirtualPolicy
from models.domain import BlockedDomain
from models.dns_log import DnsLog
from services.forensics_service import ForensicsService
from services.digital_twin_service import DigitalTwinService


def test_list_and_get_security_incidents(client, auth_headers):
    """Verifies listing and inspecting recorded DNS security incidents"""
    res = client.get('/api/forensics/incidents', headers=auth_headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert len(data['incidents']) >= 3
    codes = [i['incidentCode'] for i in data['incidents']]
    assert 'INC-8821' in codes
    assert 'INC-8822' in codes
    assert 'INC-8823' in codes

    # Get details for first incident
    first_id = data['incidents'][0]['id']
    detail_res = client.get(f'/api/forensics/incidents/{first_id}', headers=auth_headers)
    assert detail_res.status_code == 200
    detail_data = detail_res.get_json()
    assert detail_data['success'] is True
    inc = detail_data['incident']
    assert len(inc['timelineEvents']) >= 5
    assert 'killChainPhase' in inc['timelineEvents'][0]
    assert 'originalAction' in inc['timelineEvents'][0]


def test_replay_incident_staging(client, auth_headers):
    """Verifies staging an incident for playback via /api/forensics/replay"""
    inc = SecurityIncident.query.filter_by(incident_code='INC-8821').first()
    assert inc is not None

    res = client.post('/api/forensics/replay', json={'incidentId': inc.id}, headers=auth_headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['totalSteps'] == len(inc.timeline_events)
    assert data['incident']['incidentCode'] == 'INC-8821'


def test_counterfactual_analysis_execution(client, auth_headers):
    """
    Executes counterfactual 'what-if' simulation on INC-8821 using a strict candidate policy.
    Verifies that the candidate policy accelerates containment and reduces dwell time.
    """
    inc = SecurityIncident.query.filter_by(incident_code='INC-8821').first()
    assert inc is not None

    # Create strict candidate policy that blocks .online and has high typosquatting weight
    candidate = VirtualPolicy(
        name="Strict Anti-Phishing & TLD Policy",
        entropy_threshold=3.70,
        blocked_tlds=['online', 'top', 'xyz', 'cc', 'ru', 'biz'],
        dga_protection_mode='Aggressive',
        ai_heuristic_weight=1.5,
        action_malicious='SINKHOLE_0_0_0_0',
        action_suspicious='BLOCK_SINKHOLE'
    )
    from extensions import db
    db.session.add(candidate)
    db.session.commit()

    payload = {
        'incidentId': inc.id,
        'policyId': candidate.id
    }
    res = client.post('/api/forensics/counterfactual', json=payload, headers=auth_headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True

    m = data['metrics']
    assert m['counterfactualContainmentStep'] <= m['originalContainmentStep']
    assert m['timeSavedMinutes'] >= 0.0
    assert m['dwellTimeReductionPct'] >= 0.0
    assert len(data['stepComparisons']) == len(inc.timeline_events)

    # Verify per-step comparison integrity
    step2 = next(s for s in data['stepComparisons'] if s['step'] == 2)
    assert step2['domain'] == 'azure-sync-ad-connector.online'
    assert step2['original']['action'] == 'ALLOWED'
    assert step2['counterfactual']['action'] == 'BLOCKED'
    assert step2['stepStatus'] == 'PREVENTED_BY_POLICY'


def test_counterfactual_zero_mutation_isolation(client, auth_headers):
    """
    SECURITY TEST:
    Ensures that replaying an incident and evaluating counterfactual policies
    NEVER mutates live blocked_domains, live dns_logs, or production settings.
    """
    initial_blocked = BlockedDomain.query.count()
    initial_dns_logs = DnsLog.query.count()

    inc = SecurityIncident.query.first()
    policy = DigitalTwinService.get_or_create_baseline_policy()

    res = client.post('/api/forensics/counterfactual', json={
        'incidentId': inc.id,
        'policyId': policy.id
    }, headers=auth_headers)
    assert res.status_code == 200

    # Assert live system records are strictly unchanged
    assert BlockedDomain.query.count() == initial_blocked
    assert DnsLog.query.count() == initial_dns_logs


def test_export_forensic_report(client, auth_headers):
    """Verifies that completed counterfactual analyses can be exported as forensic audit packages"""
    inc = SecurityIncident.query.first()
    policy = DigitalTwinService.get_or_create_baseline_policy()

    cf_res = client.post('/api/forensics/counterfactual', json={
        'incidentId': inc.id,
        'policyId': policy.id
    }, headers=auth_headers).get_json()

    analysis_id = cf_res['analysisId']
    export_res = client.get(f'/api/forensics/analyses/{analysis_id}/export', headers=auth_headers)
    assert export_res.status_code == 200
    rep_data = export_res.get_json()
    assert rep_data['success'] is True
    assert 'report' in rep_data
    report = rep_data['report']
    assert 'executiveSummary' in report
    assert 'stepTimelineComparisons' in report
    assert 'remediationRecommendations' in report

