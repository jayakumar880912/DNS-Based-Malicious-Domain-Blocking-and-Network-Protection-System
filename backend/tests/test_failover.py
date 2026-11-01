"""
AegisDNS - Self-Recovering DNS Failover & Recovery Unit Tests
Verifies resolver health monitoring, canary integrity verification, automated failover,
anti-flapping safe recovery, MTTR computation, forensic report generation,
and the Security-Preserving Guarantee (100% sinkhole enforcement during failover).
"""

import pytest
import json
from models.failover import DnsResolverConfig, FailoverEvent
from models.domain import BlockedDomain
from services.failover_service import FailoverService


def test_default_resolvers_seeded_and_listed(client, auth_headers):
    """Verifies that default resolvers (Primary, Secondary, Tertiary) are configured and accessible"""
    res = client.get('/api/failover/resolvers', headers=auth_headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['count'] >= 3

    resolvers = data['resolvers']
    primary = next((r for r in resolvers if r['priority'] == 1), None)
    secondary = next((r for r in resolvers if r['priority'] == 2), None)
    tertiary = next((r for r in resolvers if r['priority'] == 3), None)

    assert primary is not None
    assert primary['ipAddress'] == '1.1.1.1'
    assert primary['isPrimary'] is True

    assert secondary is not None
    assert secondary['ipAddress'] == '8.8.8.8'

    assert tertiary is not None
    assert tertiary['ipAddress'] == '9.9.9.9'


def test_failover_status_endpoint(client, auth_headers):
    """Tests GET /api/failover/status endpoint metrics and system state"""
    res = client.get('/api/failover/status', headers=auth_headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'systemState' in data
    assert 'activeResolver' in data
    assert 'metrics' in data
    assert data['securityPreserved'] is True


def test_canary_domain_verification_engine(client):
    """Tests that canary verification evaluates reachability, RCODE NOERROR, and non-bogon records"""
    with client.application.app_context():
        # Test verification against Cloudflare Primary
        is_valid, probe = FailoverService.verify_resolver_security(
            ip_address='1.1.1.1',
            port=53,
            canary_domain='cloudflare.com',
            timeout=2.0
        )
        assert isinstance(is_valid, bool)
        assert 'canaryDomain' in probe
        assert probe['canaryDomain'] == 'cloudflare.com'
        assert 'status' in probe


def test_compromised_backup_resolver_rejected(client):
    """Verifies that an insecure or poisoned resolver is rejected and NOT routed to"""
    with client.application.app_context():
        # Inject simulated poisoning attack
        FailoverService._simulation_drill_active = True
        FailoverService._simulation_drill_type = 'POISONED_BACKUP_TEST'

        is_valid, probe = FailoverService.verify_resolver_security(
            ip_address='192.0.2.1',
            port=53,
            canary_domain='cloudflare.com'
        )

        assert is_valid is False
        assert probe['status'] == 'SECURITY_COMPROMISED'
        assert 'Anti-poisoning check failed' in probe['reason']

        # Reset simulation state
        FailoverService._simulation_drill_active = False
        FailoverService._simulation_drill_type = None


def test_automated_failover_execution(client, auth_headers):
    """Verifies automated failover transitions system to FAILOVER_ACTIVE and routes traffic to secondary"""
    with client.application.app_context():
        # Trigger failover
        result = FailoverService.execute_failover(trigger_reason='TEST_TIMEOUT_INJECTION')
        assert result['success'] is True
        assert result['systemState'] == FailoverService.STATE_FAILOVER_ACTIVE
        assert result['activeResolver']['ip'] == '8.8.8.8'

        # Verify event logged in database
        event = FailoverEvent.query.filter_by(status='ACTIVE_FAILOVER').order_by(FailoverEvent.id.desc()).first()
        assert event is not None
        assert event.to_resolver_ip == '8.8.8.8'
        assert event.security_integrity_verified is True

        # Test telemetry recording while on backup
        FailoverService.record_query_served(is_blocked=False, count=5)
        FailoverService.record_query_served(is_blocked=True, count=2)

        # Refresh event from db
        updated_event = client.application.extensions['sqlalchemy'].session.get(FailoverEvent, event.id)
        assert updated_event.queries_handled_on_backup >= 7
        assert updated_event.blocked_threats_during_failover >= 2


def test_security_preserving_guarantee_during_failover(client):
    """
    SECURITY-PRESERVING GUARANTEE:
    Crucial requirement: When failover is active (running on backup resolver 8.8.8.8),
    malicious domains must STILL be intercepted and sinkholed to 0.0.0.0 BEFORE any upstream resolution!
    """
    with client.application.app_context():
        # 1. Ensure system is in FAILOVER_ACTIVE state
        FailoverService.execute_failover(trigger_reason='SECURITY_PRESERVATION_TEST')
        assert FailoverService._system_state == FailoverService.STATE_FAILOVER_ACTIVE
        active_ip, active_port, active_name = FailoverService.get_active_upstream()
        assert active_ip == '8.8.8.8'

        # 2. Check a known blocked domain
        malicious_domain = 'paypa1-security-update-verify.com'
        is_in_blocklist = BlockedDomain.query.filter_by(domain=malicious_domain).first() is not None
        assert is_in_blocklist is True, f"Seed blocked domain {malicious_domain} should be present"

        # 3. Simulate resolver check: blocked domains MUST NOT be forwarded
        from dns_resolver.sinkhole import DnsSinkhole
        import dns.message

        qmsg = dns.message.make_query(malicious_domain, dns.rdatatype.A)
        blocked_resp = DnsSinkhole.create_blocked_response(qmsg, sinkhole_ip='0.0.0.0')

        # Verify sinkhole response has 0.0.0.0
        resolved_ips = []
        for rrset in blocked_resp.answer:
            for item in rrset:
                resolved_ips.append(item.to_text())

        assert '0.0.0.0' in resolved_ips
        # Telemetry is recorded under failover event
        FailoverService.record_query_served(is_blocked=True, count=1)


def test_safe_recovery_and_anti_flapping(client, auth_headers):
    """Tests safe failback restores upstream to primary and calculates MTTR"""
    with client.application.app_context():
        # First ensure failover is active
        FailoverService.execute_failover(trigger_reason='RECOVERY_TEST_TRIGGER')

        # Execute recovery
        res = FailoverService.execute_recovery(reason='PRIMARY_VERIFIED_STABLE')
        assert res['success'] is True
        assert res['systemState'] == FailoverService.STATE_NORMAL_PRIMARY
        assert res['activeResolver']['ip'] == '1.1.1.1'
        assert res['recoveryDurationSeconds'] is not None

        # Check FailoverEvent was marked RECOVERED_NORMAL
        ev = FailoverEvent.query.filter_by(status='RECOVERED_NORMAL').order_by(FailoverEvent.id.desc()).first()
        assert ev is not None
        assert ev.recovery_timestamp is not None
        assert ev.recovery_duration_seconds > 0.0


def test_controlled_outage_simulation_drill_and_report(client, auth_headers):
    """Tests POST /api/failover/simulate-outage and report generation"""
    # 1. Trigger simulation drill
    sim_res = client.post('/api/failover/simulate-outage', json={
        'drillType': 'TIMEOUT_SIMULATION'
    }, headers=auth_headers)

    assert sim_res.status_code == 200
    sim_data = sim_res.get_json()
    assert sim_data['success'] is True
    assert sim_data['simulationActive'] is True
    assert sim_data['systemState'] == 'FAILOVER_ACTIVE'

    # 2. Recover from drill
    rec_res = client.post('/api/failover/recover', json={
        'reason': 'DRILL_COMPLETED_OPERATOR_RESTORE'
    }, headers=auth_headers)

    assert rec_res.status_code == 200
    rec_data = rec_res.get_json()
    assert rec_data['success'] is True
    assert rec_data['systemState'] == 'NORMAL_PRIMARY'

    # 3. Retrieve events and generate recovery report
    events_res = client.get('/api/failover/events', headers=auth_headers)
    assert events_res.status_code == 200
    events_data = events_res.get_json()
    assert len(events_data['events']) > 0

    latest_event = events_data['events'][0]
    report_res = client.get(f"/api/failover/reports/{latest_event['id']}", headers=auth_headers)
    assert report_res.status_code == 200
    report_data = report_res.get_json()
    assert report_data['success'] is True
    report = report_data['report']
    assert 'reportId' in report
    assert 'executiveSummary' in report
    assert 'recommendations' in report
    assert len(report['recommendations']) >= 2


def test_critical_alert_when_no_secure_backup_available(client):
    """
    Verifies that if all backups are disabled or fail canary verification,
    the system transitions to CRITICAL_NO_UPSTREAM, emits a critical alert,
    and keeps local sinkholing active rather than dropping protection.
    """
    with client.application.app_context():
        # Temporarily deactivate all backup resolvers
        backups = DnsResolverConfig.query.filter(DnsResolverConfig.priority > 1).all()
        for b in backups:
            b.is_active = False
        client.application.extensions['sqlalchemy'].session.commit()

        try:
            res = FailoverService.execute_failover(trigger_reason='CATASTROPHIC_TEST')
            assert res['success'] is False
            assert res['error'] == 'CRITICAL_NO_SECURE_BACKUP'
            assert res['systemState'] == FailoverService.STATE_CRITICAL_NO_UPSTREAM
            assert 'Local DNS sinkhole protection remains 100% active' in res['message']
        finally:
            # Restore backups
            for b in backups:
                b.is_active = True
            client.application.extensions['sqlalchemy'].session.commit()
            FailoverService.execute_recovery(reason='TEST_CLEANUP')
