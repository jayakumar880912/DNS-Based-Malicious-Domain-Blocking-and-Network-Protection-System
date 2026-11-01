"""
AegisDNS - Blocked Domains Management Tests
Tests adding, listing, searching, and unblocking domains.
"""

def test_get_blocked_domains(client):
    """Test retrieving active blocked domains list"""
    res = client.get('/api/blocked-domains')
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    assert len(data) >= 1
    # Verify presence of seeded rule
    domains = [d['domain'] for d in data]
    assert 'c2-trojan-controller-sync.net' in domains


def test_add_blocked_domain(client):
    """Test administrator adding a domain to blocklist"""
    new_rule = {
        'domain': 'ransomware-stage-drop.org',
        'threatCategory': 'Ransomware Dropper',
        'severity': 'Critical',
        'blockingReason': 'Flagged by SOC during triage'
    }
    res = client.post('/api/blocked-domains', json=new_rule)
    assert res.status_code == 201
    data = res.get_json()
    assert data['domain'] == 'ransomware-stage-drop.org'
    assert data['severity'] == 'Critical'

    # Verify inspection reflects immediate blocking
    check_res = client.post('/api/domains/check', json={'domain': 'ransomware-stage-drop.org'})
    assert check_res.get_json()['status'] == 'MALICIOUS'


def test_add_duplicate_blocked_domain(client):
    """Test duplicate domain block rejection"""
    rule = {
        'domain': 'duplicate-test-target.net',
        'threatCategory': 'Phishing',
        'blockingReason': 'Initial block'
    }
    res1 = client.post('/api/blocked-domains', json=rule)
    assert res1.status_code == 201

    res2 = client.post('/api/blocked-domains', json=rule)
    assert res2.status_code == 409


def test_remove_blocked_domain(client):
    """Test unblocking a domain"""
    # First add domain
    domain = 'unblock-test-candidate.com'
    client.post('/api/blocked-domains', json={'domain': domain, 'threatCategory': 'Test', 'blockingReason': 'Temporary'})

    # Delete it
    del_res = client.delete(f'/api/blocked-domains/{domain}')
    assert del_res.status_code == 200
    assert del_res.get_json()['success'] is True

