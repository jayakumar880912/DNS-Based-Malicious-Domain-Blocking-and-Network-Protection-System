"""
AegisDNS - Domain Security Checker Tests
Tests classification logic for SAFE, MALICIOUS, and SUSPICIOUS domains.
"""

def test_check_safe_domain(client):
    """Test safe domain inspection (google.com)"""
    res = client.post('/api/domains/check', json={'domain': 'google.com'})
    assert res.status_code == 200
    data = res.get_json()
    assert data['domain'] == 'google.com'
    assert data['status'] == 'SAFE'
    assert data['riskScore'] <= 20
    assert '0.0.0.0' not in data['ip']


def test_check_malicious_domain_in_blocklist(client):
    """Test verified malicious domain in active sinkhole blocklist"""
    res = client.post('/api/domains/check', json={'domain': 'paypa1-security-update-verify.com'})
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'MALICIOUS'
    assert data['riskScore'] >= 90
    assert '0.0.0.0' in data['ip']


def test_check_suspicious_domain_dga(client):
    """Test suspicious domain with algorithmic randomness / DGA"""
    res = client.post('/api/domains/check', json={'domain': 'dga-8f4b219c0a.biz'})
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] in ('SUSPICIOUS', 'MALICIOUS')
    assert data['riskScore'] >= 50


def test_invalid_domain_format(client):
    """Test rejection of malformed domain string"""
    res = client.post('/api/domains/check', json={'domain': 'invalid_no_dot'})
    assert res.status_code == 400
    data = res.get_json()
    assert data['success'] is False

