"""
AegisDNS - Dashboard & Settings Integration Tests
Tests dynamic calculation of statistics, chart datasets, and settings toggling.
"""

def test_dashboard_statistics_calculation(client):
    """Test dashboard metrics calculation from database"""
    res = client.get('/api/dashboard/statistics')
    assert res.status_code == 200
    data = res.get_json()
    assert 'totalDnsRequests' in data
    assert 'safeDomains' in data
    assert 'blockedDomains' in data
    assert 'suspiciousDomains' in data
    assert 'protectionStatus' in data
    assert 'trafficHourly' in data
    assert 'threatCategories' in data


def test_dashboard_charts(client):
    """Test Chart.js data formatting endpoint"""
    res = client.get('/api/dashboard/charts')
    assert res.status_code == 200
    data = res.get_json()
    assert 'trafficHourly' in data
    assert 'threatCategories' in data
    assert len(data['trafficHourly']['labels']) == 12


def test_settings_get_and_update(client):
    """Test retrieving and updating runtime protection settings"""
    # Get current
    get_res = client.get('/api/settings')
    assert get_res.status_code == 200
    assert get_res.get_json()['protectionEnabled'] is True

    # Update sensitivity
    put_res = client.put('/api/settings', json={
        'blockingSensitivity': 'Moderate',
        'alertEmail': 'alerts@cybersec.local'
    })
    assert put_res.status_code == 200
    data = put_res.get_json()
    assert data['blockingSensitivity'] == 'Moderate'
    assert data['alertEmail'] == 'alerts@cybersec.local'


def test_protection_toggle(client):
    """Test toggling network protection on and off"""
    toggle_res = client.post('/api/settings/protection-toggle', json={'targetStatus': False})
    assert toggle_res.status_code == 200
    assert toggle_res.get_json()['protectionEnabled'] is False
    assert toggle_res.get_json()['dnsProtectionStatus'] == 'PAUSED'

    toggle_on = client.post('/api/settings/protection-toggle', json={'targetStatus': True})
    assert toggle_on.get_json()['protectionEnabled'] is True

