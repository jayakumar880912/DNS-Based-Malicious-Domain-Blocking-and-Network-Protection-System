"""
AegisDNS - User Authentication Tests
Validates user registration, duplicate email/username rejection, password hashing, and login.
"""

def test_user_registration_success(client):
    """Test successful user registration"""
    payload = {
        'fullName': 'Elena Rostova',
        'email': 'elena.rostova@enterprise.local',
        'username': 'elena_sec',
        'password': 'SecurePassword#2026',
        'role': 'Threat Intelligence Analyst'
    }
    res = client.post('/api/auth/register', json=payload)
    assert res.status_code == 201
    data = res.get_json()
    assert data['success'] is True
    assert 'token' in data
    assert data['user']['username'] == 'elena_sec'


def test_user_registration_duplicate_email(client):
    """Test duplicate email rejection"""
    payload = {
        'fullName': 'Analyst One',
        'email': 'duplicate@enterprise.local',
        'username': 'analyst_1',
        'password': 'Password123!'
    }
    res1 = client.post('/api/auth/register', json=payload)
    assert res1.status_code == 201

    # Attempt to register same email
    payload['username'] = 'analyst_2'
    res2 = client.post('/api/auth/register', json=payload)
    assert res2.status_code == 400
    assert 'already registered' in res2.get_json()['message']


def test_user_registration_duplicate_username(client):
    """Test duplicate username rejection"""
    payload = {
        'fullName': 'Analyst One',
        'email': 'analyst1@enterprise.local',
        'username': 'duplicate_user',
        'password': 'Password123!'
    }
    res1 = client.post('/api/auth/register', json=payload)
    assert res1.status_code == 201

    payload['email'] = 'analyst2@enterprise.local'
    res2 = client.post('/api/auth/register', json=payload)
    assert res2.status_code == 400
    assert 'already taken' in res2.get_json()['message']


def test_login_success(client):
    """Test login with valid credentials"""
    res = client.post('/api/auth/login', json={
        'identifier': 'admin_secops',
        'password': 'CyberShield#2026!'
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'token' in data
    assert data['user']['username'] == 'admin_secops'


def test_login_invalid_password(client):
    """Test login rejection on wrong password"""
    res = client.post('/api/auth/login', json={
        'identifier': 'admin_secops',
        'password': 'WrongPassword123!'
    })
    assert res.status_code == 401
    assert res.get_json()['success'] is False

