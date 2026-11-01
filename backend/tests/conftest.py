"""
AegisDNS - Pytest Configuration & Fixtures
Sets up isolated in-memory test database, test client, and seeded test data.
"""

import sys
import os
import pytest

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app import create_app, seed_initial_data
from extensions import db


@pytest.fixture(scope='session')
def app():
    """Initializes Flask app in test mode with SQLite in-memory DB"""
    test_app = create_app('testing')
    return test_app


@pytest.fixture(scope='function')
def client(app):
    """Provides test client, resets database, and seeds baseline records per test"""
    with app.app_context():
        db.create_all()
        seed_initial_data(app)
        yield app.test_client()
        db.session.remove()
        db.drop_all()


@pytest.fixture
def auth_headers(client):
    """Helper to authenticate and return Authorization Bearer header"""
    res = client.post('/api/auth/login', json={
        'identifier': 'admin_secops',
        'password': 'CyberShield#2026!'
    })
    token = res.get_json().get('token')
    return {'Authorization': f'Bearer {token}'}
