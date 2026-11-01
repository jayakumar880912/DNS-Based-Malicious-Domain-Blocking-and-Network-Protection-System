"""
AegisDNS - Routes Package
Registers all Flask blueprints.
"""

from routes.auth import auth_bp
from routes.domains import domains_bp
from routes.dns import dns_bp
from routes.threats import threats_bp
from routes.blocked import blocked_bp
from routes.dashboard import dashboard_bp
from routes.settings import settings_bp
from routes.activity import activity_bp


def register_routes(app):
    """Registers all REST API blueprints with the Flask application"""
    app.register_blueprint(auth_bp)
    app.register_blueprint(domains_bp)
    app.register_blueprint(dns_bp)
    app.register_blueprint(threats_bp)
    app.register_blueprint(blocked_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(activity_bp)

