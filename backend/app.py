"""
AegisDNS - Application Factory & Main Entry Point
Flask REST API and Concurrent DNS Filtering Resolver Engine.
"""

import os
import logging
from flask import Flask, jsonify
from sqlalchemy.exc import OperationalError
from sqlalchemy import create_engine
from config import config_by_name, Config
from extensions import db, jwt, cors
from routes import register_routes
from dns_resolver.resolver_server import DnsFilteringResolver

# Configure Structured Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("AegisDNS")


def create_app(config_name: str = 'default') -> Flask:
    """
    Creates and configures the Flask application instance.
    """
    app = Flask(__name__)
    cfg = config_by_name.get(config_name, Config)
    app.config.from_object(cfg)

    # Initialize Extensions
    jwt.init_app(app)
    cors.init_app(app, resources={r"/api/*": {"origins": app.config.get('CORS_ORIGINS', '*')}})

    
    # Database Initialization with Automatic SQLite Fallback

    database_uri = app.config['SQLALCHEMY_DATABASE_URI']
    test_engine = None

    try:
        # Test configured database before initializing Flask-SQLAlchemy
        test_engine = create_engine(database_uri)

        with test_engine.connect():
            logger.info("Configured database connection successful.")

    except OperationalError as e:
        if cfg.FALLBACK_TO_SQLITE:
            logger.warning(
                f"MySQL connection failed: {e}"
            )

            database_uri = cfg.SQLITE_DATABASE_URI
            app.config['SQLALCHEMY_DATABASE_URI'] = database_uri

            logger.info(
                f"Using SQLite fallback: {database_uri}"
            )
        else:
            logger.error(f"Database connection failed: {e}")
            raise

    finally:
        if test_engine is not None:
            test_engine.dispose()

    # Initialize SQLAlchemy ONLY ONCE
    db.init_app(app)

    # Create tables and seed initial data
    with app.app_context():
        db.create_all()
        seed_initial_data(app)


    # Register API Blueprints
    register_routes(app)

    # Global Error Handlers
    @app.errorhandler(400)
    def handle_bad_request(e):
        return jsonify({'success': False, 'error': 'Bad Request', 'message': str(e)}), 400

    @app.errorhandler(404)
    def handle_not_found(e):
        return jsonify({'success': False, 'error': 'Not Found', 'message': 'Requested API resource not found.'}), 404

    @app.errorhandler(500)
    def handle_internal_error(e):
        logger.error(f"Internal server error: {e}")
        return jsonify({'success': False, 'error': 'Internal Server Error', 'message': 'An unexpected error occurred.'}), 500

    @app.route('/')
    def index():
        return jsonify({
            'system': 'AegisDNS - DNS-Based Malicious Domain Blocking and Network Protection System',
            'version': '4.18.2-SecEngine',
            'status': 'OPERATIONAL',
            'endpoints': {
                'auth': '/api/auth',
                'domains': '/api/domains/check',
                'dns_monitoring': '/api/dns/logs',
                'threats': '/api/threats',
                'blocked_domains': '/api/blocked-domains',
                'dashboard': '/api/dashboard/statistics',
                'settings': '/api/settings',
                'activity_logs': '/api/activity-logs'
            }
        })

    return app


def seed_initial_data(app: Flask):
    """
    Seeds default administrator, system settings, baseline threat domains,
    and initial activity logs into the database.
    """
    from models.user import User
    from models.domain import BlockedDomain, MaliciousDomain, SuspiciousDomain
    from models.threat import ThreatDetection
    from models.dns_log import DnsLog
    from models.activity import ActivityLog
    from models.setting import SystemSetting

    # 1. Seed Administrator User
    admin = User.query.filter_by(username=app.config.get('ADMIN_USERNAME', 'admin_secops')).first()
    if not admin:
        admin = User(
            full_name=app.config.get('ADMIN_FULL_NAME', 'SecOps Administrator'),
            username=app.config.get('ADMIN_USERNAME', 'admin_secops'),
            email=app.config.get('ADMIN_EMAIL', 'admin@aegisdns.security'),
            role='Cybersecurity Incident Lead',
            is_active=True
        )
        admin.set_password(app.config.get('ADMIN_PASSWORD', 'CyberShield#2026!'))
        db.session.add(admin)
        logger.info(f"Seeded default administrator: {admin.username} ({admin.email})")

    # 2. Seed Baseline Blocked Domains
    baseline_blocks = [
        ('paypa1-security-update-verify.com', 'Phishing', 'Brand Typosquatting / Credential Harvesting', 'Critical', 'BLK-101'),
        ('c2-trojan-controller-sync.net', 'Command & Control', 'Cobalt Strike C2 Beacon Rendezvous', 'Critical', 'BLK-102'),
        ('malware-payload-stage1.biz', 'Malware Dropper', 'Trojan Downloader distribution endpoint', 'High', 'BLK-103'),
        ('miningpool-xmrig-eu.stream', 'Cryptomining', 'Unauthorized Monero browser mining pool', 'Medium', 'BLK-104'),
        ('apple-id-suspended-login.cc', 'Phishing', 'Apple ID Credential Phishing Landing Page', 'High', 'BLK-105'),
        ('stealth-keylogger-drop.online', 'Spyware Dropper', 'AgentTesla infostealer exfiltration node', 'Critical', 'BLK-106')
    ]

    for domain, cat, reason, sev, code in baseline_blocks:
        if not BlockedDomain.query.filter_by(domain=domain).first():
            b = BlockedDomain(
                policy_code=code,
                domain=domain,
                threat_category=cat,
                blocking_reason=reason,
                blocking_status='Active Blocked',
                severity=sev,
                source='Automated Threat Intelligence'
            )
            db.session.add(b)

            if not MaliciousDomain.query.filter_by(domain=domain).first():
                m = MaliciousDomain(
                    domain=domain,
                    threat_category=cat,
                    source='URLhaus / AlienVault OTX',
                    severity=sev,
                    confidence_score=98
                )
                db.session.add(m)

    # 3. Seed Suspicious Domains
    baseline_suspicious = [
        ('crypto-fast-airdrop-claim.top', 'Crypto Drainer / Unverified TLD', 3.91, 'Newly registered .top domain with high entropy'),
        ('dga-8f4b219c0a.biz', 'Domain Generation Algorithm (DGA)', 4.78, 'Shannon entropy exceeds 4.7 with Conficker signature')
    ]
    for domain, cat, entropy, reason in baseline_suspicious:
        if not SuspiciousDomain.query.filter_by(domain=domain).first():
            s = SuspiciousDomain(
                domain=domain,
                threat_category=cat,
                entropy_score=entropy,
                reason=reason,
                status='Under Review'
            )
            db.session.add(s)

    # 4. Seed Threat Detections
    baseline_threats = [
        ('THR-7721', 'c2-trojan-controller-sync.net', 'Command & Control', 'CRITICAL', 'AlienVault OTX / CobaltStrike', 99, '91.240.118.89', '192.168.1.115 (Finance Workstation 3)', 'Active botnet beaconing interval every 45s.'),
        ('THR-7720', 'paypa1-security-update-verify.com', 'Phishing', 'CRITICAL', 'PhishTank & AbuseIPDB', 98, '185.220.101.45', '192.168.1.142 (HR Laptop 12)', 'Typosquatting PayPal credential harvester with cloned login forms.'),
        ('THR-7719', 'malware-payload-stage1.biz', 'Malware Dropper', 'HIGH', 'URLhaus Live Feed', 94, '194.26.29.112', '192.168.1.177 (Guest Wi-Fi Client)', 'Serves encrypted ZIP containing malicious VBScript payload.')
    ]
    for tid, domain, cat, sev, source, score, tip, origin, ioc in baseline_threats:
        if not ThreatDetection.query.filter_by(incident_id=tid).first():
            t = ThreatDetection(
                incident_id=tid,
                domain=domain,
                category=cat,
                severity=sev,
                source_feed=source,
                risk_score=score,
                action_taken='DNS Sinkhole (0.0.0.0)',
                target_ip=tip,
                client_origin=origin,
                ioc_details=ioc
            )
            db.session.add(t)

    # 5. Seed System Settings
    settings_seed = [
        ('protection_enabled', 'true', 'boolean', 'Master network DNS protection toggle'),
        ('upstream_dns', '1.1.1.1 (Cloudflare DNS)', 'string', 'Upstream recursive DNS resolver IP'),
        ('doh_enabled', 'true', 'boolean', 'Enable DNS-over-HTTPS protocol'),
        ('dot_enabled', 'false', 'boolean', 'Enable DNS-over-TLS protocol'),
        ('auto_block', 'true', 'boolean', 'Automatically sinkhole high-confidence threats'),
        ('blocking_sensitivity', 'Strict', 'string', 'Sensitivity profile (Strict, Moderate, Lenient)'),
        ('email_alerts', 'true', 'boolean', 'Dispatch security alert emails for critical events'),
        ('alert_email', 'secops@enterprise-domain.local', 'string', 'Primary alert email address'),
        ('webhook_url', '', 'string', 'Slack or Discord webhook endpoint')
    ]
    for key, val, val_type, desc in settings_seed:
        if not SystemSetting.query.filter_by(setting_key=key).first():
            st = SystemSetting(setting_key=key, setting_value=val, value_type=val_type, description=desc)
            db.session.add(st)

    # 6. Seed Initial Activity Logs
    if ActivityLog.query.count() == 0:
        initial_activities = [
            ('ACT-9081', 'Threat Detection', 'AegisDNS Sinkhole Engine', 'paypa1-security-update-verify.com', '192.168.1.142', 'BLOCKED', 'Malicious domain intercepted. Returned 0.0.0.0 sinkhole response.'),
            ('ACT-9080', 'Threat Detection', 'AegisDNS Sinkhole Engine', 'c2-trojan-controller-sync.net', '192.168.1.115', 'BLOCKED', 'Active C2 server query rejected. Intercepted by sinkhole policy.'),
            ('ACT-9079', 'Domain Check', 'SecOps Administrator', 'dga-8f4b219c0a.biz', '192.168.1.5', 'SUSPICIOUS', 'Manual domain heuristic inspection executed via Security Console.'),
            ('ACT-9078', 'Policy Change', 'SecOps Administrator', 'Protection Setting: Sensitivity Slider', '192.168.1.5', 'UPDATED', 'Blocking heuristic sensitivity calibrated to Strict Mode.')
        ]
        for aid, atype, actor, target, ip, status, details in initial_activities:
            act = ActivityLog(activity_id=aid, activity_type=atype, actor=actor, target=target, ip_origin=ip, status=status, details=details)
            db.session.add(act)

    # 7. Seed Initial DNS Logs
    if DnsLog.query.count() == 0:
        initial_dns = [
            ('DNS-8910', 'api.github.com', '192.168.1.104', 'A', '140.82.121.4', 11.2, 'ALLOWED', 'Software / API', False),
            ('DNS-8909', 'paypa1-security-update-verify.com', '192.168.1.142', 'A', '0.0.0.0', 3.8, 'BLOCKED', 'Phishing', True),
            ('DNS-8908', 'update.microsoft.com', '192.168.1.88', 'AAAA', '2603:1030::', 18.4, 'ALLOWED', 'OS Services', False),
            ('DNS-8907', 'crypto-fast-airdrop-claim.top', '192.168.1.205', 'A', '45.154.255.8', 14.1, 'SUSPICIOUS', 'Crypto Drainer', False),
            ('DNS-8906', 'c2-trojan-controller-sync.net', '192.168.1.115', 'A', '0.0.0.0', 3.2, 'BLOCKED', 'C2 / Botnet', True)
        ]
        for duid, domain, ip, qtype, res_ip, rtime, status, cat, is_sink in initial_dns:
            dlog = DnsLog(log_uuid=duid, domain=domain, client_ip=ip, query_type=qtype, resolved_ip=res_ip, response_time_ms=rtime, status=status, category=cat, is_sinkholed=is_sink)
            db.session.add(dlog)

    # 8. Seed Digital Twin Baseline Policy & Attack Scenarios
    try:
        from services.digital_twin_service import DigitalTwinService
        DigitalTwinService.get_or_create_baseline_policy()
        DigitalTwinService.seed_default_scenarios()
    except Exception as e:
        logger.warning(f"Could not seed Digital Twin scenarios: {e}")

    db.session.commit()
    logger.info("Database seeding completed.")


# Standalone runner
if __name__ == '__main__':
    app = create_app('development')

    # Start DNS Filtering Resolver on background thread
    dns_port = app.config.get('DNS_LISTEN_PORT', 5354)
    dns_host = app.config.get('DNS_LISTEN_HOST', '127.0.0.1')
    try:
        resolver = DnsFilteringResolver(host=dns_host, port=dns_port, app=app)
        resolver.start(run_in_background=True)
        logger.info(f"DNS Filtering Resolver daemon started on UDP {dns_host}:{dns_port}")
    except Exception as e:
        logger.warning(f"Could not start DNS Filtering Resolver on {dns_host}:{dns_port}: {e}")

    flask_port = int(os.getenv('PORT', 5000))
    logger.info("===================================================================")
    logger.info(f" AegisDNS Web REST API starting at http://127.0.0.1:{flask_port}")
    logger.info(f" Local DNS Resolver active at UDP 127.0.0.1:{dns_port}")
    logger.info("===================================================================")
    app.run(host='0.0.0.0', port=flask_port, debug=False)

