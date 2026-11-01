"""
AegisDNS - Domain Security Models
Contains models for Domain Checks, Malicious Domains, Suspicious Domains, and Blocked Domains.
"""

from datetime import datetime, timezone
import json
from extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class DomainCheck(db.Model):
    """Stores history of domain security checks and reputations"""
    __tablename__ = 'domain_checks'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain = db.Column(db.String(255), nullable=False, index=True)
    status = db.Column(db.String(30), nullable=False, index=True) # SAFE, MALICIOUS, SUSPICIOUS
    category = db.Column(db.String(120), nullable=True)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    resolved_ip = db.Column(db.String(100), nullable=True)
    nameserver = db.Column(db.String(150), nullable=True)
    entropy_score = db.Column(db.Float, nullable=True)
    threat_sources_json = db.Column(db.Text, nullable=True)
    verdict_reason = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)

    @property
    def threat_sources(self):
        if not self.threat_sources_json:
            return []
        try:
            return json.loads(self.threat_sources_json)
        except Exception:
            return [self.threat_sources_json]

    @threat_sources.setter
    def threat_sources(self, value):
        if isinstance(value, (list, dict)):
            self.threat_sources_json = json.dumps(value)
        else:
            self.threat_sources_json = json.dumps([str(value)] if value else [])

    def to_dict(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'status': self.status,
            'category': self.category or 'Uncategorized',
            'riskScore': self.risk_score,
            'ip': self.resolved_ip or 'Unresolved',
            'nameserver': self.nameserver or 'None recorded',
            'entropyScore': f"{self.entropy_score:.2f}" if self.entropy_score is not None else 'N/A',
            'threatSources': self.threat_sources,
            'verdictReason': self.verdict_reason or 'No specific security advisory.',
            'checkedAt': self.created_at.strftime('%H:%M:%S'),
            'timestamp': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class MaliciousDomain(db.Model):
    """Database of verified malicious domains from threat intelligence feeds"""
    __tablename__ = 'malicious_domains'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain = db.Column(db.String(255), unique=True, nullable=False, index=True)
    threat_category = db.Column(db.String(100), nullable=False, index=True)
    source = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(30), nullable=False, default='High') # CRITICAL, HIGH, MEDIUM
    confidence_score = db.Column(db.Integer, default=95)
    first_seen_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    last_verified_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'threatCategory': self.threat_category,
            'source': self.source,
            'severity': self.severity,
            'confidenceScore': self.confidence_score,
            'firstSeenAt': self.first_seen_at.isoformat() if self.first_seen_at else None,
            'isActive': self.is_active
        }


class SuspiciousDomain(db.Model):
    """Database of anomalous domains identified via heuristics or high Shannon entropy"""
    __tablename__ = 'suspicious_domains'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain = db.Column(db.String(255), unique=True, nullable=False, index=True)
    threat_category = db.Column(db.String(100), default='Heuristic / Shannon Entropy Anomaly')
    entropy_score = db.Column(db.Float, nullable=True)
    reason = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default='Under Review')
    detected_at = db.Column(db.DateTime, default=utc_now, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'threatCategory': self.threat_category,
            'entropyScore': self.entropy_score,
            'reason': self.reason,
            'status': self.status,
            'detectedAt': self.detected_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class BlockedDomain(db.Model):
    """Active DNS sinkhole blocklist managed by policies and administrators"""
    __tablename__ = 'blocked_domains'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    policy_code = db.Column(db.String(50), unique=True, nullable=True, index=True) # e.g. BLK-101
    domain = db.Column(db.String(255), unique=True, nullable=False, index=True)
    threat_category = db.Column(db.String(100), nullable=False, default='Custom Admin Policy')
    blocking_reason = db.Column(db.Text, nullable=False)
    blocking_status = db.Column(db.String(50), nullable=False, default='Active Blocked')
    severity = db.Column(db.String(30), nullable=False, default='High')
    source = db.Column(db.String(100), nullable=False, default='Manual Administrator Rule')
    blocked_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)

    def to_dict(self):
        return {
            'id': self.policy_code or f"BLK-{self.id}",
            'domain': self.domain,
            'threatCategory': self.threat_category,
            'detectionDate': self.created_at.strftime('%Y-%m-%d'),
            'blockingReason': self.blocking_reason,
            'blockingStatus': self.blocking_status,
            'source': self.source,
            'severity': self.severity,
            'createdAt': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

