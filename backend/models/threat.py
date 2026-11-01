"""
AegisDNS - Threat Detection Model
Tracks threat telemetry, severity ratings, and Indicator of Compromise (IOC) records.
"""

from datetime import datetime, timezone
from extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class ThreatDetection(db.Model):
    __tablename__ = 'threat_detections'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    incident_id = db.Column(db.String(50), nullable=False, unique=True, index=True) # e.g. THR-7721
    domain = db.Column(db.String(255), nullable=False, index=True)
    category = db.Column(db.String(100), nullable=False, index=True) # Phishing, Command & Control, Malware Dropper, etc.
    severity = db.Column(db.String(30), nullable=False, index=True) # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    source_feed = db.Column(db.String(120), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False, default=90)
    action_taken = db.Column(db.String(120), nullable=False, default='DNS Sinkhole (0.0.0.0)')
    target_ip = db.Column(db.String(100), nullable=True)
    client_origin = db.Column(db.String(150), nullable=True)
    ioc_details = db.Column(db.Text, nullable=True)
    detected_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)

    def to_dict(self):
        return {
            'id': self.incident_id or f"THR-{self.id}",
            'domain': self.domain,
            'category': self.category,
            'severity': self.severity,
            'sourceFeed': self.source_feed,
            'riskScore': self.risk_score,
            'actionTaken': self.action_taken,
            'targetIp': self.target_ip or 'Unspecified',
            'clientOrigin': self.client_origin or 'Internal Subnet Client',
            'iocDetails': self.ioc_details or 'Indicator flagged by automated heuristics.',
            'detectionTime': self.detected_at.strftime('%Y-%m-%d %H:%M:%S'),
            'timestamp': self.detected_at.isoformat()
        }

