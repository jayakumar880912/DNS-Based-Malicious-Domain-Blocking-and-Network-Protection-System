"""
AegisDNS - DNS Monitoring Logs Model
Tracks all resolved, failed, and sinkholed DNS queries.
"""

from datetime import datetime, timezone
from extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class DnsLog(db.Model):
    __tablename__ = 'dns_logs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    log_uuid = db.Column(db.String(50), nullable=False, index=True) # e.g. DNS-8910
    domain = db.Column(db.String(255), nullable=False, index=True)
    client_ip = db.Column(db.String(60), nullable=False, index=True)
    query_type = db.Column(db.String(20), nullable=False, default='A') # A, AAAA, TXT, CNAME, MX
    resolved_ip = db.Column(db.String(100), nullable=True)
    response_time_ms = db.Column(db.Float, nullable=False, default=12.0)
    status = db.Column(db.String(30), nullable=False, index=True) # 'ALLOWED', 'BLOCKED', 'SUSPICIOUS'
    category = db.Column(db.String(100), nullable=True, default='Standard Query')
    is_sinkholed = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)

    def to_dict(self):
        return {
            'id': self.log_uuid or f"DNS-{self.id}",
            'domain': self.domain,
            'clientIp': self.client_ip,
            'queryType': self.query_type,
            'resolvedIp': self.resolved_ip or ('0.0.0.0 (Sinkholed)' if self.is_sinkholed else 'N/A'),
            'responseTimeMs': round(self.response_time_ms, 1),
            'status': self.status,
            'category': self.category or 'General DNS',
            'isSinkholed': self.is_sinkholed,
            'timestamp': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

