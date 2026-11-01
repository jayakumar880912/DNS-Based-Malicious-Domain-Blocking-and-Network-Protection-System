"""
AegisDNS - Activity Logs Model
Provides an audit trail for user authentication, domain checks, policy updates, and sinkhole actions.
"""

from datetime import datetime, timezone
from extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    activity_id = db.Column(db.String(50), nullable=False, unique=True, index=True) # e.g. ACT-9081
    activity_type = db.Column(db.String(100), nullable=False, index=True)
    actor = db.Column(db.String(120), nullable=False, default='SecOps Administrator')
    target = db.Column(db.String(255), nullable=False)
    ip_origin = db.Column(db.String(60), nullable=False, default='127.0.0.1')
    status = db.Column(db.String(50), nullable=False, default='INFO') # BLOCKED, ALLOWED, SUCCESS, UPDATED, SUSPICIOUS
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)

    def to_dict(self):
        return {
            'id': self.activity_id or f"ACT-{self.id}",
            'activityType': self.activity_type,
            'actor': self.actor,
            'target': self.target,
            'ipOrigin': self.ip_origin,
            'status': self.status,
            'details': self.details or '',
            'timestamp': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'time': self.created_at.strftime('%H:%M:%S')
        }

