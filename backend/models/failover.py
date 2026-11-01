"""
AegisDNS - Self-Recovering DNS Failover Models
SQLAlchemy ORM models for DNS Resolver Configuration and Failover Incident Tracking.
"""

from datetime import datetime, timezone
from extensions import db


class DnsResolverConfig(db.Model):
    """
    Configured DNS Resolvers (Primary, Secondary, Tertiary backups)
    with health telemetry and security verification status.
    """
    __tablename__ = 'dns_resolvers'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(64), nullable=False)
    port = db.Column(db.Integer, nullable=False, default=53)
    protocol = db.Column(db.String(20), nullable=False, default='UDP')  # UDP, TCP, DoH, DoT
    priority = db.Column(db.Integer, nullable=False, default=1)  # 1 = Primary, 2 = Secondary, 3 = Tertiary
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_primary = db.Column(db.Boolean, nullable=False, default=False)
    health_status = db.Column(db.String(30), nullable=False, default='HEALTHY')  # HEALTHY, DEGRADED, OFFLINE, UNVERIFIED, COMPROMISED
    latency_ms = db.Column(db.Float, nullable=False, default=0.0)
    packet_loss_pct = db.Column(db.Float, nullable=False, default=0.0)
    is_verified_secure = db.Column(db.Boolean, nullable=False, default=True)
    verification_details = db.Column(db.Text, nullable=True)
    last_checked_at = db.Column(db.DateTime, nullable=True)
    consecutive_failures = db.Column(db.Integer, nullable=False, default=0)
    consecutive_successes = db.Column(db.Integer, nullable=False, default=0)
    total_queries_served = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'ipAddress': self.ip_address,
            'port': self.port,
            'protocol': self.protocol,
            'priority': self.priority,
            'isActive': self.is_active,
            'isPrimary': self.is_primary,
            'healthStatus': self.health_status,
            'latencyMs': round(self.latency_ms, 2) if self.latency_ms else 0.0,
            'packetLossPct': round(self.packet_loss_pct, 1) if self.packet_loss_pct else 0.0,
            'isVerifiedSecure': self.is_verified_secure,
            'verificationDetails': self.verification_details,
            'lastCheckedAt': self.last_checked_at.isoformat() if self.last_checked_at else None,
            'consecutiveFailures': self.consecutive_failures,
            'consecutiveSuccesses': self.consecutive_successes,
            'totalQueriesServed': self.total_queries_served,
            'createdAt': self.created_at.isoformat() if self.created_at else None,
            'updatedAt': self.updated_at.isoformat() if self.updated_at else None
        }


class FailoverEvent(db.Model):
    """
    Audit log of automated and manual DNS failover events and recovery timelines.
    Tracks MTTR (Mean Time to Recovery) and ensures security preservation guarantee.
    """
    __tablename__ = 'failover_events'

    id = db.Column(db.Integer, primary_key=True)
    event_uuid = db.Column(db.String(64), unique=True, nullable=False)
    trigger_reason = db.Column(db.String(100), nullable=False)  # TIMEOUT_DETECTED, CONSECUTIVE_SERVFAIL, HIGH_LATENCY_SPIKE, SIMULATED_OUTAGE_DRILL, MANUAL_OPERATOR_SWITCH
    from_resolver_id = db.Column(db.Integer, db.ForeignKey('dns_resolvers.id', ondelete='SET NULL'), nullable=True)
    from_resolver_name = db.Column(db.String(100), nullable=False)
    from_resolver_ip = db.Column(db.String(64), nullable=False)
    to_resolver_id = db.Column(db.Integer, db.ForeignKey('dns_resolvers.id', ondelete='SET NULL'), nullable=True)
    to_resolver_name = db.Column(db.String(100), nullable=False)
    to_resolver_ip = db.Column(db.String(64), nullable=False)
    verification_passed = db.Column(db.Boolean, nullable=False, default=True)
    failover_timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    recovery_timestamp = db.Column(db.DateTime, nullable=True)
    recovery_duration_seconds = db.Column(db.Float, nullable=True)  # MTTR for this event
    queries_handled_on_backup = db.Column(db.Integer, nullable=False, default=0)
    blocked_threats_during_failover = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(30), nullable=False, default='ACTIVE_FAILOVER')  # ACTIVE_FAILOVER, RECOVERED_NORMAL, FAILED_VERIFICATION
    security_integrity_verified = db.Column(db.Boolean, nullable=False, default=True)  # True = blocklists remained 100% active
    incident_summary = db.Column(db.Text, nullable=True)
    audit_report = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    from_resolver = db.relationship('DnsResolverConfig', foreign_keys=[from_resolver_id])
    to_resolver = db.relationship('DnsResolverConfig', foreign_keys=[to_resolver_id])

    def to_dict(self):
        return {
            'id': self.id,
            'eventUuid': self.event_uuid,
            'triggerReason': self.trigger_reason,
            'fromResolverId': self.from_resolver_id,
            'fromResolverName': self.from_resolver_name,
            'fromResolverIp': self.from_resolver_ip,
            'toResolverId': self.to_resolver_id,
            'toResolverName': self.to_resolver_name,
            'toResolverIp': self.to_resolver_ip,
            'verificationPassed': self.verification_passed,
            'failoverTimestamp': self.failover_timestamp.isoformat() if self.failover_timestamp else None,
            'recoveryTimestamp': self.recovery_timestamp.isoformat() if self.recovery_timestamp else None,
            'recoveryDurationSeconds': round(self.recovery_duration_seconds, 2) if self.recovery_duration_seconds is not None else None,
            'queriesHandledOnBackup': self.queries_handled_on_backup,
            'blockedThreatsDuringFailover': self.blocked_threats_during_failover,
            'status': self.status,
            'securityIntegrityVerified': self.security_integrity_verified,
            'incidentSummary': self.incident_summary,
            'auditReport': self.audit_report,
            'createdAt': self.created_at.isoformat() if self.created_at else None
        }

