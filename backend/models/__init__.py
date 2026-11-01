"""
AegisDNS - Models Package
Exports all SQLAlchemy ORM models.
"""

from models.user import User
from models.domain import DomainCheck, MaliciousDomain, SuspiciousDomain, BlockedDomain
from models.dns_log import DnsLog
from models.threat import ThreatDetection
from models.activity import ActivityLog
from models.setting import SystemSetting

__all__ = [
    'User',
    'DomainCheck',
    'MaliciousDomain',
    'SuspiciousDomain',
    'BlockedDomain',
    'DnsLog',
    'ThreatDetection',
    'ActivityLog',
    'SystemSetting'
]

