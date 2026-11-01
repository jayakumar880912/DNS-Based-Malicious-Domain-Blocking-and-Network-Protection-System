"""
AegisDNS - Utilities Package
"""

from utils.domain_utils import (
    normalize_domain,
    is_valid_domain,
    calculate_shannon_entropy,
    is_high_risk_tld,
    matches_suspicious_patterns
)
from utils.validators import (
    validate_email,
    validate_username,
    validate_password,
    sanitize_string
)
from utils.security import (
    get_current_user_obj,
    admin_required
)

__all__ = [
    'normalize_domain',
    'is_valid_domain',
    'calculate_shannon_entropy',
    'is_high_risk_tld',
    'matches_suspicious_patterns',
    'validate_email',
    'validate_username',
    'validate_password',
    'sanitize_string',
    'get_current_user_obj',
    'admin_required'
]

