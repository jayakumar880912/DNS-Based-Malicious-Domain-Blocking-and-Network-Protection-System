"""
AegisDNS - Domain Utilities
Domain normalization, validation, Shannon entropy calculation, and lexical heuristics.
"""

import re
import math


# RFC 1035 / 1123 Domain Validation Pattern
DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9]'
    r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'[a-zA-Z]{2,63}$'
)

# High-risk TLDs frequently abused in malware and disposable phishing campaigns
HIGH_RISK_TLDS = {
    'top', 'xyz', 'cc', 'ru', 'biz', 'stream', 'online', 'loan', 'club', 'work', 'vip', 'link', 'tokyo'
}

# Suspicious keyword signatures commonly found in credential theft or C2 domains
SUSPICIOUS_KEYWORDS = [
    'paypa1', 'login-verify', 'security-update', 'account-verify', 'wallet-connect',
    'support-desk', 'token-claim', 'airdrop-claim', 'c2-beacon', 'keylogger', 'trojan',
    'stealth-agent', 'malware-drop', 'secure-bank', 'authorize-login'
]


def normalize_domain(domain_input: str) -> str:
    """
    Cleans and normalizes a domain string.
    Removes scheme (http/https), port numbers, path trailing elements, and whitespace.
    """
    if not domain_input or not isinstance(domain_input, str):
        return ""

    cleaned = domain_input.strip().lower()
    # Remove protocol prefix if supplied
    cleaned = re.sub(r'^https?://', '', cleaned)
    # Remove port or path if user pasted full URL
    cleaned = cleaned.split('/')[0]
    cleaned = cleaned.split(':')[0]
    # Remove trailing dot if FQDN
    cleaned = cleaned.rstrip('.')
    return cleaned


def is_valid_domain(domain: str) -> bool:
    """
    Validates domain string format against RFC standards.
    """
    if not domain or len(domain) > 253 or '.' not in domain:
        return False

    # Check each label length <= 63
    labels = domain.split('.')
    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False

    return bool(DOMAIN_REGEX.match(domain))


def calculate_shannon_entropy(domain_name: str) -> float:
    """
    Calculates Shannon entropy to detect DGA (Domain Generation Algorithms)
    and algorithmic randomness in domain naming.
    Higher entropy (> 3.8 - 4.0) indicates random character distributions.
    """
    # Exclude common TLD from entropy calculation to focus on subdomains and SLD
    clean_str = domain_name.split('.')[0] if '.' in domain_name else domain_name
    if not clean_str:
        return 0.0

    length = float(len(clean_str))
    counts = {}
    for char in clean_str:
        counts[char] = counts.get(char, 0) + 1

    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 2)


def is_high_risk_tld(domain: str) -> bool:
    """Checks if the domain uses a high-abuse TLD"""
    parts = domain.split('.')
    if len(parts) >= 2:
        return parts[-1] in HIGH_RISK_TLDS
    return False


def matches_suspicious_patterns(domain: str) -> tuple[bool, str]:
    """
    Examines domain lexical structure for typosquatting and deceptive keywords.
    """
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in domain:
            return True, f"Matched deceptive credential/malware keyword: '{kw}'"

    # Multiple consecutive hyphens
    if domain.count('-') >= 3:
        return True, "Excessive hyphenation detected (deceptive pattern)"

    # Numeric density check (e.g. paypa1, 0fficial)
    digits = sum(c.isdigit() for c in domain)
    if digits >= 5:
        return True, "High digit density in domain name"

    return False, ""

