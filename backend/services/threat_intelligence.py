"""
AegisDNS - Threat Intelligence Service
Integrates with external threat intelligence APIs (URLhaus, Google Safe Browsing)
and cross-references local verified malware and phishing databases.
"""

import logging
import requests
from config import Config
from models.domain import MaliciousDomain, SuspiciousDomain

logger = logging.getLogger(__name__)


class ThreatIntelligenceService:
    @staticmethod
    def query_urlhaus(domain: str) -> dict:
        """
        Queries abuse.ch URLhaus public threat intelligence API for verified malware URLs/hosts.
        """
        try:
            url = "https://urlhaus-api.abuse.ch/v1/host/"
            data = {"host": domain}
            response = requests.post(url, data=data, timeout=3.5)

            if response.status_code == 200:
                result = response.json()
                query_status = result.get('query_status')
                if query_status == 'ok':
                    urls_count = result.get('url_count', 0)
                    threat = result.get('threat', 'malware')
                    first_seen = result.get('firstseen', 'Unknown')
                    return {
                        'is_malicious': True,
                        'source': 'URLhaus (abuse.ch)',
                        'category': f"Malware Host ({threat})",
                        'confidence': 95,
                        'details': f"Verified by URLhaus: {urls_count} malicious payload URL(s) detected. First seen: {first_seen}"
                    }
                elif query_status == 'no_results':
                    return {
                        'is_malicious': False,
                        'source': 'URLhaus (abuse.ch)',
                        'details': 'No active malware listings found in URLhaus database.'
                    }
        except requests.exceptions.RequestException as e:
            logger.warning(f"URLhaus API query failed for {domain}: {e}")

        return None

    @staticmethod
    def query_google_safe_browsing(domain: str) -> dict:
        """
        Queries Google Safe Browsing API v4 if API key is configured.
        """
        api_key = Config.GOOGLE_SAFE_BROWSING_API_KEY
        if not api_key:
            return None

        try:
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
            payload = {
                "client": {
                    "clientId": "AegisDNS-Network-Protection",
                    "clientVersion": "4.18.2"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [
                        {"url": f"http://{domain}/"},
                        {"url": f"https://{domain}/"}
                    ]
                }
            }

            resp = requests.post(endpoint, json=payload, timeout=3.0)
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get('matches', [])
                if matches:
                    threat_type = matches[0].get('threatType', 'MALICIOUS')
                    return {
                        'is_malicious': True,
                        'source': 'Google Safe Browsing',
                        'category': f"Phishing / Social Engineering" if threat_type == 'SOCIAL_ENGINEERING' else 'Malware',
                        'confidence': 98,
                        'details': f"Flagged by Google Safe Browsing as {threat_type}."
                    }
                return {
                    'is_malicious': False,
                    'source': 'Google Safe Browsing',
                    'details': 'Domain is not listed in Google Safe Browsing threat lists.'
                }
        except Exception as e:
            logger.warning(f"Google Safe Browsing API error: {e}")

        return None

    @classmethod
    def check_reputation(cls, domain: str) -> dict:
        """
        Checks domain reputation across local intelligence tables and remote APIs.
        """
        sources_checked = []
        is_flagged = False
        threat_category = None
        severity = 'High'
        confidence = 0
        reasons = []

        # 1. Check local verified malicious database
        local_match = MaliciousDomain.query.filter_by(domain=domain, is_active=True).first()
        if local_match:
            sources_checked.append(f"Local Threat Intel ({local_match.source})")
            return {
                'is_malicious': True,
                'is_suspicious': False,
                'threat_category': local_match.threat_category,
                'severity': local_match.severity,
                'confidence': local_match.confidence_score,
                'sources': sources_checked,
                'reason': f"Domain is cataloged in verified intelligence database: {local_match.threat_category} (Source: {local_match.source})."
            }

        # 2. Check local suspicious database
        suspicious_match = SuspiciousDomain.query.filter_by(domain=domain).first()
        if suspicious_match:
            sources_checked.append("Aegis Heuristic Threat Intel")
            return {
                'is_malicious': False,
                'is_suspicious': True,
                'threat_category': suspicious_match.threat_category,
                'severity': 'Medium',
                'confidence': 75,
                'sources': sources_checked,
                'reason': f"Flagged as suspicious: {suspicious_match.reason} (Entropy: {suspicious_match.entropy_score})."
            }

        # 3. Query external URLhaus API
        urlhaus_res = cls.query_urlhaus(domain)
        if urlhaus_res:
            sources_checked.append(urlhaus_res['source'])
            if urlhaus_res.get('is_malicious'):
                return {
                    'is_malicious': True,
                    'is_suspicious': False,
                    'threat_category': urlhaus_res['category'],
                    'severity': 'Critical',
                    'confidence': urlhaus_res['confidence'],
                    'sources': sources_checked,
                    'reason': urlhaus_res['details']
                }

        # 4. Query Google Safe Browsing if available
        gsb_res = cls.query_google_safe_browsing(domain)
        if gsb_res:
            sources_checked.append(gsb_res['source'])
            if gsb_res.get('is_malicious'):
                return {
                    'is_malicious': True,
                    'is_suspicious': False,
                    'threat_category': gsb_res['category'],
                    'severity': 'Critical',
                    'confidence': gsb_res['confidence'],
                    'sources': sources_checked,
                    'reason': gsb_res['details']
                }

        if not sources_checked:
            sources_checked.append("Threat Intelligence Engine (Clean)")

        return {
            'is_malicious': False,
            'is_suspicious': False,
            'threat_category': None,
            'severity': 'Low',
            'confidence': 0,
            'sources': sources_checked,
            'reason': 'No active threat records or malware indicators found across queried feeds.'
        }

