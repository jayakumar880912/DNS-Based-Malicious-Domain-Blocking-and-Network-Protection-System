"""
DNS-Based Malicious Domain Blocking and Network Protection System
Python Flask Backend Starter Template

Run:
    pip install flask flask-cors
    python flask_backend_example.py
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import datetime
import math

app = Flask(__name__)
# Enable CORS for the frontend origin
CORS(app)

# In-memory Demonstration Store
DATA_STORE = {
    "protection_enabled": True,
    "blocked_domains": [
        {
            "id": "BLK-101",
            "domain": "paypa1-security-update-verify.com",
            "threatCategory": "Phishing",
            "detectionDate": "2026-10-31",
            "blockingReason": "Brand Typosquatting / Credential Harvesting",
            "blockingStatus": "Active Blocked",
            "source": "Automated Threat Intelligence",
            "severity": "Critical"
        },
        {
            "id": "BLK-102",
            "domain": "c2-trojan-controller-sync.net",
            "threatCategory": "Command & Control",
            "detectionDate": "2026-10-31",
            "blockingReason": "Cobalt Strike C2 Beacon Rendezvous",
            "blockingStatus": "Active Blocked",
            "source": "Automated Threat Intelligence",
            "severity": "Critical"
        }
    ],
    "dns_logs": [
        { "id": "DNS-8910", "timestamp": "2026-10-31 22:58:14", "clientIp": "192.168.1.104", "domain": "api.github.com", "queryType": "A", "responseTimeMs": 11, "status": "ALLOWED", "category": "Software / API" },
        { "id": "DNS-8909", "timestamp": "2026-10-31 22:58:11", "clientIp": "192.168.1.142", "domain": "paypa1-security-update-verify.com", "queryType": "A", "responseTimeMs": 4, "status": "BLOCKED", "category": "Phishing" },
        { "id": "DNS-8908", "timestamp": "2026-10-31 22:58:08", "clientIp": "192.168.1.88",  "domain": "update.microsoft.com", "queryType": "AAAA", "responseTimeMs": 18, "status": "ALLOWED", "category": "OS Services" }
    ]
}

def calculate_entropy(domain_name):
    """Calculates Shannon entropy of domain string for DGA detection"""
    p, lns = {}, float(len(domain_name))
    for c in domain_name:
        p[c] = p.get(c, 0) + 1
    return -sum([(count / lns) * math.log2(count / lns) for count in p.values()])

# 1. Authentication Endpoints
@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    data = request.json or {}
    identifier = data.get('identifier', 'admin')
    return jsonify({
        "success": True,
        "token": "jwt_token_sample_secops_9824",
        "user": {
            "name": "SecOps Administrator",
            "username": identifier,
            "email": "admin@aegisdns.security",
            "role": "Cybersecurity Incident Lead",
            "avatarInitials": "SA"
        }
    })

@app.route('/api/auth/register', methods=['POST'])
def auth_register():
    data = request.json or {}
    return jsonify({
        "success": True,
        "token": "jwt_token_sample_registered",
        "user": {
            "name": data.get("fullName", "New Analyst"),
            "email": data.get("email", "analyst@aegisdns.security"),
            "role": "Security Analyst",
            "avatarInitials": "NA"
        }
    })

# 2. Dashboard Statistics
@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    return jsonify({
        "totalDnsRequests": 2845920,
        "safeDomains": 2712490,
        "blockedDomains": len(DATA_STORE["blocked_domains"]) * 49320,
        "suspiciousDomains": 34790,
        "protectionStatus": "ACTIVE" if DATA_STORE["protection_enabled"] else "PAUSED",
        "uptime": "99.98%",
        "currentLatencyMs": 14,
        "activeResolver": "127.0.0.1:53 (AegisDNS Sinkhole)",
        "upstreamDns": "1.1.1.1 (Cloudflare CleanBrowsing)",
        "threatEngineVersion": "v4.18.2-SecEngine",
        "lastThreatFeedUpdate": "Just now",
        "rulesCount": 148520,
        "trafficHourly": {
            "labels": ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '22:00'],
            "totalRequests": [112000, 74000, 248000, 412000, 428000, 290000, 198000],
            "safeRequests":  [107500, 71200, 237800, 393500, 408500, 277200, 189800],
            "blockedRequests": [3200, 1900, 7200, 12900, 13700, 9100, 5800],
            "suspiciousRequests": [1300, 900, 3000, 5600, 5800, 3700, 2400]
        },
        "threatCategories": {
            "labels": ['Phishing', 'Malware C2', 'DGA', 'Cryptomining', 'Ransomware'],
            "data": [41250, 26400, 14200, 10190, 6600],
            "colors": ['#ff3366', '#ff7b00', '#a855f7', '#00f0ff', '#eab308']
        }
    })

# 3. Domain Security Checker Endpoint
@app.route('/api/check-domain', methods=['POST'])
def check_domain():
    data = request.json or {}
    domain = data.get('domain', '').strip().lower()
    
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    entropy = round(calculate_entropy(domain), 2)
    now_time = datetime.datetime.now().strftime("%H:%M:%S")

    # Check if in custom blocklist
    for b in DATA_STORE["blocked_domains"]:
        if b["domain"].lower() == domain:
            return jsonify({
                "domain": domain,
                "status": "MALICIOUS",
                "category": b.get("threatCategory", "Active Sinkhole Blocklist"),
                "riskScore": 99,
                "ip": "0.0.0.0 (Sinkholed)",
                "nameserver": "ns-sinkhole.aegisdns.internal",
                "registrar": "Restricted Null-Route",
                "ageYears": 0.05,
                "country": "Sinkhole Quarantine",
                "entropyScore": f"{entropy} (Elevated)",
                "threatSources": ["Aegis Sinkhole Engine", "Threat Intelligence Feed"],
                "dnsRecords": {"A": "0.0.0.0 (Sinkholed)", "TTL": "10s"},
                "verdictReason": b.get("blockingReason", "Matched domain in local blacklist."),
                "checkedAt": now_time
            })

    # Heuristic detection
    is_phishing = any(k in domain for k in ['paypa1', 'login-verify', 'stealth', 'keylog', 'update-verify', 'trojan', 'c2-'])
    if is_phishing:
        return jsonify({
            "domain": domain,
            "status": "MALICIOUS",
            "category": "Credential Phishing / Malware Host",
            "riskScore": 96,
            "ip": "0.0.0.0 (Sinkholed)",
            "nameserver": "ns1.bulletproof-dns.is",
            "registrar": "NameCheap Privacy Protected",
            "ageYears": 0.02,
            "country": "Offshore",
            "entropyScore": f"{entropy} (High)",
            "threatSources": ["PhishTank", "AbuseIPDB (Confidence 100%)"],
            "dnsRecords": {"A": "0.0.0.0 (Sinkholed)", "TTL": "15s"},
            "verdictReason": "Malicious signature identified. Intercepted by DNS sinkhole.",
            "checkedAt": now_time
        })

    if entropy > 3.8 or domain.endswith(('.xyz', '.top', '.cc', '.stream')):
        return jsonify({
            "domain": domain,
            "status": "SUSPICIOUS",
            "category": "High Risk TLD / Shannon Entropy Alert",
            "riskScore": 72,
            "ip": "172.67.140.88",
            "nameserver": "ns2.dynamic-nameserver.net",
            "registrar": "Cloudflare Unverified Origin",
            "ageYears": 0.1,
            "country": "Distributed Cloud",
            "entropyScore": f"{entropy} (High Randomness - Possible DGA)",
            "threatSources": ["Aegis Shannon Entropy Classifier"],
            "dnsRecords": {"A": "172.67.140.88", "TTL": "120s"},
            "verdictReason": "High structural randomness indicates potential algorithmic generation. Monitored.",
            "checkedAt": now_time
        })

    # Clean Domain
    return jsonify({
        "domain": domain,
        "status": "SAFE",
        "category": "Standard Verified Service",
        "riskScore": 2,
        "ip": "142.250.190.46",
        "nameserver": "ns1.authoritative-dns.org",
        "registrar": "Verisign / MarkMonitor",
        "ageYears": 12.0,
        "country": "United States",
        "entropyScore": f"{entropy} (Normal)",
        "threatSources": ["AlienVault OTX (Clean)", "VirusTotal 0/88", "AbuseIPDB (0%)"],
        "dnsRecords": {"A": "142.250.190.46", "TTL": "300s"},
        "verdictReason": "Authoritative domain with clean reputation. Resolution approved.",
        "checkedAt": now_time
    })

# 4. DNS Request Logs Endpoint
@app.route('/api/dns/logs', methods=['GET'])
def get_dns_logs():
    return jsonify(DATA_STORE["dns_logs"])

# 5. Blocked Domains Endpoints
@app.route('/api/blocked-domains', methods=['GET'])
def get_blocked_domains():
    return jsonify(DATA_STORE["blocked_domains"])

@app.route('/api/blocked-domains', methods=['POST'])
def add_blocked_domain():
    data = request.json or {}
    domain = data.get('domain', '').strip().lower()
    new_entry = {
        "id": f"BLK-{100 + len(DATA_STORE['blocked_domains']) + 1}",
        "domain": domain,
        "threatCategory": data.get("threatCategory", "Custom Administrator Policy"),
        "detectionDate": datetime.date.today().isoformat(),
        "blockingReason": data.get("blockingReason", "Manually blacklisted by analyst"),
        "blockingStatus": "Active Blocked",
        "source": "Manual Administrator Rule",
        "severity": data.get("severity", "High")
    }
    DATA_STORE["blocked_domains"].insert(0, new_entry)
    return jsonify(new_entry), 201

@app.route('/api/blocked-domains/<domain_id>', methods=['DELETE'])
def remove_blocked_domain(domain_id):
    DATA_STORE["blocked_domains"] = [b for b in DATA_STORE["blocked_domains"] if b["id"] != domain_id and b["domain"] != domain_id]
    return jsonify({"success": True})

# 6. Settings Endpoints
@app.route('/api/settings', methods=['GET', 'PUT'])
def handle_settings():
    if request.method == 'PUT':
        data = request.json or {}
        if "protectionEnabled" in data:
            DATA_STORE["protection_enabled"] = data["protectionEnabled"]
        return jsonify(data)
    return jsonify({
        "protectionEnabled": DATA_STORE["protection_enabled"],
        "dnsProtectionStatus": "ACTIVE" if DATA_STORE["protection_enabled"] else "PAUSED",
        "primaryDnsResolver": "127.0.0.1:53",
        "upstreamDns": "1.1.1.1",
        "dohEnabled": True,
        "dotEnabled": False,
        "autoBlock": True,
        "blockingSensitivity": "Strict"
    })

if __name__ == '__main__':
    print("===================================================================")
    print(" AegisDNS Flask Backend API running at http://localhost:5000")
    print(" To connect frontend: change USE_MOCK to false in js/api-service.js")
    print("===================================================================")
    app.run(host='0.0.0.0', port=5000, debug=True)

