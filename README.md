# AegisDNS — DNS-Based Malicious Domain Blocking and Network Protection System
## Enterprise Cybersecurity Web Application Frontend

A modern, professional, high-performance cybersecurity frontend designed for real-time DNS telemetry, domain reputation inspection, threat classification, sinkhole blacklist management, and immutable audit logging.

Built with dark navy and pitch-black themes, glowing neon cyan accents, glassmorphism cards, responsive layouts, and interactive Chart.js visualizations.

---

## 1. Directory Structure

```text
frontend/
├── index.html                  # Landing Page (Hero, animated network canvas, features, interactive probe)
├── login.html                  # Analyst Login Page (Validation, show/hide password, demo autofill)
├── register.html               # SecOps Registration Page (Validation, live password strength meter)
├── dashboard.html              # Main Security Operations Dashboard (5 metric cards, traffic & threat charts)
├── domain-checker.html         # Domain Security Checker (Radar scan animation, Safe/Malicious/Suspicious verdicts)
├── dns-monitoring.html         # Live DNS Traffic Monitoring (Search, filters, sorting, live stream simulator, CSV export)
├── threat-detection.html       # Threat Detection & Intelligence (Severity badges, IOC inspection modal, metrics)
├── blocked-domains.html        # Blocked Domains Management (Add custom block rule modal, unblock whitelist action)
├── activity-logs.html          # System Activity & Forensic Audit Trail (Search, filter, export to CSV)
├── settings.html               # System Settings (Master protection toggle, DoH/DoT switches, profile, password)
├── css/
│   ├── cyber-theme.css         # Design tokens, dark navy glassmorphism palette, neon glows, typography, badges
│   ├── dashboard-layout.css    # Collapsible sidebar, topbar ticker, profile dropdown, responsive drawer
│   ├── components.css          # Radar scanner, result verdict cards, modal styles, input groups, switches
│   └── landing.css             # Hero network canvas, shield radar graphic, step pipeline, metrics strip
├── js/
│   ├── mock-data.js            # Decoupled realistic cybersecurity demonstration data store
│   ├── api-service.js          # REST API integration layer (ready for Python Flask)
│   ├── auth.js                 # Authentication logic, form validation, and session storage
│   ├── cyber-ui.js             # Sidebar collapse, global protection state sync, toast alerts, counter animation
│   ├── charts-config.js        # Chart.js neon gradient configurations (Traffic line & Threat donut charts)
│   ├── landing.js              # HTML5 particle node canvas animation & hero domain probe
│   ├── dashboard.js            # Dashboard controller, live metric counters, recent activities stream
│   ├── domain-checker.js       # Domain inspection scanner, verdict builder, Shannon entropy scoring
│   ├── dns-monitoring.js       # Live DNS logs table, real-time query stream generator, CSV export
│   ├── threat-detection.js     # Threat metrics, severity filter, detailed IOC forensics modal
│   ├── blocked-domains.js      # Blocklist table, custom block modal form, unblock actions
│   ├── activity-logs.js        # Audit trail controller, filter by type/status, CSV export
│   └── settings.js             # Protection toggles, DoH/DoT switches, profile update, cache flusher
└── README.md                   # Complete documentation and Flask backend integration guide
```

---

## 2. Key Pages and Features

| Page | URL / File | Features & Capabilities |
| :--- | :--- | :--- |
| **Landing Page** | `index.html` | Cyber network particle canvas, hero domain probe, 6 core feature highlights, 4-step resolution pipeline, metrics strip, compliance footer. |
| **Login Page** | `login.html` | Form validation, password visibility toggle, remember me, quick demo credentials filler button. |
| **Registration Page** | `register.html` | Full name, email, username, password validation, live password strength meter, policy consent checkbox. |
| **Main Dashboard** | `dashboard.html` | 5 key metric cards (Total Requests, Safe, Blocked, Suspicious, Protection Status), 24h DNS activity chart, threat donut chart, recent activities feed. |
| **Domain Security Checker** | `domain-checker.html` | Interactive domain input, radar scan animation, SAFE (green) / MALICIOUS (red) / SUSPICIOUS (orange) verdict cards with Shannon entropy, WHOIS, and threat feeds. |
| **DNS Monitoring** | `dns-monitoring.html` | Real-time DNS query logs, query types (A, AAAA, TXT, CNAME), latency, decision status, auto-stream simulator toggle, search/sort, CSV export. |
| **Threat Detection** | `threat-detection.html` | Severity breakdown (Critical, High, Medium, Low), threat categories (Phishing, C2 Botnet, Malware Dropper, Cryptomining, DGA), detailed IOC modal. |
| **Blocked Domains** | `blocked-domains.html` | Sinkhole blacklisted domains, add custom block rule modal, unblock/whitelist domain with confirmation, search and category filters. |
| **Activity Logs** | `activity-logs.html` | Immutable forensic audit trail for compliance, filtering by event type and status, search, CSV export. |
| **Settings** | `settings.html` | Master network protection toggle, automatic blocking switch, sensitivity slider, DoH/DoT toggles, upstream DNS configuration, user profile, password update, DNS cache flush. |

---

## 3. Architecture & Backend Integration Readiness

### Important Security Architecture Notice
> **DNS Resolution and Packet Filtering Notice:**
> Actual network-level packet interception, DNS resolution, and sinkhole redirection (`0.0.0.0`) are executed exclusively by the backend daemon (Python Flask / DNS Resolver engine on port 53). The frontend interface communicates with backend REST APIs to present telemetry, trigger policy enforcement, and configure rules.

### Connecting to Python Flask Backend
In `frontend/js/api-service.js`, switch `USE_MOCK` from `true` to `false`:

```javascript
const CONFIG = {
  USE_MOCK: false,                      // <-- Set to false to connect to Flask
  BASE_URL: 'http://localhost:5000/api', // <-- Your Flask backend base URL
  TIMEOUT_MS: 5000
};
```

### Python Flask Endpoints Specification

Below is the corresponding Python Flask API blueprint for reference:

```python
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing for the frontend

# 1. Authentication
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    # Validate credentials against user database
    return jsonify({
        "success": True,
        "token": "jwt_token_sample",
        "user": {"name": "SecOps Administrator", "role": "Security Lead"}
    })

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    # Create user profile
    return jsonify({"success": True, "token": "jwt_token_sample"})

# 2. Dashboard Telemetry
@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    return jsonify({
        "totalDnsRequests": 2845920,
        "safeDomains": 2712490,
        "blockedDomains": 98640,
        "suspiciousDomains": 34790,
        "protectionStatus": "ACTIVE",
        "uptime": "99.98%",
        "currentLatencyMs": 14,
        "trafficHourly": { ... },
        "threatCategories": { ... }
    })

# 3. Domain Security Checker
@app.route('/api/check-domain', methods=['POST'])
def check_domain():
    domain = request.json.get('domain')
    # Run domain against threat intelligence feeds, DGA entropy, and sinkhole rules
    return jsonify({
        "domain": domain,
        "status": "MALICIOUS", # or "SAFE" or "SUSPICIOUS"
        "category": "Credential Phishing / Typosquatting",
        "riskScore": 98,
        "ip": "0.0.0.0 (Sinkholed)",
        "nameserver": "ns1.bulletproof-dns.is",
        "verdictReason": "Flagged on active threat feed",
        "checkedAt": "22:58:11"
    })

# 4. DNS Request Logs
@app.route('/api/dns/logs', methods=['GET'])
def get_dns_logs():
    # Return recent DNS queries from backend SQLite / Redis cache
    return jsonify([...])

# 5. Threats & Blocked Domains
@app.route('/api/threats', methods=['GET'])
def get_threats():
    return jsonify([...])

@app.route('/api/blocked-domains', methods=['GET', 'POST'])
def manage_blocked_domains():
    if request.method == 'POST':
        # Add new domain to local sinkhole rule table
        return jsonify(request.json), 201
    return jsonify([...])

@app.route('/api/blocked-domains/<domain_id>', methods=['DELETE'])
def unblock_domain(domain_id):
    # Remove from sinkhole table
    return jsonify({"success": True})

# 6. Activity & Settings
@app.route('/api/activity-logs', methods=['GET'])
def get_activity_logs():
    return jsonify([...])

@app.route('/api/settings', methods=['GET', 'PUT'])
def system_settings():
    if request.method == 'PUT':
        # Update daemon protection parameters
        return jsonify(request.json)
    return jsonify({ "protectionEnabled": True, "dohEnabled": True })

if __name__ == '__main__':
    app.run(port=5000, debug=True)
```

---

## 4. Running Locally in a Browser

You can open the application directly in any modern browser:

1. **Option A: Direct File Open**
   - Double-click `frontend/index.html` to open in Chrome, Firefox, Edge, or Safari.

2. **Option B: Local Web Server (Recommended)**
   Using Python's built-in HTTP server:
   ```bash
   cd frontend
   python -m http.server 8080
   ```
   Then open `http://localhost:8080` in your web browser.

---

## 5. Technology Stack
- **HTML5 & CSS3**: Modern custom cyber dark theme, glassmorphism (`backdrop-filter`), CSS variables, custom scrollbars.
- **Bootstrap 5.3.3**: Grid layout, flex utilities, modals, and responsive collapse offcanvas.
- **FontAwesome 6.5.1**: Cybersecurity, shield, network, and status icons.
- **Vanilla ES6+ JavaScript**: Modular architecture (`CyberApiService`, `CyberUI`, `CyberCharts`).
- **Chart.js**: Glowing neon area chart and threat category donut visualizations.

