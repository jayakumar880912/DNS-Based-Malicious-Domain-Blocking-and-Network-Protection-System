# AegisDNS — Backend & DNS Filtering Resolver Engine
## DNS-Based Malicious Domain Blocking and Network Protection System

A secure, scalable, and modular backend built with Python 3, Flask REST API, SQLAlchemy ORM, MySQL Database, Flask-JWT-Extended, dnspython, and real threat intelligence integration.

---

## 1. Architecture Overview

```text
backend/
├── app.py                      # Flask Application Factory & concurrent DNS Resolver starter
├── config.py                   # Environment-driven configuration (MySQL & SQLite fallback)
├── extensions.py               # SQLAlchemy, Flask-JWT-Extended, and CORS instances
├── init_db.py                  # Standalone database initialization & seeding script
├── schema.sql                  # MySQL Relational Database Schema DDL
├── requirements.txt            # Python dependencies
├── .env.example                # Environment variable configuration template
│
├── models/                     # SQLAlchemy Relational Models
│   ├── __init__.py             # Exports all models
│   ├── user.py                 # Users table (auth, password hashing, roles)
│   ├── domain.py               # DomainChecks, MaliciousDomains, SuspiciousDomains, BlockedDomains
│   ├── dns_log.py              # DnsLogs table (resolution telemetry)
│   ├── threat.py               # ThreatDetections table (incident records & IOCs)
│   ├── activity.py             # ActivityLogs table (audit trail)
│   └── setting.py              # SystemSettings table (runtime protection policies)
│
├── routes/                     # Flask REST API Blueprints
│   ├── __init__.py             # Blueprint registration
│   ├── auth.py                 # /api/auth (register, login, profile, logout)
│   ├── domains.py              # /api/domains/check & /api/check-domain
│   ├── dns.py                  # /api/dns/logs & /api/dns/statistics
│   ├── threats.py              # /api/threats & /api/threats/statistics
│   ├── blocked.py              # /api/blocked-domains (GET, POST, DELETE)
│   ├── dashboard.py            # /api/dashboard/statistics & /api/dashboard/charts
│   ├── settings.py             # /api/settings & /api/settings/protection-toggle
│   └── activity.py             # /api/activity-logs (paginated audit trail)
│
├── services/                   # Core Business Logic Layer
│   ├── __init__.py             # Exports all services
│   ├── auth_service.py         # Registration, password hashing, JWT generation
│   ├── dns_service.py          # dnspython live resolution, latency measurement, query logging
│   ├── threat_intelligence.py  # URLhaus & Google Safe Browsing integration
│   ├── domain_checker_service.py # 10-step multi-factor domain evaluation
│   ├── stats_service.py        # Real-time database aggregation for dashboard
│   └── activity_service.py     # Central audit trail logging
│
├── dns_resolver/               # DNS Filtering Engine Prototype
│   ├── __init__.py
│   ├── sinkhole.py             # RFC-compliant 0.0.0.0 and NXDOMAIN response generator
│   └── resolver_server.py      # UDP DNS server on port 53/5353 with blocklist filtering
│
├── utils/                      # Security & Utility Functions
│   ├── __init__.py
│   ├── domain_utils.py         # RFC normalization, Shannon entropy, high-risk TLDs
│   ├── validators.py           # Email, username, password complexity validation
│   └── security.py             # Current user resolver & role-based decorators
│
└── tests/                      # Automated Pytest Test Suite (20 Tests)
    ├── __init__.py
    ├── conftest.py             # Isolated SQLite in-memory test fixtures
    ├── test_auth.py            # Registration, login, validation tests
    ├── test_domain_checker.py  # SAFE, MALICIOUS, and SUSPICIOUS classification tests
    ├── test_blocked_domains.py # Blocklist add, list, duplicate, unblock tests
    ├── test_dns_resolver.py    # dnspython and sinkhole response tests
    └── test_dashboard.py       # Metrics, charts, and protection toggle tests
```

---

## 2. Prerequisites & Installation

### Requirements
- Python 3.10+ (tested and verified on Python 3.13)
- MySQL Server 8.0+ (or MariaDB)
- `pip` package manager

### Step 1: Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### Step 2: Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Edit `.env` to configure your MySQL connection details:
```ini
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=aegis_dns_db

DATABASE_URL=mysql+pymysql://root:your_mysql_password@127.0.0.1:3306/aegis_dns_db
```

> **Note on Local SQLite Fallback:**
> If MySQL is not running on your machine during development or automated testing, the backend will automatically fall back to a local SQLite database (`aegis_dns.db`) with zero manual configuration required.

---

## 3. Database Initialization & Schema

### Option A: Using the Python Initializer Script
```bash
python init_db.py
```
This script will:
1. Connect to the configured MySQL database (or SQLite fallback).
2. Create all 9 database tables (`users`, `domain_checks`, `malicious_domains`, `suspicious_domains`, `dns_logs`, `blocked_domains`, `threat_detections`, `activity_logs`, `system_settings`).
3. Seed the default administrator account:
   - **Username**: `admin_secops`
   - **Email**: `admin@aegisdns.security`
   - **Password**: `CyberShield#2026!`
4. Seed baseline threat intelligence rules and system settings.

### Option B: Using MySQL Command-Line Client
```bash
mysql -u root -p < schema.sql
```

---

## 4. Running the Application

### Running the Web REST API & DNS Filtering Resolver
```bash
python app.py
```

Output:
```text
===================================================================
 AegisDNS Web REST API starting at http://127.0.0.1:5000
 Local DNS Resolver active at UDP 127.0.0.1:5353
===================================================================
```

- **Flask REST API**: Runs on `http://127.0.0.1:5000`
- **DNS Filtering Resolver**: Concurrently listens for DNS queries on UDP `127.0.0.1:5353`

---

## 5. Testing the DNS Filtering Resolver Prototype

The DNS filtering resolver intercepts inbound UDP queries, checks the blocklist, and returns:
- **Blocked domain**: Synthetic `0.0.0.0` sinkhole answer.
- **Clean domain**: Forwards to upstream DNS (`1.1.1.1:53`) and returns the real IP.

You can test the resolver using `nslookup` or `dig`:

### Test 1: Querying a Malicious Blocked Domain
```bash
nslookup -port=5353 paypa1-security-update-verify.com 127.0.0.1
```
**Expected Output:**
```text
Server:  127.0.0.1
Address: 127.0.0.1#5353

Name:    paypa1-security-update-verify.com
Address: 0.0.0.0
```

### Test 2: Querying a Legitimate Safe Domain
```bash
nslookup -port=5353 google.com 127.0.0.1
```
**Expected Output:**
```text
Server:  127.0.0.1
Address: 127.0.0.1#5353

Non-authoritative answer:
Name:    google.com
Address: 142.250.190.46
```

### Running the Resolver as a Standalone Daemon
```bash
python -m dns_resolver.resolver_server
```

---

## 6. Running the Automated Test Suite

A complete test suite covering all modules is located in `backend/tests/`:

```bash
pytest backend/tests -v
```

**Test Coverage Summary:**
- `test_auth.py`: Registration, duplicate email rejection, duplicate username rejection, valid login, invalid password rejection.
- `test_domain_checker.py`: Safe domain verification, malicious blocklist matching, DGA Shannon entropy detection, malformed domain rejection.
- `test_blocked_domains.py`: Blocklist retrieval, adding block rules, duplicate block rejection, unblocking/whitelisting.
- `test_dns_resolver.py`: Live dnspython resolution, synthetic 0.0.0.0 packet generation, resolver block decision cache.
- `test_dashboard.py`: Real-time database metrics aggregation, Chart.js dataset formatting, settings updates, protection toggle.

---

## 7. REST API Documentation

### Authentication Endpoints
| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Register new security analyst profile | No |
| `POST` | `/api/auth/login` | Authenticate and obtain JWT access token | No |
| `GET` | `/api/auth/profile` | Retrieve current authenticated user profile | Yes (Bearer) |
| `PUT` | `/api/auth/profile` | Update profile information | Yes (Bearer) |
| `POST` | `/api/auth/change-password` | Update master password | Yes (Bearer) |
| `POST` | `/api/auth/logout` | Invalidate current JWT access token | Yes (Bearer) |

### Domain Security Checker Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/domains/check` | Analyze domain reputation, entropy, and sinkhole policy |
| `GET` | `/api/domains/history` | Retrieve historical domain inspection records |

### DNS Monitoring Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/dns/logs` | Query DNS resolution logs (supports `status`, `type`, `search`) |
| `GET` | `/api/dns/statistics` | Retrieve total, allowed, blocked query counts and average latency |

### Threat Detection Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/threats` | Retrieve detected threats with severity indicators |
| `GET` | `/api/threats/statistics` | Retrieve severity and threat category distribution counts |

### Blocked Domains Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/blocked-domains` | List all active sinkholed domains |
| `POST` | `/api/blocked-domains` | Add custom domain block rule |
| `DELETE` | `/api/blocked-domains/{id}` | Unblock / whitelist domain by ID, policy code, or name |

### Dashboard & Analytics Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/dashboard/statistics` | Complete dashboard overview metrics |
| `GET` | `/api/dashboard/recent-activities`| Latest security resolution events |
| `GET` | `/api/dashboard/charts` | 24-hour traffic and threat category datasets for Chart.js |

### Settings & Policies Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/settings` | Retrieve current network protection parameters |
| `PUT` | `/api/settings` | Update protection parameters, DoH/DoT, and alert emails |
| `POST` | `/api/settings/protection-toggle` | Quick-toggle master network protection state |

### Activity Logs Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/activity-logs` | Retrieve chronological audit trail with type/status filters |

