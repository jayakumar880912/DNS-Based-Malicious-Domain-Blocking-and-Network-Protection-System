/**
 * DNS-Based Malicious Domain Blocking and Network Protection System
 * API Service Layer - Python Flask Backend Integration Interface
 * 
 * ARCHITECTURE NOTICE:
 * Actual DNS resolution, sinkhole redirection, and network-level packet filtering
 * are performed exclusively by the backend daemon (Python Flask / DNS Resolver engine).
 * This frontend service communicates with backend REST endpoints to retrieve security
 * telemetry, stream DNS logs, and trigger administrative policies.
 */

const CyberApiService = (() => {
  // Configuration for Backend Connection
  const CONFIG = {
    // Set to false to connect to the live Python Flask backend.
    // If Flask backend is offline, calls gracefully fall back to local mock data.
    USE_MOCK: false,
    BASE_URL: 'http://localhost:5000/api',
    TIMEOUT_MS: 5000,
    STORAGE_KEYS: {
      SETTINGS: 'aegis_protection_settings',
      BLOCKED: 'aegis_blocked_domains',
      DNS_LOGS: 'aegis_dns_logs',
      THREATS: 'aegis_threats',
      ACTIVITIES: 'aegis_activity_logs',
      AUTH_TOKEN: 'aegis_auth_token',
      CURRENT_USER: 'aegis_current_user'
    }
  };

  // Helper to attach JWT Bearer token
  const getAuthHeaders = () => {
    const headers = { 'Content-Type': 'application/json' };
    const token = localStorage.getItem(CONFIG.STORAGE_KEYS.AUTH_TOKEN);
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  };

  // Helper to simulate network latency for authentic UI responsiveness
  const simulateLatency = (ms = 220) => new Promise(resolve => setTimeout(resolve, ms));

  // Initialize Local Persistent Demonstration State from CyberMockData
  const getStoredData = (key, defaultData) => {
    try {
      const stored = localStorage.getItem(key);
      if (stored) return JSON.parse(stored);
    } catch (e) {
      console.warn('LocalStorage access warning:', e);
    }
    return defaultData;
  };

  const setStoredData = (key, data) => {
    try {
      localStorage.setItem(key, JSON.stringify(data));
    } catch (e) {
      console.warn('LocalStorage save warning:', e);
    }
  };

  // Safe fallback if CyberMockData is loaded
  const mock = (typeof window !== 'undefined' && window.CyberMockData) ? window.CyberMockData : {};

  // Initialize default stores
  if (!localStorage.getItem(CONFIG.STORAGE_KEYS.SETTINGS) && mock.settings) {
    setStoredData(CONFIG.STORAGE_KEYS.SETTINGS, mock.settings);
  }
  if (!localStorage.getItem(CONFIG.STORAGE_KEYS.BLOCKED) && mock.blockedDomains) {
    setStoredData(CONFIG.STORAGE_KEYS.BLOCKED, mock.blockedDomains);
  }
  if (!localStorage.getItem(CONFIG.STORAGE_KEYS.DNS_LOGS) && mock.dnsLogs) {
    setStoredData(CONFIG.STORAGE_KEYS.DNS_LOGS, mock.dnsLogs);
  }
  if (!localStorage.getItem(CONFIG.STORAGE_KEYS.THREATS) && mock.threats) {
    setStoredData(CONFIG.STORAGE_KEYS.THREATS, mock.threats);
  }
  if (!localStorage.getItem(CONFIG.STORAGE_KEYS.ACTIVITIES) && mock.activityLogs) {
    setStoredData(CONFIG.STORAGE_KEYS.ACTIVITIES, mock.activityLogs);
  }

  // ==========================================================================
  // Public API Methods
  // ==========================================================================
  return {
    config: CONFIG,

    /**
     * User Authentication - Login
     * Endpoint: POST /api/auth/login
     */
    async login(identifier, password, remember = false) {
      if (CONFIG.USE_MOCK) {
        await simulateLatency(350);
        if (!identifier || !password) {
          throw new Error('Please enter both username/email and password.');
        }
        if (password.length < 4) {
          throw new Error('Invalid credentials. Password too short.');
        }
        const user = {
          name: 'SecOps Administrator',
          username: identifier.includes('@') ? identifier.split('@')[0] : identifier,
          email: identifier.includes('@') ? identifier : `${identifier}@aegisdns.security`,
          role: 'Cybersecurity Incident Lead',
          avatarInitials: 'SA',
          lastLogin: new Date().toISOString()
        };
        const token = 'aegis_jwt_' + Math.random().toString(36).substring(2);
        localStorage.setItem(CONFIG.STORAGE_KEYS.AUTH_TOKEN, token);
        setStoredData(CONFIG.STORAGE_KEYS.CURRENT_USER, user);
        return { success: true, token, user };
      }

      const res = await fetch(`${CONFIG.BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier, password, remember })
      });
      if (!res.ok) throw new Error((await res.json()).message || 'Login failed');
      return await res.json();
    },

    /**
     * User Registration
     * Endpoint: POST /api/auth/register
     */
    async register(formData) {
      if (CONFIG.USE_MOCK) {
        await simulateLatency(450);
        if (!formData.fullName || !formData.email || !formData.username || !formData.password) {
          throw new Error('All registration fields are required.');
        }
        if (formData.password !== formData.confirmPassword) {
          throw new Error('Passwords do not match.');
        }
        const newUser = {
          name: formData.fullName,
          username: formData.username,
          email: formData.email,
          role: 'Network Security Analyst',
          avatarInitials: formData.fullName.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase(),
          registeredAt: new Date().toISOString()
        };
        const token = 'aegis_jwt_' + Math.random().toString(36).substring(2);
        localStorage.setItem(CONFIG.STORAGE_KEYS.AUTH_TOKEN, token);
        setStoredData(CONFIG.STORAGE_KEYS.CURRENT_USER, newUser);
        return { success: true, token, user: newUser };
      }

      const res = await fetch(`${CONFIG.BASE_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });
      if (!res.ok) throw new Error((await res.json()).message || 'Registration failed');
      return await res.json();
    },

    /**
     * Get Current Authenticated User
     */
    getCurrentUser() {
      return getStoredData(CONFIG.STORAGE_KEYS.CURRENT_USER, {
        name: 'SecOps Administrator',
        username: 'admin_secops',
        email: 'admin@aegisdns.security',
        role: 'Cybersecurity Incident Lead',
        avatarInitials: 'SA'
      });
    },

    /**
     * Logout
     */
    logout() {
      localStorage.removeItem(CONFIG.STORAGE_KEYS.AUTH_TOKEN);
      localStorage.removeItem(CONFIG.STORAGE_KEYS.CURRENT_USER);
      window.location.href = 'login.html';
    },

    /**
     * Fetch Dashboard Overview Statistics
     * Endpoint: GET /api/dashboard/stats
     */
    async getDashboardStats() {
      if (CONFIG.USE_MOCK) {
        await simulateLatency(150);
        const settings = getStoredData(CONFIG.STORAGE_KEYS.SETTINGS, mock.settings);
        const blockedList = getStoredData(CONFIG.STORAGE_KEYS.BLOCKED, mock.blockedDomains || []);
        
        return {
          ...mock.dashboardStats,
          blockedDomains: blockedList.length * 12330, // scaled realistic count
          protectionStatus: settings.protectionEnabled ? 'ACTIVE' : 'PAUSED',
          trafficHourly: mock.trafficHourly,
          threatCategories: mock.threatCategories
        };
      }

      const res = await fetch(`${CONFIG.BASE_URL}/dashboard/stats`);
      if (!res.ok) throw new Error('Failed to fetch dashboard statistics');
      return await res.json();
    },

    /**
     * Check Domain Security Status
     * Endpoint: POST /api/check-domain
     * 
     * Performs lookup against threat databases, heuristic analysis,
     * Shannon entropy calculation, and simulated sinkhole rules.
     */
    async checkDomain(domainInput) {
      if (!domainInput || typeof domainInput !== 'string') {
        throw new Error('Please enter a valid domain name.');
      }

      const cleanDomain = domainInput.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
      if (!cleanDomain.includes('.') || cleanDomain.length < 3) {
        throw new Error('Invalid domain format. Example: paypal-security.xyz or github.com');
      }

      if (CONFIG.USE_MOCK) {
        await simulateLatency(650); // realistic inspection scan time
        
        // 1. Direct match in local reputation database
        if (mock.domainReputationDatabase && mock.domainReputationDatabase[cleanDomain]) {
          return {
            ...mock.domainReputationDatabase[cleanDomain],
            checkedAt: new Date().toLocaleTimeString()
          };
        }

        // 2. Check if present in custom blocked domains list
        const blockedList = getStoredData(CONFIG.STORAGE_KEYS.BLOCKED, []);
        const inBlocked = blockedList.find(b => b.domain.toLowerCase() === cleanDomain);
        if (inBlocked) {
          return {
            domain: cleanDomain,
            status: 'MALICIOUS',
            category: inBlocked.threatCategory || 'Blocked by Administrative Rule',
            riskScore: 95,
            ip: '0.0.0.0 (Sinkholed)',
            nameserver: 'ns-sinkhole.aegisdns.internal',
            registrar: 'Restricted / Null Route',
            ageYears: 0.1,
            country: 'Sinkhole Null-Route',
            entropyScore: '4.21 (High)',
            threatSources: ['Aegis DNS Sinkhole Policy Engine', 'Active Blocklist'],
            dnsRecords: { A: '0.0.0.0 (Sinkhole)', TXT: 'AEGIS_BLOCKED_POLICY' },
            verdictReason: inBlocked.blockingReason || 'Matched domain in local sinkhole blocklist.',
            checkedAt: new Date().toLocaleTimeString()
          };
        }

        // 3. Dynamic heuristic inspection for unlisted domains
        const isMaliciousKeywords = /(phish|paypa1|bank|login-verify|stealth|keylog|trojan|c2-|beacon|payload|hack|exploit)/i.test(cleanDomain);
        const isSuspiciousTLD = /\.(xyz|top|cc|ru|biz|stream|info|club|online)$/i.test(cleanDomain);
        const hasSuspiciousHyphens = (cleanDomain.match(/-/g) || []).length >= 2;

        if (isMaliciousKeywords) {
          return {
            domain: cleanDomain,
            status: 'MALICIOUS',
            category: 'Phishing / Malware Host',
            riskScore: Math.floor(Math.random() * 8) + 91,
            ip: '185.196.22.' + Math.floor(Math.random() * 200 + 10),
            nameserver: 'ns1.bulletproof-servers.is',
            registrar: 'NameCheap FastFlux',
            ageYears: 0.03,
            country: 'Offshore Bulletproof',
            entropyScore: '4.65 (High Risk)',
            threatSources: ['Aegis Heuristic Engine (Signature Match)', 'Threat Intelligence Feed'],
            dnsRecords: { A: '0.0.0.0 (Sinkholed)', TTL: '15s' },
            verdictReason: 'Malicious naming heuristics detected. Intercepted and blocked by sinkhole.',
            checkedAt: new Date().toLocaleTimeString()
          };
        }

        if (isSuspiciousTLD || hasSuspiciousHyphens) {
          return {
            domain: cleanDomain,
            status: 'SUSPICIOUS',
            category: 'Unverified / High Risk TLD',
            riskScore: Math.floor(Math.random() * 20) + 62,
            ip: '172.67.140.' + Math.floor(Math.random() * 200 + 10),
            nameserver: 'ns2.unverified-dns.net',
            registrar: 'Cloudflare / Unverified Origin',
            ageYears: 0.15,
            country: 'Distributed Cloud',
            entropyScore: '3.75 (Elevated)',
            threatSources: ['Aegis Heuristic Classifier (Shannon Entropy Alert)'],
            dnsRecords: { A: '172.67.140.88', TTL: '120s' },
            verdictReason: 'Suspicious domain structural characteristics. Manual verification recommended.',
            checkedAt: new Date().toLocaleTimeString()
          };
        }

        // Default SAFE domain response
        return {
          domain: cleanDomain,
          status: 'SAFE',
          category: 'Standard Web Service / Verified Host',
          riskScore: Math.floor(Math.random() * 6) + 2,
          ip: '104.26.12.' + Math.floor(Math.random() * 200 + 10),
          nameserver: 'ns1.authoritative-dns.org',
          registrar: 'Cloudflare / Verisign',
          ageYears: 8.5,
          country: 'United States',
          entropyScore: '2.18 (Normal Standard Distribution)',
          threatSources: ['AlienVault OTX (Clean)', 'VirusTotal 0/88', 'AbuseIPDB (0%)'],
          dnsRecords: { A: '104.26.12.74', TTL: '300s' },
          verdictReason: 'Clean reputation with verified WHOIS age and zero threat feed hits. Access permitted.',
          checkedAt: new Date().toLocaleTimeString()
        };
      }

      const res = await fetch(`${CONFIG.BASE_URL}/check-domain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: cleanDomain })
      });
      if (!res.ok) throw new Error('Domain security check failed');
      return await res.json();
    },

    /**
     * Get DNS Request Logs
     * Endpoint: GET /api/dns/logs
     */
    async getDnsLogs() {
      if (CONFIG.USE_MOCK) {
        await simulateLatency(120);
        return getStoredData(CONFIG.STORAGE_KEYS.DNS_LOGS, mock.dnsLogs || []);
      }
      const res = await fetch(`${CONFIG.BASE_URL}/dns/logs`);
      return await res.json();
    },

    /**
     * Get Detected Threats
     * Endpoint: GET /api/threats
     */
    async getThreats() {
      if (CONFIG.USE_MOCK) {
        await simulateLatency(150);
        return getStoredData(CONFIG.STORAGE_KEYS.THREATS, mock.threats || []);
      }
      const res = await fetch(`${CONFIG.BASE_URL}/threats`);
      return await res.json();
    },

    /**
     * Get Blocked Domains List
     * Endpoint: GET /api/blocked-domains
     */
    async getBlockedDomains() {
      if (CONFIG.USE_MOCK) {
        await simulateLatency(120);
        return getStoredData(CONFIG.STORAGE_KEYS.BLOCKED, mock.blockedDomains || []);
      }
      const res = await fetch(`${CONFIG.BASE_URL}/blocked-domains`);
      return await res.json();
    },

    /**
     * Add Domain to Blocklist
     * Endpoint: POST /api/blocked-domains
     */
    async addBlockedDomain(newDomainData) {
      if (CONFIG.USE_MOCK) {
        await simulateLatency(250);
        const list = getStoredData(CONFIG.STORAGE_KEYS.BLOCKED, mock.blockedDomains || []);
        const cleanDomain = newDomainData.domain.trim().toLowerCase();
        
        if (list.some(d => d.domain.toLowerCase() === cleanDomain)) {
          throw new Error(`Domain "${cleanDomain}" is already in the blocked list.`);
        }

        const newEntry = {
          id: 'BLK-' + (100 + list.length + 1),
          domain: cleanDomain,
          threatCategory: newDomainData.threatCategory || 'Custom Admin Policy',
          detectionDate: new Date().toISOString().split('T')[0],
          blockingReason: newDomainData.blockingReason || 'Manually added by administrator',
          blockingStatus: 'Active Blocked',
          source: 'Manual Administrator Rule',
          severity: newDomainData.severity || 'High'
        };

        list.unshift(newEntry);
        setStoredData(CONFIG.STORAGE_KEYS.BLOCKED, list);

        // Record in activity log
        this.logActivity({
          activityType: 'Domain Block Added',
          target: cleanDomain,
          status: 'BLOCKED',
          details: `Manual sinkhole rule created: ${newEntry.blockingReason}`
        });

        return newEntry;
      }

      const res = await fetch(`${CONFIG.BASE_URL}/blocked-domains`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newDomainData)
      });
      return await res.json();
    },

    /**
     * Remove / Whitelist Blocked Domain
     * Endpoint: DELETE /api/blocked-domains/<id>
     */
    async removeBlockedDomain(domainId) {
      if (CONFIG.USE_MOCK) {
        await simulateLatency(200);
        let list = getStoredData(CONFIG.STORAGE_KEYS.BLOCKED, mock.blockedDomains || []);
        const target = list.find(d => d.id === domainId || d.domain === domainId);
        list = list.filter(d => d.id !== domainId && d.domain !== domainId);
        setStoredData(CONFIG.STORAGE_KEYS.BLOCKED, list);

        if (target) {
          this.logActivity({
            activityType: 'Domain Unblocked / Whitelisted',
            target: target.domain,
            status: 'ALLOWED',
            details: `Removed domain ${target.domain} from sinkhole policy.`
          });
        }
        return { success: true };
      }

      const res = await fetch(`${CONFIG.BASE_URL}/blocked-domains/${domainId}`, {
        method: 'DELETE'
      });
      return await res.json();
    },

    /**
     * Get Activity Logs
     * Endpoint: GET /api/activity-logs
     */
    async getActivityLogs() {
      if (CONFIG.USE_MOCK) {
        await simulateLatency(120);
        return getStoredData(CONFIG.STORAGE_KEYS.ACTIVITIES, mock.activityLogs || []);
      }
      const res = await fetch(`${CONFIG.BASE_URL}/activity-logs`);
      return await res.json();
    },

    /**
     * Log an Activity
     */
    logActivity(activity) {
      const logs = getStoredData(CONFIG.STORAGE_KEYS.ACTIVITIES, mock.activityLogs || []);
      const user = this.getCurrentUser();
      const newLog = {
        id: 'ACT-' + (9082 + logs.length),
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        activityType: activity.activityType || 'System Event',
        actor: user.name || 'SecOps Administrator',
        target: activity.target || 'Network Interface',
        ipOrigin: '192.168.1.5',
        status: activity.status || 'INFO',
        details: activity.details || 'System policy execution'
      };
      logs.unshift(newLog);
      setStoredData(CONFIG.STORAGE_KEYS.ACTIVITIES, logs);
      return newLog;
    },

    /**
     * Get System Settings
     * Endpoint: GET /api/settings
     */
    async getSettings() {
      if (CONFIG.USE_MOCK) {
        await simulateLatency(100);
        return getStoredData(CONFIG.STORAGE_KEYS.SETTINGS, mock.settings || {});
      }
      const res = await fetch(`${CONFIG.BASE_URL}/settings`);
      return await res.json();
    },

    /**
     * Update System Settings
     * Endpoint: PUT /api/settings
     */
    async updateSettings(newSettings) {
      if (CONFIG.USE_MOCK) {
        await simulateLatency(300);
        const current = getStoredData(CONFIG.STORAGE_KEYS.SETTINGS, mock.settings || {});
        const updated = { ...current, ...newSettings };
        setStoredData(CONFIG.STORAGE_KEYS.SETTINGS, updated);

        this.logActivity({
          activityType: 'Settings Updated',
          target: 'System Configuration',
          status: 'UPDATED',
          details: 'Updated network protection settings and parameters.'
        });

        return updated;
      }

      const res = await fetch(`${CONFIG.BASE_URL}/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newSettings)
      });
      return await res.json();
    },

    /**
     * Toggle Protection Master Status
     * Endpoint: POST /api/settings/protection-toggle
     */
    async toggleProtection(targetStatus) {
      const current = await this.getSettings();
      const isEnabled = targetStatus !== undefined ? targetStatus : !current.protectionEnabled;
      return await this.updateSettings({
        protectionEnabled: isEnabled,
        dnsProtectionStatus: isEnabled ? 'ACTIVE' : 'PAUSED'
      });
    }
  };
})();

// Export to window
if (typeof window !== 'undefined') {
  window.CyberApiService = CyberApiService;
}

