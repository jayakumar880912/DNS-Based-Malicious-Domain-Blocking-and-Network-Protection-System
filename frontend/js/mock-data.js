/**
 * DNS-Based Malicious Domain Blocking and Network Protection System
 * Realistic Cybersecurity Mock Data Store
 * 
 * NOTE: This demonstration data is decoupled from application logic
 * so it can be seamlessly replaced with real Python Flask API responses.
 */

const CyberMockData = {
  // System Overview Statistics
  dashboardStats: {
    totalDnsRequests: 2845920,
    safeDomains: 2712490,
    blockedDomains: 98640,
    suspiciousDomains: 34790,
    protectionStatus: 'ACTIVE', // 'ACTIVE' or 'PAUSED'
    uptime: '99.98%',
    currentLatencyMs: 14,
    activeResolver: '127.0.0.1:53 (AegisDNS Sinkhole)',
    upstreamDns: '1.1.1.1 (Cloudflare CleanBrowsing)',
    threatEngineVersion: 'v4.18.2-SecEngine',
    lastThreatFeedUpdate: '2 minutes ago',
    rulesCount: 148520
  },

  // Hourly Traffic for Chart.js
  trafficHourly: {
    labels: ['00:00', '02:00', '04:00', '06:00', '08:00', '10:00', '12:00', '14:00', '16:00', '18:00', '20:00', '22:00'],
    totalRequests: [112000, 89000, 74000, 125000, 248000, 385000, 412000, 395000, 428000, 370000, 290000, 198000],
    safeRequests:  [107500, 85600, 71200, 120400, 237800, 368000, 393500, 377000, 408500, 353000, 277200, 189800],
    blockedRequests: [3200, 2400, 1900, 3300, 7200, 11800, 12900, 12100, 13700, 11900, 9100, 5800],
    suspiciousRequests: [1300, 1000, 900, 1300, 3000, 5200, 5600, 5900, 5800, 5100, 3700, 2400]
  },

  // Threat Category Distribution for Donut Chart
  threatCategories: {
    labels: ['Phishing & Credential Theft', 'Malware C2 / Botnet', 'DGA (Domain Gen Algo)', 'Cryptomining Pool', 'Ransomware Dropper'],
    data: [41250, 26400, 14200, 10190, 6600],
    colors: ['#ff3366', '#ff7b00', '#a855f7', '#00f0ff', '#eab308']
  },

  // Known Sample Domains for Checker Test
  domainReputationDatabase: {
    'google.com': {
      domain: 'google.com',
      status: 'SAFE',
      category: 'Search Engine & Technology Services',
      riskScore: 2,
      ip: '142.250.190.46',
      nameserver: 'ns1.google.com',
      registrar: 'MarkMonitor Inc.',
      ageYears: 27,
      country: 'United States',
      entropyScore: '2.14 (Low - Normal)',
      threatSources: ['AlienVault OTX (Clean)', 'VirusTotal 0/88', 'AbuseIPDB (0%)'],
      dnsRecords: { A: '142.250.190.46', AAAA: '2607:f8b0:4005:808::200e', TTL: '300s' },
      verdictReason: 'Verified authoritative domain with flawless reputation.'
    },
    'github.com': {
      domain: 'github.com',
      status: 'SAFE',
      category: 'Software Development & Hosting',
      riskScore: 3,
      ip: '140.82.121.4',
      nameserver: 'dns1.p08.nsone.net',
      registrar: 'MarkMonitor Inc.',
      ageYears: 16,
      country: 'United States',
      entropyScore: '2.45 (Low - Normal)',
      threatSources: ['AlienVault OTX (Clean)', 'VirusTotal 0/88', 'AbuseIPDB (0%)'],
      dnsRecords: { A: '140.82.121.4', TTL: '60s' },
      verdictReason: 'Legitimate developer infrastructure. High trust score.'
    },
    'paypa1-security-update-verify.com': {
      domain: 'paypa1-security-update-verify.com',
      status: 'MALICIOUS',
      category: 'Credential Phishing / Typosquatting',
      riskScore: 98,
      ip: '185.220.101.45',
      nameserver: 'ns1.bulletproof-dns.is',
      registrar: 'NameCheap (Privacy Protected)',
      ageYears: 0.02, // 8 days old
      country: 'Seychelles / Bulletproof Hosting',
      entropyScore: '4.82 (High - Typosquatting Match)',
      threatSources: ['AlienVault OTX (Flagged)', 'VirusTotal 64/88', 'AbuseIPDB (Confidence 100%)'],
      dnsRecords: { A: '0.0.0.0 (Sinkholed)', TXT: 'AEGIS_BLOCKED_SINKHOLE_ID_984' },
      verdictReason: 'Impersonates PayPal brand with deceptive typosquatting. Detected on active phishing feed.'
    },
    'c2-trojan-controller-sync.net': {
      domain: 'c2-trojan-controller-sync.net',
      status: 'MALICIOUS',
      category: 'Command & Control (C2) / Botnet',
      riskScore: 99,
      ip: '91.240.118.89',
      nameserver: 'ns1.fastflux-network.cc',
      registrar: 'Tonic Domains Corp',
      ageYears: 0.05,
      country: 'Russia / Fast-flux relay',
      entropyScore: '4.68 (High)',
      threatSources: ['AbuseIPDB (100% Malicious)', 'AlienVault OTX (CobaltStrike Profile)', 'VirusTotal 71/88'],
      dnsRecords: { A: '0.0.0.0 (Sinkholed)', TTL: '10s' },
      verdictReason: 'Active Cobalt Strike beacon listener. DNS queries routed to local sinkhole.'
    },
    'crypto-fast-airdrop-claim.top': {
      domain: 'crypto-fast-airdrop-claim.top',
      status: 'SUSPICIOUS',
      category: 'Crypto Drainer / Unverified TLD',
      riskScore: 68,
      ip: '45.154.255.8',
      nameserver: 'ns1.free-tld-park.org',
      registrar: 'Alibaba Cloud US LLC',
      ageYears: 0.08,
      country: 'Lithuania',
      entropyScore: '3.91 (Medium-High)',
      threatSources: ['URLHaus (Suspicious Heuristics)', 'VirusTotal 8/88 (Under Evaluation)'],
      dnsRecords: { A: '45.154.255.8', TTL: '120s' },
      verdictReason: 'Newly registered domain matching crypto drainer signature templates. DNS queries flagged.'
    },
    'dga-8f4b219c0a.biz': {
      domain: 'dga-8f4b219c0a.biz',
      status: 'SUSPICIOUS',
      category: 'Domain Generation Algorithm (DGA)',
      riskScore: 74,
      ip: '194.87.144.12',
      nameserver: 'ns2.dynamic-ip.ro',
      registrar: 'Regtime Ltd',
      ageYears: 0.01,
      country: 'Romania',
      entropyScore: '4.78 (Extremely High Randomness)',
      threatSources: ['Aegis Heuristic Classifier (Shannon Entropy > 4.7)', 'Threat Feeds (Unregistered)'],
      dnsRecords: { A: '194.87.144.12', TTL: '60s' },
      verdictReason: 'Algorithmic domain structure indicates malware fallback rendezvous channel.'
    }
  },

  // Live DNS Request Logs Table
  dnsLogs: [
    { id: 'DNS-8910', timestamp: '2026-10-31 22:58:14', clientIp: '192.168.1.104', domain: 'api.github.com', queryType: 'A', responseTimeMs: 11, status: 'ALLOWED', category: 'Software / API' },
    { id: 'DNS-8909', timestamp: '2026-10-31 22:58:11', clientIp: '192.168.1.142', domain: 'paypa1-security-update-verify.com', queryType: 'A', responseTimeMs: 4, status: 'BLOCKED', category: 'Phishing' },
    { id: 'DNS-8908', timestamp: '2026-10-31 22:58:08', clientIp: '192.168.1.88',  domain: 'update.microsoft.com', queryType: 'AAAA', responseTimeMs: 18, status: 'ALLOWED', category: 'OS Services' },
    { id: 'DNS-8907', timestamp: '2026-10-31 22:57:59', clientIp: '192.168.1.205', domain: 'crypto-fast-airdrop-claim.top', queryType: 'A', responseTimeMs: 14, status: 'SUSPICIOUS', category: 'Crypto Drainer' },
    { id: 'DNS-8906', timestamp: '2026-10-31 22:57:52', clientIp: '192.168.1.115', domain: 'c2-trojan-controller-sync.net', queryType: 'A', responseTimeMs: 3, status: 'BLOCKED', category: 'C2 / Botnet' },
    { id: 'DNS-8905', timestamp: '2026-10-31 22:57:45', clientIp: '192.168.1.104', domain: 'cdn.cloudflare.net', queryType: 'A', responseTimeMs: 8, status: 'ALLOWED', category: 'CDN Infrastructure' },
    { id: 'DNS-8904', timestamp: '2026-10-31 22:57:38', clientIp: '192.168.1.177', domain: 'malware-payload-stage1.biz', queryType: 'A', responseTimeMs: 5, status: 'BLOCKED', category: 'Malware Dropper' },
    { id: 'DNS-8903', timestamp: '2026-10-31 22:57:24', clientIp: '192.168.1.64',  domain: 'dga-8f4b219c0a.biz', queryType: 'A', responseTimeMs: 12, status: 'SUSPICIOUS', category: 'DGA Heuristic' },
    { id: 'DNS-8902', timestamp: '2026-10-31 22:57:12', clientIp: '192.168.1.104', domain: 'slack-edge.com', queryType: 'A', responseTimeMs: 15, status: 'ALLOWED', category: 'Business Collab' },
    { id: 'DNS-8901', timestamp: '2026-10-31 22:57:01', clientIp: '192.168.1.191', domain: 'miningpool-xmrig-eu.stream', queryType: 'A', responseTimeMs: 4, status: 'BLOCKED', category: 'Cryptominer' },
    { id: 'DNS-8900', timestamp: '2026-10-31 22:56:52', clientIp: '192.168.1.88',  domain: 'dns.google', queryType: 'A', responseTimeMs: 10, status: 'ALLOWED', category: 'DNS Resolver' },
    { id: 'DNS-8899', timestamp: '2026-10-31 22:56:40', clientIp: '192.168.1.210', domain: 'apple-id-suspended-login.cc', queryType: 'A', responseTimeMs: 3, status: 'BLOCKED', category: 'Phishing' },
    { id: 'DNS-8898', timestamp: '2026-10-31 22:56:32', clientIp: '192.168.1.142', domain: 'registry.npmjs.org', queryType: 'A', responseTimeMs: 22, status: 'ALLOWED', category: 'Dev Repositories' },
    { id: 'DNS-8897', timestamp: '2026-10-31 22:56:21', clientIp: '192.168.1.104', domain: 'stealth-keylogger-drop.online', queryType: 'A', responseTimeMs: 5, status: 'BLOCKED', category: 'Spyware Dropper' },
    { id: 'DNS-8896', timestamp: '2026-10-31 22:56:09', clientIp: '192.168.1.115', domain: 'aws.amazon.com', queryType: 'A', responseTimeMs: 14, status: 'ALLOWED', category: 'Cloud Infrastructure' }
  ],

  // Threat Detection Records
  threats: [
    {
      id: 'THR-7721',
      domain: 'c2-trojan-controller-sync.net',
      category: 'Command & Control',
      severity: 'CRITICAL',
      sourceFeed: 'AlienVault OTX / CobaltStrike',
      detectionTime: '2026-10-31 22:57:52',
      riskScore: 99,
      actionTaken: 'DNS Sinkhole (0.0.0.0)',
      targetIp: '91.240.118.89',
      clientOrigin: '192.168.1.115 (Finance Workstation 3)',
      iocDetails: 'Matches active botnet beaconing interval (every 45s). Host quarantined.'
    },
    {
      id: 'THR-7720',
      domain: 'paypa1-security-update-verify.com',
      category: 'Phishing',
      severity: 'CRITICAL',
      sourceFeed: 'PhishTank & AbuseIPDB',
      detectionTime: '2026-10-31 22:58:11',
      riskScore: 98,
      actionTaken: 'DNS Sinkhole (0.0.0.0)',
      targetIp: '185.220.101.45',
      clientOrigin: '192.168.1.142 (HR Laptop 12)',
      iocDetails: 'Typosquatting PayPal credential harvester with cloned login forms.'
    },
    {
      id: 'THR-7719',
      domain: 'malware-payload-stage1.biz',
      category: 'Malware Dropper',
      severity: 'HIGH',
      sourceFeed: 'URLhaus Live Malware Feed',
      detectionTime: '2026-10-31 22:57:38',
      riskScore: 94,
      actionTaken: 'DNS Sinkhole (0.0.0.0)',
      targetIp: '194.26.29.112',
      clientOrigin: '192.168.1.177 (Guest Wi-Fi Client)',
      iocDetails: 'Serves encrypted ZIP containing malicious VBScript payload.'
    },
    {
      id: 'THR-7718',
      domain: 'miningpool-xmrig-eu.stream',
      category: 'Cryptomining',
      severity: 'MEDIUM',
      sourceFeed: 'NoCoin Cryptomining Blocklist',
      detectionTime: '2026-10-31 22:57:01',
      riskScore: 82,
      actionTaken: 'DNS Sinkhole (0.0.0.0)',
      targetIp: '51.38.120.7',
      clientOrigin: '192.168.1.191 (Engineering Dev Server 2)',
      iocDetails: 'Stratum mining protocol handshake domain over port 3333.'
    },
    {
      id: 'THR-7717',
      domain: 'crypto-fast-airdrop-claim.top',
      category: 'Suspicious / Drainer',
      severity: 'MEDIUM',
      sourceFeed: 'Aegis Heuristic Classifier',
      detectionTime: '2026-10-31 22:57:59',
      riskScore: 68,
      actionTaken: 'Flagged / Monitored',
      targetIp: '45.154.255.8',
      clientOrigin: '192.168.1.205 (Marketing iPad)',
      iocDetails: 'High Shannon entropy + TLD .top with newly minted WHOIS record.'
    },
    {
      id: 'THR-7716',
      domain: 'dga-8f4b219c0a.biz',
      category: 'DGA Heuristic',
      severity: 'MEDIUM',
      sourceFeed: 'Internal Machine Learning Classifier',
      detectionTime: '2026-10-31 22:57:24',
      riskScore: 74,
      actionTaken: 'Flagged / Rate-Limited',
      targetIp: '194.87.144.12',
      clientOrigin: '192.168.1.64 (Lab Workstation 08)',
      iocDetails: 'Vowel-to-consonant ratio anomalous (0.11), n-gram perplexity matched Conficker family.'
    },
    {
      id: 'THR-7715',
      domain: 'apple-id-suspended-login.cc',
      category: 'Phishing',
      severity: 'HIGH',
      sourceFeed: 'OpenPhish Real-time',
      detectionTime: '2026-10-31 22:56:40',
      riskScore: 92,
      actionTaken: 'DNS Sinkhole (0.0.0.0)',
      targetIp: '104.21.32.14',
      clientOrigin: '192.168.1.210 (Executive Laptop)',
      iocDetails: 'Targeted SMS phishing link pointing to malicious Apple ID portal.'
    },
    {
      id: 'THR-7714',
      domain: 'stealth-keylogger-drop.online',
      category: 'Spyware Dropper',
      severity: 'CRITICAL',
      sourceFeed: 'Emerging Threats Pro',
      detectionTime: '2026-10-31 22:56:21',
      riskScore: 97,
      actionTaken: 'DNS Sinkhole (0.0.0.0)',
      targetIp: '185.196.8.99',
      clientOrigin: '192.168.1.104 (Accounting Desktop)',
      iocDetails: 'Known AgentTesla C2 exfiltration server. Blocked instantly.'
    }
  ],

  // Blocked Domains Management List
  blockedDomains: [
    {
      id: 'BLK-101',
      domain: 'paypa1-security-update-verify.com',
      threatCategory: 'Phishing',
      detectionDate: '2026-10-31',
      blockingReason: 'Brand Typosquatting / Credential Harvesting',
      blockingStatus: 'Active Blocked',
      source: 'Automated Threat Intelligence',
      severity: 'Critical'
    },
    {
      id: 'BLK-102',
      domain: 'c2-trojan-controller-sync.net',
      threatCategory: 'Command & Control',
      detectionDate: '2026-10-31',
      blockingReason: 'Cobalt Strike C2 Beacon Rendezvous',
      blockingStatus: 'Active Blocked',
      source: 'Automated Threat Intelligence',
      severity: 'Critical'
    },
    {
      id: 'BLK-103',
      domain: 'malware-payload-stage1.biz',
      threatCategory: 'Malware Dropper',
      detectionDate: '2026-10-30',
      blockingReason: 'Trojan Downloader distribution endpoint',
      blockingStatus: 'Active Blocked',
      source: 'URLhaus Live Feed',
      severity: 'High'
    },
    {
      id: 'BLK-104',
      domain: 'miningpool-xmrig-eu.stream',
      threatCategory: 'Cryptomining',
      detectionDate: '2026-10-30',
      blockingReason: 'Unauthorized Monero browser mining pool',
      blockingStatus: 'Active Blocked',
      source: 'NoCoin Blacklist',
      severity: 'Medium'
    },
    {
      id: 'BLK-105',
      domain: 'apple-id-suspended-login.cc',
      threatCategory: 'Phishing',
      detectionDate: '2026-10-29',
      blockingReason: 'Apple ID Credential Phishing Landing Page',
      blockingStatus: 'Active Blocked',
      source: 'OpenPhish Feed',
      severity: 'High'
    },
    {
      id: 'BLK-106',
      domain: 'stealth-keylogger-drop.online',
      threatCategory: 'Spyware Dropper',
      detectionDate: '2026-10-29',
      blockingReason: 'AgentTesla infostealer exfiltration node',
      blockingStatus: 'Active Blocked',
      source: 'Emerging Threats Rule',
      severity: 'Critical'
    },
    {
      id: 'BLK-107',
      domain: 'lockbit-decryptor-scam.xyz',
      threatCategory: 'Ransomware',
      detectionDate: '2026-10-28',
      blockingReason: 'Fake Ransomware payment & decryptor portal',
      blockingStatus: 'Active Blocked',
      source: 'Custom Security Policy',
      severity: 'Critical'
    },
    {
      id: 'BLK-108',
      domain: 'ad-telemetry-tracker-popup.info',
      threatCategory: 'Adware / Tracking',
      detectionDate: '2026-10-27',
      blockingReason: 'Aggressive adware and browser hijacking scripts',
      blockingStatus: 'Active Blocked',
      source: 'Adguard DNS Filter',
      severity: 'Low'
    }
  ],

  // Activity Logs
  activityLogs: [
    {
      id: 'ACT-9081',
      timestamp: '2026-10-31 22:58:11',
      activityType: 'Threat Detection',
      actor: 'AegisDNS Sinkhole Engine',
      target: 'paypa1-security-update-verify.com',
      ipOrigin: '192.168.1.142',
      status: 'BLOCKED',
      details: 'Malicious domain intercepted. Client returned 0.0.0.0 sinkhole response.'
    },
    {
      id: 'ACT-9080',
      timestamp: '2026-10-31 22:57:52',
      activityType: 'Threat Detection',
      actor: 'AegisDNS Sinkhole Engine',
      target: 'c2-trojan-controller-sync.net',
      ipOrigin: '192.168.1.115',
      status: 'BLOCKED',
      details: 'Known C2 server query rejected. Alert dispatched to SecOps Slack channel.'
    },
    {
      id: 'ACT-9079',
      timestamp: '2026-10-31 22:57:24',
      activityType: 'Domain Check',
      actor: 'Administrator (SecOps Admin)',
      target: 'dga-8f4b219c0a.biz',
      ipOrigin: '192.168.1.5',
      status: 'SUSPICIOUS',
      details: 'Manual domain heuristic inspection executed via Security Console.'
    },
    {
      id: 'ACT-9078',
      timestamp: '2026-10-31 22:56:15',
      activityType: 'Policy Change',
      actor: 'Administrator (SecOps Admin)',
      target: 'Protection Setting: Sensitivity Slider',
      ipOrigin: '192.168.1.5',
      status: 'UPDATED',
      details: 'Blocking heuristic sensitivity calibrated to "Strict Mode (Level 3)".'
    },
    {
      id: 'ACT-9077',
      timestamp: '2026-10-31 22:55:00',
      activityType: 'Threat Feed Sync',
      actor: 'Threat Intelligence Daemon',
      target: 'AlienVault OTX & AbuseIPDB Feeds',
      ipOrigin: '127.0.0.1',
      status: 'SUCCESS',
      details: 'Synchronized 4,120 new malicious indicators into local cache memory.'
    },
    {
      id: 'ACT-9076',
      timestamp: '2026-10-31 22:50:33',
      activityType: 'User Authentication',
      actor: 'SecOps Administrator',
      target: 'Web Security Console',
      ipOrigin: '192.168.1.5',
      status: 'SUCCESS',
      details: 'Successful administrator login with multi-factor session token.'
    },
    {
      id: 'ACT-9075',
      timestamp: '2026-10-31 22:42:10',
      activityType: 'DNS Request',
      actor: 'Workstation 104',
      target: 'api.github.com',
      ipOrigin: '192.168.1.104',
      status: 'ALLOWED',
      details: 'Resolved legitimate developer API endpoint in 11ms.'
    }
  ],

  // System Settings Defaults
  settings: {
    protectionEnabled: true,
    dnsProtectionStatus: 'ACTIVE',
    primaryDnsResolver: '127.0.0.1:53 (AegisDNS Sinkhole)',
    upstreamDns: '1.1.1.1',
    dohEnabled: true,
    dotEnabled: false,
    autoBlock: true,
    blockingSensitivity: 'Strict', // 'Strict', 'Moderate', 'Lenient'
    threatNotifications: true,
    emailAlerts: true,
    alertEmail: 'secops@enterprise-domain.local',
    webhookUrl: 'https://hooks.slack.com/services/T00/B00/X00',
    adminName: 'SecOps Administrator',
    adminEmail: 'admin@aegisdns.security',
    adminUsername: 'admin_secops',
    adminRole: 'Cybersecurity Incident Lead'
  },

  // Digital Twin & Policy Simulation Mock Data
  digitalTwin: {
    virtualPolicies: [
      {
        id: 1,
        name: 'Production Baseline Policy (Live Replica)',
        description: 'Digital Twin replica mirroring active live network DNS protection rules.',
        entropyThreshold: 3.90,
        blockedTlds: ['top', 'xyz', 'cc', 'ru', 'biz', 'online', 'loan', 'work', 'vip'],
        blockedCategories: ['Phishing', 'Malware C2', 'Ransomware Dropper', 'Cryptomining', 'DGA Anomaly'],
        dgaProtectionMode: 'Balanced',
        aiHeuristicWeight: 1.0,
        minConfidenceScore: 85,
        actionMalicious: 'SINKHOLE_0_0_0_0',
        actionSuspicious: 'CHALLENGE_FLAG',
        customWhitelist: ['github.com', 'microsoft.com'],
        customBlacklist: [],
        isBaseline: true,
        createdBy: 'System Digital Twin Engine',
        createdAt: '2026-10-31 20:00:00',
        updatedAt: '2026-10-31 20:00:00'
      },
      {
        id: 2,
        name: 'Aggressive Zero-Trust Policy',
        description: 'Strict Shannon entropy and aggressive DGA detection for elevated threat posture.',
        entropyThreshold: 3.70,
        blockedTlds: ['top', 'xyz', 'cc', 'ru', 'biz', 'online', 'loan', 'work', 'vip', 'link', 'tokyo'],
        blockedCategories: ['Phishing', 'Malware C2', 'Ransomware Dropper', 'Cryptomining', 'DGA Anomaly', 'Adware / Spyware'],
        dgaProtectionMode: 'Aggressive',
        aiHeuristicWeight: 1.4,
        minConfidenceScore: 75,
        actionMalicious: 'SINKHOLE_0_0_0_0',
        actionSuspicious: 'BLOCK_SINKHOLE',
        customWhitelist: ['github.com', 'microsoft.com', 'cloudfront.net'],
        customBlacklist: [],
        isBaseline: false,
        createdBy: 'SecOps Administrator',
        createdAt: '2026-11-01 10:15:00',
        updatedAt: '2026-11-01 10:15:00'
      },
      {
        id: 3,
        name: 'Relaxed Developer / Cloud Sandbox Policy',
        description: 'Tolerant entropy thresholds designed to avoid false positives on dynamic microservices and CDN endpoints.',
        entropyThreshold: 4.25,
        blockedTlds: ['top', 'xyz', 'cc'],
        blockedCategories: ['Phishing', 'Malware C2'],
        dgaProtectionMode: 'Conservative',
        aiHeuristicWeight: 0.8,
        minConfidenceScore: 90,
        actionMalicious: 'NXDOMAIN',
        actionSuspicious: 'ALLOW_WITH_LOG',
        customWhitelist: ['*'],
        customBlacklist: [],
        isBaseline: false,
        createdBy: 'SecOps Administrator',
        createdAt: '2026-11-01 11:30:00',
        updatedAt: '2026-11-01 11:30:00'
      }
    ],

    scenarios: [
      {
        id: 1,
        scenarioKey: 'phishing-surge',
        name: 'Phishing & Brand Impersonation Campaign Surge',
        category: 'Phishing / Social Engineering',
        description: 'Simulates a massive wave of credential harvesting and brand impersonation attacks targeting banking, cloud, and enterprise SSO portals.',
        difficulty: 'High',
        domainCount: 25
      },
      {
        id: 2,
        scenarioKey: 'dga-botnet',
        name: 'DGA Botnet Infiltration & Ransomware C2 Beaconing',
        category: 'DGA / Malware C2',
        description: 'Evaluates detection resilience against pseudorandom algorithmic domain generation (DGA) used by ransomware and advanced botnets while monitoring CDN false positives.',
        difficulty: 'Advanced',
        domainCount: 22
      },
      {
        id: 3,
        scenarioKey: 'enterprise-benchmark',
        name: 'Enterprise Mixed Traffic Benchmark (Stress Test)',
        category: 'Mixed Workload',
        description: 'Balanced benchmark simulating 75% legitimate corporate SaaS & developer lookups alongside 25% blended zero-day and known cyber threats.',
        difficulty: 'Advanced',
        domainCount: 24
      }
    ]
  },

  // Attack Replay & Counterfactual Security Forensics Mock Data
  forensics: {
    incidents: [
      {
        id: 1,
        incidentCode: 'INC-8821',
        title: 'APT-29 SolarFlare Phishing & Multi-Stage C2 Infiltration',
        threatActor: 'APT-29 / CozyBear (State-Sponsored)',
        severity: 'CRITICAL',
        attackVector: 'Spearphishing Email -> Staged C2 Beaconing -> Lateral Lookup',
        targetSystem: 'Finance & Executive Workstation Subnet (192.168.1.100-150)',
        dwellTimeMinutes: 48,
        totalEvents: 6,
        originalOutcome: 'Breach Occurred & C2 Channel Established',
        summary: 'Targeted multi-stage advanced threat campaign. The attacker bypassed initial lexical checks using deceptive branding on .online, established encrypted C2 beaconing, and performed internal lateral reconnaissance before late manual sinkholing.',
        impactDetails: 'Initial access credentials harvested; active C2 beacon sustained for 48 minutes; 14 internal host records queried.',
        timelineEvents: [
          {
            step: 1,
            offsetSec: 0,
            domain: 'update-check.microsoft-telemetry.cc',
            queryType: 'A',
            clientIp: '192.168.1.115',
            groundTruth: 'SUSPICIOUS',
            originalAction: 'ALLOWED',
            originalVerdict: 'SAFE',
            killChainPhase: 'Reconnaissance',
            threatDetails: 'Subtle deceptive brand spoofing. Unverified on public feeds during early probe.',
            historicalImpact: 'Attacker verified target subnet resolves external DNS without active challenge.'
          },
          {
            step: 2,
            offsetSec: 180,
            domain: 'azure-sync-ad-connector.online',
            queryType: 'A',
            clientIp: '192.168.1.115',
            groundTruth: 'MALICIOUS',
            originalAction: 'ALLOWED',
            originalVerdict: 'SAFE',
            killChainPhase: 'Weaponized Delivery / Phishing',
            threatDetails: 'Credential harvesting landing page masquerading as Azure AD single sign-on.',
            historicalImpact: 'Victim workstation downloaded weaponized dropper payload.'
          },
          {
            step: 3,
            offsetSec: 620,
            domain: 'x8k2m9v4q1.biz',
            queryType: 'A',
            clientIp: '192.168.1.115',
            groundTruth: 'MALICIOUS',
            originalAction: 'ALLOWED',
            originalVerdict: 'SUSPICIOUS',
            killChainPhase: 'DGA Secondary Beacon',
            threatDetails: 'Pseudorandom DGA rendezvous domain with Shannon entropy 3.84.',
            historicalImpact: 'Payload obtained secondary dynamic IP controller address.'
          },
          {
            step: 4,
            offsetSec: 1440,
            domain: 'c2-trojan-controller-sync.net',
            queryType: 'A',
            clientIp: '192.168.1.115',
            groundTruth: 'MALICIOUS',
            originalAction: 'ALLOWED',
            originalVerdict: 'SUSPICIOUS',
            killChainPhase: 'C2 Channel Establishment',
            threatDetails: 'Cobalt Strike malleable C2 interactive session initiation.',
            historicalImpact: 'Active shell access established; operator commenced host enumeration.'
          },
          {
            step: 5,
            offsetSec: 2100,
            domain: 'corp-dc01-active-directory.local',
            queryType: 'SRV',
            clientIp: '192.168.1.115',
            groundTruth: 'BENIGN',
            originalAction: 'ALLOWED',
            originalVerdict: 'SAFE',
            killChainPhase: 'Lateral Reconnaissance',
            threatDetails: 'Internal Active Directory service record query executed by threat agent.',
            historicalImpact: 'Primary domain controller located on corporate network.'
          },
          {
            step: 6,
            offsetSec: 2880,
            domain: 'stage2-payload-exfil.top',
            queryType: 'A',
            clientIp: '192.168.1.115',
            groundTruth: 'MALICIOUS',
            originalAction: 'BLOCKED',
            originalVerdict: 'MALICIOUS',
            killChainPhase: 'Exfiltration Staging',
            threatDetails: 'Known malicious infostealer endpoint; matched late signature feed update.',
            historicalImpact: 'Late containment: Query sinkholed to 0.0.0.0, but credential harvesting had already completed.'
          }
        ]
      },
      {
        id: 2,
        incidentCode: 'INC-8822',
        title: 'DarkSide Ransomware Pre-Encryption Outbreak',
        threatActor: 'DarkSide Ransomware Syndicate',
        severity: 'CRITICAL',
        attackVector: 'Malvertising Drive-by -> Dynamic DNS Key Exchange -> Volume Shadow Drop',
        targetSystem: 'Billing & Payroll Database Host (192.168.1.142)',
        dwellTimeMinutes: 34,
        totalEvents: 6,
        originalOutcome: 'Partial Subnet Encryption Before Containment',
        summary: 'High-velocity ransomware deployment. Initial malicious redirect on .top was allowed due to permissive TLD rules. The malware established asymmetric key exchange with dynamic DNS controllers, detonating encryption across 3 networked shared drives before late sinkholing.',
        impactDetails: '3 shared network folders encrypted; backup shadow copies targeted; incident response engaged after user ticket.',
        timelineEvents: [
          {
            step: 1,
            offsetSec: 0,
            domain: 'secure-document-portal-view.top',
            queryType: 'A',
            clientIp: '192.168.1.142',
            groundTruth: 'MALICIOUS',
            originalAction: 'ALLOWED',
            originalVerdict: 'SAFE',
            killChainPhase: 'Initial Delivery',
            threatDetails: 'Malvertising lure hosted on high-abuse .top TLD.',
            historicalImpact: 'Browser silently downloaded Stage 1 loader script.'
          },
          {
            step: 2,
            offsetSec: 240,
            domain: 'malware-payload-stage1.biz',
            queryType: 'A',
            clientIp: '192.168.1.142',
            groundTruth: 'MALICIOUS',
            originalAction: 'ALLOWED',
            originalVerdict: 'SAFE',
            killChainPhase: 'Payload Download',
            threatDetails: 'Encrypted binary dropper download endpoint.',
            historicalImpact: 'Ransomware executable written to %APPDATA% directory.'
          },
          {
            step: 3,
            offsetSec: 780,
            domain: 'p9o8i7u6y5t4r3.biz',
            queryType: 'A',
            clientIp: '192.168.1.142',
            groundTruth: 'MALICIOUS',
            originalAction: 'ALLOWED',
            originalVerdict: 'SUSPICIOUS',
            killChainPhase: 'Key Exchange C2',
            threatDetails: 'High-entropy algorithmic controller negotiated master encryption public key.',
            historicalImpact: 'Symmetric AES-256 session key generated and bound to local machine GUID.'
          },
          {
            step: 4,
            offsetSec: 1200,
            domain: 'ransomware-negotiation-portal.cc',
            queryType: 'A',
            clientIp: '192.168.1.142',
            groundTruth: 'MALICIOUS',
            originalAction: 'ALLOWED',
            originalVerdict: 'SUSPICIOUS',
            killChainPhase: 'Ransom Note Staging',
            threatDetails: 'TOR proxy negotiation mirror.',
            historicalImpact: 'Ransom instructions rendered to victim desktop.'
          },
          {
            step: 5,
            offsetSec: 1680,
            domain: 'dc-backup-controller.lan',
            queryType: 'A',
            clientIp: '192.168.1.142',
            groundTruth: 'BENIGN',
            originalAction: 'ALLOWED',
            originalVerdict: 'SAFE',
            killChainPhase: 'Internal Shared Storage',
            threatDetails: 'Legitimate internal storage volume mapped via SMB.',
            historicalImpact: 'File encryption initiated across local drives and network shares.'
          },
          {
            step: 6,
            offsetSec: 2040,
            domain: 'darkside-drop-vault.ru',
            queryType: 'A',
            clientIp: '192.168.1.142',
            groundTruth: 'MALICIOUS',
            originalAction: 'BLOCKED',
            originalVerdict: 'MALICIOUS',
            killChainPhase: 'Exfiltration Channel',
            threatDetails: 'Targeted by emergency SecOps sinkhole policy rule.',
            historicalImpact: 'Exfiltration halted at Step 6, but encryption damage had already occurred.'
          }
        ]
      },
      {
        id: 3,
        incidentCode: 'INC-8823',
        title: 'Covert DNS Tunneling & Customer Data Exfiltration',
        threatActor: 'FIN7 / Carbanak Financial Syndicate',
        severity: 'HIGH',
        attackVector: 'Base64 Subdomain DNS Tunneling (Slow & Low)',
        targetSystem: 'Point-of-Sale / E-Commerce Backend (192.168.1.205)',
        dwellTimeMinutes: 65,
        totalEvents: 6,
        originalOutcome: '14,200 Customer Payment Records Exfiltrated',
        summary: 'Covert low-frequency data exfiltration leveraging encoded DNS queries. Because standard DNS packet filtering did not enforce subdomain depth or character entropy thresholds on subdomains, 18 sequential chunks bypassed detection until firewall netflow alerts triggered.',
        impactDetails: 'Payment card tokens and customer PII exfiltrated in TXT and A query subdomains.',
        timelineEvents: [
          {
            step: 1,
            offsetSec: 0,
            domain: 'tunnel-gateway.dns-tunnel-drop.xyz',
            queryType: 'TXT',
            clientIp: '192.168.1.205',
            groundTruth: 'MALICIOUS',
            originalAction: 'ALLOWED',
            originalVerdict: 'SAFE',
            killChainPhase: 'Tunnel Handshake',
            threatDetails: 'Initial tunneling protocol sync packet with Base64 signature.',
            historicalImpact: 'Tunnel established; threat agent verified bidirectional DNS encoding.'
          },
          {
            step: 2,
            offsetSec: 420,
            domain: 'dG9rZW4xMjM0NTY3OA.tunnel-gateway.dns-tunnel-drop.xyz',
            queryType: 'A',
            clientIp: '192.168.1.205',
            groundTruth: 'MALICIOUS',
            originalAction: 'ALLOWED',
            originalVerdict: 'SAFE',
            killChainPhase: 'Data Exfiltration (Chunk 01)',
            threatDetails: 'Base64 encoded customer record batch 1. Entropy: 4.15.',
            historicalImpact: '2,400 records exfiltrated covertly.'
          },
          {
            step: 3,
            offsetSec: 960,
            domain: 'cGFzc3dvcmQxMjM0NTY.tunnel-gateway.dns-tunnel-drop.xyz',
            queryType: 'A',
            clientIp: '192.168.1.205',
            groundTruth: 'MALICIOUS',
            originalAction: 'ALLOWED',
            originalVerdict: 'SAFE',
            killChainPhase: 'Data Exfiltration (Chunk 02)',
            threatDetails: 'Base64 encoded customer record batch 2. Entropy: 4.22.',
            historicalImpact: '3,100 additional records leaked.'
          },
          {
            step: 4,
            offsetSec: 1680,
            domain: 'Y3JjMTZzdW1jaGVja2RhdGE.tunnel-gateway.dns-tunnel-drop.xyz',
            queryType: 'A',
            clientIp: '192.168.1.205',
            groundTruth: 'MALICIOUS',
            originalAction: 'ALLOWED',
            originalVerdict: 'SAFE',
            killChainPhase: 'Data Exfiltration (Chunk 03)',
            threatDetails: 'Base64 encoded customer record batch 3. Entropy: 4.18.',
            historicalImpact: '4,200 records leaked.'
          },
          {
            step: 5,
            offsetSec: 2520,
            domain: 'ZW5jcnlwdGVkYmF0Y2gwNA.tunnel-gateway.dns-tunnel-drop.xyz',
            queryType: 'A',
            clientIp: '192.168.1.205',
            groundTruth: 'MALICIOUS',
            originalAction: 'ALLOWED',
            originalVerdict: 'SAFE',
            killChainPhase: 'Data Exfiltration (Chunk 04)',
            threatDetails: 'Base64 encoded customer record batch 4. Entropy: 4.19.',
            historicalImpact: '4,500 records leaked (Cumulative: 14,200).'
          },
          {
            step: 6,
            offsetSec: 3900,
            domain: 'tunnel-gateway.dns-tunnel-drop.xyz',
            queryType: 'A',
            clientIp: '192.168.1.205',
            groundTruth: 'MALICIOUS',
            originalAction: 'BLOCKED',
            originalVerdict: 'MALICIOUS',
            killChainPhase: 'Emergency Containment',
            threatDetails: 'Manual administrator domain sinkhole rule applied after firewall alert.',
            historicalImpact: 'Tunnel disconnected after 65 minutes. Breach had already transpired.'
          }
        ]
      }
    ]
  }
};

// Export to window
if (typeof window !== 'undefined') {
  window.CyberMockData = CyberMockData;
}

