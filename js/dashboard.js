/**
 * DNS-Based Malicious Domain Blocking and Network Protection System
 * Dashboard Page Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  try {
    // 1. Fetch Overview Statistics via API Service
    const stats = await CyberApiService.getDashboardStats();
    renderDashboardStats(stats);

    // 2. Initialize Charts
    if (typeof CyberCharts !== 'undefined') {
      CyberCharts.initTrafficChart('dnsTrafficChart', stats.trafficHourly);
      CyberCharts.initThreatCategoriesChart('threatCategoriesChart', stats.threatCategories);
    }

    // 3. Render Recent Security Activities Table
    renderRecentActivities();

    // 4. Live Simulation / Quick Refresh Button
    const refreshBtn = document.getElementById('btnRefreshDashboard');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', async () => {
        refreshBtn.innerHTML = '<i class="fa-solid fa-arrows-rotate fa-spin me-1"></i> Syncing...';
        const freshStats = await CyberApiService.getDashboardStats();
        renderDashboardStats(freshStats);
        CyberUI.showToast('Security metrics and telemetry refreshed from local cache.', 'info');
        setTimeout(() => {
          refreshBtn.innerHTML = '<i class="fa-solid fa-arrows-rotate me-1"></i> Refresh Data';
        }, 500);
      });
    }

    // 5. Simulate Threat Interception Demo Button
    const simulateBtn = document.getElementById('btnSimulateThreat');
    if (simulateBtn) {
      simulateBtn.addEventListener('click', () => {
        triggerThreatInterceptionSimulation();
      });
    }
  } catch (err) {
    console.error('Dashboard initialization error:', err);
    CyberUI.showToast('Failed to load dashboard telemetry: ' + err.message, 'danger');
  }

  /**
   * Render and animate the 5 primary statistics cards
   */
  function renderDashboardStats(stats) {
    // 1. Total DNS Requests
    const totalRequestsEl = document.getElementById('statTotalRequests');
    CyberUI.animateCounter(totalRequestsEl, stats.totalDnsRequests);

    // 2. Safe Domains
    const safeDomainsEl = document.getElementById('statSafeDomains');
    CyberUI.animateCounter(safeDomainsEl, stats.safeDomains);

    // Safe Percentage
    const safePctEl = document.getElementById('statSafePct');
    if (safePctEl) {
      const pct = ((stats.safeDomains / stats.totalDnsRequests) * 100).toFixed(1);
      safePctEl.textContent = `${pct}% Clean Traffic`;
    }

    // 3. Blocked Malicious Domains
    const blockedDomainsEl = document.getElementById('statBlockedDomains');
    CyberUI.animateCounter(blockedDomainsEl, stats.blockedDomains);

    // 4. Suspicious Domains
    const suspiciousDomainsEl = document.getElementById('statSuspiciousDomains');
    CyberUI.animateCounter(suspiciousDomainsEl, stats.suspiciousDomains);

    // 5. Network Protection Status
    const statusTextEl = document.getElementById('statProtectionStatusText');
    const statusDotEl = document.getElementById('statProtectionStatusDot');
    const statusUptimeEl = document.getElementById('statProtectionUptime');
    const statusLatencyEl = document.getElementById('statProtectionLatency');

    if (stats.protectionStatus === 'ACTIVE') {
      if (statusTextEl) {
        statusTextEl.textContent = 'PROTECTED';
        statusTextEl.className = 'stat-value text-safe';
      }
      if (statusDotEl) statusDotEl.className = 'status-pulse pulse-safe me-2';
    } else {
      if (statusTextEl) {
        statusTextEl.textContent = 'PAUSED';
        statusTextEl.className = 'stat-value text-suspicious';
      }
      if (statusDotEl) statusDotEl.className = 'status-pulse pulse-suspicious me-2';
    }

    if (statusUptimeEl) statusUptimeEl.textContent = `Uptime: ${stats.uptime}`;
    if (statusLatencyEl) statusLatencyEl.textContent = `Resolver Latency: ${stats.currentLatencyMs}ms`;

    // Last scan info
    const lastScanEl = document.getElementById('statLastScanInfo');
    if (lastScanEl) {
      lastScanEl.textContent = `Feed updated ${stats.lastThreatFeedUpdate} • ${stats.rulesCount.toLocaleString()} active sinkhole rules`;
    }
  }

  /**
   * Render Recent Security Activities
   */
  async function renderRecentActivities() {
    const listBody = document.getElementById('recentActivitiesBody');
    if (!listBody) return;

    try {
      const activities = await CyberApiService.getActivityLogs();
      const recent = activities.slice(0, 6);

      listBody.innerHTML = recent.map(act => {
        let badgeClass = 'badge-info';
        if (act.status === 'BLOCKED') badgeClass = 'badge-malicious';
        else if (act.status === 'ALLOWED' || act.status === 'SUCCESS') badgeClass = 'badge-safe';
        else if (act.status === 'SUSPICIOUS') badgeClass = 'badge-suspicious';

        return `
          <tr>
            <td class="font-mono text-dim" style="font-size: 0.8rem;">${act.timestamp.split(' ')[1] || act.timestamp}</td>
            <td class="fw-semibold text-bright">${act.activityType}</td>
            <td class="font-mono text-cyan" style="font-size: 0.82rem;">${act.target}</td>
            <td class="font-mono text-dim" style="font-size: 0.8rem;">${act.ipOrigin}</td>
            <td><span class="cyber-badge ${badgeClass}">${act.status}</span></td>
            <td class="text-muted text-truncate" style="max-width: 280px; font-size: 0.82rem;" title="${act.details}">${act.details}</td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.warn('Could not populate recent activities:', e);
    }
  }

  /**
   * Interactive Threat Interception Demonstration
   */
  function triggerThreatInterceptionSimulation() {
    const simulationDomains = [
      'c2-beacon-trojan-drop.ru',
      'phish-apple-id-suspended-verify.xyz',
      'stealth-keylog-gate01.biz',
      'monero-pool-coinhive-miner.cc'
    ];
    const picked = simulationDomains[Math.floor(Math.random() * simulationDomains.length)];

    CyberUI.showToast(`[SINKHOLE TRIGGERED] Intercepted malicious DNS query for "${picked}"! Returned 0.0.0.0.`, 'danger', 4500);

    // Increment blocked counter visually
    const blockedDomainsEl = document.getElementById('statBlockedDomains');
    if (blockedDomainsEl) {
      const current = parseInt(blockedDomainsEl.textContent.replace(/,/g, '')) || 98640;
      CyberUI.animateCounter(blockedDomainsEl, current + 1, 300);
    }

    // Add activity log
    CyberApiService.logActivity({
      activityType: 'Threat Intercepted',
      target: picked,
      status: 'BLOCKED',
      details: 'Automatic sinkhole interception executed. Client redirected.'
    });

    // Refresh table
    renderRecentActivities();
  }
});

