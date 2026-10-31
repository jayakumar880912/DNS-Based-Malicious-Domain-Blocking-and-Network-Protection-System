/**
 * DNS-Based Malicious Domain Blocking and Network Protection System
 * DNS Monitoring Page Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  const tableBody = document.getElementById('dnsLogsTableBody');
  const searchInput = document.getElementById('dnsSearchInput');
  const filterStatus = document.getElementById('dnsStatusFilter');
  const filterQueryType = document.getElementById('dnsTypeFilter');
  const sortSelect = document.getElementById('dnsSortSelect');
  const liveStreamToggle = document.getElementById('toggleLiveStream');
  const liveStatusBadge = document.getElementById('liveStreamBadge');
  const btnExportCsv = document.getElementById('btnExportDnsLogs');
  const logCountDisplay = document.getElementById('dnsLogCountDisplay');

  let logs = [];
  let liveStreamInterval = null;

  try {
    logs = await CyberApiService.getDnsLogs();
    applyFiltersAndRender();
  } catch (err) {
    console.error('Failed to load DNS logs:', err);
    CyberUI.showToast('Could not load DNS logs: ' + err.message, 'danger');
  }

  // 1. Search Input Handler
  if (searchInput) {
    searchInput.addEventListener('input', () => applyFiltersAndRender());
  }

  // 2. Filter Status Handler (All, Allowed, Blocked, Suspicious)
  if (filterStatus) {
    filterStatus.addEventListener('change', () => applyFiltersAndRender());
  }

  // 3. Filter Query Type (A, AAAA, TXT, CNAME, etc.)
  if (filterQueryType) {
    filterQueryType.addEventListener('change', () => applyFiltersAndRender());
  }

  // 4. Sorting Handler
  if (sortSelect) {
    sortSelect.addEventListener('change', () => applyFiltersAndRender());
  }

  // 5. Live Stream Simulation Toggle
  if (liveStreamToggle) {
    liveStreamToggle.addEventListener('change', () => {
      if (liveStreamToggle.checked) {
        startLiveStream();
        if (liveStatusBadge) {
          liveStatusBadge.innerHTML = `<span class="status-pulse pulse-safe"></span> LIVE STREAMING`;
          liveStatusBadge.className = 'cyber-badge badge-safe';
        }
        CyberUI.showToast('Live DNS telemetry stream active.', 'success');
      } else {
        stopLiveStream();
        if (liveStatusBadge) {
          liveStatusBadge.innerHTML = `<span class="status-pulse pulse-suspicious"></span> STREAM PAUSED`;
          liveStatusBadge.className = 'cyber-badge badge-suspicious';
        }
        CyberUI.showToast('Live DNS stream paused.', 'info');
      }
    });
  }

  // 6. CSV Export Functionality
  if (btnExportCsv) {
    btnExportCsv.addEventListener('click', () => {
      exportLogsToCsv(getFilteredLogs());
    });
  }

  /**
   * Filter and Sort Helpers
   */
  function getFilteredLogs() {
    const query = searchInput ? searchInput.value.trim().toLowerCase() : '';
    const status = filterStatus ? filterStatus.value : 'ALL';
    const qType = filterQueryType ? filterQueryType.value : 'ALL';
    const sortBy = sortSelect ? sortSelect.value : 'time_desc';

    return logs.filter(log => {
      const matchQuery = !query || 
        log.domain.toLowerCase().includes(query) || 
        log.clientIp.toLowerCase().includes(query) ||
        log.id.toLowerCase().includes(query);

      const matchStatus = status === 'ALL' || log.status === status;
      const matchType = qType === 'ALL' || log.queryType === qType;

      return matchQuery && matchStatus && matchType;
    }).sort((a, b) => {
      if (sortBy === 'time_desc') return new Date(b.timestamp) - new Date(a.timestamp);
      if (sortBy === 'time_asc') return new Date(a.timestamp) - new Date(b.timestamp);
      if (sortBy === 'latency_desc') return b.responseTimeMs - a.responseTimeMs;
      if (sortBy === 'latency_asc') return a.responseTimeMs - b.responseTimeMs;
      if (sortBy === 'domain_asc') return a.domain.localeCompare(b.domain);
      return 0;
    });
  }

  function applyFiltersAndRender() {
    const filtered = getFilteredLogs();
    renderLogsTable(filtered);
    if (logCountDisplay) {
      logCountDisplay.textContent = `Showing ${filtered.length} of ${logs.length} DNS Records`;
    }
  }

  /**
   * Render Table Rows
   */
  function renderLogsTable(data, highlightNewId = null) {
    if (!tableBody) return;

    if (data.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="7" class="text-center py-5 text-muted">
            <i class="fa-solid fa-satellite-dish mb-2 fa-2x" style="opacity: 0.3;"></i>
            <div>No matching DNS requests found for the specified filters.</div>
          </td>
        </tr>
      `;
      return;
    }

    tableBody.innerHTML = data.map(log => {
      let badgeClass = 'badge-safe';
      let icon = 'fa-circle-check';
      if (log.status === 'BLOCKED') {
        badgeClass = 'badge-malicious';
        icon = 'fa-ban';
      } else if (log.status === 'SUSPICIOUS') {
        badgeClass = 'badge-suspicious';
        icon = 'fa-triangle-exclamation';
      }

      const isNewClass = log.id === highlightNewId ? 'row-new' : '';

      return `
        <tr class="${isNewClass}">
          <td class="font-mono text-dim" style="font-size: 0.8rem;">${log.timestamp}</td>
          <td>
            <div class="fw-semibold font-mono text-bright">${log.domain}</div>
            <div class="text-dim" style="font-size: 0.75rem;">${log.category || 'DNS Query'}</div>
          </td>
          <td class="font-mono text-cyan" style="font-size: 0.82rem;">${log.clientIp}</td>
          <td><span class="cyber-badge badge-info font-mono" style="font-size: 0.72rem;">${log.queryType}</span></td>
          <td class="font-mono" style="font-size: 0.82rem;">
            <span class="${log.responseTimeMs < 10 ? 'text-safe' : log.responseTimeMs < 25 ? 'text-cyan' : 'text-suspicious'}">
              ${log.responseTimeMs} ms
            </span>
          </td>
          <td>
            <span class="cyber-badge ${badgeClass}">
              <i class="fa-solid ${icon}"></i> ${log.status}
            </span>
          </td>
          <td>
            <a href="domain-checker.html?domain=${encodeURIComponent(log.domain)}" class="btn-cyber-secondary btn-cyber-sm" title="Analyze in Security Checker">
              <i class="fa-solid fa-magnifying-glass"></i>
            </a>
          </td>
        </tr>
      `;
    }).join('');
  }

  /**
   * Live Query Stream Simulator
   */
  function startLiveStream() {
    if (liveStreamInterval) clearInterval(liveStreamInterval);

    const simulatedQueries = [
      { domain: 'connect.microsoft.com', queryType: 'A', status: 'ALLOWED', category: 'Cloud Infrastructure', latency: 12 },
      { domain: 'telemetry.adobe.io', queryType: 'AAAA', status: 'ALLOWED', category: 'Software Telemetry', latency: 9 },
      { domain: 'c2-beacon-trojan-drop.ru', queryType: 'A', status: 'BLOCKED', category: 'Botnet C2 Sinkhole', latency: 3 },
      { domain: 'api.slack.com', queryType: 'A', status: 'ALLOWED', category: 'Business Tool', latency: 16 },
      { domain: 'fake-update-chrome-installer.top', queryType: 'A', status: 'BLOCKED', category: 'Malware Dropper', latency: 4 },
      { domain: 'dga-901844b.biz', queryType: 'A', status: 'SUSPICIOUS', category: 'DGA Heuristic', latency: 14 },
      { domain: 'cdnjs.cloudflare.com', queryType: 'A', status: 'ALLOWED', category: 'CDN Asset', latency: 7 }
    ];

    liveStreamInterval = setInterval(() => {
      const sample = simulatedQueries[Math.floor(Math.random() * simulatedQueries.length)];
      const now = new Date();
      const timeStr = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')} ${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`;

      const newLog = {
        id: 'DNS-' + Math.floor(Math.random() * 9000 + 1000),
        timestamp: timeStr,
        clientIp: '192.168.1.' + Math.floor(Math.random() * 210 + 10),
        domain: sample.domain,
        queryType: sample.queryType,
        responseTimeMs: sample.latency,
        status: sample.status,
        category: sample.category
      };

      logs.unshift(newLog);
      if (logs.length > 100) logs.pop();

      applyFiltersAndRender();
    }, 2800);
  }

  function stopLiveStream() {
    if (liveStreamInterval) {
      clearInterval(liveStreamInterval);
      liveStreamInterval = null;
    }
  }

  /**
   * Export to CSV
   */
  function exportLogsToCsv(data) {
    if (!data || data.length === 0) {
      CyberUI.showToast('No logs available to export.', 'warning');
      return;
    }

    const headers = ['ID', 'Timestamp', 'Domain', 'Client IP', 'Query Type', 'Response Time (ms)', 'Status', 'Category'];
    const rows = data.map(d => [
      `"${d.id}"`,
      `"${d.timestamp}"`,
      `"${d.domain}"`,
      `"${d.clientIp}"`,
      `"${d.queryType}"`,
      d.responseTimeMs,
      `"${d.status}"`,
      `"${d.category || ''}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `aegisdns_monitoring_logs_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    CyberUI.showToast('DNS query logs exported successfully to CSV.', 'success');
  }
});

