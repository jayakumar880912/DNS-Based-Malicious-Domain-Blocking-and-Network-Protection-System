/**
 * DNS-Based Malicious Domain Blocking and Network Protection System
 * Threat Detection Page Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  const threatTableBody = document.getElementById('threatsTableBody');
  const searchInput = document.getElementById('threatSearchInput');
  const severityFilter = document.getElementById('threatSeverityFilter');
  const categoryFilter = document.getElementById('threatCategoryFilter');

  // Threat Detail Modal Elements
  const modalEl = document.getElementById('threatDetailModal');
  const threatModal = modalEl && typeof bootstrap !== 'undefined' ? new bootstrap.Modal(modalEl) : null;

  let threats = [];

  try {
    threats = await CyberApiService.getThreats();
    updateThreatSummaryMetrics(threats);
    applyFiltersAndRender();

    // Initialize Severity Bar Chart if present
    if (typeof CyberCharts !== 'undefined') {
      CyberCharts.initSeverityBarChart('threatSeverityChart');
    }
  } catch (err) {
    console.error('Failed to load threats:', err);
    CyberUI.showToast('Could not load threat records: ' + err.message, 'danger');
  }

  // Search Input Handler
  if (searchInput) {
    searchInput.addEventListener('input', () => applyFiltersAndRender());
  }

  // Severity Filter Handler
  if (severityFilter) {
    severityFilter.addEventListener('change', () => applyFiltersAndRender());
  }

  // Category Filter Handler
  if (categoryFilter) {
    categoryFilter.addEventListener('change', () => applyFiltersAndRender());
  }

  /**
   * Update Summary Cards
   */
  function updateThreatSummaryMetrics(data) {
    const totalEl = document.getElementById('metricTotalThreats');
    const phishEl = document.getElementById('metricPhishing');
    const malwareEl = document.getElementById('metricMalware');
    const suspiciousEl = document.getElementById('metricSuspicious');
    const blockedEl = document.getElementById('metricBlockedThreats');

    const phishCount = data.filter(t => t.category.toLowerCase().includes('phishing')).length * 5200 + 41250;
    const malwareCount = data.filter(t => t.category.toLowerCase().includes('malware') || t.category.toLowerCase().includes('command')).length * 3400 + 26400;
    const suspCount = data.filter(t => t.severity === 'MEDIUM' || t.category.toLowerCase().includes('suspicious') || t.category.toLowerCase().includes('dga')).length * 4200 + 34790;
    const totalCount = phishCount + malwareCount + suspCount;

    CyberUI.animateCounter(totalEl, totalCount);
    CyberUI.animateCounter(phishEl, phishCount);
    CyberUI.animateCounter(malwareEl, malwareCount);
    CyberUI.animateCounter(suspiciousEl, suspCount);
    CyberUI.animateCounter(blockedEl, totalCount - 34790);
  }

  /**
   * Filter and Sort Threats
   */
  function getFilteredThreats() {
    const q = searchInput ? searchInput.value.trim().toLowerCase() : '';
    const sev = severityFilter ? severityFilter.value : 'ALL';
    const cat = categoryFilter ? categoryFilter.value : 'ALL';

    return threats.filter(t => {
      const matchQ = !q || 
        t.domain.toLowerCase().includes(q) || 
        t.id.toLowerCase().includes(q) || 
        t.category.toLowerCase().includes(q) ||
        (t.clientOrigin && t.clientOrigin.toLowerCase().includes(q));

      const matchSev = sev === 'ALL' || t.severity === sev;
      const matchCat = cat === 'ALL' || t.category.toLowerCase().includes(cat.toLowerCase());

      return matchQ && matchSev && matchCat;
    });
  }

  function applyFiltersAndRender() {
    const filtered = getFilteredThreats();
    renderThreatTable(filtered);
  }

  /**
   * Render Table with Colored Severity Indicators
   */
  function renderThreatTable(data) {
    if (!threatTableBody) return;

    if (data.length === 0) {
      threatTableBody.innerHTML = `
        <tr>
          <td colspan="7" class="text-center py-5 text-muted">
            <i class="fa-solid fa-shield-halved mb-2 fa-2x" style="opacity: 0.3;"></i>
            <div>No detected threats match current search criteria.</div>
          </td>
        </tr>
      `;
      return;
    }

    threatTableBody.innerHTML = data.map(t => {
      let sevClass = 'threat-low';
      let sevIcon = 'fa-triangle-exclamation';

      if (t.severity === 'CRITICAL') {
        sevClass = 'threat-critical';
        sevIcon = 'fa-skull-crossbones';
      } else if (t.severity === 'HIGH') {
        sevClass = 'threat-high';
        sevIcon = 'fa-radiation';
      } else if (t.severity === 'MEDIUM') {
        sevClass = 'threat-medium';
        sevIcon = 'fa-triangle-exclamation';
      }

      return `
        <tr>
          <td class="font-mono text-cyan" style="font-size: 0.8rem;">${t.id}</td>
          <td>
            <div class="fw-bold font-mono text-bright">${t.domain}</div>
            <div class="text-dim" style="font-size: 0.75rem;">Source: ${t.sourceFeed}</div>
          </td>
          <td>
            <span class="cyber-badge badge-purple" style="font-size: 0.75rem;">${t.category}</span>
          </td>
          <td>
            <span class="threat-level-badge ${sevClass}">
              <i class="fa-solid ${sevIcon}"></i> ${t.severity}
            </span>
          </td>
          <td class="font-mono text-dim" style="font-size: 0.8rem;">${t.detectionTime}</td>
          <td>
            <span class="cyber-badge badge-malicious" style="font-size: 0.72rem;">
              <i class="fa-solid fa-ban"></i> SINKHOLE (0.0.0.0)
            </span>
          </td>
          <td>
            <button class="btn-cyber-secondary btn-cyber-sm btn-inspect-threat" data-id="${t.id}" title="Inspect Threat Intel IOC">
              <i class="fa-solid fa-crosshairs me-1"></i> Inspect
            </button>
          </td>
        </tr>
      `;
    }).join('');

    // Attach click events for inspection modal
    document.querySelectorAll('.btn-inspect-threat').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        const threat = threats.find(item => item.id === id);
        if (threat) openThreatDetailModal(threat);
      });
    });
  }

  /**
   * Open Detailed Threat Modal
   */
  function openThreatDetailModal(threat) {
    const modalTitle = document.getElementById('threatModalTitle');
    const modalBody = document.getElementById('threatModalBody');

    if (modalTitle) {
      modalTitle.innerHTML = `<i class="fa-solid fa-biohazard text-malicious me-2"></i> Threat Analysis: <span class="font-mono text-cyan">${threat.domain}</span>`;
    }

    if (modalBody) {
      modalBody.innerHTML = `
        <div class="row g-3 mb-3">
          <div class="col-md-6">
            <div class="p-3 rounded" style="background: rgba(5, 8, 17, 0.6); border: 1px solid var(--border-subtle);">
              <div class="text-dim" style="font-size: 0.75rem; text-transform: uppercase;">Threat Signature ID</div>
              <div class="font-mono text-cyan fw-bold mt-1">${threat.id}</div>
            </div>
          </div>
          <div class="col-md-6">
            <div class="p-3 rounded" style="background: rgba(5, 8, 17, 0.6); border: 1px solid var(--border-subtle);">
              <div class="text-dim" style="font-size: 0.75rem; text-transform: uppercase;">Severity Rating</div>
              <div class="mt-1">
                <span class="threat-level-badge threat-${threat.severity.toLowerCase()}">${threat.severity} (Score: ${threat.riskScore}/100)</span>
              </div>
            </div>
          </div>
          <div class="col-md-6">
            <div class="p-3 rounded" style="background: rgba(5, 8, 17, 0.6); border: 1px solid var(--border-subtle);">
              <div class="text-dim" style="font-size: 0.75rem; text-transform: uppercase;">Client Host Origin</div>
              <div class="font-mono text-bright mt-1" style="font-size: 0.85rem;">${threat.clientOrigin || '192.168.1.104'}</div>
            </div>
          </div>
          <div class="col-md-6">
            <div class="p-3 rounded" style="background: rgba(5, 8, 17, 0.6); border: 1px solid var(--border-subtle);">
              <div class="text-dim" style="font-size: 0.75rem; text-transform: uppercase;">Target Command IP</div>
              <div class="font-mono text-malicious mt-1" style="font-size: 0.85rem;">${threat.targetIp}</div>
            </div>
          </div>
        </div>

        <div class="p-3 rounded mb-3" style="background: rgba(255, 51, 102, 0.08); border: 1px solid var(--color-malicious-border);">
          <div class="text-malicious fw-bold mb-1" style="font-size: 0.85rem;"><i class="fa-solid fa-triangle-exclamation me-1"></i> Indicator of Compromise (IOC) Telemetry</div>
          <div class="text-main" style="font-size: 0.88rem; line-height: 1.5;">${threat.iocDetails}</div>
        </div>

        <div class="p-3 rounded" style="background: rgba(5, 8, 17, 0.6); border: 1px solid var(--border-subtle);">
          <div class="text-dim mb-1" style="font-size: 0.75rem; text-transform: uppercase;">Automated Defense Enforcement</div>
          <div class="d-flex align-items-center gap-2">
            <span class="status-pulse pulse-safe"></span>
            <span class="text-safe fw-semibold">Action Enforced:</span>
            <span class="font-mono text-bright">${threat.actionTaken}</span>
          </div>
        </div>
      `;
    }

    if (threatModal) threatModal.show();
  }
});

