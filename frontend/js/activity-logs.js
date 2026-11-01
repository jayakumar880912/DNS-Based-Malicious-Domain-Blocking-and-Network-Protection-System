/**
 * DNS-Based Malicious Domain Blocking and Network Protection System
 * Activity Logs Audit Trail Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  const tableBody = document.getElementById('activityTableBody');
  const searchInput = document.getElementById('activitySearchInput');
  const typeFilter = document.getElementById('activityTypeFilter');
  const statusFilter = document.getElementById('activityStatusFilter');
  const exportBtn = document.getElementById('btnExportActivity');
  const countDisplay = document.getElementById('activityCountDisplay');

  let activities = [];

  try {
    activities = await CyberApiService.getActivityLogs();
    applyFiltersAndRender();
  } catch (err) {
    console.error('Failed to load activity audit logs:', err);
    CyberUI.showToast('Could not load activity logs: ' + err.message, 'danger');
  }

  // Search input handler
  if (searchInput) {
    searchInput.addEventListener('input', () => applyFiltersAndRender());
  }

  // Type filter handler
  if (typeFilter) {
    typeFilter.addEventListener('change', () => applyFiltersAndRender());
  }

  // Status filter handler
  if (statusFilter) {
    statusFilter.addEventListener('change', () => applyFiltersAndRender());
  }

  // Export CSV handler
  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      exportActivityToCsv(getFilteredActivities());
    });
  }

  /**
   * Filter helper
   */
  function getFilteredActivities() {
    const q = searchInput ? searchInput.value.trim().toLowerCase() : '';
    const type = typeFilter ? typeFilter.value : 'ALL';
    const status = statusFilter ? statusFilter.value : 'ALL';

    return activities.filter(act => {
      const matchQ = !q ||
        act.id.toLowerCase().includes(q) ||
        act.actor.toLowerCase().includes(q) ||
        act.target.toLowerCase().includes(q) ||
        act.details.toLowerCase().includes(q) ||
        act.ipOrigin.toLowerCase().includes(q);

      const matchType = type === 'ALL' || act.activityType.toLowerCase().includes(type.toLowerCase());
      const matchStatus = status === 'ALL' || act.status === status;

      return matchQ && matchType && matchStatus;
    });
  }

  function applyFiltersAndRender() {
    const filtered = getFilteredActivities();
    renderActivityTable(filtered);
    if (countDisplay) {
      countDisplay.textContent = `Showing ${filtered.length} of ${activities.length} Audit Events`;
    }
  }

  /**
   * Render table rows
   */
  function renderActivityTable(data) {
    if (!tableBody) return;

    if (data.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="7" class="text-center py-5 text-muted">
            <i class="fa-solid fa-list-check mb-2 fa-2x" style="opacity: 0.3;"></i>
            <div>No activity events match the current filter selection.</div>
          </td>
        </tr>
      `;
      return;
    }

    tableBody.innerHTML = data.map(act => {
      let badgeClass = 'badge-info';
      if (act.status === 'BLOCKED') badgeClass = 'badge-malicious';
      else if (act.status === 'ALLOWED' || act.status === 'SUCCESS') badgeClass = 'badge-safe';
      else if (act.status === 'SUSPICIOUS' || act.status === 'UPDATED') badgeClass = 'badge-suspicious';

      return `
        <tr>
          <td class="font-mono text-cyan" style="font-size: 0.8rem;">${act.id}</td>
          <td class="font-mono text-dim" style="font-size: 0.8rem;">${act.timestamp}</td>
          <td>
            <div class="fw-semibold text-bright" style="font-size: 0.88rem;">${act.activityType}</div>
          </td>
          <td class="text-muted" style="font-size: 0.82rem;">${act.actor}</td>
          <td class="font-mono text-cyan" style="font-size: 0.82rem;">${act.target}</td>
          <td class="font-mono text-dim" style="font-size: 0.8rem;">${act.ipOrigin}</td>
          <td>
            <span class="cyber-badge ${badgeClass}" style="font-size: 0.72rem;">${act.status}</span>
          </td>
          <td class="text-muted" style="font-size: 0.82rem; max-width: 280px;">${act.details}</td>
        </tr>
      `;
    }).join('');
  }

  /**
   * Export activities to CSV
   */
  function exportActivityToCsv(data) {
    if (!data || data.length === 0) {
      CyberUI.showToast('No logs available to export.', 'warning');
      return;
    }

    const headers = ['ID', 'Timestamp', 'Activity Type', 'Actor', 'Target', 'IP Origin', 'Status', 'Details'];
    const rows = data.map(d => [
      `"${d.id}"`,
      `"${d.timestamp}"`,
      `"${d.activityType}"`,
      `"${d.actor}"`,
      `"${d.target}"`,
      `"${d.ipOrigin}"`,
      `"${d.status}"`,
      `"${(d.details || '').replace(/"/g, '""')}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `aegisdns_audit_activity_log_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    CyberUI.showToast('Activity audit trail exported successfully to CSV.', 'success');
  }
});

