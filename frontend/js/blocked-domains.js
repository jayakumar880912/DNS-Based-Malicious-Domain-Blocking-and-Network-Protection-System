/**
 * DNS-Based Malicious Domain Blocking and Network Protection System
 * Blocked Domains Management Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  const tableBody = document.getElementById('blockedDomainsTableBody');
  const searchInput = document.getElementById('blockedSearchInput');
  const categoryFilter = document.getElementById('blockedCategoryFilter');
  const blockedCountDisplay = document.getElementById('blockedCountDisplay');
  const addBlockForm = document.getElementById('addBlockDomainForm');

  // Modal references
  const modalEl = document.getElementById('addBlockModal');
  const addBlockModal = modalEl && typeof bootstrap !== 'undefined' ? new bootstrap.Modal(modalEl) : null;

  let blockedList = [];

  try {
    blockedList = await CyberApiService.getBlockedDomains();
    applyFiltersAndRender();
  } catch (err) {
    console.error('Failed to load blocked domains:', err);
    CyberUI.showToast('Could not load blocked domains: ' + err.message, 'danger');
  }

  // Search input handler
  if (searchInput) {
    searchInput.addEventListener('input', () => applyFiltersAndRender());
  }

  // Category filter handler
  if (categoryFilter) {
    categoryFilter.addEventListener('change', () => applyFiltersAndRender());
  }

  // Add Custom Block Rule Form Submission
  if (addBlockForm) {
    addBlockForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      const domain = document.getElementById('newBlockDomain').value.trim();
      const threatCategory = document.getElementById('newBlockCategory').value;
      const severity = document.getElementById('newBlockSeverity').value;
      const blockingReason = document.getElementById('newBlockReason').value.trim();

      if (!domain) {
        CyberUI.showToast('Please enter a valid domain to block.', 'warning');
        return;
      }

      try {
        const added = await CyberApiService.addBlockedDomain({
          domain,
          threatCategory,
          severity,
          blockingReason: blockingReason || 'Blocked by SecOps administrator custom rule'
        });

        blockedList.unshift(added);
        applyFiltersAndRender();

        if (addBlockModal) addBlockModal.hide();
        addBlockForm.reset();
        CyberUI.showToast(`Domain "${domain}" added to active DNS sinkhole blocklist!`, 'success');
      } catch (err) {
        CyberUI.showToast(err.message, 'danger');
      }
    });
  }

  /**
   * Filter and Sort Helpers
   */
  function getFilteredBlocked() {
    const q = searchInput ? searchInput.value.trim().toLowerCase() : '';
    const cat = categoryFilter ? categoryFilter.value : 'ALL';

    return blockedList.filter(item => {
      const matchQ = !q || 
        item.domain.toLowerCase().includes(q) || 
        item.blockingReason.toLowerCase().includes(q) ||
        item.id.toLowerCase().includes(q);

      const matchCat = cat === 'ALL' || item.threatCategory === cat;

      return matchQ && matchCat;
    });
  }

  function applyFiltersAndRender() {
    const filtered = getFilteredBlocked();
    renderBlockedTable(filtered);
    if (blockedCountDisplay) {
      blockedCountDisplay.textContent = `Active Blocked Domains: ${blockedList.length.toLocaleString()}`;
    }
  }

  /**
   * Render Table Rows
   */
  function renderBlockedTable(data) {
    if (!tableBody) return;

    if (data.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="7" class="text-center py-5 text-muted">
            <i class="fa-solid fa-ban mb-2 fa-2x" style="opacity: 0.3;"></i>
            <div>No blocked domain policies matched current criteria.</div>
          </td>
        </tr>
      `;
      return;
    }

    tableBody.innerHTML = data.map(item => {
      return `
        <tr>
          <td class="font-mono text-cyan" style="font-size: 0.8rem;">${item.id}</td>
          <td>
            <div class="fw-bold font-mono text-bright">${item.domain}</div>
            <div class="text-dim" style="font-size: 0.72rem;">Feed: ${item.source || 'Threat Intelligence Engine'}</div>
          </td>
          <td>
            <span class="cyber-badge badge-purple" style="font-size: 0.75rem;">${item.threatCategory}</span>
          </td>
          <td class="text-muted text-truncate" style="max-width: 260px; font-size: 0.82rem;" title="${item.blockingReason}">
            ${item.blockingReason}
          </td>
          <td class="font-mono text-dim" style="font-size: 0.8rem;">${item.detectionDate}</td>
          <td>
            <span class="cyber-badge badge-malicious" style="font-size: 0.72rem;">
              <span class="status-pulse pulse-malicious"></span> SINKHOLED
            </span>
          </td>
          <td>
            <div class="d-flex gap-1">
              <a href="domain-checker.html?domain=${encodeURIComponent(item.domain)}" class="btn-cyber-secondary btn-cyber-sm" title="Inspect Security Report">
                <i class="fa-solid fa-magnifying-glass"></i>
              </a>
              <button class="btn-cyber-outline-danger btn-cyber-sm btn-unblock-domain" data-id="${item.id}" data-domain="${item.domain}" title="Whitelist / Unblock Domain">
                <i class="fa-solid fa-unlock"></i> Unblock
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    // Attach unblock handlers
    document.querySelectorAll('.btn-unblock-domain').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        const domain = btn.getAttribute('data-domain');

        if (confirm(`Are you sure you want to unblock "${domain}" and remove it from DNS sinkhole enforcement?`)) {
          try {
            await CyberApiService.removeBlockedDomain(id);
            blockedList = blockedList.filter(d => d.id !== id && d.domain !== domain);
            applyFiltersAndRender();
            CyberUI.showToast(`Domain "${domain}" unblocked and whitelisted.`, 'warning');
          } catch (err) {
            CyberUI.showToast(err.message, 'danger');
          }
        }
      });
    });
  }
});

