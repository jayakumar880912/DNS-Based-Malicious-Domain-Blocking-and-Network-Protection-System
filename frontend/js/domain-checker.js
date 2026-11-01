/**
 * DNS-Based Malicious Domain Blocking and Network Protection System
 * Domain Security Checker Page Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  const domainInput = document.getElementById('checkerDomainInput');
  const checkBtn = document.getElementById('btnExecuteCheck');
  const clearBtn = document.getElementById('btnClearChecker');
  const loadingSection = document.getElementById('checkerLoadingSection');
  const resultSection = document.getElementById('checkerResultSection');
  const samplePills = document.querySelectorAll('.sample-domain-pill');

  // Check if URL contains ?domain= query parameter
  const urlParams = new URLSearchParams(window.location.search);
  const paramDomain = urlParams.get('domain');
  if (paramDomain && domainInput) {
    domainInput.value = paramDomain;
    performDomainSecurityCheck(paramDomain);
  }

  // Check Domain Button Handler
  if (checkBtn) {
    checkBtn.addEventListener('click', () => {
      const val = domainInput ? domainInput.value.trim() : '';
      performDomainSecurityCheck(val);
    });
  }

  // Enter Key Handler
  if (domainInput) {
    domainInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        performDomainSecurityCheck(domainInput.value.trim());
      }
    });
  }

  // Clear Button Handler
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      if (domainInput) {
        domainInput.value = '';
        domainInput.focus();
      }
      if (resultSection) resultSection.style.display = 'none';
      if (loadingSection) loadingSection.style.display = 'none';
      CyberUI.showToast('Inspection form cleared.', 'info');
    });
  }

  // Quick Preset Sample Pills
  samplePills.forEach(pill => {
    pill.addEventListener('click', () => {
      const domain = pill.getAttribute('data-domain');
      if (domainInput) domainInput.value = domain;
      performDomainSecurityCheck(domain);
    });
  });

  /**
   * Execute Inspection Workflow
   */
  async function performDomainSecurityCheck(domain) {
    if (!domain) {
      CyberUI.showToast('Please enter a domain name to inspect.', 'warning');
      if (domainInput) domainInput.focus();
      return;
    }

    // Show loading radar scanner
    if (resultSection) resultSection.style.display = 'none';
    if (loadingSection) loadingSection.style.display = 'block';
    if (checkBtn) {
      checkBtn.disabled = true;
      checkBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-2"></i> Analyzing Domain...';
    }

    try {
      // Call Backend / API Service
      const result = await CyberApiService.checkDomain(domain);
      renderInspectionResult(result);
    } catch (err) {
      CyberUI.showToast(err.message, 'danger');
      if (loadingSection) loadingSection.style.display = 'none';
    } finally {
      if (checkBtn) {
        checkBtn.disabled = false;
        checkBtn.innerHTML = '<i class="fa-solid fa-shield-virus me-2"></i> Check Domain';
      }
    }
  }

  /**
   * Render Result Card (Safe / Malicious / Suspicious)
   */
  function renderInspectionResult(data) {
    if (loadingSection) loadingSection.style.display = 'none';
    if (!resultSection) return;

    resultSection.style.display = 'block';

    let cardClass = 'result-safe';
    let iconClass = 'fa-circle-check text-safe';
    let statusLabel = 'SAFE';
    let headline = 'Domain is Safe';
    let permissionNotice = 'Access Permitted • DNS Resolution Approved';
    let scoreColor = 'var(--color-safe)';

    if (data.status === 'MALICIOUS') {
      cardClass = 'result-malicious';
      iconClass = 'fa-skull-crossbones text-malicious';
      statusLabel = 'MALICIOUS';
      headline = 'Malicious Domain Detected';
      permissionNotice = 'Access Blocked • Intercepted by DNS Sinkhole (0.0.0.0)';
      scoreColor = 'var(--color-malicious)';
    } else if (data.status === 'SUSPICIOUS') {
      cardClass = 'result-suspicious';
      iconClass = 'fa-triangle-exclamation text-suspicious';
      statusLabel = 'SUSPICIOUS';
      headline = 'Suspicious Domain Detected';
      permissionNotice = 'Further Verification Recommended • Flagged for SecOps Review';
      scoreColor = 'var(--color-suspicious)';
    }

    resultSection.innerHTML = `
      <div class="result-card ${cardClass}">
        <div class="verdict-header">
          <div class="verdict-icon-box">
            <i class="fa-solid ${iconClass}"></i>
          </div>
          <div style="flex: 1;">
            <div class="d-flex align-items-center gap-2 mb-1">
              <span class="cyber-badge badge-${data.status.toLowerCase()}">${statusLabel}</span>
              <span class="text-dim" style="font-size: 0.8rem;">Checked at ${data.checkedAt || 'Just now'}</span>
            </div>
            <h3 class="mb-1 fw-bold text-bright font-mono" style="word-break: break-all;">${data.domain}</h3>
            <div class="fw-semibold text-${data.status.toLowerCase()}" style="font-size: 1.05rem;">
              ${headline} &mdash; <span style="font-size: 0.9rem; font-weight: 500;">${permissionNotice}</span>
            </div>
          </div>
          <div class="score-meter-box d-none d-md-block">
            <div class="stat-label">Risk Rating</div>
            <div class="score-meter-num" style="color: ${scoreColor};">${data.riskScore}<span style="font-size: 1.1rem; color: var(--text-dim);">/100</span></div>
            <div style="font-size: 0.72rem; color: var(--text-muted);">${data.status === 'SAFE' ? 'Low Risk' : data.status === 'MALICIOUS' ? 'Severe Threat' : 'Elevated Risk'}</div>
          </div>
        </div>

        <div class="row g-3 mb-4">
          <div class="col-lg-8">
            <div class="p-3 rounded mb-3" style="background: rgba(5, 8, 17, 0.6); border: 1px solid var(--border-subtle);">
              <div class="text-muted mb-1" style="font-size: 0.8rem; font-weight: 600; text-transform: uppercase;">Analysis Verdict & Findings</div>
              <div class="text-main" style="font-size: 0.92rem; line-height: 1.6;">${data.verdictReason}</div>
            </div>

            <div class="row g-3">
              <div class="col-sm-6">
                <div class="p-3 rounded" style="background: rgba(5, 8, 17, 0.4); border: 1px solid var(--border-subtle);">
                  <div class="text-dim" style="font-size: 0.75rem; text-transform: uppercase;">Domain Category</div>
                  <div class="fw-semibold text-bright font-mono mt-1" style="font-size: 0.88rem;">${data.category}</div>
                </div>
              </div>
              <div class="col-sm-6">
                <div class="p-3 rounded" style="background: rgba(5, 8, 17, 0.4); border: 1px solid var(--border-subtle);">
                  <div class="text-dim" style="font-size: 0.75rem; text-transform: uppercase;">Resolved IP / Null-Route</div>
                  <div class="fw-semibold font-mono text-cyan mt-1" style="font-size: 0.88rem;">${data.ip}</div>
                </div>
              </div>
              <div class="col-sm-6">
                <div class="p-3 rounded" style="background: rgba(5, 8, 17, 0.4); border: 1px solid var(--border-subtle);">
                  <div class="text-dim" style="font-size: 0.75rem; text-transform: uppercase;">Nameserver (NS)</div>
                  <div class="font-mono text-muted mt-1" style="font-size: 0.82rem;">${data.nameserver}</div>
                </div>
              </div>
              <div class="col-sm-6">
                <div class="p-3 rounded" style="background: rgba(5, 8, 17, 0.4); border: 1px solid var(--border-subtle);">
                  <div class="text-dim" style="font-size: 0.75rem; text-transform: uppercase;">Entropy & Heuristics</div>
                  <div class="font-mono text-muted mt-1" style="font-size: 0.82rem;">${data.entropyScore}</div>
                </div>
              </div>
            </div>
          </div>

          <div class="col-lg-4">
            <div class="p-3 rounded h-100" style="background: rgba(5, 8, 17, 0.6); border: 1px solid var(--border-subtle);">
              <div class="text-muted mb-2" style="font-size: 0.8rem; font-weight: 600; text-transform: uppercase;">Threat Feed Corroboration</div>
              <ul class="list-unstyled mb-3" style="font-size: 0.82rem;">
                ${(data.threatSources || []).map(s => `
                  <li class="mb-2 d-flex align-items-center gap-2">
                    <i class="fa-solid ${data.status === 'SAFE' ? 'fa-check text-safe' : data.status === 'MALICIOUS' ? 'fa-xmark text-malicious' : 'fa-exclamation text-suspicious'}"></i>
                    <span>${s}</span>
                  </li>
                `).join('')}
              </ul>
              <div class="text-dim" style="font-size: 0.75rem; border-top: 1px solid var(--border-subtle); padding-top: 0.65rem;">
                WHOIS Age: <strong class="text-bright">${data.ageYears} yrs</strong> | Geo: <strong class="text-bright">${data.country}</strong>
              </div>
            </div>
          </div>
        </div>

        <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 pt-2 border-top border-subtle">
          <div class="text-muted" style="font-size: 0.8rem;">
            <i class="fa-solid fa-server text-cyan me-1"></i> Policy Engine: AegisDNS Local Sinkhole & Heuristic Analyzer
          </div>
          <div class="d-flex gap-2">
            ${data.status === 'MALICIOUS' || data.status === 'SUSPICIOUS' ? `
              <a href="blocked-domains.html" class="btn-cyber-outline-danger btn-cyber-sm">
                <i class="fa-solid fa-ban me-1"></i> View Block Policy
              </a>
            ` : ''}
            <button class="btn-cyber-secondary btn-cyber-sm" onclick="window.print()">
              <i class="fa-solid fa-print me-1"></i> Export Report
            </button>
          </div>
        </div>
      </div>
    `;

    // Scroll smoothly to results
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
});

