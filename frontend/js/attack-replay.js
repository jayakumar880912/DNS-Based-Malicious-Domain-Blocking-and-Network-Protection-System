/**
 * AegisDNS - Attack Replay & Counterfactual Forensics Controller
 * Handles historical incident playback, interactive kill-chain scrubbing,
 * counterfactual "what-if" policy testing, and automated forensic gap reporting.
 */

document.addEventListener('DOMContentLoaded', async () => {
  // Global State
  const state = {
    incidents: [],
    policies: [],
    currentIncident: null,
    currentStep: 1,
    isPlaying: false,
    playbackSpeed: 1,
    playInterval: null,
    currentAnalysis: null
  };

  // DOM Elements
  const el = {
    // Top KPIs
    statArchivedIncidents: document.getElementById('statArchivedIncidents'),
    statAvgDwellTime: document.getElementById('statAvgDwellTime'),
    statCounterfactualRate: document.getElementById('statCounterfactualRate'),
    statMeanAcceleration: document.getElementById('statMeanAcceleration'),

    // Replay Tab
    incidentsContainer: document.getElementById('incidentsContainer'),
    currentIncidentTitle: document.getElementById('currentIncidentTitle'),
    currentIncidentCode: document.getElementById('currentIncidentCode'),
    currentIncidentMeta: document.getElementById('currentIncidentMeta'),
    badgeCurrentOutcome: document.getElementById('badgeCurrentOutcome'),
    labelStepIndicator: document.getElementById('labelStepIndicator'),
    killchainStepper: document.getElementById('killchainStepper'),
    replayScrubber: document.getElementById('replayScrubber'),
    btnPlayPause: document.getElementById('btnPlayPause'),
    btnPrevStep: document.getElementById('btnPrevStep'),
    btnNextStep: document.getElementById('btnNextStep'),
    btnResetReplay: document.getElementById('btnResetReplay'),
    replaySpeedGroup: document.getElementById('replaySpeedGroup'),
    btnSwitchToCounterfactual: document.getElementById('btnSwitchToCounterfactual'),

    // Step Inspector
    inspectorStepBadge: document.getElementById('inspectorStepBadge'),
    inspectorPhaseBadge: document.getElementById('inspectorPhaseBadge'),
    inspectorTimestamp: document.getElementById('inspectorTimestamp'),
    inspectorOriginalAction: document.getElementById('inspectorOriginalAction'),
    inspectorDomain: document.getElementById('inspectorDomain'),
    inspectorQueryType: document.getElementById('inspectorQueryType'),
    inspectorClientIp: document.getElementById('inspectorClientIp'),
    inspectorThreatDetails: document.getElementById('inspectorThreatDetails'),
    inspectorHistoricalImpact: document.getElementById('inspectorHistoricalImpact'),

    // Counterfactual Tab
    selectCfIncident: document.getElementById('selectCfIncident'),
    selectCfPolicy: document.getElementById('selectCfPolicy'),
    btnExecuteCounterfactual: document.getElementById('btnExecuteCounterfactual'),
    cfMetricDwellPct: document.getElementById('cfMetricDwellPct'),
    cfMetricTimeSaved: document.getElementById('cfMetricTimeSaved'),
    cfMetricStepDelta: document.getElementById('cfMetricStepDelta'),
    cfMetricStepsAccelerated: document.getElementById('cfMetricStepsAccelerated'),
    cfMetricDamageScore: document.getElementById('cfMetricDamageScore'),
    cfMetricVerdict: document.getElementById('cfMetricVerdict'),
    cfComparisonTableBody: document.getElementById('cfComparisonTableBody'),

    // Gaps Tab
    forensicGapsContainer: document.getElementById('forensicGapsContainer'),

    // Reports Tab
    analysesHistoryTableBody: document.getElementById('analysesHistoryTableBody'),
    btnRefreshAnalyses: document.getElementById('btnRefreshAnalyses'),
    btnQuickExportForensic: document.getElementById('btnQuickExportForensic')
  };

  // ==========================================================================
  // Initialization & Data Loading
  // ==========================================================================
  async function init() {
    try {
      const [incRes, polRes, analRes] = await Promise.all([
        CyberApiService.getSecurityIncidents(),
        CyberApiService.getVirtualPolicies(),
        CyberApiService.getCounterfactualAnalyses(20)
      ]);

      state.incidents = incRes.incidents || [];
      state.policies = polRes.policies || [];
      const analyses = analRes.analyses || [];

      // Update Top KPIs
      if (el.statArchivedIncidents) el.statArchivedIncidents.textContent = state.incidents.length;

      let totalDwell = 0;
      state.incidents.forEach(i => totalDwell += (i.dwellTimeMinutes || 45));
      const avgDwell = state.incidents.length > 0 ? Math.round(totalDwell / state.incidents.length) : 48;
      if (el.statAvgDwellTime) el.statAvgDwellTime.textContent = `${avgDwell} min`;

      if (el.statCounterfactualRate) el.statCounterfactualRate.textContent = '100%';
      if (el.statMeanAcceleration) el.statMeanAcceleration.textContent = '+4.0 Steps';

      // Render Sub-Views
      renderIncidentSelector();
      populateCounterfactualDropdowns();
      renderAnalysesHistory(analyses);

      // Load First Incident by default
      if (state.incidents.length > 0) {
        await loadIncident(state.incidents[0].id);
      }

    } catch (err) {
      console.error('Initialization error:', err);
      CyberUI.showToast('Could not load forensic incident records.', 'danger');
    }
  }

  // ==========================================================================
  // Render Incident Selector Cards
  // ==========================================================================
  function renderIncidentSelector() {
    if (!el.incidentsContainer) return;
    el.incidentsContainer.innerHTML = '';

    state.incidents.forEach((inc, idx) => {
      const card = document.createElement('div');
      card.className = `incident-card ${idx === 0 ? 'active' : ''}`;
      card.id = `incident-card-${inc.id}`;
      card.onclick = () => loadIncident(inc.id);

      let sevBadge = 'badge-malicious';
      if (inc.severity === 'HIGH') sevBadge = 'badge-warning';

      card.innerHTML = `
        <div class="d-flex justify-content-between align-items-center mb-1">
          <span class="badge ${sevBadge} font-mono">${inc.incidentCode}</span>
          <span class="text-dim font-mono" style="font-size: 0.75rem;">${inc.dwellTimeMinutes} min dwell</span>
        </div>
        <strong class="text-white d-block mb-1" style="font-size: 0.88rem;">${inc.title}</strong>
        <p class="text-muted mb-2" style="font-size: 0.78rem; line-height: 1.3;">${inc.summary}</p>
        <div class="d-flex justify-content-between align-items-center font-mono" style="font-size: 0.72rem;">
          <span class="text-dim">Vector: <span class="text-cyan">${inc.attackVector.split('->')[0].trim()}</span></span>
          <span class="text-safe fw-bold">${inc.totalEvents || 6} Steps</span>
        </div>
      `;
      el.incidentsContainer.appendChild(card);
    });
  }

  async function loadIncident(incidentId) {
    pausePlayback();
    document.querySelectorAll('.incident-card').forEach(c => c.classList.remove('active'));
    const target = document.getElementById(`incident-card-${incidentId}`);
    if (target) target.classList.add('active');

    try {
      const res = await CyberApiService.getSecurityIncidentDetails(incidentId);
      if (!res.success || !res.incident) throw new Error('Incident not found');

      state.currentIncident = res.incident;
      state.currentStep = 1;

      // Update Header
      if (el.currentIncidentTitle) el.currentIncidentTitle.textContent = res.incident.title;
      if (el.currentIncidentCode) el.currentIncidentCode.textContent = res.incident.incidentCode;
      if (el.currentIncidentMeta) {
        el.currentIncidentMeta.textContent = `Actor: ${res.incident.threatActor} • Target: ${res.incident.targetSystem} • Dwell Time: ${res.incident.dwellTimeMinutes} min`;
      }
      if (el.badgeCurrentOutcome) {
        el.badgeCurrentOutcome.textContent = res.incident.originalOutcome.toUpperCase();
      }

      // Render Kill Chain Stepper
      renderKillChainStepper(res.incident.timelineEvents || []);

      // Configure Scrubber
      const totalSteps = (res.incident.timelineEvents || []).length;
      if (el.replayScrubber) {
        el.replayScrubber.min = 1;
        el.replayScrubber.max = totalSteps;
        el.replayScrubber.value = 1;
      }

      // Render Step 1
      renderStepInspector(1);

    } catch (err) {
      console.error('Failed to load incident details:', err);
      CyberUI.showToast(`Error: ${err.message}`, 'danger');
    }
  }

  // ==========================================================================
  // Kill-Chain Stepper & Inspector
  // ==========================================================================
  function renderKillChainStepper(events) {
    if (!el.killchainStepper) return;
    el.killchainStepper.innerHTML = '';

    events.forEach(ev => {
      const stepItem = document.createElement('div');
      stepItem.className = `killchain-step ${ev.step === state.currentStep ? 'active' : ''}`;
      stepItem.id = `kc-step-${ev.step}`;
      stepItem.onclick = () => jumpToStep(ev.step);

      stepItem.innerHTML = `
        <div class="killchain-step-node">${ev.step}</div>
        <div class="killchain-step-label text-truncate">${ev.killChainPhase.split(' ')[0]}</div>
      `;
      el.killchainStepper.appendChild(stepItem);
    });
  }

  function renderStepInspector(stepNum) {
    if (!state.currentIncident || !state.currentIncident.timelineEvents) return;
    const events = state.currentIncident.timelineEvents;
    const ev = events.find(e => e.step === stepNum) || events[0];
    if (!ev) return;

    state.currentStep = stepNum;

    // Update Stepper active classes
    document.querySelectorAll('.killchain-step').forEach((el, idx) => {
      el.classList.remove('active', 'completed');
      if (idx + 1 < stepNum) el.classList.add('completed');
      if (idx + 1 === stepNum) el.classList.add('active');
    });

    // Update Scrubber
    if (el.replayScrubber) el.replayScrubber.value = stepNum;
    if (el.labelStepIndicator) el.labelStepIndicator.textContent = `Step ${stepNum} of ${events.length}`;

    // Update Inspector Fields
    if (el.inspectorStepBadge) el.inspectorStepBadge.textContent = `STEP ${stepNum}`;
    if (el.inspectorPhaseBadge) el.inspectorPhaseBadge.textContent = ev.killChainPhase.toUpperCase();
    
    // Format timestamp offset (+02m:30s)
    const mins = Math.floor(ev.offsetSec / 60);
    const secs = ev.offsetSec % 60;
    const timeStr = `+${String(mins).padStart(2, '0')}m:${String(secs).padStart(2, '0')}s elapsed`;
    if (el.inspectorTimestamp) el.inspectorTimestamp.textContent = timeStr;

    // Original Action
    if (el.inspectorOriginalAction) {
      if (ev.originalAction === 'BLOCKED') {
        el.inspectorOriginalAction.className = 'badge badge-malicious font-mono';
        el.inspectorOriginalAction.textContent = `BLOCKED (${ev.originalVerdict})`;
      } else {
        el.inspectorOriginalAction.className = 'badge badge-safe font-mono';
        el.inspectorOriginalAction.textContent = `ALLOWED (${ev.originalVerdict})`;
      }
    }

    if (el.inspectorDomain) el.inspectorDomain.textContent = ev.domain;
    if (el.inspectorQueryType) el.inspectorQueryType.textContent = ev.queryType || 'A';
    if (el.inspectorClientIp) el.inspectorClientIp.textContent = ev.clientIp || '192.168.1.115';
    if (el.inspectorThreatDetails) el.inspectorThreatDetails.textContent = ev.threatDetails || 'No threat signature mapped.';
    if (el.inspectorHistoricalImpact) el.inspectorHistoricalImpact.textContent = ev.historicalImpact || 'Threat proceeded unhindered.';
  }

  function jumpToStep(stepNum) {
    pausePlayback();
    renderStepInspector(stepNum);
  }

  // ==========================================================================
  // Playback Engine
  // ==========================================================================
  if (el.btnPlayPause) {
    el.btnPlayPause.addEventListener('click', () => {
      if (state.isPlaying) {
        pausePlayback();
      } else {
        startPlayback();
      }
    });
  }

  function startPlayback() {
    if (!state.currentIncident) return;
    const totalSteps = state.currentIncident.timelineEvents.length;
    if (state.currentStep >= totalSteps) {
      state.currentStep = 0; // restart
    }

    state.isPlaying = true;
    el.btnPlayPause.innerHTML = '<i class="fa-solid fa-pause me-1"></i> Pause';
    el.btnPlayPause.classList.replace('btn-cyan', 'btn-outline-warning');

    const intervalMs = 2000 / state.playbackSpeed;
    state.playInterval = setInterval(() => {
      if (state.currentStep < totalSteps) {
        renderStepInspector(state.currentStep + 1);
      } else {
        pausePlayback();
      }
    }, intervalMs);
  }

  function pausePlayback() {
    state.isPlaying = false;
    if (state.playInterval) clearInterval(state.playInterval);
    if (el.btnPlayPause) {
      el.btnPlayPause.innerHTML = '<i class="fa-solid fa-play me-1"></i> Play';
      el.btnPlayPause.classList.replace('btn-outline-warning', 'btn-cyan');
    }
  }

  if (el.btnNextStep) {
    el.btnNextStep.addEventListener('click', () => {
      pausePlayback();
      const total = state.currentIncident ? state.currentIncident.timelineEvents.length : 6;
      if (state.currentStep < total) renderStepInspector(state.currentStep + 1);
    });
  }

  if (el.btnPrevStep) {
    el.btnPrevStep.addEventListener('click', () => {
      pausePlayback();
      if (state.currentStep > 1) renderStepInspector(state.currentStep - 1);
    });
  }

  if (el.btnResetReplay) {
    el.btnResetReplay.addEventListener('click', () => {
      pausePlayback();
      renderStepInspector(1);
    });
  }

  if (el.replayScrubber) {
    el.replayScrubber.addEventListener('input', (e) => {
      pausePlayback();
      renderStepInspector(parseInt(e.target.value));
    });
  }

  if (el.replaySpeedGroup) {
    el.replaySpeedGroup.addEventListener('click', (e) => {
      if (e.target.tagName === 'BUTTON') {
        el.replaySpeedGroup.querySelectorAll('button').forEach(b => b.classList.remove('active'));
        e.target.classList.add('active');
        state.playbackSpeed = parseInt(e.target.getAttribute('data-speed'));
        if (state.isPlaying) {
          pausePlayback();
          startPlayback();
        }
      }
    });
  }

  if (el.btnSwitchToCounterfactual) {
    el.btnSwitchToCounterfactual.addEventListener('click', () => {
      const cfTabBtn = document.getElementById('tab-counterfactual-btn');
      if (cfTabBtn) new bootstrap.Tab(cfTabBtn).show();
    });
  }

  // ==========================================================================
  // Counterfactual "What-If" Analysis Engine
  // ==========================================================================
  function populateCounterfactualDropdowns() {
    if (!el.selectCfIncident || !el.selectCfPolicy) return;
    el.selectCfIncident.innerHTML = '';
    el.selectCfPolicy.innerHTML = '';

    state.incidents.forEach(inc => {
      const opt = document.createElement('option');
      opt.value = inc.id;
      opt.textContent = `${inc.incidentCode} - ${inc.title}`;
      el.selectCfIncident.appendChild(opt);
    });

    state.policies.forEach((pol, idx) => {
      const opt = document.createElement('option');
      opt.value = pol.id;
      opt.textContent = `${pol.isBaseline ? '[BASELINE] ' : ''}${pol.name} (Entropy: ${pol.entropyThreshold})`;
      if (idx === 1 || (idx === 0 && state.policies.length === 1)) opt.selected = true;
      el.selectCfPolicy.appendChild(opt);
    });
  }

  if (el.btnExecuteCounterfactual) {
    el.btnExecuteCounterfactual.addEventListener('click', async () => {
      const incidentId = parseInt(el.selectCfIncident.value);
      const policyId = parseInt(el.selectCfPolicy.value);

      if (!incidentId || !policyId) {
        CyberUI.showToast('Please select both an incident and a policy.', 'warning');
        return;
      }

      el.btnExecuteCounterfactual.disabled = true;
      el.btnExecuteCounterfactual.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-1"></i> Simulating...';

      try {
        const res = await CyberApiService.runCounterfactualAnalysis(incidentId, policyId);
        if (!res.success) throw new Error(res.message || 'Counterfactual analysis failed.');

        state.currentAnalysis = res;
        renderCounterfactualResults(res);
        renderForensicGaps(res.recommendations || []);

        CyberUI.showToast(`Analysis complete: ${res.metrics.verdict.replace(/_/g, ' ')}!`, 'success');

        // Refresh History
        CyberApiService.getCounterfactualAnalyses(20).then(r => renderAnalysesHistory(r.analyses || []));

      } catch (err) {
        console.error('Counterfactual error:', err);
        CyberUI.showToast(`Error: ${err.message}`, 'danger');
      } finally {
        el.btnExecuteCounterfactual.disabled = false;
        el.btnExecuteCounterfactual.innerHTML = '<i class="fa-solid fa-bolt me-1"></i> Run Analysis';
      }
    });
  }

  function renderCounterfactualResults(data) {
    const m = data.metrics;

    // Update KPI Cards
    if (el.cfMetricDwellPct) el.cfMetricDwellPct.textContent = `-${m.dwellTimeReductionPct.toFixed(1)}%`;
    if (el.cfMetricTimeSaved) el.cfMetricTimeSaved.textContent = `${m.timeSavedMinutes.toFixed(1)} min saved`;
    if (el.cfMetricStepDelta) el.cfMetricStepDelta.textContent = `Step ${m.counterfactualContainmentStep} vs ${m.originalContainmentStep}`;
    if (el.cfMetricStepsAccelerated) el.cfMetricStepsAccelerated.textContent = `+${m.stepsAccelerated} Steps earlier`;
    if (el.cfMetricDamageScore) el.cfMetricDamageScore.textContent = `${m.damageMitigationScore.toFixed(0)}%`;
    if (el.cfMetricVerdict) el.cfMetricVerdict.textContent = m.verdict.replace(/_/g, ' ');

    // Render Side-by-Side Table
    if (!el.cfComparisonTableBody) return;
    el.cfComparisonTableBody.innerHTML = '';

    (data.stepComparisons || []).forEach(step => {
      const tr = document.createElement('tr');

      // Status pill
      let statusBadge = 'badge-info';
      let statusText = step.stepStatus.replace(/_/g, ' ');
      if (step.stepStatus === 'PREVENTED_BY_POLICY') {
        statusBadge = 'badge-prevented';
        statusText = 'PREVENTED BY POLICY';
      } else if (step.stepStatus === 'REDUNDANT_BLOCKED') {
        statusBadge = 'badge-safe';
        statusText = 'REDUNDANT BLOCKED';
      } else if (step.stepStatus === 'MISSED_BY_BOTH') {
        statusBadge = 'badge-missed';
        statusText = 'MISSED BY BOTH';
      }

      const origActionBadge = step.original.action === 'BLOCKED' ? 'badge-malicious' : 'badge-safe';
      const cfActionBadge = step.counterfactual.action === 'BLOCKED' ? 'badge-malicious' : 'badge-safe';

      tr.innerHTML = `
        <td class="font-mono text-cyan fw-bold">Step ${step.step}</td>
        <td class="font-mono text-dim" style="font-size: 0.78rem;">+${Math.floor(step.offsetSec / 60)}m:${String(step.offsetSec % 60).padStart(2, '0')}s</td>
        <td><span class="badge badge-info font-mono" style="font-size: 0.7rem;">${step.killChainPhase}</span></td>
        <td class="font-mono text-white fw-bold text-break" style="max-width: 220px;">${step.domain}</td>
        <td><span class="badge ${origActionBadge}">${step.original.action}</span> <span class="text-dim font-mono" style="font-size: 0.75rem;">(${step.original.verdict})</span></td>
        <td><span class="badge ${cfActionBadge}">${step.counterfactual.action}</span> <span class="text-dim font-mono" style="font-size: 0.75rem;">(${step.counterfactual.verdict})</span></td>
        <td><span class="${statusBadge}">${statusText}</span></td>
      `;
      el.cfComparisonTableBody.appendChild(tr);
    });
  }

  // ==========================================================================
  // Render Forensic Gaps & AI Remediation
  // ==========================================================================
  function renderForensicGaps(recommendations) {
    if (!el.forensicGapsContainer) return;
    el.forensicGapsContainer.innerHTML = '';

    if (!recommendations || recommendations.length === 0) {
      el.forensicGapsContainer.innerHTML = '<div class="alert alert-cyber alert-success">No critical blind spots diagnosed.</div>';
      return;
    }

    recommendations.forEach(rec => {
      const card = document.createElement('div');
      let typeClass = 'rec-info';
      let sevBadge = 'badge-info';
      if (rec.severity === 'CRITICAL_FIX') { typeClass = 'rec-critical'; sevBadge = 'badge-malicious'; }
      if (rec.severity === 'HIGH') { typeClass = 'rec-high'; sevBadge = 'badge-warning'; }

      card.className = `recommendation-card ${typeClass}`;
      card.innerHTML = `
        <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-2">
          <div class="d-flex align-items-center gap-2">
            <span class="badge ${sevBadge} font-mono">${rec.severity}</span>
            <strong class="text-white" style="font-size: 0.92rem;">${rec.title}</strong>
          </div>
          <span class="text-cyan font-mono" style="font-size: 0.78rem;">${rec.impact || ''}</span>
        </div>
        <p class="text-muted mb-2" style="font-size: 0.83rem;">${rec.finding}</p>
        <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 pt-2 border-top border-secondary-subtle">
          <div class="text-dim font-mono" style="font-size: 0.78rem;">
            <i class="fa-solid fa-lightbulb text-warning me-1"></i> ${rec.actionableStep}
          </div>
          <a href="digital-twin.html" class="btn btn-outline-cyan btn-sm">
            <i class="fa-solid fa-sliders me-1"></i> Tune in Policy Studio
          </a>
        </div>
      `;
      el.forensicGapsContainer.appendChild(card);
    });
  }

  // ==========================================================================
  // Analyses History & Reports Tab
  // ==========================================================================
  function renderAnalysesHistory(analyses) {
    if (!el.analysesHistoryTableBody) return;
    el.analysesHistoryTableBody.innerHTML = '';

    if (!analyses || analyses.length === 0) {
      el.analysesHistoryTableBody.innerHTML = '<tr><td colspan="9" class="text-center py-4 text-muted">No counterfactual analyses recorded yet.</td></tr>';
      return;
    }

    analyses.forEach(a => {
      const tr = document.createElement('tr');
      const m = a.metrics || {};
      tr.innerHTML = `
        <td class="font-mono text-cyan fw-bold">${a.analysisUuid}</td>
        <td><strong>${a.incidentId ? `INC-${a.incidentId}` : 'Target Incident'}</strong></td>
        <td>${a.policyName}</td>
        <td class="font-mono text-safe">+${m.stepsAccelerated || 0} Steps</td>
        <td class="font-mono">${m.timeSavedMinutes || 0} min</td>
        <td class="font-mono text-safe fw-bold">${m.dwellTimeReductionPct ? m.dwellTimeReductionPct.toFixed(1) : '0.0'}%</td>
        <td><span class="badge ${m.breachPrevented ? 'badge-safe' : 'badge-warning'} font-mono">${m.verdict ? m.verdict.replace(/_/g, ' ') : '--'}</span></td>
        <td class="font-mono text-dim" style="font-size: 0.75rem;">${a.createdAt}</td>
        <td>
          <button class="btn btn-outline-cyan btn-sm btn-export-cfa" data-cfa-id="${a.id}">
            <i class="fa-solid fa-download me-1"></i> Export
          </button>
        </td>
      `;
      el.analysesHistoryTableBody.appendChild(tr);
    });

    // Wire up export buttons
    document.querySelectorAll('.btn-export-cfa').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const cid = e.currentTarget.getAttribute('data-cfa-id');
        try {
          const res = await CyberApiService.exportForensicReport(cid);
          if (res.success && res.report) {
            downloadJson(res.report, `aegis-forensic-report-${res.report.analysisUuid || cid}.json`);
          }
        } catch (err) {
          CyberUI.showToast(`Export error: ${err.message}`, 'danger');
        }
      });
    });
  }

  if (el.btnRefreshAnalyses) {
    el.btnRefreshAnalyses.addEventListener('click', async () => {
      const res = await CyberApiService.getCounterfactualAnalyses(20);
      renderAnalysesHistory(res.analyses || []);
      CyberUI.showToast('Refreshed forensic analysis history.', 'info');
    });
  }

  if (el.btnQuickExportForensic) {
    el.btnQuickExportForensic.addEventListener('click', () => {
      if (state.currentAnalysis) {
        downloadJson(state.currentAnalysis, `aegis-forensics-${state.currentAnalysis.analysisUuid || 'report'}.json`);
      } else {
        CyberUI.showToast('Run a counterfactual analysis to export the report.', 'info');
      }
    });
  }

  function downloadJson(data, filename) {
    const jsonStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
    const a = document.createElement('a');
    a.setAttribute("href", jsonStr);
    a.setAttribute("download", filename);
    document.body.appendChild(a);
    a.click();
    a.remove();
    CyberUI.showToast('Exported forensic security report.', 'success');
  }

  // Kick off
  init();
});

