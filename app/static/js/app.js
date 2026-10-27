// RoutePulse SOC Core Application Controller

let subnetCalcInstance = null;
let timelineChartInstance = null;
let liveStreamTimer = null;
let isStreamPaused = false;

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initSubnetCalc();
  initTimelineChart();
  initIPAssessment();
  initSimulator();
  initLogUpload();
  initMembershipChecker();
  startLiveTelemetryLoop();
});

// -------------------------------------------------------------
// Tabs Navigation
// -------------------------------------------------------------
function initTabs() {
  const tabs = document.querySelectorAll('.tab-btn');
  tabs.forEach(btn => {
    btn.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      
      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      const target = document.getElementById(targetId);
      if (target) {
        target.classList.add('active');
        if (targetId === 'tab-overview' && timelineChartInstance) {
          timelineChartInstance.resize();
        }
      }
    });
  });
}

function switchTab(tabId) {
  const btn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
  if (btn) btn.click();
}

// -------------------------------------------------------------
// Subnet NetCalc Pro Setup
// -------------------------------------------------------------
function initSubnetCalc() {
  subnetCalcInstance = new SubnetCalculator();
}

function initTimelineChart() {
  timelineChartInstance = new ThreatTimelineChart('threatTimelineCanvas');
}

// -------------------------------------------------------------
// Real-time Telemetry Poller & Generator
// -------------------------------------------------------------
function startLiveTelemetryLoop() {
  pollMetrics();
  pollEvents();
  pollAlerts();
  pollBlockedIPs();

  // Polling intervals
  setInterval(() => {
    if (!isStreamPaused) {
      triggerSimulatedEvent();
    }
  }, 2200);

  setInterval(() => {
    pollMetrics();
    pollAlerts();
    pollBlockedIPs();
  }, 4000);
}

async function triggerSimulatedEvent() {
  try {
    const res = await fetch('/api/v1/traffic/generate', { method: 'POST' });
    const data = await res.json();
    if (data.status === 'success') {
      appendEventRow(data.event);
      if (data.event.triggered_alert) {
        showToast(`🚨 Threat Alert: ${data.event.triggered_alert.rule_name} from ${data.event.src_ip}`);
        pollAlerts();
        if (timelineChartInstance) timelineChartInstance.pushPoint(true, false);
      } else {
        if (timelineChartInstance) timelineChartInstance.pushPoint(false, false);
      }
    }
  } catch (err) {
    console.error("Telemetry stream err:", err);
  }
}

async function pollMetrics() {
  try {
    const res = await fetch('/api/v1/traffic/metrics');
    const data = await res.json();
    if (data.status === 'success') {
      const m = data.metrics;
      setText('kpiTotalScans', m.total_scans);
      setText('kpiEvents24h', (m.events_24h / 1000).toFixed(1) + 'K');
      setText('kpiThreatIPs', m.threat_ips);
      setText('kpiFeedMatches', (m.feed_matches / 1000).toFixed(1) + 'K');
      setText('kpiLoadedIndicators', m.loaded_indicators.toLocaleString());
      setText('kpiFeedsOk', m.feeds_ok);
      setText('kpiTuningRules', m.tuning_rules);
      setText('kpiHostsScored', (m.hosts_scored / 1000).toFixed(1) + 'K');

      // Hero banner threat gauge
      const gaugeValEl = document.getElementById('heroGaugeVal');
      const gaugeFillEl = document.getElementById('heroGaugeFill');
      if (gaugeValEl) gaugeValEl.textContent = m.threat_gauge;
      if (gaugeFillEl) gaugeFillEl.style.width = `${m.threat_gauge_percent}%`;

      // Update alert badge count
      const alertCount = (m.detection_stats.total_alerts || 0);
      const tabBadge = document.getElementById('alertsTabBadge');
      if (tabBadge) tabBadge.textContent = alertCount;
    }
  } catch (e) {
    console.error("Metrics poll err:", e);
  }
}

async function pollEvents() {
  try {
    const res = await fetch('/api/v1/traffic/events?limit=25');
    const data = await res.json();
    if (data.status === 'success') {
      const tbody = document.getElementById('liveTrafficTbody');
      if (tbody) {
        tbody.innerHTML = '';
        data.events.forEach(evt => appendEventRow(evt, false));
      }
    }
  } catch (e) {
    console.error("Events poll err:", e);
  }
}

function appendEventRow(evt, prepend = true) {
  const tbody = document.getElementById('liveTrafficTbody');
  if (!tbody) return;

  const tr = document.createElement('tr');
  const sc = evt.status_code;
  let badgeClass = 'badge-2xx';
  if (sc >= 500) badgeClass = 'badge-5xx';
  else if (sc >= 400) badgeClass = 'badge-4xx';
  else if (sc >= 300) badgeClass = 'badge-3xx';

  tr.innerHTML = `
    <td>${evt.time_str}</td>
    <td>
      <a href="javascript:void(0)" onclick="quickAssessIP('${evt.src_ip}')" style="color: #38bdf8; text-decoration: none; font-weight: 700;">
        ${evt.src_ip}
      </a>
    </td>
    <td>${evt.dst_port}</td>
    <td>${evt.protocol}</td>
    <td><span style="color: #94a3b8; font-weight: 600;">${evt.method}</span> <span style="color: #cbd5e1;">${evt.path}</span></td>
    <td><span class="badge ${badgeClass}">${sc}</span></td>
    <td>${evt.bytes_transferred} B</td>
    <td>
      ${evt.status_action === 'BLOCKED_BY_FIREWALL' ? 
        '<span class="badge badge-crit">FIREWALL DROP</span>' : 
        (evt.triggered_alert ? '<span class="badge badge-high">ALERTED</span>' : '<span class="badge badge-2xx">PERMITTED</span>')}
    </td>
    <td>
      <button class="btn btn-secondary btn-sm" onclick="quickAssessIP('${evt.src_ip}')">Inspect</button>
      <button class="btn btn-danger btn-sm" onclick="promptBlockIP('${evt.src_ip}')">Block</button>
    </td>
  `;

  if (prepend && tbody.firstChild) {
    tbody.insertBefore(tr, tbody.firstChild);
    if (tbody.children.length > 50) tbody.removeChild(tbody.lastChild);
  } else {
    tbody.appendChild(tr);
  }
}

async function pollAlerts() {
  try {
    const res = await fetch('/api/v1/alerts');
    const data = await res.json();
    if (data.status === 'success') {
      renderAlertsTable(data.alerts);
    }
  } catch (e) {
    console.error("Alerts poll err:", e);
  }
}

function renderAlertsTable(alerts) {
  const tbody = document.getElementById('alertsTableBody');
  if (!tbody) return;

  if (alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 2rem;">No active alerts. All intrusion detection rules operational.</td></tr>`;
    return;
  }

  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td><span style="font-family: var(--font-mono); font-weight: 700; color: #cbd5e1;">${a.id}</span></td>
      <td>
        <span class="badge ${a.severity === 'CRITICAL' ? 'badge-crit' : 'badge-high'}">${a.severity}</span>
      </td>
      <td>
        <div style="font-weight: 700; color: #fff;">${a.rule_name}</div>
        <div style="font-size: 0.72rem; color: #64748b;">${a.category} &bull; ${a.rule_id}</div>
      </td>
      <td>
        <a href="javascript:void(0)" onclick="quickAssessIP('${a.src_ip}')" style="color: #38bdf8; font-family: var(--font-mono); font-weight: 700;">
          ${a.src_ip}
        </a>
      </td>
      <td style="color: #cbd5e1; font-size: 0.8rem; max-width: 320px;">
        ${a.details}
        <div style="font-size: 0.72rem; color: #f59e0b; margin-top: 0.2rem;">Rec: ${a.recommended_action}</div>
      </td>
      <td>${a.timestamp}</td>
      <td style="display: flex; gap: 0.35rem; flex-wrap: wrap;">
        <button class="btn btn-primary btn-sm" onclick="openIncidentWorkbench('${a.id}')">Investigate</button>
        <button class="btn btn-danger btn-sm" onclick="blockIPFromAlert('${a.src_ip}', '${a.rule_name}')">Block</button>
        <button class="btn btn-secondary btn-sm" onclick="dismissAlert('${a.id}')">Dismiss</button>
      </td>
    </tr>
  `).join('');
}

async function openIncidentWorkbench(alertId) {
  try {
    const res = await fetch(`/api/v1/alerts/investigate?alert_id=${alertId}`);
    const data = await res.json();
    if (data.status === 'success') {
      renderIncidentModal(data.investigation);
    }
  } catch (e) {
    showToast(`Failed to open investigation: ${e}`);
  }
}

function renderIncidentModal(inv) {
  const existing = document.getElementById('incidentModal');
  if (existing) existing.remove();

  const isCompromised = inv.attempt_succeeded;
  const statusColor = isCompromised ? '#ef4444' : '#10b981';

  const modal = document.createElement('div');
  modal.id = 'incidentModal';
  modal.style.position = 'fixed';
  modal.style.top = '0';
  modal.style.left = '0';
  modal.style.width = '100vw';
  modal.style.height = '100vh';
  modal.style.background = 'rgba(0, 0, 0, 0.75)';
  modal.style.backdropFilter = 'blur(8px)';
  modal.style.zIndex = '999';
  modal.style.display = 'flex';
  modal.style.alignItems = 'center';
  modal.style.justifyContent = 'center';
  modal.style.padding = '1.5rem';

  modal.innerHTML = `
    <div style="background: #0f172a; border: 1px solid ${statusColor}; border-radius: 14px; max-width: 800px; width: 100%; max-height: 90vh; overflow-y: auto; padding: 1.75rem; box-shadow: 0 10px 40px rgba(0,0,0,0.8);">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.25rem;">
        <div>
          <div style="font-size: 0.75rem; color: #38bdf8; text-transform: uppercase; font-weight: 700;">Log360 Incident Triage Workbench (Slide 9 Flowchart)</div>
          <h2 style="font-size: 1.4rem; color: #fff; margin-top: 0.25rem;">${inv.alert.rule_name} &bull; ${inv.src_ip}</h2>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="document.getElementById('incidentModal').remove()">&times; Close</button>
      </div>

      <!-- Triage Question Card -->
      <div style="background: rgba(0,0,0,0.4); border: 2px dashed ${statusColor}; border-radius: 10px; padding: 1.25rem; margin-bottom: 1.25rem; text-align: center;">
        <div style="font-size: 0.8rem; text-transform: uppercase; color: #94a3b8; font-weight: 700;">Key Triage Question (Slide 9):</div>
        <div style="font-size: 1.2rem; font-weight: 800; color: #fff; margin: 0.4rem 0;">"${inv.key_triage_question}"</div>
        <div style="display: inline-block; padding: 0.35rem 1rem; border-radius: 20px; background: rgba(0,0,0,0.5); border: 1px solid ${statusColor}; color: ${statusColor}; font-weight: 800; font-family: var(--font-mono); margin-top: 0.4rem;">
          ${inv.triage_verdict}
        </div>
      </div>

      <!-- Investigation Details & Remediation Steps -->
      <div style="display: grid; grid-template-columns: 1fr; gap: 1rem; margin-bottom: 1.5rem;">
        <div style="background: rgba(30, 41, 59, 0.5); border-radius: 8px; padding: 1rem;">
          <div style="font-weight: 700; color: #38bdf8; font-size: 0.85rem; margin-bottom: 0.5rem;">Prescribed Remediation & Reporting Actions:</div>
          <ul style="list-style: none; padding: 0; font-size: 0.825rem; color: #cbd5e1; display: flex; flex-direction: column; gap: 0.4rem;">
            ${inv.remediation_steps.map(s => `<li style="padding-left: 0.5rem; border-left: 3px solid ${statusColor};">${s}</li>`).join('')}
          </ul>
        </div>
      </div>

      <!-- Modal Footer Action Buttons -->
      <div style="display: flex; justify-content: flex-end; gap: 0.75rem; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 1rem;">
        <button class="btn btn-secondary btn-sm" onclick="quickAssessIP('${inv.src_ip}'); document.getElementById('incidentModal').remove();">Deep IP Lookup</button>
        <button class="btn btn-danger btn-sm" onclick="blockIP('${inv.src_ip}', 'Triage Verdict: ${inv.triage_verdict}'); document.getElementById('incidentModal').remove();">Block IP at Perimeter</button>
        <button class="btn btn-primary btn-sm" onclick="sendTestWebhook('${inv.alert.id}');">Dispatch SOAR Webhook</button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);
}

async function sendTestWebhook(alertId) {
  try {
    const res = await fetch('/api/v1/webhooks/test-dispatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_id: alertId })
    });
    const d = await res.json();
    showToast(`SOAR Webhook Triggered: ${d.message}`);
  } catch (e) {
    showToast(`Webhook error: ${e}`);
  }
}

async function dismissAlert(alertId) {
  const formData = new FormData();
  formData.append('alert_id', alertId);
  await fetch('/api/v1/alerts/dismiss', { method: 'POST', body: formData });
  showToast(`Alert ${alertId} dismissed`);
  pollAlerts();
}

async function pollBlockedIPs() {
  try {
    const res = await fetch('/api/v1/firewall/blocked');
    const data = await res.json();
    if (data.status === 'success') {
      renderBlockedTable(data.blocked_ips);
      setText('kpiBlockedHosts', data.count);
    }
  } catch (e) {
    console.error("Blocked IPs err:", e);
  }
}

function renderBlockedTable(list) {
  const tbody = document.getElementById('blockedTableBody');
  if (!tbody) return;

  if (list.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: #64748b; padding: 2rem;">No active blocked IPs. Perimeter filter clean.</td></tr>`;
    return;
  }

  tbody.innerHTML = list.map(b => `
    <tr>
      <td style="font-family: var(--font-mono); font-weight: 700; color: #ef4444;">${b.ip}</td>
      <td style="color: #cbd5e1;">${b.reason}</td>
      <td><span class="badge badge-crit">${b.action}</span></td>
      <td>${b.blocked_at}</td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="unblockIP('${b.ip}')">Unblock / Restore</button>
      </td>
    </tr>
  `).join('');
}

async function blockIP(ip, reason) {
  const res = await fetch('/api/v1/firewall/block', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, reason, analyst: "SOC Lead Analyst" })
  });
  const data = await res.json();
  if (data.status === 'success') {
    showToast(`IP ${ip} blocked at firewall perimeter`);
    pollBlockedIPs();
  }
}

async function unblockIP(ip) {
  const res = await fetch('/api/v1/firewall/unblock', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip })
  });
  const data = await res.json();
  if (data.status === 'success') {
    showToast(`IP ${ip} unblocked`);
    pollBlockedIPs();
  }
}

function promptBlockIP(ip) {
  const reason = prompt(`Enter reason for blocking ${ip}:`, "Suspicious inbound anomalous behavior detected");
  if (reason) {
    blockIP(ip, reason);
  }
}

function blockIPFromAlert(ip, ruleName) {
  blockIP(ip, `Triggered ${ruleName}`);
}

// -------------------------------------------------------------
// IP Threat Assessment & Intelligence Module (Slide 6)
// -------------------------------------------------------------
function initIPAssessment() {
  const form = document.getElementById('ipLookupForm');
  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const ip = document.getElementById('targetIpInput').value.trim();
      if (ip) assessTargetIP(ip);
    });
  }
}

function quickAssessIP(ip) {
  switchTab('tab-intelligence');
  const input = document.getElementById('targetIpInput');
  if (input) input.value = ip;
  assessTargetIP(ip);
}

async function assessTargetIP(ip) {
  const card = document.getElementById('threatProfileCard');
  if (!card) return;

  card.style.display = 'block';
  card.innerHTML = `<div style="text-align: center; padding: 2rem; color: #38bdf8;">Querying Threat Intelligence feeds, ASN registries & Tor relay status for ${ip}...</div>`;

  try {
    const res = await fetch(`/api/v1/ip/assess?ip=${encodeURIComponent(ip)}`);
    const json = await res.json();
    if (json.status === 'success') {
      renderThreatProfile(json.data);
    } else {
      card.innerHTML = `<div style="color: #ef4444; padding: 1.5rem;">Error: ${json.detail || 'Unable to assess IP'}</div>`;
    }
  } catch (e) {
    card.innerHTML = `<div style="color: #ef4444; padding: 1.5rem;">Failed to fetch intelligence: ${e}</div>`;
  }
}

function renderThreatProfile(d) {
  const card = document.getElementById('threatProfileCard');
  if (!card) return;

  if (!d.valid) {
    card.innerHTML = `<div style="color: #ef4444; padding: 1.5rem;">${d.error}</div>`;
    return;
  }

  const score = d.risk_score;
  let circleClass = 'clean';
  let badgeSeverity = 'badge-2xx';
  if (score >= 80) { circleClass = ''; badgeSeverity = 'badge-crit'; }
  else if (score >= 45) { circleClass = 'elevated'; badgeSeverity = 'badge-high'; }

  card.innerHTML = `
    <div class="profile-top">
      <div>
        <div style="display: flex; align-items: center; gap: 0.75rem;">
          <h3 style="font-size: 1.5rem; font-family: var(--font-mono); color: #fff;">${d.ip}</h3>
          <span class="badge ${badgeSeverity}">${d.risk_level}</span>
          <span class="badge" style="background: rgba(255,255,255,0.06); color: #cbd5e1;">${d.version}</span>
        </div>
        <div style="font-size: 0.85rem; color: #94a3b8; margin-top: 0.25rem;">
          ${d.classification} &bull; ${d.city}, ${d.region}, ${d.country} (${d.country_code})
        </div>
      </div>
      <div style="display: flex; align-items: center; gap: 1.5rem;">
        <div class="score-badge-circle ${circleClass}">
          <div class="score-num" style="color: ${score >= 80 ? '#ef4444' : (score >= 45 ? '#f59e0b' : '#10b981')}">${score}</div>
          <div class="score-sub">RISK / 100</div>
        </div>
        <div>
          <button class="btn btn-danger btn-sm" onclick="promptBlockIP('${d.ip}')">Block at Perimeter</button>
          <button class="btn btn-secondary btn-sm" onclick="sendToSubnetTool('${d.ip}')" style="margin-top: 0.4rem; display: block; width: 100%;">Inspect Subnet</button>
        </div>
      </div>
    </div>

    <!-- Telemetry & Threat Attributes (Slide 6 Replica) -->
    <div class="profile-grid">
      <div class="profile-item">
        <div class="profile-item-title">Autonomous System (ASN)</div>
        <div class="profile-item-val" style="color: #38bdf8;">${d.asn}</div>
        <div style="font-size: 0.72rem; color: #64748b; margin-top: 0.2rem;">${d.isp}</div>
      </div>
      <div class="profile-item">
        <div class="profile-item-title">Proxy / Tor / VPN Detected</div>
        <div class="profile-item-val" style="color: ${(d.is_tor || d.is_proxy || d.is_vpn) ? '#ef4444' : '#10b981'};">
          ${d.is_tor ? 'YES (Tor Exit Node)' : (d.is_proxy ? 'YES (Public Proxy)' : (d.is_vpn ? 'YES (VPN Pool)' : 'NO (Direct / Residential)'))}
        </div>
      </div>
      <div class="profile-item">
        <div class="profile-item-title">Data Center / Cloud Block</div>
        <div class="profile-item-val" style="color: ${d.is_datacenter ? '#f59e0b' : '#10b981'};">
          ${d.is_datacenter ? 'YES (Server Hosting)' : 'NO (End-user ISP)'}
        </div>
      </div>
      <div class="profile-item">
        <div class="profile-item-title">Reverse DNS (PTR) & RIR</div>
        <div class="profile-item-val" style="color: #38bdf8; font-size: 0.85rem; word-break: break-all;">${d.rdns || 'NXDOMAIN'}</div>
        <div style="font-size: 0.72rem; color: #64748b; margin-top: 0.2rem;">Registry: ${d.rir || 'IANA'}</div>
      </div>
      <div class="profile-item">
        <div class="profile-item-title">Threat Intelligence Flags</div>
        <div style="margin-top: 0.25rem;">
          ${d.threat_flags.length > 0 ? 
            d.threat_flags.map(f => `<span class="badge badge-high" style="margin-right: 0.3rem; margin-bottom: 0.3rem;">${f}</span>`).join('') :
            '<span class="badge badge-2xx">Clean / No Abuse Reports</span>'
          }
        </div>
      </div>
    </div>

    <!-- Slide 6 Session Steps Verification Timeline -->
    <div style="margin-top: 1.25rem; background: rgba(15, 23, 42, 0.8); border: 1px solid var(--border-color); border-radius: 8px; padding: 1.25rem;">
      <div style="font-size: 0.85rem; font-weight: 700; color: #38bdf8; margin-bottom: 0.75rem; display: flex; align-items: center; gap: 0.5rem;">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 11 12 14 22 4"></polyline><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path></svg>
        Session Verification & Identity Footprint Steps (Slide 6 Prototype)
      </div>
      <div style="display: flex; flex-direction: column; gap: 0.5rem;">
        ${(d.session_steps || []).map(s => {
          let badgeColor = '#10b981';
          if (s.status === 'REJECTED') badgeColor = '#ef4444';
          else if (s.status === 'WARNING') badgeColor = '#f59e0b';
          else if (s.status === 'INFO') badgeColor = '#38bdf8';
          return `
            <div style="display: flex; align-items: center; justify-content: space-between; font-size: 0.8rem; padding: 0.4rem 0.6rem; background: rgba(0,0,0,0.25); border-radius: 6px;">
              <span style="display: flex; align-items: center; gap: 0.6rem;">
                <span style="width: 8px; height: 8px; border-radius: 50%; background: ${badgeColor}; box-shadow: 0 0 6px ${badgeColor};"></span>
                <strong style="color: #fff;">${s.step}:</strong>
                <span style="color: #94a3b8;">${s.detail}</span>
              </span>
              <span class="badge" style="border: 1px solid ${badgeColor}; color: ${badgeColor};">${s.status}</span>
            </div>
          `;
        }).join('')}
      </div>
    </div>

    <!-- Risk Breakdown & Recommendation -->
    <div style="margin-top: 1.25rem; background: rgba(0,0,0,0.3); border: 1px solid var(--border-color); border-radius: 8px; padding: 1rem;">
      <div style="font-size: 0.8rem; font-weight: 700; color: #cbd5e1; margin-bottom: 0.5rem;">Analytical Risk Factor Breakdown:</div>
      ${d.risk_breakdown.map(rb => `
        <div style="display: flex; justify-content: space-between; font-size: 0.8rem; padding: 0.3rem 0; border-bottom: 1px solid rgba(255,255,255,0.03);">
          <span style="color: #94a3b8;">${rb.factor}: <span style="color: #64748b;">${rb.description}</span></span>
          <span style="font-family: var(--font-mono); font-weight: 700; color: #38bdf8;">+${rb.impact} pts</span>
        </div>
      `).join('')}
      <div style="margin-top: 0.85rem; font-size: 0.85rem; color: #f59e0b; background: rgba(245, 158, 11, 0.08); padding: 0.75rem; border-radius: 6px; border: 1px solid rgba(245, 158, 11, 0.2);">
        <strong>SOC Operational Recommendation:</strong> ${d.recommendation}
      </div>
    </div>
  `;
}

function sendToSubnetTool(ip) {
  switchTab('tab-subnet');
  if (subnetCalcInstance) {
    subnetCalcInstance.setIP(ip, 24);
  }
}

// -------------------------------------------------------------
// Attack Scenario Simulator (Slide 9 & 5)
// -------------------------------------------------------------
function initSimulator() {
  const btnBrute = document.getElementById('simBruteForceBtn');
  const btnScan = document.getElementById('simPortScanBtn');
  const btnBot = document.getElementById('simBadBotBtn');
  const btnToggle = document.getElementById('toggleStreamBtn');

  if (btnBrute) btnBrute.addEventListener('click', () => injectScenario('brute_force'));
  if (btnScan) btnScan.addEventListener('click', () => injectScenario('port_scan'));
  if (btnBot) btnBot.addEventListener('click', () => injectScenario('bad_bot'));

  if (btnToggle) {
    btnToggle.addEventListener('click', () => {
      isStreamPaused = !isStreamPaused;
      btnToggle.textContent = isStreamPaused ? 'Resume Traffic Stream' : 'Pause Traffic Stream';
      btnToggle.className = isStreamPaused ? 'btn btn-primary btn-sm' : 'btn btn-secondary btn-sm';
    });
  }
}

async function injectScenario(scenario) {
  showToast(`Injecting Scenario: ${scenario.replace('_', ' ').toUpperCase()} attack wave...`);
  for (let i = 0; i < 4; i++) {
    await fetch('/api/v1/traffic/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario })
    });
  }
  setTimeout(() => {
    pollEvents();
    pollAlerts();
    pollMetrics();
  }, 400);
}

// -------------------------------------------------------------
// Raw Log Normalization & File Upload (Layer 1 & 2)
// -------------------------------------------------------------
function initLogUpload() {
  const form = document.getElementById('logUploadForm');
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fileInput = document.getElementById('logFileInput');
      const textInput = document.getElementById('rawLogTextInput');
      const statusBox = document.getElementById('uploadStatusBox');

      const formData = new FormData();
      if (fileInput.files.length > 0) {
        formData.append('file', fileInput.files[0]);
      } else if (textInput.value.trim()) {
        formData.append('raw_log_text', textInput.value.trim());
      } else {
        alert("Please select a log file or paste log text.");
        return;
      }

      if (statusBox) statusBox.innerHTML = '<span style="color: #38bdf8;">Normalizing headers and parsing events...</span>';

      try {
        const res = await fetch('/api/v1/traffic/upload-logs', {
          method: 'POST',
          body: formData
        });
        const d = await res.json();
        if (d.status === 'success') {
          if (statusBox) statusBox.innerHTML = `<span style="color: #10b981;">Successfully ingested ${d.ingested_count} log events. Triggered ${d.alerts_triggered} threat alerts.</span>`;
          pollEvents();
          pollAlerts();
          pollMetrics();
        } else {
          if (statusBox) statusBox.innerHTML = `<span style="color: #ef4444;">Error: ${d.detail}</span>`;
        }
      } catch (err) {
        if (statusBox) statusBox.innerHTML = `<span style="color: #ef4444;">Upload error: ${err}</span>`;
      }
    });
  }
}

// -------------------------------------------------------------
// CIDR Subnet Membership Verification (Slide 7 & 8)
// -------------------------------------------------------------
function initMembershipChecker() {
  const form = document.getElementById('membershipForm');
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const ip = document.getElementById('memberCandidateIp').value.trim();
      const cidr = document.getElementById('memberTargetCidr').value.trim();
      const resBox = document.getElementById('membershipResultBox');
      if (!resBox) return;

      resBox.style.display = 'block';
      resBox.innerHTML = '<span style="color: #38bdf8;">Testing membership...</span>';

      try {
        const res = await fetch('/api/v1/subnet/check-member', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ candidate_ip: ip, network_cidr: cidr })
        });
        const data = await res.json();
        if (data.status === 'success') {
          const d = data.data;
          const isMember = d.is_member;
          const color = isMember ? '#10b981' : '#ef4444';
          resBox.innerHTML = `
            <div style="padding: 0.75rem; border-radius: 6px; background: rgba(0,0,0,0.4); border: 1px solid ${color};">
              <span style="font-weight: 700; color: ${color};">
                ${isMember ? 'VERIFIED MEMBER' : 'OUTSIDE SUBNET SCOPE'}
              </span>: 
              Host <code>${d.candidate_ip}</code> ${isMember ? 'resides inside' : 'does NOT belong to'} network <code>${d.network_cidr}</code>.
              ${isMember ? `<br><span style="color: #94a3b8;">Host Offset Index: <strong>#${d.host_index}</strong> of ${d.total_hosts} available addresses. Network: ${d.network_address}, Broadcast: ${d.broadcast_address}</span>` : ''}
            </div>
          `;
        } else {
          resBox.innerHTML = `<span style="color: #ef4444;">Error: ${data.detail}</span>`;
        }
      } catch (err) {
        resBox.innerHTML = `<span style="color: #ef4444;">Verification error: ${err}</span>`;
      }
    });
  }
}

// -------------------------------------------------------------
// SOAR Webhook Dispatcher (Slide 13 Phase 4)
// -------------------------------------------------------------
async function dispatchCustomWebhook() {
  const urlInput = document.getElementById('webhookTestUrl');
  const resDisplay = document.getElementById('webhookResultDisplay');
  const url = urlInput ? urlInput.value.trim() : null;

  if (resDisplay) {
    resDisplay.style.display = 'block';
    resDisplay.innerHTML = '<span style="color: #38bdf8;">Generating and dispatching webhook payload...</span>';
  }

  try {
    const res = await fetch('/api/v1/webhooks/test-dispatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ webhook_url: url })
    });
    const d = await res.json();
    if (d.status === 'success') {
      showToast("SOAR Webhook Alert Sent!");
      if (resDisplay) {
        resDisplay.innerHTML = `
          <div style="background: rgba(0,0,0,0.5); padding: 0.75rem; border-radius: 6px; border: 1px solid #10b981;">
            <div style="color: #10b981; font-weight: 700;">Status: ${d.message}</div>
            <pre style="margin-top: 0.5rem; font-size: 0.72rem; color: #38bdf8; overflow-x: auto;">${JSON.stringify(d.payload, null, 2)}</pre>
          </div>
        `;
      }
    }
  } catch (err) {
    if (resDisplay) resDisplay.innerHTML = `<span style="color: #ef4444;">Failed to dispatch: ${err}</span>`;
  }
}

// -------------------------------------------------------------
// Utility Helpers
// -------------------------------------------------------------
function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}
