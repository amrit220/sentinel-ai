/* =========================================================================
   Sentinel AI — single page application
   hash router: #/dashboard #/scan #/scans #/results/:id #/reports #/monitor #/learn
   ========================================================================= */

const UI = {
  modal() { return document.getElementById('modal'); },
  openModal(html) {
    document.getElementById('modalCard').innerHTML =
      `<button class="modal-x" onclick="UI.closeModal()">✕</button>` + html;
    UI.modal().classList.remove('hidden');
  },
  closeModal() { UI.modal().classList.add('hidden'); },

  toast(msg, err = false) {
    const el = document.createElement('div');
    el.className = 'toast' + (err ? ' err' : '');
    el.textContent = msg;
    document.getElementById('toasts').appendChild(el);
    setTimeout(() => el.remove(), 4200);
  },
};

/** Mobile drawer: slide the sidebar in/out (>=900px it is always visible). */
function toggleSidebar(force) {
  const sb = document.querySelector('.sidebar');
  const bd = document.querySelector('.sidebar-backdrop');
  if (!sb) return;
  const open = force !== undefined ? force : !sb.classList.contains('open');
  sb.classList.toggle('open', open);
  if (bd) bd.classList.toggle('show', open);
}

const DEMO_URL = 'http://127.0.0.1:5099';
let CURRENT_SCAN = null;   // shared state for results view

/* ============================== router ==============================
   Hash-based SPA router. Reads the URL fragment (#/page/arg), highlights
   the matching sidebar item and renders the page function into #view.
   Falls back to the dashboard for unknown routes. */
const routes = {
  dashboard: pageDashboard, scan: pageScan, scans: pageScans,
  results: pageResults, reports: pageReports, monitor: pageMonitor, learn: pageLearn,
};
const TITLES = { dashboard: 'Dashboard', scan: 'New Scan', scans: 'Scans & Results',
                 results: 'Scan Results', reports: 'Reports', monitor: 'Continuous Monitoring',
                 learn: 'Learning Mode' };

async function route() {
  // '#/dashboard' -> 'dashboard'; '#/results/<id>' -> page + scan id arg
  toggleSidebar(false);   // close the mobile drawer after navigation
  const hash = location.hash.slice(2) || 'dashboard';
  const [name, arg] = hash.split('/');
  const fn = routes[name] || pageDashboard;
  document.getElementById('pageTitle').textContent = TITLES[name] || 'Sentinel AI';
  document.querySelectorAll('.nav-item').forEach(a =>
    a.classList.toggle('active', a.dataset.nav === (name === 'results' ? 'scans' : name)));
  const view = document.getElementById('view');
  view.innerHTML = `<div class="empty">loading…</div>`;
  try { await fn(arg, view); }
  catch (e) { view.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`; }
}
window.addEventListener('hashchange', route);

/* ============================ boot ============================
   On load: ping backend health (shows which AI backend is active),
   kick off the alert-badge poller and render the initial route. */
(async function boot() {
  try {
    const h = await API.get('/api/health');
    document.getElementById('healthDot').classList.add('on');
    document.getElementById('healthTxt').textContent =
      `online · ${h.ai_backend === 'llm' ? 'LLM connected' : 'SentinelMind (offline AI)'}`;
    document.getElementById('aiBackend').textContent = `AI: ${h.ai_backend}`;
  } catch (e) {
    document.getElementById('healthTxt').textContent = 'backend unreachable';
  }
  refreshAlertBadge();
  route();
  setInterval(refreshAlertBadge, 20000);
})();

/** Polls unread alerts and keeps the sidebar Monitoring badge in sync. */
async function refreshAlertBadge() {
  try {
    const a = await API.get('/api/alerts?unread=1');
    const b = document.getElementById('alertBadge');
    b.classList.toggle('hidden', a.alerts.length === 0);
    b.textContent = a.alerts.length;
  } catch (e) { /* ignore */ }
}

/* ============================ DASHBOARD ============================
   Overview page: four score donuts from the latest completed scan,
   threat-distribution bars, latest alerts and the recent scans table. */
async function pageDashboard(_arg, view) {
  const [scans, alerts] = await Promise.all([API.get('/api/scans'), API.get('/api/alerts')]);
  const last = scans.scans[0];
  const done = scans.scans.filter(s => s.status === 'completed');
  const doneLast = done[0];
  const counts = doneLast?.summary?.counts || { critical: 0, high: 0, medium: 0, low: 0 };
  const scores = doneLast?.summary?.scores || { overall: 0, security: 0, performance: 0, quality: 0 };

  view.innerHTML = `
    <div class="grid c4">
      ${scoreCard('Overall', scores.overall, doneLast?.summary?.scores?.risk)}
      ${scoreCard('Security', scores.security)}
      ${scoreCard('Performance', scores.performance)}
      ${scoreCard('Quality', scores.quality)}
    </div>

    <div class="grid c2 mt">
      <div class="card">
        <div class="row spread"><h2 class="sect" style="margin:0">Threat distribution</h2>
          <span class="muted small">latest completed scan</span></div>
        ${Charts.bars([
          { label: 'Critical', value: counts.critical || 0, color: SEV_COLOR.critical },
          { label: 'High', value: counts.high || 0, color: SEV_COLOR.high },
          { label: 'Medium', value: counts.medium || 0, color: SEV_COLOR.medium },
          { label: 'Low', value: counts.low || 0, color: SEV_COLOR.low },
        ])}
        ${doneLast ? `<div class="row mt small">
          <a href="#/results/${doneLast.id}">View full results for ${esc(doneLast.target)} →</a></div>`
          : `<div class="muted small mt">No completed scans yet — start one.</div>`}
      </div>
      <div class="card">
        <h2 class="sect" style="margin-top:0">Recent alerts</h2>
        <div id="dashAlerts"></div>
      </div>
    </div>

    <h2 class="sect">Recent scans</h2>
    <div class="card">${scanTable(scans.scans.slice(0, 8))}</div>`;

  const aBox = view.querySelector('#dashAlerts');
  aBox.innerHTML = alerts.alerts.slice(0, 5).map(alertRow).join('')
    || '<div class="muted small">No alerts. Run a scan to begin.</div>';
}

/** Donut + label card used by the dashboard and results pages. */
function scoreCard(label, val, risk) {
  const col = val >= 80 ? '#00e5a0' : val >= 60 ? '#4dd8ff' : val >= 40 ? '#ffd23d' : '#ff3b5c';
  return `<div class="card score-card">
    ${Charts.donut(val, col, 108, 9)}
    <div>
      <div class="score-label">${label}</div>
      <div class="score-grade">score ${val ?? 0}/100</div>
      ${risk ? `<div class="score-risk" style="color:${col}">${esc(risk)}</div>` : ''}
    </div>
  </div>`;
}

/** Shared "recent scans" table with per-row progress bars. */
function scanTable(scans) {
  if (!scans.length) return `<div class="muted">No scans yet. <a href="#/scan">Start one →</a></div>`;
  return `<table class="tbl"><tr><th>Target</th><th>Status</th><th>Progress</th><th>Scores</th><th>Started</th><th></th></tr>
  ${scans.map(s => {
    const sc = s.summary?.scores || {};
    const prog = s.status === 'completed' ? 100 : (s.progress || 0);
    return `<tr>
      <td class="mono">${esc(s.target)}</td>
      <td><span class="statusdot ${s.status}"></span>${s.status}</td>
      <td style="min-width:120px"><div class="progress"><div style="width:${prog}%"></div></div>
          <div class="muted small">${esc(s.stage || '')}</div></td>
      <td>${s.status === 'completed' ? `<span class="sev ${sc.overall >= 80 ? 'pass' : sc.overall >= 60 ? 'low' : sc.overall >= 40 ? 'medium' : 'critical'}">${sc.overall}</span>` : '—'}</td>
      <td class="muted small">${fmtTime(s.started_at || s.created_at)}</td>
      <td><a class="link" href="#/results/${s.id}">open →</a></td>
    </tr>`; }).join('')}</table>`;
}

function alertRow(a) {
  return `<div class="alert ${a.severity}"><span class="sdot"></span>
    <div><div>${esc(a.message)}</div>
    <div class="muted small">${fmtTime(a.created_at)}</div></div></div>`;
}

/* ============================ NEW SCAN ============================ */
async function pageScan(_arg, view) {
  view.innerHTML = `
  <div class="grid c2">
    <div class="card">
      <h2 class="sect" style="margin-top:0">Target</h2>
      <div class="field">
        <span class="lbl">Base URL of the API / system (authorized targets only)</span>
        <input type="text" id="scTarget" placeholder="https://api.example.com">
      </div>
      <div class="row mb">
        <button class="btn small" onclick="useDemo()">⚡ Use bundled demo target</button>
        <span class="muted small">launches full detection pipeline vs. demo</span>
      </div>
      <div class="field">
        <span class="lbl">OpenAPI / Swagger spec (optional — auto-discovery otherwise)</span>
        <textarea id="scSpec" rows="5" placeholder='{"openapi":"3.0.0","paths":{"/api/users":{"get":{...}}}}'></textarea>
      </div>
      <h2 class="sect">Modules</h2>
      <div style="display:flex;flex-direction:column;gap:8px">
        <label class="ck"><input type="checkbox" id="mFunc" checked> Functional / edge / negative test suite</label>
        <label class="ck"><input type="checkbox" id="mAtk" checked> Vulnerability detection + attack simulation</label>
        <label class="ck"><input type="checkbox" id="mPerf"> Performance / load testing</label>
      </div>
      <div id="perfCfg" class="hidden mt">
        <div class="grid c2">
          <div class="field"><span class="lbl">Virtual users</span><input type="number" id="pConc" value="20"></div>
          <div class="field"><span class="lbl">Duration (s)</span><input type="number" id="pDur" value="8"></div>
        </div>
      </div>
      <button class="btn primary mt" id="scStart" onclick="startScan()">▶ Launch scan</button>
    </div>

    <div class="card">
      <h2 class="sect" style="margin-top:0">Live pipeline</h2>
      <div id="scProgress">
        <div class="muted small">Configure a target and launch. The pipeline runs:
        discovery → tests → attacks → classification → AI analysis → scoring.</div>
      </div>
    </div>
  </div>`;

  const perf = view.querySelector('#mPerf');
  perf.addEventListener('change', () => view.querySelector('#perfCfg').classList.toggle('hidden', !perf.checked));
}

/** Fill the form with the bundled demo target — and verify it's actually
    reachable (no-cors ping: succeeds on connect, rejects on refusal). */
async function useDemo() {
  document.getElementById('scTarget').value = DEMO_URL;
  try {
    await fetch(DEMO_URL + '/api/health', { mode: 'no-cors' });
    UI.toast('Demo target set: ' + DEMO_URL);
  } catch (e) {
    UI.toast('Demo target NOT running — start it with: python app.py --with-demo', true);
  }
}

/** Collect target + module config from the form and POST /api/scans,
    then hand off to the live progress poller. */
async function startScan() {
  const target = document.getElementById('scTarget').value.trim();
  if (!target) return UI.toast('Enter a target URL', true);
  const body = {
    target,
    openapi: document.getElementById('scSpec').value.trim() || null,
    functional: document.getElementById('mFunc').checked,
    attacks: document.getElementById('mAtk').checked,
    performance: document.getElementById('mPerf').checked,
  };
  if (body.performance) {
    body.perfConcurrency = +document.getElementById('pConc').value;
    body.perfDuration = +document.getElementById('pDur').value;
  }
  const btn = document.getElementById('scStart');
  btn.disabled = true; btn.textContent = 'launching…';
  try {
    const r = await API.post('/api/scans', body);
    UI.toast('Scan launched');
    pollScanProgress(r.scan_id);
  } catch (e) { UI.toast(e.message, true); btn.disabled = false; btn.textContent = '▶ Launch scan'; }
}

/** Poll scan status ~1x/sec until it completes or fails, rendering a live
    progress bar with the current pipeline stage. */
async function pollScanProgress(scanId) {
  const box = document.getElementById('scProgress');
  for (;;) {
    try {
      const s = await API.get(`/api/scans/${scanId}`);
      const pct = s.status === 'completed' ? 100 : s.progress;
      box.innerHTML = `
        <div class="row spread small mb"><b class="mono">${esc(s.target)}</b>
          <span class="sev ${s.status === 'failed' ? 'fail' : s.status}">${s.status}</span></div>
        <div class="progress"><div style="width:${pct}%"></div></div>
        <div class="muted small mt">${esc(s.stage || '')} ${pct}%</div>
        ${s.status === 'completed' ? `
          <div class="row mt">
            <a class="btn primary small" href="#/results/${s.id}">View results →</a>
          </div>` : ''}
        ${s.status === 'failed' ? `<div class="mt small" style="color:var(--crit)">Error: ${esc(s.error)}</div>` : ''}`;
      if (s.status === 'completed' || s.status === 'failed') {
        refreshAlertBadge();
        if (s.status === 'completed') UI.toast('Scan completed ✔');
        return;
      }
    } catch (e) { UI.toast(e.message, true); return; }
    await new Promise(r => setTimeout(r, 1200));
  }
}

/* ============================ SCANS LIST ============================ */
async function pageScans(_arg, view) {
  const scans = await API.get('/api/scans');
  view.innerHTML = `<div class="card">${scanTable(scans.scans)}</div>`;
}

/* ============================ RESULTS ============================
   Detail page for one scan: score cards, AI executive summary,
   expandable finding cards (attack replay / deep analysis / chat),
   filterable test table and the load-test panel. Auto-refreshes while
   the scan is still running. */
async function pageResults(scanId, view) {
  if (!scanId) { location.hash = '#/scans'; return; }
  let s;
  try { s = await API.get(`/api/scans/${scanId}`); }
  catch (e) { view.innerHTML = `<div class="empty">Scan not found.</div>`; return; }

  if (s.status === 'running' || s.status === 'queued') {
    view.innerHTML = `
      <div class="card"><div class="row spread mb"><b class="mono">${esc(s.target)}</b>
        <span class="sev ${s.status}">${s.status}</span></div>
        <div class="progress"><div style="width:${s.progress}%"></div></div>
        <div class="muted small mt">${esc(s.stage || '')} — auto-refreshing…</div></div>`;
    setTimeout(() => pageResults(scanId, view), 1500);
    return;
  }

  const { findings } = await API.get(`/api/scans/${scanId}/findings`);
  const { tests } = await API.get(`/api/scans/${scanId}/tests`);
  CURRENT_SCAN = { scan: s, findings, tests };
  const sum = s.summary || {}, sc = sum.scores || {}, counts = sum.counts || {};
  const perf = sum.performance;

  view.innerHTML = `
    <div class="card tight scanbar">
      <b class="mono">${esc(s.target)}</b>
      <span class="sev ${s.status}">${s.status}</span>
      <span class="tagchip">${esc(sum.discovery_mode || '')}</span>
      <span class="tagchip">${sum.endpoints_scanned ?? 0} endpoints</span>
      <span class="tagchip">${sum.attacks_simulated ?? 0} attacks</span>
      <span class="tagchip">${sum.test_total ?? 0} tests</span>
      <div style="flex:1"></div>
      <a class="btn small" href="#/reports">reports</a>
      <button class="btn small" onclick="startMonitorPrompt('${scanId}')">◉ monitor</button>
    </div>

    <div class="grid c4 mt">
      ${scoreCard('Overall', sc.overall, sc.risk)}
      ${scoreCard('Security', sc.security)}
      ${scoreCard('Performance', sc.performance)}
      ${scoreCard('Quality', sc.quality)}
    </div>

    ${(sum.ai_summary?.executive_summary) ? `
      <div class="card mt">
        <div class="row spread"><h2 class="sect" style="margin:0">AI executive summary</h2>
          <span class="pill">AI: ${esc(sum.ai_backend || '')}</span></div>
        <p>${esc(sum.ai_summary.executive_summary)}</p>
        ${sum.ai_summary.top_risks?.length ? `<div class="mt"><b>Top risks</b><ul style="margin-left:18px">
          ${sum.ai_summary.top_risks.map(r => `<li>${esc(r)}</li>`).join('')}</ul></div>` : ''}
      </div>` : ''}

    <h2 class="sect">Findings (${findings.length})</h2>
    <div id="findingsList">${findingsSorted(findings).map((f, i) => findingCard(f, i)).join('')
      || '<div class="empty">No findings — target survived all simulated attacks.</div>'}</div>

    <h2 class="sect">Test case results (${tests.length})</h2>
    <div class="card">${testTable(tests)}</div>

    ${perf ? `
      <h2 class="sect">Load test — ${esc(perf.verdict?.toUpperCase() || '')}</h2>
      <div class="card">
        <div class="grid c4" style="text-align:center">
          <div><div class="score-label">Throughput</div><b>${perf.throughput_rps} rps</b></div>
          <div><div class="score-label">p50 / p95 / p99</div><b>${perf.latency_p50_ms} / ${perf.latency_p95_ms} / ${perf.latency_p99_ms} ms</b></div>
          <div><div class="score-label">Error rate</div><b>${(perf.error_rate * 100).toFixed(1)}%</b></div>
          <div><div class="score-label">Requests</div><b>${perf.total_requests}</b></div>
        </div>
        <p class="muted small mt">${esc(perf.bottleneck_analysis || '')}</p>
      </div>` : ''}

    <div id="aiHidden" class="hidden"></div>`;

  // bind finding expanders
  view.querySelectorAll('.finding-head').forEach(h =>
    h.addEventListener('click', (ev) => {
      if (ev.target.closest('button')) return;
      h.parentElement.classList.toggle('open');
    }));
}

/** Sort findings critical -> info for consistent display order. */
function findingsSorted(fs) {
  return [...fs].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
}

/** Expandable finding card: evidence, impact, AI explanation + code fix,
    learning-mode lesson, and the replay / analyze / chat action buttons. */
function findingCard(f, i) {
  const ai = f.ai_analysis || {};
  const learning = f.ai_learning || ai.learning || {};
  const code = f.ai_fix_code || ai.fix_code;
  return `
  <div class="finding ${f.severity}" id="f-${f.id}">
    <div class="finding-head">
      <span class="sev ${f.severity}">${f.severity}</span>
      <span class="title">${esc(f.title)}</span>
      <span class="endp">${esc(f.method || 'GET')} ${esc(f.endpoint || '')}</span>
      <span class="muted small">${f.confidence ? Math.round(f.confidence * 100) : 80}% conf</span>
      <span class="sev ${f.exploit_success ? 'fail' : 'pass'}">${f.exploit_success ? 'exploited' : 'not exploited'}</span>
    </div>
    <div class="finding-body">
      <div class="kv"><b>Evidence</b><br>${esc(f.evidence || '')}</div>
      <div class="kv"><b>Impact</b><br>${esc(f.impact || '')}</div>
      ${ai.explanation || f.ai_explanation ? `<div class="kv"><b>AI explanation</b><br>${esc(ai.explanation || f.ai_explanation)}</div>` : ''}
      ${ai.fix_conceptual || f.ai_fix ? `<div class="kv"><b>Fix</b><br>${esc(ai.fix_conceptual || f.ai_fix)}</div>` : ''}
      ${code ? `<div class="kv"><b>Suggested code</b><pre class="code">${esc(code)}</pre></div>` : ''}
      ${learning.mistake ? `
        <div class="kv"><b>🎓 Learning mode</b>
          <div class="mt small"><b>Mistake made:</b> ${esc(learning.mistake)}</div>
          <div class="small"><b>Best practice:</b> ${esc(learning.best_practice)}</div>
          <div class="small"><b>Why it matters:</b> ${esc(learning.why)}</div></div>` : ''}
      <div class="row mt">
        ${f.attack_path?.length ? `<button class="btn small" onclick="UI.replay('${f.id}', ${i})">⏯ Attack replay</button>` : ''}
        <button class="btn small" onclick="UI.deepAnalyze('${f.id}')">🤖 Analyze with AI</button>
        <button class="btn small" onclick="UI.askAI('${f.id}')">💬 Debug assistant</button>
      </div>
    </div>
  </div>`;
}

/** Attack Replay Mode: step-by-step modal reconstruction of the simulated
    exploit — request, payload, response and the attacker's reasoning. */
UI.replay = function (fid, i) {
  const f = CURRENT_SCAN.findings.find(x => x.id === fid);
  if (!f) return;
  const req = f.request || {};
  UI.openModal(`
    <h2 style="margin-bottom:4px">⏯ Attack replay — ${esc(f.title)}</h2>
    <div class="muted small mb">step-by-step reconstruction of the simulated exploit</div>
    <div class="card tight mb"><b>Request</b>
      <pre class="code">${esc(req.method || 'GET')} ${esc(req.url || '')}
${req.params ? 'params: ' + esc(JSON.stringify(req.params)) : ''}
${req.json_body ? 'body: ' + esc(JSON.stringify(req.json_body)) : ''}</pre></div>
    <div class="attack-steps">${(f.attack_path || []).map(st => `
      <div class="attack-step">
        <div class="n">${st.step}</div>
        <div><div class="t">${esc(st.title)}</div><div class="d">${esc(st.detail)}</div></div>
      </div>`).join('')}</div>
    <div class="card tight"><b>Response</b>
      <pre class="code">HTTP ${esc(f.response?.status ?? '?')} · ${esc(f.response?.latency_ms ?? '?')}ms
${esc(f.response?.body_snippet || '')}</pre></div>`);
};

/** AI Debug Assistant: on-demand deep analysis of a single finding
    (explanation, root cause, conceptual + code-level fix). */
UI.deepAnalyze = async function (fid) {
  const scanId = location.hash.split('/')[2];
  UI.toast('AI analyzing finding…');
  try {
    const updated = await API.post(`/api/scans/${scanId}/analyze`, { finding_id: fid });
    const f = CURRENT_SCAN.findings.find(x => x.id === fid);
    Object.assign(f, {
      ai_analysis: { explanation: updated.explanation, fix_conceptual: updated.fix_conceptual, learning: updated.learning },
      ai_fix_code: updated.fix_code, ai_learning: updated.learning,
      ai_explanation: updated.explanation, ai_fix: updated.fix_conceptual,
    });
    const idx = findingsSorted(CURRENT_SCAN.findings).findIndex(x => x.id === fid);
    document.getElementById(`f-${fid}`).outerHTML = findingCard(f, idx);
    document.getElementById(`f-${fid}`).classList.add('open');
    UI.toast('AI analysis complete ✔');
  } catch (e) { UI.toast(e.message, true); }
};

/** Chat-style Q&A modal bound to a finding's context. */
UI.askAI = function (fid) {
  const f = CURRENT_SCAN.findings.find(x => x.id === fid);
  UI.openModal(`
    <h2 style="margin-bottom:12px">💬 Sentinel Debug Assistant</h2>
    <div class="chat-log" id="chatLog"></div>
    <div class="row">
      <input type="text" id="chatIn" placeholder="Ask why this happened, or how to fix it…"
        style="flex:1" onkeydown="if(event.key==='Enter')UI.sendChat('${fid}')">
      <button class="btn primary small" onclick="UI.sendChat('${fid}')">Send</button>
    </div>`);
};

UI.sendChat = async function (fid) {
  const inp = document.getElementById('chatIn');
  const log = document.getElementById('chatLog');
  const q = inp.value.trim(); if (!q) return;
  inp.value = '';
  log.insertAdjacentHTML('beforeend', `<div class="chat-msg user"><span class="who">you</span>${esc(q)}</div>`);
  log.scrollTop = log.scrollHeight;
  try {
    const r = await API.post('/api/ai/assistant', { question: q, finding_id: fid });
    log.insertAdjacentHTML('beforeend', `<div class="chat-msg ai"><span class="who">sentinel ai</span>${esc(r.answer)}</div>`);
  } catch (e) { UI.toast(e.message, true); }
  log.scrollTop = log.scrollHeight;
};

/** Test table with a kind filter (functional / edge / negative / perf). */
function testTable(tests) {
  if (!tests.length) return '<div class="muted small">No tests recorded.</div>';
  const filter = `
    <div class="row mb"><select id="tFilter" onchange="filterTests(this.value)" style="width:auto;min-width:200px">
      <option value="">All kinds</option>
      <option value="functional">Functional</option>
      <option value="edge">Edge</option>
      <option value="negative">Negative</option>
      <option value="performance">Performance</option>
    </select></div><div id="tWrap">`;
  return filter + `<table class="tbl"><tbody>
    ${tests.map(t => `<tr data-kind="${t.kind}">
      <td><span class="sev ${t.status}">${t.status}</span></td>
      <td><b>${esc(t.name)}</b><br><span class="muted small mono">${esc(t.method || '')} ${esc(t.endpoint || '')}</span></td>
      <td class="small">${esc(t.expected || '')} → <b>${esc(t.actual || '')}</b></td>
      <td class="small">${t.latency_ms ?? 0} ms</td>
    </tr>`).join('')}</tbody></table></div>`;
}

function filterTests(kind) {
  document.querySelectorAll('#tWrap tr[data-kind]').forEach(tr => {
    tr.style.display = (!kind || tr.dataset.kind === kind) ? '' : 'none';
  });
}

/* ============================ REPORTS ============================
   Developer (technical), Client (plain language) and JSON downloads
   per completed scan — served by the Flask report generator. */
async function pageReports(_arg, view) {
  const scans = await API.get('/api/scans');
  const done = scans.scans.filter(s => s.status === 'completed');
  view.innerHTML = `
    <div class="card"><p class="muted">Sentinel AI generates two report formats plus a raw JSON export.
    The <b>developer report</b> contains technical detail, attack replays and code fixes; the
    <b>client report</b> explains the same findings in plain language for non-technical stakeholders.</p></div>
    ${done.length ? done.map(s => `
      <div class="card">
        <div class="row spread">
          <div>
            <b class="mono">${esc(s.target)}</b>
            <div class="muted small">completed ${fmtTime(s.finished_at)} ·
              overall score ${s.summary?.scores?.overall ?? '—'}</div>
          </div>
          <div class="row">
            <a class="btn small" href="/api/scans/${s.id}/report?format=developer" target="_blank">⬇ Developer (HTML)</a>
            <a class="btn small" href="/api/scans/${s.id}/report?format=client" target="_blank">⬇ Client (HTML)</a>
            <a class="btn small" href="/api/scans/${s.id}/report?format=json" target="_blank">⬇ JSON</a>
          </div>
        </div>
      </div>`).join('') : '<div class="empty">Complete a scan first to generate reports.</div>'}`;
}

/* ============================ MONITOR ============================
   Continuous monitoring: schedule periodic re-scans of a completed
   scan's config and surface new/escalated-vulnerability alerts. */
async function pageMonitor(_arg, view) {
  const [scans, alerts] = await Promise.all([API.get('/api/scans'), API.get('/api/alerts')]);
  const done = scans.scans.filter(s => s.status === 'completed');
  view.innerHTML = `
    <div class="card">
      <p class="muted mb">Continuous monitoring re-runs a completed scan's configuration on a schedule
      and alerts you when <b>new vulnerabilities appear or an existing one escalates</b> in severity.</p>
      ${done.length ? `
        <div class="field"><span class="lbl">Monitored scan</span>
          <select id="monScan">${done.map(s =>
            `<option value="${s.id}">${esc(s.target)} (${fmtTime(s.finished_at)})</option>`).join('')}</select></div>
        <div class="grid c2">
          <div class="field"><span class="lbl">Interval (minutes)</span>
            <input type="number" id="monInterval" value="15"></div>
          <div class="field"><span class="lbl">&nbsp;</span>
            <button class="btn primary" style="width:100%" onclick="startMonitorPrompt(null, true)">◉ Start monitoring</button></div>
        </div>` : '<div class="empty">Complete a scan first, then enable monitoring on it.</div>'}
    </div>
    <div class="card">
      <div class="row spread"><h2 class="sect" style="margin:0">Alert feed</h2>
        <button class="btn small" onclick="markRead()">mark all read</button></div>
      <div class="mt">${alerts.alerts.map(alertRow).join('')
        || '<div class="muted small">No alerts yet.</div>'}</div>
    </div>`;
}

/** Enable monitoring for a scan (directly from results page, or via the
    monitor page form which supplies interval in minutes). */
async function startMonitorPrompt(scanId, useForm) {
  let id = scanId, interval = 900;
  if (useForm) {
    id = document.getElementById('monScan').value;
    interval = (+document.getElementById('monInterval').value) * 60;
  }
  try {
    await API.post(`/api/monitor/${id}/start`, { interval });
    UI.toast('Continuous monitoring enabled ✔');
    refreshAlertBadge();
  } catch (e) { UI.toast(e.message, true); }
}

async function markRead() {
  await API.post('/api/alerts/read');
  UI.toast('Alerts marked read');
  refreshAlertBadge();
  pageMonitor(null, document.getElementById('view'));
}

/* ============================ LEARNING ============================
   Educational layer: converts every detected finding into a lesson —
   the mistake, the best practice, and why it matters. */
async function pageLearn(_arg, view) {
  let findings = [];
  const scans = await API.get('/api/scans');
  for (const s of scans.scans.filter(x => x.status === 'completed').slice(0, 5)) {
    try { findings.push(...(await API.get(`/api/scans/${s.id}/findings`)).findings); }
    catch (e) { /* skip */ }
  }
  const cats = {};
  findings.forEach(f => {
    const learning = f.ai_learning || {};
    if (!cats[f.category]) cats[f.category] = { title: f.title, f, learning };
  });
  view.innerHTML = `
    <div class="card"><p class="muted">Learning mode turns every detected issue into a lesson:
    what mistake was made, what the best practice is, and why it matters. Lessons below are drawn
    from real findings across your scans.</p></div>
    ${Object.values(cats).length ? Object.values(cats).map(c => `
      <div class="card">
        <div class="row spread"><h3>${esc(c.title)}</h3>
          <span class="sev ${c.f.severity}">${c.f.severity}</span></div>
        <div class="mt"><b>❌ The mistake</b><p class="muted">${esc(c.learning.mistake || '—')}</p></div>
        <div class="mt"><b>✅ Best practice</b><p class="muted">${esc(c.learning.best_practice || '—')}</p></div>
        <div class="mt"><b>💡 Why it matters</b><p class="muted">${esc(c.learning.why || '—')}</p></div>
      </div>`).join('')
    : '<div class="empty">Run a scan — every finding will automatically get a lesson here.</div>'}`;
}
