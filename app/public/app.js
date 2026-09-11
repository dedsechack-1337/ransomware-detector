const GAUGE_CIRC = 276;

function renderGauge(risk, verdict) {
  const arc = document.getElementById('gauge-arc');
  const label = document.getElementById('gauge-label');
  const pill = document.getElementById('verdict-pill');
  const verdictText = document.getElementById('verdict-text');
  const riskVerdictText = document.getElementById('risk-verdict-text');

  const offset = GAUGE_CIRC - (GAUGE_CIRC * Math.min(risk, 100) / 100);
  let color = '#1f7a4d';
  let verdictLabel = 'Normal';
  let pillClass = '';
  let pillLabel = 'No threats detected';

  if (verdict === 'suspicious') {
    color = '#a86a10'; verdictLabel = 'Suspicious'; pillClass = 'suspicious'; pillLabel = 'Suspicious activity';
  } else if (verdict === 'ransomware_likely') {
    color = '#b3261e'; verdictLabel = 'Ransomware likely'; pillClass = 'ransomware_likely'; pillLabel = 'RANSOMWARE LIKELY';
  }

  arc.style.stroke = color;
  arc.style.strokeDashoffset = offset;
  label.textContent = Math.round(risk);
  label.style.color = color;
  riskVerdictText.textContent = verdictLabel;
  riskVerdictText.style.color = color;

  pill.className = 'verdict-pill ' + pillClass;
  verdictText.textContent = pillLabel;
}

function renderCards(summary) {
  const cards = document.getElementById('cards');
  const items = [
    { label: 'Total events', value: summary.totalEvents },
    { label: 'Files touched', value: summary.filesTouched },
    { label: 'Alerts raised', value: summary.alerts },
    { label: 'Overall risk', value: summary.overallRisk + '/100' },
  ];
  cards.innerHTML = items.map(i => `
    <div class="stat-card"><div class="label">${i.label}</div><div class="value">${i.value}</div></div>
  `).join('');
}

function renderAlerts(alerts) {
  const body = document.getElementById('alerts-body');
  document.getElementById('alert-count').textContent = alerts.length ? `${alerts.length} found` : '';
  if (!alerts.length) {
    body.innerHTML = '<div class="empty">No alerts — nothing crossed a detection threshold.</div>';
    return;
  }
  const rows = alerts.map(a => `
    <tr>
      <td><span class="sev ${a.severity}">${a.severity}</span></td>
      <td>${a.type.replace(/_/g, ' ')}</td>
      <td style="color:#6b6656;">${a.detail}</td>
    </tr>
  `).join('');
  body.innerHTML = `<table><thead><tr><th>Severity</th><th>Type</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderSessions(sessions) {
  const body = document.getElementById('sessions-body');
  if (!sessions.length) {
    body.innerHTML = '<div class="empty">No activity sessions recorded yet.</div>';
    return;
  }
  const rows = sessions.map(s => {
    const color = s.anomalyScore >= 60 ? '#b3261e' : s.anomalyScore >= 30 ? '#a86a10' : '#1f7a4d';
    const time = new Date(s.startTime * 1000).toLocaleTimeString();
    return `
    <tr>
      <td>${time}</td>
      <td>${s.filesTouched}</td>
      <td>${s.eventsPerSecond.toFixed(2)}</td>
      <td>${s.uniqueNewExtensions}</td>
      <td>${(s.pctHighEntropy * 100).toFixed(1)}%</td>
      <td>${s.renameCount}</td>
      <td style="color:${color}; font-weight:700;">${s.anomalyScore}</td>
    </tr>`;
  }).join('');
  body.innerHTML = `
    <table>
      <thead><tr><th>Start</th><th>Files</th><th>Events/sec</th><th>New exts</th><th>% high entropy</th><th>Renames</th><th>Anomaly score</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

async function refresh() {
  try {
    const res = await fetch('/api/report');
    const data = await res.json();
    renderCards(data.summary);
    renderGauge(data.summary.overallRisk, data.summary.verdict);
    renderAlerts(data.alerts);
    renderSessions(data.sessions);
  } catch (e) {
    console.error(e);
  }
}

document.getElementById('attack-btn').addEventListener('click', async (e) => {
  e.target.disabled = true;
  e.target.textContent = 'Attack running…';
  try {
    await fetch('/api/simulate-attack', { method: 'POST' });
  } catch (err) { /* ignore */ }
  setTimeout(() => {
    e.target.disabled = false;
    e.target.textContent = 'Launch simulated attack';
  }, 8000);
});

document.getElementById('reset-btn').addEventListener('click', async (e) => {
  e.target.disabled = true;
  try {
    await fetch('/api/reset', { method: 'POST' });
  } finally {
    setTimeout(() => { e.target.disabled = false; }, 1500);
  }
});

refresh();
setInterval(refresh, 2000);

// ---------- Upload & analyze panel ----------

const VERDICT_LABEL = {
  clean: 'Clean',
  suspicious: 'Suspicious',
  ransomware_likely: 'Ransomware likely',
};

function fmtBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / (1024 * 1024)).toFixed(2) + ' MB';
}

function renderUploadResult(result) {
  const box = document.getElementById('upload-result');
  const badgeClass = result.verdict;
  const findingsHtml = result.findings.length
    ? result.findings.map(f => `
        <div class="finding">
          <span class="sev ${f.severity}">${f.severity}</span>
          <div>
            <div class="fd-rule">${f.rule.replace(/_/g, ' ')}</div>
            <div class="fd-text">${f.detail}</div>
          </div>
        </div>`).join('')
    : `<div class="empty">No detection rules triggered on this file.</div>`;

  box.innerHTML = `
    <div class="upload-result">
      <div class="upload-result-head">
        <div>
          <div class="fname">${result.filename}</div>
          <div class="fmeta">${fmtBytes(result.sizeBytes)} · entropy ${result.entropy.toFixed(2)} bits/byte</div>
        </div>
        <span class="result-badge ${badgeClass}">${VERDICT_LABEL[result.verdict]}</span>
      </div>
      <div class="result-metrics">
        <div class="m"><div class="label">Risk score</div><div class="value">${result.score}/100</div></div>
        <div class="m"><div class="label">Entropy</div><div class="value">${result.entropy.toFixed(2)}</div></div>
        <div class="m"><div class="label">Rules triggered</div><div class="value">${result.findings.length}</div></div>
      </div>
      <div class="result-findings">${findingsHtml}</div>
    </div>`;
}

function renderUploadError(message) {
  document.getElementById('upload-result').innerHTML = '';
  document.getElementById('upload-status').innerHTML = `<div class="upload-error">${message}</div>`;
}

async function analyzeFile(file) {
  document.getElementById('upload-result').innerHTML = '';
  document.getElementById('upload-status').innerHTML = `<div class="upload-spinner">Analyzing ${file.name}…</div>`;
  try {
    const formData = new FormData();
    formData.append('file', file, file.name);
    const res = await fetch('/api/analyze-upload', { method: 'POST', body: formData });
    const data = await res.json();
    document.getElementById('upload-status').innerHTML = '';
    if (!res.ok) {
      renderUploadError(data.error || 'Analysis failed.');
      return;
    }
    renderUploadResult(data);
  } catch (err) {
    document.getElementById('upload-status').innerHTML = '';
    renderUploadError('Could not reach the analyzer. Please try again.');
  }
}

async function analyzeSample(url, filename) {
  document.getElementById('upload-result').innerHTML = '';
  document.getElementById('upload-status').innerHTML = `<div class="upload-spinner">Loading sample…</div>`;
  try {
    const res = await fetch(url);
    const blob = await res.blob();
    const file = new File([blob], filename, { type: blob.type || 'application/octet-stream' });
    await analyzeFile(file);
  } catch (err) {
    document.getElementById('upload-status').innerHTML = '';
    renderUploadError('Could not load the demo sample.');
  }
}

const fileInput = document.getElementById('file-input');
const uploadZone = document.getElementById('upload-zone');

fileInput.addEventListener('change', () => {
  if (fileInput.files && fileInput.files[0]) {
    analyzeFile(fileInput.files[0]);
    fileInput.value = '';
  }
});

['dragenter', 'dragover'].forEach(evt => {
  uploadZone.addEventListener(evt, (e) => {
    e.preventDefault();
    uploadZone.classList.add('dragover');
  });
});
['dragleave', 'drop'].forEach(evt => {
  uploadZone.addEventListener(evt, (e) => {
    e.preventDefault();
    uploadZone.classList.remove('dragover');
  });
});
uploadZone.addEventListener('drop', (e) => {
  const file = e.dataTransfer.files && e.dataTransfer.files[0];
  if (file) analyzeFile(file);
});

document.getElementById('sample-clean').addEventListener('click', () =>
  analyzeSample('/samples/demo-safe-report.txt', 'demo-safe-report.txt'));
document.getElementById('sample-entropy').addEventListener('click', () =>
  analyzeSample('/samples/demo-encrypted-sample.locked', 'demo-encrypted-sample.locked'));
document.getElementById('sample-note').addEventListener('click', () =>
  analyzeSample('/samples/README_DECRYPT_DEMO.txt', 'README_DECRYPT_DEMO.txt'));
