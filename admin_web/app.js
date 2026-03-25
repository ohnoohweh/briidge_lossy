function fmtNumber(value, digits = 1) {
  if (value == null || Number.isNaN(value)) return 'n/a';
  return Number(value).toFixed(digits);
}

function fmtInteger(value) {
  if (value == null || Number.isNaN(value)) return 'n/a';
  return String(value);
}

function fmtBytes(value) {
  if (value == null || Number.isNaN(value)) return 'n/a';
  const bytes = Math.max(0, Number(value));
  const KB = 1024;
  const MB = KB * 1024;
  const GB = MB * 1024;

  if (bytes < KB) return `${Math.floor(bytes)} B`;
  if (bytes < MB) return `${(bytes / KB).toFixed(1)} kB`;
  if (bytes < GB) return `${(bytes / MB).toFixed(1)} MB`;
  return `${(bytes / GB).toFixed(1)} GB`;
}

function fmtUptime(sec) {
  if (sec == null || Number.isNaN(sec)) return 'n/a';
  const s = Math.max(0, Math.floor(sec));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  if (h > 0) return `${h}h ${m}m ${r}s`;
  if (m > 0) return `${m}m ${r}s`;
  return `${r}s`;
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function setProgress(id, value, maxScale = 256.0) {
  const el = document.getElementById(id);
  if (!el) return;
  const pct = Math.max(0, Math.min(100, (Number(value || 0) / maxScale) * 100));
  el.style.width = pct.toFixed(1) + '%';
}

function fmtEndpoint(ep) {
  if (!ep) return 'n/a';
  if (Array.isArray(ep) && ep.length >= 2) return `${ep[0]}:${ep[1]}`;
  if (typeof ep === 'object' && ep.host != null && ep.port != null) return `${ep.host}:${ep.port}`;
  return String(ep);
}

function fmtDestination(dest) {
  if (!dest) return 'n/a';
  if (dest.host != null && dest.port != null) return `${dest.host}:${dest.port}`;
  return fmtEndpoint(dest);
}

function roleClass(role) {
  const r = String(role || 'unknown').toLowerCase();
  if (r === 'server') return 'role-pill role-server';
  if (r === 'client') return 'role-pill role-client';
  return 'role-pill role-unknown';
}

function renderConnectionTable(tbodyId, rows) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;

  if (!rows || rows.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="10">No ${tbodyId.startsWith('udp') ? 'UDP' : 'TCP'} connections</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map((row) => {
    const rxBytes = row.stats?.rx_bytes ?? 0;
    const txBytes = row.stats?.tx_bytes ?? 0;
    const rxMsgs = row.stats?.rx_msgs ?? 0;
    const txMsgs = row.stats?.tx_msgs ?? 0;
    return `
      <tr>
        <td class="mono">${fmtInteger(row.chan_id)}</td>
        <td class="mono">${fmtInteger(row.svc_id)}</td>
        <td><span class="${roleClass(row.role)}">${row.role || 'unknown'}</span></td>
        <td class="mono">${fmtEndpoint(row.source)}</td>
        <td class="mono">${fmtInteger(row.local_port)}</td>
        <td class="mono">${fmtDestination(row.remote_destination)}</td>
        <td class="mono">${fmtBytes(rxBytes)}</td>
        <td class="mono">${fmtBytes(txBytes)}</td>
        <td class="mono">${fmtInteger(rxMsgs)}</td>
        <td class="mono">${fmtInteger(txMsgs)}</td>        
      </tr>
    `;
  }).join('');
}

function applyPeerState(state) {
  const badge = document.getElementById('peerStateBadge');
  const normalized = String(state || 'UNKNOWN').toUpperCase();
  setText('peerState', normalized);
  if (!badge) return;

  badge.textContent = normalized;
  badge.classList.remove('state-connected', 'state-degraded', 'state-disconnected', 'state-unknown');

  if (normalized.includes('CONNECT')) {
    badge.classList.add('state-connected');
  } else if (normalized.includes('DEGRADE') || normalized.includes('WAIT') || normalized.includes('RETRY')) {
    badge.classList.add('state-degraded');
  } else if (normalized.includes('DISCONNECT') || normalized.includes('DOWN') || normalized.includes('FAIL')) {
    badge.classList.add('state-disconnected');
  } else {
    badge.classList.add('state-unknown');
  }
}

async function loadMeta() {
  try {
    const r = await fetch('/api/meta', { cache: 'no-store' });
    const j = await r.json();
    setText('uptimeSec', fmtUptime(j.uptime_sec));
    const meta = document.getElementById('meta');
    if (meta) meta.textContent = JSON.stringify(j, null, 2);
  } catch (e) {
    const meta = document.getElementById('meta');
    if (meta) meta.textContent = 'meta load failed: ' + e;
  }
}

async function restart() {
  const r = await fetch('/api/restart', { method: 'POST' });
  const j = await r.json();
  alert(JSON.stringify(j));
}

async function loadStatus() {
  try {
    const r = await fetch('/api/status', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();

    applyPeerState(j.peer_state);
    setText('detailOverlayBind', j.overlay?.bind ?? 'n/a');
    setText('detailOverlayPeer', j.overlay?.peer ?? 'n/a');

    setText('udpOpen', fmtInteger(j.open_connections?.udp));
    setText('tcpOpen', fmtInteger(j.open_connections?.tcp));

    const appRx = j.traffic?.rates_kBps?.app_rx ?? 0;
    const appTx = j.traffic?.rates_kBps?.app_tx ?? 0;
    const peerRx = j.traffic?.rates_kBps?.peer_rx ?? 0;
    const peerTx = j.traffic?.rates_kBps?.peer_tx ?? 0;

    setText('appRxRate', fmtNumber(appRx));
    setText('appTxRate', fmtNumber(appTx));
    setText('peerRxRate', fmtNumber(peerRx));
    setText('peerTxRate', fmtNumber(peerTx));

    setProgress('barAppRx', appRx);
    setProgress('barAppTx', appTx);
    setProgress('barPeerRx', peerRx);
    setProgress('barPeerTx', peerTx);

    const rtt = j.transport?.rtt_est_ms;
    const inflight = j.transport?.inflight;
    const errors = j.decode_errors?.unidentified_frames ?? 0;
    const myudp = j.myudp || {};
    const retransmit = myudp.retransmit || {};

    setText('rttEst', fmtNumber(rtt));
    setText('inflight', fmtInteger(inflight));
    setText('decodeErrors', fmtInteger(errors));
    setText('myudpFirstPass', fmtInteger(retransmit.first_pass));
    setText('myudpRepeatedOnce', fmtInteger(retransmit.repeated_once));
    setText('myudpRepeatedMultiple', fmtInteger(retransmit.repeated_multiple));
    setText('myudpConfirmedTotal', fmtInteger(retransmit.confirmed_total));
  } catch (e) {
    console.error('status load failed', e);
  }
}

function renderPeerTable(rows) {
  const tbody = document.getElementById('peerConnectionsBody');
  if (!tbody) return;
  if (!rows || rows.length === 0) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="11">No peer sessions</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map((row) => `
    <tr>
      <td class="mono">${fmtInteger(row.id)}</td>
      <td class="mono">${row.transport || 'n/a'}</td>
      <td><span class="${(row.connected ? 'role-pill role-server' : 'role-pill role-unknown')}">${row.connected ? 'yes' : 'no'}</span></td>
      <td class="mono">${row.peer || 'n/a'}</td>
      <td class="mono">${fmtNumber(row.rtt_est_ms)}</td>
      <td class="mono">${fmtInteger(row.inflight)}</td>
      <td class="mono">${fmtInteger(row.open_connections?.udp ?? 0)}</td>
      <td class="mono">${fmtInteger(row.open_connections?.tcp ?? 0)}</td>
      <td class="mono">${fmtInteger(row.traffic?.rx_bytes ?? 0)}</td>
      <td class="mono">${fmtInteger(row.traffic?.tx_bytes ?? 0)}</td>
      <td class="mono">${fmtInteger(row.decode_errors ?? 0)}</td>
    </tr>
  `).join('');
}

async function loadConnections() {
  try {
    const r = await fetch('/api/connections', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();

    renderConnectionTable('udpConnectionsBody', j.udp || []);
    renderConnectionTable('tcpConnectionsBody', j.tcp || []);
    setText('udpOpen', fmtInteger(j.counts?.udp ?? (j.udp || []).length));
    setText('tcpOpen', fmtInteger(j.counts?.tcp ?? (j.tcp || []).length));
  } catch (e) {
    console.error('connections load failed', e);
  }
}

async function loadPeers() {
  try {
    const r = await fetch('/api/peers', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    renderPeerTable(j.peers || []);
  } catch (e) {
    console.error('peers load failed', e);
  }
}

async function loadConfig() {
  try {
    const r = await fetch('/api/config', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    configState = {
      config: j.config || {},
      schema: j.schema || {},
    };
    renderConfigSections(configState.schema, configState.config);
    setText('configMessage', '');
  } catch (e) {
    setText('configMessage', 'config load failed: ' + e);
  }
}

async function saveConfig() {
  const editors = Array.from(document.querySelectorAll('.config-editor[data-config-key]'));
  if (editors.length === 0) return;

  const updates = {};
  for (const input of editors) {
    const key = input.getAttribute('data-config-key');
    const raw = (input.value || '').trim();
    try {
      const parsed = JSON.parse(raw);
      const current = configState.config ? configState.config[key] : undefined;
      if (JSON.stringify(parsed) !== JSON.stringify(current)) {
        updates[key] = parsed;
      }
    } catch (e) {
      setText('configMessage', `Invalid JSON for ${key}: ${e}`);
      return;
    }
  }
  if (Object.keys(updates).length === 0) {
    setText('configMessage', 'No configuration changes to save.');
    return;
  }

  try {
    const r = await fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ updates }),
    });
    const j = await r.json();
    if (!r.ok || !j.ok) {
      throw new Error(j.error || `HTTP ${r.status}`);
    }
    setText('configMessage', `Saved ${Object.keys(updates).length} configuration value(s).`);
    await loadConfig();
  } catch (e) {
    setText('configMessage', `Save failed: ${e}`);
  }
}

let configState = {
  config: {},
  schema: {},
};

function configValueToEditor(value) {
  return JSON.stringify(value);
}

function renderConfigSections(schema, config) {
  const root = document.getElementById('configSections');
  if (!root) return;
  const sectionNames = Object.keys(schema || {});
  if (sectionNames.length === 0) {
    root.innerHTML = '<div class="empty-state card"><p>No configuration schema available.</p></div>';
    return;
  }

  root.innerHTML = sectionNames.map((section) => {
    const items = schema[section] || [];
    const rows = items.map((item) => {
      const key = item.key;
      const current = Object.prototype.hasOwnProperty.call(config, key) ? config[key] : null;
      const currentRaw = configValueToEditor(current);
      const defaultRaw = configValueToEditor(item.default);
      return `
        <tr>
          <td class="mono">${key}</td>
          <td>${item.description || '(no description)'}</td>
          <td class="mono">${defaultRaw}</td>
          <td><input class="config-editor mono" data-config-key="${key}" value="${currentRaw.replace(/"/g, '&quot;')}" /></td>
        </tr>
      `;
    }).join('');
    return `
      <section class="config-section card">
        <div class="section-header compact">
          <div>
            <h3>${section}</h3>
          </div>
        </div>
        <div class="table-wrap">
          <table class="conn-table">
            <thead>
              <tr>
                <th>Key</th>
                <th>Description</th>
                <th>Default</th>
                <th>Current (JSON)</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </section>
    `;
  }).join('');
}

async function loadLogs() {
  try {
    const r = await fetch('/api/logs?limit=500', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    const lines = Array.isArray(j.lines) ? j.lines : [];
    const box = document.getElementById('debugLogs');
    if (box) box.textContent = lines.join('\n');
  } catch (e) {
    const box = document.getElementById('debugLogs');
    if (box) box.textContent = 'debug logs load failed: ' + e;
  }
}

function initTabs() {
  const tabs = document.querySelectorAll('.nav-tab');
  const panels = document.querySelectorAll('.tab-panel');
  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const target = tab.dataset.tab;
      tabs.forEach((t) => t.classList.toggle('active', t === tab));
      panels.forEach((p) => p.classList.toggle('active', p.id === `tab-${target}`));
    });
  });
}

function initMetaToggle() {
  const btn = document.getElementById('toggleMetaBtn');
  const meta = document.getElementById('meta');
  if (!btn || !meta) return;
  btn.addEventListener('click', () => {
    meta.classList.toggle('collapsed');
  });
}

document.getElementById('restartBtn').addEventListener('click', restart);
document.getElementById('configReloadBtn')?.addEventListener('click', loadConfig);
document.getElementById('configSaveBtn')?.addEventListener('click', saveConfig);
document.getElementById('logsReloadBtn')?.addEventListener('click', loadLogs);
initTabs();
initMetaToggle();
loadMeta();
loadStatus();
loadConnections();
loadPeers();
loadConfig();
loadLogs();
setInterval(loadStatus, 1000);
setInterval(loadConnections, 1000);
setInterval(loadPeers, 1000);
setInterval(loadMeta, 5000);
setInterval(loadConfig, 5000);
setInterval(loadLogs, 2000);
