function fmtNumber(value, digits = 1) {
  if (value == null || Number.isNaN(value)) return 'n/a';
  return Number(value).toFixed(digits);
}

function fmtInteger(value) {
  if (value == null || Number.isNaN(value)) return 'n/a';
  return String(value);
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
        <td class="mono">${fmtInteger(rxBytes)}</td>
        <td class="mono">${fmtInteger(txBytes)}</td>
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
    setText('overlayBind', j.overlay?.bind ?? 'n/a');
    setText('overlayPeer', j.overlay?.peer ?? 'n/a');
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

    setText('rttEst', fmtNumber(rtt));
    setText('inflight', fmtInteger(inflight));
    setText('sidebarRtt', rtt == null ? 'n/a' : `${fmtNumber(rtt)} ms`);
    setText('sidebarInflight', fmtInteger(inflight));
    setText('decodeErrors', fmtInteger(errors));
    setText('sidebarErrors', fmtInteger(errors));
  } catch (e) {
    console.error('status load failed', e);
  }
}

async function loadConnections() {
  try {
    const r = await fetch('/api/connections', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();

    renderConnectionTable('udpConnectionsBody', j.udp || []);
    renderConnectionTable('tcpConnectionsBody', j.tcp || []);
    document.getElementById('udpOpen').textContent = fmtInteger(j.counts?.udp ?? (j.udp || []).length);
    document.getElementById('tcpOpen').textContent = fmtInteger(j.counts?.tcp ?? (j.tcp || []).length);
    const ts = new Date();
    document.getElementById('connectionsUpdatedAt').textContent =
      `updated ${ts.toLocaleTimeString()}`;
  } catch (e) {
    console.error('connections load failed', e);
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
initTabs();
initMetaToggle();
loadMeta();
loadStatus();
loadConnections();
setInterval(loadStatus, 1000);
setInterval(loadConnections, 1000);
setInterval(loadMeta, 5000);