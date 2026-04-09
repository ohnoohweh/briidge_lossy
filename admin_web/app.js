function fmtNumber(value, digits = 1) {
  if (value == null || Number.isNaN(value)) return 'n/a';
  return Number(value).toFixed(digits);
}

function fmtInteger(value) {
  if (value == null || Number.isNaN(value)) return 'n/a';
  return String(value);
}
function fmtChan(value) {
  if (value == null || Number.isNaN(value)) return '-';
  return String(value);
}
function fmtConnectionId(value) {
  if (value == null || value === '' || Number.isNaN(value)) return '-';
  return String(value);
}

function fmtPeerCompositeId(transport, id) {
  const t = String(transport || '').trim();
  const ident = fmtConnectionId(id);
  if (!t) return ident;
  if (!ident || ident === '-') return t;
  return `${t}:${ident}`;
}

function fmtText(value) {
  if (value == null || value === '') return 'n/a';
  return String(value);
}

function fmtBool(value) {
  if (value == null) return 'n/a';
  return value ? 'yes' : 'no';
}

function fmtUnixTs(value) {
  if (value == null || Number.isNaN(value)) return 'n/a';
  return String(value);
}

function fmtDateTime(value) {
  if (value == null || Number.isNaN(value)) return 'n/a';
  const date = new Date(Number(value) * 1000);
  if (Number.isNaN(date.getTime())) return 'n/a';
  return date.toLocaleString([], {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function fmtUptimeFromUnixTs(value) {
  if (value == null || Number.isNaN(value)) return 'n/a';
  return fmtUptime(Math.max(0, Math.floor(Date.now() / 1000 - Number(value))));
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

function fmtAgeSeconds(sec) {
  if (sec == null || Number.isNaN(sec)) return 'n/a';
  return fmtUptime(sec);
}

const APP_BASE_TITLE = 'ObstacleBridge';

const authState = {
  required: false,
  authenticated: false,
  appStarted: false,
  username: '',
};

const restartState = {
  active: false,
  reloadAtMs: 0,
  intervalId: null,
};

const liveState = {
  socket: null,
  reconnectTimerId: null,
  connected: false,
  pollingStarted: false,
  pollingStops: [],
};

const uiState = {
  statusDoc: null,
  securityAdvisorShownOnce: false,
  initialTabApplied: false,
};

function isApiEnabled() {
  return !authState.required || authState.authenticated;
}

function setAuthMessage(message, isOk = false) {
  const el = document.getElementById('authMessage');
  if (!el) return;
  el.textContent = message || '';
  el.classList.toggle('ok', Boolean(message) && isOk);
}

function setConfigGateMessage(message, isOk = false) {
  const el = document.getElementById('configGateMessage');
  if (!el) return;
  el.textContent = message || '';
  el.classList.toggle('ok', Boolean(message) && isOk);
}

const configGateState = {
  resolver: null,
};

function openConfigGate(message) {
  const gate = document.getElementById('configGate');
  const copy = document.getElementById('configGateCopy');
  const passwordInput = document.getElementById('configGatePassword');
  const messageNode = document.getElementById('configGateMessage');
  if (!gate || !copy || !passwordInput || !messageNode) {
    return Promise.resolve(null);
  }
  copy.textContent = message || 'Enter the current admin password to confirm the configuration changes.';
  messageNode.textContent = '';
  passwordInput.value = '';
  gate.classList.remove('hidden');
  document.body.classList.add('config-locked');
  window.setTimeout(() => passwordInput.focus(), 0);
  return new Promise((resolve) => {
    configGateState.resolver = resolve;
  });
}

function closeConfigGate(result = null) {
  const gate = document.getElementById('configGate');
  const passwordInput = document.getElementById('configGatePassword');
  if (gate) gate.classList.add('hidden');
  document.body.classList.remove('config-locked');
  if (passwordInput) passwordInput.value = '';
  const resolver = configGateState.resolver;
  configGateState.resolver = null;
  if (resolver) resolver(result);
}

function browserLoginHashHint() {
  return 'Browser login hashing is unavailable. Use a modern browser with JavaScript enabled.';
}

function updateAuthUi() {
  const locked = authState.required && !authState.authenticated;
  document.body.classList.toggle('auth-locked', locked);
  document.getElementById('authGate')?.classList.toggle('hidden', !locked);
  document.getElementById('logoutBtn')?.classList.toggle('hidden', !authState.required || !authState.authenticated);
}

function updateRestartUi(remainingSec) {
  const active = restartState.active;
  document.body.classList.toggle('restart-locked', active);
  document.getElementById('restartGate')?.classList.toggle('hidden', !active);
  const restartBtn = document.getElementById('restartBtn');
  if (restartBtn) restartBtn.disabled = active;
  const countdown = document.getElementById('restartCountdown');
  if (countdown) countdown.textContent = `${Math.max(0, remainingSec)}s`;
}

function startRestartCountdown(durationSec = 40) {
  if (restartState.intervalId) {
    window.clearInterval(restartState.intervalId);
    restartState.intervalId = null;
  }
  restartState.active = true;
  restartState.reloadAtMs = Date.now() + (durationSec * 1000);

  const tick = () => {
    const remainingMs = restartState.reloadAtMs - Date.now();
    const remainingSec = Math.ceil(remainingMs / 1000);
    updateRestartUi(remainingSec);
    if (remainingMs <= 0) {
      if (restartState.intervalId) {
        window.clearInterval(restartState.intervalId);
        restartState.intervalId = null;
      }
      window.location.reload();
    }
  };

  tick();
  restartState.intervalId = window.setInterval(tick, 200);
}

function handleAuthRequired(message = 'Authentication required.') {
  if (!authState.required) return;
  authState.authenticated = false;
  updateAuthUi();
  setAuthMessage(message);
}

async function apiFetch(url, options = {}) {
  const { authRequest = false, ...fetchOptions } = options;
  const response = await fetch(url, {
    credentials: 'same-origin',
    ...fetchOptions,
  });
  if (response.status === 401 && !authRequest) {
    handleAuthRequired('Session expired. Please sign in again.');
    throw new Error('HTTP 401');
  }
  return response;
}

function sha256RoTR(value, bits) {
  return (value >>> bits) | (value << (32 - bits));
}

function sha256ToHex(words) {
  return words.map((word) => (word >>> 0).toString(16).padStart(8, '0')).join('');
}

function sha256HexFallback(text) {
  const bytes = new TextEncoder().encode(text);
  const length = bytes.length;
  const totalWords = ((((length + 9) + 63) >> 6) << 4);
  const words = new Uint32Array(totalWords);

  for (let i = 0; i < length; i += 1) {
    words[i >> 2] |= bytes[i] << (24 - ((i & 3) << 3));
  }
  words[length >> 2] |= 0x80 << (24 - ((length & 3) << 3));

  const bitLength = length * 8;
  words[totalWords - 2] = Math.floor(bitLength / 0x100000000);
  words[totalWords - 1] = bitLength >>> 0;

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const w = new Uint32Array(64);
  for (let offset = 0; offset < totalWords; offset += 16) {
    for (let i = 0; i < 16; i += 1) {
      w[i] = words[offset + i] >>> 0;
    }
    for (let i = 16; i < 64; i += 1) {
      const s0 = sha256RoTR(w[i - 15], 7) ^ sha256RoTR(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = sha256RoTR(w[i - 2], 17) ^ sha256RoTR(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i += 1) {
      const s1 = sha256RoTR(e, 6) ^ sha256RoTR(e, 11) ^ sha256RoTR(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + s1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const s0 = sha256RoTR(a, 2) ^ sha256RoTR(a, 13) ^ sha256RoTR(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  return sha256ToHex([h0, h1, h2, h3, h4, h5, h6, h7]);
}

const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

async function sha256Hex(text) {
  if (window.isSecureContext && window.crypto?.subtle) {
    const digest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  return sha256HexFallback(text);
}

async function fetchAuthState() {
  const r = await apiFetch('/api/auth/state', { cache: 'no-store', authRequest: true });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}

async function refreshAuthState() {
  const state = await fetchAuthState();
  authState.required = Boolean(state.auth_required);
  authState.authenticated = !authState.required || Boolean(state.authenticated);
  updateAuthUi();
  if (!authState.required || authState.authenticated) {
    setAuthMessage('');
  }
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function applyAdminInstanceName(name) {
  const trimmed = String(name || '').trim();
  const fullTitle = trimmed ? `${APP_BASE_TITLE} ${trimmed}` : APP_BASE_TITLE;
  document.title = fullTitle;
  setText('appHeadline', fullTitle);
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
    tbody.innerHTML = `<tr class="empty-row"><td colspan="12">No ${tbodyId.startsWith('udp') ? 'UDP' : 'TCP'} connections</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map((row) => {
    const rxBytes = row.stats?.rx_bytes ?? 0;
    const txBytes = row.stats?.tx_bytes ?? 0;
    const rxMsgs = row.stats?.rx_msgs ?? 0;
    const txMsgs = row.stats?.tx_msgs ?? 0;
    const state = String(row.state || 'connected').toLowerCase();
    const isListening = state === 'listening';
    return `
      <tr>
        <td class="mono">${fmtConnectionId(row.peer_id)}</td>
        <td class="mono">${fmtChan(row.chan_id)}</td>
        <td class="mono">${fmtInteger(row.svc_id)}</td>
        <td><span class="${isListening ? 'role-pill role-unknown' : 'role-pill role-client'}">${state}</span></td>
        <td><span class="${roleClass(row.role)}">${row.role || 'unknown'}</span></td>
        <td class="mono">${isListening ? 'n/a' : fmtEndpoint(row.source)}</td>
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

function detailPillClass(value) {
  const normalized = String(value || '').toLowerCase();
  if (
    normalized.includes('auth')
    || normalized.includes('connect')
    || normalized === 'yes'
    || normalized === 'true'
  ) return 'role-pill role-server';
  if (
    normalized.includes('rekey')
    || normalized.includes('wait')
    || normalized.includes('handshak')
    || normalized.includes('progress')
  ) return 'role-pill role-client';
  if (
    normalized.includes('fail')
    || normalized.includes('reject')
    || normalized.includes('error')
    || normalized === 'no'
    || normalized === 'false'
  ) return 'role-pill role-unknown';
  return 'role-pill role-unknown';
}

function renderMetric(label, value, { pill = false, compact = false } = {}) {
  const renderedValue = pill
    ? `<span class="${detailPillClass(value)}">${escapeHtml(fmtText(value))}</span>`
    : `<span class="peer-detail-value mono">${escapeHtml(fmtText(value))}</span>`;
  return `
    <div class="peer-detail-metric${compact ? ' peer-detail-metric-compact' : ''}">
      <span class="peer-detail-label">${escapeHtml(label)}</span>
      ${renderedValue}
    </div>
  `;
}

function renderMetricLine(metrics) {
  return `
    <div class="peer-detail-line">
      ${metrics.join('')}
    </div>
  `;
}

function renderMetricStack(lines) {
  return `
    <div class="peer-detail-stack">
      ${lines.map((line) => renderMetricLine(line)).join('')}
    </div>
  `;
}

function renderPeerDetailRow(rowLabel, metrics, extraClass = '') {
  return `
    <tr class="peer-detail-row ${extraClass}">
      <td class="peer-detail-kind">${escapeHtml(rowLabel)}</td>
      <td>
        <div class="peer-detail-grid">
          ${metrics.join('')}
        </div>
      </td>
    </tr>
  `;
}

async function loadMeta() {
  try {
    const r = await apiFetch('/api/meta', { cache: 'no-store' });
    const j = await r.json();
    applyMetaDoc(j);
  } catch (e) {
    const meta = document.getElementById('meta');
    if (meta) meta.textContent = 'meta load failed: ' + e;
  }
}

async function restart() {
  try {
    if (restartState.active) return;
    const r = await apiFetch('/api/restart', { method: 'POST' });
    const j = await r.json();
    if (!r.ok || !j.ok) {
      throw new Error(j.error || `HTTP ${r.status}`);
    }
    const delaySec = Math.max(0, Number(j.restart_delay_sec || 0));
    if (delaySec > 0) {
      startRestartCountdown(delaySec);
    }
  } catch (e) {
    window.alert(`Restart failed: ${e}`);
  }
}

function fmtBuildBadge(build) {
  if (!build || !build.available) return 'build unknown';
  const commit = String(build.commit || 'unknown');
  const tracked = Number(build.tracked_changes || 0);
  const untracked = Number(build.untracked_changes || 0);
  if (build.tainted) {
    return `commit ${commit} tainted (${tracked} tracked, ${untracked} untracked)`;
  }
  return `commit ${commit} clean`;
}

async function reconnectOverlay() {
  const reconnectBtn = document.getElementById('reconnectBtn');
  try {
    if (restartState.active) return;
    if (reconnectBtn) reconnectBtn.disabled = true;
    const r = await apiFetch('/api/reconnect', { method: 'POST' });
    const j = await r.json();
    if (!r.ok || !j.ok) {
      throw new Error(j.error || j.reason || `HTTP ${r.status}`);
    }
  } catch (e) {
    window.alert(`Reconnect failed: ${e}`);
  } finally {
    if (reconnectBtn && !restartState.active) reconnectBtn.disabled = false;
  }
}

async function reconnectPeer(peerId, triggerButton = null) {
  const normalizedPeerId = String(peerId || '').trim();
  if (!normalizedPeerId) {
    window.alert('Reconnect failed: missing peer id');
    return;
  }
  const buttons = Array.from(document.querySelectorAll('.peer-reconnect-btn'));
  try {
    buttons.forEach((button) => {
      button.disabled = true;
    });
    const r = await apiFetch('/api/reconnect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ peer_id: normalizedPeerId }),
    });
    const j = await r.json();
    if (!r.ok || !j.ok) {
      throw new Error(j.error || j.reason || `HTTP ${r.status}`);
    }
  } catch (e) {
    window.alert(`Reconnect failed: ${e}`);
  } finally {
    buttons.forEach((button) => {
      button.disabled = false;
    });
    if (triggerButton instanceof HTMLElement) {
      triggerButton.blur();
    }
  }
}

async function requestSecureLinkRekey(peerId) {
  const normalizedPeerId = String(peerId || '').trim();
  if (!normalizedPeerId) {
    window.alert('Rekey request failed: missing peer id');
    return;
  }
  const buttons = Array.from(document.querySelectorAll('.secure-link-rekey-btn'));
  try {
    buttons.forEach((button) => {
      button.disabled = true;
    });
    const r = await apiFetch('/api/secure-link/rekey', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ peer_id: normalizedPeerId }),
    });
    const j = await r.json();
    if (!r.ok || !j.ok) {
      throw new Error(j.error || `HTTP ${r.status}`);
    }
  } catch (e) {
    window.alert(`Rekey request failed: ${e}`);
  } finally {
    buttons.forEach((button) => {
      button.disabled = false;
    });
  }
}

async function requestSecureLinkReload(scope) {
  const normalizedScope = String(scope || '').trim();
  if (!normalizedScope) {
    window.alert('Secure-link reload failed: missing scope');
    return;
  }
  const buttons = [
    document.getElementById('secureLinkReloadRevocationBtn'),
    document.getElementById('secureLinkReloadIdentityBtn'),
    document.getElementById('secureLinkReloadAllBtn'),
  ].filter(Boolean);
  try {
    buttons.forEach((button) => {
      button.disabled = true;
    });
    const r = await apiFetch('/api/secure-link/reload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scope: normalizedScope }),
    });
    const j = await r.json();
    if (!r.ok || !j.ok) {
      throw new Error(j.error || j.reason || `HTTP ${r.status}`);
    }
  } catch (e) {
    window.alert(`Secure-link reload failed: ${e}`);
  } finally {
    buttons.forEach((button) => {
      button.disabled = false;
    });
  }
}

async function exitProgram() {
  const confirmed = window.confirm('Exit the program now?');
  if (!confirmed) return;
  const r = await apiFetch('/api/shutdown', { method: 'POST' });
  const j = await r.json();
  alert(JSON.stringify(j));
}

function sleep(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function startPolling(task, intervalMs) {
  let stopped = false;

  async function tick() {
    while (!stopped) {
      if (!isApiEnabled()) {
        await sleep(intervalMs);
        continue;
      }
      const startedAt = Date.now();
      try {
        await task();
      } catch (e) {
        console.error('poll task failed', e);
      }
      const elapsedMs = Date.now() - startedAt;
      const waitMs = Math.max(0, intervalMs - elapsedMs);
      await sleep(waitMs);
    }
  }

  tick();
  return () => {
    stopped = true;
  };
}

function isTabActive(tabName) {
  const panel = document.getElementById(`tab-${tabName}`);
  return Boolean(panel && panel.classList.contains('active'));
}

function setActiveTab(tabName) {
  const tabs = document.querySelectorAll('.nav-tab');
  const panels = document.querySelectorAll('.tab-panel');
  tabs.forEach((tab) => tab.classList.toggle('active', tab.dataset.tab === tabName));
  panels.forEach((panel) => panel.classList.toggle('active', panel.id === `tab-${tabName}`));
  updateLiveSubscriptions();
}

function advisorSeverityClass(value) {
  const normalized = String(value || 'informational').toLowerCase();
  if (normalized === 'critical') return 'severity-critical';
  if (normalized === 'warning') return 'severity-warning';
  if (normalized === 'recommended') return 'severity-recommended';
  return 'severity-informational';
}

function renderSecurityAdvisorMarkup(statusDoc, findingsElementId, summaryElementId) {
  const summary = document.getElementById(summaryElementId);
  const findingsRoot = document.getElementById(findingsElementId);
  const advisor = statusDoc?.security_advisor || {};
  if (!summary || !findingsRoot) return;
  summary.textContent = String(advisor.summary || 'Current security posture and recommended next steps.');
  const findings = Array.isArray(advisor.findings) ? advisor.findings : [];
  if (findings.length === 0) {
    findingsRoot.innerHTML = '<div class="advisor-item severity-informational"><div class="advisor-item-top"><h3>No immediate findings</h3><span class="advisor-severity severity-informational">ok</span></div><p>No startup security recommendations are active in this first implementation slice.</p></div>';
    return;
  }
  findingsRoot.innerHTML = findings.map((item) => {
    const severity = advisorSeverityClass(item.severity);
    const title = escapeHtml(fmtText(item.title));
    const message = escapeHtml(fmtText(item.message));
    const actionLabel = String(item.action_label || '').trim();
    const actionTarget = String(item.action_target || '').trim();
    return `
      <article class="advisor-item ${severity}">
        <div class="advisor-item-top">
          <h3>${title}</h3>
          <span class="advisor-severity ${severity}">${escapeHtml(fmtText(item.severity))}</span>
        </div>
        <p>${message}</p>
        ${actionLabel && actionTarget ? `<button class="btn btn-secondary" type="button" data-open-tab="${escapeHtml(actionTarget)}">${escapeHtml(actionLabel)}</button>` : ''}
      </article>
    `;
  }).join('');
}

function openSecurityAdvisorGate() {
  const gate = document.getElementById('securityAdvisorGate');
  if (!gate) return;
  gate.classList.remove('hidden');
  document.body.classList.add('config-locked');
}

function closeSecurityAdvisorGate() {
  const gate = document.getElementById('securityAdvisorGate');
  if (!gate) return;
  gate.classList.add('hidden');
  document.body.classList.remove('config-locked');
}

function maybeOpenSecurityAdvisor(statusDoc) {
  if (uiState.securityAdvisorShownOnce) return;
  const advisor = statusDoc?.security_advisor || {};
  const adminUi = statusDoc?.admin_ui || {};
  const findings = Array.isArray(advisor.findings) ? advisor.findings : [];
  if (!advisor.enabled || !adminUi.security_advisor_startup_enabled || findings.length === 0) return;
  uiState.securityAdvisorShownOnce = true;
  renderSecurityAdvisorMarkup(statusDoc, 'securityAdvisorGateFindings', 'securityAdvisorGateSummary');
  openSecurityAdvisorGate();
}

function renderHomeTab(statusDoc) {
  const summary = document.getElementById('homeSummary');
  const button = document.getElementById('openSecurityAdvisorBtn');
  const openStatusCheckbox = document.getElementById('homeOpenStatusOnStartup');
  const adminUi = statusDoc?.admin_ui || {};
  const homeEnabled = Boolean(adminUi.home_tab_enabled);
  const homePanel = document.getElementById('tab-home');
  const homeNav = document.querySelector('.nav-tab[data-tab="home"]');
  if (homePanel) homePanel.classList.toggle('hidden', !homeEnabled);
  if (homeNav) homeNav.classList.toggle('hidden', !homeEnabled);
  if (openStatusCheckbox) {
    openStatusCheckbox.checked = String(adminUi.first_tab || 'home').toLowerCase() === 'status';
  }
  if (!summary || !button) return;
  const advisor = statusDoc?.security_advisor || {};
  const findings = Array.isArray(advisor.findings) ? advisor.findings : [];
  if (!advisor.enabled) {
    summary.textContent = 'Security Advisor is disabled. Setup and troubleshooting helpers can live here as they grow.';
    button.disabled = true;
    return;
  }
  if (findings.length === 0) {
    summary.textContent = 'No immediate Security Advisor findings are active right now. You can reopen the advisor to confirm the current posture any time.';
  } else {
    summary.textContent = String(advisor.summary || 'You can reopen the Security Advisor any time from this Home tab.');
  }
  button.disabled = false;
}

async function loadStatus() {
  try {
    const r = await apiFetch('/api/status', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    applyStatusDoc(j);
  } catch (e) {
    console.error('status load failed', e);
  }
}

function renderPeerTable(rows) {
  const tbody = document.getElementById('peerConnectionsBody');
  if (!tbody) return;
  if (!rows || rows.length === 0) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="3">No peer sessions</td></tr>';
    return;
  }
  const fmtMyUdpMetric = (row, value) => {
    const transport = String(row.transport || '').toLowerCase();
    if (transport !== 'myudp') return 'n/a';
    return fmtInteger(value);
  };
  tbody.innerHTML = rows.map((row) => {
    const transport = String(row.transport || '').toLowerCase();
    const isMyUdp = transport === 'myudp';
    const isListeningPeer = String(row.state || '').toLowerCase() === 'listening';
    const isConnectingPeer = String(row.state || '').toLowerCase() === 'connecting';
    const secureLink = row.secure_link || {};
    const secureLinkEnabled = Boolean(secureLink.enabled);
    const secureLinkMode = String(secureLink.mode || '').toLowerCase();
    const isCertMode = secureLinkMode === 'cert';
    const trustFailureReason = String(secureLink.trust_failure_reason || '').trim();
    const trustFailureDetail = String(secureLink.trust_failure_detail || '').trim();
    const showSecurityLifecycle = secureLinkEnabled && !isListeningPeer && !isConnectingPeer;
    const showMyUdpProtocolStats = isMyUdp;
    const showMyUdpDetailStats = isMyUdp;
    const stateText = String(row.state || 'unknown').toLowerCase();
    const connectionLine1 = [
      `
      <div class="peer-state-control">
        <div class="peer-detail-metric">
          <span class="peer-detail-label">State</span>
          <span class="${detailPillClass(stateText)}">${escapeHtml(fmtText(stateText))}</span>
        </div>
        ${!isListeningPeer ? `<button class="btn btn-secondary peer-reconnect-btn" type="button" data-peer-id="${escapeHtml(fmtText(row.id))}">Reconnect</button>` : ''}
      </div>
      `,
    ];
    if (isListeningPeer) {
      connectionLine1.push(renderMetric('Listen', row.listen));
    } else {
      connectionLine1.push(renderMetric('Peer', row.peer));
    }
    const connectionLines = [connectionLine1];
    if (!isListeningPeer && isConnectingPeer) {
      connectionLines.push([
        renderMetric('Last Incoming', fmtAgeSeconds(row.last_incoming_age_seconds)),
      ]);
    }
    if (!isListeningPeer && !isConnectingPeer) {
      connectionLines.push([
        renderMetric('UDP Open', fmtInteger(row.open_connections?.udp ?? 0)),
        renderMetric('TCP Open', fmtInteger(row.open_connections?.tcp ?? 0)),
      ]);
      connectionLines.push([
        renderMetric('Connection Uptime', fmtUptimeFromUnixTs(secureLink.connected_since_unix_ts)),
        renderMetric('Last Incoming', fmtAgeSeconds(row.last_incoming_age_seconds)),
        renderMetric('RX Bytes', fmtBytes(row.traffic?.rx_bytes ?? 0)),
        renderMetric('RTT Est (ms)', fmtNumber(row.rtt_est_ms)),
        renderMetric('TX Bytes', fmtBytes(row.traffic?.tx_bytes ?? 0)),
      ]);
    }
    const connectionMetrics = renderMetricStack(connectionLines);
    const showProtocolRow = !isListeningPeer && !isConnectingPeer;
    const protocolMetrics = showMyUdpProtocolStats
      ? renderMetricStack([
        [
          renderMetric('Decode Errors', fmtInteger(row.decode_errors ?? 0)),
          renderMetric('Buffered Frames', fmtMyUdpMetric(row, row.myudp?.buffered_frames)),
          renderMetric('Inflight', fmtInteger(row.inflight)),
        ],
        [
          renderMetric('myUDP Confirmed Total', fmtMyUdpMetric(row, row.myudp?.confirmed_total)),
          renderMetric('myUDP First Pass', fmtMyUdpMetric(row, row.myudp?.first_pass)),
          renderMetric('myUDP Repeated Once', fmtMyUdpMetric(row, row.myudp?.repeated_once)),
          renderMetric('myUDP Repeated Multiple', fmtMyUdpMetric(row, row.myudp?.repeated_multiple)),
        ],
      ])
      : renderMetricStack([
        [
          renderMetric('Decode Errors', fmtInteger(row.decode_errors ?? 0)),
        ],
      ]);
    const securityLines = [];
    if (showSecurityLifecycle) {
      securityLines.push([
        renderMetric('secure_link.state', secureLink.state, { pill: true }),
        renderMetric('secure_link.authenticated', fmtBool(secureLink.authenticated), { pill: true }),
        renderMetric('session_id', fmtInteger(secureLink.session_id)),
      ]);
      if (isCertMode) {
        securityLines.push([
          renderMetric('peer_subject_id', secureLink.peer_subject_id),
          renderMetric('peer_subject_name', secureLink.peer_subject_name),
          renderMetric('peer_roles', Array.isArray(secureLink.peer_roles) && secureLink.peer_roles.length ? secureLink.peer_roles.join(', ') : 'n/a'),
        ]);
        securityLines.push([
          renderMetric('peer_deployment_id', secureLink.peer_deployment_id),
          renderMetric('peer_serial', secureLink.peer_serial),
          renderMetric('issuer_id', secureLink.issuer_id),
        ]);
        securityLines.push([
          renderMetric('trust_validation_state', secureLink.trust_validation_state, { pill: true }),
          renderMetric('trust_anchor_id', secureLink.trust_anchor_id),
        ]);
        if (trustFailureReason || trustFailureDetail) {
          securityLines.push([
            renderMetric('trust_failure_reason', trustFailureReason || 'n/a', { pill: true }),
            renderMetric('trust_failure_detail', trustFailureDetail || 'n/a'),
          ]);
        }
      }
    }
    const securityMetrics = showSecurityLifecycle ? renderMetricStack(securityLines) : '';
    const allowRekeyAction = String(row.state || '').toLowerCase() !== 'listening';
    const lifecycleMetrics = showSecurityLifecycle ? [
      renderMetric('last_event', secureLink.last_event),
      renderMetric('last_event_unix_ts', fmtDateTime(secureLink.last_event_unix_ts)),
      renderMetric('last_authenticated_unix_ts', fmtDateTime(secureLink.last_authenticated_unix_ts)),
      renderMetric('authenticated_sessions_total', fmtInteger(secureLink.authenticated_sessions_total)),
      renderMetric('rekeys_completed_total', fmtInteger(secureLink.rekeys_completed_total)),
      renderMetric('last_rekey_trigger', secureLink.last_rekey_trigger),
      ...(isCertMode ? [
        renderMetric('active_material_generation', fmtInteger(secureLink.active_material_generation)),
        renderMetric('last_material_reload_unix_ts', fmtDateTime(secureLink.last_material_reload_unix_ts)),
        renderMetric('last_material_reload_scope', secureLink.last_material_reload_scope),
        renderMetric('last_material_reload_result', secureLink.last_material_reload_result),
        renderMetric('last_material_reload_detail', secureLink.last_material_reload_detail),
        renderMetric('trust_enforced_unix_ts', fmtDateTime(secureLink.trust_enforced_unix_ts)),
        renderMetric('disconnect_reason', secureLink.disconnect_reason),
        renderMetric('disconnect_detail', secureLink.disconnect_detail),
      ] : []),
    ] : [];
    const rowSpan = showSecurityLifecycle ? 4 : ((isListeningPeer || isConnectingPeer) ? 1 : 2);
    const detailRows = [
      `
      <tr class="peer-detail-row peer-detail-row-start ${(isListeningPeer || isConnectingPeer) ? 'peer-detail-row-end' : ''}">
        <td class="mono peer-id-cell" rowspan="${rowSpan}">${escapeHtml(fmtPeerCompositeId(row.transport, row.id))}</td>
        <td class="peer-detail-kind">Connection</td>
        <td>${connectionMetrics}</td>
      </tr>
      `,
    ];
    if (showProtocolRow) {
      detailRows.push(`
      <tr class="peer-detail-row ${showSecurityLifecycle ? '' : 'peer-detail-row-end'}">
        <td class="peer-detail-kind">Protocol</td>
        <td>${protocolMetrics}</td>
      </tr>
      `);
    }
    if (showSecurityLifecycle) {
      detailRows.push(`
      <tr class="peer-detail-row ">
        <td class="peer-detail-kind">Security</td>
        <td>
          <div class="peer-detail-stack">
            ${securityMetrics}
            ${allowRekeyAction ? `
              <div class="peer-detail-rekey-row">
                ${renderMetric('Rekey in progress', secureLink.rekey_in_progress, { pill: true, compact: true })}
                <button class="btn btn-secondary secure-link-rekey-btn" type="button" data-peer-id="${escapeHtml(fmtText(row.id))}">Rekey Request</button>
              </div>
            ` : ''}
          </div>
        </td>
      </tr>
      `);
      detailRows.push(renderPeerDetailRow('Lifecycle', lifecycleMetrics, 'peer-detail-row-end'));
    }
    return `
      ${detailRows.join('')}
    `;
  }).join('');
}

async function loadConnections() {
  try {
    const r = await apiFetch('/api/connections', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    applyConnectionsDoc(j);
  } catch (e) {
    console.error('connections load failed', e);
  }
}

async function loadPeers() {
  try {
    const r = await apiFetch('/api/peers', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    applyPeersDoc(j);
  } catch (e) {
    console.error('peers load failed', e);
  }
}

function applyMetaDoc(j) {
  applyAdminInstanceName(j.admin_web_name);
  setText('uptimeSec', fmtUptime(j.uptime_sec));
  const badge = document.getElementById('buildBadge');
  if (badge) {
    badge.textContent = fmtBuildBadge(j.build || {});
    badge.classList.toggle('build-tainted', Boolean(j.build?.tainted));
  }
  const meta = document.getElementById('meta');
  if (meta) meta.textContent = JSON.stringify(j, null, 2);
}

function applyStatusDoc(j) {
  uiState.statusDoc = j || {};
  if (!uiState.initialTabApplied) {
    uiState.initialTabApplied = true;
    const preferredTab = String(j?.admin_ui?.first_tab || 'home').toLowerCase();
    setActiveTab(preferredTab);
  }
  applyAdminInstanceName(j.admin_web_name);
  const badge = document.getElementById('buildBadge');
  if (badge) {
    badge.textContent = fmtBuildBadge(j.build || {});
    badge.classList.toggle('build-tainted', Boolean(j.build?.tainted));
  }
  renderHomeTab(j);
  maybeOpenSecurityAdvisor(j);
  setText('uptimeSec', fmtUptime(j.uptime_sec));
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
  setText('secureLinkMaterialGeneration', fmtInteger(j.secure_link_material_generation));
  setText('secureLinkLastReloadUnixTs', fmtDateTime(j.secure_link_last_reload_unix_ts));
  setText('secureLinkLastReloadScope', fmtText(j.secure_link_last_reload_scope));
  setText('secureLinkLastReloadResult', fmtText(j.secure_link_last_reload_result));
  setText('secureLinkLastReloadDetail', fmtText(j.secure_link_last_reload_detail));
  setText('secureLinkPeersDroppedTotal', fmtInteger(j.secure_link_peers_dropped_total));

  const errors = j.decode_errors?.unidentified_frames ?? 0;
  setText('decodeErrors', fmtInteger(errors));
}

function applyConnectionsDoc(j) {
  renderConnectionTable('udpConnectionsBody', j.udp || []);
  renderConnectionTable('tcpConnectionsBody', j.tcp || []);
  setText('udpOpen', fmtInteger(j.counts?.udp ?? (j.udp || []).length));
  setText('tcpOpen', fmtInteger(j.counts?.tcp ?? (j.tcp || []).length));
  setText('udpListening', fmtInteger(j.counts?.udp_listening ?? 0));
  setText('tcpListening', fmtInteger(j.counts?.tcp_listening ?? 0));
}

function applyPeersDoc(j) {
  renderPeerTable(j.peers || []);
}

async function loadConfig() {
  try {
    const r = await apiFetch('/api/config', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    configState = {
      config: j.config || {},
      schema: j.schema || {},
    };
    applyAdminInstanceName(configState.config.admin_web_name);
    renderConfigSections(configState.schema, configState.config);
    setText('configMessage', '');
  } catch (e) {
    setText('configMessage', 'config load failed: ' + e);
  }
}

async function saveConfigUpdates(updates, successMessage) {
  try {
    const challengeResp = await apiFetch('/api/config/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ updates }),
    });
    const challengeDoc = await challengeResp.json();
    if (!challengeResp.ok || !challengeDoc.ok) {
      throw new Error(challengeDoc.error || `HTTP ${challengeResp.status}`);
    }

    const payload = { updates };
    if (challengeDoc.auth_required) {
      const username = String(configState.config?.admin_web_username || authState.username || '').trim();
      if (!username) {
        throw new Error('admin username is required to confirm configuration changes');
      }
      const password = await openConfigGate(
        `Enter the current admin password to confirm ${Object.keys(updates).length} configuration change(s).`
      );
      if (password == null) {
        setText('configMessage', 'Configuration save canceled.');
        return;
      }
      const proof = await sha256Hex(`${String(challengeDoc.seed || '')}:${username}:${password}:${String(challengeDoc.updates_digest || '')}`);
      payload.challenge_id = String(challengeDoc.challenge_id || '');
      payload.proof = proof;
    }

    const r = await apiFetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const j = await r.json();
    if (!r.ok || !j.ok) {
      throw new Error(j.error || `HTTP ${r.status}`);
    }
    setText('configMessage', successMessage || `Saved ${Object.keys(updates).length} configuration value(s).`);
    await loadConfig();
    return true;
  } catch (e) {
    setText('configMessage', `Save failed: ${e}`);
    return false;
  }
}

async function saveConfig() {
  const editors = Array.from(document.querySelectorAll('.config-editor[data-config-key]'));
  if (editors.length === 0) return;

  const updates = {};
  for (const input of editors) {
    const key = input.getAttribute('data-config-key');
    const isSecret = input.getAttribute('data-secret') === 'true';
    if (isSecret) {
      const nextValue = input.value || '';
      if (nextValue) {
        updates[key] = nextValue;
      }
      continue;
    }
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
  await saveConfigUpdates(updates, `Saved ${Object.keys(updates).length} configuration value(s).`);
}

async function disableSecurityAdvisorStartup() {
  const button = document.getElementById('securityAdvisorGateDisableStartupBtn');
  if (button) button.disabled = true;
  try {
    if (!configState.config || Object.keys(configState.config).length === 0) {
      await loadConfig();
    }
    const ok = await saveConfigUpdates(
      { admin_web_security_advisor_startup_disable: true },
      'Security Advisor startup popup disabled and configuration saved.'
    );
    if (ok) {
      if (uiState.statusDoc?.admin_ui) {
        uiState.statusDoc.admin_ui.security_advisor_startup_enabled = false;
      }
      closeSecurityAdvisorGate();
    }
  } finally {
    if (button) button.disabled = false;
  }
}

async function toggleOpenStatusOnStartup(event) {
  const checkbox = event?.target;
  if (!(checkbox instanceof HTMLInputElement)) return;
  checkbox.disabled = true;
  const nextFirstTab = checkbox.checked ? 'status' : 'home';
  try {
    if (!configState.config || Object.keys(configState.config).length === 0) {
      await loadConfig();
    }
    const ok = await saveConfigUpdates(
      { admin_web_first_tab: nextFirstTab },
      `Startup page updated to ${nextFirstTab}.`
    );
    if (ok) {
      if (uiState.statusDoc?.admin_ui) {
        uiState.statusDoc.admin_ui.first_tab = nextFirstTab;
      }
    } else {
      checkbox.checked = !checkbox.checked;
    }
  } finally {
    checkbox.disabled = false;
  }
}

let configState = {
  config: {},
  schema: {},
};

function configValueToEditor(value) {
  return JSON.stringify(value);
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function configValueToPreview(value) {
  if (value == null) return 'null';
  return configValueToEditor(value);
}

function isStructuredConfigValue(value) {
  return Array.isArray(value) || (value != null && typeof value === 'object');
}

function isLongConfigValue(rawValue) {
  return String(rawValue || '').length > 72 || String(rawValue || '').includes('\\n');
}

function renderSecretInput(key, { readonly = false } = {}) {
  const readonlyAttr = readonly ? ' readonly aria-readonly="true"' : '';
  const placeholder = readonly ? 'Read-only secret' : 'Leave blank to keep current value';
  return `<input type="password" class="config-editor mono" data-config-key="${key}" data-secret="true"${readonlyAttr} placeholder="${placeholder}" autocomplete="new-password" data-lpignore="true" data-1p-ignore="true" />`;
}

function renderReadonlySecretValue(key) {
  return `
    <div class="config-value-display config-value-display-readonly" data-config-readonly="${key}">
      <span class="config-value-preview config-secret-value" title="hidden">hidden</span>
    </div>
  `;
}

function renderTextConfigEditor(key, currentValue) {
  const currentRaw = configValueToEditor(currentValue);
  const escapedValue = escapeHtml(currentRaw);
  const multiline = isStructuredConfigValue(currentValue) || isLongConfigValue(currentRaw);
  if (multiline) {
    return `<textarea class="config-editor config-editor-textarea mono" data-config-key="${key}" rows="4" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" data-lpignore="true" data-1p-ignore="true">${escapedValue}</textarea>`;
  }
  return `<input class="config-editor mono" data-config-key="${key}" value="${escapedValue}" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" data-lpignore="true" data-1p-ignore="true" />`;
}

function renderConfigValueCell(item, current) {
  const key = item.key;
  const isSecret = Boolean(item.secret);
  const isReadonly = Boolean(item.readonly);
  const isLevelSetting = isLoggingLevelSetting(key, current, item.default);
  const isLogFileSetting = isLogFileConfigSetting(key);
  const isDirectEntrySetting = isDirectEntryConfigSetting(key);
  const isBooleanSetting = isBooleanConfigSetting(current, item.default);
  const hasChoices = !isLogFileSetting
    && !isDirectEntrySetting
    && Array.isArray(item.choices)
    && item.choices.length > 0;
  const previewText = isSecret ? 'hidden' : configValueToPreview(current);
  const previewClass = isSecret ? 'config-value-preview config-secret-value' : 'config-value-preview mono';
  if (isSecret && isReadonly) {
    return `
      <div class="config-value-cell" data-config-cell="${key}">
        ${renderReadonlySecretValue(key)}
      </div>
    `;
  }
  const editorHtml = isSecret
    ? renderSecretInput(key)
      : hasChoices
        ? renderChoiceSelect(key, current, item.choices)
      : (isBooleanSetting
        ? renderBooleanSelect(key, current)
        : (isLevelSetting
          ? renderLogLevelSelect(key, current)
          : renderTextConfigEditor(key, current)));
  return `
    <div class="config-value-cell" data-config-cell="${key}">
      <button class="config-value-display" type="button" data-config-activate="${key}" aria-label="Edit ${key}">
        <span class="${previewClass}" data-config-preview="${key}" title="${escapeHtml(previewText)}">${escapeHtml(previewText)}</span>
      </button>
      <div class="config-value-editor hidden" data-config-editor-wrap="${key}">
        ${editorHtml}
        <div class="config-inline-actions">
          <button class="btn btn-secondary config-inline-btn" type="button" data-config-cancel="${key}">Cancel</button>
        </div>
      </div>
    </div>
  `;
}

function renderConfigRows(items, config) {
  return (items || []).map((item) => {
    const key = item.key;
    const current = Object.prototype.hasOwnProperty.call(config, key) ? config[key] : null;
    const defaultRaw = configValueToEditor(item.default);
    return `
      <tr data-config-row="${key}">
        <td class="mono">${key}</td>
        <td>${item.description || '(no description)'}</td>
        <td class="mono">${defaultRaw}</td>
        <td>${renderConfigValueCell(item, current)}</td>
      </tr>
    `;
  }).join('');
}

function renderConfigCard(title, rowsHtml) {
  return `
    <section class="config-section card">
      <div class="section-header compact">
        <div>
          <h3>${title}</h3>
        </div>
      </div>
      <div class="table-wrap config-table-wrap">
        <table class="conn-table">
          <thead>
            <tr>
              <th>Key</th>
              <th>Description</th>
              <th>Default</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      </div>
    </section>
  `;
}

function renderConfigSections(schema, config) {
  const root = document.getElementById('configSections');
  if (!root) return;
  const sectionNames = Object.keys(schema || {});
  if (sectionNames.length === 0) {
    root.innerHTML = '<div class="empty-state card"><p>No configuration schema available.</p></div>';
    return;
  }

  const cards = [];

  sectionNames.forEach((section) => {
    const items = schema[section] || [];
    if (items.length > 0) {
      cards.push(renderConfigCard(section, renderConfigRows(items, config)));
    }
  });

  root.innerHTML = cards.join('');
  initConfigEditors();
}

const LOG_LEVEL_OPTIONS = ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'NOTSET'];

function isLogFileConfigSetting(key) {
  const normalizedKey = String(key || '').toLowerCase();
  return normalizedKey === '--log-file'
    || normalizedKey === 'log_file'
    || normalizedKey.endsWith('.--log-file')
    || normalizedKey.endsWith('.log_file');
}

function isDirectEntryConfigSetting(key) {
  const normalizedKey = String(key || '').toLowerCase();
  return normalizedKey === 'log_file_backup_count'
    || normalizedKey === 'log_file_max_bytes'
    || normalizedKey.endsWith('.log_file_backup_count')
    || normalizedKey.endsWith('.log_file_max_bytes');
}

function isLoggingLevelSetting(key, currentValue, defaultValue) {
  const normalizedKey = String(key || '').toLowerCase();
  if (isLogFileConfigSetting(normalizedKey)) return false;
  if (isDirectEntryConfigSetting(normalizedKey)) return false;
  const byName = normalizedKey === 'log'
    || normalizedKey.startsWith('log_')
    || normalizedKey.endsWith('_level');
  if (byName) return true;

  const c = typeof currentValue === 'string' ? currentValue.toUpperCase() : '';
  const d = typeof defaultValue === 'string' ? defaultValue.toUpperCase() : '';
  return LOG_LEVEL_OPTIONS.includes(c) || LOG_LEVEL_OPTIONS.includes(d);
}

function renderLogLevelSelect(key, currentValue) {
  const normalizedCurrent = String(currentValue ?? '').toUpperCase();
  const options = LOG_LEVEL_OPTIONS.map((level) => {
    const selected = level === normalizedCurrent ? ' selected' : '';
    return `<option value="${JSON.stringify(level).replace(/"/g, '&quot;')}"${selected}>${level}</option>`;
  }).join('');
  return `<select class="config-editor mono" data-config-key="${key}" autocomplete="off" data-lpignore="true" data-1p-ignore="true">${options}</select>`;
}

function isBooleanConfigSetting(currentValue, defaultValue) {
  return typeof currentValue === 'boolean' || typeof defaultValue === 'boolean';
}

function renderBooleanSelect(key, currentValue) {
  const normalizedCurrent = Boolean(currentValue);
  const options = [true, false].map((value) => {
    const selected = value === normalizedCurrent ? ' selected' : '';
    return `<option value="${JSON.stringify(value)}"${selected}>${value}</option>`;
  }).join('');
  return `<select class="config-editor mono" data-config-key="${key}" autocomplete="off" data-lpignore="true" data-1p-ignore="true">${options}</select>`;
}

function renderChoiceSelect(key, currentValue, choices) {
  const allowed = Array.isArray(choices) ? choices : [];
  const fallbackChoices = allowed.some((choice) => JSON.stringify(choice) === JSON.stringify(currentValue))
    ? allowed
    : [...allowed, currentValue];
  const options = fallbackChoices.map((choice) => {
    const selected = JSON.stringify(choice) === JSON.stringify(currentValue) ? ' selected' : '';
    const value = JSON.stringify(choice).replace(/"/g, '&quot;');
    const label = typeof choice === 'string' ? choice : JSON.stringify(choice);
    return `<option value="${value}"${selected}>${label}</option>`;
  }).join('');
  return `<select class="config-editor mono" data-config-key="${key}" autocomplete="off" data-lpignore="true" data-1p-ignore="true">${options}</select>`;
}

function setConfigRowEditing(key, editing) {
  const row = document.querySelector(`[data-config-row="${CSS.escape(key)}"]`);
  if (!row) return;
  row.classList.toggle('config-row-editing', editing);
  const editorWrap = row.querySelector(`[data-config-editor-wrap="${CSS.escape(key)}"]`);
  const display = row.querySelector(`[data-config-activate="${CSS.escape(key)}"]`);
  editorWrap?.classList.toggle('hidden', !editing);
  display?.classList.toggle('hidden', editing);
  if (editing) {
    const input = row.querySelector('.config-editor');
    input?.focus();
    if (input?.tagName === 'TEXTAREA') {
      input.selectionStart = input.value.length;
      input.selectionEnd = input.value.length;
    }
  }
}

function resetConfigEditorValue(key) {
  const input = document.querySelector(`.config-editor[data-config-key="${CSS.escape(key)}"]`);
  if (!input) return;
  const isSecret = input.getAttribute('data-secret') === 'true';
  if (isSecret) {
    input.value = '';
    return;
  }
  input.value = configValueToEditor(configState.config ? configState.config[key] : null);
}

function refreshConfigPreview(key) {
  const preview = document.querySelector(`[data-config-preview="${CSS.escape(key)}"]`);
  const input = document.querySelector(`.config-editor[data-config-key="${CSS.escape(key)}"]`);
  const row = document.querySelector(`[data-config-row="${CSS.escape(key)}"]`);
  if (!preview || !input || !row) return;

  const isSecret = input.getAttribute('data-secret') === 'true';
  if (isSecret) {
    const dirty = Boolean(input.value);
    preview.textContent = dirty ? 'updated' : 'hidden';
    preview.title = dirty ? 'updated' : 'hidden';
    row.classList.toggle('config-row-dirty', dirty);
    return;
  }

  const raw = input.value || '';
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (_err) {
    preview.textContent = raw || '(invalid JSON)';
    preview.title = raw || '(invalid JSON)';
    row.classList.add('config-row-invalid');
    row.classList.remove('config-row-dirty');
    return;
  }

  const previewText = configValueToPreview(parsed);
  const current = configState.config ? configState.config[key] : undefined;
  const dirty = JSON.stringify(parsed) !== JSON.stringify(current);
  preview.textContent = previewText;
  preview.title = previewText;
  row.classList.toggle('config-row-dirty', dirty);
  row.classList.remove('config-row-invalid');
}

function initConfigEditors() {
  document.querySelectorAll('[data-config-activate]').forEach((button) => {
    button.addEventListener('click', () => {
      const key = button.getAttribute('data-config-activate');
      if (key) setConfigRowEditing(key, true);
    });
  });

  document.querySelectorAll('[data-config-cancel]').forEach((button) => {
    button.addEventListener('click', () => {
      const key = button.getAttribute('data-config-cancel');
      if (!key) return;
      resetConfigEditorValue(key);
      refreshConfigPreview(key);
      setConfigRowEditing(key, false);
    });
  });

  document.querySelectorAll('.config-editor[data-config-key]').forEach((input) => {
    const key = input.getAttribute('data-config-key');
    if (!key) return;
    const onInput = () => refreshConfigPreview(key);
    input.addEventListener('input', onInput);
    input.addEventListener('change', onInput);
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        resetConfigEditorValue(key);
        refreshConfigPreview(key);
        setConfigRowEditing(key, false);
      }
    });
    if (input.tagName !== 'SELECT') {
      input.addEventListener('blur', () => {
        window.setTimeout(() => {
          const row = document.querySelector(`[data-config-row="${CSS.escape(key)}"]`);
          if (!row) return;
          if (row.contains(document.activeElement)) return;
          setConfigRowEditing(key, false);
        }, 0);
      });
    }
    refreshConfigPreview(key);
  });
}

async function loadLogs() {
  try {
    const r = await apiFetch('/api/logs?limit=500', { cache: 'no-store' });
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
      updateLiveSubscriptions();
      if (!isApiEnabled()) return;
      if (target === 'status' && !liveState.connected) {
        loadConnections();
        loadPeers();
      }
      if (target === 'misc' && !liveState.connected) {
        loadMeta();
      }
    });
  });
}

function buildLiveWsUrl() {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}/api/live`;
}

function currentLiveTopics() {
  const topics = ['status'];
  if (isTabActive('status')) {
    topics.push('connections', 'peers');
  }
  if (isTabActive('misc')) {
    topics.push('meta');
  }
  return topics;
}

function sendLiveMessage(obj) {
  const socket = liveState.socket;
  if (!socket || socket.readyState !== window.WebSocket.OPEN) return;
  socket.send(JSON.stringify(obj));
}

function updateLiveSubscriptions() {
  if (!liveState.connected) return;
  const activeTabs = [];
  if (isTabActive('status')) activeTabs.push('status');
  if (isTabActive('misc')) activeTabs.push('misc');
  sendLiveMessage({
    subscribe: currentLiveTopics(),
    active_tabs: activeTabs,
  });
}

function stopHttpPollingFallback() {
  if (!liveState.pollingStarted) return;
  liveState.pollingStops.forEach((stop) => {
    try {
      stop();
    } catch (e) {
      console.error('poll stop failed', e);
    }
  });
  liveState.pollingStops = [];
  liveState.pollingStarted = false;
}

function startHttpPollingFallback() {
  if (liveState.pollingStarted) return;
  liveState.pollingStarted = true;
  liveState.pollingStops = [
    startPolling(loadStatus, 1000),
    startPolling(async () => {
      if (!isTabActive('status')) return;
      await loadConnections();
    }, 1000),
    startPolling(async () => {
      if (!isTabActive('status')) return;
      await loadPeers();
    }, 1000),
    startPolling(async () => {
      if (!isTabActive('misc')) return;
      await loadMeta();
    }, 5000),
  ];
}

function scheduleLiveReconnect(delayMs = 1500) {
  if (liveState.reconnectTimerId || !isApiEnabled()) return;
  liveState.reconnectTimerId = window.setTimeout(() => {
    liveState.reconnectTimerId = null;
    connectLiveUpdates();
  }, delayMs);
}

function handleLiveMessage(event) {
  let msg;
  try {
    msg = JSON.parse(String(event.data || '{}'));
  } catch (e) {
    console.error('live message parse failed', e);
    return;
  }
  if (msg.type === 'status') {
    applyStatusDoc(msg.data || {});
    return;
  }
  if (msg.type === 'connections') {
    applyConnectionsDoc(msg.data || {});
    return;
  }
  if (msg.type === 'peers') {
    applyPeersDoc(msg.data || {});
    return;
  }
  if (msg.type === 'meta') {
    applyMetaDoc(msg.data || {});
  }
}

function connectLiveUpdates() {
  if (!window.WebSocket) {
    startHttpPollingFallback();
    return;
  }
  const existing = liveState.socket;
  if (existing && (existing.readyState === window.WebSocket.OPEN || existing.readyState === window.WebSocket.CONNECTING)) {
    return;
  }
  try {
    const socket = new window.WebSocket(buildLiveWsUrl());
    liveState.socket = socket;
    socket.addEventListener('open', () => {
      liveState.connected = true;
      stopHttpPollingFallback();
      updateLiveSubscriptions();
      sendLiveMessage({ request: currentLiveTopics() });
    });
    socket.addEventListener('message', handleLiveMessage);
    socket.addEventListener('close', async () => {
      liveState.connected = false;
      if (liveState.socket === socket) {
        liveState.socket = null;
      }
      startHttpPollingFallback();
      try {
        await refreshAuthState();
      } catch (_err) {
        handleAuthRequired('Session expired. Please sign in again.');
      }
      scheduleLiveReconnect();
    });
    socket.addEventListener('error', (e) => {
      console.error('live socket failed', e);
    });
  } catch (e) {
    console.error('live socket init failed', e);
    startHttpPollingFallback();
  }
}

async function loginAdmin(event) {
  event?.preventDefault();
  const username = (document.getElementById('authUsername')?.value || '').trim();
  const password = document.getElementById('authPassword')?.value || '';
  if (!username || !password) {
    setAuthMessage('Username and password are required.');
    return;
  }
  setAuthMessage('Authenticating...', true);
  try {
    const challengeResp = await apiFetch('/api/auth/challenge', { cache: 'no-store', authRequest: true });
    if (!challengeResp.ok) throw new Error('HTTP ' + challengeResp.status);
    const challenge = await challengeResp.json();
    if (!challenge.auth_required) {
      authState.required = false;
      authState.authenticated = true;
      authState.username = username;
      updateAuthUi();
      await startAdminApp();
      return;
    }
    const proof = await sha256Hex(`${String(challenge.seed || '')}:${username}:${password}`);
    const loginResp = await apiFetch('/api/auth/login', {
      method: 'POST',
      authRequest: true,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge_id: String(challenge.challenge_id || ''),
        proof,
      }),
    });
    const loginDoc = await loginResp.json();
    if (!loginResp.ok || !loginDoc.ok) {
      throw new Error(loginDoc.error || `HTTP ${loginResp.status}`);
    }
    document.getElementById('authPassword').value = '';
    authState.required = true;
    authState.authenticated = true;
    authState.username = username;
    updateAuthUi();
    setAuthMessage('');
    await startAdminApp();
  } catch (e) {
    handleAuthRequired(`Login failed: ${e}`);
  }
}

async function logoutAdmin() {
  try {
    await apiFetch('/api/auth/logout', { method: 'POST', authRequest: true });
  } catch (e) {
    console.error('logout failed', e);
  }
  if (liveState.reconnectTimerId) {
    window.clearTimeout(liveState.reconnectTimerId);
    liveState.reconnectTimerId = null;
  }
  if (liveState.socket) {
    liveState.socket.close();
    liveState.socket = null;
  }
  liveState.connected = false;
  startHttpPollingFallback();
  authState.authenticated = false;
  authState.username = '';
  updateAuthUi();
  setAuthMessage('Signed out.');
}

async function startAdminApp() {
  if (!authState.appStarted) {
    authState.appStarted = true;
    loadStatus();
    loadConnections();
    loadPeers();
    loadMeta();
    loadConfig();
    startHttpPollingFallback();
    connectLiveUpdates();
    return;
  }
  connectLiveUpdates();
  if (isTabActive('status')) {
    await loadStatus();
    if (!liveState.connected) {
      await loadConnections();
      await loadPeers();
    }
    return;
  }
  if (isTabActive('configuration')) {
    await loadConfig();
    return;
  }
  if (isTabActive('misc') && !liveState.connected) {
    await loadMeta();
  }
}

async function bootstrapAdmin() {
  try {
    await refreshAuthState();
  } catch (e) {
    handleAuthRequired(`Authentication check failed: ${e}`);
    return;
  }
  if (isApiEnabled()) {
    await startAdminApp();
  } else {
    setAuthMessage('Authentication required.');
  }
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
document.getElementById('logoutBtn')?.addEventListener('click', logoutAdmin);
document.getElementById('exitBtn')?.addEventListener('click', exitProgram);
document.getElementById('secureLinkReloadRevocationBtn')?.addEventListener('click', () => requestSecureLinkReload('revocation'));
document.getElementById('secureLinkReloadIdentityBtn')?.addEventListener('click', () => requestSecureLinkReload('local_identity'));
document.getElementById('secureLinkReloadAllBtn')?.addEventListener('click', () => requestSecureLinkReload('all'));
document.getElementById('configReloadBtn')?.addEventListener('click', loadConfig);
document.getElementById('configSaveBtn')?.addEventListener('click', saveConfig);
document.getElementById('configGateForm')?.addEventListener('submit', (event) => {
  event.preventDefault();
  const passwordInput = document.getElementById('configGatePassword');
  const password = String(passwordInput?.value || '');
  if (!password) {
    setConfigGateMessage('Password is required.');
    return;
  }
  closeConfigGate(password);
});
document.getElementById('configGateCancelBtn')?.addEventListener('click', () => {
  setConfigGateMessage('');
  closeConfigGate(null);
});
document.getElementById('logsReloadBtn')?.addEventListener('click', loadLogs);
document.getElementById('openSecurityAdvisorBtn')?.addEventListener('click', () => {
  if (!uiState.statusDoc) return;
  renderSecurityAdvisorMarkup(uiState.statusDoc, 'securityAdvisorGateFindings', 'securityAdvisorGateSummary');
  openSecurityAdvisorGate();
});
document.getElementById('homeOpenStatusOnStartup')?.addEventListener('change', toggleOpenStatusOnStartup);
document.getElementById('securityAdvisorGateDisableStartupBtn')?.addEventListener('click', disableSecurityAdvisorStartup);
document.getElementById('securityAdvisorGateCloseBtn')?.addEventListener('click', closeSecurityAdvisorGate);
document.getElementById('authForm')?.addEventListener('submit', loginAdmin);
document.getElementById('peerConnectionsBody')?.addEventListener('click', (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (target.classList.contains('peer-reconnect-btn')) {
    reconnectPeer(target.getAttribute('data-peer-id') || '', target);
    return;
  }
  if (!target.classList.contains('secure-link-rekey-btn')) return;
  requestSecureLinkRekey(target.getAttribute('data-peer-id') || '');
});
document.body?.addEventListener('click', (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const tabName = target.getAttribute('data-open-tab');
  if (!tabName) return;
  if (!document.getElementById('securityAdvisorGate')?.classList.contains('hidden')) {
    closeSecurityAdvisorGate();
  }
  setActiveTab(tabName);
  if (!isApiEnabled()) return;
  if (tabName === 'configuration') {
    loadConfig();
    return;
  }
  if (tabName === 'status' && !liveState.connected) {
    loadStatus();
    loadConnections();
    loadPeers();
    return;
  }
  if (tabName === 'misc' && !liveState.connected) {
    loadMeta();
  }
});
initTabs();
initMetaToggle();
updateAuthUi();
bootstrapAdmin();
