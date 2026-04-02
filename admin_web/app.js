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

const APP_BASE_TITLE = 'ObstacleBridge';

const authState = {
  required: false,
  authenticated: false,
  appStarted: false,
};

const restartState = {
  active: false,
  reloadAtMs: 0,
  intervalId: null,
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

function startRestartCountdown(durationSec = 30) {
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

async function sha256Hex(text) {
  const digest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
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

function applyPeerState(state) {
  const badge = document.getElementById('peerStateBadge');
  const normalized = String(state || 'UNKNOWN').toUpperCase();
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
    const r = await apiFetch('/api/meta', { cache: 'no-store' });
    const j = await r.json();
    applyAdminInstanceName(j.admin_web_name);
    setText('uptimeSec', fmtUptime(j.uptime_sec));
    const meta = document.getElementById('meta');
    if (meta) meta.textContent = JSON.stringify(j, null, 2);
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
    startRestartCountdown(30);
  } catch (e) {
    window.alert(`Restart failed: ${e}`);
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

async function loadStatus() {
  try {
    const r = await apiFetch('/api/status', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    applyAdminInstanceName(j.admin_web_name);
    setText('uptimeSec', fmtUptime(j.uptime_sec));

    applyPeerState(j.peer_state);
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

    const errors = j.decode_errors?.unidentified_frames ?? 0;

    setText('decodeErrors', fmtInteger(errors));
  } catch (e) {
    console.error('status load failed', e);
  }
}

function renderPeerTable(rows) {
  const tbody = document.getElementById('peerConnectionsBody');
  if (!tbody) return;
  if (!rows || rows.length === 0) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="17">No peer sessions</td></tr>';
    return;
  }
  const fmtMyUdpMetric = (row, value) => {
    const transport = String(row.transport || '').toLowerCase();
    if (transport !== 'myudp') return 'n/a';
    return fmtInteger(value);
  };
  tbody.innerHTML = rows.map((row) => `
    <tr>
      <td class="mono">${fmtInteger(row.id)}</td>
      <td class="mono">${row.transport || 'n/a'}</td>
      <td class="mono">${row.listen || 'n/a'}</td>
      <td><span class="${(row.connected ? 'role-pill role-server' : 'role-pill role-unknown')}">${row.connected ? 'yes' : 'no'}</span></td>
      <td class="mono">${row.peer || 'n/a'}</td>
      <td class="mono">${fmtNumber(row.rtt_est_ms)}</td>
      <td class="mono">${fmtInteger(row.open_connections?.udp ?? 0)}</td>
      <td class="mono">${fmtInteger(row.open_connections?.tcp ?? 0)}</td>
      <td class="mono">${fmtBytes(row.traffic?.rx_bytes ?? 0)}</td>
      <td class="mono">${fmtBytes(row.traffic?.tx_bytes ?? 0)}</td>
      <td class="mono">${fmtInteger(row.decode_errors ?? 0)}</td>
      <td class="mono">${fmtMyUdpMetric(row, row.myudp?.buffered_frames)}</td>
      <td class="mono">${fmtInteger(row.inflight)}</td>
      <td class="mono">${fmtMyUdpMetric(row, row.myudp?.confirmed_total)}</td>
      <td class="mono">${fmtMyUdpMetric(row, row.myudp?.first_pass)}</td>
      <td class="mono">${fmtMyUdpMetric(row, row.myudp?.repeated_once)}</td>
      <td class="mono">${fmtMyUdpMetric(row, row.myudp?.repeated_multiple)}</td>
    </tr>
  `).join('');
}

async function loadConnections() {
  try {
    const r = await apiFetch('/api/connections', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();

    renderConnectionTable('udpConnectionsBody', j.udp || []);
    renderConnectionTable('tcpConnectionsBody', j.tcp || []);
    setText('udpOpen', fmtInteger(j.counts?.udp ?? (j.udp || []).length));
    setText('tcpOpen', fmtInteger(j.counts?.tcp ?? (j.tcp || []).length));
    setText('udpListening', fmtInteger(j.counts?.udp_listening ?? 0));
    setText('tcpListening', fmtInteger(j.counts?.tcp_listening ?? 0));
  } catch (e) {
    console.error('connections load failed', e);
  }
}

async function loadPeers() {
  try {
    const r = await apiFetch('/api/peers', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    renderPeerTable(j.peers || []);
  } catch (e) {
    console.error('peers load failed', e);
  }
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

  try {
    const r = await apiFetch('/api/config', {
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

function renderSecretInput(key) {
  return `<input type="password" class="config-editor mono" data-config-key="${key}" data-secret="true" placeholder="Leave blank to keep current value" autocomplete="new-password" data-lpignore="true" data-1p-ignore="true" />`;
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
      if (!isApiEnabled()) return;
      if (target === 'status') {
        loadConnections();
        loadPeers();
      }
      if (target === 'misc') {
        loadMeta();
      }
    });
  });
}

async function loginAdmin(event) {
  event?.preventDefault();
  const username = (document.getElementById('authUsername')?.value || '').trim();
  const password = document.getElementById('authPassword')?.value || '';
  if (!username || !password) {
    setAuthMessage('Username and password are required.');
    return;
  }
  if (!window.crypto?.subtle) {
    setAuthMessage('Browser crypto support is required for login.');
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
  authState.authenticated = false;
  updateAuthUi();
  setAuthMessage('Signed out.');
}

async function startAdminApp() {
  if (!authState.appStarted) {
    authState.appStarted = true;
    loadStatus();
    loadConnections();
    loadPeers();
    loadConfig();
    startPolling(loadStatus, 1000);
    startPolling(async () => {
      if (!isTabActive('status')) return;
      await loadConnections();
    }, 1000);
    startPolling(async () => {
      if (!isTabActive('status')) return;
      await loadPeers();
    }, 1000);
    startPolling(async () => {
      if (!isTabActive('misc')) return;
      await loadMeta();
    }, 5000);
    return;
  }
  if (isTabActive('status')) {
    await loadStatus();
    await loadConnections();
    await loadPeers();
    return;
  }
  if (isTabActive('configuration')) {
    await loadConfig();
    return;
  }
  if (isTabActive('misc')) {
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
document.getElementById('configReloadBtn')?.addEventListener('click', loadConfig);
document.getElementById('configSaveBtn')?.addEventListener('click', saveConfig);
document.getElementById('logsReloadBtn')?.addEventListener('click', loadLogs);
document.getElementById('authForm')?.addEventListener('submit', loginAdmin);
initTabs();
initMetaToggle();
updateAuthUi();
bootstrapAdmin();
