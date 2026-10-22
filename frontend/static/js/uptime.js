// =========================================================================
// Server Dashboard - Uptime & Monitors + Status Pages Module
// =========================================================================

let uptimeMonitors = [];
let selectedMonitorId = null;
let currentUptimeFilter = 'all';
let uptimeSearchQuery = '';
let uptimeWs = null;
let toastDismissedFor = null;
let currentStatusPage = null;
let allStatusPagesList = [];
let editingMonitorId = null;
let availableSystemDrives = [];

// =========================================================================
// 1. WEBSOCKET CONNECTION & SYNC
// =========================================================================

function initUptimeWebSocket() {
  if (uptimeWs && (uptimeWs.readyState === WebSocket.OPEN || uptimeWs.readyState === WebSocket.CONNECTING)) {
    return;
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/uptime`;

  try {
    uptimeWs = new WebSocket(wsUrl);

    uptimeWs.onmessage = (event) => {
      try {
        const { type, payload } = JSON.parse(event.data);
        if (type === 'INIT') {
          uptimeMonitors = payload.monitors || [];
          if (!selectedMonitorId && uptimeMonitors.length > 0) {
            selectedMonitorId = uptimeMonitors[0].id;
          }
          renderUptimeView();
        } else if (type === 'HEARTBEAT') {
          const idx = uptimeMonitors.findIndex(m => String(m.id) === String(payload.monitorId));
          if (idx !== -1) {
            uptimeMonitors[idx] = payload.monitor;
          } else {
            uptimeMonitors.push(payload.monitor);
          }
          renderUptimeView();
        } else if (type === 'MONITOR_ADDED') {
          uptimeMonitors.push(payload);
          if (!selectedMonitorId) selectedMonitorId = payload.id;
          renderUptimeView();
        } else if (type === 'MONITOR_UPDATED') {
          const idx = uptimeMonitors.findIndex(m => String(m.id) === String(payload.id));
          if (idx !== -1) uptimeMonitors[idx] = payload;
          renderUptimeView();
        } else if (type === 'MONITOR_DELETED') {
          uptimeMonitors = uptimeMonitors.filter(m => String(m.id) !== String(payload.id));
          if (String(selectedMonitorId) === String(payload.id)) {
            selectedMonitorId = uptimeMonitors.length > 0 ? uptimeMonitors[0].id : null;
          }
          renderUptimeView();
        }
      } catch (err) {
        console.error('[Uptime WS] Parse error:', err);
      }
    };

    uptimeWs.onclose = () => {
      setTimeout(() => {
        if (window.currentPage === 'uptime') {
          initUptimeWebSocket();
        }
      }, 3000);
    };
  } catch (e) {
    console.error('[Uptime WS] Connect error:', e);
  }
}

// =========================================================================
// 2. DASHBOARD LOADER
// =========================================================================

async function loadUptimeDashboard() {
  initUptimeWebSocket();
  await fetchSystemDrives();

  try {
    const res = await apiFetch('/api/monitors');
    if (res.ok) {
      uptimeMonitors = await res.json();
      if (!selectedMonitorId && uptimeMonitors.length > 0) {
        selectedMonitorId = uptimeMonitors[0].id;
      }
      renderUptimeView();
    }
  } catch (err) {
    console.error('Failed to load monitors:', err);
  }
}

async function fetchSystemDrives() {
  try {
    const res = await apiFetch('/api/system/drives');
    if (res.ok) {
      availableSystemDrives = await res.json();
    }
  } catch (e) {
    console.error('Failed to fetch system drives:', e);
  }
}

// =========================================================================
// 3. UI RENDERING
// =========================================================================

function renderUptimeView() {
  renderMonitorSidebar();
  renderMonitorDetail();
}

function renderMonitorSidebar() {
  const listEl = document.getElementById('uptimeMonitorList');
  if (!listEl) return;

  const totalCountEl = document.getElementById('uptimeTotalCount');
  const upCountEl = document.getElementById('uptimeUpCount');
  const downCountEl = document.getElementById('uptimeDownCount');
  const pausedCountEl = document.getElementById('uptimePausedCount');

  const total = uptimeMonitors.length;
  const upCount = uptimeMonitors.filter(m => m.status === 'up').length;
  const downCount = uptimeMonitors.filter(m => m.status === 'down').length;
  const pausedCount = uptimeMonitors.filter(m => m.status === 'paused').length;

  if (totalCountEl) totalCountEl.textContent = total;
  if (upCountEl) upCountEl.textContent = upCount;
  if (downCountEl) downCountEl.textContent = downCount;
  if (pausedCountEl) pausedCountEl.textContent = pausedCount;
  const dirCountEl = document.getElementById('uptimeDirectoryCount');
  if (dirCountEl) {
    dirCountEl.textContent = (filtered.length === total) ? `${total} Total` : `${filtered.length} of ${total}`;
  }

  // Filter monitors
  let filtered = [...uptimeMonitors];
  if (currentUptimeFilter === 'up') {
    filtered = filtered.filter(m => m.status === 'up');
  } else if (currentUptimeFilter === 'down') {
    filtered = filtered.filter(m => m.status === 'down');
  } else if (currentUptimeFilter === 'paused') {
    filtered = filtered.filter(m => m.status === 'paused');
  }

  if (uptimeSearchQuery.trim()) {
    const q = uptimeSearchQuery.toLowerCase();
    filtered = filtered.filter(m =>
      (m.name || '').toLowerCase().includes(q) ||
      (m.url || '').toLowerCase().includes(q) ||
      (m.tag || '').toLowerCase().includes(q) ||
      (m.type || '').toLowerCase().includes(q)
    );
  }

  if (filtered.length === 0) {
    listEl.innerHTML = `<div class="uptime-empty-state">No monitors match current filter</div>`;
    return;
  }

  listEl.innerHTML = filtered.map(m => {
    const isSelected = String(m.id) === String(selectedMonitorId);
    const isDown = m.status === 'down';
    const isPaused = m.status === 'paused';
    const isHost = ['disk', 'cpu', 'memory'].includes(m.type);

    const dotClass = isDown ? 'dot-down' : (isPaused ? 'dot-paused' : 'dot-up');
    const valText = isDown ? 'DOWN' : (isHost ? `${m.lastPing || 0}%` : `${m.lastPing || 0}ms`);

    // Mini heartbeat strip (20 bars)
    const heartbeats = m.heartbeats || [];
    const ticks = heartbeats.slice(-20);
    while (ticks.length < 20) ticks.unshift({ status: 'empty' });
    const miniTicksHtml = ticks.map(t => {
      let c = 'mini-tick-empty';
      if (t.status === 'up') c = 'mini-tick-up';
      if (t.status === 'down') c = 'mini-tick-down';
      if (t.status === 'paused') c = 'mini-tick-paused';
      return `<div class="mini-tick ${c}"></div>`;
    }).join('');

    return `
      <div class="uptime-monitor-card ${isSelected ? 'active' : ''}" onclick="selectUptimeMonitor('${m.id}')">
        <div class="uptime-card-header">
          <div class="uptime-card-title-row">
            <span class="status-dot ${dotClass}"></span>
            <span class="uptime-card-name">${escapeUptimeHtml(m.name)}</span>
          </div>
          <span class="uptime-card-value font-mono">${valText}</span>
        </div>
        <div class="uptime-card-footer">
          <span class="uptime-badge-type">${m.type.toUpperCase()}</span>
          <div class="uptime-mini-strip">${miniTicksHtml}</div>
          <span class="uptime-pct font-mono">${m.uptime24h || 100}%</span>
        </div>
      </div>
    `;
  }).join('');
}

function renderMonitorDetail() {
  const detailEl = document.getElementById('uptimeMonitorDetail');
  if (!detailEl) return;

  const monitor = uptimeMonitors.find(m => String(m.id) === String(selectedMonitorId));
  if (!monitor) {
    detailEl.innerHTML = `
      <div class="uptime-no-selection">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
        <h3>No Monitor Selected</h3>
        <p>Select a service from the left list or click <strong>+ Add Monitor</strong> to begin tracking.</p>
      </div>
    `;
    return;
  }

  const isDown = monitor.status === 'down';
  const isPaused = monitor.status === 'paused';
  const isHost = ['disk', 'cpu', 'memory'].includes(monitor.type);

  const currentVal = isDown ? 'N/A' : (isHost ? `${monitor.lastPing || 0}%` : `${monitor.lastPing || 0}ms`);
  const avgVal = isHost ? `${monitor.avgPing || 0}%` : `${monitor.avgPing || 0}ms`;

  // Heartbeat Strip (36 bars)
  const heartbeats = monitor.heartbeats || [];
  const totalSlots = 36;
  const ticks = heartbeats.slice(-totalSlots);
  while (ticks.length < totalSlots) ticks.unshift({ status: 'empty' });

  const stripHtml = ticks.map(t => {
    let tClass = 'tick-empty';
    if (t.status === 'up') tClass = 'tick-up';
    if (t.status === 'down') tClass = 'tick-down';
    if (t.status === 'paused') tClass = 'tick-paused';

    const tooltip = t.time ? `${new Date(t.time).toLocaleTimeString()} - ${t.msg || t.status}` : 'No check data';
    return `<div class="uptime-tick ${tClass}" data-tooltip="${escapeUptimeHtml(tooltip)}"></div>`;
  }).join('');

  // Target label
  let targetHtml = '';
  if (monitor.url) {
    targetHtml = `<a href="${escapeUptimeHtml(monitor.url)}" target="_blank" rel="noopener noreferrer" class="uptime-target-link font-mono">${escapeUptimeHtml(monitor.url)} ↗</a>`;
  } else if (monitor.target) {
    targetHtml = `<span class="uptime-target-badge font-mono">Host Partition: ${escapeUptimeHtml(monitor.target)} (Alert > ${monitor.threshold}%)</span>`;
  } else {
    targetHtml = `<span class="uptime-target-badge font-mono">Host Metric (${monitor.type.toUpperCase()}) (Alert > ${monitor.threshold}%)</span>`;
  }

  detailEl.innerHTML = `
    <!-- Top Action Bar -->
    <div class="uptime-detail-header">
      <div>
        <div class="uptime-detail-title-row">
          <h2 class="uptime-detail-title">${escapeUptimeHtml(monitor.name)}</h2>
          <span class="uptime-badge-type">${monitor.type.toUpperCase()}</span>
        </div>
        <div style="margin-top: 4px;">${targetHtml}</div>
      </div>

      <div class="uptime-actions-bar">
        <!-- Telegram Toggle -->
        <button onclick="toggleUptimeTelegram('${monitor.id}')" class="btn-outline ${monitor.telegramEnabled !== false ? 'uptime-btn-telegram-active' : ''}" title="Toggle Telegram alerts for this monitor">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
          <span>Telegram: ${monitor.telegramEnabled !== false ? 'Active' : 'Off'}</span>
        </button>

        <!-- Pause / Resume -->
        <button onclick="toggleUptimePause('${monitor.id}')" class="btn-outline" title="Pause or Resume monitor checks">
          ${monitor.active ? '<svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg> Pause' : '<svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg> Resume'}
        </button>

        <!-- Edit -->
        <button onclick="openEditMonitorModal('${monitor.id}')" class="btn-outline" title="Edit Monitor">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          Edit
        </button>

        <!-- Clone -->
        <button onclick="cloneUptimeMonitor('${monitor.id}')" class="btn-outline" title="Clone Monitor">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
          Clone
        </button>

        <!-- Delete -->
        <button onclick="deleteUptimeMonitor('${monitor.id}')" class="btn-outline uptime-btn-danger" title="Delete Monitor">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
          Delete
        </button>
      </div>
    </div>

    <!-- Heartbeat Status Strip Banner -->
    <div class="uptime-strip-card">
      <div class="uptime-strip-left">
        <div class="uptime-strip-label">Heartbeat History (${monitor.interval || 30}s intervals)</div>
        <div class="uptime-strip-bars">${stripHtml}</div>
      </div>
      <div class="uptime-strip-right">
        <span class="uptime-status-pill ${isDown ? 'status-down' : (isPaused ? 'status-paused' : 'status-up')}">
          ${isDown ? 'Down' : (isPaused ? 'Paused' : 'Operational')}
        </span>
      </div>
    </div>

    <!-- 5 KPI Overview Tiles -->
    <div class="uptime-kpi-grid">
      <div class="uptime-kpi-tile">
        <div class="uptime-kpi-label">Response <span>(Current)</span></div>
        <div class="uptime-kpi-value font-mono">${currentVal}</div>
      </div>
      <div class="uptime-kpi-tile">
        <div class="uptime-kpi-label">Avg. Response <span>(24h)</span></div>
        <div class="uptime-kpi-value font-mono">${avgVal}</div>
      </div>
      <div class="uptime-kpi-tile">
        <div class="uptime-kpi-label">Uptime <span>(24 hours)</span></div>
        <div class="uptime-kpi-value font-mono">${monitor.uptime24h || 100}%</div>
      </div>
      <div class="uptime-kpi-tile">
        <div class="uptime-kpi-label">Uptime <span>(30 days)</span></div>
        <div class="uptime-kpi-value font-mono">${monitor.uptime30d || 100}%</div>
      </div>
      <div class="uptime-kpi-tile">
        <div class="uptime-kpi-label">Uptime <span>(1 year)</span></div>
        <div class="uptime-kpi-value font-mono">${monitor.uptime1y || 100}%</div>
      </div>
    </div>

    <!-- Response Time / Ping Chart -->
    <div class="uptime-chart-card">
      <div class="uptime-chart-header">
        <div class="uptime-chart-title">
          <span class="uptime-chart-dot"></span>
          <span>${isHost ? 'Usage Telemetry Curve' : 'Response Latency (ms)'}</span>
        </div>
        <button onclick="clearUptimeData('${monitor.id}')" class="btn-outline uptime-btn-sm uptime-btn-danger" title="Clear heartbeat history">
          Clear History
        </button>
      </div>
      <div class="uptime-canvas-wrap">
        <canvas id="uptimeLatencyCanvas" height="140"></canvas>
      </div>
    </div>

    <!-- Down Outage Alert Toast -->
    ${isDown && monitor.lastError && toastDismissedFor !== monitor.id ? `
      <div class="uptime-incident-toast">
        <div class="toast-icon">⚠️</div>
        <div class="toast-content">
          <div class="toast-title">Active Service Incident</div>
          <div class="toast-msg font-mono">${escapeUptimeHtml(monitor.lastError)}</div>
        </div>
        <button onclick="dismissUptimeToast('${monitor.id}')" class="toast-close-btn">&times;</button>
      </div>
    ` : ''}
  `;

  // Draw chart
  drawUptimeChart(monitor);
}

// =========================================================================
// 4. PING & TELEMETRY CHART
// =========================================================================

function colorWithAlpha(colorStr, alpha, fallback) {
  if (!colorStr) return fallback;
  const c = colorStr.trim();
  if (c.startsWith('#')) {
    let hex = c.substring(1);
    if (hex.length === 3) hex = hex.split('').map(x => x + x).join('');
    if (hex.length === 6) {
      const num = parseInt(hex, 16);
      return `rgba(${(num >> 16) & 255}, ${(num >> 8) & 255}, ${num & 255}, ${alpha})`;
    }
  } else if (c.startsWith('rgb(')) {
    return c.replace('rgb(', 'rgba(').replace(')', `, ${alpha})`);
  } else if (c.startsWith('rgba(')) {
    return c.replace(/[\d\.]+\)$/, `${alpha})`);
  }
  return fallback;
}

function drawUptimeChart(monitor) {
  const canvas = document.getElementById('uptimeLatencyCanvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();

  canvas.width = rect.width * dpr;
  canvas.height = 140 * dpr;
  ctx.scale(dpr, dpr);

  const cs = getComputedStyle(document.documentElement);
  const okColor = cs.getPropertyValue('--ok').trim() || '#10b981';
  const badColor = cs.getPropertyValue('--bad').trim() || '#ef4444';
  const mutedColor = cs.getPropertyValue('--muted').trim() || '#64748b';
  const borderColor = cs.getPropertyValue('--border').trim() || 'rgba(255, 255, 255, 0.08)';

  const heartbeats = monitor.heartbeats || [];
  const W = rect.width;
  const H = 140;
  const padLeft = 45;
  const padRight = 15;
  const padTop = 15;
  const padBottom = 25;
  const chartW = W - padLeft - padRight;
  const chartH = H - padTop - padBottom;

  ctx.clearRect(0, 0, W, H);

  if (heartbeats.length < 2) {
    ctx.fillStyle = mutedColor;
    ctx.font = '12px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Gathering heartbeat ticks...', W / 2, H / 2);
    return;
  }

  const pings = heartbeats.map(h => (h.status === 'up' ? Number(h.ping || 0) : 0));
  const rawMax = Math.max(...pings, 1);
  const maxVal = Math.ceil(rawMax * 1.25);
  const minVal = 0;

  const getX = (idx) => padLeft + (idx / (heartbeats.length - 1)) * chartW;
  const getY = (val) => padTop + chartH - ((Math.min(val, maxVal) - minVal) / (maxVal - minVal || 1)) * chartH;

  // Grid lines
  ctx.strokeStyle = borderColor;
  ctx.lineWidth = 1;
  ctx.setLineDash([3, 3]);
  ctx.fillStyle = mutedColor;
  ctx.font = '9px JetBrains Mono, monospace';
  ctx.textAlign = 'right';

  const isHost = ['disk', 'cpu', 'memory'].includes(monitor.type);
  const unit = isHost ? '%' : 'ms';
  const steps = [0, Math.round(maxVal * 0.5), maxVal];
  steps.forEach(val => {
    const y = getY(val);
    ctx.beginPath();
    ctx.moveTo(padLeft, y);
    ctx.lineTo(W - padRight, y);
    ctx.stroke();
    ctx.fillText(`${val}${unit}`, padLeft - 6, y + 3);
  });
  ctx.setLineDash([]);

  // Draw downtime outage vertical highlight bands
  ctx.fillStyle = colorWithAlpha(badColor, 0.16, 'rgba(239, 68, 68, 0.16)');
  const slotW = chartW / (heartbeats.length - 1);
  heartbeats.forEach((h, idx) => {
    if (h.status === 'down') {
      const x = getX(idx) - slotW / 2;
      ctx.fillRect(Math.max(x, padLeft), padTop, slotW, chartH);
    }
  });

  // Draw gradient area
  const gradient = ctx.createLinearGradient(0, padTop, 0, padTop + chartH);
  gradient.addColorStop(0, colorWithAlpha(okColor, 0.28, 'rgba(16, 185, 129, 0.28)'));
  gradient.addColorStop(1, colorWithAlpha(okColor, 0.0, 'rgba(16, 185, 129, 0.0)'));

  ctx.beginPath();
  heartbeats.forEach((h, idx) => {
    const x = getX(idx);
    const y = getY(h.status === 'up' ? h.ping : 0);
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.lineTo(getX(heartbeats.length - 1), padTop + chartH);
  ctx.lineTo(getX(0), padTop + chartH);
  ctx.closePath();
  ctx.fillStyle = gradient;
  ctx.fill();

  // Draw line
  ctx.beginPath();
  heartbeats.forEach((h, idx) => {
    const x = getX(idx);
    const y = getY(h.status === 'up' ? h.ping : 0);
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = okColor;
  ctx.lineWidth = 2;
  ctx.stroke();

  // Timestamp labels at start and end
  ctx.fillStyle = mutedColor;
  ctx.font = '9px JetBrains Mono, monospace';
  ctx.textAlign = 'left';
  ctx.fillText(new Date(heartbeats[0].time).toLocaleTimeString(), padLeft, H - 8);
  ctx.textAlign = 'right';
  ctx.fillText(new Date(heartbeats[heartbeats.length - 1].time).toLocaleTimeString(), W - padRight, H - 8);
}

// =========================================================================
// 5. MONITOR ACTIONS (CRUD, PAUSE, TELEGRAM, CLONE, CLEAR)
// =========================================================================

function selectUptimeMonitor(id) {
  selectedMonitorId = id;
  renderUptimeView();
}

function setUptimeFilter(filter) {
  currentUptimeFilter = filter;
  document.querySelectorAll('.uptime-tab-btn, .uptime-filter-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.filter === filter);
  });
  renderMonitorSidebar();
}

function handleUptimeSearch(query) {
  uptimeSearchQuery = query;
  renderMonitorSidebar();
}

function dismissUptimeToast(id) {
  toastDismissedFor = id;
  renderMonitorDetail();
}

async function toggleUptimePause(id) {
  try {
    const res = await apiFetch(`/api/monitors/${id}/pause`, { method: 'POST' });
    if (res.ok) {
      const updated = await res.json();
      const idx = uptimeMonitors.findIndex(m => String(m.id) === String(id));
      if (idx !== -1) uptimeMonitors[idx] = updated;
      renderUptimeView();
    }
  } catch (e) {
    console.error('Failed to toggle pause:', e);
  }
}

async function toggleUptimeTelegram(id) {
  try {
    const res = await apiFetch(`/api/monitors/${id}/toggle-telegram`, { method: 'POST' });
    if (res.ok) {
      const updated = await res.json();
      const idx = uptimeMonitors.findIndex(m => String(m.id) === String(id));
      if (idx !== -1) uptimeMonitors[idx] = updated;
      renderUptimeView();
    }
  } catch (e) {
    console.error('Failed to toggle telegram:', e);
  }
}

async function clearUptimeData(id) {
  if (!confirm('Clear all historical latency and heartbeat ticks for this monitor?')) return;
  try {
    const res = await apiFetch(`/api/monitors/${id}/clear`, { method: 'POST' });
    if (res.ok) {
      const monitor = uptimeMonitors.find(m => String(m.id) === String(id));
      if (monitor) {
        monitor.heartbeats = [];
        monitor.lastError = null;
        monitor.uptime24h = 100.0;
        monitor.avgPing = 0.0;
      }
      renderUptimeView();
    }
  } catch (e) {
    console.error('Failed to clear data:', e);
  }
}

async function cloneUptimeMonitor(id) {
  const orig = uptimeMonitors.find(m => String(m.id) === String(id));
  if (!orig) return;

  const cloned = {
    name: `${orig.name} (Clone)`,
    tag: `${orig.tag || orig.name} (Clone)`,
    type: orig.type,
    url: orig.url,
    target: orig.target,
    threshold: orig.threshold,
    interval: orig.interval,
    telegramEnabled: orig.telegramEnabled,
    telegramBotToken: orig.telegramBotToken,
    telegramChatId: orig.telegramChatId
  };

  try {
    const res = await apiFetch('/api/monitors', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cloned)
    });
    if (res.ok) {
      const created = await res.json();
      uptimeMonitors.push(created);
      selectedMonitorId = created.id;
      renderUptimeView();
    }
  } catch (e) {
    console.error('Failed to clone monitor:', e);
  }
}

async function deleteUptimeMonitor(id) {
  if (!confirm('Permanently delete this monitor and all recorded heartbeats?')) return;
  try {
    const res = await apiFetch(`/api/monitors/${id}`, { method: 'DELETE' });
    if (res.ok) {
      uptimeMonitors = uptimeMonitors.filter(m => String(m.id) !== String(id));
      if (String(selectedMonitorId) === String(id)) {
        selectedMonitorId = uptimeMonitors.length > 0 ? uptimeMonitors[0].id : null;
      }
      renderUptimeView();
    }
  } catch (e) {
    console.error('Failed to delete monitor:', e);
  }
}

// =========================================================================
// 6. ADD / EDIT MONITOR MODAL
// =========================================================================

function openAddMonitorModal() {
  editingMonitorId = null;
  document.getElementById('monitorModalTitle').textContent = 'Add New Monitor';
  document.getElementById('monitorForm').reset();
  document.getElementById('monitorTypeSelect').value = 'http';
  document.getElementById('monitorIntervalInput').value = '30';
  document.getElementById('monitorThresholdInput').value = '90';
  document.getElementById('monitorTelegramCheck').checked = true;

  populateDrivesDropdown();
  updateMonitorFormTypeFields();
  document.getElementById('uptimeMonitorModal').style.display = 'flex';
}

function openEditMonitorModal(id) {
  editingMonitorId = id;
  const m = uptimeMonitors.find(item => String(item.id) === String(id));
  if (!m) return;

  document.getElementById('monitorModalTitle').textContent = 'Edit Monitor';
  document.getElementById('monitorNameInput').value = m.name || '';
  document.getElementById('monitorTypeSelect').value = m.type || 'http';
  document.getElementById('monitorUrlInput').value = m.url || '';
  document.getElementById('monitorIntervalInput').value = m.interval || 30;
  document.getElementById('monitorThresholdInput').value = m.threshold || 90;
  document.getElementById('monitorThresholdVal').textContent = `${m.threshold || 90}%`;
  document.getElementById('monitorTelegramCheck').checked = m.telegramEnabled !== false;
  document.getElementById('monitorTelegramChatInput').value = m.telegramChatId || '';

  populateDrivesDropdown();
  if (m.target) {
    document.getElementById('monitorDriveSelect').value = m.target;
  }
  updateMonitorFormTypeFields();
  document.getElementById('uptimeMonitorModal').style.display = 'flex';
}

function closeMonitorModal() {
  document.getElementById('uptimeMonitorModal').style.display = 'none';
  editingMonitorId = null;
}

function populateDrivesDropdown() {
  const driveSelect = document.getElementById('monitorDriveSelect');
  if (!driveSelect) return;

  if (availableSystemDrives.length === 0) {
    driveSelect.innerHTML = `<option value="C:">C: (Default)</option>`;
    return;
  }

  driveSelect.innerHTML = availableSystemDrives.map(d => {
    const sizeGb = Math.round(d.size / 1e9);
    return `<option value="${d.mount}">${d.mount} (${sizeGb} GB, currently ${d.usePercent}% used)</option>`;
  }).join('');
}

function updateMonitorFormTypeFields() {
  const type = document.getElementById('monitorTypeSelect').value;
  const urlGroup = document.getElementById('monitorUrlGroup');
  const driveGroup = document.getElementById('monitorDriveGroup');
  const thresholdGroup = document.getElementById('monitorThresholdGroup');
  const urlLabel = document.getElementById('monitorUrlLabel');

  if (type === 'http') {
    urlGroup.style.display = 'block';
    driveGroup.style.display = 'none';
    thresholdGroup.style.display = 'none';
    urlLabel.textContent = 'Target URL (HTTP / HTTPS)';
  } else if (type === 'port') {
    urlGroup.style.display = 'block';
    driveGroup.style.display = 'none';
    thresholdGroup.style.display = 'none';
    urlLabel.textContent = 'Host:Port (e.g. 127.0.0.1:5432)';
  } else if (type === 'disk') {
    urlGroup.style.display = 'none';
    driveGroup.style.display = 'block';
    thresholdGroup.style.display = 'block';
  } else {
    // cpu or memory
    urlGroup.style.display = 'none';
    driveGroup.style.display = 'none';
    thresholdGroup.style.display = 'block';
  }
}

async function saveUptimeMonitor(e) {
  if (e) e.preventDefault();
  const name = document.getElementById('monitorNameInput').value.trim();
  const type = document.getElementById('monitorTypeSelect').value;
  const url = document.getElementById('monitorUrlInput').value.trim();
  const target = document.getElementById('monitorDriveSelect').value;
  const threshold = Number(document.getElementById('monitorThresholdInput').value);
  const interval = Number(document.getElementById('monitorIntervalInput').value);
  const telegramEnabled = document.getElementById('monitorTelegramCheck').checked;
  const telegramChatId = document.getElementById('monitorTelegramChatInput').value.trim();

  const payload = {
    name: name || (type === 'disk' ? `Disk (${target})` : `${type.toUpperCase()} Monitor`),
    tag: name || type.toUpperCase(),
    type,
    url: (type === 'http' || type === 'port') ? url : '',
    target: type === 'disk' ? target : '',
    threshold,
    interval: interval || 30,
    telegramEnabled,
    telegramChatId
  };

  try {
    if (editingMonitorId) {
      const res = await apiFetch(`/api/monitors/${editingMonitorId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        const updated = await res.json();
        const idx = uptimeMonitors.findIndex(m => String(m.id) === String(editingMonitorId));
        if (idx !== -1) uptimeMonitors[idx] = updated;
      }
    } else {
      const res = await apiFetch('/api/monitors', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        const created = await res.json();
        uptimeMonitors.push(created);
        selectedMonitorId = created.id;
      }
    }
    closeMonitorModal();
    renderUptimeView();
  } catch (err) {
    alert(`Failed to save monitor: ${err.message}`);
  }
}

// =========================================================================
// 7. TELEGRAM NOTIFICATIONS SETUP MODAL
// =========================================================================

async function openTelegramSettingsModal() {
  document.getElementById('telegramTestResult').style.display = 'none';
  try {
    const res = await apiFetch('/api/settings');
    if (res.ok) {
      const data = await res.json();
      const tg = data.telegram || {};
      document.getElementById('tgEnabledCheck').checked = tg.enabled !== false;
      document.getElementById('tgBotTokenInput').value = tg.botToken || '';
      document.getElementById('tgChatIdInput').value = tg.chatId || '';
    }
  } catch (e) {
    console.error('Failed to load telegram settings:', e);
  }
  document.getElementById('uptimeTelegramModal').style.display = 'flex';
}

function closeTelegramSettingsModal() {
  document.getElementById('uptimeTelegramModal').style.display = 'none';
}

async function testTelegramSettings() {
  const botToken = document.getElementById('tgBotTokenInput').value.trim();
  const chatId = document.getElementById('tgChatIdInput').value.trim();
  const resultEl = document.getElementById('telegramTestResult');

  if (!botToken || !chatId) {
    resultEl.style.display = 'block';
    resultEl.className = 'uptime-test-banner test-failed';
    resultEl.textContent = 'Please enter both Bot Token and Chat ID before testing.';
    return;
  }

  resultEl.style.display = 'block';
  resultEl.className = 'uptime-test-banner test-pending';
  resultEl.textContent = 'Sending test message to Telegram...';

  try {
    const res = await apiFetch('/api/settings/telegram/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ botToken, chatId })
    });
    const data = await res.json();
    if (data.success) {
      resultEl.className = 'uptime-test-banner test-success';
      resultEl.textContent = '✓ Test notification delivered successfully! Check your Telegram chat.';
    } else {
      resultEl.className = 'uptime-test-banner test-failed';
      resultEl.textContent = `✗ Error: ${data.error || 'Failed to send test message'}`;
    }
  } catch (err) {
    resultEl.className = 'uptime-test-banner test-failed';
    resultEl.textContent = `✗ Error: ${err.message}`;
  }
}

async function saveTelegramSettings(e) {
  if (e) e.preventDefault();
  const enabled = document.getElementById('tgEnabledCheck').checked;
  const botToken = document.getElementById('tgBotTokenInput').value.trim();
  const chatId = document.getElementById('tgChatIdInput').value.trim();

  try {
    const res = await apiFetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        telegram: { enabled, botToken, chatId }
      })
    });
    if (res.ok) {
      closeTelegramSettingsModal();
      alert('Telegram alert settings saved successfully.');
    }
  } catch (err) {
    alert(`Failed to save settings: ${err.message}`);
  }
}

// =========================================================================
// 8. STATUS PAGES EDITOR & INCIDENTS
// =========================================================================

async function loadStatusPagesAdmin() {
  try {
    const res = await apiFetch('/api/status-pages');
    if (res.ok) {
      allStatusPagesList = await res.json();
      populateStatusPageDropdown();

      const activeSlug = currentStatusPage ? currentStatusPage.slug : (allStatusPagesList[0]?.slug || 'monitor');
      await switchStatusPageAdmin(activeSlug);
    }
  } catch (err) {
    console.error('Failed to load status pages:', err);
  }
}

function populateStatusPageDropdown() {
  const select = document.getElementById('statusPageSelect');
  if (!select) return;

  select.innerHTML = allStatusPagesList.map(p => {
    return `<option value="${p.slug}">${escapeUptimeHtml(p.title)} (${p.isPublic ? 'Public' : 'Private'})</option>`;
  }).join('');
}

async function switchStatusPageAdmin(slug) {
  try {
    const res = await apiFetch(`/api/status-page/${slug}`);
    if (res.ok) {
      currentStatusPage = await res.json();
      renderStatusPageEditor();
    }
  } catch (e) {
    console.error('Failed to switch status page:', e);
  }
}

function renderStatusPageEditor() {
  if (!currentStatusPage) return;

  const select = document.getElementById('statusPageSelect');
  if (select) select.value = currentStatusPage.slug;

  document.getElementById('spTitleInput').value = currentStatusPage.title || '';
  document.getElementById('spSlugInput').value = currentStatusPage.slug || '';
  document.getElementById('spDescInput').value = currentStatusPage.description || '';
  document.getElementById('spFooterInput').value = currentStatusPage.footerText || '';
  document.getElementById('spRefreshInput').value = currentStatusPage.refreshInterval || 300;
  document.getElementById('spPublicCheck').checked = currentStatusPage.isPublic !== false;

  const linkPill = document.getElementById('spPublicLinkPill');
  if (linkPill) {
    linkPill.textContent = `${window.location.origin}/status/${currentStatusPage.slug}`;
  }

  // Render Monitor Groups
  renderMonitorGroups();

  // Render Incidents
  renderActiveIncidents();
}

function renderMonitorGroups() {
  const container = document.getElementById('spGroupsContainer');
  if (!container || !currentStatusPage) return;

  const groups = currentStatusPage.groups || [];
  if (groups.length === 0) {
    container.innerHTML = `<div class="uptime-empty-state">No component groups defined. Click <strong>+ Add Group</strong> to organize monitors.</div>`;
    return;
  }

  container.innerHTML = groups.map((g, gIdx) => {
    const gMonitors = (g.monitorIds || []).map(mid => {
      const found = uptimeMonitors.find(m => String(m.id) === String(mid));
      return found || { id: mid, name: `Monitor #${mid}`, type: 'service' };
    });

    const monitorsHtml = gMonitors.map(m => `
      <div class="sp-monitor-pill">
        <span>${escapeUptimeHtml(m.name)}</span>
        <button onclick="removeMonitorFromGroup('${g.id}', '${m.id}')" title="Remove">&times;</button>
      </div>
    `).join('');

    const unassignedMonitors = uptimeMonitors.filter(m => !(g.monitorIds || []).includes(String(m.id)));

    return `
      <div class="sp-group-card">
        <div class="sp-group-header">
          <input type="text" class="field sp-group-name-input" value="${escapeUptimeHtml(g.name || 'Services')}" onchange="updateGroupName('${g.id}', this.value)" />
          <button onclick="deleteMonitorGroup('${g.id}')" class="btn-outline uptime-btn-sm uptime-btn-danger" title="Delete Group">Delete</button>
        </div>

        <div class="sp-group-monitors-wrap">
          ${monitorsHtml || '<div class="muted" style="font-size:0.8rem;">No monitors assigned to this group yet.</div>'}
        </div>

        <div class="sp-group-add-row">
          <select id="addSelect-${g.id}" class="field" style="max-width:240px;">
            <option value="">-- Assign Monitor --</option>
            ${unassignedMonitors.map(m => `<option value="${m.id}">${escapeUptimeHtml(m.name)} (${m.type})</option>`).join('')}
          </select>
          <button onclick="addSelectedMonitorToGroup('${g.id}')" class="btn-outline uptime-btn-sm">Add to Group</button>
        </div>
      </div>
    `;
  }).join('');
}

function updateGroupName(groupId, newName) {
  if (!currentStatusPage || !currentStatusPage.groups) return;
  const g = currentStatusPage.groups.find(item => item.id === groupId);
  if (g) g.name = newName.trim();
}

function addNewMonitorGroup() {
  if (!currentStatusPage) return;
  if (!currentStatusPage.groups) currentStatusPage.groups = [];

  currentStatusPage.groups.push({
    id: 'g-' + Date.now(),
    name: 'New Component Group',
    monitorIds: []
  });
  renderMonitorGroups();
}

function deleteMonitorGroup(groupId) {
  if (!currentStatusPage || !currentStatusPage.groups) return;
  currentStatusPage.groups = currentStatusPage.groups.filter(g => g.id !== groupId);
  renderMonitorGroups();
}

function addSelectedMonitorToGroup(groupId) {
  const select = document.getElementById(`addSelect-${groupId}`);
  if (!select || !select.value) return;
  addMonitorToGroup(groupId, select.value);
}

function addMonitorToGroup(groupId, monitorId) {
  if (!currentStatusPage || !currentStatusPage.groups) return;
  const g = currentStatusPage.groups.find(item => item.id === groupId);
  if (g) {
    if (!g.monitorIds) g.monitorIds = [];
    if (!g.monitorIds.includes(String(monitorId))) {
      g.monitorIds.push(String(monitorId));
      renderMonitorGroups();
    }
  }
}

function removeMonitorFromGroup(groupId, monitorId) {
  if (!currentStatusPage || !currentStatusPage.groups) return;
  const g = currentStatusPage.groups.find(item => item.id === groupId);
  if (g && g.monitorIds) {
    g.monitorIds = g.monitorIds.filter(id => String(id) !== String(monitorId));
    renderMonitorGroups();
  }
}

function renderActiveIncidents() {
  const container = document.getElementById('spIncidentsList');
  if (!container || !currentStatusPage) return;

  const incidents = currentStatusPage.incidents || [];
  if (incidents.length === 0) {
    container.innerHTML = `<div class="uptime-empty-state">No active incidents posted for this status page.</div>`;
    return;
  }

  container.innerHTML = incidents.map(inc => {
    const styleClass = inc.style === 'critical' ? 'incident-critical' : (inc.style === 'info' ? 'incident-info' : 'incident-warning');
    const timeFormatted = inc.createdAt ? new Date(inc.createdAt).toLocaleString() : '';
    return `
      <div class="sp-incident-item ${styleClass}">
        <div class="sp-incident-header">
          <div>
            <span class="sp-incident-title">${escapeUptimeHtml(inc.title)}</span>
            <span class="sp-incident-style-tag">${(inc.style || 'warning').toUpperCase()}</span>
          </div>
          <button onclick="deleteStatusIncident('${inc.id}')" class="btn-outline uptime-btn-sm uptime-btn-danger">Resolve / Delete</button>
        </div>
        <div class="sp-incident-content">${escapeUptimeHtml(inc.content || '')}</div>
        <div class="sp-incident-time font-mono">${timeFormatted}</div>
      </div>
    `;
  }).join('');
}

async function saveStatusPageConfig() {
  if (!currentStatusPage) return;

  const title = document.getElementById('spTitleInput').value.trim();
  const slug = document.getElementById('spSlugInput').value.trim();
  const desc = document.getElementById('spDescInput').value.trim();
  const footer = document.getElementById('spFooterInput').value.trim();
  const refresh = Number(document.getElementById('spRefreshInput').value);
  const isPublic = document.getElementById('spPublicCheck').checked;

  const payload = {
    ...currentStatusPage,
    title: title || 'System Status',
    slug: slug || 'monitor',
    description: desc,
    footerText: footer,
    refreshInterval: refresh || 300,
    isPublic
  };

  try {
    const res = await apiFetch('/api/status-page', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      alert('Status page configuration saved successfully!');
      currentStatusPage = payload;
      await loadStatusPagesAdmin();
    }
  } catch (err) {
    alert(`Failed to save status page: ${err.message}`);
  }
}

async function deleteStatusPageAdmin() {
  if (!currentStatusPage) return;
  if (currentStatusPage.slug === 'monitor') {
    alert('The default "monitor" status page cannot be deleted.');
    return;
  }
  if (!confirm(`Permanently delete status page "${currentStatusPage.title}"?`)) return;

  try {
    const res = await apiFetch(`/api/status-page/${currentStatusPage.slug}`, { method: 'DELETE' });
    if (res.ok) {
      currentStatusPage = null;
      await loadStatusPagesAdmin();
    }
  } catch (err) {
    alert(`Failed to delete status page: ${err.message}`);
  }
}

function openNewStatusPageModal() {
  document.getElementById('newPageTitleInput').value = '';
  document.getElementById('newPageSlugInput').value = '';
  document.getElementById('newPagePublicCheck').checked = true;
  document.getElementById('newStatusPageModal').style.display = 'flex';
}

function closeNewStatusPageModal() {
  document.getElementById('newStatusPageModal').style.display = 'none';
}

async function createStatusPage(e) {
  if (e) e.preventDefault();
  const title = document.getElementById('newPageTitleInput').value.trim();
  const rawSlug = document.getElementById('newPageSlugInput').value.trim() || title;
  const slug = rawSlug.toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  const isPublic = document.getElementById('newPagePublicCheck').checked;

  if (!slug) {
    alert('Please provide a valid title or slug.');
    return;
  }

  const newConfig = {
    slug,
    title: title || slug,
    description: 'Live system and service telemetry',
    footerText: 'Powered by Server Dashboard',
    refreshInterval: 300,
    theme: 'auto',
    domainNames: [],
    groups: [
      {
        id: 'g-' + Date.now(),
        name: 'Services',
        monitorIds: uptimeMonitors.slice(0, 3).map(m => m.id)
      }
    ],
    incidents: [],
    isPublic
  };

  try {
    const res = await apiFetch('/api/status-page', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newConfig)
    });
    if (res.ok) {
      closeNewStatusPageModal();
      currentStatusPage = newConfig;
      await loadStatusPagesAdmin();
    }
  } catch (err) {
    alert(`Failed to create status page: ${err.message}`);
  }
}

function openNewIncidentModal() {
  document.getElementById('incidentTitleInput').value = '';
  document.getElementById('incidentContentInput').value = '';
  document.getElementById('incidentStyleSelect').value = 'warning';
  document.getElementById('uptimeIncidentModal').style.display = 'flex';
}

function closeNewIncidentModal() {
  document.getElementById('uptimeIncidentModal').style.display = 'none';
}

async function postStatusIncident(e) {
  if (e) e.preventDefault();
  if (!currentStatusPage) return;

  const title = document.getElementById('incidentTitleInput').value.trim();
  const content = document.getElementById('incidentContentInput').value.trim();
  const style = document.getElementById('incidentStyleSelect').value;

  try {
    const res = await apiFetch('/api/status-page/incident', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        slug: currentStatusPage.slug,
        title: title || 'Service Degradation',
        content,
        style
      })
    });
    if (res.ok) {
      const data = await res.json();
      currentStatusPage = data.config;
      closeNewIncidentModal();
      renderActiveIncidents();
    }
  } catch (err) {
    alert(`Failed to post incident: ${err.message}`);
  }
}

async function deleteStatusIncident(incidentId) {
  if (!currentStatusPage) return;
  try {
    const res = await apiFetch(`/api/status-page/incident/${incidentId}?slug=${currentStatusPage.slug}`, {
      method: 'DELETE'
    });
    if (res.ok) {
      const data = await res.json();
      currentStatusPage = data.config;
      renderActiveIncidents();
    }
  } catch (err) {
    alert(`Failed to delete incident: ${err.message}`);
  }
}

function copyStatusPageLink() {
  if (!currentStatusPage) return;
  const url = `${window.location.origin}/status/${currentStatusPage.slug}`;
  navigator.clipboard.writeText(url).then(() => {
    alert(`Link copied: ${url}`);
  });
}

function viewStatusPageLive() {
  if (!currentStatusPage) return;
  window.open(`/status/${currentStatusPage.slug}`, '_blank');
}

function escapeUptimeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// =========================================================================
// EXPOSE GLOBALS TO WINDOW
// =========================================================================

window.loadUptimeDashboard = loadUptimeDashboard;
window.loadStatusPagesAdmin = loadStatusPagesAdmin;
window.selectUptimeMonitor = selectUptimeMonitor;
window.setUptimeFilter = setUptimeFilter;
window.handleUptimeSearch = handleUptimeSearch;
window.dismissUptimeToast = dismissUptimeToast;
window.openAddMonitorModal = openAddMonitorModal;
window.openEditMonitorModal = openEditMonitorModal;
window.closeMonitorModal = closeMonitorModal;
window.updateMonitorFormTypeFields = updateMonitorFormTypeFields;
window.saveUptimeMonitor = saveUptimeMonitor;
window.toggleUptimePause = toggleUptimePause;
window.toggleUptimeTelegram = toggleUptimeTelegram;
window.cloneUptimeMonitor = cloneUptimeMonitor;
window.deleteUptimeMonitor = deleteUptimeMonitor;
window.clearUptimeData = clearUptimeData;
window.openTelegramSettingsModal = openTelegramSettingsModal;
window.closeTelegramSettingsModal = closeTelegramSettingsModal;
window.testTelegramSettings = testTelegramSettings;
window.saveTelegramSettings = saveTelegramSettings;
window.switchStatusPageAdmin = switchStatusPageAdmin;
window.renderStatusPageEditor = renderStatusPageEditor;
window.updateGroupName = updateGroupName;
window.addNewMonitorGroup = addNewMonitorGroup;
window.deleteMonitorGroup = deleteMonitorGroup;
window.addSelectedMonitorToGroup = addSelectedMonitorToGroup;
window.addMonitorToGroup = addMonitorToGroup;
window.removeMonitorFromGroup = removeMonitorFromGroup;
window.saveStatusPageConfig = saveStatusPageConfig;
window.deleteStatusPageAdmin = deleteStatusPageAdmin;
window.openNewStatusPageModal = openNewStatusPageModal;
window.closeNewStatusPageModal = closeNewStatusPageModal;
window.createStatusPage = createStatusPage;
window.openNewIncidentModal = openNewIncidentModal;
window.closeNewIncidentModal = closeNewIncidentModal;
window.postStatusIncident = postStatusIncident;
window.deleteStatusIncident = deleteStatusIncident;
window.copyStatusPageLink = copyStatusPageLink;
window.viewStatusPageLive = viewStatusPageLive;


// =========================================================================
// REACTIVE RESIZE & THEME LISTENERS
// =========================================================================

let uptimeResizeTimer = null;
window.addEventListener('resize', () => {
  clearTimeout(uptimeResizeTimer);
  uptimeResizeTimer = setTimeout(() => {
    const uptimePage = document.getElementById('uptimePage');
    if (uptimePage && uptimePage.style.display !== 'none' && selectedMonitorId) {
      const activeMonitor = uptimeMonitors.find(m => String(m.id) === String(selectedMonitorId));
      if (activeMonitor) drawUptimeChart(activeMonitor);
    }
  }, 100);
});

try {
  const uptimeThemeObserver = new MutationObserver(() => {
    const uptimePage = document.getElementById('uptimePage');
    if (uptimePage && uptimePage.style.display !== 'none' && selectedMonitorId) {
      const activeMonitor = uptimeMonitors.find(m => String(m.id) === String(selectedMonitorId));
      if (activeMonitor) drawUptimeChart(activeMonitor);
    }
  });
  uptimeThemeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
} catch (e) {
  console.warn('[Uptime] Theme observer setup error:', e);
}
