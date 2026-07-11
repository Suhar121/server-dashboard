// Metrics and Monitoring
    function getThemeChartPalette(theme) {
      const palette = {
        light: {
          tick: "#5b6b86",
          grid: "rgba(15,23,42,0.06)",
          legend: "#0f172a",
          metrics: {
            cpu: { border: "#2563eb", bg: "rgba(37,99,235,0.15)" },
            ram: { border: "#059669", bg: "rgba(5,150,105,0.15)" },
            battery: { border: "#d97706", bg: "rgba(217,119,6,0.15)" },
          }
        },
        dark: {
          tick: "#94a3b8",
          grid: "rgba(255,255,255,0.06)",
          legend: "#e2e8f0",
          metrics: {
            cpu: { border: "#60a5fa", bg: "rgba(96,165,250,0.16)" },
            ram: { border: "#34d399", bg: "rgba(52,211,153,0.16)" },
            battery: { border: "#fbbf24", bg: "rgba(251,191,36,0.16)" },
          }
        },
        car: {
          tick: "#d1d5db",
          grid: "rgba(255,255,255,0.08)",
          legend: "#f3f4f6",
          metrics: {
            cpu: { border: "#ef4444", bg: "rgba(239,68,68,0.18)" },
            ram: { border: "#22c55e", bg: "rgba(34,197,94,0.16)" },
            battery: { border: "#f59e0b", bg: "rgba(245,158,11,0.18)" },
          }
        },
        batman: {
          tick: "#d4d4c3",
          grid: "rgba(250,204,21,0.12)",
          legend: "#f8f7e3",
          metrics: {
            cpu: { border: "#facc15", bg: "rgba(250,204,21,0.16)" },
            ram: { border: "#84cc16", bg: "rgba(132,204,22,0.16)" },
            battery: { border: "#f59e0b", bg: "rgba(245,158,11,0.16)" },
          }
        },
        builder: {
          tick: "#7a6b57",
          grid: "rgba(122,107,87,0.12)",
          legend: "#2f2618",
          metrics: {
            cpu: { border: "#f59e0b", bg: "rgba(245,158,11,0.17)" },
            ram: { border: "#16a34a", bg: "rgba(22,163,74,0.17)" },
            battery: { border: "#b45309", bg: "rgba(180,83,9,0.17)" },
          }
        },
        coding: {
          tick: "#9fb0c3",
          grid: "rgba(88,166,255,0.12)",
          legend: "#e6edf3",
          metrics: {
            cpu: { border: "#58a6ff", bg: "rgba(88,166,255,0.17)" },
            ram: { border: "#3fb950", bg: "rgba(63,185,80,0.17)" },
            battery: { border: "#d29922", bg: "rgba(210,153,34,0.17)" },
          }
        },
        networking: {
          tick: "#486581",
          grid: "rgba(14,165,233,0.12)",
          legend: "#102a43",
          metrics: {
            cpu: { border: "#0ea5e9", bg: "rgba(14,165,233,0.17)" },
            ram: { border: "#10b981", bg: "rgba(16,185,129,0.17)" },
            battery: { border: "#f59e0b", bg: "rgba(245,158,11,0.17)" },
          }
        },
      };
      return palette[theme] || palette.light;
    }

    function loadPortAliases() {
      try {
        const raw = localStorage.getItem(PORT_ALIAS_STORAGE_KEY);
        if (!raw) return {};
        const parsed = JSON.parse(raw);
        return parsed && typeof parsed === "object" ? parsed : {};
      } catch {
        return {};
      }
    }

    function savePortAliases() {
      try {
        localStorage.setItem(PORT_ALIAS_STORAGE_KEY, JSON.stringify(portAliases || {}));
      } catch {
        // Ignore storage failures.
      }
    }

    function loadRecentPortActivity() {
      try {
        const raw = localStorage.getItem(PORT_ACTIVITY_STORAGE_KEY);
        if (!raw) return [];
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed.slice(0, MAX_PORT_ACTIVITY_ITEMS) : [];
      } catch {
        return [];
      }
    }

    function saveRecentPortActivity() {
      try {
        localStorage.setItem(
          PORT_ACTIVITY_STORAGE_KEY,
          JSON.stringify((recentPortActivity || []).slice(0, MAX_PORT_ACTIVITY_ITEMS))
        );
      } catch {
        // Ignore storage failures.
      }
    }

    function extractPortNumber(localAddress) {
      const text = String(localAddress || "").trim();
      const matched = text.match(/:(\d{1,5})$/);
      if (!matched) return null;
      const port = Number(matched[1]);
      if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
      return port;
    }

    function normalizePortEntry(entry) {
      const protocol = String(entry?.protocol || "").trim();
      const state = String(entry?.state || "").trim();
      const local = String(entry?.local || "").trim();
      const port = extractPortNumber(local);
      return {
        protocol,
        state,
        local,
        port,
        key: `${protocol}|${state}|${local}`,
      };
    }

    function recordPortActivity(type, entry, timestamp) {
      const newest = recentPortActivity[0];
      if (
        newest
        && newest.type === type
        && newest.key === entry.key
        && Math.abs(Number(newest.timestamp || 0) - Number(timestamp)) < 1500
      ) {
        return;
      }

      recentPortActivity.unshift({
        type,
        key: entry.key,
        protocol: entry.protocol,
        state: entry.state,
        local: entry.local,
        port: entry.port,
        timestamp,
      });

      recentPortActivity = recentPortActivity.slice(0, MAX_PORT_ACTIVITY_ITEMS);
      saveRecentPortActivity();
    }

    function updateRecentPortActivity(snapshot) {
      const now = Date.now();

      for (const [key, entry] of snapshot.entries()) {
        if (!lastPortSnapshot.has(key)) {
          recordPortActivity("opened", entry, now);
        }
      }

      for (const [key, entry] of lastPortSnapshot.entries()) {
        if (!snapshot.has(key)) {
          recordPortActivity("closed", entry, now);
        }
      }
    }

    function renderRecentPortActivity() {
      const list = document.getElementById("recentPortsList");
      if (!list) return;

      if (!recentPortActivity.length) {
        list.innerHTML = `<div class="muted">No recent port activity yet.</div>`;
        return;
      }

      list.innerHTML = recentPortActivity.slice(0, 8).map((entry) => {
        const isOpen = entry.type === "opened";
        const stateClass = isOpen ? "recent-port-open" : "recent-port-closed";
        const badgeText = isOpen ? "OPENED" : "CLOSED";
        const alias = entry.port ? (portAliases[String(entry.port)] || "") : "";
        const aliasText = alias ? ` • ${esc(alias)}` : "";
        const timeText = entry.timestamp
          ? new Date(Number(entry.timestamp)).toLocaleTimeString()
          : "--:--:--";
        const portText = entry.port ? `:${entry.port}` : "(unknown)";

        return `
          <div class="recent-port-item">
            <span class="recent-port-badge ${stateClass}">${badgeText}</span>
            <strong>${esc(portText)}</strong>
            <span>${aliasText || "<span class=\"muted\">No alias</span>"}</span>
            <span class="muted">${esc(entry.protocol)} • ${esc(entry.local)} • ${esc(timeText)}</span>
          </div>
        `;
      }).join("");
    }

    async function renamePortAlias(encodedLocalAddress, triggerEl = null) {
      if (triggerEl && triggerEl.closest("details")) {
        triggerEl.closest("details").removeAttribute("open");
      }

      const localAddress = decodeURIComponent(String(encodedLocalAddress || ""));
      const port = extractPortNumber(localAddress);
      if (!port) {
        alert("Could not detect a numeric port for this row.");
        return;
      }

      const currentAlias = portAliases[String(port)] || "";
      const nextAlias = prompt(
        `Set alias for port ${port} (leave empty to clear):`,
        currentAlias
      );

      if (nextAlias === null) return;

      const trimmed = String(nextAlias).trim().slice(0, 40);
      if (trimmed) {
        portAliases[String(port)] = trimmed;
      } else {
        delete portAliases[String(port)];
      }

      savePortAliases();
      await Promise.all([loadPorts(), loadPinnedPorts()]);
    }

    function updateAccessTabs() {
      document.querySelectorAll(".access-tab-btn").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.page === currentPage);
      });
    }

    function setAccessHubCount(selector, value) {
      const text = value === null || value === undefined ? "--" : String(value);
      document.querySelectorAll(selector).forEach((el) => {
        el.innerText = text;
      });
    }

    function setAccessHubTunnelState(running) {
      let label = "Unknown";
      let cls = "unknown";

      if (running === true) {
        label = "Active";
        cls = "active";
      } else if (running === false) {
        label = "Inactive";
        cls = "inactive";
      }

      document.querySelectorAll(".hub-tunnel-state").forEach((el) => {
        el.classList.remove("active", "inactive", "unknown");
        el.classList.add(cls);
        el.innerText = label;
      });
    }

    async function loadAccessHubStats() {
      if (!hasRole("admin")) {
        setAccessHubCount(".hub-ssh-count", "--");
        setAccessHubCount(".hub-route-count", "--");
        setAccessHubTunnelState(null);
        return;
      }

      try {
        const [sshRes, cloudRes] = await Promise.all([
          apiFetch("/ssh/keys"),
          apiFetch("/cloudflared/routes"),
        ]);

        const sshData = await sshRes.json();
        const cloudData = await cloudRes.json();

        const keyCount = Array.isArray(sshData.keys) ? sshData.keys.length : 0;
        const routeCount = Array.isArray(cloudData.routes) ? cloudData.routes.length : 0;

        setAccessHubCount(".hub-ssh-count", keyCount);
        setAccessHubCount(".hub-route-count", routeCount);
        setAccessHubTunnelState(cloudData.tunnel_running === true ? true : (cloudData.tunnel_running === false ? false : null));
      } catch {
        setAccessHubCount(".hub-ssh-count", "--");
        setAccessHubCount(".hub-route-count", "--");
        setAccessHubTunnelState(null);
      }
    }

    function updateChartColors(theme) {
      if (!cpuChart) return;
      const palette = getThemeChartPalette(theme);
      const datasets = cpuChart.data.datasets || [];

      if (datasets[0]) {
        datasets[0].borderColor = palette.metrics.cpu.border;
        datasets[0].backgroundColor = palette.metrics.cpu.bg;
      }
      if (datasets[1]) {
        datasets[1].borderColor = palette.metrics.ram.border;
        datasets[1].backgroundColor = palette.metrics.ram.bg;
      }
      if (datasets[2]) {
        datasets[2].borderColor = palette.metrics.battery.border;
        datasets[2].backgroundColor = palette.metrics.battery.bg;
      }
      
      cpuChart.options.scales.x.ticks.color = palette.tick;
      cpuChart.options.scales.x.grid.color = palette.grid;
      cpuChart.options.scales.y.ticks.color = palette.tick;
      cpuChart.options.scales.y.grid.color = palette.grid;
      
      cpuChart.options.plugins.legend.labels.color = palette.legend;
      
      cpuChart.update();
    }

    const chartCtx = document.getElementById("cpuChart").getContext("2d");
    const cpuChart = new Chart(chartCtx, {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            label: "CPU %",
            data: [],
            borderColor: "#4db7ff",
            backgroundColor: "rgba(77,183,255,0.18)",
            fill: false,
            tension: 0.28,
            pointRadius: 1.8,
          },
          {
            label: "RAM %",
            data: [],
            borderColor: "#22c55e",
            backgroundColor: "rgba(34,197,94,0.16)",
            fill: false,
            tension: 0.28,
            pointRadius: 1.8,
          },
          {
            label: "Battery %",
            data: [],
            borderColor: "#f59e0b",
            backgroundColor: "rgba(245,158,11,0.16)",
            fill: false,
            tension: 0.28,
            pointRadius: 1.8,
          }
        ]
      },
      options: {
        responsive: true,
        scales: {
          y: { beginAtZero: true, max: 100, ticks: { color: "#9eb2dd" }, grid: { color: "rgba(158,178,221,0.14)" } },
          x: { ticks: { color: "#9eb2dd" }, grid: { color: "rgba(158,178,221,0.08)" } }
        },
        plugins: {
          legend: { labels: { color: "#e2ebff" } }
        }
      }
    });

    const initialTheme = document.documentElement.getAttribute('data-theme') || 'light';
    updateChartColors(initialTheme);

    async function addPinnedPort(portOverride = null) {
      if (!hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }

      const rawPort = portOverride ?? document.getElementById("pinnedPortInput")?.value;
      const port = Number(rawPort);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        alert("Enter a valid port between 1 and 65535.");
        return;
      }

      try {
        await apiFetch("/state/pinned-ports", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ port }),
        });

        const input = document.getElementById("pinnedPortInput");
        if (input) input.value = "";
        await loadPinnedPorts();
      } catch (e) {
        alert(e.message || "Failed to pin port.");
      }
    }

    async function removePinnedPort(pinId) {
      if (!hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }

      try {
        await apiFetch(`/state/pinned-ports/${pinId}`, { method: "DELETE" });
        await loadPinnedPorts();
      } catch (e) {
        alert(e.message || "Failed to remove pinned port.");
      }
    }

    async function terminatePinnedPort(port) {
      if (!hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }

      if (!confirm(`Stop processes listening on port ${port}?`)) {
        return;
      }

      try {
        const res = await apiFetch(`/ports/${port}/terminate`, { method: "POST" });
        const data = await res.json();
        if (data.status === "no_process") {
          alert(`No process found on port ${port}.`);
        }
        await Promise.all([loadPinnedPorts(), loadPorts()]);
      } catch (e) {
        alert(e.message || "Failed to stop port processes.");
      }
    }

    async function renamePortAliasByPort(port) {
      const normalizedPort = Number(port);
      if (!Number.isInteger(normalizedPort) || normalizedPort < 1 || normalizedPort > 65535) {
        alert("Invalid port.");
        return;
      }

      const key = String(normalizedPort);
      const currentAlias = portAliases[key] || "";
      const nextAlias = prompt(`Set alias for port ${normalizedPort} (leave empty to clear):`, currentAlias);
      if (nextAlias === null) return;

      const trimmed = String(nextAlias).trim().slice(0, 40);
      if (trimmed) {
        portAliases[key] = trimmed;
      } else {
        delete portAliases[key];
      }

      savePortAliases();
      await Promise.all([loadPinnedPorts(), loadPorts()]);
    }

    async function pinPortFromMenu(port, triggerEl = null) {
      if (triggerEl && triggerEl.closest("details")) {
        triggerEl.closest("details").removeAttribute("open");
      }

      if (!Number.isInteger(Number(port))) {
        alert("Port value is invalid for pinning.");
        return;
      }

      await addPinnedPort(Number(port));
    }

    async function loadPinnedPorts() {
      const body = document.getElementById("pinnedPortsBody");
      if (!body) return;

      try {
        const res = await apiFetch("/state/pinned-ports");
        const data = await res.json();
        pinnedPorts = data.ports || [];
      } catch {
        pinnedPorts = [];
      }

      if (!pinnedPorts.length) {
        body.innerHTML = `<tr><td colspan="4" class="muted">No pinned ports yet.</td></tr>`;
        return;
      }

      const rows = await Promise.all(pinnedPorts.map(async (item) => {
        let active = false;
        try {
          const res = await apiFetch(`/check-port/${item.port}`, {}, { silent: true });
          const data = await res.json();
          active = !!data.active;
        } catch {
          active = false;
        }

        const alias = portAliases[String(item.port)] || "";
        const canOperate = hasRole("operator");
        const hasCommand = !!item.command;
        const svcLabel = item.service_name ? esc(item.service_name) : `port-${item.port}`;

        let actionButtons = `<button class="btn-neutral" onclick="renamePortAliasByPort(${item.port})">Rename</button>`;

        if (hasCommand && canOperate) {
          if (active) {
            actionButtons += `<button class="btn-warn" onclick="stopPinnedPortSvc(${item.id})">Stop</button>`;
            actionButtons += `<button class="btn-neutral" onclick="restartPinnedPortSvc(${item.id})">Restart</button>`;
          } else {
            actionButtons += `<button class="btn-success" onclick="startPinnedPortSvc(${item.id})">Start</button>`;
          }
        } else if (canOperate) {
          actionButtons += `<button class="btn-warn" onclick="terminatePinnedPort(${item.port})">Stop</button>`;
        }

        actionButtons += `<button class="btn-neutral" onclick="openPinnedPortServiceModal(${item.id})">Configure</button>`;

        if (canOperate) {
          actionButtons += `<button class="btn-danger" onclick="removePinnedPort(${item.id})">Unpin</button>`;
        }

        return `
          <tr>
            <td>${esc(item.port)}</td>
            <td>${alias ? esc(alias) : '<span class="muted">—</span>'}</td>
            <td class="${active ? "status-up" : "status-down"}">${active ? "Active" : "Down"}${hasCommand ? ` <span class="muted" style="font-size:0.72rem;">(${svcLabel})</span>` : ""}</td>
            <td>
              <div class="actions">
                ${actionButtons}
              </div>
            </td>
          </tr>
        `;
      }));

      body.innerHTML = rows.join("");
    }

    async function loadBattery() {
      try {
        const res = await apiFetch("/battery");
        const data = await res.json();

        if (data.percent === null || data.percent === undefined) {
          lastBatteryPercent = null;
          document.getElementById("batteryValue").innerText = "N/A";
          document.getElementById("batteryMode").innerText = "Battery info unavailable";
          return;
        }

        lastBatteryPercent = Number(data.percent);
        document.getElementById("batteryValue").innerText = `${lastBatteryPercent.toFixed(1)}%`;
        document.getElementById("batteryMode").innerText = data.plugged ? "Charging" : "On battery";
      } catch {
        lastBatteryPercent = null;
        document.getElementById("batteryValue").innerText = "--%";
        document.getElementById("batteryMode").innerText = "Battery check failed";
      }
    }

    async function loadSystem() {
      try {
        const res = await apiFetch("/system");
        const data = await res.json();

        const cpu = Number(data.cpu || 0);
        const ram = Number(data.memory || 0);

        document.getElementById("cpuValue").innerText = `${cpu.toFixed(1)}%`;
        document.getElementById("ramValue").innerText = `${ram.toFixed(1)}%`;

        if (data.vmem) {
          const usedGB = (data.vmem.used / (1024 * 1024 * 1024)).toFixed(1);
          const totalGB = (data.vmem.total / (1024 * 1024 * 1024)).toFixed(1);
          document.getElementById("ramDelta").innerText = `${usedGB} GB / ${totalGB} GB Used`;
        } else {
          document.getElementById("ramDelta").innerText = "Current memory consumption";
        }

        const nowMs = Date.now();
        if (nowMs - lastTrendPointAt >= TREND_SAMPLE_INTERVAL_MS) {
          lastTrendPointAt = nowMs;
          trendPoints.push({
            t: nowMs,
            cpu,
            ram,
            battery: Number.isFinite(lastBatteryPercent) ? lastBatteryPercent : null,
          });
        }

        const cutoff = nowMs - TREND_WINDOW_MINUTES * 60 * 1000;
        trendPoints = trendPoints.filter((p) => p.t >= cutoff);

        cpuChart.data.labels = trendPoints.map((p) =>
          new Date(p.t).toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit" })
        );
        cpuChart.data.datasets[0].data = trendPoints.map((p) => p.cpu);
        cpuChart.data.datasets[1].data = trendPoints.map((p) => p.ram);
        cpuChart.data.datasets[2].data = trendPoints.map((p) => p.battery);
        cpuChart.update();
      } catch {
        document.getElementById("cpuValue").innerText = "--%";
        document.getElementById("ramValue").innerText = "--%";
        document.getElementById("ramDelta").innerText = "Connection failed";
      }
    }

    async function loadPorts() {
      const body = document.getElementById("portsBody");
      try {
        const res = await apiFetch("/ports");
        const ports = await res.json();
        const normalized = (ports || []).map(normalizePortEntry).filter((entry) => !!entry.local);

        const snapshot = new Map();
        normalized.forEach((entry) => snapshot.set(entry.key, entry));

        if (lastPortSnapshot.size > 0) {
          updateRecentPortActivity(snapshot);
        }
        lastPortSnapshot = snapshot;
        renderRecentPortActivity();

        if (!normalized.length) {
          body.innerHTML = `<tr><td colspan="5" class="muted">No open ports found.</td></tr>`;
          return;
        }

        body.innerHTML = normalized.slice(0, 20).map((p) => {
          const alias = p.port ? (portAliases[String(p.port)] || "") : "";
          const encodedLocal = encodeURIComponent(p.local);
          return `
          <tr>
            <td>${esc(p.protocol)}</td>
            <td>${esc(p.state)}</td>
            <td>${esc(p.local)}</td>
            <td>${alias ? esc(alias) : '<span class="muted">—</span>'}</td>
            <td>
              ${p.port
                ? `<details class="port-action-menu">
                    <summary aria-label="Port actions" title="Actions">⋮</summary>
                    <div class="port-menu-dropdown">
                      <button class="port-menu-item" onclick="renamePortAlias('${encodedLocal}', this)">Rename</button>
                      ${hasRole("operator") ? `<button class="port-menu-item" onclick="pinPortFromMenu(${p.port}, this)">Pin Port</button>` : ""}
                    </div>
                  </details>`
                : '<span class="muted">N/A</span>'}
            </td>
          </tr>
        `;
        }).join("");
      } catch {
        renderRecentPortActivity();
        body.innerHTML = `<tr><td colspan="5" class="muted">Failed to load port data.</td></tr>`;
      }
    }


// Expose to window
window.getThemeChartPalette = getThemeChartPalette;
window.loadPortAliases = loadPortAliases;
window.savePortAliases = savePortAliases;
window.loadRecentPortActivity = loadRecentPortActivity;
window.saveRecentPortActivity = saveRecentPortActivity;
window.extractPortNumber = extractPortNumber;
window.normalizePortEntry = normalizePortEntry;
window.recordPortActivity = recordPortActivity;
window.updateRecentPortActivity = updateRecentPortActivity;
window.renderRecentPortActivity = renderRecentPortActivity;
window.renamePortAlias = renamePortAlias;
window.updateAccessTabs = updateAccessTabs;
window.setAccessHubCount = setAccessHubCount;
window.setAccessHubTunnelState = setAccessHubTunnelState;
window.loadAccessHubStats = loadAccessHubStats;
window.updateChartColors = updateChartColors;
window.addPinnedPort = addPinnedPort;
window.removePinnedPort = removePinnedPort;
window.terminatePinnedPort = terminatePinnedPort;
window.renamePortAliasByPort = renamePortAliasByPort;
window.pinPortFromMenu = pinPortFromMenu;
window.loadPinnedPorts = loadPinnedPorts;
window.loadBattery = loadBattery;
window.loadSystem = loadSystem;
window.loadPorts = loadPorts;
