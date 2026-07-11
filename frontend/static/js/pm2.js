// PM2 Process Management
    async function loadPm2Processes() {
      const body = document.getElementById("pm2ProcessBody");
      if (!body) return;

      try {
        const res = await apiFetch("/api/pm2/list");
        if (res.status === 403) {
          body.innerHTML = `<tr><td colspan="11" class="error-text">Forbidden: Administrator access required.</td></tr>`;
          return;
        }
        const data = await res.json();
        
        if (!data || data.length === 0) {
          body.innerHTML = `<tr><td colspan="11" style="padding:32px;text-align:center;color:var(--muted);font-size:0.85rem;">No PM2 applications running.</td></tr>`;
          return;
        }

        body.innerHTML = data.map(app => {
          let statusBadge = "";
          const status = String(app.status || "").toLowerCase();
          if (status === "online") {
            statusBadge = `<span class="docker-status-badge docker-status-up" style="background:var(--ok-soft);color:var(--ok);">online</span>`;
          } else if (status === "stopped") {
            statusBadge = `<span class="docker-status-badge docker-status-down" style="background:var(--muted-soft);color:var(--muted);">stopped</span>`;
          } else {
            statusBadge = `<span class="docker-status-badge docker-status-down" style="background:var(--bad-soft);color:var(--bad);">${esc(status)}</span>`;
          }

          const memoryFormatted = formatBytes(app.memory || 0);
          const cpuFormatted = `${app.cpu || 0}%`;
          const uptimeFormatted = app.uptime ? formatDuration(app.uptime) : "0s";
          const versionFormatted = esc(app.version || "N/A");
          const workingDir = esc(app.cwd || "N/A");

          return `
            <tr>
              <td><strong>${esc(app.id)}</strong></td>
              <td><span style="font-weight:600;color:var(--brand);">${esc(app.name)}</span></td>
              <td class="muted">${esc(app.pid || "-")}</td>
              <td>${statusBadge}</td>
              <td style="font-family:monospace;">${cpuFormatted}</td>
              <td style="font-family:monospace;">${memoryFormatted}</td>
              <td class="muted">${uptimeFormatted}</td>
              <td class="muted">${esc(app.restarts)}</td>
              <td class="muted">${versionFormatted}</td>
              <td><div style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${workingDir}">${workingDir}</div></td>
              <td>
                <div style="display:flex;gap:4px;">
                  ${status !== "online" 
                    ? `<button class="btn-neutral" style="padding:2px 6px;min-height:0;font-size:0.75rem;" onclick="pm2AppAction('${esc(app.name)}', 'start')">▶ Start</button>`
                    : `<button class="btn-neutral" style="padding:2px 6px;min-height:0;font-size:0.75rem;" onclick="pm2AppAction('${esc(app.name)}', 'stop')">⏹ Stop</button>`
                  }
                  <button class="btn-neutral" style="padding:2px 6px;min-height:0;font-size:0.75rem;" onclick="pm2AppAction('${esc(app.name)}', 'restart')">🔄 Restart</button>
                  <button class="btn-neutral" style="padding:2px 6px;min-height:0;font-size:0.75rem;" onclick="pm2AppAction('${esc(app.name)}', 'reload')">⚡ Reload</button>
                  <button class="btn-neutral" style="padding:2px 6px;min-height:0;font-size:0.75rem;" onclick="openPm2LogsModal('${esc(app.name)}')">📋 Logs</button>
                  <button class="btn-danger" style="padding:2px 6px;min-height:0;font-size:0.75rem;background:var(--bad);" onclick="pm2AppAction('${esc(app.name)}', 'delete')">🗑 Delete</button>
                </div>
              </td>
            </tr>
          `;
        }).join("");
      } catch (e) {
        body.innerHTML = `<tr><td colspan="11" class="error-text">Failed to fetch PM2 list: ${esc(e.message)}</td></tr>`;
      }
    }

    async function pm2GlobalAction(action) {
      if (action === "kill" && !confirm("Are you sure you want to KILL the PM2 daemon? All running applications will stop.")) {
        return;
      }
      try {
        const res = await apiFetch("/api/pm2/action", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action })
        });
        const result = await res.json();
        if (res.ok) {
          alert(`Global command '${action}' completed successfully.`);
          loadPm2Processes();
        } else {
          alert(`Error: ${result.detail || "Command failed"}`);
        }
      } catch (e) {
        alert(`Failed to execute global action: ${e.message}`);
      }
    }

    async function pm2AppAction(appName, action) {
      if (action === "delete" && !confirm(`Are you sure you want to delete '${appName}'?`)) {
        return;
      }
      try {
        const res = await apiFetch("/api/pm2/action", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action, app_name: appName })
        });
        const result = await res.json();
        if (res.ok) {
          loadPm2Processes();
        } else {
          alert(`Error: ${result.detail || "App action failed"}`);
        }
      } catch (e) {
        alert(`Failed to execute app action: ${e.message}`);
      }
    }

    function openStartPm2AppModal() {
      document.getElementById("pm2AppName").value = "";
      document.getElementById("pm2AppScript").value = "";
      document.getElementById("pm2AppCwd").value = "";
      document.getElementById("pm2AppInterpreter").value = "auto";
      document.getElementById("pm2AppArgs").value = "";
      document.getElementById("pm2AppEnv").value = "";
      document.getElementById("pm2AppInstances").value = "";
      document.getElementById("pm2AppMaxMemory").value = "";
      document.getElementById("pm2AppDelay").value = "";
      document.getElementById("pm2AppCron").value = "";
      document.getElementById("pm2AppAutorestart").checked = true;
      document.getElementById("pm2AppWatch").checked = false;
      document.getElementById("startPm2AppModal").style.display = "flex";
    }

    function closeStartPm2AppModal() {
      document.getElementById("startPm2AppModal").style.display = "none";
    }

    async function pm2StartNewApp() {
      const name = document.getElementById("pm2AppName").value.trim();
      const script = document.getElementById("pm2AppScript").value.trim();
      
      if (!name || !script) {
        alert("App Name and Start Script are required.");
        return;
      }

      const cwd = document.getElementById("pm2AppCwd").value.trim() || null;
      const interpreter = document.getElementById("pm2AppInterpreter").value;
      const args = document.getElementById("pm2AppArgs").value.trim() || null;
      const envRaw = document.getElementById("pm2AppEnv").value.trim();
      const instancesRaw = document.getElementById("pm2AppInstances").value;
      const maxMemory = document.getElementById("pm2AppMaxMemory").value.trim() || null;
      const delayRaw = document.getElementById("pm2AppDelay").value;
      const cron = document.getElementById("pm2AppCron").value.trim() || null;
      const autorestart = document.getElementById("pm2AppAutorestart").checked;
      const watch = document.getElementById("pm2AppWatch").checked;

      let env_vars = null;
      if (envRaw) {
        try {
          env_vars = JSON.parse(envRaw);
        } catch (e) {
          alert("Invalid JSON format in Environment Variables field.");
          return;
        }
      }

      const instances = instancesRaw ? parseInt(instancesRaw, 10) : null;
      const startup_delay = delayRaw ? parseInt(delayRaw, 10) : null;

      const payload = {
        name,
        script,
        cwd,
        interpreter,
        args,
        env_vars,
        autorestart,
        watch,
        instances,
        max_memory_restart: maxMemory,
        startup_delay,
        cron_restart: cron
      };

      try {
        const res = await apiFetch("/api/pm2/start-app", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const result = await res.json();
        if (res.ok) {
          closeStartPm2AppModal();
          loadPm2Processes();
        } else {
          alert(`Failed to start application: ${result.detail || "Error"}`);
        }
      } catch (e) {
        alert(`Failed to start application: ${e.message}`);
      }
    }

    function openPm2LogsModal(appName) {
      pm2LogsAppName = appName;
      document.getElementById("pm2LogsTitle").innerText = `📋 PM2 Logs: ${appName}`;
      document.getElementById("pm2LogsContent").textContent = "Loading logs...";
      document.getElementById("pm2LogsModal").style.display = "flex";
      
      pm2LogsFullContent = "";
      reloadPm2Logs();
      startPm2LogsStream(appName);
    }

    function closePm2LogsModal() {
      stopPm2LogsStream();
      document.getElementById("pm2LogsModal").style.display = "none";
    }

    async function reloadPm2Logs() {
      if (!pm2LogsAppName) return;
      const limit = document.getElementById("pm2LogsLinesLimit").value;
      
      try {
        const res = await apiFetch(`/api/pm2/logs/${encodeURIComponent(pm2LogsAppName)}?limit=${limit}`);
        const data = await res.json();
        if (res.ok) {
          pm2LogsFullContent = data.logs || "No logs available.";
          displayPm2Logs();
        } else {
          pm2LogsFullContent = `Error loading logs: ${data.detail || "Unknown error"}`;
          displayPm2Logs();
        }
      } catch (e) {
        pm2LogsFullContent = `Error loading logs: ${e.message}`;
        displayPm2Logs();
      }
    }

    function startPm2LogsStream(appName) {
      stopPm2LogsStream();

      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${protocol}//${window.location.host}/ws/pm2/logs/${encodeURIComponent(appName)}/stream`;
      
      pm2LogsWs = new WebSocket(wsUrl);
      
      pm2LogsWs.onopen = () => {
        console.log("PM2 logs stream connected.");
        document.getElementById("pm2LogsSubtitle").innerText = "Streaming real-time logs...";
        setPm2LogsStreamBtnState(true);
      };

      pm2LogsWs.onmessage = (event) => {
        pm2LogsFullContent += event.data;
        displayPm2Logs();
      };

      pm2LogsWs.onclose = (event) => {
        console.log("PM2 logs stream closed:", event.reason);
        document.getElementById("pm2LogsSubtitle").innerText = "Stream paused/disconnected.";
        setPm2LogsStreamBtnState(false);
      };

      pm2LogsWs.onerror = (err) => {
        console.error("PM2 logs stream error:", err);
      };
    }

    function stopPm2LogsStream() {
      if (pm2LogsWs) {
        pm2LogsWs.close();
        pm2LogsWs = null;
      }
      setPm2LogsStreamBtnState(false);
    }

    function togglePm2LogsStream() {
      if (pm2LogsWs) {
        stopPm2LogsStream();
        document.getElementById("pm2LogsSubtitle").innerText = "Stream paused.";
      } else {
        if (pm2LogsAppName) {
          startPm2LogsStream(pm2LogsAppName);
        }
      }
    }

    function setPm2LogsStreamBtnState(active) {
      const btn = document.getElementById("pm2LogsStreamToggle");
      if (!btn) return;
      if (active) {
        btn.style.background = "var(--ok-soft)";
        btn.style.color = "var(--ok)";
        btn.innerHTML = `<i data-lucide="play" style="width:12px;height:12px;"></i> Streaming`;
      } else {
        btn.style.background = "var(--border)";
        btn.style.color = "var(--text)";
        btn.innerHTML = `<i data-lucide="pause" style="width:12px;height:12px;"></i> Paused`;
      }
      if (typeof lucide !== "undefined") lucide.createIcons();
    }

    function clearPm2LogsDisplay() {
      pm2LogsFullContent = "";
      displayPm2Logs();
    }

    function displayPm2Logs() {
      const container = document.getElementById("pm2LogsContent");
      if (!container) return;

      const filterText = document.getElementById("pm2LogsSearch").value.toLowerCase().trim();
      if (!filterText) {
        container.textContent = pm2LogsFullContent;
      } else {
        const lines = pm2LogsFullContent.split("\n");
        const filtered = lines.filter(line => line.toLowerCase().includes(filterText));
        container.textContent = filtered.join("\n");
      }
      
      // Auto-scroll to bottom
      container.scrollTop = container.scrollHeight;
    }

    function filterPm2Logs() {
      displayPm2Logs();
    }

    function downloadPm2Logs() {
      if (!pm2LogsAppName) return;
      const element = document.createElement("a");
      const file = new Blob([pm2LogsFullContent], {type: "text/plain"});
      element.href = URL.createObjectURL(file);
      element.download = `pm2_${pm2LogsAppName}_logs.txt`;
      document.body.appendChild(element);
      element.click();
      document.body.removeChild(element);
    }


// Expose to window
window.loadPm2Processes = loadPm2Processes;
window.pm2GlobalAction = pm2GlobalAction;
window.pm2AppAction = pm2AppAction;
window.openStartPm2AppModal = openStartPm2AppModal;
window.closeStartPm2AppModal = closeStartPm2AppModal;
window.pm2StartNewApp = pm2StartNewApp;
window.openPm2LogsModal = openPm2LogsModal;
window.closePm2LogsModal = closePm2LogsModal;
window.reloadPm2Logs = reloadPm2Logs;
window.startPm2LogsStream = startPm2LogsStream;
window.stopPm2LogsStream = stopPm2LogsStream;
window.togglePm2LogsStream = togglePm2LogsStream;
window.clearPm2LogsDisplay = clearPm2LogsDisplay;
window.displayPm2Logs = displayPm2Logs;
window.filterPm2Logs = filterPm2Logs;
window.downloadPm2Logs = downloadPm2Logs;
