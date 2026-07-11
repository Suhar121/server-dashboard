// Docker Container Management
    
    // --- Docker Manager logic ---
    async function loadDockerContainers() {
      const body = document.getElementById("dockerFullBody");
      if (!body) return;

      try {
        const res = await apiFetch("/docker");
        const data = await res.json();
        const containers = Array.isArray(data) ? data : (data.containers || []);

        const runningCount = containers.filter((c) => String(c.state || "").toLowerCase() === "running").length;
        const imageCount = new Set(containers.map((c) => String(c.image || "")).filter(Boolean)).size;

        document.getElementById("dockerKpiTotal").innerText = containers.length;
        document.getElementById("dockerKpiRunning").innerText = `${runningCount} running`;
        document.getElementById("dockerKpiImages").innerText = imageCount;

        if (!containers.length) {
          body.innerHTML = `<tr><td colspan="6" class="muted">No containers found.</td></tr>`;
          return;
        }

        body.innerHTML = containers.map((c) => {
          const id = String(c.id || "");
          const isRunning = String(c.state || "").toLowerCase() === "running";
          
          const statusBadgeClass = isRunning ? "docker-status-badge docker-status-up" : "docker-status-badge docker-status-down";
          const statusText = isRunning ? "running" : (c.state || "stopped");

          const portsRaw = String(c.ports || "").split(",").map(p => p.trim()).filter(Boolean);
          const portsHtml = portsRaw.length > 0 
            ? portsRaw.map(p => `<span class="docker-port-badge">${esc(p)}</span>`).join("")
            : `<span class="muted" style="font-size:0.78rem;">No exposed ports</span>`;

          const idShort = id ? esc(id.substring(0, 12)) : "--";

          const restartSvg = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>';
          const stopSvg = '<svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="1"/></svg>';
          const startSvg = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>';
          const logsSvg = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>';
          const consoleSvg = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/></svg>';

          const actionButtons = id
            ? (isRunning
              ? `<button class="btn-warn" onclick="dockerAction('${esc(id)}', 'restart')" title="Restart" style="height:28px;width:28px;padding:0;">${restartSvg}</button>
                 <button class="btn-danger" onclick="dockerAction('${esc(id)}', 'stop')" title="Stop" style="height:28px;width:28px;padding:0;">${stopSvg}</button>`
              : `<button class="btn-success" onclick="dockerAction('${esc(id)}', 'start')" title="Start" style="height:28px;width:28px;padding:0;">${startSvg}</button>`)
            : "";

          return `
            <tr>
              <td style="font-family:var(--font-mono);font-size:0.78rem;color:var(--muted);">${idShort}</td>
              <td style="font-weight:500;">${esc(c.name || "--")}</td>
              <td><span style="font-size:0.78rem;color:var(--text-secondary);">${esc(c.image || "--")}</span></td>
              <td>
                <div style="display:flex;flex-direction:column;gap:3px;">
                  <span class="${statusBadgeClass}">${esc(statusText)}</span>
                  <span style="font-size:0.68rem;color:var(--muted);">${esc(c.status || "--")}</span>
                </div>
              </td>
              <td><div style="display:flex;flex-wrap:wrap;gap:4px;">${portsHtml}</div></td>
              <td>
                <div style="display:flex;gap:4px;align-items:center;">
                  ${actionButtons}
                  ${id ? `<button class="btn-outline" onclick="dockerLogs('${esc(id)}')" title="Logs" style="height:28px;width:28px;padding:0;">${logsSvg}</button>` : ""}
                  ${isRunning && id ? `<button class="btn-outline" onclick="dockerExec('${esc(id)}')" title="Console" style="height:28px;width:28px;padding:0;">${consoleSvg}</button>` : ""}
                </div>
              </td>
            </tr>
          `;
        }).join("");
      } catch (e) {
        body.innerHTML = `<tr><td colspan="6" class="error-text">Failed to load docker list: ${esc(e.message)}</td></tr>`;
      }
    }

    async function dockerAction(id, action) {
      try {
        await apiFetch("/docker/action", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ container_id: id, action }),
        });
        await loadDockerContainers();
        await loadDocker();
      } catch (e) {
        alert(e.message || `Failed to ${action} container.`);
      }
    }

    async function dockerLogs(id) {
      try {
        const res = await apiFetch(`/docker/logs/${encodeURIComponent(id)}?lines=200`);
        const data = await res.json();
        const lines = Array.isArray(data.logs) ? data.logs : [];
        if (logTimer) {
          clearInterval(logTimer);
          logTimer = null;
        }
        currentLogService = null;
        document.getElementById("logTitle").innerText = `📜 Docker Logs (${id.substring(0, 12)})`;
        document.getElementById("logModal").style.display = "block";
        document.getElementById("logContent").textContent = lines.length ? lines.join("") : "No logs.";
      } catch (e) {
        alert(e.message || "Failed to load Docker logs.");
      }
    }

    function dockerExec(id) {
      goToPage("terminal");
      alert(`Use terminal command: docker exec -it ${id.substring(0, 12)} /bin/sh`);
    }

    function pruneDocker() {
      alert("Manual mode: run this in your terminal -> docker image prune -f");
    }

    // ─── PM2 Manager JS Functions ───
    let pm2LogsWs = null;
    let pm2LogsAppName = null;
    let pm2LogsFullContent = "";


// Expose to window
window.loadDockerContainers = loadDockerContainers;
window.dockerAction = dockerAction;
window.dockerLogs = dockerLogs;
window.dockerExec = dockerExec;
window.pruneDocker = pruneDocker;
