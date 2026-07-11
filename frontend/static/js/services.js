// Services Controls & Logs
    function openPinnedPortServiceModal(pinId) {
      const pin = pinnedPorts.find(p => p.id === pinId);
      if (!pin) return;

      document.getElementById("ppSvcPinId").value = pinId;
      document.getElementById("ppSvcName").value = pin.service_name || "";
      document.getElementById("ppSvcCommand").value = pin.command || "";
      document.getElementById("ppSvcSetup").value = pin.setup_command || "";
      document.getElementById("ppSvcWorkdir").value = pin.workdir || "";
      document.getElementById("ppSvcError").textContent = "";
      document.getElementById("ppSvcSuccess").textContent = "";
      document.getElementById("pinnedPortServiceDesc").textContent = `Port ${pin.port} — Set up a start command so you can start/stop the service from the dashboard.`;

      const hasExisting = !!pin.command;
      document.getElementById("ppSvcClearBtn").style.display = hasExisting ? "" : "none";

      document.getElementById("pinnedPortServiceModal").style.display = "flex";
      lucide.createIcons();
    }

    function closePinnedPortServiceModal() {
      document.getElementById("pinnedPortServiceModal").style.display = "none";
    }

    async function savePinnedPortService() {
      const pinId = Number(document.getElementById("ppSvcPinId").value);
      if (!pinId) return;

      const serviceName = document.getElementById("ppSvcName").value.trim();
      const command = document.getElementById("ppSvcCommand").value.trim();
      const setupCommand = document.getElementById("ppSvcSetup").value.trim();
      const workdir = document.getElementById("ppSvcWorkdir").value.trim();

      const errEl = document.getElementById("ppSvcError");
      const okEl = document.getElementById("ppSvcSuccess");
      errEl.textContent = "";
      okEl.textContent = "";

      if (command && !serviceName) {
        errEl.textContent = "Service Name is required when a Start Command is set.";
        return;
      }

      try {
        await apiFetch(`/state/pinned-ports/${pinId}/service`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            service_name: serviceName || null,
            command: command || null,
            setup_command: setupCommand || null,
            workdir: workdir || null,
          }),
        });

        okEl.textContent = "Saved! You can close this dialog.";
        await loadPinnedPorts();
      } catch (e) {
        errEl.textContent = e.message || "Failed to save service config.";
      }
    }

    async function clearPinnedPortService() {
      const pinId = Number(document.getElementById("ppSvcPinId").value);
      if (!pinId) return;

      if (!confirm("Remove the service configuration for this pinned port? The port will remain pinned but Start/Stop buttons will disappear.")) return;

      const errEl = document.getElementById("ppSvcError");
      const okEl = document.getElementById("ppSvcSuccess");
      errEl.textContent = "";
      okEl.textContent = "";

      try {
        await apiFetch(`/state/pinned-ports/${pinId}/service`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            service_name: null,
            command: null,
            setup_command: null,
            workdir: null,
          }),
        });

        okEl.textContent = "Configuration removed.";
        await loadPinnedPorts();
      } catch (e) {
        errEl.textContent = e.message || "Failed to clear service config.";
      }
    }

    async function startPinnedPortSvc(pinId) {
      if (!hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }

      const pin = pinnedPorts.find(p => p.id === pinId);
      const label = pin ? (pin.service_name || `port-${pin.port}`) : "service";

      try {
        const res = await apiFetch(`/state/pinned-ports/${pinId}/start`, { method: "POST" });
        const data = await res.json();

        if (data.status === "setup_failed") {
          alert(`Setup failed for '${label}':\n${data.stderr || data.stdout || "Unknown error"}`);
        } else if (data.status === "already_running") {
          alert(`'${label}' is already running.`);
        }
      } catch (e) {
        alert(e.message || `Failed to start ${label}.`);
      }

      await loadPinnedPorts();
    }

    async function stopPinnedPortSvc(pinId) {
      if (!hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }

      const pin = pinnedPorts.find(p => p.id === pinId);
      const label = pin ? (pin.service_name || `port-${pin.port}`) : "service";

      try {
        const res = await apiFetch(`/state/pinned-ports/${pinId}/stop`, { method: "POST" });
        const data = await res.json();

        if (data.status === "not_managed") {
          alert(`'${label}' is not currently managed. Trying process kill instead.`);
          if (pin) await terminatePinnedPort(pin.port);
          return;
        }
      } catch (e) {
        alert(e.message || `Failed to stop ${label}.`);
      }

      await loadPinnedPorts();
    }

    async function restartPinnedPortSvc(pinId) {
      if (!hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }

      await stopPinnedPortSvc(pinId);
      await startPinnedPortSvc(pinId);
    }

    async function addService() {
      if (!hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }

      const name = document.getElementById("serviceName").value.trim();
      const port = Number(document.getElementById("servicePort").value);
      const command = document.getElementById("serviceCommand").value.trim();

      if (!name || !port || !command) {
        alert("Please enter service name, port, and command.");
        return;
      }

      try {
        await apiFetch("/state/services", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name, port, command }),
        });

        document.getElementById("serviceName").value = "";
        document.getElementById("servicePort").value = "";
        document.getElementById("serviceCommand").value = "";

        await loadServices();
      } catch (e) {
        alert(e.message || "Failed to save pinned service.");
      }
    }

    async function loadServices() {
      const body = document.getElementById("servicesBody");
      try {
        const res = await apiFetch("/state/services");
        const data = await res.json();
        services = data.services || [];
      } catch {
        services = [];
      }

      if (!services.length) {
        body.innerHTML = `<tr><td colspan="4" class="muted">No services added yet.</td></tr>`;
        return;
      }

      const rows = await Promise.all(services.map(async (s) => {
        let active = false;
        try {
          const res = await apiFetch(`/check-port/${s.port}`, {}, { silent: true });
          const data = await res.json();
          active = !!data.active;
        } catch {
          active = false;
        }

        const canOperate = hasRole("operator");
        const isAdmin = hasRole("admin");

        return `
          <tr>
            <td>${esc(s.name)}</td>
            <td>${esc(s.port)}</td>
            <td class="${active ? "status-up" : "status-down"}">
              ${active ? "Active" : "Down"}
            </td>
            <td>
              <div class="actions">
                ${canOperate ? `<button class="btn-success" onclick="startServiceById(${s.id})">Start</button>` : ""}
                ${canOperate ? `<button class="btn-warn" onclick="restartServiceById(${s.id})">Restart</button>` : ""}
                ${canOperate ? `<button class="btn-danger" onclick="stopServiceById(${s.id})">Stop</button>` : ""}
                ${isAdmin ? `<button class="btn-neutral" onclick="quickTunnelService(${s.id})">🌐 Tunnel</button>` : ""}
                <button class="btn-neutral" onclick="viewLogsById(${s.id})">📜 View Logs</button>
                ${isAdmin ? `<button class="btn-danger" onclick="removeService(${s.id})">Remove</button>` : ""}
              </div>
            </td>
          </tr>
        `;
      }));

      body.innerHTML = rows.join("");
    }

    async function removeService(serviceId) {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      try {
        await apiFetch(`/state/services/${serviceId}`, { method: "DELETE" });
        await loadServices();
      } catch (e) {
        alert(e.message || "Failed to remove pinned service.");
      }
    }

    function getServiceById(serviceId) {
      return services.find((s) => s.id === serviceId);
    }

    function getCloudflaredRouteById(routeId) {
      return cloudflaredRoutes.find((r) => r.id === routeId);
    }

    async function quickTunnelService(serviceId) {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      const service = getServiceById(serviceId);
      if (!service) {
        alert("Service not found.");
        return;
      }

      const suggested = `${service.name || "my-app"}`
        .toLowerCase()
        .replace(/[^a-z0-9-]+/g, "-")
        .replace(/^-+|-+$/g, "") || "my-app";
      const hostname = prompt(
        `Hostname for service '${service.name}' on port ${service.port} (e.g. ${suggested}.yourdomain.com):`,
        `${suggested}.yourdomain.com`
      );

      if (!hostname || !hostname.trim()) {
        return;
      }

      try {
        const res = await apiFetch("/cloudflared/routes", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            hostname: hostname.trim(),
            service_scheme: "http",
            service_host: "127.0.0.1",
            service_port: Number(service.port),
          }),
        });
        const data = await res.json();

        const dnsLabel = data.dns_routed ? "DNS ready" : `DNS warning: ${data.dns_message || "not configured"}`;
        alert(`Tunnel ready for '${service.name}'\n${data.public_url || `https://${hostname.trim()}`}\n${dnsLabel}`);

        if (currentPage === "cloudflared") {
          await loadCloudflaredRoutes();
        }
      } catch (e) {
        alert(e.message || "Failed to create tunnel route.");
      }
    }

    async function startServiceById(serviceId) {
      if (!hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }
      const s = getServiceById(serviceId);
      if (!s) return;

      await apiFetch("/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: s.name, port: s.port, command: s.command })
      });

      loadServices();
    }

    async function stopServiceById(serviceId) {
      if (!hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }
      const s = getServiceById(serviceId);
      if (!s) return;

      await apiFetch("/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: s.name })
      });

      loadServices();
    }

    async function restartServiceById(serviceId) {
      const s = getServiceById(serviceId);
      if (!s) return;

      await stopServiceById(serviceId);
      await startServiceById(serviceId);
      loadServices();
    }

    function viewLogsById(serviceId) {
      const s = getServiceById(serviceId);
      if (!s) return;

      currentLogService = s.name;
      document.getElementById("logTitle").innerText = `📜 ${s.name} Logs`;
      document.getElementById("logModal").style.display = "block";
      refreshLogs();

      if (logTimer) clearInterval(logTimer);
      logTimer = setInterval(refreshLogs, 2000);
    }

    function closeLogs() {
      currentLogService = null;
      document.getElementById("logModal").style.display = "none";
      if (logTimer) {
        clearInterval(logTimer);
        logTimer = null;
      }
    }

    async function refreshLogs() {
      if (!currentLogService) return;
      try {
        const res = await apiFetch(`/logs/${encodeURIComponent(currentLogService)}?lines=100`);
        const data = await res.json();
        const content = document.getElementById("logContent");
        content.textContent = (data.logs || ["No logs yet"]).join("");
        content.scrollTop = content.scrollHeight;
      } catch {
        document.getElementById("logContent").textContent = "Unable to load logs.";
      }
    }


// Expose to window
window.openPinnedPortServiceModal = openPinnedPortServiceModal;
window.closePinnedPortServiceModal = closePinnedPortServiceModal;
window.savePinnedPortService = savePinnedPortService;
window.clearPinnedPortService = clearPinnedPortService;
window.startPinnedPortSvc = startPinnedPortSvc;
window.stopPinnedPortSvc = stopPinnedPortSvc;
window.restartPinnedPortSvc = restartPinnedPortSvc;
window.addService = addService;
window.loadServices = loadServices;
window.removeService = removeService;
window.getServiceById = getServiceById;
window.getCloudflaredRouteById = getCloudflaredRouteById;
window.quickTunnelService = quickTunnelService;
window.startServiceById = startServiceById;
window.stopServiceById = stopServiceById;
window.restartServiceById = restartServiceById;
window.viewLogsById = viewLogsById;
window.closeLogs = closeLogs;
window.refreshLogs = refreshLogs;
