// SSH Keys, Users, Audits, Cloudflared Routes
    async function loadUsers() {
      const body = document.getElementById("usersBody");
      if (!hasRole("admin")) {
        body.innerHTML = "";
        return;
      }

      try {
        const res = await apiFetch("/auth/users");
        const data = await res.json();
        const users = data.users || [];

        if (!users.length) {
          body.innerHTML = `<tr><td colspan="3" class="muted">No users found.</td></tr>`;
          return;
        }

        body.innerHTML = users.map((u) => {
          const created = u.created_at ? new Date(u.created_at * 1000).toLocaleString() : "--";
          const lastLogin = u.last_login_at ? new Date(u.last_login_at * 1000).toLocaleString() : "Never";
          const roleOptions = ["viewer", "operator", "admin"].map((role) => (
            `<option value="${role}" ${u.role === role ? "selected" : ""}>${role}</option>`
          )).join("");

          const isSelf = currentUser && currentUser.username === u.username;
          const encodedUsername = encodeURIComponent(u.username);

          return `
            <tr>
              <td>${esc(u.username)}</td>
              <td>
                <select class="role-select" data-username="${encodedUsername}">
                  ${roleOptions}
                </select>
              </td>
              <td>${esc(created)}</td>
              <td>${esc(lastLogin)}</td>
              <td>
                <div class="actions">
                  <button class="btn-warn" onclick="changeUserRole(this)">Change Role</button>
                  <button class="btn-danger" ${isSelf ? "disabled" : ""} onclick="deleteUser('${encodedUsername}')">Delete</button>
                </div>
              </td>
            </tr>
          `;
        }).join("");
      } catch {
        body.innerHTML = `<tr><td colspan="3" class="muted">Failed to load users.</td></tr>`;
      }
    }

    async function createUser() {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      const username = document.getElementById("newUsername").value.trim();
      const password = document.getElementById("newPassword").value;
      const role = document.getElementById("newUserRole").value;
      const msg = document.getElementById("createUserMsg");
      msg.innerText = "";

      if (!username || !password || !role) {
        msg.innerText = "Please fill username, password, and role.";
        return;
      }

      try {
        await apiFetch("/auth/users", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password, role }),
        });

        document.getElementById("newUsername").value = "";
        document.getElementById("newPassword").value = "";
        msg.innerText = `User ${username} created successfully.`;
        await loadUsers();
      } catch (e) {
        msg.innerText = e.message || "Failed to create user.";
      }
    }

    async function changeUserRole(buttonEl) {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      const row = buttonEl.closest("tr");
      const select = row ? row.querySelector("select.role-select") : null;
      if (!select) return;

      const encodedUsername = select.dataset.username;
      const username = decodeURIComponent(encodedUsername || "");
      const role = select.value;
      const msg = document.getElementById("createUserMsg");
      msg.innerText = "";

      try {
        await apiFetch(`/auth/users/${encodeURIComponent(username)}/role`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ role }),
        });
        msg.innerText = `Role for ${username} changed to ${role}.`;
        await loadUsers();
      } catch (e) {
        msg.innerText = e.message || "Failed to change role.";
      }
    }

    async function deleteUser(encodedUsername) {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      const username = decodeURIComponent(encodedUsername || "");

      if (!confirm(`Delete user '${username}'?`)) {
        return;
      }

      const msg = document.getElementById("createUserMsg");
      msg.innerText = "";

      try {
        await apiFetch(`/auth/users/${encodeURIComponent(username)}`, {
          method: "DELETE",
        });
        msg.innerText = `User ${username} deleted.`;
        await loadUsers();
      } catch (e) {
        msg.innerText = e.message || "Failed to delete user.";
      }
    }


    async function loadAuditLogs() {
      const body = document.getElementById("auditLogsBody");
      if (!hasRole("admin")) {
        body.innerHTML = "";
        return;
      }

      try {
        const res = await apiFetch("/audit-logs?limit=100");
        const data = await res.json();
        const logs = data.logs || [];

        if (!logs.length) {
          body.innerHTML = `<tr><td colspan="4" class="muted">No audit logs found.</td></tr>`;
          return;
        }

        body.innerHTML = logs.map((log) => {
          const timestamp = new Date(log.timestamp * 1000).toLocaleString();
          return `
            <tr>
              <td>${esc(timestamp)}</td>
              <td>${esc(log.username)}</td>
              <td><strong>${esc(log.action)}</strong></td>
              <td>${esc(log.details || "-")}</td>
            </tr>
          `;
        }).join("");
      } catch (e) {
        body.innerHTML = `<tr><td colspan="4" class="muted">Failed to load audit logs.</td></tr>`;
      }
    }

    async function loadAlertRules() {
      const body = document.getElementById("alertRulesBody");
      if (!hasRole("admin")) {
        body.innerHTML = "";
        return;
      }

      try {
        const res = await apiFetch("/alert-rules");
        const data = await res.json();
        const rules = data.rules || [];

        if (!rules.length) {
          body.innerHTML = `<tr><td colspan="5" class="muted">No alert rules configured. Create one above.</td></tr>`;
          return;
        }

        body.innerHTML = rules.map((rule) => {
          const created = new Date(rule.created_at * 1000).toLocaleString();
          const metricDisplay = rule.metric_type === "cpu" ? "CPU" : "RAM";
          const statusDisplay = rule.enabled ? `<span class="status-up">Enabled</span>` : `<span class="status-down">Disabled</span>`;

          return `
            <tr>
              <td>${esc(metricDisplay)}</td>
              <td>${esc(rule.threshold)}%</td>
              <td>${statusDisplay}</td>
              <td>${esc(created)}</td>
              <td>
                <div class="actions">
                  <button class="btn-${rule.enabled ? 'warn' : 'success'}" onclick="toggleAlertRule(${rule.id}, ${!rule.enabled})">
                    ${rule.enabled ? 'Disable' : 'Enable'}
                  </button>
                  <button class="btn-danger" onclick="deleteAlertRule(${rule.id})">Delete</button>
                </div>
              </td>
            </tr>
          `;
        }).join("");
      } catch (e) {
        body.innerHTML = `<tr><td colspan="5" class="muted">Failed to load alert rules.</td></tr>`;
      }
    }

    async function createAlertRule() {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      const metric_type = document.getElementById("newAlertMetric").value;
      const threshold = Number(document.getElementById("newAlertThreshold").value);
      const msg = document.getElementById("createAlertMsg");
      msg.innerText = "";

      if (!threshold || threshold < 0 || threshold > 100) {
        msg.innerText = "Please enter a valid threshold (0-100).";
        return;
      }

      try {
        await apiFetch("/alert-rules", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ metric_type, threshold }),
        });

        document.getElementById("newAlertThreshold").value = "";
        const metricName = metric_type === "cpu" ? "CPU" : "RAM";
        msg.innerText = `${metricName} alert rule created (threshold: ${threshold}%).`;
        await loadAlertRules();
      } catch (e) {
        msg.innerText = e.message || "Failed to create alert rule.";
      }
    }

    async function toggleAlertRule(ruleId, enabled) {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      const msg = document.getElementById("createAlertMsg");
      msg.innerText = "";

      try {
        await apiFetch(`/alert-rules/${ruleId}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled }),
        });

        msg.innerText = `Alert rule ${enabled ? 'enabled' : 'disabled'}.`;
        await loadAlertRules();
      } catch (e) {
        msg.innerText = e.message || "Failed to update alert rule.";
      }
    }

    async function deleteAlertRule(ruleId) {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      if (!confirm("Delete this alert rule?")) {
        return;
      }

      const msg = document.getElementById("createAlertMsg");
      msg.innerText = "";

      try {
        await apiFetch(`/alert-rules/${ruleId}`, {
          method: "DELETE",
        });

        msg.innerText = "Alert rule deleted.";
        await loadAlertRules();
      } catch (e) {
        msg.innerText = e.message || "Failed to delete alert rule.";
      }
    }

    async function loadLoginAlertsSetting() {
      try {
        const res = await apiFetch("/settings/login-alerts");
        const data = await res.json();
        updateLoginAlertsToggle(data.enabled);
      } catch {}
    }

    function updateLoginAlertsToggle(enabled) {
      const toggle = document.getElementById("loginAlertsToggle");
      const slider = document.getElementById("loginAlertsSlider");
      const knob = document.getElementById("loginAlertsKnob");
      if (toggle) toggle.checked = enabled;
      if (slider) slider.style.background = enabled ? 'var(--ok)' : 'var(--bad)';
      if (knob) knob.style.left = enabled ? '25px' : '3px';
    }

    async function toggleLoginAlerts(enabled) {
      try {
        await apiFetch("/settings/login-alerts", {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled }),
        });
        updateLoginAlertsToggle(enabled);
      } catch (e) {
        alert(e.message || "Failed to update login alerts setting");
        loadLoginAlertsSetting();
      }
    }

    async function loadSshKeys() {
      const body = document.getElementById("sshKeysBody");
      renderSshCommandSnippets();
      if (!hasRole("admin")) {
        body.innerHTML = "";
        setAccessHubCount(".hub-ssh-count", "--");
        return;
      }

      try {
        const res = await apiFetch("/ssh/keys");
        const data = await res.json();
        const keys = data.keys || [];
        setAccessHubCount(".hub-ssh-count", keys.length);

        if (!keys.length) {
          body.innerHTML = `<tr><td colspan="7" class="muted">No SSH keys configured yet.</td></tr>`;
          return;
        }

        body.innerHTML = keys.map((item) => {
          const created = item.created_at ? new Date(item.created_at * 1000).toLocaleString() : "--";
          return `
            <tr>
              <td>${esc(item.id)}</td>
              <td>${esc(item.ssh_user)}</td>
              <td>${esc(item.label)}</td>
              <td>${esc(item.key_type)}</td>
              <td style="font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.8rem;">${esc(item.fingerprint_sha256)}</td>
              <td>${esc(created)}</td>
              <td>
                <button class="btn-danger" onclick="deleteSshKey(${item.id}, '${esc(item.label)}')">Delete</button>
              </td>
            </tr>
          `;
        }).join("");
      } catch (e) {
        setAccessHubCount(".hub-ssh-count", "--");
        body.innerHTML = `<tr><td colspan="7" class="muted">${esc(e.message || "Failed to load SSH keys.")}</td></tr>`;
      }
    }

    async function createSshKey() {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      const ssh_user = document.getElementById("newSshLinuxUser").value.trim();
      const label = document.getElementById("newSshLabel").value.trim() || "SSH Key";
      const public_key = document.getElementById("newSshPublicKey").value.trim();
      const msg = document.getElementById("createSshKeyMsg");
      msg.innerText = "";

      if (!ssh_user || !public_key) {
        msg.innerText = "Linux user and public key are required.";
        return;
      }

      try {
        await apiFetch("/ssh/keys", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ssh_user, label, public_key }),
        });

        document.getElementById("newSshPublicKey").value = "";
        msg.innerText = `SSH key added for Linux user '${ssh_user}'.`;
        await loadSshKeys();
      } catch (e) {
        msg.innerText = e.message || "Failed to add SSH key.";
      }
    }

    async function deleteSshKey(keyId, label) {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      if (!confirm(`Delete SSH key '${label}' (ID ${keyId})?`)) {
        return;
      }

      const msg = document.getElementById("createSshKeyMsg");
      msg.innerText = "";

      try {
        await apiFetch(`/ssh/keys/${keyId}`, { method: "DELETE" });
        msg.innerText = `SSH key '${label}' deleted.`;
        await loadSshKeys();
      } catch (e) {
        msg.innerText = e.message || "Failed to delete SSH key.";
      }
    }

    function renderSshCommandSnippets() {
      const email = (document.getElementById("sshCmdEmail")?.value || "suharyaseen36@gmail.com").trim() || "suharyaseen36@gmail.com";
      const keyPath = (document.getElementById("sshCmdKeyPath")?.value || "C:\\Users\\suhar\\.ssh\\my_custom_key").trim() || "C:\\Users\\suhar\\.ssh\\my_custom_key";
      const remoteUser = (document.getElementById("sshCmdRemoteUser")?.value || "user").trim() || "user";
      const remoteHost = (document.getElementById("sshCmdRemoteHost")?.value || "server_ip").trim() || "server_ip";

      const keygenCmd = `ssh-keygen -t ed25519 -C "${email}" -f ${keyPath}`;
      const connectCmd = `ssh -i ${keyPath} ${remoteUser}@${remoteHost}`;

      const keygenEl = document.getElementById("sshKeygenCmd");
      const connectEl = document.getElementById("sshConnectCmd");
      if (keygenEl) keygenEl.value = keygenCmd;
      if (connectEl) connectEl.value = connectCmd;
    }

    async function copySshCommand(elementId) {
      const input = document.getElementById(elementId);
      if (!input) return;

      try {
        await navigator.clipboard.writeText(input.value);
        const msg = document.getElementById("createSshKeyMsg");
        msg.innerText = "Command copied to clipboard.";
      } catch {
        input.select();
        document.execCommand("copy");
        const msg = document.getElementById("createSshKeyMsg");
        msg.innerText = "Command copied to clipboard.";
      }
    }

    async function loadCloudflaredRoutes() {
      const body = document.getElementById("cloudflaredRoutesBody");
      const configPathEl = document.getElementById("cloudflaredConfigPath");
      const routeInfoEl = document.getElementById("cloudflaredRouteInfo");
      const configHostnamesEl = document.getElementById("cloudflaredConfigHostnames");
      const hostnameSuggestionsEl = document.getElementById("cloudflaredHostnameSuggestions");
      const importBtn = document.getElementById("importCloudflaredBtn");
      const tunnelIndicator = document.getElementById("cloudflaredTunnelIndicator");
      const tunnelIndicatorText = document.getElementById("cloudflaredTunnelIndicatorText");

      function setTunnelIndicator(state, text) {
        if (!tunnelIndicator || !tunnelIndicatorText) return;
        tunnelIndicator.classList.remove("active", "inactive", "unknown");
        tunnelIndicator.classList.add(state);
        tunnelIndicatorText.innerText = text;
      }

      if (!hasRole("admin")) {
        body.innerHTML = "";
        if (configHostnamesEl) configHostnamesEl.innerText = "";
        if (hostnameSuggestionsEl) hostnameSuggestionsEl.innerHTML = "";
        if (importBtn) importBtn.disabled = true;
        setTunnelIndicator("unknown", "Tunnel status: unavailable");
        setAccessHubCount(".hub-route-count", "--");
        setAccessHubTunnelState(null);
        return;
      }

      try {
        const res = await apiFetch("/cloudflared/routes");
        const data = await res.json();
        const routes = data.routes || [];
        setAccessHubCount(".hub-route-count", routes.length);
        setAccessHubTunnelState(data.tunnel_running === true ? true : (data.tunnel_running === false ? false : null));
        cloudflaredRoutes = routes;
        const configHostnames = Array.isArray(data.config_hostnames) ? data.config_hostnames : [];
        const unmanagedConfigHostnames = Array.isArray(data.unmanaged_config_hostnames)
          ? data.unmanaged_config_hostnames
          : [];

        if (importBtn) {
          importBtn.disabled = unmanagedConfigHostnames.length === 0;
          importBtn.innerText = unmanagedConfigHostnames.length
            ? `Import Unmanaged Hostnames (${unmanagedConfigHostnames.length})`
            : "Import Unmanaged Hostnames";
        }
        configPathEl.innerText = data.config_path || "/etc/cloudflared/config.yml";
        const tunnelName = data.tunnel_name || "(not detected)";
        const tunnelState = data.tunnel_running ? `running (${data.tunnel_process_count || 0})` : "stopped";
        const dnsMode = data.dns_auto_route ? "auto DNS ON" : "auto DNS OFF";
        const cliMode = data.cloudflared_cli_available ? "cloudflared CLI detected" : "cloudflared CLI missing";
        const syncedCount = Number(data.config_sync_updated || 0);
        const syncNote = syncedCount > 0 ? ` • synced from config: ${syncedCount}` : "";
        routeInfoEl.innerText = `Tunnel: ${tunnelName} • ${tunnelState} • ${dnsMode} • ${cliMode}${syncNote}`;

        if (data.tunnel_running) {
          setTunnelIndicator("active", `Tunnel status: ACTIVE (${data.tunnel_process_count || 0} process)`);
        } else if (data.cloudflared_cli_available) {
          setTunnelIndicator("inactive", "Tunnel status: INACTIVE (not running)");
        } else {
          setTunnelIndicator("unknown", "Tunnel status: UNKNOWN (cloudflared CLI missing)");
        }

        if (hostnameSuggestionsEl) {
          hostnameSuggestionsEl.innerHTML = configHostnames
            .map((hostname) => `<option value="${esc(hostname)}"></option>`)
            .join("");
        }

        if (configHostnamesEl) {
          if (!configHostnames.length) {
            configHostnamesEl.innerText = "No hostname entries found in active Cloudflared config yet.";
          } else {
            const base = `Config hostnames (${configHostnames.length}): ${configHostnames.join(", ")}`;
            const unmanagedNote = unmanagedConfigHostnames.length
              ? ` • Not yet managed in dashboard: ${unmanagedConfigHostnames.join(", ")}`
              : "";
            configHostnamesEl.innerText = `${base}${unmanagedNote}`;
          }
        }

        if (!routes.length) {
          body.innerHTML = `<tr><td colspan="6" class="muted">No Cloudflared routes configured yet.</td></tr>`;
          return;
        }

        body.innerHTML = routes.map((item) => {
          const created = item.created_at ? new Date(item.created_at * 1000).toLocaleString() : "--";
          const service = `${item.service_scheme}://${item.service_host}:${item.service_port}`;
          return `
            <tr>
              <td>${esc(item.id)}</td>
              <td>${esc(item.hostname)}</td>
              <td style="font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.82rem;">${esc(service)}</td>
              <td>${esc(item.created_by || "--")}</td>
              <td>${esc(created)}</td>
              <td>
                <button class="btn-neutral" onclick="editCloudflaredRoute(${item.id})">Edit</button>
                <button class="btn-danger" onclick="deleteCloudflaredRoute(${item.id}, '${esc(item.hostname)}')">Delete</button>
              </td>
            </tr>
          `;
        }).join("");
      } catch (e) {
        setAccessHubCount(".hub-route-count", "--");
        setAccessHubTunnelState(null);
        routeInfoEl.innerText = "Unable to fetch tunnel metadata.";
        if (configHostnamesEl) configHostnamesEl.innerText = "Unable to read hostnames from Cloudflared config.";
        setTunnelIndicator("unknown", "Tunnel status: error while checking");
        if (importBtn) {
          importBtn.disabled = true;
          importBtn.innerText = "Import Unmanaged Hostnames";
        }
        body.innerHTML = `<tr><td colspan="6" class="muted">${esc(e.message || "Failed to load Cloudflared routes.")}</td></tr>`;
      }
    }

    async function importUnmanagedCloudflaredRoutes() {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      const msg = document.getElementById("createCloudflaredMsg");
      const importBtn = document.getElementById("importCloudflaredBtn");
      msg.innerText = "Importing unmanaged Cloudflared hostnames from config...";
      if (importBtn) importBtn.disabled = true;

      try {
        const res = await apiFetch("/cloudflared/routes/import-unmanaged", { method: "POST" });
        const data = await res.json();
        const importedCount = Number(data.imported_count || 0);
        const skipped = Array.isArray(data.skipped) ? data.skipped : [];
        const skippedSummary = skipped.length
          ? ` • Skipped: ${skipped.slice(0, 3).map((s) => `${s.hostname} (${s.reason})`).join(", ")}${skipped.length > 3 ? "..." : ""}`
          : "";
        msg.innerText = `Imported ${importedCount} unmanaged route(s).${skippedSummary}`;
        await loadCloudflaredRoutes();
        await loadAccessHubStats();
      } catch (e) {
        msg.innerText = e.message || "Failed to import unmanaged hostnames.";
      } finally {
        if (importBtn) importBtn.disabled = false;
      }
    }

    async function editCloudflaredRoute(routeId) {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      const route = getCloudflaredRouteById(routeId);
      if (!route) {
        alert("Route not found. Refresh and try again.");
        return;
      }

      const hostnameInput = prompt("Edit hostname:", route.hostname || "");
      if (hostnameInput === null) return;

      const schemeInputRaw = prompt("Edit service scheme (http/https/tcp):", route.service_scheme || "http");
      if (schemeInputRaw === null) return;
      const schemeInput = String(schemeInputRaw).trim().toLowerCase();
      if (!["http", "https", "tcp"].includes(schemeInput)) {
        alert("Scheme must be http, https, or tcp.");
        return;
      }

      const hostInput = prompt("Edit local service host:", route.service_host || "127.0.0.1");
      if (hostInput === null) return;

      const portInput = prompt("Edit local service port:", String(route.service_port || ""));
      if (portInput === null) return;
      const service_port = Number(String(portInput).trim());
      if (!Number.isInteger(service_port) || service_port < 1 || service_port > 65535) {
        alert("Port must be a valid integer between 1 and 65535.");
        return;
      }

      const msg = document.getElementById("createCloudflaredMsg");
      msg.innerText = "";

      try {
        const res = await apiFetch(`/cloudflared/routes/${routeId}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            hostname: String(hostnameInput).trim(),
            service_scheme: schemeInput,
            service_host: String(hostInput).trim(),
            service_port,
          }),
        });
        const data = await res.json();
        const dnsLabel = data.dns_routed ? "DNS route updated" : `DNS note: ${data.dns_message || "not configured"}`;
        msg.innerText = `Cloudflared route updated: ${data.route.hostname} -> ${data.route.service_scheme}://${data.route.service_host}:${data.route.service_port} • ${dnsLabel}`;
        await loadCloudflaredRoutes();
        await loadAccessHubStats();
      } catch (e) {
        msg.innerText = e.message || "Failed to update Cloudflared route.";
      }
    }

    async function restartCloudflaredTunnel() {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      const msg = document.getElementById("createCloudflaredMsg");
      const restartBtn = document.getElementById("restartCloudflaredBtn");
      msg.innerText = "Restarting Cloudflared tunnel...";
      if (restartBtn) restartBtn.disabled = true;

      try {
        const res = await apiFetch("/cloudflared/tunnel/restart", { method: "POST" });
        const data = await res.json();
        const activePids = (data.processes || []).map((p) => p.pid).filter(Boolean);
        const pidLabel = activePids.length ? activePids.join(", ") : (data.started_pid || "--");
        msg.innerText = `Cloudflared tunnel restarted (${data.tunnel_name || "unknown"}). Active PID(s): ${pidLabel}`;
        await loadCloudflaredRoutes();
        await loadAccessHubStats();
      } catch (e) {
        msg.innerText = e.message || "Failed to restart Cloudflared tunnel.";
      } finally {
        if (restartBtn) restartBtn.disabled = false;
      }
    }

    async function createCloudflaredRoute() {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      const hostname = document.getElementById("newCloudflaredHostname").value.trim();
      const service_scheme = document.getElementById("newCloudflaredScheme").value;
      const service_host = document.getElementById("newCloudflaredServiceHost").value.trim() || "127.0.0.1";
      const service_port = Number(document.getElementById("newCloudflaredServicePort").value);
      const msg = document.getElementById("createCloudflaredMsg");
      msg.innerText = "";

      if (!hostname || !Number.isInteger(service_port) || service_port < 1 || service_port > 65535) {
        msg.innerText = "Hostname and valid local port (1-65535) are required.";
        return;
      }

      try {
        const res = await apiFetch("/cloudflared/routes", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ hostname, service_scheme, service_host, service_port }),
        });
        const data = await res.json();

        document.getElementById("newCloudflaredHostname").value = "";
        document.getElementById("newCloudflaredServicePort").value = "";
        const dnsLabel = data.dns_routed ? "DNS route created" : `DNS note: ${data.dns_message || "not configured"}`;
        msg.innerText = `Cloudflared route added: ${hostname} -> ${service_scheme}://${service_host}:${service_port} • ${dnsLabel} • ${data.public_url || `https://${hostname}`}`;
        await loadCloudflaredRoutes();
        await loadAccessHubStats();
      } catch (e) {
        msg.innerText = e.message || "Failed to add Cloudflared route.";
      }
    }

    async function deleteCloudflaredRoute(routeId, hostname) {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      if (!confirm(`Delete Cloudflared route '${hostname}' (ID ${routeId})?`)) {
        return;
      }

      const msg = document.getElementById("createCloudflaredMsg");
      msg.innerText = "";

      try {
        await apiFetch(`/cloudflared/routes/${routeId}`, { method: "DELETE" });
        msg.innerText = `Cloudflared route '${hostname}' deleted.`;
        await loadCloudflaredRoutes();
        await loadAccessHubStats();
      } catch (e) {
        msg.innerText = e.message || "Failed to delete Cloudflared route.";
      }
    }




// Expose to window
window.loadUsers = loadUsers;
window.createUser = createUser;
window.changeUserRole = changeUserRole;
window.deleteUser = deleteUser;
window.loadAuditLogs = loadAuditLogs;
window.loadAlertRules = loadAlertRules;
window.createAlertRule = createAlertRule;
window.toggleAlertRule = toggleAlertRule;
window.deleteAlertRule = deleteAlertRule;
window.loadLoginAlertsSetting = loadLoginAlertsSetting;
window.updateLoginAlertsToggle = updateLoginAlertsToggle;
window.toggleLoginAlerts = toggleLoginAlerts;
window.loadSshKeys = loadSshKeys;
window.createSshKey = createSshKey;
window.deleteSshKey = deleteSshKey;
window.renderSshCommandSnippets = renderSshCommandSnippets;
window.copySshCommand = copySshCommand;
window.loadCloudflaredRoutes = loadCloudflaredRoutes;
window.importUnmanagedCloudflaredRoutes = importUnmanagedCloudflaredRoutes;
window.editCloudflaredRoute = editCloudflaredRoute;
window.restartCloudflaredTunnel = restartCloudflaredTunnel;
window.createCloudflaredRoute = createCloudflaredRoute;
window.deleteCloudflaredRoute = deleteCloudflaredRoute;
