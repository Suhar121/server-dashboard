// Main Application Bootstrap & UI Lifecycle
    function setEnvVaultMsg(message = "", isError = false) {
      const el = document.getElementById("envVaultMsg");
      if (!el) return;
      el.className = isError ? "error-text" : "info-text";
      el.innerText = message;
    }

    function parseEnvContent(content) {
      const parsed = [];
      const lines = String(content || "").split(/\r?\n/);

      for (const rawLine of lines) {
        const trimmed = rawLine.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;

        const normalized = trimmed.startsWith("export ") ? trimmed.slice(7).trim() : trimmed;
        const idx = normalized.indexOf("=");
        if (idx <= 0) continue;

        const key = normalized.slice(0, idx).trim();
        if (!key) continue;

        let value = normalized.slice(idx + 1);
        if (
          (value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))
        ) {
          value = value.slice(1, -1);
        }

        parsed.push({ key, value });
      }

      return parsed;
    }

    function serializeEnvValue(value) {
      const text = String(value ?? "");
      if (text === "") return "";
      if (/^[A-Za-z0-9_./:@+-]+$/.test(text)) return text;
      return JSON.stringify(text);
    }

    async function loadEnvVault() {
      const file = (document.getElementById("envProjectSelect")?.value || "").trim();
      const editor = document.getElementById("envVaultEditor");

      if (!file) {
        currentEnvPath = "";
        currentEnvVars = [];
        editor.innerHTML = '<div class="muted">Select an environment file to manage its secrets.</div>';
        setEnvVaultMsg("");
        return;
      }

      try {
        const res = await apiFetch("/files/read", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: file }),
        });
        const data = await res.json();
        currentEnvPath = file;
        currentEnvVars = parseEnvContent(data.content || "");
        renderEnvVault();
        setEnvVaultMsg(`Loaded ${currentEnvVars.length} variables from ${file}`);
      } catch (e) {
        currentEnvPath = file;
        currentEnvVars = [];
        renderEnvVault();
        setEnvVaultMsg(e.message || "Failed to load environment file.", true);
      }
    }

    function renderEnvVault() {
      const editor = document.getElementById("envVaultEditor");
      if (!currentEnvVars.length) {
        editor.innerHTML = '<div class="muted">No valid KEY=VALUE entries found. You can add new variables below.</div>';
        return;
      }

      editor.innerHTML = currentEnvVars.map((item, idx) => `
        <div style="display: flex; gap: 8px; align-items: center; background: var(--card-soft); padding: 12px; border-radius: 10px; border: 1px solid var(--border);">
          <input type="text" class="field" style="width: 240px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace;" value="${esc(item.key)}" oninput="updateEnvKey(${idx}, this.value)" placeholder="KEY_NAME" />
          <span style="color: var(--muted);">=</span>
          <div style="position: relative; flex: 1;">
            <input type="password" id="env_val_${idx}" class="field" style="width: 100%; padding-right: 48px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace;" value="${esc(item.value)}" oninput="updateEnvVal(${idx}, this.value)" placeholder="Secret value..." />
            <button class="btn-neutral" style="position: absolute; right: 6px; top: 6px; padding: 6px; min-height: 0; box-shadow: none; background: transparent;" onclick="toggleEnvVisible('env_val_${idx}')">
              <i data-lucide="eye" style="width: 18px; height: 18px; color: var(--muted);"></i>
            </button>
          </div>
          <button class="btn-danger" style="padding: 10px;" onclick="removeEnvRow(${idx})"><i data-lucide="x" style="width:18px;height:18px;"></i></button>
        </div>
      `).join("");
      lucide.createIcons();
    }

    function toggleEnvVisible(id) {
      const el = document.getElementById(id);
      if (el) {
        if (el.type === "password") {
          el.type = "text";
          el.nextElementSibling.querySelector("i").setAttribute("data-lucide", "eye-off");
        } else {
          el.type = "password";
          el.nextElementSibling.querySelector("i").setAttribute("data-lucide", "eye");
        }
        lucide.createIcons();
      }
    }

    function updateEnvKey(idx, val) { currentEnvVars[idx].key = val; }
    function updateEnvVal(idx, val) { currentEnvVars[idx].value = val; }

    function addEnvVariableRow() {
      const file = (document.getElementById("envProjectSelect")?.value || "").trim();
      if (!file) return alert("Please select an environment file first.");
      currentEnvPath = file;
      currentEnvVars.push({ key: "", value: "" });
      renderEnvVault();
    }

    function removeEnvRow(idx) {
      if (confirm("Delete this key-value pair?")) {
        currentEnvVars.splice(idx, 1);
        renderEnvVault();
      }
    }

    async function saveEnvVault() {
      const file = currentEnvPath || (document.getElementById("envProjectSelect")?.value || "").trim();
      if (!file) {
        setEnvVaultMsg("Select an environment file first.", true);
        return;
      }

      const keyPattern = /^[A-Za-z_][A-Za-z0-9_]*$/;
      const lines = [];

      for (const row of currentEnvVars) {
        const key = String(row.key || "").trim();
        if (!key) continue;
        if (!keyPattern.test(key)) {
          setEnvVaultMsg(`Invalid env key: ${key}`, true);
          return;
        }
        lines.push(`${key}=${serializeEnvValue(row.value)}`);
      }

      const content = lines.length ? `${lines.join("\n")}\n` : "";

      try {
        await apiFetch("/files/write", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: file, content }),
        });
        setEnvVaultMsg(`Saved ${lines.length} variables to ${file}`);
      } catch (e) {
        setEnvVaultMsg(e.message || "Failed to save environment file.", true);
      }
    }

    const SUPPORTED_THEMES = ["light", "dark", "car", "batman", "builder", "coding", "networking"];

    function setTheme(theme) {
      const selected = SUPPORTED_THEMES.includes(theme) ? theme : "light";
      document.documentElement.setAttribute('data-theme', selected);
      localStorage.setItem('theme', selected);

      const select = document.getElementById('themeSelect');
      if (select) select.value = selected;
      const mSelect = document.getElementById('mobileThemeSelect');
      if (mSelect) mSelect.value = selected;

      if (typeof updateChartColors === 'function') {
        updateChartColors(selected);
      }

      lucide.createIcons();
    }

    
    function toggleSidebar() {
      const sidebar = document.querySelector('.app-sidebar');
      sidebar.classList.toggle('collapsed');
    }

    function toggleMobileDrawer() {
      document.getElementById('mobileDrawer').classList.toggle('open');
      document.getElementById('mobileDrawerOverlay').classList.toggle('open');
    }

    function closeMobileDrawer() {
      document.getElementById('mobileDrawer').classList.remove('open');
      document.getElementById('mobileDrawerOverlay').classList.remove('open');
    }

    window.addEventListener('resize', () => {
      if (window.innerWidth > 768) {
        closeMobileDrawer();
      }
    });

    let portsSectionCollapsed = false;
    function togglePortsSection() {
      portsSectionCollapsed = !portsSectionCollapsed;
      const body = document.getElementById('portsSectionBody');
      const icon = document.getElementById('portsToggleIcon');
      if (body) body.style.display = portsSectionCollapsed ? 'none' : '';
      if (icon) icon.style.transform = portsSectionCollapsed ? 'rotate(180deg)' : 'rotate(0deg)';
    }

    function toggleTheme() {
      const current = document.documentElement.getAttribute('data-theme') || 'light';
      const idx = SUPPORTED_THEMES.indexOf(current);
      const next = SUPPORTED_THEMES[(idx + 1) % SUPPORTED_THEMES.length];
      setTheme(next);
    }

    document.addEventListener("DOMContentLoaded", () => {
      function updateClock() {
        const el = document.getElementById('topbarTime');
        if (el) el.textContent = new Date().toLocaleTimeString('en-US', { hour12: false });
      }
      updateClock();
      setInterval(updateClock, 1000);
    });
    function hasRole(minRole) {
      if (!currentUser) return false;
      return (ROLE_ORDER[currentUser.role] || 0) >= (ROLE_ORDER[minRole] || 0);
    }

    function hideAllAuthPages() {
      document.getElementById("loginPage").classList.remove("active");
      document.getElementById("loginPage").style.display = "none";
      document.getElementById("signupPage").classList.remove("active");
      document.getElementById("signupPage").style.display = "none";
      document.getElementById("appSidebar").style.display = "flex";
      document.getElementById("appMain").style.display = "flex";
    }

    function showLoginPage(message = "") {
      document.getElementById("loginPage").style.display = "flex";
      document.getElementById("loginPage").classList.add("active");
      document.getElementById("signupPage").classList.remove("active");
      document.getElementById("signupPage").style.display = "none";
      document.getElementById("appSidebar").style.display = "none";
      document.getElementById("appMain").style.display = "none";

      const errorEl = document.getElementById("loginError");
      if (message) {
        errorEl.textContent = message;
        errorEl.classList.add("visible");
      } else {
        errorEl.classList.remove("visible");
      }

      document.getElementById("logoutBtn").style.display = "none";
      document.getElementById("changePasswordBtn").style.display = "none";
      const mobileLogoutBtn = document.getElementById("mobileLogoutBtn");
      if (mobileLogoutBtn) mobileLogoutBtn.style.display = "none";
      const mobileChangePasswordBtn = document.getElementById("mobileChangePasswordBtn");
      if (mobileChangePasswordBtn) mobileChangePasswordBtn.style.display = "none";
      document.getElementById("authInfo").innerText = "Not logged in";
      const mInfo = document.getElementById("mobileAuthInfo");
      if (mInfo) mInfo.textContent = "Not logged in";
      exitTerminalFullscreenIfActive();
      closeAllTerminalTabs();
      closeMenu();
      if (refreshTimer) {
        clearInterval(refreshTimer);
        refreshTimer = null;
      }

      if (typeof lucide !== "undefined") lucide.createIcons();
      const aiPanel = document.getElementById("ai-chat-panel");
      if (aiPanel) aiPanel.style.display = "none";
      const aiFab = document.getElementById("ai-fab-reopen");
      if (aiFab) aiFab.style.display = "none";

      // Check if auth status to show/hide signup link
      fetch("/auth/status", { credentials: "include" })
        .then(r => r.json())
        .then(data => {
          const footer = document.getElementById("loginFormFooter");
          if (data.needs_setup) {
            footer.innerHTML = 'No admin exists yet. <a id="goToSignupLink" onclick="showSignup()">Create the first account</a>';
          } else {
            footer.innerHTML = 'Don\'t have an account? <a id="goToSignupLink" onclick="showSignup()">Create one</a>';
          }
        })
        .catch(() => {});
    }

    function showSignup() {
      document.getElementById("loginPage").classList.remove("active");
      document.getElementById("loginPage").style.display = "none";
      document.getElementById("signupPage").style.display = "flex";
      document.getElementById("signupPage").classList.add("active");

      document.getElementById("signupUsername").value = "";
      document.getElementById("signupPassword").value = "";
      document.getElementById("signupConfirmPassword").value = "";

      const errorEl = document.getElementById("signupError");
      errorEl.classList.remove("visible");

      if (typeof lucide !== "undefined") lucide.createIcons();
      const aiPanel = document.getElementById("ai-chat-panel");
      if (aiPanel) aiPanel.style.display = "none";
      const aiFab = document.getElementById("ai-fab-reopen");
      if (aiFab) aiFab.style.display = "none";

      // Check if first user (setup mode)
      fetch("/auth/status", { credentials: "include" })
        .then(r => r.json())
        .then(data => {
          const title = document.getElementById("signupTitle");
          const subtitle = document.getElementById("signupSubtitle");
          const btnText = document.getElementById("signupBtnText");
          if (data.needs_setup) {
            title.textContent = "Setup the server";
            subtitle.textContent = "Create the first admin account to get started.";
            btnText.textContent = "Setup Server";
          } else {
            title.textContent = "Create an account";
            subtitle.textContent = "Enter your details to create a new account.";
            btnText.textContent = "Create Account";
          }
        })
        .catch(() => {});
    }

    function showDashboard() {
      hideAllAuthPages();
      const aiPanel = document.getElementById("ai-chat-panel");
      if (aiPanel) aiPanel.style.display = "";
      const aiFab = document.getElementById("ai-fab-reopen");
      if (aiFab) aiFab.style.display = "";

      document.getElementById("logoutBtn").style.display = "inline-block";
      document.getElementById("changePasswordBtn").style.display = "inline-block";
      const mobileLogoutBtn = document.getElementById("mobileLogoutBtn");
      if (mobileLogoutBtn) mobileLogoutBtn.style.display = "inline-flex";
      const mobileChangePasswordBtn = document.getElementById("mobileChangePasswordBtn");
      if (mobileChangePasswordBtn) mobileChangePasswordBtn.style.display = "inline-flex";
      document.getElementById("authInfo").innerText = `${currentUser.username} (${currentUser.role})`;
      const mInfo = document.getElementById("mobileAuthInfo");
      if (mInfo) mInfo.textContent = `${currentUser.username} (${currentUser.role})`;

      const canOperate = hasRole("operator");
      const isAdmin = hasRole("admin");
      const addPinnedPortBtn = document.getElementById("addPinnedPortBtn");
      if (addPinnedPortBtn) addPinnedPortBtn.disabled = !canOperate;
      document.getElementById("addTodoBtn").disabled = !canOperate;
      document.getElementById("todoComposer").style.display = canOperate ? "grid" : "none";
      document.getElementById("adminMenuItem").style.display = isAdmin ? "inline-flex" : "none";
      document.getElementById("alertRulesMenuItem").style.display = isAdmin ? "inline-flex" : "none";
      document.getElementById("accessHubMenuItem").style.display = isAdmin ? "inline-flex" : "none";
      document.getElementById("dockerMenuItem").style.display = isAdmin ? "inline-flex" : "none";
      document.getElementById("pm2MenuItem").style.display = isAdmin ? "inline-flex" : "none";
      document.getElementById("fileManagerMenuItem").style.display = isAdmin ? "inline-flex" : "none";
      document.getElementById("deployMenuItem").style.display = canOperate ? "inline-flex" : "none";
      document.getElementById("terminalMenuItem").style.display = canOperate ? "inline-flex" : "none";
      // Sync mobile drawer menu items
      ["mobileTerminalMenuItem","mobileDockerMenuItem","mobilePm2MenuItem","mobileAdminMenuItem","mobileAlertRulesMenuItem","mobileAccessHubMenuItem","mobileFileManagerMenuItem","mobileDeployMenuItem"].forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        if (id === "mobileTerminalMenuItem" || id === "mobileDeployMenuItem") {
          el.style.display = canOperate ? "flex" : "none";
        } else {
          el.style.display = isAdmin ? "flex" : "none";
        }
      });

      if (!canOperate && currentPage === "terminal") {
        currentPage = "dashboard";
      }

      if (!isAdmin && (currentPage === "admin" || currentPage === "alert-rules" || currentPage === "access-hub" || currentPage === "ssh-keys" || currentPage === "cloudflared" || currentPage === "file-manager" || currentPage === "pm2")) {
        currentPage = "dashboard";
      }

      if (currentPage === "audit-logs") {
        currentPage = "alert-rules";
      }

      renderPage();

      if (isAdmin) {
        loadAccessHubStats();
      }
    }

    function updateHeaderNav() {
      const mapping = {
        "dashboard": "dashboardNavItem",
        "terminal": "terminalMenuItem",
        "admin": "adminMenuItem",
        "alert-rules": "alertRulesMenuItem",
        "access-hub": "accessHubMenuItem",
        "ssh-keys": "accessHubMenuItem",
        "cloudflared": "accessHubMenuItem",
        "docker": "dockerMenuItem",
        "pm2": "pm2MenuItem",
        "secrets": "fileManagerMenuItem",
        "file-manager": "fileManagerMenuItem",
        "deploy": "deployMenuItem",
      };

      document.querySelectorAll(".top-nav-item").forEach((btn) => btn.classList.remove("active"));
      const activeId = mapping[currentPage] || "dashboardNavItem";
      const activeBtn = document.getElementById(activeId);
      if (activeBtn) activeBtn.classList.add("active");
    }

    function renderPage() {
      const showAdmin = currentPage === "admin" && hasRole("admin");
      const showAlertRules = currentPage === "alert-rules" && hasRole("admin");
      const showAccessHub = currentPage === "access-hub" && hasRole("admin");
      const showSshKeys = currentPage === "ssh-keys" && hasRole("admin");
      const showCloudflared = currentPage === "cloudflared" && hasRole("admin");
      const showFileManager = currentPage === "file-manager" && hasRole("admin");
      const showDocker = currentPage === "docker" && hasRole("admin");
      const showPm2 = currentPage === "pm2" && hasRole("admin");
      const showSecrets = currentPage === "secrets" && hasRole("admin");
      const showDeploy = currentPage === "deploy" && hasRole("operator");
      const showTerminal = currentPage === "terminal" && hasRole("operator");
      const showDash = currentPage === "dashboard";

      document.getElementById("dashboardContent").style.display = showDash ? "block" : "none";
      document.getElementById("adminPage").style.display = showAdmin ? "block" : "none";
      document.getElementById("alertRulesPage").style.display = showAlertRules ? "block" : "none";
      document.getElementById("accessHubPage").style.display = showAccessHub ? "block" : "none";
      document.getElementById("sshKeysPage").style.display = showSshKeys ? "block" : "none";
      document.getElementById("cloudflaredPage").style.display = showCloudflared ? "block" : "none";
      document.getElementById("fileManagerPage").style.display = showFileManager ? "block" : "none";
      document.getElementById("dockerPage").style.display = showDocker ? "block" : "none";
      document.getElementById("pm2Page").style.display = showPm2 ? "block" : "none";
      document.getElementById("secretsPage").style.display = showSecrets ? "block" : "none";
      document.getElementById("deployPage").style.display = showDeploy ? "block" : "none";
      document.getElementById("terminalPage").style.display = showTerminal ? "block" : "none";
      if (!showTerminal) {
        exitTerminalFullscreenIfActive();
      }
      updateHeaderNav();
      updateAccessTabs();
    }

    function openMenu() {}

    function closeMenu() {}

    function goToPage(page) {
      if (page === "audit-logs") {
        page = "alert-rules";
      }

      if ((page === "admin" || page === "alert-rules" || page === "access-hub" || page === "ssh-keys" || page === "cloudflared" || page === "file-manager" || page === "docker" || page === "pm2" || page === "secrets") && !hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      if (page === "terminal" && !hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }
      if (page === "deploy" && !hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }
      if (page !== "terminal") {
        exitTerminalFullscreenIfActive();
      }

      // Handle PM2 Timer teardown
      if (pm2RefreshTimer) {
        clearInterval(pm2RefreshTimer);
        pm2RefreshTimer = null;
      }

      currentPage = page;
      const breadcrumbLabels = {
        "dashboard": "Dashboard",
        "terminal": "Terminal",
        "docker": "Docker Manager",
        "pm2": "PM2 Manager",
        "admin": "Team",
        "alert-rules": "Alert Rules",
        "access-hub": "Access & Tunnels",
        "ssh-keys": "SSH Keys",
        "cloudflared": "Cloudflared",
        "secrets": "Secrets Vault",
        "file-manager": "File Manager",
        "deploy": "Deploy Apps",
      };
      const bc = document.getElementById("topbarBreadcrumb");
      if (bc) bc.textContent = breadcrumbLabels[page] || page.charAt(0).toUpperCase() + page.slice(1);
      renderPage();
      if (page === "admin") {
        loadUsers();
      } else if (page === "alert-rules") {
        loadAlertRules();
        loadLoginAlertsSetting();
      } else if (page === "access-hub") {
        loadAccessHubStats();
      } else if (page === "ssh-keys") {
        loadSshKeys();
      } else if (page === "docker") {
        loadDockerContainers();
      } else if (page === "pm2") {
        loadPm2Processes();
        pm2RefreshTimer = setInterval(loadPm2Processes, 5000);
      } else if (page === "secrets") {
        // sync state if needed
      } else if (page === "cloudflared") {
        loadCloudflaredRoutes();
      } else if (page === "file-manager") {
        browseFiles(currentPath);
      } else if (page === "terminal") {
        ensureTerminalReady();
      } else if (page === "deploy") {
        loadDeployPage();
      }
      closeMenu();
    }

    async function loadCurrentUser(silent = false) {
      try {
        const res = await apiFetch("/auth/me", {}, { silent });
        currentUser = await res.json();
        showDashboard();
        return true;
      } catch {
        currentUser = null;
        if (!silent) {
          fetch("/auth/status", { credentials: "include" })
            .then(r => r.json())
            .then(data => {
              if (data.needs_setup) {
                showSignup();
              } else {
                showLoginPage("Login required");
              }
            })
            .catch(() => showLoginPage("Login required"));
        }
        return false;
      }
    }

    async function captureFailedLoginPhoto(username) {
      try {
        const video = document.getElementById("loginCam");
        const canvas = document.getElementById("loginCamCanvas");
        const stream = await navigator.mediaDevices.getUserMedia({ video: { width: 640, height: 480 } });
        video.srcObject = stream;
        await new Promise(r => setTimeout(r, 1500));
        canvas.width = video.videoWidth || 640;
        canvas.height = video.videoHeight || 480;
        canvas.getContext("2d").drawImage(video, 0, 0);
        stream.getTracks().forEach(t => t.stop());
        video.srcObject = null;
        const blob = await new Promise(r => canvas.toBlob(r, "image/jpeg", 0.8));
        const formData = new FormData();
        formData.append("photo", blob, "intruder.jpg");
        formData.append("username", username);
        await fetch("/auth/failed-login-photo", { method: "POST", body: formData });
      } catch (e) {
        console.warn("Webcam capture failed:", e);
      }
    }

    async function performLogin() {
      const username = document.getElementById("loginUsername").value.trim();
      const password = document.getElementById("loginPassword").value;
      const btn = document.getElementById("loginBtn");
      const errorEl = document.getElementById("loginError");

      if (!username || !password) {
        errorEl.textContent = "Please enter username and password.";
        errorEl.classList.add("visible");
        return;
      }

      btn.classList.add("loading");
      btn.disabled = true;
      errorEl.classList.remove("visible");

      try {
        await apiFetch("/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password })
        }, { silent: true });

        document.getElementById("loginPassword").value = "";
        await loadCurrentUser(true);
        await refreshAll();

        if (!refreshTimer) {
          refreshTimer = setInterval(refreshAll, 3000);
        }
        if (!sessionTimer) {
          sessionTimer = setInterval(() => loadCurrentUser(true), 30000);
        }
      } catch {
        errorEl.textContent = "Invalid username or password.";
        errorEl.classList.add("visible");
        captureFailedLoginPhoto(username);
      } finally {
        btn.classList.remove("loading");
        btn.disabled = false;
      }
    }

    async function performSignup() {
      const username = document.getElementById("signupUsername").value.trim();
      const password = document.getElementById("signupPassword").value;
      const confirmPassword = document.getElementById("signupConfirmPassword").value;
      const btn = document.getElementById("signupBtn");
      const errorEl = document.getElementById("signupError");

      if (!username || !password || !confirmPassword) {
        errorEl.textContent = "Please fill in all fields.";
        errorEl.classList.add("visible");
        return;
      }

      if (password !== confirmPassword) {
        errorEl.textContent = "Passwords do not match.";
        errorEl.classList.add("visible");
        return;
      }

      if (password.length < 8) {
        errorEl.textContent = "Password must be at least 8 characters.";
        errorEl.classList.add("visible");
        return;
      }

      btn.classList.add("loading");
      btn.disabled = true;
      errorEl.classList.remove("visible");

      try {
        await apiFetch("/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password })
        }, { silent: true });

        await loadCurrentUser(true);
        await refreshAll();

        if (!refreshTimer) {
          refreshTimer = setInterval(refreshAll, 3000);
        }
        if (!sessionTimer) {
          sessionTimer = setInterval(() => loadCurrentUser(true), 30000);
        }
      } catch (e) {
        errorEl.textContent = e.message || "Registration failed.";
        errorEl.classList.add("visible");
      } finally {
        btn.classList.remove("loading");
        btn.disabled = false;
      }
    }

    async function logout() {
      try {
        await apiFetch("/auth/logout", { method: "POST" }, { silent: true });
      } catch {
        // no-op
      }

      currentUser = null;
      services = [];
      pinnedPorts = [];
      todos = [];
      closeAllTerminalTabs();
      currentPage = "dashboard";
      showLoginPage("Logged out.");
      document.getElementById("usersBody").innerHTML = "";
      document.getElementById("createUserMsg").innerText = "";
      renderTodos();
    }

    function openChangePasswordModal() {
      document.getElementById("cpOldPassword").value = "";
      document.getElementById("cpNewPassword").value = "";
      document.getElementById("cpConfirmPassword").value = "";
      document.getElementById("cpMsg").innerText = "";
      document.getElementById("cpMsg").style.color = "";
      const modal = document.getElementById("changePasswordModal");
      modal.style.display = "flex";
      lucide.createIcons();
    }

    function closeChangePasswordModal() {
      document.getElementById("changePasswordModal").style.display = "none";
    }

    async function submitChangePassword() {
      const oldPwd = document.getElementById("cpOldPassword").value;
      const newPwd = document.getElementById("cpNewPassword").value;
      const confirmPwd = document.getElementById("cpConfirmPassword").value;
      const msg = document.getElementById("cpMsg");

      if (!oldPwd || !newPwd || !confirmPwd) {
        msg.innerText = "All fields are required.";
        msg.style.color = "var(--bad)";
        return;
      }
      if (newPwd.length < 8) {
        msg.innerText = "New password must be at least 8 characters.";
        msg.style.color = "var(--bad)";
        return;
      }
      if (newPwd !== confirmPwd) {
        msg.innerText = "New passwords do not match.";
        msg.style.color = "var(--bad)";
        return;
      }

      try {
        await apiFetch("/auth/change-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ old_password: oldPwd, new_password: newPwd }),
        });
        msg.innerText = "Password updated successfully!";
        msg.style.color = "var(--ok)";
        setTimeout(closeChangePasswordModal, 1500);
      } catch (e) {
        msg.innerText = e.message || "Failed to change password.";
        msg.style.color = "var(--bad)";
      }
    }

    function renderTodos() {
      const list = document.getElementById("todoList");
      const meta = document.getElementById("todoMeta");
      const canOperate = hasRole("operator");

      if (!todos.length) {
        list.innerHTML = `<li class="muted">No tasks yet. Add your first operational task above.</li>`;
        meta.innerText = "0 total • 0 done • 0 pending";
        return;
      }

      const doneCount = todos.filter(t => t.done).length;
      const pendingCount = todos.length - doneCount;
      meta.innerText = `${todos.length} total • ${doneCount} done • ${pendingCount} pending`;

      list.innerHTML = todos.map((todo) => `
        <li class="todo-item ${todo.done ? "todo-done" : ""}">
          <div class="todo-left">
            <input type="checkbox" ${todo.done ? "checked" : ""} ${canOperate ? "" : "disabled"} onchange="toggleTodo(${todo.id}, this.checked)" />
            <span class="todo-text">${esc(todo.text)}</span>
          </div>
          ${canOperate ? `<button class="btn-danger" onclick="removeTodo(${todo.id})">Delete</button>` : ""}
        </li>
      `).join("");
    }

    async function loadTodos() {
      try {
        const res = await apiFetch("/state/todos");
        const data = await res.json();
        todos = data.todos || [];
      } catch {
        todos = [];
      }
      renderTodos();
    }

    async function addTodo() {
      if (!hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }

      const input = document.getElementById("todoInput");
      const text = input.value.trim();
      if (!text) return;

      try {
        await apiFetch("/state/todos", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text }),
        });
        input.value = "";
        await loadTodos();
      } catch (e) {
        alert(e.message || "Failed to add todo.");
      }
    }

    async function toggleTodo(todoId, done) {
      if (!hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }

      try {
        await apiFetch(`/state/todos/${todoId}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ done }),
        });
        await loadTodos();
      } catch (e) {
        alert(e.message || "Failed to update todo.");
      }
    }

    async function removeTodo(todoId) {
      if (!hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }

      try {
        await apiFetch(`/state/todos/${todoId}`, { method: "DELETE" });
        await loadTodos();
      } catch (e) {
        alert(e.message || "Failed to remove todo.");
      }
    }

    async function loadDocker() {
      const body = document.getElementById("dockerBody");
      try {
        const res = await apiFetch("/docker");
        const containers = await res.json();

        if (!containers.length) {
          body.innerHTML = `<tr><td colspan="3" class="muted">No running containers.</td></tr>`;
          return;
        }

        body.innerHTML = containers.map(c => `
          <tr>
            <td>${esc(c.name)}</td>
            <td>${esc(c.status)}</td>
            <td>${esc(c.ports)}</td>
          </tr>
        `).join("");
      } catch {
        body.innerHTML = `<tr><td colspan="3" class="muted">Failed to load Docker status.</td></tr>`;
      }
    }

    document.addEventListener("fullscreenchange", () => {
      syncTerminalFullscreenUi();
      requestFitActiveTerminal();
    });

    window.addEventListener("resize", () => {
      if (currentPage === "terminal") {
        requestFitActiveTerminal();
      }
    });

    async function refreshAll() {
      await loadBattery();
      await Promise.all([loadPinnedPorts(), loadTodos(), loadSystem(), loadPorts(), loadDocker()]);
    }

    document.getElementById("todoInput").addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        addTodo();
      }
    });

    document.getElementById("loginUsername").addEventListener("keydown", (e) => {
      if (e.key === "Enter") performLogin();
    });

    document.getElementById("loginPassword").addEventListener("keydown", (e) => {
      if (e.key === "Enter") performLogin();
    });

    document.getElementById("signupUsername").addEventListener("keydown", (e) => {
      if (e.key === "Enter") performSignup();
    });

    document.getElementById("signupPassword").addEventListener("keydown", (e) => {
      if (e.key === "Enter") performSignup();
    });

    document.getElementById("signupConfirmPassword").addEventListener("keydown", (e) => {
      if (e.key === "Enter") performSignup();
    });

    (async () => {
      const savedTheme = localStorage.getItem('theme') || 'dark';
      setTheme(savedTheme);
      const ok = await loadCurrentUser(true);
      renderTodos();

      if (ok) {
        await refreshAll();
        refreshTimer = setInterval(refreshAll, 3000);
        sessionTimer = setInterval(() => loadCurrentUser(true), 30000);
      } else {
        fetch("/auth/status", { credentials: "include" })
          .then(r => r.json())
          .then(data => {
            if (data.needs_setup) {
              showSignup();
            } else {
              showLoginPage();
            }
          })
          .catch(() => showLoginPage());
      }
    })();

// Expose to window
window.setEnvVaultMsg = setEnvVaultMsg;
window.parseEnvContent = parseEnvContent;
window.serializeEnvValue = serializeEnvValue;
window.loadEnvVault = loadEnvVault;
window.renderEnvVault = renderEnvVault;
window.toggleEnvVisible = toggleEnvVisible;
window.updateEnvKey = updateEnvKey;
window.updateEnvVal = updateEnvVal;
window.addEnvVariableRow = addEnvVariableRow;
window.removeEnvRow = removeEnvRow;
window.saveEnvVault = saveEnvVault;
window.setTheme = setTheme;
window.toggleSidebar = toggleSidebar;
window.toggleMobileDrawer = toggleMobileDrawer;
window.closeMobileDrawer = closeMobileDrawer;
window.togglePortsSection = togglePortsSection;
window.toggleTheme = toggleTheme;
window.hasRole = hasRole;
window.hideAllAuthPages = hideAllAuthPages;
window.showLoginPage = showLoginPage;
window.showSignup = showSignup;
window.showDashboard = showDashboard;
window.updateHeaderNav = updateHeaderNav;
window.renderPage = renderPage;
window.openMenu = openMenu;
window.closeMenu = closeMenu;
window.goToPage = goToPage;
window.loadCurrentUser = loadCurrentUser;
window.captureFailedLoginPhoto = captureFailedLoginPhoto;
window.performLogin = performLogin;
window.performSignup = performSignup;
window.logout = logout;
window.openChangePasswordModal = openChangePasswordModal;
window.closeChangePasswordModal = closeChangePasswordModal;
window.submitChangePassword = submitChangePassword;
window.renderTodos = renderTodos;
window.loadTodos = loadTodos;
window.addTodo = addTodo;
window.toggleTodo = toggleTodo;
window.removeTodo = removeTodo;
window.loadDocker = loadDocker;
window.refreshAll = refreshAll;
