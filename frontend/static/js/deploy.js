// Deployed Apps & Github Deployments
    let deployTemplates = [];
    let deploySelectedTemplate = null;

    async function loadDeployPage() {
      await Promise.all([loadDeployTemplates(), loadDeployedApps()]);
    }

    async function loadDeployTemplates() {
      try {
        const res = await apiFetch("/deploy/templates");
        const data = await res.json();
        deployTemplates = data.templates || [];
        renderDeployTemplates(deployTemplates);
        document.getElementById("deployKpiTemplates").textContent = deployTemplates.length;
      } catch (e) {
        document.getElementById("deployTemplateGrid").innerHTML = `<div class="error-text">Failed to load templates: ${esc(e.message)}</div>`;
      }
    }

    function filterDeployTemplates() {
      const search = (document.getElementById("deployTemplateSearch").value || "").toLowerCase();
      const category = document.getElementById("deployCategoryFilter").value;
      let filtered = deployTemplates;
      if (search) {
        filtered = filtered.filter(t => t.name.toLowerCase().includes(search) || t.description.toLowerCase().includes(search));
      }
      if (category) {
        filtered = filtered.filter(t => t.category === category);
      }
      renderDeployTemplates(filtered);
    }

    function renderDeployTemplates(templates) {
      const grid = document.getElementById("deployTemplateGrid");
      if (!templates.length) {
        grid.innerHTML = '<div class="muted">No templates found.</div>';
        return;
      }
      grid.innerHTML = templates.map(t => `
        <div class="deploy-template-card" onclick="openDeployWizard(${t.id})">
          <div class="deploy-template-icon">
            <i data-lucide="${esc(t.icon || 'box')}" style="width:22px;height:22px;"></i>
          </div>
          <div class="deploy-template-name">${esc(t.name)}</div>
          <div class="deploy-template-desc">${esc(t.description)}</div>
          <div class="deploy-template-meta">
            <span class="deploy-badge deploy-badge-category">${esc(t.category)}</span>
            ${t.default_port ? `<span class="deploy-badge deploy-badge-port">Port ${t.default_port}</span>` : ''}
          </div>
        </div>
      `).join("");
      lucide.createIcons();
    }

    async function openDeployWizard(templateId) {
      if (!hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }
      deploySelectedTemplate = null;
      document.getElementById("deployAppName").value = "";
      document.getElementById("deployPortOverride").value = "";
      document.getElementById("deployEnvVarsFields").innerHTML = "";
      document.getElementById("deployComposePreview").textContent = "";
      document.getElementById("deployWizardError").textContent = "";

      try {
        const res = await apiFetch(`/deploy/templates/${templateId}`);
        deploySelectedTemplate = await res.json();
      } catch (e) {
        document.getElementById("deployWizardError").textContent = "Failed to load template: " + e.message;
        document.getElementById("deployWizardModal").style.display = "flex";
        return;
      }

      document.getElementById("deployWizardTitle").textContent = `Deploy ${deploySelectedTemplate.name}`;
      document.getElementById("deployWizardDesc").textContent = deploySelectedTemplate.description;
      document.getElementById("deployComposePreview").textContent = deploySelectedTemplate.compose_yaml;

      if (deploySelectedTemplate.default_port) {
        document.getElementById("deployPortOverride").placeholder = `Default: ${deploySelectedTemplate.default_port}`;
      }

      const envFields = document.getElementById("deployEnvVarsFields");
      const schema = deploySelectedTemplate.env_schema || [];
      if (schema.length) {
        envFields.innerHTML = schema.map(v => `
          <div style="display:flex; flex-direction:column; gap:2px;">
            <label style="font-size:0.8rem; font-weight:600; color:var(--muted);">${esc(v.label || v.key)}</label>
            <input class="field deploy-env-input" data-key="${esc(v.key)}" value="${esc(v.default || '')}" placeholder="${esc(v.default || '')}" />
          </div>
        `).join("");
      } else {
        envFields.innerHTML = '<div class="muted" style="font-size:0.82rem;">No environment variables required.</div>';
      }

      document.getElementById("deployWizardModal").style.display = "flex";
    }

    function closeDeployWizard() {
      document.getElementById("deployWizardModal").style.display = "none";
      deploySelectedTemplate = null;
    }

    async function submitDeploy() {
      const errorEl = document.getElementById("deployWizardError");
      errorEl.textContent = "";

      const appName = document.getElementById("deployAppName").value.trim();
      if (!appName) {
        errorEl.textContent = "Application name is required.";
        return;
      }
      if (!/^[a-zA-Z0-9_-]+$/.test(appName)) {
        errorEl.textContent = "Name must be alphanumeric with dashes/underscores only.";
        return;
      }

      const portVal = document.getElementById("deployPortOverride").value;
      const portOverride = portVal ? parseInt(portVal) : null;

      const envVars = {};
      document.querySelectorAll(".deploy-env-input").forEach(input => {
        const key = input.getAttribute("data-key");
        const val = input.value.trim();
        if (key && val) {
          envVars[key] = val;
        }
      });

      const btn = document.getElementById("deployWizardSubmitBtn");
      btn.disabled = true;
      btn.innerHTML = '<i data-lucide="loader" style="width:14px;height:14px;animation:spin 1s linear infinite;"></i> Deploying...';
      lucide.createIcons();

      try {
        const res = await apiFetch("/deploy", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            template_id: deploySelectedTemplate ? deploySelectedTemplate.id : null,
            app_name: appName,
            env_vars: envVars,
            port_override: portOverride,
          }),
        });
        const data = await res.json();
        closeDeployWizard();
        await loadDeployedApps();
        loadDeployTemplates();
      } catch (e) {
        errorEl.textContent = e.message || "Deployment failed.";
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<i data-lucide="rocket" style="width:14px;height:14px;"></i> Deploy';
        lucide.createIcons();
      }
    }

    async function loadDeployedApps() {
      const body = document.getElementById("deployedAppsBody");
      if (!body) return;
      try {
        const res = await apiFetch("/deploy/apps");
        const data = await res.json();
        const apps = data.apps || [];
        let running = 0;
        apps.forEach(a => { if (a.status === "running") running++; });
        document.getElementById("deployKpiRunning").textContent = running;
        document.getElementById("deployKpiTotal").textContent = apps.length;

        if (!apps.length) {
          body.innerHTML = '<tr><td colspan="6" class="muted">No apps deployed yet. Select a template above to get started.</td></tr>';
          return;
        }

        body.innerHTML = apps.map(a => {
          const statusClass = a.status === "running" ? "deploy-status-running" : a.status === "failed" ? "deploy-status-failed" : "deploy-status-stopped";
          const portsHtml = (a.ports || []).map(p => `<span class="deploy-badge deploy-badge-port">${esc(String(p))}</span>`).join(" ");
          const isRunning = a.status === "running";
          const actionBtns = `
            <div class="actions" style="gap:4px;">
              ${isRunning
                ? `<button class="btn-warn" onclick="deployAppAction(${a.id}, 'restart')"><i data-lucide="rotate-cw" style="width:14px;height:14px;"></i></button>
                   <button class="btn-danger" onclick="deployAppAction(${a.id}, 'stop')"><i data-lucide="square" style="width:14px;height:14px;"></i></button>`
                : `<button class="btn-success" onclick="deployAppAction(${a.id}, 'start')"><i data-lucide="play" style="width:14px;height:14px;"></i></button>`}
              <button class="btn-neutral" onclick="viewDeployLogs(${a.id}, '${esc(a.name)}')"><i data-lucide="file-text" style="width:14px;height:14px;"></i></button>
              <button class="btn-danger" onclick="deployAppAction(${a.id}, 'delete')"><i data-lucide="trash-2" style="width:14px;height:14px;"></i></button>
            </div>`;
          return `
            <tr>
              <td style="font-weight:600;">${esc(a.name)}</td>
              <td>${a.template_name ? `<span class="deploy-badge deploy-badge-category">${esc(a.template_name)}</span>` : '<span class="muted">Custom</span>'}</td>
              <td><span class="${statusClass}">${esc(a.status)}</span></td>
              <td>${portsHtml || '<span class="muted">--</span>'}</td>
              <td style="font-size:0.85rem; color:var(--muted);">${esc(a.created_by)}</td>
              <td>${actionBtns}</td>
            </tr>`;
        }).join("");
        lucide.createIcons();
      } catch (e) {
        body.innerHTML = `<tr><td colspan="6" class="error-text">Failed to load: ${esc(e.message)}</td></tr>`;
      }
    }

    async function deployAppAction(appId, action) {
      if (action === "delete" && !confirm("Delete this app and all its containers/data?")) return;
      try {
        await apiFetch(`/deploy/apps/${appId}/action`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action }),
        });
        await loadDeployedApps();
      } catch (e) {
        alert("Action failed: " + (e.message || "Unknown error"));
      }
    }

    async function viewDeployLogs(appId, appName) {
      document.getElementById("deployLogsTitle").textContent = appName + " — Logs";
      document.getElementById("deployLogsContent").textContent = "Loading...";
      document.getElementById("deployLogsModal").style.display = "flex";
      try {
        const res = await apiFetch(`/deploy/apps/${appId}/logs`);
        const data = await res.json();
        document.getElementById("deployLogsContent").textContent = (data.logs || []).join("") || "No logs available.";
      } catch (e) {
        document.getElementById("deployLogsContent").textContent = "Error: " + e.message;
      }
    }

    function closeDeployLogs() {
      document.getElementById("deployLogsModal").style.display = "none";
    }

    // ── GitHub Deploy JS ──
    let ghAnalysis = null;
    let ghDeployId = null;
    let ghPollTimer = null;

    let ghPrivateUsername = null;
    let ghPrivateToken = null;
    let ghPrivatePendingUrl = null;
    let ghPrivatePendingBranch = null;

    function openPrivateRepoModal(url, branch) {
      ghPrivatePendingUrl = url;
      ghPrivatePendingBranch = branch;
      document.getElementById("ghPrivateUsername").value = ghPrivateUsername || "";
      document.getElementById("ghPrivateToken").value = ghPrivateToken || "";
      document.getElementById("ghPrivateRepoError").textContent = "";
      document.getElementById("ghPrivateRepoModal").style.display = "flex";
    }

    function closePrivateRepoModal() {
      document.getElementById("ghPrivateRepoModal").style.display = "none";
      ghPrivatePendingUrl = null;
      ghPrivatePendingBranch = null;
    }

    async function submitPrivateRepoCredentials() {
      const user = document.getElementById("ghPrivateUsername").value.trim();
      const token = document.getElementById("ghPrivateToken").value.trim();
      const errEl = document.getElementById("ghPrivateRepoError");
      errEl.textContent = "";

      if (!token) {
        errEl.textContent = "Personal Access Token or password is required.";
        return;
      }

      ghPrivateUsername = user || null;
      ghPrivateToken = token;

      document.getElementById("ghPrivateRepoModal").style.display = "none";

      if (ghPrivatePendingUrl) {
        document.getElementById("ghRepoUrl").value = ghPrivatePendingUrl;
        document.getElementById("ghBranch").value = ghPrivatePendingBranch;
        analyzeGitHubRepo();
      }
    }

    async function analyzeGitHubRepo() {
      const url = document.getElementById("ghRepoUrl").value.trim();
      const branch = document.getElementById("ghBranch").value.trim() || "main";
      const errEl = document.getElementById("ghAnalyzeError");
      const btn = document.getElementById("ghAnalyzeBtn");
      errEl.textContent = "";

      if (!url) { errEl.textContent = "Repository URL is required."; return; }

      btn.disabled = true;
      btn.innerHTML = '<i data-lucide="loader" style="width:16px;height:16px;animation:spin 1s linear infinite;"></i> Analyzing...';
      lucide.createIcons();

      try {
        const res = await apiFetch("/deploy/github/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            repo_url: url,
            branch,
            username: ghPrivateUsername,
            password: ghPrivateToken
          }),
        });
        ghAnalysis = await res.json();
        renderAnalysisResult(ghAnalysis);
      } catch (e) {
        if (e.message === "AUTH_REQUIRED") {
          const wasPrompted = (ghPrivateToken !== null);
          openPrivateRepoModal(url, branch);
          if (wasPrompted) {
            document.getElementById("ghPrivateRepoError").textContent = "Invalid username or token. Please try again.";
          }
          return;
        }
        errEl.textContent = e.message || "Analysis failed.";
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<i data-lucide="search" style="width:16px;height:16px;"></i> Analyze';
        lucide.createIcons();
      }
    }

    function renderComposeServiceList(services) {
      const section = document.getElementById("ghServiceSection");
      const list = document.getElementById("ghServiceList");
      if (!services || services.length === 0) {
        section.style.display = "none";
        list.innerHTML = "";
        return;
      }
      section.style.display = "block";

      list.innerHTML = services.map(svc => {
        const portHtml = (svc.ports || []).map(p => `
          <div class="gh-service-port">
            <input class="gh-service-port-input" data-service="${esc(svc.name)}"
                   type="number" value="${p.host || ''}" placeholder="${p.host || 'auto'}" />
            <span class="gh-service-port-sep">→</span>
            <span class="gh-service-port-container">${p.container || '?'}</span>
          </div>
        `).join("");

        const envTags = (svc.env_vars || []).map(e =>
          `<span class="gh-service-env-tag">${esc(e.key)}</span>`
        ).join("");

        const depTags = (svc.depends_on || []).map(d =>
          `<span class="gh-service-dep-tag">${esc(d)}</span>`
        ).join("");

        const imageTag = svc.image
          ? `<span class="gh-service-image">${esc(svc.image)}</span>`
          : (svc.build ? `<span class="gh-service-image">build: ${esc(typeof svc.build === 'string' ? svc.build : '.')}</span>` : '');

        return `
          <div class="gh-service-card">
            <div class="gh-service-header">
              <i data-lucide="container" style="width:16px;height:16px;color:var(--brand);"></i>
              <span class="gh-service-name">${esc(svc.name)}</span>
              ${imageTag}
            </div>
            ${portHtml ? `<div class="gh-service-ports">${portHtml}</div>` : ''}
            ${depTags ? `<div class="gh-service-deps">Depends on: ${depTags}</div>` : ''}
            ${envTags ? `<div class="gh-service-envs">Env: ${envTags}</div>` : ''}
          </div>
        `;
      }).join("");
      lucide.createIcons();
    }

    function renderAnalysisResult(a) {
      const card = document.getElementById("ghAnalysisCard");
      card.classList.add("visible");

      const badges = document.getElementById("ghBadges");
      const hasCompose = a.has_compose && a.compose_services && a.compose_services.length > 0;
      const svcCount = a.compose_services ? a.compose_services.length : 0;
      badges.innerHTML = `
        <span class="gh-badge gh-badge-type"><i data-lucide="tag" style="width:12px;height:12px;"></i> ${esc(a.type)}</span>
        ${a.framework !== 'none' ? `<span class="gh-badge gh-badge-framework"><i data-lucide="layers" style="width:12px;height:12px;"></i> ${esc(a.framework)}</span>` : ''}
        ${hasCompose
          ? `<span class="gh-badge gh-badge-compose"><i data-lucide="layers" style="width:12px;height:12px;"></i> Compose</span>
             <span class="gh-badge gh-badge-services"><i data-lucide="box" style="width:12px;height:12px;"></i> ${svcCount} services</span>`
          : `<span class="gh-badge gh-badge-port"><i data-lucide="radio" style="width:12px;height:12px;"></i> Port ${a.port}</span>`
        }
      `;

      document.getElementById("ghAppName").value = a.repo_name || "";

      // Render service cards for compose projects
      renderComposeServiceList(a.compose_services || []);

      // Render env vars from .env.example
      const envSection = document.getElementById("ghEnvSection");
      const envVars = document.getElementById("ghEnvVars");
      if (a.env_vars && a.env_vars.length > 0) {
        envSection.style.display = "block";
        envVars.innerHTML = a.env_vars.map(v => `
          <div class="gh-env-item">
            <span class="gh-env-key">${esc(v.key)}</span>
            <input class="gh-env-val gh-env-input" data-key="${esc(v.key)}" value="${esc(v.default || '')}" placeholder="${esc(v.default || 'value...')}" />
          </div>
        `).join("");
      } else {
        envSection.style.display = "none";
        envVars.innerHTML = "";
      }

      lucide.createIcons();

      const dfs = document.getElementById("ghDockerfileToggle");
      const dfp = document.getElementById("ghDockerfilePreview");
      if (a.dockerfile_content) {
        dfp.textContent = a.dockerfile_content;
        dfs.style.display = "flex";
      } else {
        dfs.style.display = "none";
      }

      const cps = document.getElementById("ghComposeToggle");
      const cpp = document.getElementById("ghComposePreview");
      if (a.compose_content) {
        cpp.textContent = a.compose_content;
        cps.style.display = "flex";
      } else {
        cps.style.display = "none";
      }

      document.getElementById("ghDeployPanel").classList.remove("visible");
    }

    function togglePreview(id, toggleEl) {
      const el = document.getElementById(id);
      const isVisible = el.classList.contains("visible");
      el.classList.toggle("visible");
      const icon = toggleEl.querySelector("i");
      if (icon) icon.style.transform = isVisible ? "" : "rotate(90deg)";
    }

    async function deployFromGitHub() {
      if (!ghAnalysis) { alert("Analyze a repo first."); return; }
      const appName = document.getElementById("ghAppName").value.trim();
      const errEl = document.getElementById("ghDeployError");
      const btn = document.getElementById("ghDeployBtn");
      errEl.textContent = "";

      if (!appName) { errEl.textContent = "App name is required."; return; }
      if (!/^[a-zA-Z0-9_-]+$/.test(appName)) { errEl.textContent = "Name: alphanumeric, dashes, underscores only."; return; }

      // Collect env vars from .env.example form
      const envVars = {};
      document.querySelectorAll(".gh-env-input").forEach(inp => {
        const k = inp.getAttribute("data-key");
        const v = inp.value.trim();
        if (k && v) envVars[k] = v;
      });

      // Collect per-service port overrides
      const portOverrides = {};
      document.querySelectorAll(".gh-service-port-input").forEach(inp => {
        const svc = inp.getAttribute("data-service");
        const val = parseInt(inp.value);
        if (svc && val && !isNaN(val)) portOverrides[svc] = val;
      });

      btn.disabled = true;
      btn.innerHTML = '<i data-lucide="loader" style="width:14px;height:14px;animation:spin 1s linear infinite;"></i> Starting...';
      lucide.createIcons();

      try {
        const res = await apiFetch("/deploy/github/deploy", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            repo_url: ghAnalysis.repo_url,
            app_name: appName,
            branch: ghAnalysis.branch,
            env_vars: envVars,
            port_overrides: portOverrides,
            username: ghPrivateUsername,
            password: ghPrivateToken
          }),
        });
        const data = await res.json();
        ghDeployId = data.deploy_id;

        document.getElementById("ghDeployTitle").textContent = `Deploying ${esc(appName)}...`;
        document.getElementById("ghDeployPanel").classList.add("visible");
        document.getElementById("ghDeployLog").textContent = "Pipeline started...\n";

        resetStepper();
        startDeployPolling(ghDeployId);
      } catch (e) {
        errEl.textContent = e.message || "Deploy failed.";
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<i data-lucide="rocket" style="width:14px;height:14px;"></i> Deploy';
        lucide.createIcons();
      }
    }

    async function deleteFailedGitHubDeploy() {
      const btn = document.getElementById("ghDeleteDeployBtn");
      const deployId = btn.getAttribute("data-deploy-id");
      const appName = btn.getAttribute("data-app-name");
      if (!deployId) return;
      if (!confirm(`Delete failed deployment "${appName || deployId}"? This cannot be undone.`)) return;

      try {
        await apiFetch(`/deploy/github/${deployId}`, { method: "DELETE" });
        document.getElementById("ghDeployTitle").textContent = "Deployment deleted";
        document.getElementById("ghDeployStatus").textContent = "Cleaned up.";
        btn.style.display = "none";
        lucide.createIcons();
      } catch (e) {
        alert("Failed to delete: " + (e.message || "Unknown error"));
      }
    }

    function resetStepper() {
      document.querySelectorAll("#ghStepper .gh-step").forEach(el => {
        el.className = "gh-step";
      });
    }

    function updateStepper(stepStatus) {
      const steps = ["clone", "detect", "configure", "build", "deploy", "health"];
      steps.forEach(name => {
        const el = document.querySelector(`#ghStepper .gh-step[data-step="${name}"]`);
        if (!el) return;
        const status = stepStatus[name] || "pending";
        el.className = "gh-step " + (status === "done" ? "done" : status === "running" ? "running" : status === "failed" ? "failed" : "");
        const circle = el.querySelector(".gh-step-circle");
        if (status === "done") circle.innerHTML = '<i data-lucide="check" style="width:16px;height:16px;"></i>';
        else if (status === "failed") circle.innerHTML = '<i data-lucide="x" style="width:16px;height:16px;"></i>';
        else if (status === "running") circle.innerHTML = '<i data-lucide="loader" style="width:16px;height:16px;animation:spin 1s linear infinite;"></i>';
        else circle.textContent = steps.indexOf(name) + 1;
      });
      lucide.createIcons();
    }

    function startDeployPolling(deployId) {
      if (ghPollTimer) clearInterval(ghPollTimer);
      ghPollTimer = setInterval(async () => {
        try {
          const res = await apiFetch(`/deploy/github/status/${deployId}`);
          const dep = await res.json();

          updateStepper(dep.step_status || {});
          if (dep.logs) {
            document.getElementById("ghDeployLog").textContent = dep.logs;
            const logEl = document.getElementById("ghDeployLog");
            logEl.scrollTop = logEl.scrollHeight;
          }

          const statusMap = {
            "pending": "Queued...",
            "cloning": "Cloning repository...",
            "detecting": "Analyzing project...",
            "configuring": "Generating config...",
            "building": "Building Docker image...",
            "deploying": "Starting containers...",
            "health_check": "Running health check...",
            "running": "Deployment successful!",
            "failed": "Deployment failed.",
          };
          document.getElementById("ghDeployStatus").textContent = statusMap[dep.status] || dep.status;

          if (dep.status === "running" || dep.status === "failed") {
            clearInterval(ghPollTimer);
            ghPollTimer = null;
            if (dep.status === "running") {
              document.getElementById("ghDeployTitle").textContent = `${dep.app_name} is live!`;
              document.getElementById("ghDeleteDeployBtn").style.display = "none";
            } else {
              document.getElementById("ghDeployTitle").textContent = `Deploy failed`;
              document.getElementById("ghDeleteDeployBtn").style.display = "inline-flex";
              document.getElementById("ghDeleteDeployBtn").setAttribute("data-deploy-id", dep.id);
              document.getElementById("ghDeleteDeployBtn").setAttribute("data-app-name", dep.app_name);
              lucide.createIcons();
            }
            loadDeployedApps();
          }
        } catch (e) {
          // ignore poll errors
        }
      }, 2000);
    }

    function resetGitHubDeploy() {
      if (ghPollTimer) { clearInterval(ghPollTimer); ghPollTimer = null; }
      ghAnalysis = null;
      ghDeployId = null;
      document.getElementById("ghRepoUrl").value = "";
      document.getElementById("ghBranch").value = "main";
      document.getElementById("ghAnalyzeError").textContent = "";
      document.getElementById("ghDeployError").textContent = "";
      document.getElementById("ghAnalysisCard").classList.remove("visible");
      document.getElementById("ghDeployPanel").classList.remove("visible");
      document.getElementById("ghServiceSection").style.display = "none";
      document.getElementById("ghServiceList").innerHTML = "";
      document.getElementById("ghEnvSection").style.display = "none";
      document.getElementById("ghEnvVars").innerHTML = "";
      resetStepper();
    }


// Expose to window
window.loadDeployPage = loadDeployPage;
window.loadDeployTemplates = loadDeployTemplates;
window.filterDeployTemplates = filterDeployTemplates;
window.renderDeployTemplates = renderDeployTemplates;
window.openDeployWizard = openDeployWizard;
window.closeDeployWizard = closeDeployWizard;
window.submitDeploy = submitDeploy;
window.loadDeployedApps = loadDeployedApps;
window.deployAppAction = deployAppAction;
window.viewDeployLogs = viewDeployLogs;
window.closeDeployLogs = closeDeployLogs;
window.openPrivateRepoModal = openPrivateRepoModal;
window.closePrivateRepoModal = closePrivateRepoModal;
window.submitPrivateRepoCredentials = submitPrivateRepoCredentials;
window.analyzeGitHubRepo = analyzeGitHubRepo;
window.renderComposeServiceList = renderComposeServiceList;
window.renderAnalysisResult = renderAnalysisResult;
window.togglePreview = togglePreview;
window.deployFromGitHub = deployFromGitHub;
window.deleteFailedGitHubDeploy = deleteFailedGitHubDeploy;
window.resetStepper = resetStepper;
window.updateStepper = updateStepper;
window.startDeployPolling = startDeployPolling;
window.resetGitHubDeploy = resetGitHubDeploy;
