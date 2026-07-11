// Terminal WebSocket & Session Management
    function getTerminalSocketUrl() {
      const protocol = location.protocol === "https:" ? "wss" : "ws";
      return `${protocol}://${location.host}/ws/terminal?protocol=v2`;
    }

    function sendTerminalMessage(tab, payload) {
      if (!tab || !tab.ws || tab.ws.readyState !== WebSocket.OPEN) return;

      const messageType = String(payload?.type || "").toLowerCase();

      if (messageType === "input") {
        const inputData = typeof payload?.data === "string" ? payload.data : "";
        if (!inputData) return;

        try {
          if (tab.protocolVersion >= 2) {
            tab.ws.send(JSON.stringify({ type: "input", data: inputData }));
          } else {
            tab.ws.send(inputData);
          }
        } catch (_) {}
        return;
      }

      if (messageType === "resize") {
        if (tab.protocolVersion < 2) return;
        try {
          tab.ws.send(JSON.stringify({
            type: "resize",
            cols: payload?.cols,
            rows: payload?.rows,
          }));
        } catch (_) {}
        return;
      }

      try {
        tab.ws.send(JSON.stringify(payload));
      } catch (_) {}
    }

    function sendTerminalResize(tab) {
      if (!tab || !tab.term) return;
      const cols = Math.max(20, Number(tab.term.cols) || 80);
      const rows = Math.max(5, Number(tab.term.rows) || 24);
      sendTerminalMessage(tab, { type: "resize", cols, rows });
    }

    function fitTerminalTab(tab) {
      if (!tab || !tab.term) return;

      if (tab.fitAddon && typeof tab.fitAddon.fit === "function") {
        try {
          tab.fitAddon.fit();
        } catch (_) {}
      }

      sendTerminalResize(tab);
    }

    function fitActiveTerminal() {
      const tab = terminalTabs.find((t) => t.id === activeTerminalTabId);
      if (!tab) return;
      fitTerminalTab(tab);
    }

    function requestFitActiveTerminal() {
      if (terminalResizeRaf) {
        cancelAnimationFrame(terminalResizeRaf);
      }
      terminalResizeRaf = requestAnimationFrame(() => {
        terminalResizeRaf = null;
        fitActiveTerminal();
      });
    }

    function isTerminalFullscreenActive() {
      const terminalPage = document.getElementById("terminalPage");
      if (!terminalPage) return false;
      return document.fullscreenElement === terminalPage || terminalPage.classList.contains("terminal-fallback-fullscreen");
    }

    function syncTerminalFullscreenUi() {
      const btn = document.getElementById("terminalFullscreenBtn");
      if (!btn) return;

      const isActive = isTerminalFullscreenActive();
      btn.innerHTML = isActive
        ? '<i data-lucide="minimize" style="width:16px;height:16px;"></i> Exit Full Screen'
        : '<i data-lucide="maximize" style="width:16px;height:16px;"></i> Full Screen';
      lucide.createIcons();
    }

    async function toggleTerminalFullscreen() {
      const terminalPage = document.getElementById("terminalPage");
      if (!terminalPage) return;

      if (terminalPage.classList.contains("terminal-fallback-fullscreen")) {
        terminalPage.classList.remove("terminal-fallback-fullscreen");
        syncTerminalFullscreenUi();
        requestFitActiveTerminal();
        return;
      }

      if (document.fullscreenElement === terminalPage) {
        try {
          await document.exitFullscreen();
        } catch (_) {}
        syncTerminalFullscreenUi();
        requestFitActiveTerminal();
        return;
      }

      if (typeof terminalPage.requestFullscreen === "function") {
        try {
          await terminalPage.requestFullscreen();
          syncTerminalFullscreenUi();
          requestFitActiveTerminal();
          return;
        } catch (_) {
          // fallback below
        }
      }

      terminalPage.classList.add("terminal-fallback-fullscreen");
      syncTerminalFullscreenUi();
      requestFitActiveTerminal();
    }

    async function exitTerminalFullscreenIfActive() {
      const terminalPage = document.getElementById("terminalPage");
      if (!terminalPage) return;

      if (terminalPage.classList.contains("terminal-fallback-fullscreen")) {
        terminalPage.classList.remove("terminal-fallback-fullscreen");
      }

      if (document.fullscreenElement === terminalPage && typeof document.exitFullscreen === "function") {
        try {
          await document.exitFullscreen();
        } catch (_) {}
      }

      syncTerminalFullscreenUi();
      requestFitActiveTerminal();
    }

    function ensureTerminalReady() {
      if (!terminalTabs.length) {
        createTerminalTab();
      } else {
        switchTerminalTab(terminalTabs[terminalTabs.length - 1].id);
      }
      applyPendingTerminalPath();
      syncTerminalFullscreenUi();
      requestFitActiveTerminal();
    }

    function renderTerminalTabs() {
      const tabsWrap = document.getElementById("terminalTabs");
      tabsWrap.innerHTML = terminalTabs.map((tab) => `
        <button class="terminal-tab ${tab.id === activeTerminalTabId ? "active" : ""}" onclick="switchTerminalTab('${tab.id}')">
          <span>Tab ${tab.index}</span>
          <span class="terminal-tab-close" onclick="event.stopPropagation(); closeTerminalTab('${tab.id}')">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </span>
        </button>
      `).join("");
    }

    function renderTerminalHistory() {
      const list = document.getElementById("terminalHistoryList");
      const tab = terminalTabs.find(t => t.id === activeTerminalTabId);
      if (!tab || !tab.history.length) {
        list.innerHTML = `<li class="muted">No commands yet.</li>`;
        return;
      }

      const visible = tab.history.slice(-40).reverse();
      list.innerHTML = visible.map((cmd) => `<li>$ ${esc(cmd)}</li>`).join("");
    }

    function switchTerminalTab(tabId) {
      activeTerminalTabId = tabId;
      document.querySelectorAll(".terminal-instance").forEach((node) => {
        node.classList.remove("active");
      });
      const activeNode = document.getElementById(`terminal-instance-${tabId}`);
      if (activeNode) activeNode.classList.add("active");

      renderTerminalTabs();
      renderTerminalHistory();

      const tab = terminalTabs.find((t) => t.id === tabId);
      if (tab && tab.term) {
        tab.term.focus();
        requestFitActiveTerminal();
      }
    }

    function trackTerminalInput(tab, data) {
      if (data === "\r") {
        const cmd = tab.inputBuffer.trim();
        if (cmd) {
          tab.history.push(cmd);
          if (tab.history.length > 200) {
            tab.history = tab.history.slice(-200);
          }
          renderTerminalHistory();
        }
        tab.inputBuffer = "";
        return;
      }

      if (data === "\u007f") {
        tab.inputBuffer = tab.inputBuffer.slice(0, -1);
        return;
      }

      if (data.startsWith("\u001b")) {
        return;
      }

      tab.inputBuffer += data.replace(/[\x00-\x1F\x7F]/g, "");
    }

    function createTerminalTab() {
      if (!hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }

      const shell = document.getElementById("terminalShell");
      if (!shell) return;

      terminalTabCounter += 1;
      const tabId = `tab-${Date.now()}-${terminalTabCounter}`;

      const holder = document.createElement("div");
      holder.id = `terminal-instance-${tabId}`;
      holder.className = "terminal-instance";
      shell.appendChild(holder);

      const term = new Terminal({
        cursorBlink: true,
        convertEol: true,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
        fontSize: 14,
        theme: {
          background: "#020817",
          foreground: "#d4e6ff",
          cursor: "#60a5fa",
          black: "#0b1222",
          brightBlue: "#60a5fa",
          green: "#22c55e",
        },
      });

      const fitAddon = window.FitAddon && typeof window.FitAddon.FitAddon === "function"
        ? new window.FitAddon.FitAddon()
        : null;
      if (fitAddon) {
        term.loadAddon(fitAddon);
      }

      term.open(holder);
      term.write("\u001b[34mConnecting to shell...\u001b[0m\r\n");

      const ws = new WebSocket(getTerminalSocketUrl());

      const tab = {
        id: tabId,
        index: terminalTabCounter,
        term,
        fitAddon,
        ws,
        protocolVersion: 1,
        history: [],
        inputBuffer: "",
        pendingPath: pendingTerminalPath,
      };

      pendingTerminalPath = null;

      ws.onopen = () => {
        term.write("\u001b[32mConnected. Happy hacking.\u001b[0m\r\n");
        if (tab.pendingPath) {
          sendTerminalCd(tab, tab.pendingPath);
          tab.pendingPath = null;
        }
        requestFitActiveTerminal();
      };

      ws.onmessage = (event) => {
        if ((event.data || "") === TERMINAL_PROTOCOL_V2_MARKER) {
          tab.protocolVersion = 2;
          requestFitActiveTerminal();
          return;
        }
        term.write(event.data || "");
      };

      ws.onclose = () => {
        term.write("\r\n\u001b[31m[Terminal disconnected]\u001b[0m\r\n");
      };

      ws.onerror = () => {
        term.write("\r\n\u001b[31m[Terminal connection error]\u001b[0m\r\n");
      };

      term.onData((data) => {
        trackTerminalInput(tab, data);
        sendTerminalMessage(tab, { type: "input", data });
      });

      terminalTabs.push(tab);
      switchTerminalTab(tabId);
      requestFitActiveTerminal();
    }

    function closeTerminalTab(tabId) {
      const index = terminalTabs.findIndex((t) => t.id === tabId);
      if (index === -1) return;

      const [tab] = terminalTabs.splice(index, 1);

      try {
        if (tab.ws && tab.ws.readyState < 2) {
          tab.ws.close();
        }
      } catch (_) {}

      try {
        tab.term.dispose();
      } catch (_) {}

      const holder = document.getElementById(`terminal-instance-${tabId}`);
      if (holder) holder.remove();

      if (!terminalTabs.length) {
        activeTerminalTabId = null;
        renderTerminalTabs();
        renderTerminalHistory();
        return;
      }

      const nextTab = terminalTabs[Math.max(0, index - 1)] || terminalTabs[0];
      switchTerminalTab(nextTab.id);
      requestFitActiveTerminal();
    }

    function clearTerminalHistory() {
      const tab = terminalTabs.find((t) => t.id === activeTerminalTabId);
      if (!tab) return;
      tab.history = [];
      renderTerminalHistory();
    }

    function closeAllTerminalTabs() {
      const ids = terminalTabs.map((t) => t.id);
      ids.forEach((id) => closeTerminalTab(id));
      terminalTabs = [];
      activeTerminalTabId = null;
      renderTerminalTabs();
      renderTerminalHistory();
    }


// Expose to window
window.getTerminalSocketUrl = getTerminalSocketUrl;
window.sendTerminalMessage = sendTerminalMessage;
window.sendTerminalResize = sendTerminalResize;
window.fitTerminalTab = fitTerminalTab;
window.fitActiveTerminal = fitActiveTerminal;
window.requestFitActiveTerminal = requestFitActiveTerminal;
window.isTerminalFullscreenActive = isTerminalFullscreenActive;
window.syncTerminalFullscreenUi = syncTerminalFullscreenUi;
window.toggleTerminalFullscreen = toggleTerminalFullscreen;
window.exitTerminalFullscreenIfActive = exitTerminalFullscreenIfActive;
window.ensureTerminalReady = ensureTerminalReady;
window.renderTerminalTabs = renderTerminalTabs;
window.renderTerminalHistory = renderTerminalHistory;
window.switchTerminalTab = switchTerminalTab;
window.trackTerminalInput = trackTerminalInput;
window.createTerminalTab = createTerminalTab;
window.closeTerminalTab = closeTerminalTab;
window.clearTerminalHistory = clearTerminalHistory;
window.closeAllTerminalTabs = closeAllTerminalTabs;
