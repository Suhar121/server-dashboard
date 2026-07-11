// ─── AI Chat Panel ───────────────────────────────────────────────────────────
(function() {
  const PANEL_ID = 'ai-chat-panel';
  const STORAGE_KEY = 'ai_chat_history';
  const QUICK_PROMPTS = [
    'Show my system metrics',
    'Check running Docker containers',
    'What ports are currently open?',
    'Show recent audit logs',
    'Restart a service',
    'Check battery status'
  ];

  let isOpen = false;
  let chatHistory = [];
  let isStreaming = false;
  let aiAvailable = false;

  function getHistory() {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); } catch { return []; }
  }
  function saveHistory(h) {
    if (h.length > 50) h = h.slice(-50);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(h));
  }

  function render() {
    let panel = document.getElementById(PANEL_ID);
    if (!panel) {
      panel = document.createElement('div');
      panel.id = PANEL_ID;
      document.body.appendChild(panel);
    }
    panel.onclick = function(e) {
      if (panel.classList.contains('collapsed')) {
        toggleAIPanel();
      }
    };
    panel.innerHTML = `
      <style>
      #${PANEL_ID} {
        position: fixed;
        bottom: 24px;
        right: 24px;
        width: 420px;
        max-width: calc(100vw - 48px);
        height: 600px;
        max-height: calc(100vh - 48px);
        background: var(--card, #ffffff);
        border: 1px solid var(--border, #e2e8f0);
        border-radius: 20px;
        display: flex;
        flex-direction: column;
        font-family: 'Inter', inherit;
        font-size: 14px;
        z-index: 9999;
        box-shadow: 0 24px 48px rgba(15, 23, 42, 0.15), 0 0 0 1px rgba(15, 23, 42, 0.05);
        overflow: hidden;
        transition: opacity 0.3s cubic-bezier(0.4, 0, 0.2, 1), transform 0.3s cubic-bezier(0.4, 0, 0.2, 1), box-shadow 0.3s;
      }
      #${PANEL_ID}.collapsed {
        height: 64px;
        width: 64px;
        border-radius: 32px;
        cursor: pointer;
      }
      #${PANEL_ID}.collapsed:hover {
        transform: scale(1.05);
        box-shadow: 0 24px 48px rgba(15, 23, 42, 0.2), 0 0 0 1px rgba(15, 23, 42, 0.08);
      }
      #${PANEL_ID}.collapsed .ai-header,
      #${PANEL_ID}.collapsed .ai-body,
      #${PANEL_ID}.collapsed .ai-input-area { display: none !important; }
      #${PANEL_ID}.collapsed .ai-bubble-icon { display: flex !important; }
      .ai-bubble-icon {
        display: none;
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 36px;
        height: 36px;
        background: linear-gradient(135deg, var(--brand, #2563eb) 0%, #8b5cf6 100%);
        border-radius: 18px;
        align-items: center;
        justify-content: center;
        color: white;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3);
      }
      .ai-close-btn {
        position: absolute;
        top: -8px;
        right: -8px;
        width: 22px;
        height: 22px;
        background: #ef4444;
        border: 2px solid var(--card, #ffffff);
        border-radius: 50%;
        display: none;
        align-items: center;
        justify-content: center;
        color: white;
        font-size: 12px;
        cursor: pointer;
        z-index: 10;
        transition: transform 0.2s;
      }
      .ai-close-btn:hover {
        transform: scale(1.15);
      }
      #${PANEL_ID}.collapsed .ai-close-btn { display: flex !important; }
      .ai-header {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 16px 20px;
        border-bottom: 1px solid var(--border, #e2e8f0);
        background: var(--card, #ffffff);
        border-radius: 20px 20px 0 0;
        flex-shrink: 0;
      }
      .ai-avatar {
        width: 40px;
        height: 40px;
        border-radius: 12px;
        background: linear-gradient(135deg, var(--brand, #2563eb) 0%, #8b5cf6 100%);
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-size: 18px;
        flex-shrink: 0;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.25);
      }
      .ai-avatar.user-avatar {
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        box-shadow: 0 4px 12px rgba(16, 185, 129, 0.25);
      }
      .ai-header-info {
        flex: 1;
        min-width: 0;
      }
      .ai-header-title {
        font-weight: 700;
        font-size: 15px;
        color: var(--text, #0f172a);
        letter-spacing: -0.01em;
      }
      .ai-header-status {
        display: flex;
        align-items: center;
        gap: 6px;
        margin-top: 2px;
      }
      .ai-status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: var(--muted, #94a3b8);
      }
      .ai-status-dot.online {
        background: #10b981;
        box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.2);
        animation: pulse 2s infinite;
      }
      @keyframes pulse {
        0%, 100% { box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.2); }
        50% { box-shadow: 0 0 0 5px rgba(16, 185, 129, 0.1); }
      }
      .ai-status-text {
        font-size: 12px;
        color: var(--muted, #64748b);
      }
      .ai-header-actions {
        display: flex;
        gap: 4px;
      }
      .ai-header-btn {
        background: var(--card-soft, #f8fafc);
        border: 1px solid var(--border, #e2e8f0);
        cursor: pointer;
        color: var(--muted, #64748b);
        font-size: 13px;
        padding: 8px;
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.2s;
      }
      .ai-header-btn:hover {
        background: var(--brand-soft, rgba(37, 99, 235, 0.1));
        border-color: var(--brand, #2563eb);
        color: var(--brand, #2563eb);
      }
      .ai-body {
        flex: 1;
        overflow-y: auto;
        padding: 20px;
        display: flex;
        flex-direction: column;
        gap: 16px;
        scroll-behavior: smooth;
        background: var(--bg, #f8fafc);
      }
      .ai-welcome {
        text-align: center;
        padding: 32px 20px;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 12px;
      }
      .ai-welcome-icon {
        width: 64px;
        height: 64px;
        border-radius: 20px;
        background: linear-gradient(135deg, var(--brand, #2563eb) 0%, #8b5cf6 100%);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 28px;
        color: white;
        box-shadow: 0 8px 24px rgba(37, 99, 235, 0.3);
        margin-bottom: 4px;
      }
      .ai-welcome-title {
        font-weight: 700;
        font-size: 18px;
        color: var(--text, #0f172a);
        letter-spacing: -0.02em;
      }
      .ai-welcome-subtitle {
        font-size: 13px;
        color: var(--muted, #64748b);
        max-width: 260px;
        line-height: 1.5;
      }
      .ai-quick-prompts {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        justify-content: center;
        margin-top: 8px;
      }
      .ai-quick-prompt {
        background: var(--card, #ffffff);
        border: 1px solid var(--border, #e2e8f0);
        border-radius: 20px;
        padding: 8px 14px;
        font-size: 12px;
        font-weight: 500;
        color: var(--text, #0f172a);
        cursor: pointer;
        transition: all 0.2s;
        white-space: nowrap;
      }
      .ai-quick-prompt:hover {
        background: var(--brand-soft, rgba(37, 99, 235, 0.1));
        border-color: var(--brand, #2563eb);
        color: var(--brand, #2563eb);
        transform: translateY(-1px);
      }
      .ai-msg-row {
        display: flex;
        gap: 10px;
        animation: msgIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      }
      .ai-msg-row.user {
        flex-direction: row-reverse;
      }
      @keyframes msgIn {
        from { opacity: 0; transform: translateY(8px); }
        to { opacity: 1; transform: translateY(0); }
      }
      .ai-msg-avatar {
        width: 32px;
        height: 32px;
        border-radius: 10px;
        background: linear-gradient(135deg, var(--brand, #2563eb) 0%, #8b5cf6 100%);
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-size: 14px;
        flex-shrink: 0;
        align-self: flex-end;
      }
      .ai-msg-avatar.user {
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
      }
      .ai-msg-content {
        max-width: 75%;
        display: flex;
        flex-direction: column;
        gap: 4px;
      }
      .ai-msg-bubble {
        padding: 12px 16px;
        border-radius: 16px;
        line-height: 1.55;
        white-space: pre-wrap;
        word-break: break-word;
        font-size: 13.5px;
      }
      .ai-msg.user .ai-msg-bubble {
        background: linear-gradient(135deg, var(--brand, #2563eb) 0%, #2563eb 100%);
        color: #ffffff;
        border-bottom-right-radius: 6px;
      }
      .ai-msg.ai .ai-msg-bubble {
        background: var(--card, #ffffff);
        color: var(--text, #0f172a);
        border: 1px solid var(--border, #e2e8f0);
        border-bottom-left-radius: 6px;
        box-shadow: 0 2px 8px rgba(15, 23, 42, 0.04);
      }
      .ai-msg.error .ai-msg-bubble {
        background: rgba(239, 68, 68, 0.1);
        color: #ef4444;
        border: 1px solid rgba(239, 68, 68, 0.2);
      }
      .ai-msg-time {
        font-size: 11px;
        color: var(--muted, #94a3b8);
        padding: 0 4px;
      }
      .ai-msg.user .ai-msg-time {
        text-align: right;
      }
      .ai-tool-card {
        background: var(--card, #ffffff);
        border: 1px solid var(--border, #e2e8f0);
        border-radius: 12px;
        padding: 12px 14px;
        font-size: 12px;
        color: var(--muted, #64748b);
        align-self: flex-start;
        width: 100%;
        box-sizing: border-box;
        box-shadow: 0 2px 8px rgba(15, 23, 42, 0.04);
        margin-left: 42px;
      }
      .ai-tool-card-header {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 8px;
      }
      .ai-tool-icon {
        width: 24px;
        height: 24px;
        border-radius: 6px;
        background: var(--brand-soft, rgba(37, 99, 235, 0.1));
        display: flex;
        align-items: center;
        justify-content: center;
        color: var(--brand, #2563eb);
        font-size: 12px;
      }
      .ai-tool-name {
        font-weight: 600;
        color: var(--text, #0f172a);
        font-size: 12px;
      }
      .ai-tool-result {
        margin-top: 8px;
        padding: 8px 10px;
        background: var(--bg, #f8fafc);
        border-radius: 8px;
        font-family: 'Monaco', 'Consolas', monospace;
        font-size: 11px;
        color: var(--text, #0f172a);
        max-height: 100px;
        overflow-y: auto;
        white-space: pre-wrap;
        word-break: break-all;
        border: 1px solid var(--border, #e2e8f0);
      }
      .ai-pending-card {
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.1) 0%, rgba(245, 158, 11, 0.05) 100%);
        border: 1px solid rgba(245, 158, 11, 0.3);
        border-radius: 14px;
        padding: 14px 16px;
        align-self: flex-start;
        width: calc(100% - 52px);
        margin-left: 42px;
        box-shadow: 0 2px 8px rgba(245, 158, 11, 0.1);
      }
      .ai-pending-header {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 8px;
      }
      .ai-pending-icon {
        font-size: 16px;
      }
      .ai-pending-title {
        font-weight: 600;
        font-size: 13px;
        color: #b45309;
      }
      .ai-pending-desc {
        font-size: 12px;
        color: #92400e;
        line-height: 1.5;
        margin-bottom: 12px;
      }
      .ai-pending-btns {
        display: flex;
        gap: 8px;
      }
      .ai-pending-btns button {
        padding: 8px 20px;
        border-radius: 8px;
        border: none;
        cursor: pointer;
        font-size: 12px;
        font-weight: 600;
        transition: all 0.2s;
      }
      .ai-pending-btns .approve-btn {
        background: #10b981;
        color: white;
        box-shadow: 0 2px 8px rgba(16, 185, 129, 0.3);
      }
      .ai-pending-btns .approve-btn:hover {
        background: #059669;
        transform: translateY(-1px);
      }
      .ai-pending-btns .deny-btn {
        background: var(--card, #ffffff);
        color: #64748b;
        border: 1px solid var(--border, #e2e8f0);
      }
      .ai-pending-btns .deny-btn:hover {
        background: #fef2f2;
        border-color: #ef4444;
        color: #ef4444;
      }
      .ai-typing-indicator {
        display: flex;
        gap: 4px;
        padding: 4px 0;
      }
      .ai-typing-indicator span {
        width: 6px;
        height: 6px;
        background: var(--muted, #94a3b8);
        border-radius: 50%;
        animation: typing 1.4s infinite;
      }
      .ai-typing-indicator span:nth-child(2) { animation-delay: 0.2s; }
      .ai-typing-indicator span:nth-child(3) { animation-delay: 0.4s; }
      @keyframes typing {
        0%, 60%, 100% { transform: translateY(0); opacity: 0.4; }
        30% { transform: translateY(-6px); opacity: 1; }
      }
      .ai-input-area {
        display: flex;
        gap: 10px;
        padding: 16px 20px;
        border-top: 1px solid var(--border, #e2e8f0);
        background: var(--card, #ffffff);
        border-radius: 0 0 20px 20px;
        flex-shrink: 0;
      }
      .ai-input {
        flex: 1;
        background: var(--bg, #f8fafc);
        border: 1px solid var(--border, #e2e8f0);
        border-radius: 14px;
        padding: 12px 16px;
        color: var(--text, #0f172a);
        font-family: 'Inter', inherit;
        font-size: 13.5px;
        resize: none;
        max-height: 120px;
        outline: none;
        transition: border-color 0.2s, box-shadow 0.2s;
        line-height: 1.5;
      }
      .ai-input:focus {
        border-color: var(--brand, #2563eb);
        box-shadow: 0 0 0 3px var(--brand-soft, rgba(37, 99, 235, 0.1));
      }
      .ai-input::placeholder {
        color: var(--muted, #94a3b8);
      }
      .ai-send-btn {
        background: linear-gradient(135deg, var(--brand, #2563eb) 0%, #2563eb 100%);
        border: none;
        border-radius: 12px;
        width: 44px;
        height: 44px;
        cursor: pointer;
        color: #fff;
        font-size: 18px;
        display: flex;
        align-items: center;
        justify-content: center;
        align-self: flex-end;
        transition: all 0.2s;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3);
      }
      .ai-send-btn:hover:not(:disabled) {
        transform: translateY(-2px);
        box-shadow: 0 6px 16px rgba(37, 99, 235, 0.4);
      }
      .ai-send-btn:disabled {
        opacity: 0.5;
        cursor: not-allowed;
        transform: none;
        box-shadow: none;
      }
      .ai-unavailable {
        padding: 8px 12px;
        background: rgba(239, 68, 68, 0.1);
        border-radius: 8px;
        font-size: 11px;
        color: #ef4444;
        margin-top: 4px;
        text-align: center;
      }
      </style>
      <div class="ai-bubble-icon">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg>
      </div>
      <div class="ai-close-btn" onclick="event.stopPropagation(); hideAIPanel()" title="Close">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>
      </div>
      <div class="ai-header">
        <div class="ai-avatar">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg>
        </div>
        <div class="ai-header-info">
          <div class="ai-header-title">AI Assistant</div>
          <div class="ai-header-status">
            <div class="ai-status-dot" id="aiStatusDot"></div>
            <span class="ai-status-text" id="aiStatusText">Checking...</span>
          </div>
        </div>
        <div class="ai-header-actions">
          <button class="ai-header-btn" onclick="toggleAIPanel()" title="Minimize">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14"/></svg>
          </button>
          <button class="ai-header-btn" onclick="hideAIPanel()" title="Close" style="color: #ef4444;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>
          </button>
          <button class="ai-header-btn" onclick="startNewChat()" title="New chat">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
          </button>
        </div>
      </div>
      <div class="ai-body" id="aiBody"></div>
      <div class="ai-input-area">
        <textarea class="ai-input" id="aiInput" rows="1" placeholder="Ask about your server..."
          onkeydown="handleAIInputKey(event)" oninput="autoResizeInput(this)"></textarea>
        <button class="ai-send-btn" id="aiSendBtn" onclick="sendAIMessage()">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/></svg>
        </button>
      </div>
    `;

    chatHistory = getHistory();
    renderMessages();
    if (!isOpen) panel.classList.add('collapsed');
  }

  function renderMessages() {
    const body = document.getElementById('aiBody');
    if (!body) return;
    body.innerHTML = '';

    if (chatHistory.length === 0) {
      renderWelcome(body);
    } else {
      for (const msg of chatHistory) {
        appendMsgEl(body, msg);
      }
    }
    body.scrollTop = body.scrollHeight;
  }

  function renderWelcome(body) {
    const welcome = document.createElement('div');
    welcome.className = 'ai-welcome';
    welcome.innerHTML = `
      <div class="ai-welcome-icon">🤖</div>
      <div class="ai-welcome-title">How can I help you?</div>
      <div class="ai-welcome-subtitle">I can help you monitor your server, manage Docker containers, check ports, and more.</div>
      <div class="ai-quick-prompts">
        ${QUICK_PROMPTS.map(p => `<button class="ai-quick-prompt" onclick="sendQuickPrompt('${p.replace(/'/g, "\\'")}')">${p}</button>`).join('')}
      </div>
    `;
    body.appendChild(welcome);
  }

  function appendMsgEl(container, msg) {
    if (msg.type === 'tool_call') {
      const card = document.createElement('div');
      card.className = 'ai-tool-card';
      card.innerHTML = `
        <div class="ai-tool-card-header">
          <div class="ai-tool-icon">⚡</div>
          <span class="ai-tool-name">${escapeHtml(msg.tool)}</span>
        </div>
        <div class="ai-tool-result">Executing tool...</div>`;
      container.appendChild(card);
      return;
    }
    if (msg.type === 'tool_result') {
      const cards = container.querySelectorAll('.ai-tool-card');
      const last = cards[cards.length - 1];
      if (last && last.innerHTML.includes(msg.tool)) {
        const res = last.querySelector('.ai-tool-result');
        if (res) res.textContent = formatJSON(msg.result);
      }
      return;
    }
    if (msg.type === 'action_pending') {
      const card = document.createElement('div');
      card.className = 'ai-pending-card';
      card.innerHTML = `
        <div class="ai-pending-header">
          <span class="ai-pending-icon">⚠️</span>
          <span class="ai-pending-title">Action Required</span>
        </div>
        <div class="ai-pending-desc">The AI wants to ${escapeHtml(msg.tool)} with the provided parameters. Do you want to approve this action?</div>
        <div class="ai-pending-btns">
          <button class="approve-btn" onclick="confirmAIAction('${msg.action_id}', true)">Approve</button>
          <button class="deny-btn" onclick="confirmAIAction('${msg.action_id}', false)">Deny</button>
        </div>`;
      container.appendChild(card);
      return;
    }

    const isUser = msg.role === 'user';
    const row = document.createElement('div');
    row.className = 'ai-msg-row ' + (isUser ? 'user' : 'ai');

    const time = msg.timestamp ? formatTime(msg.timestamp) : formatTime(Date.now());

    row.innerHTML = `
      <div class="ai-msg-avatar ${isUser ? 'user' : ''}">
        ${isUser ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>' : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg>'}
      </div>
      <div class="ai-msg-content">
        <div class="ai-msg-bubble">${escapeHtml(msg.content || '')}</div>
        <div class="ai-msg-time">${time}</div>
      </div>
    `;
    container.appendChild(row);
  }

  function escapeHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function formatJSON(obj) {
    try { return JSON.stringify(obj, null, 2); } catch { return String(obj); }
  }

  function formatTime(ts) {
    const d = new Date(ts);
    return d.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
  }

  function autoResizeInput(el) {
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 120) + 'px';
  }

  window.toggleAIPanel = function() {
    isOpen = !isOpen;
    const panel = document.getElementById(PANEL_ID);
    if (panel) {
      if (isOpen) panel.classList.remove('collapsed');
      else panel.classList.add('collapsed');
    }
  };

  window.hideAIPanel = function() {
    isOpen = false;
    const panel = document.getElementById(PANEL_ID);
    if (panel) panel.style.display = 'none';
    let fab = document.getElementById('ai-fab-reopen');
    if (!fab) {
      fab = document.createElement('button');
      fab.id = 'ai-fab-reopen';
      fab.title = 'Open AI Assistant';
      fab.style.cssText = 'position:fixed;bottom:24px;right:24px;width:56px;height:56px;border-radius:28px;background:linear-gradient(135deg,var(--brand,#2563eb) 0%,#8b5cf6 100%);border:none;cursor:pointer;z-index:9998;display:flex;align-items:center;justify-content:center;color:white;box-shadow:0 8px 24px rgba(37,99,235,0.3);transition:transform 0.2s;';
      fab.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg>';
      fab.onmouseenter = function() { fab.style.transform = 'scale(1.1)'; };
      fab.onmouseleave = function() { fab.style.transform = 'scale(1)'; };
      fab.onclick = function() { showAIPanel(); };
      document.body.appendChild(fab);
    }
    fab.style.display = 'flex';
  };

  window.showAIPanel = function() {
    const panel = document.getElementById(PANEL_ID);
    if (panel) {
      panel.style.display = '';
      panel.classList.add('collapsed');
      isOpen = false;
    }
    const fab = document.getElementById('ai-fab-reopen');
    if (fab) fab.style.display = 'none';
  };

  window.startNewChat = function() {
    chatHistory = [];
    localStorage.removeItem(STORAGE_KEY);
    const body = document.getElementById('aiBody');
    if (body) {
      body.innerHTML = '';
      renderWelcome(body);
    }
  };

  window.sendQuickPrompt = function(text) {
    const input = document.getElementById('aiInput');
    if (input) {
      input.value = text;
      sendAIMessage();
    }
  };

  window.clearAIHistory = function() {
    startNewChat();
  };

  window.handleAIInputKey = function(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendAIMessage();
    }
  };

  window.confirmAIAction = async function(action_id, approved) {
    try {
      const res = await fetch('/ai/confirm-action', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action_id, approved}),
      });
      const data = await res.json();
      const body = document.getElementById('aiBody');
      if (body) {
        const msg = {
          role: 'ai',
          content: approved
            ? `Action ${data.executed ? 'executed successfully' : 'failed'}: ${formatJSON(data.result || data.error)}`
            : 'Action denied by user.',
          timestamp: Date.now()
        };
        chatHistory.push(msg);
        saveHistory(chatHistory);
        body.innerHTML = '';
        renderMessages();
        body.scrollTop = body.scrollHeight;
      }
    } catch (e) {
      alert('Failed to confirm action: ' + e.message);
    }
  };

  window.sendAIMessage = async function() {
    const input = document.getElementById('aiInput');
    const sendBtn = document.getElementById('aiSendBtn');
    if (!input || isStreaming) return;
    const text = input.value.trim();
    if (!text) return;

    if (text.includes('data:image/') || text.includes('[object Blob]') || text.includes('[object File]')) {
      const body = document.getElementById('aiBody');
      if (body) {
        const errMsg = { role: 'ai', content: 'Image input is not supported. Please send text only.', timestamp: Date.now() };
        chatHistory.push(errMsg);
        appendMsgEl(body, errMsg);
        body.scrollTop = body.scrollHeight;
      }
      return;
    }

    isStreaming = true;
    sendBtn.disabled = true;
    input.value = '';
    input.style.height = 'auto';

    const body = document.getElementById('aiBody');
    if (!body) return;

    if (chatHistory.length === 0) {
      body.innerHTML = '';
    }

    const userMsg = { role: 'user', content: text, timestamp: Date.now() };
    chatHistory.push(userMsg);
    saveHistory(chatHistory);
    appendMsgEl(body, userMsg);
    body.scrollTop = body.scrollHeight;

    const loadingRow = document.createElement('div');
    loadingRow.className = 'ai-msg-row ai';
    loadingRow.innerHTML = `
      <div class="ai-msg-avatar">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg>
      </div>
      <div class="ai-msg-content">
        <div class="ai-msg-bubble"><div class="ai-typing-indicator"><span></span><span></span><span></span></div></div>
      </div>
    `;
    body.appendChild(loadingRow);
    body.scrollTop = body.scrollHeight;

    try {
      const res = await fetch('/ai/chat', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({message: text, stream: true}),
      });

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let aiMsgDiv = loadingRow.querySelector('.ai-msg-bubble');
      let aiContentDiv = loadingRow.querySelector('.ai-msg-content');
      let aiTimeDiv = document.createElement('div');
      aiTimeDiv.className = 'ai-msg-time';
      aiContentDiv.appendChild(aiTimeDiv);

      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, {stream: true});
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const event = JSON.parse(line.slice(6));
            if (event.type === 'text') {
              aiMsgDiv.innerHTML = escapeHtml(event.content);
              body.scrollTop = body.scrollHeight;
            } else if (event.type === 'tool_call') {
              const toolCard = document.createElement('div');
              toolCard.className = 'ai-tool-card';
              toolCard.innerHTML = `
                <div class="ai-tool-card-header">
                  <div class="ai-tool-icon">⚡</div>
                  <span class="ai-tool-name">${escapeHtml(event.tool)}</span>
                </div>
                <div class="ai-tool-result">Running...</div>`;
              body.appendChild(toolCard);
              body.scrollTop = body.scrollHeight;
            } else if (event.type === 'tool_result') {
              appendMsgEl(body, {type: 'tool_result', tool: event.tool, result: event.result});
            } else if (event.type === 'action_pending') {
              appendMsgEl(body, {type: 'action_pending', action_id: event.action_id, summary: event.summary, tool: event.tool});
            } else if (event.type === 'done') {
              const finalContent = aiMsgDiv.textContent || '[Analysis complete]';
              aiTimeDiv.textContent = formatTime(Date.now());
              chatHistory.push({role: 'ai', content: finalContent, timestamp: Date.now()});
              saveHistory(chatHistory);
            } else if (event.type === 'error') {
              aiMsgDiv.innerHTML = `<span style="color: #ef4444;">Error: ${escapeHtml(event.message)}</span>`;
              aiTimeDiv.textContent = formatTime(Date.now());
            }
          } catch {}
        }
      }
    } catch (e) {
      aiMsgDiv.innerHTML = `<span style="color: #ef4444;">Connection error: ${escapeHtml(e.message)}</span>`;
      aiTimeDiv.textContent = formatTime(Date.now());
    } finally {
      isStreaming = false;
      sendBtn.disabled = false;
      saveHistory(chatHistory);
    }
  };

  render();

  (async function checkAIAvailable() {
    const statusDot = document.getElementById('aiStatusDot');
    const statusText = document.getElementById('aiStatusText');
    try {
      const res = await fetch('/ai/status');
      const data = await res.json();
      aiAvailable = data.available;
      if (statusDot) {
        if (aiAvailable) {
          statusDot.classList.add('online');
          if (statusText) statusText.textContent = 'Online';
        } else {
          statusDot.classList.remove('online');
          if (statusText) statusText.textContent = 'Not configured';
        }
      }
      if (!aiAvailable) {
        const input = document.getElementById('aiInput');
        if (input) {
          input.placeholder = 'AI not configured. Set GEMINI_API_KEY';
          input.disabled = true;
        }
        const sendBtn = document.getElementById('aiSendBtn');
        if (sendBtn) sendBtn.disabled = true;
      }
    } catch {
      if (statusDot) statusDot.classList.remove('online');
      if (statusText) statusText.textContent = 'Offline';
    }
  })();
})();
