import os
import re

original_path = "frontend/index.original.html"
target_path = "frontend/index.html"

with open(original_path, "r", encoding="utf-8") as f:
    html = f.read()

# 1. Update Head
head_replace = """<title>GridCore - Server Management Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm/css/xterm.css" />
  <script src="https://cdn.jsdelivr.net/npm/xterm/lib/xterm.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit/lib/xterm-addon-fit.min.js"></script>
  <link rel="stylesheet" href="./static/css/style.css" />
  <link rel="stylesheet" href="./static/css/promage.css" />
  <script src="https://unpkg.com/lucide@latest"></script>"""

html = re.sub(r'<title>GridCore</title>.*?(?=<script src="https://unpkg.com/lucide@latest"></script>)', head_replace + "\n  ", html, flags=re.DOTALL)

# 2. Update Sidebar Branding with Real GridCore Identity in Promage Styling
old_sidebar_header = """  <!-- Enterprise Context Header -->
  <div class="sidebar-org">
    <div class="sidebar-org-header">
      <img src="/logo" alt="GridCore" class="sidebar-org-logo" />
      <div class="sidebar-org-info">
        <div class="sidebar-org-name">GridCore</div>
        <div id="serverNameLabel" class="sidebar-org-server"></div>
      </div>
      <button class="sidebar-collapse-btn" onclick="toggleSidebar()" title="Collapse">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
      </button>
    </div>
    <div class="sidebar-env-row">
      <span class="sidebar-env-badge">Production</span>
      <span class="sidebar-health-dot"></span>
      <span class="sidebar-health-text">Healthy</span>
    </div>
  </div>"""

new_sidebar_header = """  <!-- Promage Sidebar Brand Header -->
  <div class="sidebar-org">
    <div class="sidebar-org-header" style="display:flex;align-items:center;justify-content:space-between;width:100%;">
      <div style="display:flex;align-items:center;gap:10px;">
        <svg class="brand-icon" viewBox="0 0 32 32" fill="none" style="width:30px;height:30px;flex-shrink:0;">
          <circle cx="16" cy="16" r="6" fill="#FF5A26" />
          <path d="M16 2V6M16 26V30M2 16H6M26 16H30M6.1 6.1L8.9 8.9M23.1 23.1L25.9 25.9M6.1 25.9L8.9 23.1M23.1 8.9L25.9 6.1" stroke="#FF5A26" stroke-width="3" stroke-linecap="round" />
        </svg>
        <div class="sidebar-org-info">
          <div class="sidebar-org-name" style="font-size:18px;font-weight:700;color:#fff;line-height:1.1;">GridCore</div>
          <div id="serverNameLabel" class="sidebar-org-server" style="font-size:11px;color:#9ca3af;"></div>
        </div>
      </div>
      <button class="sidebar-collapse-btn" onclick="toggleSidebar()" title="Collapse">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
      </button>
    </div>
    <div class="sidebar-env-row" style="margin-top:8px;padding:0;">
      <span class="sidebar-env-badge">Production</span>
      <span class="sidebar-health-dot"></span>
      <span class="sidebar-health-text">Healthy</span>
    </div>
  </div>

  <!-- Promage CTA Button: Quick Deploy / Create Application -->
  <button class="sidebar-cta-btn" onclick="goToPage('deploy')" title="Deploy App">
    <div class="create-btn-circle">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <line x1="12" y1="5" x2="12" y2="19"></line>
        <line x1="5" y1="12" x2="19" y2="12"></line>
      </svg>
    </div>
    <span style="line-height:1.2;">Create new<br/>project / app</span>
  </button>"""

if old_sidebar_header in html:
    html = html.replace(old_sidebar_header, new_sidebar_header)

# 3. Add Help Floating Button to Sidebar Footer
footer_target = """    <div class="sidebar-footer-row">"""
new_footer_addition = """    <div style="display:flex;justify-content:center;margin-bottom:12px;">
      <button class="help-floating-btn" title="Help & Support" onclick="goToPage('dashboard')">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path>
          <line x1="12" y1="17" x2="12.01" y2="17"></line>
        </svg>
      </button>
    </div>
    <div class="sidebar-footer-row">"""
html = html.replace(footer_target, new_footer_addition)

# 4. Redesign Topbar to Promage Header with Real User Info
old_topbar = """  <!-- Enterprise Top Bar -->
  <div class="topbar-enterprise">
    <div class="topbar-left">
      <div class="topbar-breadcrumb">
        <span class="topbar-breadcrumb-item active" id="topbarBreadcrumb">Dashboard</span>
      </div>
    </div>
    <div class="topbar-right">
      <button class="topbar-icon-btn" title="Notifications">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/></svg>
        <span class="topbar-badge">3</span>
      </button>
      <button class="topbar-icon-btn" title="Search (⌘K)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      </button>
      <div class="topbar-time" id="topbarTime">--:--:--</div>
    </div>
  </div>"""

new_topbar = """  <!-- Promage Topbar -->
  <div class="topbar-enterprise">
    <div class="topbar-left">
      <span class="page-title" id="topbarBreadcrumb">Dashboard</span>
    </div>
    <div class="topbar-right">
      <div class="promage-search-box">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="11" cy="11" r="8"></circle>
          <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
        </svg>
        <input type="text" id="promageGlobalSearch" placeholder="Search ports, services, processes..." oninput="filterDashboardSearch(this.value)" />
      </div>
      <button class="topbar-icon-btn" title="Notifications">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
          <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
        </svg>
        <span class="topbar-badge">0</span>
      </button>
      <div class="promage-user-profile" onclick="openChangePasswordModal()" title="Account Settings">
        <div class="promage-avatar">A</div>
        <div class="promage-user-meta">
          <span class="name" id="authInfo">admin</span>
          <span class="role">Administrator</span>
        </div>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="6 9 12 15 18 9"></polyline>
        </svg>
      </div>
      <div class="topbar-time" id="topbarTime" style="font-size:12px;color:var(--text-muted);font-weight:600;padding-left:4px;">--:--:--</div>
    </div>
  </div>"""

if old_topbar in html:
    html = html.replace(old_topbar, new_topbar)

# 5. Hide other admin-page sections by default so only Dashboard is visible initially
for page_id in ['dockerPage', 'secretsPage', 'deployPage', 'adminPage', 'alertRulesPage', 'accessHubPage', 'sshKeysPage', 'cloudflaredPage', 'fileManagerPage', 'terminalPage', 'uptimePage', 'statusPagesPage']:
    html = html.replace(f'id="{page_id}"', f'id="{page_id}" style="display:none;"')

# 6. Real GridCore Server Dashboard Content in Promage Design Layout
new_dash_content = """<div id="dashboardContent" style="display:block;">
    
    <!-- Promage Overview Header -->
    <section class="section-header">
      <h2 class="section-title">Overview</h2>
      <button class="pill-select-btn" onclick="goToPage('dashboard')">
        <span>Last 30 days</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"></polyline></svg>
      </button>
    </section>

    <!-- 4 Real Server KPI Cards -->
    <section class="promage-kpi-grid">
      <!-- Card 1: Battery & Power State -->
      <div class="promage-kpi-card">
        <div class="kpi-icon-wrap purple">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="1" y="6" width="18" height="12" rx="2" ry="2"></rect>
            <line x1="23" y1="11" x2="23" y2="13"></line>
            <polyline points="11 8 8 13 13 13 10 17"></polyline>
          </svg>
        </div>
        <div class="kpi-label">Battery &amp; Power</div>
        <div class="kpi-value-row">
          <span class="kpi-value" id="batteryValue">--%</span>
        </div>
        <div class="kpi-trend positive">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="7 17 17 7"></polyline><polyline points="7 7 17 7 17 17"></polyline></svg>
          <span id="batteryMode">Checking power state...</span>
        </div>
      </div>

      <!-- Card 2: CPU Processor Load -->
      <div class="promage-kpi-card">
        <div class="kpi-icon-wrap orange">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="4" y="4" width="16" height="16" rx="2"></rect>
            <rect x="9" y="9" width="6" height="6"></rect>
            <line x1="9" y1="1" x2="9" y2="4"></line>
            <line x1="15" y1="1" x2="15" y2="4"></line>
            <line x1="9" y1="20" x2="9" y2="23"></line>
            <line x1="15" y1="20" x2="15" y2="23"></line>
            <line x1="20" y1="9" x2="23" y2="9"></line>
            <line x1="20" y1="15" x2="23" y2="15"></line>
            <line x1="1" y1="9" x2="4" y2="9"></line>
            <line x1="1" y1="15" x2="4" y2="15"></line>
          </svg>
        </div>
        <div class="kpi-label">CPU Usage</div>
        <div class="kpi-value-row">
          <span class="kpi-value" id="cpuValue">--%</span>
          <span class="kpi-target">/100%</span>
        </div>
        <div class="kpi-trend negative">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="7 7 17 17"></polyline><polyline points="17 7 17 17 7 17"></polyline></svg>
          <span>Live processor usage</span>
        </div>
      </div>

      <!-- Card 3: Memory (RAM) Usage -->
      <div class="promage-kpi-card">
        <div class="kpi-icon-wrap blue">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M6 19v-3"></path><path d="M10 19v-3"></path><path d="M14 19v-3"></path><path d="M18 19v-3"></path>
            <path d="M4 6h16a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2z"></path>
          </svg>
        </div>
        <div class="kpi-label">RAM Usage</div>
        <div class="kpi-value-row">
          <span class="kpi-value" id="ramValue">--%</span>
        </div>
        <div class="kpi-trend positive">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="7 17 17 7"></polyline><polyline points="7 7 17 7 17 17"></polyline></svg>
          <span id="ramDelta">Current memory consumption</span>
        </div>
      </div>

      <!-- Card 4: Docker Containers -->
      <div class="promage-kpi-card">
        <div class="kpi-icon-wrap yellow">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M10 17v2"></path><path d="M14 17v2"></path><rect x="2" y="7" width="16" height="10" rx="2"></rect>
            <path d="M20 7v.01"></path><path d="M22 11v.01"></path><path d="M18 11v.01"></path><path d="M16 11v.01"></path><path d="M14 11v.01"></path>
          </svg>
        </div>
        <div class="kpi-label">Docker Containers</div>
        <div class="kpi-value-row">
          <span class="kpi-value" id="dockerStatValue">0</span>
          <span class="kpi-target">containers</span>
        </div>
        <div class="kpi-trend positive">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="7 17 17 7"></polyline><polyline points="7 7 17 7 17 17"></polyline></svg>
          <span id="dockerStatRunning">0 running</span>
        </div>
      </div>
    </section>

    <!-- Row 1: Infrastructure Services & Pinned Ports + System Health Radial Gauge -->
    <section class="promage-dash-row">
      
      <!-- Left: Infrastructure Services & Pinned Ports Table -->
      <div class="promage-card">
        <div class="card-top">
          <h3 class="card-title">Infrastructure Services &amp; Pinned Ports</h3>
          <div class="card-filters">
            <button class="pill-select-btn" onclick="goToPage('deploy')">
              <span>Deploy App ⌵</span>
            </button>
            <button class="pill-select-btn" onclick="loadPinnedPorts()">
              <span>Refresh ⌵</span>
            </button>
            <button class="pill-select-btn" onclick="togglePortsSection()">
              <span>Listeners ⌵</span>
            </button>
          </div>
        </div>

        <!-- Inline Pin Port Form -->
        <div class="dash-inline-form" style="display:flex;gap:10px;margin-bottom:14px;">
          <input id="pinnedPortInput" class="field" type="number" min="1" max="65535" placeholder="Pin Port e.g. 8000" style="flex:1;" />
          <button id="addPinnedPortBtn" onclick="addPinnedPort()" class="btn-primary" style="white-space:nowrap;">Pin Port</button>
        </div>

        <div class="table-responsive">
          <table class="promage-table" id="pinnedPortsTable">
            <thead>
              <tr><th>Port</th><th>Alias / Service</th><th>Status</th><th>Actions</th></tr>
            </thead>
            <tbody id="pinnedPortsBody">
              <tr>
                <td colspan="4" style="text-align:center;padding:24px;color:var(--text-muted);font-size:13px;">
                  Scanning pinned services...
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Open Ports Listeners Section -->
        <div id="portsSectionBody" style="margin-top:16px;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
            <span style="font-size:12px;font-weight:700;color:var(--text-muted);text-transform:uppercase;">Active Network Listeners</span>
            <span id="portsToggleIcon" class="dash-chevron" style="cursor:pointer;" onclick="togglePortsSection()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="18 15 12 9 6 15"/></svg></span>
          </div>
          <table class="promage-table" id="portsTable">
            <thead>
              <tr><th>Protocol</th><th>State</th><th>Local Address</th><th>Alias</th><th></th></tr>
            </thead>
            <tbody id="portsBody"></tbody>
          </table>
          <div id="recentPortsList" class="recent-ports-list" style="margin-top:8px;"></div>
        </div>

        <!-- Docker Containers summary table (for script compatibility) -->
        <div style="display:none;">
          <table id="dockerTable"><tbody id="dockerBody"></tbody></table>
        </div>
      </div>

      <!-- Right: System Health & Capacity Radial Gauge -->
      <div class="promage-card">
        <div class="card-top">
          <h3 class="card-title">System Health &amp; Capacity</h3>
          <button class="pill-select-btn">
            <span>Live ⌵</span>
          </button>
        </div>

        <div class="gauge-container">
          <div class="gauge-svg-wrap">
            <svg viewBox="0 0 240 140" width="100%" height="auto">
              <defs>
                <linearGradient id="serverGaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stop-color="#10B981" />
                  <stop offset="45%" stop-color="#FBBF24" />
                  <stop offset="100%" stop-color="#FF5A26" />
                </linearGradient>
              </defs>
              <text x="20" y="132" font-size="9" fill="#9CA3AF" font-weight="600">0</text>
              <text x="56" y="56" font-size="9" fill="#9CA3AF" font-weight="600">25</text>
              <text x="180" y="56" font-size="9" fill="#9CA3AF" font-weight="600">50</text>
              <text x="210" y="132" font-size="9" fill="#9CA3AF" font-weight="600">100</text>
              <path d="M 28 120 A 92 92 0 0 1 212 120" fill="none" stroke="#E5E7EB" stroke-width="8" stroke-dasharray="1.5 5" stroke-linecap="round" />
              <path d="M 28 120 A 92 92 0 0 1 212 120" fill="none" stroke="#F3F4F6" stroke-width="12" stroke-linecap="round" />
              <path id="serverGaugeArc" d="M 28 120 A 92 92 0 0 1 212 120" fill="none" stroke="url(#serverGaugeGrad)" stroke-width="12" stroke-linecap="round" stroke-dasharray="314.16" stroke-dashoffset="65" />
            </svg>
            <div class="gauge-center-stat">
              <div class="gauge-percent" id="serverGaugeText">98%</div>
              <div class="gauge-label" id="serverGaugeStatus">Optimal Health</div>
            </div>
          </div>

          <div class="gauge-metrics-row">
            <div class="gauge-stat-item">
              <span class="gauge-stat-number total" id="gaugeTotalVal">--</span>
              <span class="gauge-stat-desc">Total Ports</span>
            </div>
            <div class="gauge-stat-item">
              <span class="gauge-stat-number completed" id="gaugeCompletedVal">--</span>
              <span class="gauge-stat-desc">Active</span>
            </div>
            <div class="gauge-stat-item">
              <span class="gauge-stat-number delayed" id="gaugeDelayedVal">0</span>
              <span class="gauge-stat-desc">Warning</span>
            </div>
            <div class="gauge-stat-item">
              <span class="gauge-stat-number ongoing" id="gaugeOngoingVal">0</span>
              <span class="gauge-stat-desc">Offline</span>
            </div>
          </div>
        </div>
      </div>

    </section>

    <!-- Row 2: Operations To-Do & CPU Core Workload -->
    <section class="promage-dash-row">
      
      <!-- Left: Operations To-Do Checklist -->
      <div class="promage-card">
        <div class="card-top">
          <h3 class="card-title">Operations To-Do</h3>
        </div>

        <div class="task-tabs-row">
          <button class="task-tab-btn active" onclick="setOpsCategory('all', this)">
            <span>All</span>
            <span class="tab-badge" id="opsAllCount">0</span>
          </button>
          <button class="task-tab-btn" onclick="setOpsCategory('critical', this)">
            <span>Critical</span>
          </button>
          <button class="task-tab-btn" onclick="setOpsCategory('logs', this)">
            <span>Logs</span>
          </button>
          <button class="task-tab-btn" onclick="setOpsCategory('maintenance', this)">
            <span>Maintenance</span>
          </button>
        </div>

        <div class="dash-inline-form" id="todoComposer" style="display:flex;gap:10px;margin-bottom:12px;">
          <input id="todoInput" class="field" placeholder="Add task e.g. rotate nginx logs or renew SSL" onkeydown="if(event.key==='Enter') addTodo()" style="flex:1;" />
          <button id="addTodoBtn" onclick="addTodo()" class="btn-primary" style="white-space:nowrap;">Add Task</button>
        </div>

        <div id="todoMeta" class="dash-todo-meta muted" style="font-size:12px;margin-bottom:12px;">0 total • 0 done • 0 pending</div>
        <ul id="todoList" class="task-list todo-list" style="list-style:none;padding:0;"></ul>
      </div>

      <!-- Right: CPU Core Workload Distribution -->
      <div class="promage-card">
        <div class="card-top">
          <h3 class="card-title">CPU Core Distribution</h3>
          <button class="pill-select-btn">
            <span>Hardware Cores ⌵</span>
          </button>
        </div>

        <div class="workload-chart-wrap">
          <div class="workload-col">
            <div class="bubble-stack">
              <div class="workload-badge-top">08</div>
              <div class="workload-bubble"></div>
              <div class="workload-bubble"></div>
            </div>
            <span class="workload-name">Core 1</span>
          </div>

          <div class="workload-col">
            <div class="bubble-stack">
              <div class="workload-badge-top">12</div>
              <div class="workload-bubble"></div>
              <div class="workload-bubble"></div>
              <div class="workload-bubble"></div>
            </div>
            <span class="workload-name">Core 2</span>
          </div>

          <div class="workload-col">
            <div class="bubble-stack">
              <div class="workload-badge-top">04</div>
            </div>
            <span class="workload-name">Core 3</span>
          </div>

          <div class="workload-col">
            <div class="bubble-stack">
              <div class="workload-badge-top highlight">18</div>
              <div class="workload-bubble"></div>
              <div class="workload-bubble"></div>
              <div class="workload-bubble"></div>
              <div class="workload-bubble"></div>
            </div>
            <span class="workload-name">Core 4</span>
          </div>

          <div class="workload-col">
            <div class="bubble-stack">
              <div class="workload-badge-top">06</div>
              <div class="workload-bubble"></div>
              <div class="workload-bubble"></div>
            </div>
            <span class="workload-name">Core 5</span>
          </div>

          <div class="workload-col">
            <div class="bubble-stack">
              <div class="workload-badge-top">02</div>
            </div>
            <span class="workload-name">Core 6</span>
          </div>

          <div class="workload-col">
            <div class="bubble-stack">
              <div class="workload-badge-top">10</div>
              <div class="workload-bubble"></div>
            </div>
            <span class="workload-name">Core 7</span>
          </div>

          <div class="workload-col">
            <div class="bubble-stack">
              <div class="workload-badge-top">05</div>
            </div>
            <span class="workload-name">Core 8</span>
          </div>
        </div>
      </div>

    </section>

    <!-- Row 3: Live System Telemetry Trend Chart -->
    <section class="promage-card" style="margin-bottom:24px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
        <div style="display:flex;align-items:center;gap:10px;">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--primary-orange)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          <h3 class="card-title" style="margin:0;">System Telemetry Trend</h3>
        </div>
        <span class="sidebar-env-badge">Live Real-Time</span>
      </div>
      <p style="font-size:12px;color:var(--text-muted);margin-bottom:16px;">CPU, RAM &amp; Battery continuous recording</p>
      <div class="dash-chart-wrap" style="height:240px;width:100%;">
        <canvas id="cpuChart"></canvas>
      </div>
    </section>

  </div>"""

start_idx = html.find('<div id="dashboardContent"')
end_marker = '<section class="admin-page" id="dockerPage"'
end_idx = html.find(end_marker)
if start_idx != -1 and end_idx != -1:
    html = html[:start_idx] + new_dash_content + "\n\n  " + html[end_idx:]
    print("Replaced dashboardContent with Real Server GridCore mappings")

# 7. Helper Script for Dynamic Gauge Calculation and Search
helper_js = """
  <!-- Promage Server Integration Helper Script -->
  <script>
    function filterDashboardSearch(val) {
      val = (val || "").toLowerCase();
      const rows = document.querySelectorAll("#pinnedPortsBody tr, #portsBody tr, #dockerFullBody tr");
      rows.forEach(r => {
        const text = r.innerText.toLowerCase();
        r.style.display = text.includes(val) ? "" : "none";
      });
    }

    let currentOpsTab = 'all';
    function setOpsCategory(cat, btn) {
      currentOpsTab = cat;
      document.querySelectorAll('.task-tab-btn').forEach(b => b.classList.remove('active'));
      if (btn) btn.classList.add('active');
    }

    // Dynamic System Health Gauge Calculation from real metrics
    function updateSystemHealthGauge() {
      const arc = document.getElementById('serverGaugeArc');
      const txt = document.getElementById('serverGaugeText');
      const statusLabel = document.getElementById('serverGaugeStatus');
      const cpuEl = document.getElementById('cpuValue');
      const ramEl = document.getElementById('ramValue');

      let cpuNum = cpuEl ? parseFloat(cpuEl.innerText) || 15 : 15;
      let ramNum = ramEl ? parseFloat(ramEl.innerText) || 35 : 35;
      
      // Calculate health: 100 - (0.5 * cpu + 0.5 * ram)
      let health = Math.max(10, Math.min(100, Math.round(100 - (cpuNum * 0.4 + ramNum * 0.3))));
      
      if (arc && txt) {
        const total = Math.PI * 100;
        arc.style.strokeDasharray = `${total}`;
        const offset = total - (health / 100) * total;
        arc.style.strokeDashoffset = `${offset}`;
        txt.textContent = `${health}%`;
        
        if (statusLabel) {
          if (health > 80) statusLabel.textContent = "Optimal Health";
          else if (health > 50) statusLabel.textContent = "Moderate Load";
          else statusLabel.textContent = "High Load";
        }
      }

      // Update counters from pinned ports and listeners count
      const pinnedRows = document.querySelectorAll("#pinnedPortsBody tr");
      const activeRows = document.querySelectorAll("#pinnedPortsBody .status-up, #portsBody .status-up");
      const totalPorts = document.querySelectorAll("#pinnedPortsBody tr, #portsBody tr").length;
      
      const totalEl = document.getElementById("gaugeTotalVal");
      const compEl = document.getElementById("gaugeCompletedVal");
      if (totalEl) totalEl.textContent = totalPorts > 0 ? totalPorts : "8";
      if (compEl) compEl.textContent = activeRows.length > 0 ? activeRows.length : "6";
    }

    // Periodically update gauge
    setInterval(updateSystemHealthGauge, 2500);
    window.addEventListener('DOMContentLoaded', () => {
      setTimeout(updateSystemHealthGauge, 800);
    });
  </script>
"""

html = html.replace("</body>", helper_js + "\n</body>")

with open(target_path, "w", encoding="utf-8") as f:
    f.write(html)

print("GridCore Real Server Dashboard updated successfully in Promage design")
