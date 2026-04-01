import re

with open('index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add lucide script
if 'lucide.min.js' not in content and 'lucide@latest' not in content:
    content = content.replace('</head>', '  <script src="https://unpkg.com/lucide@latest"></script>\n</head>')

# 2. Add data-theme="dark" support to CSS
dark_theme_css = """
    :root[data-theme="dark"] {
      --bg: #0f1219;
      --bg-grad: radial-gradient(circle at 15% 10%, #171b26 0%, #0f1219 45%, #131722 100%);
      --card: rgba(23, 27, 38, 0.88);
      --card-soft: #1c212e;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --ok: #22c55e;
      --bad: #ef4444;
      --brand: #3b82f6;
      --brand-soft: rgba(59, 130, 246, 0.2);
      --border: rgba(255, 255, 255, 0.1);
      --shadow-sm: 0 6px 20px rgba(0, 0, 0, 0.3);
      --shadow-md: 0 14px 36px rgba(0, 0, 0, 0.4);
    }
"""
if '[data-theme="dark"]' not in content:
    content = content.replace('    * { box-sizing: border-box; }', dark_theme_css + '\n    * { box-sizing: border-box; }')

# 3. Add icon toggles and switchers
# In Topbar
if 'id="themeToggle"' not in content:
    topbar_html = """    <div class="auth-badge">
      <button id="themeToggle" class="btn-neutral" onclick="toggleTheme()" style="background:transparent;color:var(--text);box-shadow:none;border:none;padding:4px;display:flex;align-items:center;">
        <i data-lucide="moon" id="themeIcon"></i>
      </button>"""
    content = content.replace('    <div class="auth-badge">', topbar_html)

# 4. Convert menu items
replaces = {
    '<h3>☰ Menu</h3>': '<h3><i data-lucide="menu"></i> Menu</h3>',
    '<button class="menu-btn" onclick="openMenu()">☰</button>': '<button class="menu-btn" onclick="openMenu()" style="display:flex;align-items:center;justify-content:center;"><i data-lucide="menu"></i></button>',
    'onclick="goToPage(\'dashboard\')">Dashboard</button>': 'onclick="goToPage(\'dashboard\')" style="display:flex;align-items:center;gap:8px;"><i data-lucide="layout-dashboard"></i> Dashboard</button>',
    'onclick="goToPage(\'admin\')">Admin Users</button>': 'onclick="goToPage(\'admin\')" style="display:flex;align-items:center;gap:8px;"><i data-lucide="users"></i> Admin Users</button>',
    'onclick="goToPage(\'audit-logs\')">Audit Logs</button>': 'onclick="goToPage(\'audit-logs\')" style="display:flex;align-items:center;gap:8px;"><i data-lucide="clipboard-list"></i> Audit Logs</button>',
    'onclick="goToPage(\'alert-rules\')">Alert Rules</button>': 'onclick="goToPage(\'alert-rules\')" style="display:flex;align-items:center;gap:8px;"><i data-lucide="bell"></i> Alert Rules</button>',
    'onclick="goToPage(\'file-manager\')">File Manager</button>': 'onclick="goToPage(\'file-manager\')" style="display:flex;align-items:center;gap:8px;"><i data-lucide="folder-tree"></i> File Manager</button>',
    'onclick="goToPage(\'terminal\')">Web Terminal</button>': 'onclick="goToPage(\'terminal\')" style="display:flex;align-items:center;gap:8px;"><i data-lucide="terminal-square"></i> Web Terminal</button>',
}
for k, v in replaces.items():
    content = content.replace(k, v)


# 5. Fix Javascript Initialization
js_init = """
  <script>
    // Theme setup
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);

    function toggleTheme() {
      const current = document.documentElement.getAttribute('data-theme');
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
      
      const themeIcon = document.getElementById('themeIcon');
      if (themeIcon) {
        themeIcon.setAttribute('data-lucide', next === 'dark' ? 'sun' : 'moon');
        lucide.createIcons();
      }
      
      if (typeof updateChartColors === 'function') {
        updateChartColors(next);
      }
    }

    document.addEventListener("DOMContentLoaded", () => {
      lucide.createIcons();
      const current = document.documentElement.getAttribute('data-theme');
      const themeIcon = document.getElementById('themeIcon');
      if (themeIcon) themeIcon.setAttribute('data-lucide', current === 'dark' ? 'sun' : 'moon');
      lucide.createIcons();
    });
"""

if 'savedTheme' not in content:
    content = content.replace('<script>', js_init, 1)


# Write back
with open('index.html', 'w', encoding='utf-8') as f:
    f.write(content)

