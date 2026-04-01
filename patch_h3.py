import re

with open('index.html', 'r', encoding='utf-8') as f:
    text = f.read()

replacements = {
    '<h3>Battery</h3>': '<h3 style="display:flex;align-items:center;gap:6px;"><i data-lucide="battery"></i> Battery</h3>',
    '<h3>CPU Usage</h3>': '<h3 style="display:flex;align-items:center;gap:6px;"><i data-lucide="cpu"></i> CPU Usage</h3>',
    '<h3>RAM Usage</h3>': '<h3 style="display:flex;align-items:center;gap:6px;"><i data-lucide="memory-stick"></i> RAM Usage</h3>',
    '<h3>CPU Trend</h3>': '<h3 style="display:flex;align-items:center;gap:6px;"><i data-lucide="activity"></i> CPU Trend</h3>',
    '<h3>Pinned Services</h3>': '<h3 style="display:flex;align-items:center;gap:6px;"><i data-lucide="server"></i> Pinned Services</h3>',
    '<h3>Open Ports</h3>': '<h3 style="display:flex;align-items:center;gap:6px;"><i data-lucide="network"></i> Open Ports</h3>',
    '<h3>Docker Containers</h3>': '<h3 style="display:flex;align-items:center;gap:6px;"><i data-lucide="box"></i> Docker Containers</h3>',
    '<h3>✅ Operations To-Do</h3>': '<h3 style="display:flex;align-items:center;gap:6px;"><i data-lucide="list-todo"></i> Operations To-Do</h3>',
    '<h3>Admin User Management</h3>': '<h3 style="display:flex;align-items:center;gap:6px;"><i data-lucide="shield"></i> Admin User Management</h3>',
    '<h3>Audit Logs</h3>': '<h3 style="display:flex;align-items:center;gap:6px;"><i data-lucide="scroll-text"></i> Audit Logs</h3>',
    '<h3>Alert Rules</h3>': '<h3 style="display:flex;align-items:center;gap:6px;"><i data-lucide="bell-ring"></i> Alert Rules</h3>',
    '<h3>Web Terminal</h3>': '<h3 style="display:flex;align-items:center;gap:6px;"><i data-lucide="terminal"></i> Web Terminal</h3>',
    '<h3>File Manager</h3>': '<h3 style="display:flex;align-items:center;gap:6px;"><i data-lucide="hard-drive"></i> File Manager</h3>',
    '<h3>🔐 Login Required</h3>': '<h3 style="display:flex;align-items:center;gap:6px;"><i data-lucide="lock"></i> Login Required</h3>',
    '<h3>🔑 File Permissions</h3>': '<h3 style="display:flex;align-items:center;gap:6px;"><i data-lucide="key"></i> File Permissions</h3>',
}

for old, new in replacements.items():
    text = text.replace(old, new)

with open('index.html', 'w', encoding='utf-8') as f:
    f.write(text)

