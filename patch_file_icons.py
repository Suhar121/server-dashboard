import re

with open('index.html', 'r', encoding='utf-8') as f:
    text = f.read()

# Replace file icons dict
text = text.replace(
    '"md": "📝", "txt": "📄", "log": "📊", "sh": "⚙️", "env": "🔐",',
    '"md": "file-text", "txt": "file", "log": "bar-chart", "sh": "settings", "env": "lock",'
)

text = text.replace(
    'const icon = item.is_dir ? "📁" : (extMap[ext] || "📄");',
    'const icon = item.is_dir ? "folder" : (extMap[ext] || "file");'
)

# And render them as lucide icons
text = text.replace(
    '<div class="file-icon">${icon}</div>',
    '<div class="file-icon"><i data-lucide="${icon}"></i></div>'
)

text = text.replace(
    '<div class="file-icon" style="font-size: 1.2rem; margin:0;">${icon}</div>',
    '<div class="file-icon" style="font-size: 1.2rem; margin:0; display:flex;"><i data-lucide="${icon}"></i></div>'
)

# Replace Permissions Keys
text = text.replace('>🔑</button>', '><i data-lucide="key" style="width:14px;height:14px;"></i></button>')

# Add lucide render step after rendering file manager
text = text.replace(
    "document.getElementById('fileGrid').innerHTML = listHtml;",
    "document.getElementById('fileGrid').innerHTML = listHtml;\nlucide.createIcons();"
)

with open('index.html', 'w', encoding='utf-8') as f:
    f.write(text)

