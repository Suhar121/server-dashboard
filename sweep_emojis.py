import re

with open('index.html', 'r', encoding='utf-8') as f:
    text = f.read()

repls = {
    '📁 root': '<i data-lucide="folder" style="width:14px;height:14px;display:inline-block;vertical-align:middle;"></i> root',
    '📄 New File': '<div style="display:flex;align-items:center;gap:6px;"><i data-lucide="file-plus" style="width:16px;height:16px;"></i> New File</div>',
    '📁 New Folder': '<div style="display:flex;align-items:center;gap:6px;"><i data-lucide="folder-plus" style="width:16px;height:16px;"></i> New Folder</div>',
    '⬆️ Upload File': '<div style="display:flex;align-items:center;gap:6px;"><i data-lucide="upload" style="width:16px;height:16px;"></i> Upload File</div>',
    
    'if (item.is_directory) return "📁";': 'if (item.is_directory) return "folder";',
    'return iconMap[ext] || "📄";': 'return iconMap[ext] || "file";',
    '"jpg": "🖼️", "png": "🖼️", "gif": "🖼️", "svg": "🎨",': '"jpg": "image", "png": "image", "gif": "image", "svg": "palette",',
    
    '>⬇️</button>': '><i data-lucide="download" style="width:14px;height:14px;"></i></button>',
    '>🗑️</button>': '><i data-lucide="trash-2" style="width:14px;height:14px;"></i></button>',
    
    "📂 Open": '<div style=\"display:flex;align-items:center;gap:6px;\"><i data-lucide=\"folder-open\" style=\"width:14px;height:14px;\"></i> Open</div>',
    "✏️ Edit": '<div style=\"display:flex;align-items:center;gap:6px;\"><i data-lucide=\"edit-2\" style=\"width:14px;height:14px;\"></i> Edit</div>',
}

for old, new in repls.items():
    text = text.replace(old, new)


with open('index.html', 'w', encoding='utf-8') as f:
    f.write(text)

