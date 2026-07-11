// Utility and Helper Functions
    const FILE_ICONS = {
      "folder": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"/></svg>',
      "file-code": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
      "file-text": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
      "file": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
      "image": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>',
      "terminal": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/></svg>',
      "lock": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
      "database": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
      "archive": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5" rx="2"/><line x1="10" y1="12" x2="14" y2="12"/></svg>',
      "palette": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="13.5" cy="6.5" r=".5"/><circle cx="17.5" cy="10.5" r=".5"/><circle cx="8.5" cy="7.5" r=".5"/><circle cx="6.5" cy="12.5" r=".5"/><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.93 0 1.5-.67 1.5-1.5 0-.39-.15-.74-.39-1.01-.23-.26-.38-.61-.38-1 0-.83.67-1.5 1.5-1.5H16c3.31 0 6-2.69 6-6 0-4.42-4.5-8-10-8z"/></svg>',
    };

    async function apiFetch(url, options = {}, opts = {}) {
      const res = await fetch(url, { credentials: "include", ...options });

      if (res.status === 401) {
        if (!opts.silent) {
          showLoginPage("Session expired. Please log in again.");
        }
        throw new Error("Unauthorized");
      }

      if (res.status === 403) {
        const err = await res.json().catch(() => ({ detail: "Forbidden" }));
        throw new Error(err.detail || "Forbidden");
      }

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `Request failed (${res.status})` }));
        throw new Error(err.detail || `Request failed (${res.status})`);
      }

      return res;
    }

    function esc(text) {
      return String(text)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }

    function formatDuration(ms) {
      if (!ms || ms < 0) return "0s";
      const seconds = Math.floor(ms / 1000);
      const m = Math.floor(seconds / 60);
      const h = Math.floor(m / 60);
      const d = Math.floor(h / 24);

      if (d > 0) return `${d}d ${h % 24}h`;
      if (h > 0) return `${h}h ${m % 60}m`;
      if (m > 0) return `${m}m ${seconds % 60}s`;
      return `${seconds}s`;
    }

    function formatBytes(bytes) {
      if (bytes === 0) return "0 B";
      const k = 1024;
      const sizes = ["B", "KB", "MB", "GB", "TB"];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }

    // --- Secrets Vault logic ---
    function getFileIcon(item) {
      if (item.is_directory) return FILE_ICONS["folder"] || "📁";
      const ext = item.name.split(".").pop().toLowerCase();
      const iconMap = {
        "js": "file-code", "py": "file-code", "html": "file-code", "css": "palette", "json": "file-code",
        "md": "file-text", "txt": "file-text", "log": "file-text", "sh": "terminal", "env": "lock",
        "jpg": "image", "png": "image", "gif": "image", "svg": "palette",
        "zip": "archive", "tar": "archive", "gz": "archive", "pdf": "file-text", "db": "database"
      };
      return FILE_ICONS[iconMap[ext]] || FILE_ICONS["file"];
    }

    function formatFileSize(bytes) {
      if (bytes < 1024) return bytes + " B";
      if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
      if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + " MB";
      return (bytes / 1073741824).toFixed(1) + " GB";
    }


// Expose utilities to window
window.apiFetch = apiFetch;
window.esc = esc;
window.formatDuration = formatDuration;
window.formatBytes = formatBytes;
window.getFileIcon = getFileIcon;
window.formatFileSize = formatFileSize;
window.FILE_ICONS = FILE_ICONS;
