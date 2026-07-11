// File Manager & Explorer
    function setFileManagerEnvVaultMsg(message = "", isError = false) {
      const el = document.getElementById("fmEnvVaultMsg");
      if (!el) return;
      el.className = isError ? "error-text" : "info-text";
      el.innerText = message;
    }

    function updateFileManagerEnvKey(idx, val) {
      if (!fileManagerEnvVars[idx]) return;
      fileManagerEnvVars[idx].key = val;
    }

    function updateFileManagerEnvVal(idx, val) {
      if (!fileManagerEnvVars[idx]) return;
      fileManagerEnvVars[idx].value = val;
    }

    function addFileManagerEnvVariableRow() {
      const file = (document.getElementById("fmEnvProjectSelect")?.value || "").trim();
      if (!file) return alert("Please select an environment file first.");
      fileManagerEnvPath = file;
      fileManagerEnvVars.push({ key: "", value: "" });
      renderFileManagerEnvVault();
    }

    function removeFileManagerEnvRow(idx) {
      if (confirm("Delete this key-value pair?")) {
        fileManagerEnvVars.splice(idx, 1);
        renderFileManagerEnvVault();
      }
    }

    function renderFileManagerEnvVault() {
      const editor = document.getElementById("fmEnvVaultEditor");
      if (!editor) return;

      if (!fileManagerEnvVars.length) {
        editor.innerHTML = '<div class="muted">No valid KEY=VALUE entries found. You can add new variables below.</div>';
        return;
      }

      editor.innerHTML = fileManagerEnvVars.map((item, idx) => `
        <div style="display: flex; gap: 8px; align-items: center; background: var(--card-soft); padding: 10px; border-radius: 10px; border: 1px solid var(--border);">
          <input type="text" class="field" style="width: 230px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace;" value="${esc(item.key)}" oninput="updateFileManagerEnvKey(${idx}, this.value)" placeholder="KEY_NAME" />
          <span style="color: var(--muted);">=</span>
          <div style="position: relative; flex: 1;">
            <input type="password" id="fm_env_val_${idx}" class="field" style="width: 100%; padding-right: 48px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace;" value="${esc(item.value)}" oninput="updateFileManagerEnvVal(${idx}, this.value)" placeholder="Secret value..." />
            <button class="btn-neutral" style="position: absolute; right: 6px; top: 6px; padding: 6px; min-height: 0; box-shadow: none; background: transparent;" onclick="toggleEnvVisible('fm_env_val_${idx}')">
              <i data-lucide="eye" style="width: 18px; height: 18px; color: var(--muted);"></i>
            </button>
          </div>
          <button class="btn-danger" style="padding: 8px;" onclick="removeFileManagerEnvRow(${idx})"><i data-lucide="x" style="width:16px;height:16px;"></i></button>
        </div>
      `).join("");

      lucide.createIcons();
    }

    async function loadFileManagerEnvVault() {
      const file = (document.getElementById("fmEnvProjectSelect")?.value || "").trim();
      const editor = document.getElementById("fmEnvVaultEditor");
      if (!editor) return;

      if (!file) {
        fileManagerEnvPath = "";
        fileManagerEnvVars = [];
        editor.innerHTML = '<div class="muted">Select an environment file to manage its secrets.</div>';
        setFileManagerEnvVaultMsg("");
        return;
      }

      try {
        const res = await apiFetch("/files/read", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: file }),
        });

        const data = await res.json();
        fileManagerEnvPath = file;
        fileManagerEnvVars = parseEnvContent(data.content || "");
        renderFileManagerEnvVault();
        setFileManagerEnvVaultMsg(`Loaded ${fileManagerEnvVars.length} variables from ${file}`);
      } catch (e) {
        fileManagerEnvPath = file;
        fileManagerEnvVars = [];
        renderFileManagerEnvVault();
        setFileManagerEnvVaultMsg(e.message || "Failed to load environment file.", true);
      }
    }

    async function saveFileManagerEnvVault() {
      const file = fileManagerEnvPath || (document.getElementById("fmEnvProjectSelect")?.value || "").trim();
      if (!file) {
        setFileManagerEnvVaultMsg("Select an environment file first.", true);
        return;
      }

      const keyPattern = /^[A-Za-z_][A-Za-z0-9_]*$/;
      const lines = [];

      for (const row of fileManagerEnvVars) {
        const key = String(row.key || "").trim();
        if (!key) continue;
        if (!keyPattern.test(key)) {
          setFileManagerEnvVaultMsg(`Invalid env key: ${key}`, true);
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

        setFileManagerEnvVaultMsg(`Saved ${lines.length} variables to ${file}`);
      } catch (e) {
        setFileManagerEnvVaultMsg(e.message || "Failed to save environment file.", true);
      }
    }



    function renderBreadcrumb(path) {
      const breadcrumb = document.getElementById("fileBreadcrumb");
      const parts = path.split("/").filter(p => p);

      let html = '<span class="breadcrumb-item" onclick="browseFiles(\'/\')">' + FILE_ICONS["folder"] + ' root</span>';

      let buildPath = "";
      parts.forEach((part, idx) => {
        buildPath += "/" + part;
        const currentPath = buildPath;
        html += '<span class="breadcrumb-separator">›</span>';
        html += `<span class="breadcrumb-item" onclick="browseFiles('${currentPath}')">${esc(part)}</span>`;
      });

      breadcrumb.innerHTML = html;
    }

    async function browseFiles(path) {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      const requestedPath = path;
      const msg = document.getElementById("fileManagerMsg");
      msg.innerText = "";

      try {
        const res = await apiFetch(`/files/browse?path=${encodeURIComponent(requestedPath)}`);
        const data = await res.json();

        if (data.type === "file") {
          // It's a file, open editor
          await openFileEditor(requestedPath);
          return;
        }

        // It's a directory
        currentPath = data.path || requestedPath;
        lastDirectoryPath = currentPath;
        renderBreadcrumb(currentPath);
        renderFileList(data.items || []);
      } catch (e) {
        msg.innerText = e.message || "Failed to browse directory.";
      }
    }

    function renderFileList(items) {
      const gridView = document.getElementById("fileGridView");
      const listView = document.getElementById("fileListView");

      if (fileView === "grid") {
        renderGridView(items);
        gridView.style.display = "grid";
        listView.style.display = "none";
      } else {
        renderListView(items);
        gridView.style.display = "none";
        listView.style.display = "block";
      }
    }

    function renderGridView(items) {
      const gridView = document.getElementById("fileGridView");

      if (!items.length) {
        gridView.innerHTML = '<div class="muted" style="grid-column: 1/-1; text-align: center; padding: 40px;">Empty directory</div>';
        return;
      }

      gridView.innerHTML = items.map(item => {
        const icon = getFileIcon(item);
        const size = item.is_directory ? "Folder" : formatFileSize(item.size);
        const perms = item.permissions || "---";
        const DL = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
        const KEY = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>';
        const TRASH = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>';

        const downloadAction = item.is_directory
          ? `<button title="Download Folder" onclick="downloadFolder('${esc(item.path)}')">${DL}</button>`
          : `<button title="Download" onclick="downloadFile('${esc(item.path)}')">${DL}</button>`;

        return `
          <div class="file-item" onclick="handleFileClick('${esc(item.path)}', ${item.is_directory})" ondblclick="handleFileDoubleClick('${esc(item.path)}', ${item.is_directory})">
            <div class="file-item-actions" onclick="event.stopPropagation()">
              ${downloadAction}
              <button title="Permissions" onclick="openPermissionsModal('${esc(item.path)}', '${perms}')">${KEY}</button>
              <button title="Delete" onclick="deleteFileOrFolder('${esc(item.path)}', '${esc(item.name)}')">${TRASH}</button>
            </div>
            <div class="file-icon">${icon}</div>
            <div class="file-name">${esc(item.name)}</div>
            <div class="file-meta">${size} • ${perms}</div>
          </div>
        `;
      }).join("");
    }

    function renderListView(items) {
      const listView = document.getElementById("fileListView");

      if (!items.length) {
        listView.innerHTML = '<li class="muted" style="text-align: center; padding: 40px;">Empty directory</li>';
        return;
      }

      listView.innerHTML = items.map(item => {
        const icon = getFileIcon(item);
        const size = item.is_directory ? "Folder" : formatFileSize(item.size);
        const modified = new Date(item.modified * 1000).toLocaleString();
        const perms = item.permissions || "---";
        const DL = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
        const KEY = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>';
        const TRASH = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>';
        const FOLDER_OPEN = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 19a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h4l3 3h7a2 2 0 0 1 2 2v1M5 19l5-5 3 3 5-5"/></svg>';
        const EDIT = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';

        const downloadAction = item.is_directory
          ? `<button class="btn-outline" onclick="event.stopPropagation(); downloadFolder('${esc(item.path)}')" style="height:28px;width:28px;padding:0;">${DL}</button>`
          : `<button class="btn-outline" onclick="event.stopPropagation(); downloadFile('${esc(item.path)}')" style="height:28px;width:28px;padding:0;">${DL}</button>`;

        return `
          <li class="file-list-item" onclick="handleFileClick('${esc(item.path)}', ${item.is_directory})" ondblclick="handleFileDoubleClick('${esc(item.path)}', ${item.is_directory})">
            <div class="file-icon" style="font-size:1.2rem; margin:0;">${icon}</div>
            <div class="file-name">${esc(item.name)}</div>
            <div class="file-meta">${size}</div>
            <div class="file-meta">${modified}</div>
            <div class="file-meta">${perms}</div>
            <div style="display:flex;gap:4px;">
              ${downloadAction}
              <button class="btn-outline" onclick="event.stopPropagation(); openPermissionsModal('${esc(item.path)}', '${perms}')" style="height:28px;width:28px;padding:0;">${KEY}</button>
              <button class="btn-outline" onclick="event.stopPropagation(); ${item.is_directory ? 'browseFiles' : 'openFileEditor'}('${esc(item.path)}')" style="height:28px;padding:0 8px;font-size:0.75rem;">
                ${item.is_directory ? FOLDER_OPEN + ' Open' : EDIT + ' Edit'}
              </button>
              <button class="btn-danger" onclick="event.stopPropagation(); deleteFileOrFolder('${esc(item.path)}', '${esc(item.name)}')" style="height:28px;width:28px;padding:0;">${TRASH}</button>
            </div>
          </li>
        `;
      }).join("");
    }

    function handleFileClick(path, isDirectory) {
      // Single click - just select (could add selection highlight here)
    }

    function handleFileDoubleClick(path, isDirectory) {
      if (isDirectory) {
        browseFiles(path);
      } else {
        openFileEditor(path);
      }
    }

    function switchView(view) {
      fileView = view;
      document.getElementById("gridViewBtn").classList.toggle("active", view === "grid");
      document.getElementById("listViewBtn").classList.toggle("active", view === "list");
      browseFiles(currentPath);
    }

    function refreshCurrentDir() {
      browseFiles(currentPath);
    }

    function buildTerminalCdCommand(path) {
      const raw = String(path || "").replace(/[\r\n]+/g, " ").trim();
      if (!raw) return "";
      const escaped = raw
        .replace(/\\/g, "\\\\")
        .replace(/"/g, '\\"');
      return `cd "${escaped}"\r`;
    }

    function sendTerminalCd(tab, path) {
      if (!tab) return false;
      const cmd = buildTerminalCdCommand(path);
      if (!cmd) return false;
      sendTerminalMessage(tab, { type: "input", data: cmd });
      return true;
    }

    function applyPendingTerminalPath() {
      if (!pendingTerminalPath) return;

      const tab = terminalTabs.find((t) => t.id === activeTerminalTabId)
        || terminalTabs[terminalTabs.length - 1];
      if (!tab) return;

      const targetPath = pendingTerminalPath;
      if (tab.ws && tab.ws.readyState === WebSocket.OPEN) {
        if (sendTerminalCd(tab, targetPath)) {
          pendingTerminalPath = null;
        }
      } else {
        tab.pendingPath = targetPath;
        pendingTerminalPath = null;
      }
    }

    function openCurrentFolderInTerminal() {
      if (!hasRole("operator")) {
        alert("Operator or Admin role required.");
        return;
      }

      const targetPath = String(lastDirectoryPath || currentPath || "").trim();
      if (!targetPath) {
        alert("No folder selected.");
        return;
      }

      pendingTerminalPath = targetPath;
      goToPage("terminal");
    }

    async function openFileEditor(path) {
      const msg = document.getElementById("fileManagerMsg");
      msg.innerText = "";

      try {
        const res = await apiFetch("/files/read", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path }),
        });

        const data = await res.json();
        currentEditingFile = path;

        document.getElementById("editorTitle").innerText = "Edit File";
        document.getElementById("editorPath").innerText = path;
        document.getElementById("fileEditorContent").value = data.content || "";
        document.getElementById("fileEditorModal").style.display = "block";
      } catch (e) {
        msg.innerText = e.message || "Failed to read file.";
      }
    }

    function closeFileEditor() {
      document.getElementById("fileEditorModal").style.display = "none";
      currentEditingFile = null;
    }

    async function saveFileContent() {
      if (!currentEditingFile) {
        alert("No file is being edited.");
        return;
      }

      const content = document.getElementById("fileEditorContent").value;
      const msg = document.getElementById("fileManagerMsg");
      msg.innerText = "";

      try {
        await apiFetch("/files/write", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: currentEditingFile, content }),
        });

        msg.innerText = `File saved: ${currentEditingFile}`;
        closeFileEditor();
        browseFiles(currentPath);
      } catch (e) {
        alert(e.message || "Failed to save file.");
      }
    }

    async function deleteFileOrFolder(path, name) {
      if (!confirm(`Delete "${name}"?`)) {
        return;
      }

      const msg = document.getElementById("fileManagerMsg");
      msg.innerText = "";

      try {
        await apiFetch("/files/delete", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path }),
        });

        msg.innerText = `Deleted: ${name}`;
        browseFiles(currentPath);
      } catch (e) {
        msg.innerText = e.message || "Failed to delete.";
      }
    }

    async function createNewFile() {
      const fileName = prompt("Enter file name:");
      if (!fileName) return;

      const newPath = currentPath + "/" + fileName;
      const msg = document.getElementById("fileManagerMsg");
      msg.innerText = "";

      try {
        await apiFetch("/files/write", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: newPath, content: "" }),
        });

        msg.innerText = `Created file: ${fileName}`;
        browseFiles(currentPath);
      } catch (e) {
        msg.innerText = e.message || "Failed to create file.";
      }
    }

    async function createNewFolder() {
      const folderName = prompt("Enter folder name:");
      if (!folderName) return;

      const newPath = currentPath + "/" + folderName;
      const msg = document.getElementById("fileManagerMsg");
      msg.innerText = "";

      try {
        await apiFetch("/files/mkdir", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: newPath }),
        });

        msg.innerText = `Created folder: ${folderName}`;
        browseFiles(currentPath);
      } catch (e) {
        msg.innerText = e.message || "Failed to create folder.";
      }
    }

    function suggestCloneFolderName(repoUrl) {
      const cleaned = String(repoUrl || "").trim().replace(/\/+$/g, "");
      const tail = (cleaned.split("/").pop() || "repo-clone").replace(/\.git$/i, "");
      const sanitized = tail.replace(/[^a-zA-Z0-9._-]/g, "-").replace(/^[._-]+|[._-]+$/g, "");
      return sanitized || "repo-clone";
    }

    async function gitCloneRepo() {
      if (!hasRole("admin")) {
        alert("Admin role required.");
        return;
      }

      const repo_url = prompt("Enter repository URL (https://... or git@...):");
      if (!repo_url || !repo_url.trim()) return;

      const defaultFolder = suggestCloneFolderName(repo_url);
      const folderPrompt = prompt("Folder name (optional):", defaultFolder);
      if (folderPrompt === null) return;

      const folder_name = folderPrompt.trim();
      const msg = document.getElementById("fileManagerMsg");
      msg.innerText = "Cloning repository... this may take a moment.";

      try {
        const res = await apiFetch("/files/git-clone", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            path: currentPath,
            repo_url: repo_url.trim(),
            folder_name: folder_name || null,
          }),
        });

        const data = await res.json();
        msg.innerText = `Repository cloned: ${data.folder_name}`;
        await browseFiles(currentPath);
      } catch (e) {
        msg.innerText = e.message || "Failed to clone repository.";
      }
    }

    function downloadFile(path) {
      window.open(`/files/download?path=${encodeURIComponent(path)}`, '_blank');
    }

    function downloadFolder(path) {
      window.open(`/files/download-folder?path=${encodeURIComponent(path)}`, '_blank');
    }

    async function uploadSelectedFile(event) {
      const fileInput = event.target;
      if (!fileInput.files.length) return;
      
      const file = fileInput.files[0];
      const msg = document.getElementById("fileManagerMsg");
      msg.innerText = `Uploading ${file.name}...`;

      const formData = new FormData();
      formData.append("file", file);

      try {
        const response = await fetch(`/files/upload?path=${encodeURIComponent(currentPath)}`, {
          method: "POST",
          body: formData,
          credentials: "include"
        });
        
        if (!response.ok) {
          const err = await response.json();
          throw new Error(err.detail || "Upload failed");
        }

        msg.innerText = `Uploaded file: ${file.name}`;
        browseFiles(currentPath);
      } catch (e) {
        msg.innerText = e.message;
      }

      fileInput.value = ""; // Reset input
    }

    async function uploadSelectedFolder(event) {
      const fileInput = event.target;
      if (!fileInput.files.length) return;

      const files = Array.from(fileInput.files);
      await uploadFilesWithProgress(files, true);
      fileInput.value = "";
    }

    async function uploadFilesWithProgress(files, isFolder) {
      const paths = isFolder ? files.map(f => f.webkitRelativePath || f.name) : files.map(f => f.name);
      return uploadFilesWithPaths(files, paths);
    }

    async function uploadFilesWithPaths(files, paths) {
      const progressArea = document.getElementById("uploadProgressArea");
      const progressBar = document.getElementById("uploadProgressBar");
      const progressText = document.getElementById("uploadProgressText");
      const progressCount = document.getElementById("uploadProgressCount");
      const progressDetail = document.getElementById("uploadProgressDetail");
      const msg = document.getElementById("fileManagerMsg");

      progressArea.style.display = "block";
      progressBar.style.width = "0%";
      progressText.textContent = `Uploading ${files.length} file${files.length > 1 ? 's' : ''}...`;
      progressCount.textContent = `0 / ${files.length}`;
      progressDetail.textContent = "";
      msg.innerText = "";

      const BATCH_SIZE = 20;
      let uploaded = 0;
      let errors = 0;

      for (let i = 0; i < files.length; i += BATCH_SIZE) {
        const batchFiles = files.slice(i, i + BATCH_SIZE);
        const batchPaths = paths.slice(i, i + BATCH_SIZE);
        const formData = new FormData();

        batchFiles.forEach((f, idx) => {
          formData.append("files", f);
          formData.append("paths", batchPaths[idx]);
        });

        try {
          const response = await fetch(`/files/upload-folder?path=${encodeURIComponent(currentPath)}`, {
            method: "POST",
            body: formData,
            credentials: "include"
          });

          if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || "Upload failed");
          }

          const result = await response.json();
          uploaded += result.uploaded || 0;
          errors += result.errors || 0;
        } catch (e) {
          errors += batchFiles.length;
          progressDetail.textContent = `Error: ${e.message}`;
        }

        const done = Math.min(i + BATCH_SIZE, files.length);
        const pct = Math.round((done / files.length) * 100);
        progressBar.style.width = pct + "%";
        progressCount.textContent = `${done} / ${files.length}`;
      }

      progressBar.style.width = "100%";
      progressText.textContent = `Upload complete`;
      progressCount.textContent = `${uploaded} uploaded, ${errors} failed`;
      msg.innerText = `Uploaded ${uploaded} file(s) to ${currentPath}${errors ? `, ${errors} failed` : ""}`;
      browseFiles(currentPath);

      setTimeout(() => { progressArea.style.display = "none"; }, 4000);
    }

    (function initDropZone() {
      const fm = document.getElementById("fileManagerPage");
      if (!fm) return;

      let dragCounter = 0;

      fm.addEventListener("dragenter", (e) => {
        e.preventDefault();
        dragCounter++;
        const dz = document.getElementById("fileDropZone");
        dz.style.display = "flex";
      });

      fm.addEventListener("dragleave", (e) => {
        e.preventDefault();
        dragCounter--;
        if (dragCounter <= 0) {
          dragCounter = 0;
          document.getElementById("fileDropZone").style.display = "none";
        }
      });

      fm.addEventListener("dragover", (e) => {
        e.preventDefault();
      });

      fm.addEventListener("drop", async (e) => {
        e.preventDefault();
        dragCounter = 0;
        document.getElementById("fileDropZone").style.display = "none";

        const items = e.dataTransfer.items;
        if (!items || !items.length) return;

        const allFiles = [];
        const allPaths = [];

        async function traverseEntry(entry, basePath) {
          if (entry.isFile) {
            const file = await new Promise((resolve) => entry.file(resolve));
            allFiles.push(file);
            allPaths.push(basePath + file.name);
          } else if (entry.isDirectory) {
            const reader = entry.createReader();
            const entries = await new Promise((resolve) => {
              const batch = [];
              function readBatch() {
                reader.readEntries((results) => {
                  if (results.length === 0) {
                    resolve(batch);
                  } else {
                    batch.push(...results);
                    readBatch();
                  }
                });
              }
              readBatch();
            });
            for (const child of entries) {
              await traverseEntry(child, basePath + entry.name + "/");
            }
          }
        }

        for (let i = 0; i < items.length; i++) {
          const entry = items[i].webkitGetAsEntry ? items[i].webkitGetAsEntry() : null;
          if (entry) {
            await traverseEntry(entry, "");
          } else {
            const file = items[i].getAsFile();
            if (file) {
              allFiles.push(file);
              allPaths.push(file.name);
            }
          }
        }

        if (allFiles.length > 0) {
          await uploadFilesWithPaths(allFiles, allPaths);
        }
      });
    })();

    let currentPermsFile = null;

    function openPermissionsModal(path, currentOctal) {
      currentPermsFile = path;
      document.getElementById("permsFilePath").innerText = path;
      
      // Parse octal (e.g. "644")
      const octalStr = currentOctal && currentOctal.length === 3 ? currentOctal : "644";
      const userStr = parseInt(octalStr[0], 8).toString(2).padStart(3, '0');
      const groupStr = parseInt(octalStr[1], 8).toString(2).padStart(3, '0');
      const otherStr = parseInt(octalStr[2], 8).toString(2).padStart(3, '0');

      document.getElementById("perm_u_r").checked = userStr[0] === '1';
      document.getElementById("perm_u_w").checked = userStr[1] === '1';
      document.getElementById("perm_u_x").checked = userStr[2] === '1';

      document.getElementById("perm_g_r").checked = groupStr[0] === '1';
      document.getElementById("perm_g_w").checked = groupStr[1] === '1';
      document.getElementById("perm_g_x").checked = groupStr[2] === '1';

      document.getElementById("perm_o_r").checked = otherStr[0] === '1';
      document.getElementById("perm_o_w").checked = otherStr[1] === '1';
      document.getElementById("perm_o_x").checked = otherStr[2] === '1';

      updatePermsPreview();
      document.getElementById("permissionsModal").style.display = "flex";
    }

    function closePermissionsModal() {
      document.getElementById("permissionsModal").style.display = "none";
      currentPermsFile = null;
    }

    function updatePermsPreview() {
      const u = (document.getElementById("perm_u_r").checked ? 4 : 0) +
                (document.getElementById("perm_u_w").checked ? 2 : 0) +
                (document.getElementById("perm_u_x").checked ? 1 : 0);
      const g = (document.getElementById("perm_g_r").checked ? 4 : 0) +
                (document.getElementById("perm_g_w").checked ? 2 : 0) +
                (document.getElementById("perm_g_x").checked ? 1 : 0);
      const o = (document.getElementById("perm_o_r").checked ? 4 : 0) +
                (document.getElementById("perm_o_w").checked ? 2 : 0) +
                (document.getElementById("perm_o_x").checked ? 1 : 0);
      
      document.getElementById("permsOctalPreview").innerText = `${u}${g}${o}`;
    }

    // Attach listeners to all checkboxes
    document.querySelectorAll('#permissionsBox input[type="checkbox"]').forEach(cb => {
      cb.addEventListener('change', updatePermsPreview);
    });

    async function savePermissions() {
      if (!currentPermsFile) return;
      const perms = document.getElementById("permsOctalPreview").innerText;
      
      try {
        await apiFetch("/files/chmod", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: currentPermsFile, permissions: perms }),
        });
        
        closePermissionsModal();
        browseFiles(currentPath);
      } catch (e) {
        alert(e.message || "Failed to update permissions.");
      }
    }


// Expose to window
window.setFileManagerEnvVaultMsg = setFileManagerEnvVaultMsg;
window.updateFileManagerEnvKey = updateFileManagerEnvKey;
window.updateFileManagerEnvVal = updateFileManagerEnvVal;
window.addFileManagerEnvVariableRow = addFileManagerEnvVariableRow;
window.removeFileManagerEnvRow = removeFileManagerEnvRow;
window.renderFileManagerEnvVault = renderFileManagerEnvVault;
window.loadFileManagerEnvVault = loadFileManagerEnvVault;
window.saveFileManagerEnvVault = saveFileManagerEnvVault;
window.renderBreadcrumb = renderBreadcrumb;
window.browseFiles = browseFiles;
window.renderFileList = renderFileList;
window.renderGridView = renderGridView;
window.renderListView = renderListView;
window.handleFileClick = handleFileClick;
window.handleFileDoubleClick = handleFileDoubleClick;
window.switchView = switchView;
window.refreshCurrentDir = refreshCurrentDir;
window.buildTerminalCdCommand = buildTerminalCdCommand;
window.sendTerminalCd = sendTerminalCd;
window.applyPendingTerminalPath = applyPendingTerminalPath;
window.openCurrentFolderInTerminal = openCurrentFolderInTerminal;
window.openFileEditor = openFileEditor;
window.closeFileEditor = closeFileEditor;
window.saveFileContent = saveFileContent;
window.deleteFileOrFolder = deleteFileOrFolder;
window.createNewFile = createNewFile;
window.createNewFolder = createNewFolder;
window.suggestCloneFolderName = suggestCloneFolderName;
window.gitCloneRepo = gitCloneRepo;
window.downloadFile = downloadFile;
window.downloadFolder = downloadFolder;
window.uploadSelectedFile = uploadSelectedFile;
window.uploadSelectedFolder = uploadSelectedFolder;
window.uploadFilesWithProgress = uploadFilesWithProgress;
window.uploadFilesWithPaths = uploadFilesWithPaths;
window.openPermissionsModal = openPermissionsModal;
window.closePermissionsModal = closePermissionsModal;
window.updatePermsPreview = updatePermsPreview;
window.savePermissions = savePermissions;
