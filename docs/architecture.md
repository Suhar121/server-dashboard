# GridCore Architecture Guide

This document describes the design patterns, code structure, and communication protocols of the GridCore Server Dashboard.

---

## 1. Project Restructuring Overview

GridCore's codebase is split into two physical directories to isolate backend code from frontend interface files while remaining buildless and lightweight:

```text
SERVER-DASHBOARD/
├── backend/                    # Python FastAPI application root
│   ├── main.py                 # Core FastAPI entrypoint & lifecycles
│   ├── config.py               # Shared backend configurations & state caches
│   ├── database.py             # SQLite DB connections, schema, & helpers
│   ├── battery.py              # Standalone battery alert checker
│   ├── routers/                # Decoupled backend API endpoints
│   └── ai/                     # Standalone AI agent logic
│
├── frontend/                   # UI Single Page Application root
│   ├── index.html              # Main SPA layout structure
│   └── static/                 # Static CSS stylesheets, modular JS files
│
└── tests/                      # Alert and notification test suites
```

---

## 2. Backend Design

The backend uses a modular [FastAPI](https://fastapi.tiangolo.com/) setup backed by a local [SQLite](https://www.sqlite.org/) database.

### Core Entrypoint (`backend/main.py`)
- Initializes the FastAPI app with a dynamic `sys.path` injection that adds `backend/` as a primary module search path.
- Configures global lifecycles (DB schemas creation, default admin seeding, in-memory session boots, and AI configurations).
- Mounts the `frontend/static` directory to serve JS modules, stylesheets, and assets.
- Mounts all modular API routers using `app.include_router()`.

### Shared Configuration & State Cache (`backend/config.py`)
- Centralizes all environment configuration values (e.g., ports, timeout thresholds, database paths, and API keys).
- Stores in-memory global state dictionaries (such as `active_sessions` and alert counters). To preserve this state across multiple modular router modules, they are housed here and imported by reference.

### SQLite Database Layer (`backend/database.py`)
- Coordinates connection pool mappings to `users.db`.
- Standardizes SQLite schema definitions and upgrades (e.g., user tables, alert rules, PM2 pinned services, Cloudflared ingress routes, and deployment pipeline logs).
- Consolidates all model-specific CRUD query helpers (e.g., `create_user_record`, `get_app_template`, `delete_pinned_service`).

### Modular Endpoints (`backend/routers/`)
All endpoints are grouped logically inside APIRouter modules:
- `auth.py`: Cookie-based session validation and user account lifecycle.
- `metrics.py`: System resource metrics check, open ports scanner, and port processes control.
- `docker_manager.py`: Docker CLI integrations, logs, and container alerts.
- `pm2_manager.py`: PM2 daemon control, apps deployer, and real-time logs WS channels.
- `file_manager.py`: Path traversal safety guards, file system CRUD, downloads, uploads, and git clones.
- `terminal.py`: Websocket channel connecting frontend terminals to local PTY shell forks.
- `admin.py`: Audit logging, rule configurations, SSH keys deployments, CF routes, and todos.
- `ai_chat.py`:nvidia or Gemini AI chat streaming integrations.
- `deploy.py`: Docker-compose templates, project scanner detection engine, custom deployments, and GitHub deployment pipelines.

---

## 3. Frontend Design

The frontend is a lightweight Single Page Application (SPA) designed to be served instantly by the browser **without any compile-time or build steps** (such as Node.js, Webpack, or npm).

### Native ES6 Javascript Modules
Javascript files reside in `frontend/static/js/` and are loaded using standard `<script type="module">` tags. This isolates variable scopes and permits clean imports/exports.

#### Centralized Communication & Utilities (`utils.js`)
- Houses base fetch wrappers (like `apiFetch`) that standardize error handling, loading states, alert modals, and cookie parsing.

#### Global Variable Sharing (Declarations in `index.html`)
Because strict mode is enforced inside ES6 modules, global state variables (e.g., `currentUser`, `activeTerminals`, `dockerChart`) are declared using `var` inside a standard script tag in `index.html` before module imports occur. This allows JS modules to read and update these global references without throwing strict-mode `ReferenceError`.

#### Event Callback Exposure
Browser callbacks (such as `<button onclick="pruneDocker()">`) resolve events in the global window scope. Because ES6 modules hide internal functions from the global namespace, each module explicitly exposes its public interactive functions:
```javascript
// At the bottom of static/js/docker.js
window.pruneDocker = pruneDocker;
window.startContainer = startContainer;
```

#### Client Routing & App Orchestration (`app.js`)
- Coordinates page boot sequences (authentication checks, theme loader).
- Listens to navigation bar events and manages section toggle flows (tab router).
- Configures live polling timers to refresh metrics and alert badges dynamically.

---

## 4. Testing

Automated tests are kept inside the `tests/` directory and run using `pytest`. Test scripts are written to mock backend functions and configurations to ensure system transitions, Telegram alerts, and port checks are fully validated before deployment.
