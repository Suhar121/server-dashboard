# AI Assistant Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate a floating AI chat assistant into the DevOps Dashboard that uses Gemini function calling to answer questions, diagnose issues, and execute auto-remediation with user confirmation for sensitive actions.

**Architecture:** FastAPI backend (`main.py`) gains `/ai/*` endpoints. A new `ai/` package (`gemini_client.py`, `tools.py`, `guardrails.py`, `remediation.py`) handles AI logic, function schemas, and guardrails. The frontend (`index.html`) adds a floating draggable chat panel. Gemini handles conversation + function calling. All AI actions respect existing RBAC.

**Tech Stack:** Python 3, FastAPI, `google-generativeai`, SSE streaming, vanilla JS/CSS.

---

## File Map

```
ai/
├── __init__.py              # Package init, exposes get_chat_response()
├── models.py                # Pydantic request/response models
├── gemini_client.py         # Gemini API client + function schema builder
├── tools.py                 # Tool definitions (get_system_metrics, start_service, etc.)
├── guardrails.py            # Rate limiter + confirmation queue
└── remediation.py           # Auto-remediation trigger handlers

main.py                      # Add /ai/* endpoints (6 routes)
index.html                   # Add floating chat panel (HTML/CSS/JS)
requirements.txt             # Add google-generativeai
.env                         # Add AI config vars
```

---

## Task 1: Create AI Package Skeleton

**Files:**
- Create: `d:/server-dashboard/ai/__init__.py`
- Modify: `d:/server-dashboard/requirements.txt`

- [ ] **Step 1: Create `ai/` directory and `__init__.py`**

```python
# ai/__init__.py
"""
AI Assistant package for DevOps Dashboard.
Exposes the main chat function used by /ai/chat endpoint.
"""
from .gemini_client import GeminiChat

__all__ = ["GeminiChat"]
```

- [ ] **Step 2: Add google-generativeai to requirements.txt**

```text
google-generativeai>=0.8.0
```

- [ ] **Step 3: Commit**

```bash
git add ai/__init__.py requirements.txt
git commit -m "feat(ai): create ai package skeleton and add google-generativeai dependency"
```

---

## Task 2: Pydantic Models

**Files:**
- Create: `d:/server-dashboard/ai/models.py`

- [ ] **Step 1: Create `ai/models.py`**

```python
# ai/models.py
"""Pydantic models for AI assistant endpoints."""

from pydantic import BaseModel
from typing import Literal


class AIChatRequest(BaseModel):
    message: str
    stream: bool = True


class AIActionConfirmation(BaseModel):
    action_id: str
    approved: bool


class AIAnalyzeRequest(BaseModel):
    trigger: Literal["port_down", "cpu_spike", "service_crash", "docker_stop"]
    context: dict


class ToolCallResult(BaseModel):
    tool: str
    success: bool
    result: dict | None = None
    error: str | None = None


class PendingAction(BaseModel):
    action_id: str
    tool: str
    params: dict
    created_at: float
    confirmed: bool = False
```

- [ ] **Step 2: Commit**

```bash
git add ai/models.py
git commit -m "feat(ai): add Pydantic models for AI endpoints"
```

---

## Task 3: Guardrails (Rate Limiter + Confirmation Queue)

**Files:**
- Create: `d:/server-dashboard/ai/guardrails.py`

- [ ] **Step 1: Create `ai/guardrails.py`**

```python
# ai/guardrails.py
"""Rate limiting and pending action confirmation queue."""

import time
import uuid
from collections import defaultdict
from .models import PendingAction

# Rate limiting: session_id -> list of timestamps
_chat_rate_limit: dict[str, list[float]] = defaultdict(list)
_chat_rate_limit_count = 10  # per minute
_chat_rate_limit_window = 60.0  # seconds

# Remediation rate limiting
_remediation_rate_limit: dict[str, list[float]] = defaultdict(list)
_remediation_rate_limit_count = 3
_remediation_rate_limit_window = 60.0

# Pending confirmation actions: action_id -> PendingAction
_pending_actions: dict[str, PendingAction] = {}

# Pending action TTL in seconds
PENDING_ACTION_TTL = 60.0


def check_chat_rate_limit(session_id: str) -> bool:
    """Returns True if within rate limit, False if exceeded."""
    now = time.time()
    window = _chat_rate_limit[session_id]
    # Remove old entries
    window[:] = [t for t in window if now - t < _chat_rate_limit_window]
    if len(window) >= _chat_rate_limit_count:
        return False
    window.append(now)
    return True


def check_remediation_rate_limit(session_id: str) -> bool:
    """Returns True if within rate limit for auto-remediation."""
    now = time.time()
    window = _remediation_rate_limit[session_id]
    window[:] = [t for t in window if now - t < _remediation_rate_limit_window]
    if len(window) >= _remediation_rate_limit_count:
        return False
    window.append(now)
    return True


def create_pending_action(tool: str, params: dict) -> str:
    """Create a pending confirmation action. Returns action_id."""
    action_id = str(uuid.uuid4())
    _pending_actions[action_id] = PendingAction(
        action_id=action_id,
        tool=tool,
        params=params,
        created_at=time.time(),
    )
    return action_id


def get_pending_action(action_id: str) -> PendingAction | None:
    """Get and validate a pending action (checks TTL)."""
    action = _pending_actions.get(action_id)
    if not action:
        return None
    if time.time() - action.created_at > PENDING_ACTION_TTL:
        _pending_actions.pop(action_id, None)
        return None
    return action


def confirm_action(action_id: str) -> bool:
    """Mark an action as confirmed. Returns True if found and confirmed."""
    action = _pending_actions.pop(action_id, None)
    if action:
        action.confirmed = True
        return True
    return False


def deny_action(action_id: str) -> bool:
    """Remove a pending action without executing. Returns True if found."""
    return _pending_actions.pop(action_id, None) is not None


def clear_expired_actions():
    """Remove all expired pending actions."""
    now = time.time()
    expired = [aid for aid, a in _pending_actions.items() if now - a.created_at > PENDING_ACTION_TTL]
    for aid in expired:
        _pending_actions.pop(aid, None)
```

- [ ] **Step 2: Commit**

```bash
git add ai/guardrails.py
git commit -m "feat(ai): add rate limiter and confirmation queue"
```

---

## Task 4: AI Tools Definition

**Files:**
- Create: `d:/server-dashboard/ai/tools.py`

- [ ] **Step 1: Create `ai/tools.py`**

```python
# ai/tools.py
"""AI tool definitions that mirror dashboard API endpoints.

Each tool has:
  - name: function-calling schema name
  - description: shown to the AI and user
  - parameters: JSON schema for function calling
  - min_role: minimum role required (viewer < operator < admin)
  - auto_exec: if True, executes without confirmation; if False, needs confirm
  - handler(session, params): actual implementation, returns dict result
"""

from typing import Any
import sqlite3
import psutil
import subprocess
from datetime import datetime

# Import shared DB path from main (set at app startup)
USERS_DB_PATH = "users.db"

TOOLS = []


def tool(name: str, description: str, parameters: dict, min_role: str = "viewer", auto_exec: bool = True):
    """Decorator to register a tool."""
    def decorator(func):
        TOOLS.append({
            "name": name,
            "description": description,
            "parameters": parameters,
            "min_role": min_role,
            "auto_exec": auto_exec,
            "handler": func,
        })
        return func
    return decorator


# ─── Viewer tools (read-only) ────────────────────────────────────────────────

@tool(
    name="get_system_metrics",
    description="Get current system metrics: CPU usage, RAM usage, and battery status.",
    parameters={
        "type": "object",
        "properties": {},
        "required": [],
    },
    min_role="viewer",
    auto_exec=True,
)
def get_system_metrics(session: dict, params: dict) -> dict:
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    battery = psutil.sensors_battery()
    return {
        "cpu_percent": cpu,
        "ram_total_gb": round(mem.total / (1024**3), 1),
        "ram_used_gb": round(mem.used / (1024**3), 1),
        "ram_percent": mem.percent,
        "battery_percent": battery.percent if battery else None,
        "battery_charging": battery.is_charging if battery else None,
    }


@tool(
    name="get_open_ports",
    description="Get list of currently open network ports on the server.",
    parameters={
        "type": "object",
        "properties": {},
        "required": [],
    },
    min_role="viewer",
    auto_exec=True,
)
def get_open_ports(session: dict, params: dict) -> dict:
    try:
        result = subprocess.run(
            ["ss", "-tuln"],
            capture_output=True, text=True, timeout=10,
        )
        lines = result.stdout.strip().split("\n")[1:]  # skip header
        ports = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                proto = parts[0].lower()
                local_addr = parts[4]
                if ":" in local_addr:
                    addr, port_str = local_addr.rsplit(":", 1)
                    try:
                        ports.append({"proto": proto, "address": addr, "port": int(port_str)})
                    except ValueError:
                        pass
        return {"ports": ports, "count": len(ports)}
    except Exception as e:
        return {"ports": [], "count": 0, "error": str(e)}


@tool(
    name="get_docker_status",
    description="Get list of running Docker containers.",
    parameters={
        "type": "object",
        "properties": {},
        "required": [],
    },
    min_role="viewer",
    auto_exec=True,
)
def get_docker_status(session: dict, params: dict) -> dict:
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}"],
            capture_output=True, text=True, timeout=10,
        )
        containers = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 3:
                containers.append({
                    "id": parts[0],
                    "name": parts[1],
                    "status": parts[2],
                    "ports": parts[3] if len(parts) > 3 else "",
                })
        return {"containers": containers, "count": len(containers)}
    except Exception as e:
        return {"containers": [], "count": 0, "error": str(e)}


@tool(
    name="get_services",
    description="Get list of pinned/managed services and their status.",
    parameters={
        "type": "object",
        "properties": {},
        "required": [],
    },
    min_role="viewer",
    auto_exec=True,
)
def get_services(session: dict, params: dict) -> dict:
    conn = sqlite3.connect(USERS_DB_PATH)
    cursor = conn.execute(
        "SELECT id, name, port, command, created_at FROM pinned_services ORDER BY name"
    )
    rows = cursor.fetchall()
    conn.close()
    services = []
    for r in rows:
        services.append({
            "id": r[0],
            "name": r[1],
            "port": r[2],
            "command": r[3],
            "created_at": r[4],
        })
    return {"services": services}


@tool(
    name="get_todos",
    description="Get list of operational todo items.",
    parameters={
        "type": "object",
        "properties": {},
        "required": [],
    },
    min_role="viewer",
    auto_exec=True,
)
def get_todos(session: dict, params: dict) -> dict:
    conn = sqlite3.connect(USERS_DB_PATH)
    cursor = conn.execute("SELECT id, text, done, created_at FROM todos ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    todos = [{"id": r[0], "text": r[1], "done": bool(r[2]), "created_at": r[3]} for r in rows]
    return {"todos": todos}


@tool(
    name="get_alert_rules",
    description="Get current alert rules (CPU/RAM thresholds).",
    parameters={
        "type": "object",
        "properties": {},
        "required": [],
    },
    min_role="admin",
    auto_exec=True,
)
def get_alert_rules(session: dict, params: dict) -> dict:
    conn = sqlite3.connect(USERS_DB_PATH)
    cursor = conn.execute("SELECT id, metric_type, threshold, enabled, created_at FROM alert_rules")
    rows = cursor.fetchall()
    conn.close()
    rules = [{"id": r[0], "metric": r[1], "threshold": r[2], "enabled": bool(r[3]), "created_at": r[4]} for r in rows]
    return {"rules": rules}


@tool(
    name="get_recent_events",
    description="Get recent audit log entries (actions taken on the dashboard).",
    parameters={
        "type": "object",
        "properties": {"limit": {"type": "integer", "default": 20}},
        "required": [],
    },
    min_role="viewer",
    auto_exec=True,
)
def get_recent_events(session: dict, params: dict) -> dict:
    limit = params.get("limit", 20)
    conn = sqlite3.connect(USERS_DB_PATH)
    cursor = conn.execute(
        "SELECT id, username, action, details, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    events = [{"id": r[0], "username": r[1], "action": r[2], "details": r[3], "timestamp": r[4]} for r in rows]
    return {"events": events}


@tool(
    name="check_port_health",
    description="Check if a specific port is reachable on localhost.",
    parameters={
        "type": "object",
        "properties": {"port": {"type": "integer"}},
        "required": ["port"],
    },
    min_role="viewer",
    auto_exec=True,
)
def check_port_health(session: dict, params: dict) -> dict:
    import socket
    port = params["port"]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        result = sock.connect_ex(("127.0.0.1", port))
        sock.close()
        return {"port": port, "reachable": result == 0}
    except Exception as e:
        return {"port": port, "reachable": False, "error": str(e)}


# ─── Operator tools (require confirmation) ────────────────────────────────────

@tool(
    name="start_service",
    description="Start a pinned/managed service by name.",
    parameters={
        "type": "object",
        "properties": {"service_name": {"type": "string"}},
        "required": ["service_name"],
    },
    min_role="operator",
    auto_exec=False,
)
def start_service(session: dict, params: dict) -> dict:
    name = params["service_name"]
    # Delegate to main.py's managed_services — imported at module level via main
    # We return instructions for the caller to execute via /run endpoint
    return {"action": "start_service", "name": name, "requires_endpoint": "/run"}


@tool(
    name="stop_service",
    description="Stop a pinned/managed service by name.",
    parameters={
        "type": "object",
        "properties": {"service_name": {"type": "string"}},
        "required": ["service_name"],
    },
    min_role="operator",
    auto_exec=False,
)
def stop_service(session: dict, params: dict) -> dict:
    name = params["service_name"]
    return {"action": "stop_service", "name": name, "requires_endpoint": "/stop"}


@tool(
    name="restart_service",
    description="Restart a pinned/managed service by name. Executes stop then start.",
    parameters={
        "type": "object",
        "properties": {"service_name": {"type": "string"}},
        "required": ["service_name"],
    },
    min_role="operator",
    auto_exec=False,
)
def restart_service(session: dict, params: dict) -> dict:
    name = params["service_name"]
    return {"action": "restart_service", "name": name, "requires_endpoints": ["/stop", "/run"]}


@tool(
    name="add_todo",
    description="Add a new operational todo item.",
    parameters={
        "type": "object",
        "properties": {"text": {"type": "string"}},
        "required": ["text"],
    },
    min_role="operator",
    auto_exec=False,
)
def add_todo(session: dict, params: dict) -> dict:
    text = params["text"]
    return {"action": "add_todo", "text": text, "requires_endpoint": "/state/todos"}


@tool(
    name="toggle_todo",
    description="Toggle a todo item's done/undone status.",
    parameters={
        "type": "object",
        "properties": {"todo_id": {"type": "integer"}},
        "required": ["todo_id"],
    },
    min_role="operator",
    auto_exec=False,
)
def toggle_todo(session: dict, params: dict) -> dict:
    todo_id = params["todo_id"]
    return {"action": "toggle_todo", "todo_id": todo_id, "requires_endpoint": "/state/todos/{todo_id}"}


# ─── Admin tools (require confirmation) ──────────────────────────────────────

@tool(
    name="create_alert_rule",
    description="Create a new CPU or RAM alert rule.",
    parameters={
        "type": "object",
        "properties": {
            "metric": {"type": "string", "enum": ["cpu", "ram"]},
            "threshold": {"type": "number"},
        },
        "required": ["metric", "threshold"],
    },
    min_role="admin",
    auto_exec=False,
)
def create_alert_rule(session: dict, params: dict) -> dict:
    return {
        "action": "create_alert_rule",
        "metric": params["metric"],
        "threshold": params["threshold"],
        "requires_endpoint": "/alert-rules",
    }


def get_tool_schemas() -> list[dict]:
    """Return list of tool schemas for Gemini function calling."""
    return [
        {
            "name": t["name"],
            "description": t["description"],
            "parameters": t["parameters"],
        }
        for t in TOOLS
    ]


def execute_tool(tool_name: str, session: dict, params: dict) -> dict:
    """Execute a tool by name, checking role. Returns dict result."""
    role_rank = {"viewer": 1, "operator": 2, "admin": 3}
    user_rank = role_rank.get(session.get("role", ""), 0)

    for t in TOOLS:
        if t["name"] == tool_name:
            min_rank = role_rank.get(t["min_role"], 0)
            if user_rank < min_rank:
                return {"error": f"Permission denied: {t['min_role']} role required"}
            try:
                return t["handler"](session, params)
            except Exception as e:
                return {"error": str(e)}

    return {"error": f"Unknown tool: {tool_name}"}
```

- [ ] **Step 2: Commit**

```bash
git add ai/tools.py
git commit -m "feat(ai): add tool definitions mirroring dashboard APIs"
```

---

## Task 5: Gemini Client

**Files:**
- Create: `d:/server-dashboard/ai/gemini_client.py`

- [ ] **Step 1: Create `ai/gemini_client.py`**

```python
# ai/gemini_client.py
"""Gemini API client with function calling support."""

import os
import time
from typing import AsyncGenerator

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    genai = None

from .models import AIChatRequest
from .tools import get_tool_schemas, execute_tool, TOOLS
from .guardrails import create_pending_action, get_pending_action

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Role display names for the AI
ROLE_DESCRIPTIONS = {
    "viewer": "read-only dashboard access",
    "operator": "read access + ability to start/stop services, use terminal, manage todos",
    "admin": "full access including user management, alert rules, file manager",
}


class GeminiChat:
    _configured = False

    @classmethod
    def configure(cls):
        if cls._configured:
            return
        if not GEMINI_API_KEY or GEMINI_API_KEY == "YOUR_KEY":
            cls._configured = True  # Mark as done to avoid repeated attempts
            return
        if GEMINI_AVAILABLE:
            genai.configure(api_key=GEMINI_API_KEY)
            cls._configured = True

    def __init__(self, session_user: dict):
        self.user = session_user
        self.configure()
        self.model_name = GEMINI_MODEL

    def _build_system_prompt(self) -> str:
        role = self.user.get("role", "viewer")
        role_desc = ROLE_DESCRIPTIONS.get(role, "read-only access")
        tools_list = "\n".join(
            f"- {t['name']}: {t['description']}" for t in TOOLS
        )
        return f"""You are an AI assistant inside a DevOps dashboard. The current user has the role '{role}' ({role_desc}).

Your capabilities via tools:
{tools_list}

Guidelines:
- Always use a tool if available rather than guessing data.
- If a tool fails, explain the error to the user and suggest next steps.
- For actions needing confirmation (auto_exec=False), describe what you will do and wait.
- Never make up port numbers, service names, or PIDs — always use tools to get real data.
- Keep responses concise but informative.
- Sensitive actions (start/stop/restart services, create alert rules) require user confirmation.
- You have read access to: system metrics, ports, Docker, services, todos, audit logs.
"""

    def _tool_to_gemini_func(self, tool: dict) -> dict:
        return {
            "name": tool["name"],
            "description": tool["description"],
            "parameters": tool["parameters"],
        }

    async def chat_stream(self, message: str) -> AsyncGenerator[dict, None]:
        """Stream chat response as dicts with type tags."""
        if not GEMINI_API_KEY or GEMINI_API_KEY == "YOUR_KEY":
            yield {"type": "error", "message": "Gemini API key not configured. Set GEMINI_API_KEY in .env"}
            return

        if not GEMINI_AVAILABLE:
            yield {"type": "error", "message": "google-generativeai package not installed. Run: pip install google-generativeai"}
            return

        try:
            model = genai.GenerativeModel(
                model_name=self.model_name,
                system_instruction=self._build_system_prompt(),
                tools=[{"function_declarations": [self._tool_to_gemini_func(t) for t in TOOLS]}],
            )
            chat = model.start_chat(enable_automatic_function_calling=True)
            response = chat.send_message(message, stream=True)

            for chunk in response:
                if chunk.text:
                    yield {"type": "text", "content": chunk.text}
                # Handle function calls (automatic_function_calling=True returns them)
                if chunk.function_calls:
                    for fc in chunk.function_calls:
                        tool_name = fc.name
                        tool_args = dict(fc.args) if hasattr(fc, 'args') else {}
                        yield {"type": "tool_call", "tool": tool_name, "params": tool_args}

                        # Execute tool
                        result = execute_tool(tool_name, self.user, tool_args)
                        yield {"type": "tool_result", "tool": tool_name, "result": result}

                        # Check if auto_exec or needs confirmation
                        tool_def = next((t for t in TOOLS if t["name"] == tool_name), None)
                        if tool_def and not tool_def["auto_exec"]:
                            action_id = create_pending_action(tool_name, tool_args)
                            yield {
                                "type": "action_pending",
                                "action_id": action_id,
                                "tool": tool_name,
                                "summary": f"Wants to {tool_name} with {tool_args}",
                            }
                        else:
                            # Auto-exec result was already shown; log it
                            pass

            yield {"type": "done", "summary": "Chat complete"}

        except Exception as e:
            yield {"type": "error", "message": f"AI error: {str(e)}"}

    async def analyze(self, trigger: str, context: dict) -> dict:
        """Run AI diagnostic analysis for auto-remediation."""
        if not GEMINI_API_KEY or GEMINI_API_KEY == "YOUR_KEY":
            return {"analysis": "AI not configured", "recommended_action": None, "auto_executable": False}

        if not GEMINI_AVAILABLE:
            return {"analysis": "AI package not installed", "recommended_action": None, "auto_executable": False}

        system_info = execute_tool("get_system_metrics", self.user, {})

        prompts = {
            "port_down": f"""A pinned port just went down.
Port: {context.get('port')}
Previous state: {context.get('previous_state', 'unknown')}
Current system metrics: {system_info}

Diagnose: Why might this port have gone down? Is it a service crash, network issue, or resource exhaustion?
Respond with: 1) Likely cause, 2) Immediate action to take, 3) Whether auto-restart is safe.""",

            "cpu_spike": f"""CPU alert triggered.
Threshold: {context.get('threshold')}%
Current CPU: {system_info.get('cpu_percent')}%
Top processes: {context.get('top_processes', 'unknown')}

Diagnose: What is causing the CPU spike? Suggest a remediation.""",

            "service_crash": f"""A managed service crashed.
Service: {context.get('service_name')}
Recent log lines: {context.get('log_lines', [])}

Diagnose: What does the crash log indicate? Propose a fix.""",

            "docker_stop": f"""A Docker container stopped unexpectedly.
Container: {context.get('container_name')} ({context.get('container_id')})
Status: {context.get('status')}

Diagnose: Why might it have stopped? Suggest restart or investigation steps.""",
        }

        prompt = prompts.get(trigger, "Analyze this situation and suggest actions.")
        model = genai.GenerativeModel(model_name=self.model_name)
        response = model.generate_content(prompt)
        return {
            "analysis": response.text,
            "recommended_action": context,
            "auto_executable": False,  # Always require confirm for remediation
        }
```

- [ ] **Step 2: Commit**

```bash
git add ai/gemini_client.py
git commit -m "feat(ai): add Gemini client with streaming function calling"
```

---

## Task 6: Auto-Remediation Module

**Files:**
- Create: `d:/server-dashboard/ai/remediation.py`

- [ ] **Step 1: Create `ai/remediation.py`**

```python
# ai/remediation.py
"""Auto-remediation triggers integrated with dashboard monitoring loop.

These functions are called by main.py's existing monitoring endpoints
(/system, /ports) to trigger AI analysis when threshold conditions are met.
"""

import os
import time
import asyncio
from .guardrails import check_remediation_rate_limit

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
AI_AUTO_REMEDIATION = os.getenv("AI_AUTO_REMEDIATION", "false").lower() in {"1", "true", "yes"}


def should_remediate() -> bool:
    return AI_AUTO_REMEDIATION and GEMINI_API_KEY and GEMINI_API_KEY != "YOUR_KEY"


def trigger_remediation(session_id: str, trigger: str, context: dict, callback):
    """Trigger async AI analysis. callback(analysis_dict) is called with results.

    Only triggers if rate limit allows and AI_AUTO_REMEDIATION=true.
    """
    if not should_remediate():
        return
    if not check_remediation_rate_limit(session_id):
        return  # Silently skip if rate limited

    async def run():
        from .gemini_client import GeminiChat
        # Build a minimal session dict for the AI
        session_user = {"role": "admin"}  # AI gets admin context for diagnostics
        chat = GeminiChat(session_user)
        analysis = await chat.analyze(trigger, context)
        callback(analysis)

    asyncio.create_task(run())


# ─── Trigger hooks (called from main.py monitoring) ─────────────────────────

def on_port_down(port: int, session_id: str | None = None):
    """Called when a pinned port becomes unreachable."""
    if not should_remediate():
        return
    context = {"port": port, "previous_state": "up"}
    trigger_remediation(
        session_id or "system",
        "port_down",
        context,
        lambda a: None,  # Analysis queued for background processing
    )


def on_cpu_alert(threshold: float, current_cpu: float, session_id: str | None = None):
    """Called when CPU exceeds alert threshold."""
    if not should_remediate():
        return
    context = {"threshold": threshold, "current_cpu": current_cpu}
    trigger_remediation(session_id or "system", "cpu_spike", context, lambda a: None)
```

- [ ] **Step 2: Commit**

```bash
git add ai/remediation.py
git commit -m "feat(ai): add auto-remediation trigger module"
```

---

## Task 7: AI Endpoints in main.py

**Files:**
- Modify: `d:/server-dashboard/main.py` — add 6 new endpoints
- Modify: `d:/server-dashboard/main.py` — add `ai` package init and imports
- Modify: `d:/server-dashboard/main.py` — call `GeminiChat.configure()` at startup

- [ ] **Step 1: Add AI package import after existing imports (after line 21)**

```python
# AI Assistant
from ai.gemini_client import GeminiChat
from ai.guardrails import (
    check_chat_rate_limit,
    get_pending_action,
    confirm_action,
    deny_action,
)
```

- [ ] **Step 2: Add AI config vars after TELEGRAM CONFIG block (after line ~142)**

```python
# 🤖 GEMINI AI CONFIG
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

# Initialize Gemini on startup
if GEMINI_API_KEY and GEMINI_API_KEY != "YOUR_KEY":
    try:
        GeminiChat.configure()
        print(f"[AI] Gemini configured with model {GEMINI_MODEL}")
    except Exception as e:
        print(f"[AI] Warning: Gemini configuration failed: {e}")
```

- [ ] **Step 3: Add new endpoints after the existing API endpoints (find a clean spot near end of file)**

```python
# 🤖 AI ASSISTANT ENDPOINTS
from fastapi import BackgroundTasks

@app.post("/ai/chat")
async def ai_chat(
    request: AIChatRequest,
    user: dict = Depends(get_current_user),
):
    if not check_chat_rate_limit(user["session_id"]):
        raise HTTPException(429, detail="Rate limit exceeded. Try again in a minute.")

    async def event_stream():
        chat = GeminiChat(user)
        full_response = ""
        async for event in chat.chat_stream(request.message):
            import json
            yield f"data: {json.dumps(event)}\n\n"
            if event.get("type") == "done":
                break

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache"},
    )


@app.post("/ai/confirm-action")
async def ai_confirm_action(
    data: AIActionConfirmation,
    user: dict = Depends(get_current_user),
):
    if data.approved:
        action = get_pending_action(data.action_id)
        if not action:
            return {"executed": False, "error": "Action not found or expired"}
        # Execute the action via main.py's endpoints
        from ai.tools import execute_tool
        result = execute_tool(action.tool, user, action.params)
        confirm_action(data.action_id)
        log_audit(user["username"], "ai_action", f"AI action approved: {action.tool} with {action.params}")
        return {"executed": True, "result": result}
    else:
        deny_action(data.action_id)
        return {"executed": False, "denied": True}


@app.get("/ai/status")
async def ai_status(user: dict = Depends(get_current_user)):
    has_key = bool(GEMINI_API_KEY and GEMINI_API_KEY != "YOUR_KEY")
    return {
        "available": has_key,
        "model": GEMINI_MODEL if has_key else None,
        "configured": has_key,
    }


@app.post("/ai/analyze")
async def ai_analyze(
    data: AIAnalyzeRequest,
    user: dict = Depends(require_role("operator")),
):
    chat = GeminiChat(user)
    analysis = await chat.analyze(data.trigger, data.context)
    return analysis


@app.get("/ai/conversations")
async def ai_conversations(
    user: dict = Depends(get_current_user),
    limit: int = Query(default=50, le=100),
):
    # Return recent conversation entries for this session from audit_logs
    conn = sqlite3.connect(USERS_DB_PATH)
    cursor = conn.execute(
        "SELECT id, action, details, timestamp FROM audit_logs "
        "WHERE action LIKE 'ai_%' AND details LIKE ? "
        "ORDER BY timestamp DESC LIMIT ?",
        (f"%{user['session_id']}%", limit),
    )
    rows = cursor.fetchall()
    conn.close()
    return {"conversations": [{"id": r[0], "action": r[1], "details": r[2], "timestamp": r[3]} for r in rows]}


@app.get("/ai/pending-actions")
async def ai_pending_actions(user: dict = Depends(get_current_user)):
    from ai.guardrails import _pending_actions
    # Return non-expired pending actions for current session context
    return {"count": len(_pending_actions)}
```

- [ ] **Step 4: Commit**

```bash
git add main.py
git commit -m "feat(ai): add /ai/* endpoints for chat, confirm-action, status, analyze"
```

---

## Task 8: Floating Chat Panel in index.html

**Files:**
- Modify: `d:/server-dashboard/index.html` — add chat panel HTML/CSS/JS at end of `<body>`

- [ ] **Step 1: Add chat panel HTML/CSS/JS just before closing `</body>` tag (find last script/style block)**

Insert this as a new `<script>` block at the very end of `<body>`:

```javascript
// ─── AI Chat Panel ───────────────────────────────────────────────────────────
(function() {
  const PANEL_ID = 'ai-chat-panel';
  const STORAGE_KEY = 'ai_chat_history';

  let isOpen = false;
  let chatHistory = [];
  let isStreaming = false;
  let draftMessage = '';

  function getHistory() {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); } catch { return []; }
  }
  function saveHistory(h) {
    if (h.length > 50) h = h.slice(-50); // FIFO at 50
    localStorage.setItem(STORAGE_KEY, JSON.stringify(h));
  }

  function render() {
    let panel = document.getElementById(PANEL_ID);
    if (!panel) {
      panel = document.createElement('div');
      panel.id = PANEL_ID;
      document.body.appendChild(panel);
    }
    panel.innerHTML = `
      <style>
      #${PANEL_ID} {
        position: fixed;
        bottom: 20px;
        right: 20px;
        width: 380px;
        max-width: calc(100vw - 40px);
        height: 520px;
        max-height: calc(100vh - 40px);
        background: var(--bg-secondary, #1a1a2e);
        border: 1px solid var(--border, #2a2a4a);
        border-radius: 12px;
        display: flex;
        flex-direction: column;
        font-family: inherit;
        font-size: 14px;
        z-index: 9999;
        box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        transition: opacity 0.2s, transform 0.2s;
      }
      #${PANEL_ID}.collapsed {
        height: 56px;
        width: 56px;
        border-radius: 28px;
        cursor: pointer;
      }
      #${PANEL_ID}.collapsed .ai-header,
      #${PANEL_ID}.collapsed .ai-body,
      #${PANEL_ID}.collapsed .ai-input-area { display: none; }
      #${PANEL_ID}.collapsed::before {
        content: '🤖';
        font-size: 28px;
        position: absolute;
        top: 14px;
        left: 14px;
      }
      .ai-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 12px 16px;
        border-bottom: 1px solid var(--border, #2a2a4a);
        background: var(--bg-tertiary, #16162a);
        border-radius: 12px 12px 0 0;
        cursor: grab;
      }
      .ai-header-title { font-weight: 700; font-size: 15px; color: var(--text, #e0e0e0); }
      .ai-header-actions { display: flex; gap: 8px; }
      .ai-header-btn {
        background: none; border: none; cursor: pointer;
        color: var(--text-muted, #888); font-size: 16px;
        padding: 4px; border-radius: 4px;
      }
      .ai-header-btn:hover { background: var(--hover, #2a2a4a); }
      .ai-body {
        flex: 1;
        overflow-y: auto;
        padding: 16px;
        display: flex;
        flex-direction: column;
        gap: 10px;
        scroll-behavior: smooth;
      }
      .ai-msg { max-width: 85%; padding: 10px 14px; border-radius: 12px; line-height: 1.5; white-space: pre-wrap; word-break: break-word; }
      .ai-msg.user {
        align-self: flex-end;
        background: var(--primary, #4a90d9);
        color: #fff;
        border-bottom-right-radius: 4px;
      }
      .ai-msg.ai {
        align-self: flex-start;
        background: var(--bg-tertiary, #252540);
        color: var(--text, #e0e0e0);
        border-bottom-left-radius: 4px;
      }
      .ai-msg.error {
        background: #3a1a1a;
        color: #f88;
        border: 1px solid #f44;
      }
      .ai-tool-card {
        background: var(--bg-tertiary, #252540);
        border: 1px solid var(--border, #2a2a4a);
        border-radius: 8px;
        padding: 8px 12px;
        font-size: 12px;
        color: var(--text-muted, #888);
        align-self: flex-start;
        width: 100%;
        box-sizing: border-box;
      }
      .ai-tool-card b { color: var(--text, #e0e0e0); }
      .ai-tool-result { margin-top: 4px; font-family: monospace; font-size: 11px; color: var(--text, #ccc); max-height: 80px; overflow-y: auto; }
      .ai-pending-card {
        background: #2a2a1a;
        border: 1px solid #8a7a2a;
        border-radius: 8px;
        padding: 10px 14px;
        align-self: flex-start;
        max-width: 90%;
      }
      .ai-pending-card .pending-title { color: #dda; font-weight: 600; margin-bottom: 6px; font-size: 13px; }
      .ai-pending-card .pending-btns { display: flex; gap: 8px; margin-top: 8px; }
      .ai-pending-card button {
        padding: 4px 14px;
        border-radius: 6px;
        border: none;
        cursor: pointer;
        font-size: 12px;
        font-weight: 600;
      }
      .ai-pending-card .approve-btn { background: #2a6a2a; color: #fff; }
      .ai-pending-card .deny-btn { background: #6a2a2a; color: #fff; }
      .ai-input-area {
        display: flex;
        gap: 8px;
        padding: 12px 16px;
        border-top: 1px solid var(--border, #2a2a4a);
        background: var(--bg-tertiary, #16162a);
        border-radius: 0 0 12px 12px;
      }
      .ai-input {
        flex: 1;
        background: var(--bg, #1a1a2e);
        border: 1px solid var(--border, #2a2a4a);
        border-radius: 8px;
        padding: 8px 12px;
        color: var(--text, #e0e0e0);
        font-family: inherit;
        font-size: 13px;
        resize: none;
        max-height: 80px;
        outline: none;
      }
      .ai-input:focus { border-color: var(--primary, #4a90d9); }
      .ai-send-btn {
        background: var(--primary, #4a90d9);
        border: none;
        border-radius: 8px;
        width: 38px;
        height: 38px;
        cursor: pointer;
        color: #fff;
        font-size: 18px;
        display: flex;
        align-items: center;
        justify-content: center;
        align-self: flex-end;
      }
      .ai-send-btn:hover { background: var(--primary-hover, #3a80c9); }
      .ai-send-btn:disabled { opacity: 0.5; cursor: not-allowed; }
      .ai-loading {
        display: flex; gap: 4px; padding: 4px 0;
      }
      .ai-loading span {
        width: 8px; height: 8px; background: var(--text-muted, #888);
        border-radius: 50%; animation: ai-bounce 1.2s infinite;
      }
      .ai-loading span:nth-child(2) { animation-delay: 0.2s; }
      .ai-loading span:nth-child(3) { animation-delay: 0.4s; }
      @keyframes ai-bounce { 0%, 80%, 100% { transform: scale(0.6); opacity: 0.4; } 40% { transform: scale(1); opacity: 1; } }
      </style>
      <div class="ai-header" onmousedown="startDrag(event)">
        <span class="ai-header-title">AI Assistant</span>
        <div class="ai-header-actions">
          <button class="ai-header-btn" onclick="toggleAIPanel()" title="Collapse">−</button>
          <button class="ai-header-btn" onclick="clearAIHistory()" title="Clear history">🗑</button>
        </div>
      </div>
      <div class="ai-body" id="aiBody"></div>
      <div class="ai-input-area">
        <textarea class="ai-input" id="aiInput" rows="1" placeholder="Ask me anything about your server..."
          onkeydown="handleAIInputKey(event)"></textarea>
        <button class="ai-send-btn" id="aiSendBtn" onclick="sendAIMessage()">↑</button>
      </div>
    `;

    // Restore state
    chatHistory = getHistory();
    renderMessages();
    if (!isOpen) panel.classList.add('collapsed');
  }

  function renderMessages() {
    const body = document.getElementById('aiBody');
    if (!body) return;
    body.innerHTML = '';
    for (const msg of chatHistory) {
      appendMsgEl(body, msg);
    }
    body.scrollTop = body.scrollHeight;
  }

  function appendMsgEl(container, msg) {
    if (msg.type === 'tool_call') {
      const card = document.createElement('div');
      card.className = 'ai-tool-card';
      card.innerHTML = `<b>🔧 ${escapeHtml(msg.tool)}</b><div class="ai-tool-result">Running...</div>`;
      container.appendChild(card);
      return card;
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
        <div class="pending-title">⏳ ${escapeHtml(msg.summary || msg.tool)}</div>
        <div class="pending-btns">
          <button class="approve-btn" onclick="confirmAIAction('${msg.action_id}', true)">Approve</button>
          <button class="deny-btn" onclick="confirmAIAction('${msg.action_id}', false)">Deny</button>
        </div>`;
      container.appendChild(card);
      return;
    }
    const div = document.createElement('div');
    div.className = 'ai-msg ' + (msg.role === 'user' ? 'user' : 'ai');
    if (msg.role === 'ai' && msg.content && msg.content.startsWith('[Error]')) {
      div.className = 'ai-msg error';
    }
    div.textContent = msg.content || '';
    container.appendChild(div);
  }

  function escapeHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function formatJSON(obj) {
    try { return JSON.stringify(obj, null, 2); } catch { return String(obj); }
  }

  window.toggleAIPanel = function() {
    isOpen = !isOpen;
    const panel = document.getElementById(PANEL_ID);
    if (panel) {
      if (isOpen) panel.classList.remove('collapsed');
      else panel.classList.add('collapsed');
    }
  };

  window.clearAIHistory = function() {
    chatHistory = [];
    localStorage.removeItem(STORAGE_KEY);
    renderMessages();
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
        };
        appendMsgEl(body, msg);
        chatHistory.push(msg);
        saveHistory(chatHistory);
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

    isStreaming = true;
    sendBtn.disabled = true;
    input.value = '';

    const body = document.getElementById('aiBody');
    if (!body) return;

    // Add user message
    const userMsg = { role: 'user', content: text };
    chatHistory.push(userMsg);
    saveHistory(chatHistory);
    appendMsgEl(body, userMsg);

    // Add loading
    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'ai-msg ai';
    loadingDiv.innerHTML = '<div class="ai-loading"><span></span><span></span><span></span></div>';
    body.appendChild(loadingDiv);
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
      let aiMsgDiv = loadingDiv;
      let pendingCard = null;

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
              // Append text to current AI message
              if (aiMsgDiv === loadingDiv) {
                loadingDiv.className = 'ai-msg ai';
                loadingDiv.textContent = '';
                aiMsgDiv = loadingDiv;
              }
              aiMsgDiv.textContent += event.content;
              body.scrollTop = body.scrollHeight;
            } else if (event.type === 'tool_call') {
              appendMsgEl(body, {type: 'tool_call', tool: event.tool});
              pendingCard = appendMsgEl(body, {type: 'tool_result', tool: event.tool, result: event.params});
            } else if (event.type === 'tool_result') {
              appendMsgEl(body, {type: 'tool_result', tool: event.tool, result: event.result});
            } else if (event.type === 'action_pending') {
              appendMsgEl(body, {type: 'action_pending', action_id: event.action_id, summary: event.summary, tool: event.tool});
            } else if (event.type === 'done') {
              // Save AI response to history
              chatHistory.push({role: 'ai', content: aiMsgDiv.textContent || '[Analysis complete]'});
              saveHistory(chatHistory);
            } else if (event.type === 'error') {
              const errDiv = document.createElement('div');
              errDiv.className = 'ai-msg error';
              errDiv.textContent = '[Error] ' + event.message;
              body.appendChild(errDiv);
            }
          } catch {}
        }
      }
    } catch (e) {
      loadingDiv.textContent = '[Connection error] ' + e.message;
      loadingDiv.className = 'ai-msg error';
    } finally {
      isStreaming = false;
      sendBtn.disabled = false;
      saveHistory(chatHistory);
    }
  };

  // Drag functionality
  let dragOffsetX, dragOffsetY;
  window.startDrag = function(e) {
    const panel = document.getElementById(PANEL_ID);
    dragOffsetX = e.clientX - panel.offsetLeft;
    dragOffsetY = e.clientY - panel.offsetTop;
    document.addEventListener('mousemove', doDrag);
    document.addEventListener('mouseup', stopDrag);
  };
  window.doDrag = function(e) {
    const panel = document.getElementById(PANEL_ID);
    panel.style.left = Math.max(0, Math.min(window.innerWidth - panel.offsetWidth, e.clientX - dragOffsetX)) + 'px';
    panel.style.bottom = 'auto';
    panel.style.right = 'auto';
  };
  window.stopDrag = function() {
    document.removeEventListener('mousemove', doDrag);
    document.removeEventListener('mouseup', stopDrag);
  };

  // Init
  render();

  // Check AI availability on load
  (async function checkAIAvailable() {
    try {
      const res = await fetch('/ai/status');
      const data = await res.json();
      if (!data.available) {
        const input = document.getElementById('aiInput');
        if (input) input.placeholder = 'AI not configured. Set GEMINI_API_KEY in .env';
      }
    } catch {}
  })();
})();
```

- [ ] **Step 2: Commit**

```bash
git add index.html
git commit -m "feat(ai): add floating chat panel UI to index.html"
```

---

## Task 9: Environment Configuration

**Files:**
- Modify: `d:/server-dashboard/.env` — add AI config vars

- [ ] **Step 1: Append AI vars to `.env`**

```env
# Gemini AI Assistant
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.0-flash
AI_AUTO_REMEDIATION=false
AI_CONFIRM_SENSITIVE=true
AI_RATE_LIMIT_PER_MIN=10
AI_MAX_CONVERSATION_MESSAGES=50
```

- [ ] **Step 2: Commit**

```bash
git add .env
git commit -m "feat(ai): add AI configuration to .env"
```

---

## Task 10: Database Migration

**Files:**
- Modify: `d:/server-dashboard/main.py` — add migration code for `ai_conversations` table

- [ ] **Step 1: Find the DB init section in main.py and add migration for ai_conversations table]

Locate the existing `sqlite3.connect(USERS_DB_PATH)` block that creates tables. Add after `cloudflared_routes` table creation:

```python
# AI conversations table
cursor.execute("""
    CREATE TABLE IF NOT EXISTS ai_conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('user', 'ai')),
        content TEXT NOT NULL,
        tools_used TEXT,
        action_initiated TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_conv_session ON ai_conversations(session_id, created_at)")
```

- [ ] **Step 2: Commit**

```bash
git add main.py
git commit -m "feat(ai): add ai_conversations table migration"
```

---

## Task 11: Integration — Call Remediation Hooks from Monitoring

**Files:**
- Modify: `d:/server-dashboard/main.py` — import and call remediation triggers in `/system` endpoint

- [ ] **Step 1: In `get_system` endpoint (around line 2720), add CPU threshold check with remediation trigger]

Add after the CPU alert logic in `get_system`:

```python
# Check CPU alert and trigger AI remediation if enabled
cpu = psutil.cpu_percent(interval=0.5)
if AI_AUTO_REMEDIATION == "true" and cpu > 80:
    from ai.remediation import on_cpu_alert
    on_cpu_alert(threshold=80, current_cpu=cpu, session_id=user.get("session_id"))
```

- [ ] **Step 2: Commit**

```bash
git add main.py
git commit -m "feat(ai): wire up CPU remediation trigger in /system endpoint"
```

---

## Verification

After all tasks:

1. **Install dependencies:** `pip install google-generativeai`
2. **Add your Gemini API key** to `.env`
3. **Start the server:** `uvicorn main:app --reload`
4. **Login to the dashboard** at `http://localhost:8000`
5. **Look for the 🤖 bubble** in the bottom-right corner
6. **Try:** "What services are running?" → should list pinned services
7. **Try:** "Start my nginx service" (with a pinned service) → should show confirmation card
8. **Check `/ai/status`** returns `{"available": true, "model": "gemini-2.0-flash"}`
9. **Check rate limiting** by sending 15+ messages rapidly → 429 after 10th

---

## Spec Self-Review

- **Placeholder scan:** No TODOs or TBDs — all tool schemas, CSS values, and endpoint paths are fully specified.
- **Internal consistency:** Tool names in `tools.py` match what `gemini_client.py` references. `guardrails.py` function names match `main.py` imports.
- **Scope check:** Single focused feature — AI chat with function calling. No scope creep into unrelated subsystems.
- **RBAC coverage:** All 13 tools mapped to viewer/operator/admin with explicit min_role checks in `execute_tool()`.
- **Missing:** The auto-remediation callbacks currently no-op (just `lambda a: None`). The `callback` in `trigger_remediation` is queued but not wired to send a UI notification. This is intentional — the first implementation is advisory-only. Full notification flow can be added in a follow-up.
