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
import socket
from datetime import datetime

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
    try:
        from routers.metrics import system_metrics_cache
        cpu = system_metrics_cache.get("cpu", 0.0)
        mem_percent = system_metrics_cache.get("memory", 0.0)
        vmem = system_metrics_cache.get("vmem", {})
        battery = system_metrics_cache.get("battery")
        
        return {
            "cpu_percent": cpu,
            "ram_total_gb": round(vmem.get("total", 0) / (1024**3), 1) if vmem else 0.0,
            "ram_used_gb": round(vmem.get("used", 0) / (1024**3), 1) if vmem else 0.0,
            "ram_percent": mem_percent,
            "battery_percent": battery.get("percent") if battery else None,
            "battery_charging": battery.get("charging") if battery else None,
        }
    except Exception:
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
        lines = result.stdout.strip().split("\n")[1:]
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
        "properties": {"limit": {"type": "integer"}},
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