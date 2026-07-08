from fastapi import FastAPI, HTTPException, Query, Cookie, Response, Depends, Request, UploadFile, File, Form, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from starlette.background import BackgroundTask
from pydantic import BaseModel
import psutil
import subprocess
import socket
import requests
import os
import signal
import shutil
import asyncio
from collections import deque
import secrets
import time
import sqlite3
import hashlib
import hmac
import re
import base64
import tempfile
import json
import yaml
import threading

def safe_rmtree(path, ignore_errors=False):
    import stat
    def remove_readonly(func, p, excinfo):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            if not ignore_errors:
                raise

    if os.path.exists(path):
        try:
            shutil.rmtree(path, onerror=remove_readonly)
        except Exception:
            if not ignore_errors:
                raise

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

def load_env_file(path: str = ".env"):
    if not os.path.exists(path):
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key:
                    os.environ.setdefault(key, value)
    except Exception as e:
        print("Failed to load .env:", e)

load_env_file()

app = FastAPI()

# AI Assistant (imported after env is loaded)
from ai.gemini_client import GeminiChat
from ai.nvidia_client import NvidiaChat
from ai.guardrails import (
    check_chat_rate_limit,
    get_pending_action,
    confirm_action,
    deny_action,
)

try:
    import pwd
except ImportError:
    pwd = None

try:
    import pty
    import fcntl
    import termios
    import struct
    TERMINAL_BACKEND_AVAILABLE = True
except ImportError:
    pty = None
    fcntl = None
    termios = None
    struct = None
    TERMINAL_BACKEND_AVAILABLE = False

# 🔑 TELEGRAM CONFIG
BOT_TOKEN = os.getenv("BOT_TOKEN", "YOUR_TOKEN")
CHAT_ID = os.getenv("CHAT_ID", "YOUR_CHAT_ID")
SERVER_NAME = os.getenv("SERVER_NAME", "").strip()
SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))
SESSION_TIMEOUT_SECONDS = max(60, SESSION_TIMEOUT_MINUTES * 60)
SESSION_COOKIE_NAME = "dashboard_session"
USERS_DB_PATH = os.getenv("USERS_DB_PATH", "users.db")
PASSWORD_ITERATIONS = 150_000
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")
SSH_USERNAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
CLOUDFLARED_HOSTNAME_PATTERN = re.compile(r"^(?:\*\.)?(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$")
CLOUDFLARED_SERVICE_HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9]$|^[A-Za-z0-9]$")
DOCKER_CONTAINER_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

ROLE_ORDER = {
    "viewer": 1,
    "operator": 2,
    "admin": 3,
}

BATTERY_THRESHOLD = 20
battery_alert_sent = False
managed_services = {}
active_sessions = {}  # in-memory cache, DB is source of truth
alert_last_sent = {}  # Track when alerts were last sent to avoid spam
pinned_port_down_alert_state = {}  # port -> bool (True when already alerted as down)
docker_container_alert_state = {}  # container_id -> snapshot
docker_last_alert_scan_at = 0.0
SSH_MANAGED_BLOCK_BEGIN = "# >>> dashboard-managed-ssh-keys >>>"
SSH_MANAGED_BLOCK_END = "# <<< dashboard-managed-ssh-keys <<<"
SUPPORTED_SSH_KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
}
GIT_CLONE_FOLDER_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
CLOUDFLARED_CONFIG_PATH = os.getenv("CLOUDFLARED_CONFIG_PATH", "/etc/cloudflared/config.yml")
CLOUDFLARED_FALLBACK_CONFIG_PATH = os.getenv(
    "CLOUDFLARED_FALLBACK_CONFIG_PATH",
    os.path.join(os.getcwd(), "cloudflared", "config.yml"),
)
CLOUDFLARED_MANAGED_BLOCK_BEGIN = "# >>> dashboard-managed-cloudflared-routes >>>"
CLOUDFLARED_MANAGED_BLOCK_END = "# <<< dashboard-managed-cloudflared-routes <<<"
SUPPORTED_CLOUDFLARED_SCHEMES = {"http", "https", "tcp"}
active_cloudflared_config_path = os.path.abspath(CLOUDFLARED_CONFIG_PATH)
CLOUDFLARED_BIN_PATH = (os.getenv("CLOUDFLARED_BIN_PATH", "cloudflared") or "cloudflared").strip()
CLOUDFLARED_TUNNEL_NAME = os.getenv("CLOUDFLARED_TUNNEL_NAME", "").strip()
CLOUDFLARED_DNS_AUTO_ROUTE = (os.getenv("CLOUDFLARED_DNS_AUTO_ROUTE", "true") or "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
try:
    _cf_dns_timeout = int(os.getenv("CLOUDFLARED_DNS_ROUTE_TIMEOUT_SECONDS", "20"))
except ValueError:
    _cf_dns_timeout = 20
CLOUDFLARED_DNS_ROUTE_TIMEOUT_SECONDS = max(5, min(120, _cf_dns_timeout))
try:
    _cf_tunnel_stop_timeout = int(os.getenv("CLOUDFLARED_TUNNEL_STOP_TIMEOUT_SECONDS", "10"))
except ValueError:
    _cf_tunnel_stop_timeout = 10
CLOUDFLARED_TUNNEL_STOP_TIMEOUT_SECONDS = max(2, min(30, _cf_tunnel_stop_timeout))
try:
    _docker_alert_scan_interval = int(os.getenv("DOCKER_ALERT_SCAN_INTERVAL_SECONDS", "8"))
except ValueError:
    _docker_alert_scan_interval = 8
DOCKER_ALERT_SCAN_INTERVAL_SECONDS = max(3, min(300, _docker_alert_scan_interval))
CLOUDFLARED_TUNNEL_LOG_PATH = os.path.join(LOG_DIR, "cloudflared_tunnel.log")
TERMINAL_PROTOCOL_V2_MARKER = "__DASH_TERM_PROTOCOL_V2__"

# 🤖 AI CONFIG
AI_PROVIDER = os.getenv("AI_PROVIDER", "gemini").lower()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")
NVIDIA_MODEL = os.getenv("NVIDIA_MODEL", "z-ai/glm-5.1")

# Initialize AI provider on startup
if AI_PROVIDER == "nvidia" and NVIDIA_API_KEY:
    print(f"[AI] NVIDIA provider configured with model {NVIDIA_MODEL}")
elif GEMINI_API_KEY and GEMINI_API_KEY != "YOUR_KEY":
    try:
        GeminiChat.configure()
        print(f"[AI] Gemini configured with model {GEMINI_MODEL}")
    except Exception as e:
        print(f"[AI] Warning: Gemini configuration failed: {e}")


class RunServiceRequest(BaseModel):
    name: str
    port: int | None = None
    command: str


class StopServiceRequest(BaseModel):
    name: str


class NotifyRequest(BaseModel):
    msg: str


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str


class UpdateUserRoleRequest(BaseModel):
    role: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class SaveServiceRequest(BaseModel):
    name: str
    port: int
    command: str


class SavePinnedPortRequest(BaseModel):
    port: int


class UpdatePinnedPortServiceRequest(BaseModel):
    service_name: str | None = None
    command: str | None = None
    setup_command: str | None = None
    workdir: str | None = None


class SaveTodoRequest(BaseModel):
    text: str


class UpdateTodoRequest(BaseModel):
    done: bool


class CreateAlertRuleRequest(BaseModel):
    metric_type: str
    threshold: float


class UpdateAlertRuleRequest(BaseModel):
    threshold: float | None = None
    enabled: bool | None = None


class CreateSshKeyRequest(BaseModel):
    ssh_user: str
    label: str
    public_key: str


class CreateCloudflaredRouteRequest(BaseModel):
    hostname: str
    service_port: int
    service_host: str = "127.0.0.1"
    service_scheme: str = "http"


class UpdateCloudflaredRouteRequest(BaseModel):
    hostname: str | None = None
    service_port: int | None = None
    service_host: str | None = None
    service_scheme: str | None = None


class DockerActionRequest(BaseModel):
    container_id: str
    action: str


class FileReadRequest(BaseModel):
    path: str


class FileWriteRequest(BaseModel):
    path: str
    content: str


class FileDeleteRequest(BaseModel):
    path: str


class CreateDirectoryRequest(BaseModel):
    path: str


class FilePermissionsRequest(BaseModel):
    path: str
    permissions: str


class GitCloneRequest(BaseModel):
    path: str
    repo_url: str
    folder_name: str | None = None


class DeployAppRequest(BaseModel):
    template_id: int | None = None
    app_name: str
    env_vars: dict[str, str] = {}
    port_override: int | None = None


class DeployedAppActionRequest(BaseModel):
    action: str


class GitHubAnalyzeRequest(BaseModel):
    repo_url: str
    branch: str = "main"


class GitHubDeployRequest(BaseModel):
    repo_url: str
    app_name: str
    branch: str = "main"
    env_vars: dict[str, str] = {}
    port_override: int | None = None
    port_overrides: dict[str, int] = {}


def normalize_service_name(name: str) -> str:
    allowed = "-_"
    cleaned = "".join(ch for ch in name if ch.isalnum() or ch in allowed).strip("-_")
    return cleaned or "service"


def run_docker_command(args: list[str], timeout: int = 60):
    commands = [
        ["docker", *args],
        ["sudo", "docker", *args],
    ]
    last_error = ""

    for command in commands:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            continue
        except Exception as e:
            last_error = str(e)
            continue

        if result.returncode == 0:
            return result

        stderr_text = (result.stderr or "").strip()
        stdout_text = (result.stdout or "").strip()
        lowered = f"{stderr_text}\n{stdout_text}".lower()

        if command[0] == "docker" and (
            "permission denied" in lowered
            or "cannot connect to the docker daemon" in lowered
        ):
            last_error = stderr_text or stdout_text
            continue

        raise HTTPException(
            status_code=500,
            detail=(stderr_text or stdout_text or "Docker command failed")[:500],
        )

    raise HTTPException(
        status_code=500,
        detail=(last_error or "Docker is not accessible for this user")[:500],
    )


def is_process_running(proc: subprocess.Popen | None) -> bool:
    return proc is not None and proc.poll() is None


def db_connect():
    return sqlite3.connect(USERS_DB_PATH)


def get_setting(key: str, default: str = "") -> str:
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else default


def set_setting(key: str, value: str):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
    conn.commit()
    conn.close()


def hash_password(password: str, salt: bytes | None = None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )
    return digest.hex(), salt.hex()


def verify_password(password: str, password_hash_hex: str, salt_hex: str):
    salt = bytes.fromhex(salt_hex)
    expected_digest = bytes.fromhex(password_hash_hex)
    candidate_digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )
    return hmac.compare_digest(candidate_digest, expected_digest)


def init_user_db():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_login_at INTEGER
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            expires_at REAL NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS pinned_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            port INTEGER NOT NULL,
            command TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS pinned_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port INTEGER NOT NULL UNIQUE,
            created_at INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT NOT NULL,
            done INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            timestamp INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric_type TEXT NOT NULL,
            threshold REAL NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ssh_public_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ssh_user TEXT NOT NULL,
            label TEXT NOT NULL,
            key_type TEXT NOT NULL,
            key_body TEXT NOT NULL,
            key_comment TEXT,
            fingerprint_sha256 TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            UNIQUE(ssh_user, fingerprint_sha256)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cloudflared_routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL UNIQUE,
            service_scheme TEXT NOT NULL,
            service_host TEXT NOT NULL,
            service_port INTEGER NOT NULL,
            created_by TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user', 'ai')),
            content TEXT NOT NULL,
            tools_used TEXT,
            action_initiated TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS app_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL,
            icon TEXT NOT NULL DEFAULT 'box',
            category TEXT NOT NULL DEFAULT 'general',
            compose_yaml TEXT NOT NULL,
            env_schema TEXT NOT NULL DEFAULT '[]',
            default_port INTEGER,
            created_at INTEGER NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS deployed_apps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            template_id INTEGER,
            status TEXT NOT NULL DEFAULT 'stopped',
            compose_path TEXT,
            ports TEXT NOT NULL DEFAULT '[]',
            env_vars TEXT NOT NULL DEFAULT '{}',
            container_ids TEXT NOT NULL DEFAULT '[]',
            created_by TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (template_id) REFERENCES app_templates(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS github_deployments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_name TEXT NOT NULL UNIQUE,
            repo_url TEXT NOT NULL,
            branch TEXT NOT NULL DEFAULT 'main',
            detected_type TEXT,
            detected_framework TEXT,
            detected_port INTEGER,
            env_vars TEXT NOT NULL DEFAULT '{}',
            deploy_path TEXT,
            compose_path TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            step_status TEXT NOT NULL DEFAULT '{}',
            container_ids TEXT NOT NULL DEFAULT '[]',
            logs TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )

    cur.execute("PRAGMA table_info(users)")
    user_columns = {row[1] for row in cur.fetchall()}
    if "last_login_at" not in user_columns:
        cur.execute("ALTER TABLE users ADD COLUMN last_login_at INTEGER")

    cur.execute("PRAGMA table_info(pinned_ports)")
    pp_columns = {row[1] for row in cur.fetchall()}
    for col, col_type in [
        ("service_name", "TEXT"),
        ("command", "TEXT"),
        ("setup_command", "TEXT"),
        ("workdir", "TEXT"),
    ]:
        if col not in pp_columns:
            cur.execute(f"ALTER TABLE pinned_ports ADD COLUMN {col} {col_type}")

    conn.commit()
    conn.close()

    try:
        os.chmod(USERS_DB_PATH, 0o600)
    except Exception:
        pass


DEFAULT_TEMPLATES = [
    {
        "name": "Nginx",
        "description": "High-performance web server and reverse proxy",
        "icon": "globe",
        "category": "web",
        "default_port": 80,
        "env_schema": json.dumps([
            {"key": "NGINX_HOST", "label": "Server Name", "default": "localhost"},
        ]),
        "compose_yaml": """services:
  nginx:
    image: nginx:alpine
    container_name: nginx-app
    ports:
      - "${PORT:-80}:80"
    volumes:
      - ./html:/usr/share/nginx/html
    restart: unless-stopped
""",
    },
    {
        "name": "Node.js",
        "description": "JavaScript runtime with Express.js starter",
        "icon": "code-2",
        "category": "dev",
        "default_port": 3000,
        "env_schema": json.dumps([
            {"key": "NODE_ENV", "label": "Environment", "default": "production"},
        ]),
        "compose_yaml": """services:
  node-app:
    image: node:20-alpine
    container_name: node-app
    ports:
      - "${PORT:-3000}:3000"
    working_dir: /app
    volumes:
      - ./app:/app
    command: sh -c "npm install && node index.js"
    restart: unless-stopped
""",
    },
    {
        "name": "Python",
        "description": "Python Flask/FastAPI application server",
        "icon": "terminal",
        "category": "dev",
        "default_port": 5000,
        "env_schema": json.dumps([
            {"key": "FLASK_ENV", "label": "Environment", "default": "production"},
            {"key": "PYTHONUNBUFFERED", "label": "Unbuffered Output", "default": "1"},
        ]),
        "compose_yaml": """services:
  python-app:
    image: python:3.12-slim
    container_name: python-app
    ports:
      - "${PORT:-5000}:5000"
    working_dir: /app
    volumes:
      - ./app:/app
    command: sh -c "pip install -r requirements.txt && python app.py"
    restart: unless-stopped
""",
    },
    {
        "name": "PostgreSQL",
        "description": "Advanced open-source relational database",
        "icon": "database",
        "category": "database",
        "default_port": 5432,
        "env_schema": json.dumps([
            {"key": "POSTGRES_USER", "label": "Username", "default": "admin"},
            {"key": "POSTGRES_PASSWORD", "label": "Password", "default": "changeme"},
            {"key": "POSTGRES_DB", "label": "Database Name", "default": "mydb"},
        ]),
        "compose_yaml": """services:
  postgres:
    image: postgres:16-alpine
    container_name: postgres-db
    ports:
      - "${PORT:-5432}:5432"
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-admin}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme}
      POSTGRES_DB: ${POSTGRES_DB:-mydb}
    volumes:
      - pgdata:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  pgdata:
""",
    },
    {
        "name": "Redis",
        "description": "In-memory data store for caching and queues",
        "icon": "zap",
        "category": "database",
        "default_port": 6379,
        "env_schema": json.dumps([
            {"key": "REDIS_PASSWORD", "label": "Password (optional)", "default": ""},
        ]),
        "compose_yaml": """services:
  redis:
    image: redis:7-alpine
    container_name: redis-cache
    ports:
      - "${PORT:-6379}:6379"
    command: redis-server ${REDIS_PASSWORD:+--requirepass $REDIS_PASSWORD}
    volumes:
      - redisdata:/data
    restart: unless-stopped

volumes:
  redisdata:
""",
    },
    {
        "name": "MySQL",
        "description": "Popular open-source relational database",
        "icon": "database",
        "category": "database",
        "default_port": 3306,
        "env_schema": json.dumps([
            {"key": "MYSQL_ROOT_PASSWORD", "label": "Root Password", "default": "changeme"},
            {"key": "MYSQL_DATABASE", "label": "Database Name", "default": "mydb"},
            {"key": "MYSQL_USER", "label": "Username", "default": "admin"},
            {"key": "MYSQL_PASSWORD", "label": "Password", "default": "changeme"},
        ]),
        "compose_yaml": """services:
  mysql:
    image: mysql:8
    container_name: mysql-db
    ports:
      - "${PORT:-3306}:3306"
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD:-changeme}
      MYSQL_DATABASE: ${MYSQL_DATABASE:-mydb}
      MYSQL_USER: ${MYSQL_USER:-admin}
      MYSQL_PASSWORD: ${MYSQL_PASSWORD:-changeme}
    volumes:
      - mysqldata:/var/lib/mysql
    restart: unless-stopped

volumes:
  mysqldata:
""",
    },
    {
        "name": "WordPress",
        "description": "Full WordPress site with MySQL and PHP",
        "icon": "layout",
        "category": "web",
        "default_port": 8080,
        "env_schema": json.dumps([
            {"key": "WORDPRESS_DB_USER", "label": "DB Username", "default": "wordpress"},
            {"key": "WORDPRESS_DB_PASSWORD", "label": "DB Password", "default": "wordpress"},
            {"key": "WORDPRESS_DB_NAME", "label": "DB Name", "default": "wordpress"},
        ]),
        "compose_yaml": """services:
  wordpress:
    image: wordpress:latest
    container_name: wordpress-site
    ports:
      - "${PORT:-8080}:80"
    environment:
      WORDPRESS_DB_HOST: wp-db
      WORDPRESS_DB_USER: ${WORDPRESS_DB_USER:-wordpress}
      WORDPRESS_DB_PASSWORD: ${WORDPRESS_DB_PASSWORD:-wordpress}
      WORDPRESS_DB_NAME: ${WORDPRESS_DB_NAME:-wordpress}
    volumes:
      - wpdata:/var/www/html
    depends_on:
      - wp-db
    restart: unless-stopped

  wp-db:
    image: mysql:8
    container_name: wordpress-db
    environment:
      MYSQL_DATABASE: ${WORDPRESS_DB_NAME:-wordpress}
      MYSQL_USER: ${WORDPRESS_DB_USER:-wordpress}
      MYSQL_PASSWORD: ${WORDPRESS_DB_PASSWORD:-wordpress}
      MYSQL_ROOT_PASSWORD: ${WORDPRESS_DB_PASSWORD:-wordpress}
    volumes:
      - wpdbdata:/var/lib/mysql
    restart: unless-stopped

volumes:
  wpdata:
  wpdbdata:
""",
    },
    {
        "name": "MongoDB",
        "description": "NoSQL document database",
        "icon": "database",
        "category": "database",
        "default_port": 27017,
        "env_schema": json.dumps([
            {"key": "MONGO_INITDB_ROOT_USERNAME", "label": "Username", "default": "admin"},
            {"key": "MONGO_INITDB_ROOT_PASSWORD", "label": "Password", "default": "changeme"},
        ]),
        "compose_yaml": """services:
  mongo:
    image: mongo:7
    container_name: mongodb
    ports:
      - "${PORT:-27017}:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME: ${MONGO_INITDB_ROOT_USERNAME:-admin}
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_INITDB_ROOT_PASSWORD:-changeme}
    volumes:
      - mongodata:/data/db
    restart: unless-stopped

volumes:
  mongodata:
""",
    },
]


def seed_app_templates():
    now = int(time.time())
    conn = db_connect()
    cur = conn.cursor()
    for t in DEFAULT_TEMPLATES:
        cur.execute(
            """INSERT OR IGNORE INTO app_templates (name, description, icon, category, compose_yaml, env_schema, default_port, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (t["name"], t["description"], t["icon"], t["category"], t["compose_yaml"], t["env_schema"], t["default_port"], now),
        )
    conn.commit()
    conn.close()


def list_app_templates():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT id, name, description, icon, category, compose_yaml, env_schema, default_port, created_at FROM app_templates ORDER BY category, name")
    rows = cur.fetchall()
    conn.close()
    return [
        {
            "id": r[0], "name": r[1], "description": r[2], "icon": r[3],
            "category": r[4], "compose_yaml": r[5],
            "env_schema": json.loads(r[6]) if r[6] else [],
            "default_port": r[7], "created_at": r[8],
        }
        for r in rows
    ]


def get_app_template(template_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT id, name, description, icon, category, compose_yaml, env_schema, default_port, created_at FROM app_templates WHERE id = ?", (template_id,))
    r = cur.fetchone()
    conn.close()
    if not r:
        return None
    return {
        "id": r[0], "name": r[1], "description": r[2], "icon": r[3],
        "category": r[4], "compose_yaml": r[5],
        "env_schema": json.loads(r[6]) if r[6] else [],
        "default_port": r[7], "created_at": r[8],
    }


def list_deployed_apps():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""SELECT da.id, da.name, da.template_id, da.status, da.compose_path,
                          da.ports, da.env_vars, da.container_ids, da.created_by, da.created_at,
                          t.name as template_name
                   FROM deployed_apps da LEFT JOIN app_templates t ON da.template_id = t.id
                   ORDER BY da.created_at DESC""")
    rows = cur.fetchall()
    conn.close()
    return [
        {
            "id": r[0], "name": r[1], "template_id": r[2], "status": r[3],
            "compose_path": r[4], "ports": json.loads(r[5]) if r[5] else [],
            "env_vars": json.loads(r[6]) if r[6] else {},
            "container_ids": json.loads(r[7]) if r[7] else [],
            "created_by": r[8], "created_at": r[9], "template_name": r[10],
        }
        for r in rows
    ]


def get_deployed_app(app_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""SELECT da.id, da.name, da.template_id, da.status, da.compose_path,
                          da.ports, da.env_vars, da.container_ids, da.created_by, da.created_at,
                          t.name as template_name
                   FROM deployed_apps da LEFT JOIN app_templates t ON da.template_id = t.id
                   WHERE da.id = ?""", (app_id,))
    r = cur.fetchone()
    conn.close()
    if not r:
        return None
    return {
        "id": r[0], "name": r[1], "template_id": r[2], "status": r[3],
        "compose_path": r[4], "ports": json.loads(r[5]) if r[5] else [],
        "env_vars": json.loads(r[6]) if r[6] else {},
        "container_ids": json.loads(r[7]) if r[7] else [],
        "created_by": r[8], "created_at": r[9], "template_name": r[10],
    }


def create_deployed_app(name: str, template_id: int | None, compose_path: str, ports: list, env_vars: dict, created_by: str):
    now = int(time.time())
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO deployed_apps (name, template_id, status, compose_path, ports, env_vars, container_ids, created_by, created_at)
           VALUES (?, ?, 'stopped', ?, ?, ?, '[]', ?, ?)""",
        (name, template_id, compose_path, json.dumps(ports), json.dumps(env_vars), created_by, now),
    )
    conn.commit()
    app_id = cur.lastrowid
    conn.close()
    return app_id


def update_deployed_app_status(app_id: int, status: str, container_ids: list | None = None):
    conn = db_connect()
    cur = conn.cursor()
    if container_ids is not None:
        cur.execute("UPDATE deployed_apps SET status = ?, container_ids = ? WHERE id = ?", (status, json.dumps(container_ids), app_id))
    else:
        cur.execute("UPDATE deployed_apps SET status = ? WHERE id = ?", (status, app_id))
    conn.commit()
    conn.close()


def delete_deployed_app(app_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM deployed_apps WHERE id = ?", (app_id,))
    deleted = cur.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def get_user_record(username: str):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "SELECT username, password_hash, salt, role, created_at, last_login_at FROM users WHERE username = ?",
        (username,),
    )
    row = cur.fetchone()
    conn.close()
    return row


def create_user_record(username: str, password: str, role: str, overwrite: bool = False):
    password_hash, salt = hash_password(password)
    now = int(time.time())

    conn = db_connect()
    cur = conn.cursor()

    if overwrite:
        cur.execute(
            """
            INSERT INTO users(username, password_hash, salt, role, created_at, last_login_at)
            VALUES(?, ?, ?, ?, ?, NULL)
            ON CONFLICT(username)
            DO UPDATE SET password_hash=excluded.password_hash, salt=excluded.salt, role=excluded.role
            """,
            (username, password_hash, salt, role, now),
        )
    else:
        cur.execute(
            "INSERT INTO users(username, password_hash, salt, role, created_at, last_login_at) VALUES(?, ?, ?, ?, ?, NULL)",
            (username, password_hash, salt, role, now),
        )

    conn.commit()
    conn.close()


def list_users():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT username, role, created_at, last_login_at FROM users ORDER BY username")
    rows = cur.fetchall()
    conn.close()

    return [
        {
            "username": row[0],
            "role": row[1],
            "created_at": row[2],
            "last_login_at": row[3],
        }
        for row in rows
    ]


def update_user_last_login(username: str):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("UPDATE users SET last_login_at = ? WHERE username = ?", (int(time.time()), username))
    conn.commit()
    conn.close()


def count_admin_users() -> int:
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    count = cur.fetchone()[0]
    conn.close()
    return count


def update_user_role(username: str, role: str) -> bool:
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
    updated = cur.rowcount
    conn.commit()
    conn.close()
    return updated > 0


def delete_user_record(username: str) -> bool:
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted > 0


def list_pinned_services():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT id, name, port, command, created_at FROM pinned_services ORDER BY id")
    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "name": row[1],
            "port": row[2],
            "command": row[3],
            "created_at": row[4],
        }
        for row in rows
    ]


def create_pinned_service(name: str, port: int, command: str):
    now = int(time.time())

    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO pinned_services(name, port, command, created_at) VALUES(?, ?, ?, ?)",
        (name, port, command, now),
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()

    return {
        "id": new_id,
        "name": name,
        "port": port,
        "command": command,
        "created_at": now,
    }


def delete_pinned_service(service_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM pinned_services WHERE id = ?", (service_id,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted > 0


def list_pinned_ports():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT id, port, created_at, service_name, command, setup_command, workdir FROM pinned_ports ORDER BY id")
    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "port": row[1],
            "created_at": row[2],
            "service_name": row[3],
            "command": row[4],
            "setup_command": row[5],
            "workdir": row[6],
        }
        for row in rows
    ]


def create_pinned_port(port: int):
    now = int(time.time())

    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO pinned_ports(port, created_at) VALUES(?, ?)",
        (port, now),
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()

    return {
        "id": new_id,
        "port": port,
        "created_at": now,
    }


def delete_pinned_port(pin_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM pinned_ports WHERE id = ?", (pin_id,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted > 0


def get_pinned_port(pin_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT id, port, created_at, service_name, command, setup_command, workdir FROM pinned_ports WHERE id = ?", (pin_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "port": row[1],
        "created_at": row[2],
        "service_name": row[3],
        "command": row[4],
        "setup_command": row[5],
        "workdir": row[6],
    }


def update_pinned_port_service(pin_id: int, service_name: str | None, command: str | None, setup_command: str | None, workdir: str | None):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "UPDATE pinned_ports SET service_name = ?, command = ?, setup_command = ?, workdir = ? WHERE id = ?",
        (service_name, command, setup_command, workdir, pin_id),
    )
    updated = cur.rowcount
    conn.commit()
    conn.close()
    return updated > 0


def list_process_ids_by_port(port: int):
    pids = set()
    try:
        connections = psutil.net_connections(kind="inet")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to inspect processes for port {port}: {str(e)}")

    for conn in connections:
        laddr = getattr(conn, "laddr", None)
        if not laddr:
            continue

        try:
            local_port = laddr.port if hasattr(laddr, "port") else laddr[1]
        except Exception:
            continue

        if local_port == port and conn.pid:
            pids.add(int(conn.pid))

    return sorted(pids)


def terminate_processes_for_port(port: int):
    found_pids = list_process_ids_by_port(port)
    if not found_pids:
        return {
            "found_pids": [],
            "terminated_pids": [],
            "killed_pids": [],
        }

    processes = []
    for pid in found_pids:
        try:
            processes.append(psutil.Process(pid))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    for proc in processes:
        try:
            proc.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    gone, alive = psutil.wait_procs(processes, timeout=3)

    terminated_pids = [proc.pid for proc in gone]
    killed_pids = []

    for proc in alive:
        try:
            proc.kill()
            killed_pids.append(proc.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return {
        "found_pids": found_pids,
        "terminated_pids": sorted(set(terminated_pids)),
        "killed_pids": sorted(set(killed_pids)),
    }


def list_todos():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT id, text, done, created_at FROM todos ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "text": row[1],
            "done": bool(row[2]),
            "created_at": row[3],
        }
        for row in rows
    ]


def create_todo(text: str):
    now = int(time.time())

    conn = db_connect()
    cur = conn.cursor()
    cur.execute("INSERT INTO todos(text, done, created_at) VALUES(?, 0, ?)", (text, now))
    new_id = cur.lastrowid
    conn.commit()
    conn.close()

    return {
        "id": new_id,
        "text": text,
        "done": False,
        "created_at": now,
    }


def update_todo_done(todo_id: int, done: bool):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("UPDATE todos SET done = ? WHERE id = ?", (1 if done else 0, todo_id))
    updated = cur.rowcount
    conn.commit()
    conn.close()
    return updated > 0


def delete_todo(todo_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted > 0


def log_audit(username: str, action: str, details: str = None):
    """Log an audit event to the audit_logs table"""
    now = int(time.time())
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO audit_logs(username, action, details, timestamp) VALUES(?, ?, ?, ?)",
        (username, action, details, now),
    )
    conn.commit()
    conn.close()


def list_audit_logs(limit: int = 100, offset: int = 0):
    """Retrieve audit logs with pagination"""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, action, details, timestamp FROM audit_logs ORDER BY id DESC LIMIT ? OFFSET ?",
        (limit, offset),
    )
    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "username": row[1],
            "action": row[2],
            "details": row[3],
            "timestamp": row[4],
        }
        for row in rows
    ]


def create_alert_rule(metric_type: str, threshold: float):
    """Create a new alert rule"""
    now = int(time.time())
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO alert_rules(metric_type, threshold, enabled, created_at) VALUES(?, ?, 1, ?)",
        (metric_type, threshold, now),
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()

    return {
        "id": new_id,
        "metric_type": metric_type,
        "threshold": threshold,
        "enabled": True,
        "created_at": now,
    }


def list_alert_rules():
    """List all alert rules"""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT id, metric_type, threshold, enabled, created_at FROM alert_rules ORDER BY id")
    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "metric_type": row[1],
            "threshold": row[2],
            "enabled": bool(row[3]),
            "created_at": row[4],
        }
        for row in rows
    ]


def update_alert_rule(rule_id: int, threshold: float = None, enabled: bool = None):
    """Update an alert rule"""
    conn = db_connect()
    cur = conn.cursor()

    if threshold is not None and enabled is not None:
        cur.execute(
            "UPDATE alert_rules SET threshold = ?, enabled = ? WHERE id = ?",
            (threshold, 1 if enabled else 0, rule_id),
        )
    elif threshold is not None:
        cur.execute(
            "UPDATE alert_rules SET threshold = ? WHERE id = ?",
            (threshold, rule_id),
        )
    elif enabled is not None:
        cur.execute(
            "UPDATE alert_rules SET enabled = ? WHERE id = ?",
            (1 if enabled else 0, rule_id),
        )

    updated = cur.rowcount
    conn.commit()
    conn.close()
    return updated > 0


def delete_alert_rule(rule_id: int):
    """Delete an alert rule"""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted > 0


def parse_public_ssh_key(public_key: str):
    cleaned = " ".join((public_key or "").replace("\n", " ").replace("\r", " ").split())
    if not cleaned:
        raise HTTPException(status_code=400, detail="Public key is required")

    parts = cleaned.split(" ", 2)
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="Invalid SSH public key format")

    key_type = parts[0].strip()
    key_body = parts[1].strip()
    key_comment = parts[2].strip() if len(parts) > 2 else ""

    if key_type not in SUPPORTED_SSH_KEY_TYPES:
        raise HTTPException(status_code=400, detail=f"Unsupported SSH key type: {key_type}")

    try:
        padding = "=" * (-len(key_body) % 4)
        raw_key = base64.b64decode(key_body + padding, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid SSH key payload (base64 decode failed)")

    if not raw_key:
        raise HTTPException(status_code=400, detail="Invalid SSH key payload")

    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(raw_key).digest()).decode("utf-8").rstrip("=")

    key_comment = " ".join(key_comment.split())
    normalized_key = f"{key_type} {key_body}" + (f" {key_comment}" if key_comment else "")

    return {
        "key_type": key_type,
        "key_body": key_body,
        "key_comment": key_comment,
        "fingerprint_sha256": fingerprint,
        "normalized_key": normalized_key,
    }


def list_ssh_public_keys(ssh_user: str | None = None):
    conn = db_connect()
    cur = conn.cursor()

    if ssh_user:
        cur.execute(
            """
            SELECT id, ssh_user, label, key_type, key_comment, fingerprint_sha256, created_by, created_at
            FROM ssh_public_keys
            WHERE ssh_user = ?
            ORDER BY id DESC
            """,
            (ssh_user,),
        )
    else:
        cur.execute(
            """
            SELECT id, ssh_user, label, key_type, key_comment, fingerprint_sha256, created_by, created_at
            FROM ssh_public_keys
            ORDER BY id DESC
            """
        )

    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "ssh_user": row[1],
            "label": row[2],
            "key_type": row[3],
            "key_comment": row[4] or "",
            "fingerprint_sha256": row[5],
            "created_by": row[6],
            "created_at": row[7],
        }
        for row in rows
    ]


def list_ssh_public_key_rows_for_user(ssh_user: str):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, key_type, key_body, key_comment
        FROM ssh_public_keys
        WHERE ssh_user = ?
        ORDER BY id ASC
        """,
        (ssh_user,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_ssh_public_key_record(key_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, ssh_user, label, key_type, key_body, key_comment, fingerprint_sha256, created_by, created_at
        FROM ssh_public_keys
        WHERE id = ?
        """,
        (key_id,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None

    return {
        "id": row[0],
        "ssh_user": row[1],
        "label": row[2],
        "key_type": row[3],
        "key_body": row[4],
        "key_comment": row[5] or "",
        "fingerprint_sha256": row[6],
        "created_by": row[7],
        "created_at": row[8],
    }


def create_ssh_public_key_record(
    ssh_user: str,
    label: str,
    key_type: str,
    key_body: str,
    key_comment: str,
    fingerprint_sha256: str,
    created_by: str,
):
    now = int(time.time())
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO ssh_public_keys(
            ssh_user,
            label,
            key_type,
            key_body,
            key_comment,
            fingerprint_sha256,
            created_by,
            created_at
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (ssh_user, label, key_type, key_body, key_comment, fingerprint_sha256, created_by, now),
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()

    return {
        "id": new_id,
        "ssh_user": ssh_user,
        "label": label,
        "key_type": key_type,
        "key_comment": key_comment,
        "fingerprint_sha256": fingerprint_sha256,
        "created_by": created_by,
        "created_at": now,
    }


def delete_ssh_public_key_record(key_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM ssh_public_keys WHERE id = ?", (key_id,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted > 0


def restore_ssh_public_key_record(record: dict):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO ssh_public_keys(
            id,
            ssh_user,
            label,
            key_type,
            key_body,
            key_comment,
            fingerprint_sha256,
            created_by,
            created_at
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record["id"],
            record["ssh_user"],
            record["label"],
            record["key_type"],
            record["key_body"],
            record["key_comment"],
            record["fingerprint_sha256"],
            record["created_by"],
            record["created_at"],
        ),
    )
    conn.commit()
    conn.close()


def remove_managed_ssh_block(content: str) -> str:
    pattern = re.compile(
        rf"\n?{re.escape(SSH_MANAGED_BLOCK_BEGIN)}.*?{re.escape(SSH_MANAGED_BLOCK_END)}\n?",
        re.DOTALL,
    )
    cleaned = re.sub(pattern, "\n", content)
    return cleaned.strip("\n")


def build_managed_ssh_block(ssh_user: str) -> str:
    key_rows = list_ssh_public_key_rows_for_user(ssh_user)
    if not key_rows:
        return ""

    lines = [SSH_MANAGED_BLOCK_BEGIN]
    for row in key_rows:
        key_id, key_type, key_body, key_comment = row
        label_comment = f" dashboard-key-id:{key_id}"
        key_line = f"{key_type} {key_body}"
        if key_comment:
            key_line += f" {key_comment}"
        key_line += label_comment
        lines.append(key_line)
    lines.append(SSH_MANAGED_BLOCK_END)
    return "\n".join(lines)


def sync_managed_ssh_keys(ssh_user: str):
    if pwd is None:
        raise HTTPException(
            status_code=501,
            detail="SSH key deployment is supported only on Unix/Linux hosts",
        )

    try:
        user_info = pwd.getpwnam(ssh_user)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Linux user '{ssh_user}' not found on this server")

    home_dir = user_info.pw_dir
    ssh_dir = os.path.join(home_dir, ".ssh")
    authorized_keys_path = os.path.join(ssh_dir, "authorized_keys")

    os.makedirs(ssh_dir, mode=0o700, exist_ok=True)

    existing = ""
    if os.path.exists(authorized_keys_path):
        with open(authorized_keys_path, "r", encoding="utf-8", errors="replace") as f:
            existing = f.read()

    cleaned = remove_managed_ssh_block(existing)
    managed_block = build_managed_ssh_block(ssh_user)

    if cleaned and managed_block:
        merged = f"{cleaned}\n\n{managed_block}\n"
    elif managed_block:
        merged = f"{managed_block}\n"
    elif cleaned:
        merged = f"{cleaned}\n"
    else:
        merged = ""

    tmp_path = authorized_keys_path + ".tmp-dashboard"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(merged)

    os.replace(tmp_path, authorized_keys_path)

    try:
        os.chmod(ssh_dir, 0o700)
        os.chmod(authorized_keys_path, 0o600)
    except Exception:
        pass

    try:
        os.chown(ssh_dir, user_info.pw_uid, user_info.pw_gid)
        os.chown(authorized_keys_path, user_info.pw_uid, user_info.pw_gid)
    except Exception:
        # Not running as root or unsupported environment.
        pass


def normalize_cloudflared_hostname(hostname: str) -> str:
    normalized = (hostname or "").strip().lower().rstrip(".")
    if not normalized or not CLOUDFLARED_HOSTNAME_PATTERN.match(normalized):
        raise HTTPException(status_code=400, detail="Invalid hostname (example: app.example.com)")
    return normalized


def normalize_cloudflared_service_host(service_host: str) -> str:
    normalized = (service_host or "").strip().lower()
    if not normalized:
        normalized = "127.0.0.1"

    if any(ch in normalized for ch in (" ", "/", ":", "\n", "\r", "\x00")):
        raise HTTPException(status_code=400, detail="Invalid local service host")

    if not CLOUDFLARED_SERVICE_HOST_PATTERN.match(normalized):
        raise HTTPException(status_code=400, detail="Invalid local service host")

    return normalized


def normalize_cloudflared_service_scheme(service_scheme: str) -> str:
    normalized = (service_scheme or "http").strip().lower()
    if normalized not in SUPPORTED_CLOUDFLARED_SCHEMES:
        raise HTTPException(status_code=400, detail="service_scheme must be http, https, or tcp")
    return normalized


def list_cloudflared_routes():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, hostname, service_scheme, service_host, service_port, created_by, created_at
        FROM cloudflared_routes
        ORDER BY id DESC
        """
    )
    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "hostname": row[1],
            "service_scheme": row[2],
            "service_host": row[3],
            "service_port": row[4],
            "created_by": row[5],
            "created_at": row[6],
        }
        for row in rows
    ]


def list_cloudflared_route_rows():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, hostname, service_scheme, service_host, service_port
        FROM cloudflared_routes
        ORDER BY id ASC
        """
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_cloudflared_route_record(route_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, hostname, service_scheme, service_host, service_port, created_by, created_at
        FROM cloudflared_routes
        WHERE id = ?
        """,
        (route_id,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None

    return {
        "id": row[0],
        "hostname": row[1],
        "service_scheme": row[2],
        "service_host": row[3],
        "service_port": row[4],
        "created_by": row[5],
        "created_at": row[6],
    }


def create_cloudflared_route_record(
    hostname: str,
    service_scheme: str,
    service_host: str,
    service_port: int,
    created_by: str,
):
    now = int(time.time())
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO cloudflared_routes(
            hostname,
            service_scheme,
            service_host,
            service_port,
            created_by,
            created_at
        )
        VALUES(?, ?, ?, ?, ?, ?)
        """,
        (hostname, service_scheme, service_host, service_port, created_by, now),
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()

    return {
        "id": new_id,
        "hostname": hostname,
        "service_scheme": service_scheme,
        "service_host": service_host,
        "service_port": service_port,
        "created_by": created_by,
        "created_at": now,
    }


def delete_cloudflared_route_record(route_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM cloudflared_routes WHERE id = ?", (route_id,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted > 0


def update_cloudflared_route_record(
    route_id: int,
    hostname: str,
    service_scheme: str,
    service_host: str,
    service_port: int,
):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE cloudflared_routes
        SET hostname = ?, service_scheme = ?, service_host = ?, service_port = ?
        WHERE id = ?
        """,
        (hostname, service_scheme, service_host, service_port, route_id),
    )
    updated = cur.rowcount
    conn.commit()
    conn.close()
    return updated > 0


def restore_cloudflared_route_record(record: dict):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO cloudflared_routes(
            id,
            hostname,
            service_scheme,
            service_host,
            service_port,
            created_by,
            created_at
        )
        VALUES(?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record["id"],
            record["hostname"],
            record["service_scheme"],
            record["service_host"],
            record["service_port"],
            record["created_by"],
            record["created_at"],
        ),
    )
    conn.commit()
    conn.close()


def remove_managed_cloudflared_block(content: str) -> str:
    lines = content.splitlines()
    cleaned_lines = []
    inside_managed_block = False

    for line in lines:
        stripped = line.strip()

        if stripped == CLOUDFLARED_MANAGED_BLOCK_BEGIN:
            inside_managed_block = True
            continue

        if stripped == CLOUDFLARED_MANAGED_BLOCK_END:
            inside_managed_block = False
            continue

        if not inside_managed_block:
            cleaned_lines.append(line)

    return "\n".join(cleaned_lines).strip("\n")


def normalize_cloudflared_ingress_indentation(config_content: str) -> str:
    ingress_header_pattern = re.compile(r"^\s*ingress\s*:\s*(?:#.*)?$")
    top_level_key_pattern = re.compile(r"^[A-Za-z0-9_-]+\s*:\s*(?:#.*)?$")

    lines = config_content.splitlines()
    normalized = []
    in_ingress = False

    for line in lines:
        stripped = line.strip()

        if not in_ingress:
            normalized.append(line)
            if ingress_header_pattern.match(line):
                in_ingress = True
            continue

        if stripped and not line.startswith(" ") and top_level_key_pattern.match(line):
            in_ingress = False
            normalized.append(line)
            continue

        if not stripped:
            normalized.append("")
            continue

        if stripped.startswith("#"):
            normalized.append(f"  {stripped}")
            continue

        if stripped.startswith("- "):
            normalized.append(f"  {stripped}")
            continue

        leading_spaces = len(line) - len(line.lstrip(" "))
        if leading_spaces < 4:
            normalized.append(f"    {stripped}")
        else:
            normalized.append(line)

    return "\n".join(normalized).strip("\n")


def build_managed_cloudflared_block() -> str:
    route_rows = list_cloudflared_route_rows()
    if not route_rows:
        return ""

    lines = [f"  {CLOUDFLARED_MANAGED_BLOCK_BEGIN}"]
    for row in route_rows:
        route_id, hostname, service_scheme, service_host, service_port = row
        lines.append(f"  # dashboard-route-id:{route_id}")
        lines.append(f"  - hostname: {hostname}")
        lines.append(f"    service: {service_scheme}://{service_host}:{service_port}")
    lines.append(f"  {CLOUDFLARED_MANAGED_BLOCK_END}")
    return "\n".join(lines)


def insert_managed_cloudflared_block(config_content: str, managed_block: str) -> str:
    ingress_pattern = re.compile(r"^\s*ingress\s*:\s*(?:#.*)?$")
    lines = config_content.splitlines()
    output = []
    inserted = False

    for line in lines:
        output.append(line)
        if not inserted and ingress_pattern.match(line):
            inserted = True
            if managed_block:
                output.append(managed_block)

    if not inserted:
        if output:
            output.append("")
        output.append("ingress:")
        if managed_block:
            output.append(managed_block)
        output.append("  - service: http_status:404")

    return "\n".join(output).strip("\n") + "\n"


def remove_unmanaged_cloudflared_hostname_items(config_content: str, hostnames_to_remove):
    targets = {
        (hostname or "").strip().lower().rstrip(".")
        for hostname in (hostnames_to_remove or [])
        if (hostname or "").strip()
    }
    if not targets:
        return config_content

    ingress_header_pattern = re.compile(r"^\s*ingress\s*:\s*(?:#.*)?$")
    top_level_key_pattern = re.compile(r"^[A-Za-z0-9_-]+\s*:\s*(?:#.*)?$")
    hostname_line_pattern = re.compile(r"^\s*-\s*hostname\s*:\s*(.+?)\s*(?:#.*)?$")
    item_start_pattern = re.compile(r"^\s*-\s+")

    lines = config_content.splitlines()
    output = []
    in_ingress = False
    item_buffer = []
    item_hostname = None
    item_indent = 0

    def flush_item():
        nonlocal item_buffer, item_hostname, item_indent
        if not item_buffer:
            return
        if item_hostname not in targets:
            output.extend(item_buffer)
        item_buffer = []
        item_hostname = None
        item_indent = 0

    for line in lines:
        stripped = line.strip()

        if not in_ingress:
            output.append(line)
            if ingress_header_pattern.match(line):
                in_ingress = True
            continue

        if stripped and not line.startswith(" ") and top_level_key_pattern.match(line):
            flush_item()
            in_ingress = False
            output.append(line)
            continue

        is_item_start = bool(item_start_pattern.match(line))
        if is_item_start:
            flush_item()
            item_buffer = [line]
            item_indent = len(line) - len(line.lstrip(" "))
            host_match = hostname_line_pattern.match(line)
            item_hostname = (
                host_match.group(1).strip().strip('"').strip("'").lower().rstrip(".")
                if host_match
                else None
            )
            continue

        if item_buffer:
            if not stripped:
                item_buffer.append(line)
                continue

            current_indent = len(line) - len(line.lstrip(" "))
            if current_indent > item_indent:
                item_buffer.append(line)
                continue

            flush_item()

        output.append(line)

    flush_item()
    return "\n".join(output).strip("\n")


def parse_cloudflared_tunnel_name_from_config(config_path: str) -> str | None:
    if not config_path or not os.path.exists(config_path):
        return None

    try:
        with open(config_path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("tunnel:"):
                    value = line.split(":", 1)[1].strip().strip('"').strip("'")
                    return value or None
    except Exception:
        return None

    return None


def get_cloudflared_candidate_config_paths(config_path: str | None = None):
    if config_path:
        return [os.path.abspath(config_path)]

    return [
        os.path.abspath(active_cloudflared_config_path),
        os.path.abspath(CLOUDFLARED_CONFIG_PATH),
        os.path.abspath(CLOUDFLARED_FALLBACK_CONFIG_PATH),
    ]


def parse_cloudflared_config_entries(config_path: str | None = None, include_managed: bool = True):
    candidate_paths = get_cloudflared_candidate_config_paths(config_path)
    seen_paths = set()

    ingress_header_pattern = re.compile(r"^\s*ingress\s*:\s*(?:#.*)?$")
    top_level_key_pattern = re.compile(r"^[A-Za-z0-9_-]+\s*:\s*(?:#.*)?$")
    hostname_line_pattern = re.compile(r"^\s*-\s*hostname\s*:\s*(.+?)\s*(?:#.*)?$")
    service_line_pattern = re.compile(r"^\s*service\s*:\s*(.+?)\s*(?:#.*)?$")

    for path in candidate_paths:
        if not path or path in seen_paths:
            continue
        seen_paths.add(path)

        if not os.path.exists(path):
            continue

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except Exception:
            if config_path:
                return []
            continue

        in_ingress = False
        in_managed = False
        current = None
        entries = []

        def _flush_current():
            nonlocal current
            if not current:
                return
            if current.get("hostname") and current.get("service"):
                if include_managed or not current.get("managed"):
                    entries.append(
                        {
                            "hostname": current["hostname"],
                            "service": current["service"],
                            "managed": bool(current.get("managed")),
                            "config_path": path,
                        }
                    )
            current = None

        for line in lines:
            stripped = line.strip()

            if stripped == CLOUDFLARED_MANAGED_BLOCK_BEGIN:
                in_managed = True
                continue
            if stripped == CLOUDFLARED_MANAGED_BLOCK_END:
                in_managed = False
                continue

            if not in_ingress:
                if ingress_header_pattern.match(line):
                    in_ingress = True
                continue

            if stripped and not line.startswith(" ") and top_level_key_pattern.match(line):
                _flush_current()
                in_ingress = False
                continue

            host_match = hostname_line_pattern.match(line)
            if host_match:
                _flush_current()
                hostname = host_match.group(1).strip().strip('"').strip("'").lower().rstrip(".")
                current = {
                    "hostname": hostname,
                    "service": None,
                    "managed": in_managed,
                } if hostname else None
                continue

            if current:
                service_match = service_line_pattern.match(line)
                if service_match:
                    service_value = service_match.group(1).strip().strip('"').strip("'")
                    if service_value:
                        current["service"] = service_value
                elif stripped.startswith("- "):
                    _flush_current()

        _flush_current()
        return entries

    return []


def list_cloudflared_config_hostnames(config_path: str | None = None):
    entries = parse_cloudflared_config_entries(config_path=config_path, include_managed=True)
    hostnames = []
    seen = set()
    for entry in entries:
        hostname = entry.get("hostname")
        if not hostname or hostname in seen:
            continue
        seen.add(hostname)
        hostnames.append(hostname)
    return hostnames


def parse_cloudflared_service_target(service_value: str):
    raw = (service_value or "").strip()
    matched = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://([^:/\s]+):(\d{1,5})$", raw)
    if not matched:
        return None

    return {
        "scheme": matched.group(1).lower(),
        "host": matched.group(2).strip().lower(),
        "port": int(matched.group(3)),
        "raw": raw,
    }


def resolve_cloudflared_active_config_path(config_path: str | None = None) -> str:
    global active_cloudflared_config_path

    candidates = get_cloudflared_candidate_config_paths(config_path)
    seen = set()

    for candidate in candidates:
        abs_path = os.path.abspath(candidate)
        if abs_path in seen:
            continue
        seen.add(abs_path)
        if os.path.exists(abs_path):
            active_cloudflared_config_path = abs_path
            return abs_path

    fallback = os.path.abspath(config_path) if config_path else os.path.abspath(CLOUDFLARED_CONFIG_PATH)
    active_cloudflared_config_path = fallback
    return fallback


def sync_existing_cloudflared_routes_from_config(config_path: str | None = None):
    active_path = resolve_cloudflared_active_config_path(config_path)
    config_entries = parse_cloudflared_config_entries(config_path=active_path, include_managed=True)
    if not config_entries:
        return {
            "config_path": active_path,
            "checked": 0,
            "updated": 0,
        }

    existing_routes = list_cloudflared_routes()
    routes_by_hostname = {
        (item.get("hostname") or "").strip().lower().rstrip("."): item
        for item in existing_routes
        if item.get("hostname")
    }

    checked_count = 0
    updated_count = 0

    for entry in config_entries:
        hostname = (entry.get("hostname") or "").strip().lower().rstrip(".")
        service_value = (entry.get("service") or "").strip()

        if not hostname or hostname not in routes_by_hostname:
            continue

        parsed_service = parse_cloudflared_service_target(service_value)
        if not parsed_service:
            continue

        try:
            normalized_scheme = normalize_cloudflared_service_scheme(parsed_service["scheme"])
            normalized_host = normalize_cloudflared_service_host(parsed_service["host"])
            normalized_port = int(parsed_service["port"])
        except HTTPException:
            continue
        except Exception:
            continue

        if normalized_port < 1 or normalized_port > 65535:
            continue

        current = routes_by_hostname[hostname]
        checked_count += 1

        if (
            current["service_scheme"] == normalized_scheme
            and current["service_host"] == normalized_host
            and int(current["service_port"]) == normalized_port
        ):
            continue

        changed = update_cloudflared_route_record(
            route_id=current["id"],
            hostname=current["hostname"],
            service_scheme=normalized_scheme,
            service_host=normalized_host,
            service_port=normalized_port,
        )
        if changed:
            current["service_scheme"] = normalized_scheme
            current["service_host"] = normalized_host
            current["service_port"] = normalized_port
            updated_count += 1

    return {
        "config_path": active_path,
        "checked": checked_count,
        "updated": updated_count,
    }


def get_cloudflared_tunnel_name() -> str | None:
    if CLOUDFLARED_TUNNEL_NAME:
        return CLOUDFLARED_TUNNEL_NAME

    candidate_paths = [
        active_cloudflared_config_path,
        os.path.abspath(CLOUDFLARED_CONFIG_PATH),
        os.path.abspath(CLOUDFLARED_FALLBACK_CONFIG_PATH),
    ]

    seen = set()
    for path in candidate_paths:
        if path in seen:
            continue
        seen.add(path)
        tunnel_name = parse_cloudflared_tunnel_name_from_config(path)
        if tunnel_name:
            return tunnel_name

    return None


def is_cloudflared_cli_available() -> bool:
    if os.path.sep in CLOUDFLARED_BIN_PATH:
        return os.path.exists(CLOUDFLARED_BIN_PATH) and os.access(CLOUDFLARED_BIN_PATH, os.X_OK)
    return shutil.which(CLOUDFLARED_BIN_PATH) is not None


def _is_cloudflared_tunnel_process(cmdline: list[str], process_name: str = "") -> bool:
    cmd_tokens = [str(token).strip().lower() for token in (cmdline or []) if str(token).strip()]
    cmd_joined = " ".join(cmd_tokens)
    process_name = (process_name or "").strip().lower()
    configured_bin = os.path.basename(CLOUDFLARED_BIN_PATH).strip().lower()

    is_cloudflared_binary = (
        "cloudflared" in process_name
        or "cloudflared" in cmd_joined
        or (configured_bin and configured_bin in cmd_joined)
    )
    if not is_cloudflared_binary:
        return False

    has_tunnel_run_tokens = "tunnel" in cmd_tokens and "run" in cmd_tokens
    has_tunnel_run_phrase = " tunnel " in f" {cmd_joined} " and " run " in f" {cmd_joined} "
    return has_tunnel_run_tokens or has_tunnel_run_phrase


def list_cloudflared_tunnel_processes(tunnel_name: str | None = None):
    expected_tunnel = (tunnel_name or "").strip().lower()
    processes = []

    for proc in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
        try:
            info = proc.info
            cmdline = info.get("cmdline") or []
            process_name = info.get("name") or ""

            if not _is_cloudflared_tunnel_process(cmdline, process_name):
                continue

            command = " ".join(str(part) for part in cmdline)
            if expected_tunnel and expected_tunnel not in command.lower():
                continue

            processes.append(
                {
                    "pid": int(info.get("pid")),
                    "command": command,
                    "started_at": int(info.get("create_time") or 0),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    processes.sort(key=lambda item: item["pid"])
    return processes


def stop_cloudflared_tunnel_processes(tunnel_name: str | None = None):
    matched = list_cloudflared_tunnel_processes(tunnel_name)
    if not matched:
        return []

    pid_to_process = {}
    for item in matched:
        pid = item["pid"]
        try:
            pid_to_process[pid] = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    for process in pid_to_process.values():
        try:
            process.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    gone, alive = psutil.wait_procs(
        list(pid_to_process.values()),
        timeout=CLOUDFLARED_TUNNEL_STOP_TIMEOUT_SECONDS,
    )

    stopped_pids = [proc.pid for proc in gone]

    for process in alive:
        try:
            process.kill()
            stopped_pids.append(process.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return sorted(set(stopped_pids))


def start_cloudflared_tunnel_process(tunnel_name: str, config_path: str):
    tunnel_name = (tunnel_name or "").strip()
    if not tunnel_name:
        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to determine Cloudflared tunnel name. Set CLOUDFLARED_TUNNEL_NAME "
                "or add 'tunnel: <name-or-uuid>' in your cloudflared config file."
            ),
        )

    if not is_cloudflared_cli_available():
        raise HTTPException(
            status_code=500,
            detail=(
                "Cloudflared CLI not found. Install cloudflared or set CLOUDFLARED_BIN_PATH "
                "to the executable path."
            ),
        )

    active_config = os.path.abspath(config_path or active_cloudflared_config_path)
    command = [
        CLOUDFLARED_BIN_PATH,
        "--config",
        active_config,
        "tunnel",
        "run",
        tunnel_name,
    ]

    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(CLOUDFLARED_TUNNEL_LOG_PATH, "a", encoding="utf-8") as logfile:
            logfile.write(f"\n===== CLOUDFLARED START: {tunnel_name} @ {int(time.time())} =====\n")
            logfile.flush()
            proc = subprocess.Popen(
                command,
                stdout=logfile,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                text=True,
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start Cloudflared tunnel process: {str(e)}")

    return {
        "pid": proc.pid,
        "command": " ".join(command),
        "log_path": os.path.abspath(CLOUDFLARED_TUNNEL_LOG_PATH),
    }


def ensure_cloudflared_dns_route(hostname: str):
    if not CLOUDFLARED_DNS_AUTO_ROUTE:
        return {
            "dns_routed": False,
            "dns_message": "Auto DNS route creation is disabled",
            "tunnel_name": get_cloudflared_tunnel_name(),
        }

    if not is_cloudflared_cli_available():
        raise HTTPException(
            status_code=500,
            detail=(
                "Cloudflared CLI not found. Install cloudflared or set CLOUDFLARED_BIN_PATH "
                "to the executable path."
            ),
        )

    tunnel_name = get_cloudflared_tunnel_name()
    if not tunnel_name:
        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to determine Cloudflared tunnel name. Set CLOUDFLARED_TUNNEL_NAME "
                "or add 'tunnel: <name-or-uuid>' in your cloudflared config file."
            ),
        )

    tmp_config_path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yml", delete=False) as tmp_file:
            tmp_file.write(f"tunnel: {tunnel_name}\n")
            tmp_config_path = tmp_file.name

        result = subprocess.run(
            [
                CLOUDFLARED_BIN_PATH,
                "--config",
                tmp_config_path,
                "tunnel",
                "route",
                "dns",
                tunnel_name,
                hostname,
            ],
            capture_output=True,
            text=True,
            timeout=CLOUDFLARED_DNS_ROUTE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Timed out while creating Cloudflared DNS route")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to execute cloudflared DNS route command: {str(e)}")
    finally:
        if tmp_config_path:
            try:
                os.remove(tmp_config_path)
            except Exception:
                pass

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "cloudflared DNS route failed").strip()
        if "already exists" in detail.lower():
            return {
                "dns_routed": True,
                "dns_message": "DNS route already existed",
                "tunnel_name": tunnel_name,
            }
        raise HTTPException(
            status_code=500,
            detail=(
                f"Failed to create DNS route for '{hostname}' via tunnel '{tunnel_name}': "
                f"{detail[:500]}"
            ),
        )

    return {
        "dns_routed": True,
        "dns_message": "DNS route created",
        "tunnel_name": tunnel_name,
    }


def sync_managed_cloudflared_routes_to_path(config_path: str, cleanup_hostnames: set[str] | None = None):
    config_path = os.path.abspath(config_path)
    config_dir = os.path.dirname(config_path)
    if config_dir:
        os.makedirs(config_dir, mode=0o755, exist_ok=True)

    existing = ""
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8", errors="replace") as f:
            existing = f.read()

    cleaned = remove_managed_cloudflared_block(existing)
    if cleanup_hostnames:
        cleaned = remove_unmanaged_cloudflared_hostname_items(cleaned, cleanup_hostnames)
    normalized = normalize_cloudflared_ingress_indentation(cleaned)
    managed_block = build_managed_cloudflared_block()
    merged = insert_managed_cloudflared_block(normalized, managed_block)

    tmp_path = config_path + ".tmp-dashboard"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(merged)

    os.replace(tmp_path, config_path)
    return config_path


def sync_managed_cloudflared_routes(cleanup_hostnames: set[str] | None = None):
    global active_cloudflared_config_path

    primary_path = os.path.abspath(CLOUDFLARED_CONFIG_PATH)
    fallback_path = os.path.abspath(CLOUDFLARED_FALLBACK_CONFIG_PATH)

    candidates = [primary_path]
    if fallback_path != primary_path:
        candidates.append(fallback_path)

    permission_denied_paths = []

    for candidate in candidates:
        try:
            used_path = sync_managed_cloudflared_routes_to_path(candidate, cleanup_hostnames=cleanup_hostnames)
            active_cloudflared_config_path = used_path
            return used_path
        except PermissionError:
            permission_denied_paths.append(candidate)
        except OSError as e:
            if getattr(e, "errno", None) == 13:
                permission_denied_paths.append(candidate)
            else:
                raise

    if permission_denied_paths:
        tried = ", ".join(permission_denied_paths)
        raise HTTPException(
            status_code=500,
            detail=(
                "Permission denied while writing Cloudflared config. "
                f"Tried: {tried}. "
                "Set CLOUDFLARED_CONFIG_PATH (or CLOUDFLARED_FALLBACK_CONFIG_PATH) to a writable path."
            ),
        )

    raise HTTPException(status_code=500, detail="Failed to write Cloudflared config")


def is_safe_path(path: str) -> bool:
    """Check if path is safe (no traversal into critical restricted areas)"""
    try:
        abs_path = os.path.abspath(path)

        # Prevent access to sensitive system directories
        forbidden_paths = ["/etc/shadow", "/etc/passwd", "/root", "/proc", "/sys"]
        for forbidden in forbidden_paths:
            if abs_path.startswith(forbidden):
                return False

        # Allow full filesystem access excluding the forbidden ones
        return True
    except Exception:
        return False


def get_file_info(path: str):
    """Get file information"""
    try:
        stat_info = os.stat(path)
        return {
            "name": os.path.basename(path),
            "path": path,
            "is_directory": os.path.isdir(path),
            "is_file": os.path.isfile(path),
            "size": stat_info.st_size,
            "modified": int(stat_info.st_mtime),
            "permissions": oct(stat_info.st_mode)[-3:],
            "readable": os.access(path, os.R_OK),
            "writable": os.access(path, os.W_OK),
        }
    except Exception as e:
        return None


def list_directory(path: str):
    """List directory contents"""
    try:
        if not os.path.isdir(path):
            return None

        items = []
        for item in sorted(os.listdir(path)):
            item_path = os.path.join(path, item)
            info = get_file_info(item_path)
            if info:
                items.append(info)

        return items
    except Exception as e:
        return None


def suggest_git_clone_folder_name(repo_url: str) -> str:
    cleaned = (repo_url or "").strip().rstrip("/")
    if not cleaned:
        return "repo-clone"

    tail = cleaned.split("/")[-1].strip()
    if tail.endswith(".git"):
        tail = tail[:-4]

    sanitized = re.sub(r"[^A-Za-z0-9._-]", "-", tail).strip(".-_")
    return sanitized or "repo-clone"


# ──────────────────────────────────────────────────────────────────
#  GITHUB DEPLOY — DB helpers
# ──────────────────────────────────────────────────────────────────

def create_github_deployment(app_name, repo_url, branch, deploy_path, created_by):
    now = int(time.time())
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO github_deployments
           (app_name, repo_url, branch, deploy_path, status, step_status, created_by, created_at)
           VALUES (?, ?, ?, ?, 'pending', '{}', ?, ?)""",
        (app_name, repo_url, branch, deploy_path, created_by, now),
    )
    deploy_id = cur.lastrowid
    conn.commit()
    conn.close()
    return deploy_id


def get_github_deployment(deploy_id):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM github_deployments WHERE id = ?", (deploy_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    cols = [d[0] for d in cur.description] if cur.description else []
    return dict(zip(cols, row))


def get_github_deployment_by_name(app_name):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM github_deployments WHERE app_name = ?", (app_name,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    cols = [d[0] for d in cur.description] if cur.description else []
    return dict(zip(cols, row))


def update_github_deployment_status(deploy_id, status, step_status=None, container_ids=None):
    conn = db_connect()
    cur = conn.cursor()
    if step_status is not None and container_ids is not None:
        cur.execute(
            "UPDATE github_deployments SET status=?, step_status=?, container_ids=? WHERE id=?",
            (status, json.dumps(step_status), json.dumps(container_ids), deploy_id),
        )
    elif step_status is not None:
        cur.execute(
            "UPDATE github_deployments SET status=?, step_status=? WHERE id=?",
            (status, json.dumps(step_status), deploy_id),
        )
    else:
        cur.execute("UPDATE github_deployments SET status=? WHERE id=?", (status, deploy_id))
    conn.commit()
    conn.close()


def update_github_deployment_fields(deploy_id, **fields):
    if not fields:
        return
    sets = []
    vals = []
    for k, v in fields.items():
        if k in ("detected_type", "detected_framework", "detected_port", "env_vars",
                 "compose_path", "logs", "container_ids", "step_status", "status"):
            sets.append(f"{k} = ?")
            vals.append(v)
    if not sets:
        return
    vals.append(deploy_id)
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(f"UPDATE github_deployments SET {', '.join(sets)} WHERE id = ?", vals)
    conn.commit()
    conn.close()


def list_github_deployments():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM github_deployments ORDER BY created_at DESC")
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description] if cur.description else []
    conn.close()
    return [dict(zip(cols, r)) for r in rows]


def delete_github_deployment(deploy_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM github_deployments WHERE id = ?", (deploy_id,))
    deleted = cur.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


# ──────────────────────────────────────────────────────────────────
#  GITHUB DEPLOY — Project detection engine
# ──────────────────────────────────────────────────────────────────

def _read_file_safe(path, max_bytes=65536):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes)
    except Exception:
        return ""


def _scan_env_file(repo_path):
    env_vars = []
    for name in (".env.example", ".env.sample", ".env.template"):
        p = os.path.join(repo_path, name)
        if os.path.isfile(p):
            content = _read_file_safe(p)
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, default = line.partition("=")
                    env_vars.append({"key": key.strip(), "default": default.strip().strip('"').strip("'")})
            return env_vars, name
    return [], None


def parse_compose_services(compose_path: str) -> list[dict]:
    try:
        with open(compose_path, "r") as f:
            data = yaml.safe_load(f)
    except Exception:
        return []

    if not data or not isinstance(data, dict):
        return []

    services = []
    for svc_name, svc_config in (data.get("services") or {}).items():
        if not isinstance(svc_config, dict):
            continue

        ports = []
        for p in svc_config.get("ports") or []:
            if isinstance(p, str):
                parts = p.split(":")
                if len(parts) == 2:
                    try:
                        ports.append({"host": int(parts[0]), "container": int(parts[1])})
                    except ValueError:
                        ports.append({"host": None, "container": parts[1]})
                elif len(parts) == 3:
                    try:
                        ports.append({"host": int(parts[1]), "container": int(parts[2])})
                    except ValueError:
                        ports.append({"host": None, "container": parts[2]})
            elif isinstance(p, dict):
                try:
                    host = int(p.get("published", 0)) if p.get("published") else None
                except (ValueError, TypeError):
                    host = None
                try:
                    container = int(p.get("target", 0)) if p.get("target") else None
                except (ValueError, TypeError):
                    container = None
                ports.append({"host": host, "container": container})

        env_vars = []
        env = svc_config.get("environment") or {}
        if isinstance(env, dict):
            for k, v in env.items():
                env_vars.append({"key": k, "value": str(v) if v is not None else ""})
        elif isinstance(env, list):
            for item in env:
                if isinstance(item, str) and "=" in item:
                    k, v = item.split("=", 1)
                    env_vars.append({"key": k.strip(), "value": v.strip()})

        depends_on = svc_config.get("depends_on") or {}
        if isinstance(depends_on, dict):
            depends_on = list(depends_on.keys())
        elif isinstance(depends_on, list):
            depends_on = [d if isinstance(d, str) else "" for d in depends_on]
        else:
            depends_on = []

        services.append({
            "name": svc_name,
            "image": svc_config.get("image"),
            "build": svc_config.get("build"),
            "ports": ports,
            "env_vars": env_vars,
            "depends_on": depends_on,
            "has_env_file": bool(svc_config.get("env_file")),
        })

    return services


def apply_port_overrides(compose_path: str, port_overrides: dict[str, int]) -> str | None:
    try:
        with open(compose_path, "r") as f:
            data = yaml.safe_load(f)
    except Exception:
        return None

    if not data or not isinstance(data, dict):
        return None

    changed = False
    for svc_name, new_port in port_overrides.items():
        svc = (data.get("services") or {}).get(svc_name)
        if not svc or not isinstance(svc, dict):
            continue
        ports = svc.get("ports")
        if not isinstance(ports, list):
            continue
        for i, p in enumerate(ports):
            if isinstance(p, str):
                parts = p.split(":")
                container_port = parts[-1]
                if len(parts) == 2:
                    ports[i] = f"{new_port}:{container_port}"
                    changed = True
                elif len(parts) == 3:
                    parts[1] = str(new_port)
                    ports[i] = ":".join(parts)
                    changed = True
            elif isinstance(p, dict):
                p["published"] = str(new_port)
                changed = True

    if not changed:
        return None

    return yaml.dump(data, default_flow_style=False)


def _detect_python(repo_path):
    framework = "none"
    port = 8000
    entry = "main.py"
    deps_file = None
    start_cmd = None

    for f in ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile"):
        if os.path.isfile(os.path.join(repo_path, f)):
            deps_file = f
            break

    candidates = ("main.py", "app.py", "server.py", "wsgi.py", "manage.py")
    for c in candidates:
        if os.path.isfile(os.path.join(repo_path, c)):
            entry = c
            break

    content = _read_file_safe(os.path.join(repo_path, entry))
    if "from fastapi" in content or "FastAPI()" in content:
        framework = "fastapi"
        port = 8000
        start_cmd = f"uvicorn main:app --host 0.0.0.0 --port {port}"
    elif "from flask" in content or "Flask(__name__)" in content:
        framework = "flask"
        port = 5000
        start_cmd = f"python {entry}"
    elif "from django" in content:
        framework = "django"
        port = 8000
        start_cmd = f"python manage.py runserver 0.0.0.0:{port}"
    else:
        start_cmd = f"python {entry}"

    return {
        "type": "python",
        "framework": framework,
        "port": port,
        "start_command": start_cmd,
        "build_command": None,
        "dependencies_file": deps_file,
        "entry_point": entry,
    }


def _detect_node(repo_path):
    framework = "none"
    port = 3000
    start_cmd = "node index.js"
    build_cmd = None
    pkg_path = os.path.join(repo_path, "package.json")
    content = _read_file_safe(pkg_path)
    if not content:
        return None

    try:
        pkg = json.loads(content)
    except Exception:
        return None

    all_deps = {}
    all_deps.update(pkg.get("dependencies", {}))
    all_deps.update(pkg.get("devDependencies", {}))
    scripts = pkg.get("scripts", {})

    if "next" in all_deps:
        framework = "nextjs"
        port = 3000
        build_cmd = "npm run build"
        start_cmd = "npm start"
    elif "nuxt" in all_deps:
        framework = "nuxt"
        port = 3000
        build_cmd = "npm run build"
        start_cmd = "npm start"
    elif "express" in all_deps:
        framework = "express"
        port = 3000
        start_cmd = scripts.get("start", "node index.js")
    elif "@vue/cli-service" in all_deps or "vue" in all_deps:
        framework = "vue"
        port = 8080
        build_cmd = "npm run build"
        start_cmd = "npm run serve"
    elif "react-scripts" in all_deps or "react" in all_deps:
        framework = "react"
        port = 3000
        build_cmd = "npm run build"
        start_cmd = "npm start"
    elif "start" in scripts:
        start_cmd = "npm start"

    return {
        "type": "node",
        "framework": framework,
        "port": port,
        "start_command": start_cmd,
        "build_command": build_cmd,
        "dependencies_file": "package.json",
        "entry_point": pkg.get("main", "index.js"),
    }


def _detect_go(repo_path):
    return {
        "type": "go",
        "framework": "none",
        "port": 8080,
        "start_command": "./app",
        "build_command": "go build -o app .",
        "dependencies_file": "go.mod",
        "entry_point": "main.go",
    }


def _detect_rust(repo_path):
    return {
        "type": "rust",
        "framework": "none",
        "port": 8080,
        "start_command": "./target/release/app",
        "build_command": "cargo build --release",
        "dependencies_file": "Cargo.toml",
        "entry_point": "src/main.rs",
    }


def detect_project_type(repo_path):
    files = set(os.listdir(repo_path)) if os.path.isdir(repo_path) else set()

    has_dockerfile = "Dockerfile" in files
    has_compose = any(f in files for f in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"))
    env_vars, env_file = _scan_env_file(repo_path)

    result = None

    if "requirements.txt" in files or "pyproject.toml" in files or "setup.py" in files or "Pipfile" in files:
        result = _detect_python(repo_path)
    elif "package.json" in files:
        result = _detect_node(repo_path)
    elif "go.mod" in files:
        result = _detect_go(repo_path)
    elif "Cargo.toml" in files:
        result = _detect_rust(repo_path)
    elif "index.html" in files and "package.json" not in files:
        result = {
            "type": "static",
            "framework": "none",
            "port": 80,
            "start_command": None,
            "build_command": None,
            "dependencies_file": None,
            "entry_point": "index.html",
        }
    elif has_dockerfile or has_compose:
        result = {
            "type": "docker",
            "framework": "none",
            "port": 80,
            "start_command": None,
            "build_command": None,
            "dependencies_file": None,
            "entry_point": None,
        }
    else:
        result = {
            "type": "unknown",
            "framework": "none",
            "port": 80,
            "start_command": None,
            "build_command": None,
            "dependencies_file": None,
            "entry_point": None,
        }

    result["has_dockerfile"] = has_dockerfile
    result["has_compose"] = has_compose
    result["env_file"] = env_file
    result["env_vars"] = env_vars
    return result


# ──────────────────────────────────────────────────────────────────
#  GITHUB DEPLOY — Dockerfile / Compose generators
# ──────────────────────────────────────────────────────────────────

def generate_dockerfile(detected, repo_path):
    if detected.get("has_dockerfile"):
        return _read_file_safe(os.path.join(repo_path, "Dockerfile"))

    dtype = detected["type"]
    port = detected["port"]
    fw = detected.get("framework", "none")

    if dtype == "python":
        deps = detected.get("dependencies_file", "requirements.txt")
        if fw == "fastapi":
            cmd = f'CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "{port}"]'
        elif fw == "flask":
            entry = detected.get("entry_point", "app.py")
            cmd = f'CMD ["python", "{entry}"]'
        elif fw == "django":
            cmd = f'CMD ["python", "manage.py", "runserver", "0.0.0.0:{port}"]'
        else:
            entry = detected.get("entry_point", "main.py")
            cmd = f'CMD ["python", "{entry}"]'

        return f"""FROM python:3.12-slim
WORKDIR /app
COPY {deps} .
RUN pip install --no-cache-dir -r {deps}
COPY . .
EXPOSE {port}
{cmd}
"""

    if dtype == "node":
        lines = [
            "FROM node:20-alpine",
            "WORKDIR /app",
            "COPY package*.json ./",
            "RUN npm install",
            "COPY . .",
        ]
        if detected.get("build_command"):
            lines.append(f"RUN {detected['build_command']}")
        lines.append(f"EXPOSE {port}")
        lines.append(f'CMD ["sh", "-c", "{detected["start_command"]}"]')
        return "\n".join(lines) + "\n"

    if dtype == "static":
        return """FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE 80
"""

    if dtype == "go":
        return f"""FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o app .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/app .
EXPOSE {port}
CMD ["./app"]
"""

    if dtype == "rust":
        return f"""FROM rust:1.77 AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/app .
EXPOSE {port}
CMD ["./app"]
"""

    return f"""FROM ubuntu:22.04
WORKDIR /app
COPY . .
EXPOSE {port}
CMD ["echo", "No start command detected — edit this Dockerfile"]
"""


def generate_compose_yaml(app_name, detected, port):
    internal_port = detected["port"]
    return f"""services:
  {app_name}:
    build: .
    container_name: {app_name}
    ports:
      - "{port}:{internal_port}"
    restart: unless-stopped
"""


# ──────────────────────────────────────────────────────────────────
#  GITHUB DEPLOY — Pipeline runner
# ──────────────────────────────────────────────────────────────────

def run_github_deploy_pipeline(deploy_id):
    dep = get_github_deployment(deploy_id)
    if not dep:
        return

    app_name = dep["app_name"]
    repo_url = dep["repo_url"]
    branch = dep.get("branch", "main")
    deploy_path = dep["deploy_path"]
    env_vars = json.loads(dep.get("env_vars", "{}"))
    port_override = env_vars.pop("__port_override__", None)
    port_overrides_str = env_vars.pop("__port_overrides__", None)
    port_overrides = json.loads(port_overrides_str) if port_overrides_str else {}

    steps = {
        "clone": "pending",
        "detect": "pending",
        "configure": "pending",
        "build": "pending",
        "deploy": "pending",
        "health": "pending",
    }

    def _fail(step, msg):
        steps[step] = "failed"
        update_github_deployment_status(deploy_id, "failed", steps)
        update_github_deployment_fields(deploy_id, logs=dep.get("logs", "") + f"\n[FAIL] {step}: {msg}")

    def _log(msg):
        current = dep.get("logs", "")
        dep["logs"] = current + f"\n{msg}"
        update_github_deployment_fields(deploy_id, logs=dep["logs"])

    try:
        # Step 1: Clone
        steps["clone"] = "running"
        update_github_deployment_status(deploy_id, "cloning", steps)
        _log(f"[clone] Cloning {repo_url} (branch: {branch})...")

        # Clone into a temp directory to avoid Windows file lock issues
        tmp_clone = tempfile.mkdtemp(prefix="gh-clone-")
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "-b", branch, repo_url, tmp_clone],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode != 0:
                _fail("clone", (result.stderr or result.stdout or "clone failed")[:300])
                safe_rmtree(tmp_clone, ignore_errors=True)
                return
        except subprocess.TimeoutExpired:
            safe_rmtree(tmp_clone, ignore_errors=True)
            _fail("clone", "Clone timed out after 300 seconds")
            return

        _log("[clone] Repository cloned to temp directory.")

        # Copy temp clone into deploy_path (overwrites existing files safely)
        os.makedirs(deploy_path, exist_ok=True)
        copied_count = 0
        for item in os.listdir(tmp_clone):
            if item == ".git":
                continue
            src = os.path.join(tmp_clone, item)
            dst = os.path.join(deploy_path, item)
            if os.path.isdir(src):
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dst)
            copied_count += 1
        _log(f"[clone] Copied {copied_count} items to deployment directory.")
        safe_rmtree(tmp_clone, ignore_errors=True)

        steps["clone"] = "done"
        _log("[clone] Done.")

        # Step 2: Detect
        steps["detect"] = "running"
        update_github_deployment_status(deploy_id, "detecting", steps)
        _log("[detect] Analyzing project...")
        detected = detect_project_type(deploy_path)
        steps["detect"] = "done"
        _log(f"[detect] Type={detected['type']}, Framework={detected['framework']}, Port={detected['port']}")

        update_github_deployment_fields(
            deploy_id,
            detected_type=detected["type"],
            detected_framework=detected["framework"],
            detected_port=detected["port"],
        )

        # Step 3: Configure
        steps["configure"] = "running"
        update_github_deployment_status(deploy_id, "configuring", steps)
        _log("[configure] Setting up Docker configuration...")

        port = port_override or detected["port"]

        # Write Dockerfile only if repo doesn't have one
        dockerfile_content = generate_dockerfile(detected, deploy_path)
        if not detected.get("has_dockerfile"):
            with open(os.path.join(deploy_path, "Dockerfile"), "w") as f:
                f.write(dockerfile_content)
            _log("[configure] Generated Dockerfile.")
        else:
            _log("[configure] Using existing Dockerfile.")

        # Check for existing docker-compose.yml in the cloned repo
        compose_path = None
        for candidate in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            p = os.path.join(deploy_path, candidate)
            if os.path.exists(p):
                compose_path = p
                break

        if compose_path:
            _log(f"[configure] Found existing {os.path.basename(compose_path)} — preserving it.")

            # Apply per-service port overrides if the user changed any
            if port_overrides:
                _log(f"[configure] Applying port overrides: {port_overrides}")
                modified = apply_port_overrides(compose_path, port_overrides)
                if modified:
                    with open(compose_path, "w") as f:
                        f.write(modified)
                    _log("[configure] Port overrides applied.")
                else:
                    _log("[configure] No port overrides needed or could not apply.")
        else:
            compose_content = generate_compose_yaml(app_name, detected, port)
            compose_path = os.path.join(deploy_path, "docker-compose.yml")
            with open(compose_path, "w") as f:
                f.write(compose_content)
            _log("[configure] Generated docker-compose.yml.")

        # Write .env from user-supplied environment variables
        if env_vars:
            env_lines = []
            for k, v in env_vars.items():
                env_lines.append(f"{k}={v}")
            with open(os.path.join(deploy_path, ".env"), "w") as f:
                f.write("\n".join(env_lines) + "\n")
            _log(f"[configure] Wrote .env with {len(env_vars)} variables.")

        steps["configure"] = "done"
        update_github_deployment_fields(deploy_id, compose_path=compose_path)
        _log("[configure] Done.")

        # Step 4: Build
        steps["build"] = "running"
        update_github_deployment_status(deploy_id, "building", steps)
        _log("[build] Building Docker image (this may take a while)...")

        build_result = _run_docker_compose(compose_path, ["build"], timeout=600)
        steps["build"] = "done"
        _log("[build] Build complete.")

        # Step 5: Deploy
        steps["deploy"] = "running"
        update_github_deployment_status(deploy_id, "deploying", steps)
        _log("[deploy] Starting containers...")

        deploy_result = _run_docker_compose(compose_path, ["up", "-d"], timeout=180)
        steps["deploy"] = "done"
        _log("[deploy] Containers started.")

        # Step 6: Health
        steps["health"] = "running"
        update_github_deployment_status(deploy_id, "health_check", steps)
        _log("[health] Checking container health...")

        time.sleep(3)
        container_ids = _get_compose_container_ids(compose_path)

        if container_ids:
            steps["health"] = "done"
            update_github_deployment_status(deploy_id, "running", steps, container_ids)
            _log(f"[health] OK — {len(container_ids)} container(s) running.")
        else:
            steps["health"] = "failed"
            update_github_deployment_status(deploy_id, "failed", steps)
            _log("[health] No containers found after deploy.")

    except subprocess.TimeoutExpired as e:
        _fail("build" if steps["build"] == "running" else "clone", f"Timeout: {e}")
    except Exception as e:
        current_step = [k for k, v in steps.items() if v == "running"]
        step_name = current_step[0] if current_step else "unknown"
        _fail(step_name, str(e)[:300])


# ──────────────────────────────────────────────────────────────────
#  Bootstrap / init
# ──────────────────────────────────────────────────────────────────

def bootstrap_admin_user():
    admin_username = os.getenv("ADMIN_USERNAME", "admin").strip()
    admin_password = os.getenv("ADMIN_PASSWORD", "admin123")

    if len(admin_password) < 8:
        raise RuntimeError("ADMIN_PASSWORD must be at least 8 characters")

    existing = get_user_record(admin_username)
    if not existing:
        create_user_record(admin_username, admin_password, "admin", overwrite=False)


init_user_db()
bootstrap_admin_user()
seed_app_templates()

# Load active sessions from DB into memory (survives --reload)
try:
    now = time.time()
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT token, username, role, expires_at FROM sessions WHERE expires_at > ?", (now,))
    for row in cur.fetchall():
        active_sessions[row[0]] = {"username": row[1], "role": row[2], "expires_at": row[3]}
    # Clean expired
    cur.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
    conn.commit()
    conn.close()
    print(f"[sessions] Loaded {len(active_sessions)} active session(s) from DB")
except Exception as e:
    print(f"[sessions] Could not load from DB: {e}")


def create_session(username: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = time.time() + SESSION_TIMEOUT_SECONDS
    session = {"username": username, "role": role, "expires_at": expires_at}
    active_sessions[token] = session
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO sessions (token, username, role, expires_at) VALUES (?, ?, ?, ?)",
                    (token, username, role, expires_at))
        conn.commit()
        conn.close()
    except Exception:
        pass
    return token


def _load_session_from_db(session_id: str) -> dict | None:
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute("SELECT username, role, expires_at FROM sessions WHERE token = ?", (session_id,))
        row = cur.fetchone()
        conn.close()
        if row:
            return {"username": row[0], "role": row[1], "expires_at": row[2]}
    except Exception:
        pass
    return None


def _save_session_to_db(token: str, username: str, role: str, expires_at: float):
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO sessions (token, username, role, expires_at) VALUES (?, ?, ?, ?)",
                    (token, username, role, expires_at))
        conn.commit()
        conn.close()
    except Exception:
        pass


def _delete_session_from_db(token: str):
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_current_user(
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
):
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    session = active_sessions.get(session_id)
    if not session:
        session = _load_session_from_db(session_id)
        if session:
            active_sessions[session_id] = session

    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")

    now = time.time()
    if session["expires_at"] < now:
        active_sessions.pop(session_id, None)
        _delete_session_from_db(session_id)
        raise HTTPException(status_code=401, detail="Session expired")

    session["expires_at"] = now + SESSION_TIMEOUT_SECONDS
    _save_session_to_db(session_id, session["username"], session["role"], session["expires_at"])

    return {
        "username": session["username"],
        "role": session["role"],
        "session_id": session_id,
        "expires_at": session["expires_at"],
    }


def require_role(min_role: str):
    min_rank = ROLE_ORDER[min_role]

    def _checker(user=Depends(get_current_user)):
        user_rank = ROLE_ORDER.get(user["role"], 0)
        if user_rank < min_rank:
            raise HTTPException(
                status_code=403,
                detail=f"{min_role} role required",
            )
        return user

    return _checker


def get_valid_session(session_id: str | None):
    if not session_id:
        return None

    session = active_sessions.get(session_id)
    if not session:
        session = _load_session_from_db(session_id)
        if session:
            active_sessions[session_id] = session

    if not session:
        return None

    now = time.time()
    if session["expires_at"] < now:
        active_sessions.pop(session_id, None)
        _delete_session_from_db(session_id)
        return None

    session["expires_at"] = now + SESSION_TIMEOUT_SECONDS
    _save_session_to_db(session_id, session["username"], session["role"], session["expires_at"])
    return session


def update_sessions_for_user(username: str, new_role: str | None = None, delete: bool = False):
    to_remove = []
    for token, session in active_sessions.items():
        if session.get("username") == username:
            if delete:
                to_remove.append(token)
            elif new_role:
                session["role"] = new_role
                _save_session_to_db(token, session["username"], session["role"], session["expires_at"])

    for token in to_remove:
        active_sessions.pop(token, None)
        _delete_session_from_db(token)

    # Also update/delete in DB for sessions not in cache
    try:
        conn = db_connect()
        cur = conn.cursor()
        if delete:
            cur.execute("DELETE FROM sessions WHERE username = ?", (username,))
        elif new_role:
            cur.execute("UPDATE sessions SET role = ? WHERE username = ?", (new_role, username))
        conn.commit()
        conn.close()
    except Exception:
        pass


def send_telegram(msg):
    try:
        if SERVER_NAME:
            msg = f"🖥️ [{SERVER_NAME}]\n{msg}"
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        requests.post(url, json={"chat_id": CHAT_ID, "text": msg})
    except Exception as e:
        print("Telegram error:", e)


def list_docker_container_snapshots():
    result = run_docker_command(
        [
            "ps",
            "-a",
            "--format",
            "{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|{{.Status}}|{{.Ports}}",
        ],
        timeout=30,
    )
    output = (result.stdout or "").strip().split("\n")

    containers = []
    for line in output:
        if not line:
            continue

        parts = line.split("|", 5)
        if len(parts) < 6:
            continue

        container_id, name, image, state, status, ports = parts
        containers.append(
            {
                "id": container_id,
                "name": name,
                "image": image,
                "state": state,
                "status": status,
                "ports": ports,
            }
        )

    return containers


def parse_docker_exit_code(status_text: str):
    if not status_text:
        return None

    matched = re.search(r"exited\s*\(([-]?\d+)\)", status_text, re.IGNORECASE)
    if not matched:
        return None

    try:
        return int(matched.group(1))
    except ValueError:
        return None


def docker_container_has_error(snapshot: dict) -> bool:
    state = (snapshot.get("state") or "").strip().lower()
    status = (snapshot.get("status") or "").strip().lower()

    if state in {"dead", "restarting"}:
        return True

    if "unhealthy" in status or "error" in status:
        return True

    exit_code = parse_docker_exit_code(status)
    return exit_code is not None and exit_code != 0


def format_docker_ports_for_alert(snapshot: dict) -> str:
    ports = (snapshot.get("ports") or "").strip()
    return ports if ports else "no published ports"


def check_docker_container_alerts(force: bool = False):
    """Send Telegram alerts for Docker container start/stop/error transitions."""
    global docker_container_alert_state, docker_last_alert_scan_at

    now = time.time()
    if not force and (now - docker_last_alert_scan_at) < DOCKER_ALERT_SCAN_INTERVAL_SECONDS:
        return
    docker_last_alert_scan_at = now

    try:
        snapshots = list_docker_container_snapshots()
    except Exception as e:
        print("Docker alert check error:", e)
        return

    current_by_id = {}

    for raw_snapshot in snapshots:
        container_id = (raw_snapshot.get("id") or "").strip()
        if not container_id:
            continue

        snapshot = {
            "id": container_id,
            "name": (raw_snapshot.get("name") or "").strip(),
            "image": (raw_snapshot.get("image") or "").strip(),
            "state": (raw_snapshot.get("state") or "").strip(),
            "status": (raw_snapshot.get("status") or "").strip(),
            "ports": (raw_snapshot.get("ports") or "").strip(),
        }
        current_by_id[container_id] = snapshot

        previous = docker_container_alert_state.get(container_id)
        if not previous:
            continue

        previous_state = (previous.get("state") or "").strip().lower()
        current_state = (snapshot.get("state") or "").strip().lower()

        started = previous_state != "running" and current_state == "running"
        stopped = previous_state == "running" and current_state != "running"
        previous_error = docker_container_has_error(previous)
        current_error = docker_container_has_error(snapshot)

        display_name = snapshot["name"] or container_id[:12]
        ports_text = format_docker_ports_for_alert(snapshot if snapshot.get("ports") else previous)

        if started:
            send_telegram(
                f"✅ Docker Started: {display_name} ({container_id[:12]}) is running. Ports: {ports_text}"
            )

        if stopped:
            if current_error:
                send_telegram(
                    (
                        f"🚨 Docker Error: {display_name} ({container_id[:12]}) stopped with an error. "
                        f"State: {snapshot['state'] or 'unknown'}, Status: {snapshot['status'] or 'unknown'}, "
                        f"Ports: {ports_text}"
                    )
                )
            else:
                send_telegram(
                    (
                        f"⚠️ Docker Stopped: {display_name} ({container_id[:12]}) stopped. "
                        f"State: {snapshot['state'] or 'unknown'}, Status: {snapshot['status'] or 'unknown'}, "
                        f"Ports: {ports_text}"
                    )
                )
        elif current_error and not previous_error:
            send_telegram(
                (
                    f"🚨 Docker Error: {display_name} ({container_id[:12]}) entered error state. "
                    f"State: {snapshot['state'] or 'unknown'}, Status: {snapshot['status'] or 'unknown'}, "
                    f"Ports: {ports_text}"
                )
            )

    previous_ids = set(docker_container_alert_state.keys())
    current_ids = set(current_by_id.keys())
    removed_ids = previous_ids - current_ids

    for removed_id in removed_ids:
        previous = docker_container_alert_state.get(removed_id, {})
        previous_state = (previous.get("state") or "").strip().lower()
        if previous_state != "running":
            continue

        display_name = (previous.get("name") or "").strip() or removed_id[:12]
        ports_text = format_docker_ports_for_alert(previous)
        send_telegram(
            (
                f"⚠️ Docker Stopped: {display_name} ({removed_id[:12]}) is no longer running "
                f"(container removed or not found). Ports: {ports_text}"
            )
        )

    docker_container_alert_state = current_by_id


def is_local_port_active(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        return sock.connect_ex(("127.0.0.1", int(port))) == 0
    finally:
        sock.close()


def check_alert_rules(cpu_percent: float, ram_percent: float):
    """Check if any alert rules are triggered and send notifications"""
    global alert_last_sent

    try:
        rules = list_alert_rules()
        current_time = time.time()

        # Cooldown period: 5 minutes (300 seconds) to avoid spam
        ALERT_COOLDOWN = 300

        for rule in rules:
            if not rule["enabled"]:
                continue

            rule_id = rule["id"]
            metric_type = rule["metric_type"]
            threshold = rule["threshold"]

            # Check if threshold is exceeded
            current_value = cpu_percent if metric_type == "cpu" else ram_percent

            if current_value >= threshold:
                # Check if we've recently sent an alert for this rule
                last_sent = alert_last_sent.get(rule_id, 0)

                if current_time - last_sent >= ALERT_COOLDOWN:
                    # Send alert
                    metric_name = "CPU" if metric_type == "cpu" else "RAM"
                    msg = f"🚨 Alert: {metric_name} usage is {current_value:.1f}% (threshold: {threshold}%)"
                    send_telegram(msg)

                    # Update last sent time
                    alert_last_sent[rule_id] = current_time
            else:
                # Reset the alert if usage drops below threshold
                alert_last_sent.pop(rule_id, None)

    except Exception as e:
        print("Alert check error:", e)


def check_pinned_port_alerts():
    """Send Telegram alerts when a pinned port goes down (once per downtime event)."""
    global pinned_port_down_alert_state

    try:
        pinned_ports = list_pinned_ports()
        active_port_set = set()

        for pin in pinned_ports:
            port = int(pin["port"])
            if port < 1 or port > 65535:
                continue

            active_port_set.add(port)
            is_up = is_local_port_active(port)
            was_alerted_down = bool(pinned_port_down_alert_state.get(port, False))

            if not is_up and not was_alerted_down:
                send_telegram(f"🚨 Port Down: Pinned port {port} is not reachable on 127.0.0.1")
                pinned_port_down_alert_state[port] = True
                # Trigger AI auto-remediation
                if os.getenv("AI_AUTO_REMEDIATION", "").lower() in ("1", "true", "yes"):
                    try:
                        from ai.remediation import on_port_down
                        on_port_down(port=port)
                    except Exception:
                        pass
            elif is_up and was_alerted_down:
                send_telegram(f"✅ Port Up: Pinned port {port} is back online on 127.0.0.1")
                pinned_port_down_alert_state[port] = False

        # Cleanup state for ports that are no longer pinned.
        stale_ports = [port for port in pinned_port_down_alert_state.keys() if port not in active_port_set]
        for stale_port in stale_ports:
            pinned_port_down_alert_state.pop(stale_port, None)

    except Exception as e:
        print("Pinned port alert check error:", e)


@app.middleware("http")
async def restrict_docs_to_admin(request: Request, call_next):
    path = request.url.path
    is_docs_path = (
        path == "/docs"
        or path.startswith("/docs/")
        or path == "/redoc"
        or path.startswith("/redoc/")
        or path == "/openapi.json"
    )

    if is_docs_path:
        session_id = request.cookies.get(SESSION_COOKIE_NAME)
        session = get_valid_session(session_id)

        if not session:
            return JSONResponse(status_code=401, content={"detail": "Not authenticated"})

        if session.get("role") != "admin":
            return JSONResponse(status_code=403, content={"detail": "admin role required for docs"})

    return await call_next(request)


@app.get("/")
def dashboard():
    return FileResponse("index.html")

@app.get("/logo")
def logo():
    return FileResponse("gridcore.jpg", media_type="image/jpeg")


@app.post("/auth/login")
async def login(data: LoginRequest, request: Request, response: Response):
    username = data.username.strip()
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    login_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    login_alerts_on = get_setting("login_alerts_enabled", "true") == "true"

    row = get_user_record(username)

    if not row:
        if login_alerts_on:
            send_telegram(
                f"🚨 Failed Login Attempt\n"
                f"Username: {username} (not found)\n"
                f"Time: {login_time}\n"
                f"IP: {client_ip}\n"
                f"User-Agent: {user_agent}"
            )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    _, password_hash, salt, role, _, _ = row
    if not verify_password(data.password, password_hash, salt):
        if login_alerts_on:
            send_telegram(
                f"🚨 Failed Login Attempt\n"
                f"Username: {username}\n"
                f"Role: {role}\n"
                f"Time: {login_time}\n"
                f"IP: {client_ip}\n"
                f"User-Agent: {user_agent}"
            )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    update_user_last_login(username)

    log_audit(username, "login", f"Logged in with role: {role}")

    token = create_session(username=username, role=role)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=SESSION_TIMEOUT_SECONDS,
        path="/",
    )

    if login_alerts_on:
        send_telegram(
            f"🔐 Login Alert\n"
            f"User: {username}\n"
            f"Role: {role}\n"
            f"Time: {login_time}\n"
            f"IP: {client_ip}\n"
            f"User-Agent: {user_agent}"
        )

    return {
        "status": "ok",
        "username": username,
        "role": role,
        "session_timeout_seconds": SESSION_TIMEOUT_SECONDS,
    }


@app.post("/auth/register")
async def register(data: LoginRequest, request: Request, response: Response):
    username = data.username.strip()
    password = data.password

    if not USERNAME_PATTERN.match(username):
        raise HTTPException(status_code=400, detail="Username must be 3-64 chars (letters, numbers, underscore, dash, dot)")

    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    existing = get_user_record(username)
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")

    user_count = len(list_users())
    role = "admin" if user_count == 0 else "viewer"

    create_user_record(username=username, password=password, role=role)
    log_audit(username, "register", f"Registered with role: {role}")

    update_user_last_login(username)
    token = create_session(username=username, role=role)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=SESSION_TIMEOUT_SECONDS,
        path="/",
    )

    return {
        "status": "ok",
        "username": username,
        "role": role,
        "session_timeout_seconds": SESSION_TIMEOUT_SECONDS,
    }


@app.post("/auth/logout")
async def logout(response: Response, user=Depends(get_current_user)):
    log_audit(user["username"], "logout", "User logged out")
    active_sessions.pop(user["session_id"], None)
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    return {"status": "logged_out"}


@app.post("/auth/change-password")
async def change_password(data: ChangePasswordRequest, user=Depends(get_current_user)):
    row = get_user_record(user["username"])
    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    _, password_hash, salt, _, _, _ = row
    if not verify_password(data.old_password, password_hash, salt):
        raise HTTPException(status_code=403, detail="Current password is incorrect")

    if len(data.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")

    new_hash, new_salt = hash_password(data.new_password)
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
        (new_hash, new_salt, user["username"]),
    )
    conn.commit()
    conn.close()

    log_audit(user["username"], "change_password", "Password changed successfully")
    return {"status": "ok", "detail": "Password updated"}


@app.post("/auth/failed-login-photo")
async def failed_login_photo(photo: UploadFile = File(...), username: str = ""):
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendPhoto"
        login_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        caption = f"🚨 Failed Login - Intruder Photo\nUsername: {username}\nTime: {login_time}"
        photo_bytes = await photo.read()
        requests.post(
            url,
            data={"chat_id": CHAT_ID, "caption": caption},
            files={"photo": ("intruder.jpg", photo_bytes, "image/jpeg")},
        )
    except Exception as e:
        print("Failed login photo error:", e)
    return {"status": "ok"}


@app.get("/auth/status")
def auth_status():
    user_count = len(list_users())
    return {
        "has_users": user_count > 0,
        "needs_setup": user_count == 0,
    }


@app.get("/auth/me")
def auth_me(user=Depends(require_role("viewer"))):
    expires_in = max(0, int(user["expires_at"] - time.time()))
    return {
        "username": user["username"],
        "role": user["role"],
        "session_timeout_seconds": SESSION_TIMEOUT_SECONDS,
        "expires_in_seconds": expires_in,
    }


@app.get("/auth/users")
def get_users(user=Depends(require_role("admin"))):
    return {"users": list_users()}


@app.post("/auth/users")
def create_user(data: CreateUserRequest, user=Depends(require_role("admin"))):
    username = data.username.strip()
    role = data.role.strip().lower()
    password = data.password

    if role not in ROLE_ORDER:
        raise HTTPException(status_code=400, detail="Role must be viewer, operator, or admin")

    if not USERNAME_PATTERN.match(username):
        raise HTTPException(
            status_code=400,
            detail="Username must be 3-64 chars (letters, numbers, underscore, dash, dot)",
        )

    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    if get_user_record(username):
        raise HTTPException(status_code=409, detail="Username already exists")

    create_user_record(username=username, password=password, role=role)

    log_audit(user["username"], "create_user", f"Created user '{username}' with role '{role}'")

    return {"status": "created", "username": username, "role": role}


@app.patch("/auth/users/{username}/role")
def patch_user_role(username: str, data: UpdateUserRoleRequest, user=Depends(require_role("admin"))):
    target = username.strip()
    new_role = data.role.strip().lower()

    if new_role not in ROLE_ORDER:
        raise HTTPException(status_code=400, detail="Role must be viewer, operator, or admin")

    existing = get_user_record(target)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")

    current_role = existing[3]
    if current_role == "admin" and new_role != "admin" and count_admin_users() <= 1:
        raise HTTPException(status_code=400, detail="Cannot demote the last admin")

    if not update_user_role(username=target, role=new_role):
        raise HTTPException(status_code=500, detail="Failed to update user role")

    update_sessions_for_user(username=target, new_role=new_role)

    log_audit(user["username"], "change_user_role", f"Changed role of user '{target}' from '{current_role}' to '{new_role}'")

    return {"status": "updated", "username": target, "role": new_role}


@app.delete("/auth/users/{username}")
def delete_user(username: str, user=Depends(require_role("admin"))):
    target = username.strip()
    acting_user = user["username"]

    existing = get_user_record(target)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")

    if target == acting_user:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")

    target_role = existing[3]
    if target_role == "admin" and count_admin_users() <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the last admin")

    if not delete_user_record(target):
        raise HTTPException(status_code=500, detail="Failed to delete user")

    update_sessions_for_user(username=target, delete=True)

    log_audit(user["username"], "delete_user", f"Deleted user '{target}' with role '{target_role}'")

    return {"status": "deleted", "username": target}


@app.get("/state/services")
def get_state_services(user=Depends(require_role("viewer"))):
    return {"services": list_pinned_services()}


@app.post("/state/services")
def add_state_service(data: SaveServiceRequest, user=Depends(require_role("operator"))):
    name = data.name.strip()
    command = data.command.strip()

    if not name:
        raise HTTPException(status_code=400, detail="Service name is required")
    if not command:
        raise HTTPException(status_code=400, detail="Service command is required")

    try:
        created = create_pinned_service(name=name, port=data.port, command=command)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Service name already pinned")

    return {"status": "created", "service": created}


@app.delete("/state/services/{service_id}")
def remove_state_service(service_id: int, user=Depends(require_role("admin"))):
    if not delete_pinned_service(service_id):
        raise HTTPException(status_code=404, detail="Service not found")
    return {"status": "deleted", "id": service_id}


@app.get("/state/pinned-ports")
def get_state_pinned_ports(user=Depends(require_role("viewer"))):
    return {"ports": list_pinned_ports()}


@app.post("/state/pinned-ports")
def add_state_pinned_port(data: SavePinnedPortRequest, user=Depends(require_role("operator"))):
    port = int(data.port)
    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="Port must be between 1 and 65535")

    try:
        created = create_pinned_port(port=port)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Port is already pinned")

    log_audit(user["username"], "pin_port", f"Pinned port {port}")
    return {"status": "created", "port": created}


@app.delete("/state/pinned-ports/{pin_id}")
def remove_state_pinned_port(pin_id: int, user=Depends(require_role("operator"))):
    if not delete_pinned_port(pin_id):
        raise HTTPException(status_code=404, detail="Pinned port not found")

    log_audit(user["username"], "unpin_port", f"Removed pinned port id={pin_id}")
    return {"status": "deleted", "id": pin_id}


@app.patch("/state/pinned-ports/{pin_id}/service")
def update_pinned_port_service_config(pin_id: int, data: UpdatePinnedPortServiceRequest, user=Depends(require_role("operator"))):
    pin = get_pinned_port(pin_id)
    if not pin:
        raise HTTPException(status_code=404, detail="Pinned port not found")

    service_name = data.service_name.strip() if data.service_name else None
    command = data.command.strip() if data.command else None
    setup_command = data.setup_command.strip() if data.setup_command else None
    workdir = data.workdir.strip() if data.workdir else None

    if not update_pinned_port_service(pin_id, service_name, command, setup_command, workdir):
        raise HTTPException(status_code=500, detail="Failed to update pinned port service config")

    log_audit(user["username"], "configure_pinned_port_service", f"Configured service for pinned port {pin['port']} (id={pin_id})")
    return {"status": "updated", "id": pin_id}


@app.post("/state/pinned-ports/{pin_id}/start")
async def start_pinned_port_service(pin_id: int, user=Depends(require_role("operator"))):
    pin = get_pinned_port(pin_id)
    if not pin:
        raise HTTPException(status_code=404, detail="Pinned port not found")

    command = pin.get("command")
    if not command:
        raise HTTPException(status_code=400, detail="No start command configured for this pinned port. Use Configure to set one.")

    service_name = pin.get("service_name") or f"port-{pin['port']}"
    setup_command = pin.get("setup_command")
    workdir = pin.get("workdir") or None

    existing = managed_services.get(service_name)
    if existing and is_process_running(existing.get("process")):
        return {"status": "already_running", "name": service_name}

    if setup_command:
        try:
            setup_proc = subprocess.run(
                setup_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=workdir,
            )
            if setup_proc.returncode != 0:
                return {
                    "status": "setup_failed",
                    "name": service_name,
                    "stderr": (setup_proc.stderr or "")[-500:],
                    "stdout": (setup_proc.stdout or "")[-500:],
                }
        except subprocess.TimeoutExpired:
            return {"status": "setup_failed", "name": service_name, "stderr": "Setup command timed out after 120s"}
        except Exception as e:
            return {"status": "setup_failed", "name": service_name, "stderr": str(e)}

    log_path = f"{LOG_DIR}/{normalize_service_name(service_name)}.log"
    logfile = open(log_path, "a", encoding="utf-8")

    logfile.write(f"\n===== START: {service_name} (from pinned port {pin['port']}) =====\n")
    logfile.flush()

    proc = subprocess.Popen(
        command,
        shell=True,
        stdout=logfile,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        text=True,
        cwd=workdir,
    )

    managed_services[service_name] = {
        "process": proc,
        "logfile": logfile,
        "command": command,
        "port": pin["port"],
    }

    log_audit(user["username"], "start_pinned_port_service", f"Started service '{service_name}' on port {pin['port']} (PID: {proc.pid})")
    return {"status": "started", "name": service_name, "pid": proc.pid}


@app.post("/state/pinned-ports/{pin_id}/stop")
async def stop_pinned_port_service(pin_id: int, user=Depends(require_role("operator"))):
    pin = get_pinned_port(pin_id)
    if not pin:
        raise HTTPException(status_code=404, detail="Pinned port not found")

    service_name = pin.get("service_name") or f"port-{pin['port']}"
    entry = managed_services.get(service_name)

    if not entry:
        return {"status": "not_managed", "name": service_name}

    proc = entry.get("process")
    logfile = entry.get("logfile")

    if not is_process_running(proc):
        if logfile and not logfile.closed:
            logfile.write(f"===== STOP: {service_name} (already exited) =====\n")
            logfile.flush()
            logfile.close()
        managed_services.pop(service_name, None)
        return {"status": "already_stopped", "name": service_name}

    try:
        if proc and proc.pid:
            os.killpg(proc.pid, signal.SIGTERM)
    except Exception:
        proc.terminate()

    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()

    if logfile and not logfile.closed:
        logfile.write(f"===== STOP: {service_name} =====\n")
        logfile.flush()
        logfile.close()

    managed_services.pop(service_name, None)

    log_audit(user["username"], "stop_pinned_port_service", f"Stopped service '{service_name}' on port {pin['port']}")
    return {"status": "stopped", "name": service_name}


@app.get("/state/todos")
def get_state_todos(user=Depends(require_role("viewer"))):
    return {"todos": list_todos()}


@app.post("/state/todos")
def add_state_todo(data: SaveTodoRequest, user=Depends(require_role("operator"))):
    text = data.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Todo text is required")

    created = create_todo(text=text)
    return {"status": "created", "todo": created}


@app.patch("/state/todos/{todo_id}")
def patch_state_todo(todo_id: int, data: UpdateTodoRequest, user=Depends(require_role("operator"))):
    if not update_todo_done(todo_id=todo_id, done=data.done):
        raise HTTPException(status_code=404, detail="Todo not found")
    return {"status": "updated", "id": todo_id, "done": data.done}


@app.delete("/state/todos/{todo_id}")
def remove_state_todo(todo_id: int, user=Depends(require_role("operator"))):
    if not delete_todo(todo_id):
        raise HTTPException(status_code=404, detail="Todo not found")
    return {"status": "deleted", "id": todo_id}


# 🔥 NEW: GET LOGS
@app.get("/logs/{service}")
def get_logs(
    service: str,
    lines: int = Query(100, ge=1, le=1000),
    user=Depends(require_role("viewer")),
):
    path = f"{LOG_DIR}/{normalize_service_name(service)}.log"
    if not os.path.exists(path):
        return {"logs": ["No logs yet"]}

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        last_lines = list(deque(f, maxlen=lines))

    return {"logs": last_lines}


# 🔥 NEW: RUN SERVICE WITH LOGGING
@app.post("/run")
async def run_service(data: RunServiceRequest, user=Depends(require_role("operator"))):
    if not data.command.strip():
        raise HTTPException(status_code=400, detail="Service command is required")

    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Service name is required")

    existing = managed_services.get(name)
    if existing and is_process_running(existing.get("process")):
        return {"status": "already_running", "name": name}

    log_path = f"{LOG_DIR}/{normalize_service_name(name)}.log"
    logfile = open(log_path, "a", encoding="utf-8")

    logfile.write(f"\n===== START: {name} =====\n")
    logfile.flush()

    proc = subprocess.Popen(
        data.command,
        shell=True,
        stdout=logfile,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        text=True
    )

    managed_services[name] = {
        "process": proc,
        "logfile": logfile,
        "command": data.command,
        "port": data.port,
    }

    log_audit(user["username"], "start_service", f"Started service '{name}' (PID: {proc.pid})")

    return {"status": "started", "name": name, "pid": proc.pid}


@app.post("/stop")
async def stop_service(data: StopServiceRequest, user=Depends(require_role("operator"))):
    name = data.name.strip()
    entry = managed_services.get(name)

    if not entry:
        return {"status": "not_managed", "name": name}

    proc = entry.get("process")
    logfile = entry.get("logfile")

    if not is_process_running(proc):
        if logfile and not logfile.closed:
            logfile.write(f"===== STOP: {name} (already exited) =====\n")
            logfile.flush()
            logfile.close()
        managed_services.pop(name, None)
        return {"status": "already_stopped", "name": name}

    try:
        if proc and proc.pid:
            os.killpg(proc.pid, signal.SIGTERM)
    except Exception:
        proc.terminate()

    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()

    if logfile and not logfile.closed:
        logfile.write(f"===== STOP: {name} =====\n")
        logfile.flush()
        logfile.close()

    managed_services.pop(name, None)

    log_audit(user["username"], "stop_service", f"Stopped service '{name}'")

    return {"status": "stopped", "name": name}


@app.post("/notify")
async def notify(data: NotifyRequest, user=Depends(require_role("admin"))):
    send_telegram(data.msg)

    return {"status": "sent"}


@app.get("/battery")
def battery(user=Depends(require_role("viewer"))):
    global battery_alert_sent

    batt = psutil.sensors_battery()

    if batt:
        percent = batt.percent
        plugged = batt.power_plugged

        if percent < BATTERY_THRESHOLD and not plugged:
            if not battery_alert_sent:
                send_telegram(f"🚨 Battery Low: {percent}%")
                battery_alert_sent = True
        else:
            battery_alert_sent = False

        return {"percent": percent, "plugged": plugged}

    return {"percent": None, "plugged": False}


@app.get("/server-info")
def server_info():
    return {
        "server_name": SERVER_NAME or socket.gethostname(),
        "hostname": socket.gethostname(),
    }


@app.get("/system")
def system(user=Depends(require_role("viewer"))):
    cpu = psutil.cpu_percent()
    memory = psutil.virtual_memory().percent

    # Check alert rules
    check_alert_rules(cpu, memory)
    check_pinned_port_alerts()
    check_docker_container_alerts()

    # Trigger AI auto-remediation if configured
    if os.getenv("AI_AUTO_REMEDIATION", "").lower() in ("1", "true", "yes"):
        try:
            from ai.remediation import on_cpu_alert, on_port_down
            # CPU remediation via alert rules threshold (80%)
            cpu_val = psutil.cpu_percent(interval=0.5)
            if cpu_val > 80:
                on_cpu_alert(threshold=80, current_cpu=cpu_val, session_id=user.get("session_id"))
        except Exception:
            pass

    return {
        "cpu": cpu,
        "memory": memory
    }


@app.get("/ports")
def ports(user=Depends(require_role("viewer"))):
    try:
        output = subprocess.check_output("ss -tuln", shell=True).decode()
        lines = output.split("\n")[1:]

        parsed = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                parsed.append({
                    "protocol": parts[0],
                    "state": parts[1],
                    "local": parts[4]
                })

        return parsed
    except:
        return []


@app.get("/docker")
def docker(user=Depends(require_role("viewer"))):
    try:
        return list_docker_container_snapshots()
    except:
        return []


@app.post("/docker/action")
def docker_action(data: DockerActionRequest, user=Depends(require_role("operator"))):
    container_id = (data.container_id or "").strip()
    action = (data.action or "").strip().lower()

    if action not in {"start", "stop", "restart"}:
        raise HTTPException(status_code=400, detail="action must be start, stop, or restart")

    if not DOCKER_CONTAINER_ID_PATTERN.match(container_id):
        raise HTTPException(status_code=400, detail="Invalid container identifier")

    result = run_docker_command([action, container_id], timeout=60)
    details = (result.stdout or result.stderr or "").strip()
    log_audit(user["username"], "docker_action", f"{action} container '{container_id}'")
    return {"status": "ok", "action": action, "container_id": container_id, "details": details}


@app.get("/docker/logs/{container_id}")
def docker_logs(container_id: str, lines: int = Query(100, ge=1, le=2000), user=Depends(require_role("viewer"))):
    target = (container_id or "").strip()
    if not DOCKER_CONTAINER_ID_PATTERN.match(target):
        raise HTTPException(status_code=400, detail="Invalid container identifier")

    result = run_docker_command(["logs", "--tail", str(lines), target], timeout=60)
    combined = ""
    if result.stdout:
        combined += result.stdout
    if result.stderr:
        combined += result.stderr

    return {"logs": combined.splitlines(keepends=True)}


def _render_compose_yaml(template_yaml: str, app_name: str, env_vars: dict, port_override: int | None) -> str:
    rendered = template_yaml
    port = str(port_override) if port_override else ""
    rendered = rendered.replace("${PORT:-80}", port or "80")
    rendered = rendered.replace("${PORT:-3000}", port or "3000")
    rendered = rendered.replace("${PORT:-5000}", port or "5000")
    rendered = rendered.replace("${PORT:-5432}", port or "5432")
    rendered = rendered.replace("${PORT:-6379}", port or "6379")
    rendered = rendered.replace("${PORT:-3306}", port or "3306")
    rendered = rendered.replace("${PORT:-8080}", port or "8080")
    rendered = rendered.replace("${PORT:-27017}", port or "27017")
    for key, value in env_vars.items():
        rendered = rendered.replace(f"${{{key}:-", f"${{{key}:-")
    return rendered


def _run_docker_compose(compose_path: str, args: list[str], timeout: int = 120):
    commands = [
        ["docker", "compose", "-f", compose_path, *args],
        ["docker-compose", "-f", compose_path, *args],
        ["sudo", "docker", "compose", "-f", compose_path, *args],
    ]
    last_error = ""
    for command in commands:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            continue
        except Exception as e:
            last_error = str(e)
            continue
        if result.returncode == 0:
            return result
        stderr_text = (result.stderr or "").strip()
        stdout_text = (result.stdout or "").strip()
        lowered = f"{stderr_text}\n{stdout_text}".lower()
        if "permission denied" in lowered or "cannot connect to the docker daemon" in lowered:
            last_error = stderr_text or stdout_text
            continue
        raise HTTPException(status_code=500, detail=(stderr_text or stdout_text or "Docker compose failed")[:500])
    raise HTTPException(status_code=500, detail=(last_error or "Docker compose is not available")[:500])


def _get_compose_container_ids(compose_path: str) -> list[str]:
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", compose_path, "ps", "-q"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            result = subprocess.run(
                ["docker-compose", "-f", compose_path, "ps", "-q"],
                capture_output=True, text=True, timeout=30,
            )
        ids = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
        return ids
    except Exception:
        return []


@app.get("/deploy/templates")
def get_deploy_templates(user=Depends(require_role("viewer"))):
    return {"templates": list_app_templates()}


@app.get("/deploy/templates/{template_id}")
def get_deploy_template(template_id: int, user=Depends(require_role("viewer"))):
    template = get_app_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    return template


@app.post("/deploy")
def deploy_app(data: DeployAppRequest, user=Depends(require_role("operator"))):
    app_name = data.app_name.strip()
    if not app_name:
        raise HTTPException(status_code=400, detail="App name is required")

    if not all(ch.isalnum() or ch in "-_" for ch in app_name):
        raise HTTPException(status_code=400, detail="App name must be alphanumeric with dashes/underscores only")

    template = None
    if data.template_id:
        template = get_app_template(data.template_id)
        if not template:
            raise HTTPException(status_code=404, detail="Template not found")

    compose_dir = os.path.join("deployed_apps", app_name)
    os.makedirs(compose_dir, exist_ok=True)
    compose_path = os.path.join(compose_dir, "docker-compose.yml")

    env_file_path = os.path.join(compose_dir, ".env")
    env_lines = [f"PORT={data.port_override or template['default_port'] if template else data.port_override or 80}"]
    for key, value in data.env_vars.items():
        env_lines.append(f"{key}={value}")
    with open(env_file_path, "w") as f:
        f.write("\n".join(env_lines) + "\n")

    if template:
        compose_content = _render_compose_yaml(template["compose_yaml"], app_name, data.env_vars, data.port_override)
    else:
        raise HTTPException(status_code=400, detail="Template is required for deployment")

    with open(compose_path, "w") as f:
        f.write(compose_content)

    ports = []
    if data.port_override:
        ports.append(data.port_override)
    elif template and template.get("default_port"):
        ports.append(template["default_port"])

    app_id = create_deployed_app(
        name=app_name,
        template_id=data.template_id,
        compose_path=compose_path,
        ports=ports,
        env_vars=data.env_vars,
        created_by=user["username"],
    )

    try:
        env = os.environ.copy()
        env.update(data.env_vars)
        env["PORT"] = str(data.port_override or (template["default_port"] if template else 80))

        commands = [
            ["docker", "compose", "-f", compose_path, "up", "-d"],
            ["docker-compose", "-f", compose_path, "up", "-d"],
            ["sudo", "docker", "compose", "-f", compose_path, "up", "-d"],
        ]
        last_error = ""
        deployed = False
        for command in commands:
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=180, env=env, cwd=compose_dir)
            except FileNotFoundError:
                continue
            except Exception as e:
                last_error = str(e)
                continue
            if result.returncode == 0:
                deployed = True
                break
            stderr_text = (result.stderr or "").strip()
            if "permission denied" in stderr_text.lower() or "cannot connect" in stderr_text.lower():
                last_error = stderr_text
                continue
            last_error = stderr_text
            break

        if deployed:
            container_ids = _get_compose_container_ids(compose_path)
            update_deployed_app_status(app_id, "running", container_ids)
            log_audit(user["username"], "deploy_app", f"Deployed app '{app_name}' from template '{template['name'] if template else 'custom'}'")
            return {"status": "running", "app_id": app_id, "name": app_name, "container_ids": container_ids}
        else:
            update_deployed_app_status(app_id, "failed")
            log_audit(user["username"], "deploy_app_failed", f"Failed to deploy '{app_name}': {last_error[:200]}")
            raise HTTPException(status_code=500, detail=f"Deployment failed: {last_error[:300]}")

    except HTTPException:
        raise
    except Exception as e:
        update_deployed_app_status(app_id, "failed")
        raise HTTPException(status_code=500, detail=f"Deployment error: {str(e)[:300]}")


@app.get("/deploy/apps")
def get_deploy_apps(user=Depends(require_role("viewer"))):
    apps = list_deployed_apps()
    for app in apps:
        if app["status"] == "running" and app["compose_path"] and os.path.exists(app["compose_path"]):
            container_ids = _get_compose_container_ids(app["compose_path"])
            app["container_ids"] = container_ids
    return {"apps": apps}


@app.post("/deploy/apps/{app_id}/action")
def deploy_app_action(app_id: int, data: DeployedAppActionRequest, user=Depends(require_role("operator"))):
    app = get_deployed_app(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Deployed app not found")

    action = data.action.strip().lower()
    compose_path = app["compose_path"]
    compose_dir = os.path.dirname(compose_path) if compose_path else None

    if action in ("start", "stop", "restart"):
        if not compose_path or not os.path.exists(compose_path):
            raise HTTPException(status_code=400, detail="Compose file not found for this app")

    if action == "start":
        result = _run_docker_compose(compose_path, ["up", "-d"], timeout=180)
        container_ids = _get_compose_container_ids(compose_path)
        update_deployed_app_status(app_id, "running", container_ids)
        log_audit(user["username"], "deploy_app_start", f"Started app '{app['name']}'")
        return {"status": "running", "container_ids": container_ids}

    elif action == "stop":
        result = _run_docker_compose(compose_path, ["down"], timeout=60)
        update_deployed_app_status(app_id, "stopped", [])
        log_audit(user["username"], "deploy_app_stop", f"Stopped app '{app['name']}'")
        return {"status": "stopped"}

    elif action == "restart":
        _run_docker_compose(compose_path, ["down"], timeout=60)
        _run_docker_compose(compose_path, ["up", "-d"], timeout=180)
        container_ids = _get_compose_container_ids(compose_path)
        update_deployed_app_status(app_id, "running", container_ids)
        log_audit(user["username"], "deploy_app_restart", f"Restarted app '{app['name']}'")
        return {"status": "running", "container_ids": container_ids}

    elif action == "delete":
        if compose_path and os.path.exists(compose_path):
            try:
                _run_docker_compose(compose_path, ["down", "-v"], timeout=60)
            except Exception:
                pass
        if compose_dir and os.path.exists(compose_dir):
            try:
                safe_rmtree(compose_dir, ignore_errors=True)
            except Exception:
                pass
        delete_deployed_app(app_id)
        log_audit(user["username"], "deploy_app_delete", f"Deleted app '{app['name']}'")
        return {"status": "deleted"}

    else:
        raise HTTPException(status_code=400, detail="Action must be start, stop, restart, or delete")


@app.get("/deploy/apps/{app_id}/logs")
def deploy_app_logs(app_id: int, lines: int = Query(100, ge=1, le=2000), user=Depends(require_role("viewer"))):
    app = get_deployed_app(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Deployed app not found")

    compose_path = app["compose_path"]
    if not compose_path or not os.path.exists(compose_path):
        return {"logs": ["No compose file found for this app."]}

    try:
        result = _run_docker_compose(compose_path, ["logs", "--tail", str(lines)], timeout=60)
        combined = ""
        if result.stdout:
            combined += result.stdout
        if result.stderr:
            combined += result.stderr
        return {"logs": combined.splitlines(keepends=True)}
    except Exception as e:
        return {"logs": [f"Error fetching logs: {str(e)}"]}


@app.post("/deploy/github/analyze")
def github_analyze(data: GitHubAnalyzeRequest, user=Depends(require_role("operator"))):
    repo_url = data.repo_url.strip()
    branch = data.branch.strip() or "main"
    if not repo_url:
        raise HTTPException(status_code=400, detail="Repository URL is required")

    tmp_dir = tempfile.mkdtemp(prefix="gh-analyze-")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "-b", branch, repo_url, tmp_dir],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            raise HTTPException(status_code=400, detail=f"Clone failed: {(result.stderr or result.stdout)[:300]}")

        detected = detect_project_type(tmp_dir)
        repo_name = suggest_git_clone_folder_name(repo_url)

        # Parse the actual docker-compose.yml if present
        compose_services = []
        compose_content = None
        compose_path = None
        for candidate in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            p = os.path.join(tmp_dir, candidate)
            if os.path.exists(p):
                compose_path = p
                compose_content = _read_file_safe(p)
                compose_services = parse_compose_services(p)
                break

        dockerfile_content = None
        if detected.get("has_dockerfile"):
            dockerfile_content = _read_file_safe(os.path.join(tmp_dir, "Dockerfile"))
        else:
            dockerfile_content = generate_dockerfile(detected, tmp_dir)

        if not compose_content:
            compose_content = generate_compose_yaml(repo_name, detected, detected["port"])

        log_audit(user["username"], "github_analyze", f"Analyzed repo: {repo_url}")
        return {
            "repo_name": repo_name,
            "repo_url": repo_url,
            "branch": branch,
            "dockerfile_content": dockerfile_content,
            "compose_content": compose_content,
            "compose_services": compose_services,
            **detected,
        }
    except HTTPException:
        raise
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Clone timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)[:300])
    finally:
        safe_rmtree(tmp_dir, ignore_errors=True)


@app.post("/deploy/github/deploy")
def github_deploy(data: GitHubDeployRequest, user=Depends(require_role("operator"))):
    repo_url = data.repo_url.strip()
    app_name = data.app_name.strip()
    branch = data.branch.strip() or "main"

    if not repo_url:
        raise HTTPException(status_code=400, detail="Repository URL is required")
    if not app_name:
        raise HTTPException(status_code=400, detail="App name is required")
    if not all(ch.isalnum() or ch in "-_" for ch in app_name):
        raise HTTPException(status_code=400, detail="App name must be alphanumeric with dashes/underscores only")

    existing = get_github_deployment_by_name(app_name)
    if existing:
        old_status = existing.get("status", "")
        if old_status == "running":
            raise HTTPException(status_code=409, detail=f"App '{app_name}' is currently running. Stop it first.")
        # Clean up orphaned deployment (crashed pipeline, server reload, etc.)
        old_path = existing.get("deploy_path")
        if old_path and os.path.isdir(old_path):
            safe_rmtree(old_path, ignore_errors=True)
        delete_github_deployment(existing["id"])

    deploy_path = os.path.join("deployed_apps", app_name)

    env_vars = dict(data.env_vars)
    if data.port_override:
        env_vars["__port_override__"] = str(data.port_override)
    if data.port_overrides:
        env_vars["__port_overrides__"] = json.dumps(data.port_overrides)

    deploy_id = create_github_deployment(
        app_name=app_name,
        repo_url=repo_url,
        branch=branch,
        deploy_path=deploy_path,
        created_by=user["username"],
    )
    update_github_deployment_fields(deploy_id, env_vars=json.dumps(env_vars))

    thread = threading.Thread(target=run_github_deploy_pipeline, args=(deploy_id,), daemon=True)
    thread.start()

    log_audit(user["username"], "github_deploy", f"Started deploy of '{app_name}' from {repo_url}")
    return {"deploy_id": deploy_id, "app_name": app_name, "status": "pending"}


@app.get("/deploy/github/status/{deploy_id}")
def github_deploy_status(deploy_id: int, user=Depends(require_role("viewer"))):
    dep = get_github_deployment(deploy_id)
    if not dep:
        raise HTTPException(status_code=404, detail="Deployment not found")
    step_status = dep.get("step_status", "{}")
    if isinstance(step_status, str):
        try:
            step_status = json.loads(step_status)
        except Exception:
            step_status = {}
    dep["step_status"] = step_status
    container_ids = dep.get("container_ids", "[]")
    if isinstance(container_ids, str):
        try:
            container_ids = json.loads(container_ids)
        except Exception:
            container_ids = []
    dep["container_ids"] = container_ids
    env_vars = dep.get("env_vars", "{}")
    if isinstance(env_vars, str):
        try:
            env_vars = json.loads(env_vars)
        except Exception:
            env_vars = {}
    env_vars.pop("__port_override__", None)
    env_vars.pop("__port_overrides__", None)
    dep["env_vars"] = env_vars
    return dep


@app.delete("/deploy/github/{deploy_id}")
def github_deploy_delete(deploy_id: int, user=Depends(require_role("operator"))):
    dep = get_github_deployment(deploy_id)
    if not dep:
        raise HTTPException(status_code=404, detail="Deployment not found")

    deploy_path = dep.get("deploy_path")
    if deploy_path and os.path.isdir(deploy_path):
        safe_rmtree(deploy_path, ignore_errors=True)

    delete_github_deployment(deploy_id)
    log_audit(user["username"], "github_deploy_delete", f"Deleted deployment {deploy_id} ('{dep.get('app_name', '')}')")
    return {"status": "deleted"}


@app.get("/check-port/{port}")
def check_port(port: int, user=Depends(require_role("viewer"))):
    return {"port": port, "active": is_local_port_active(port)}


@app.post("/ports/{port}/terminate")
def terminate_port_processes(port: int, user=Depends(require_role("operator"))):
    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="Port must be between 1 and 65535")

    outcome = terminate_processes_for_port(port)
    remaining_pids = list_process_ids_by_port(port)

    log_audit(
        user["username"],
        "terminate_port",
        (
            f"Attempted terminate on port {port}; found={outcome['found_pids']}, "
            f"terminated={outcome['terminated_pids']}, killed={outcome['killed_pids']}, "
            f"remaining={remaining_pids}"
        ),
    )

    if not outcome["found_pids"]:
        return {
            "status": "no_process",
            "port": port,
            "found_pids": [],
            "terminated_pids": [],
            "killed_pids": [],
            "remaining_pids": [],
        }

    return {
        "status": "terminated" if not remaining_pids else "partial",
        "port": port,
        "found_pids": outcome["found_pids"],
        "terminated_pids": outcome["terminated_pids"],
        "killed_pids": outcome["killed_pids"],
        "remaining_pids": remaining_pids,
    }


@app.get("/audit-logs")
def get_audit_logs(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(require_role("admin"))
):
    """Get audit logs (admin only)"""
    logs = list_audit_logs(limit=limit, offset=offset)
    return {"logs": logs}


@app.get("/alert-rules")
def get_alert_rules(user=Depends(require_role("admin"))):
    """Get all alert rules (admin only)"""
    rules = list_alert_rules()
    return {"rules": rules}


@app.post("/alert-rules")
def add_alert_rule(data: CreateAlertRuleRequest, user=Depends(require_role("admin"))):
    """Create a new alert rule (admin only)"""
    metric_type = data.metric_type.strip().lower()

    if metric_type not in ["cpu", "ram"]:
        raise HTTPException(status_code=400, detail="metric_type must be 'cpu' or 'ram'")

    if data.threshold < 0 or data.threshold > 100:
        raise HTTPException(status_code=400, detail="threshold must be between 0 and 100")

    rule = create_alert_rule(metric_type=metric_type, threshold=data.threshold)
    log_audit(user["username"], "create_alert_rule", f"Created {metric_type} alert rule with threshold {data.threshold}%")

    return {"status": "created", "rule": rule}


@app.patch("/alert-rules/{rule_id}")
def update_alert_rule_endpoint(
    rule_id: int,
    data: UpdateAlertRuleRequest,
    user=Depends(require_role("admin"))
):
    """Update an alert rule (admin only)"""
    if data.threshold is not None and (data.threshold < 0 or data.threshold > 100):
        raise HTTPException(status_code=400, detail="threshold must be between 0 and 100")

    if not update_alert_rule(rule_id=rule_id, threshold=data.threshold, enabled=data.enabled):
        raise HTTPException(status_code=404, detail="Alert rule not found")

    details = []
    if data.threshold is not None:
        details.append(f"threshold={data.threshold}%")
    if data.enabled is not None:
        details.append(f"enabled={data.enabled}")

    log_audit(user["username"], "update_alert_rule", f"Updated alert rule {rule_id}: {', '.join(details)}")

    return {"status": "updated", "id": rule_id}


@app.delete("/alert-rules/{rule_id}")
def remove_alert_rule(rule_id: int, user=Depends(require_role("admin"))):
    """Delete an alert rule (admin only)"""
    if not delete_alert_rule(rule_id):
        raise HTTPException(status_code=404, detail="Alert rule not found")

    log_audit(user["username"], "delete_alert_rule", f"Deleted alert rule {rule_id}")

    return {"status": "deleted", "id": rule_id}


@app.get("/settings/login-alerts")
def get_login_alerts_setting(user=Depends(require_role("admin"))):
    return {"enabled": get_setting("login_alerts_enabled", "true") == "true"}


@app.patch("/settings/login-alerts")
def toggle_login_alerts(data: dict, user=Depends(require_role("admin"))):
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        raise HTTPException(status_code=400, detail="enabled must be a boolean")
    set_setting("login_alerts_enabled", "true" if enabled else "false")
    log_audit(user["username"], "toggle_login_alerts", f"Login alerts {'enabled' if enabled else 'disabled'}")
    return {"enabled": enabled}


@app.get("/ssh/keys")
def get_ssh_keys(ssh_user: str | None = Query(None), user=Depends(require_role("admin"))):
    if ssh_user:
        target = ssh_user.strip()
        if not SSH_USERNAME_PATTERN.match(target):
            raise HTTPException(status_code=400, detail="Invalid Linux username")
        return {"keys": list_ssh_public_keys(ssh_user=target)}
    return {"keys": list_ssh_public_keys()}


@app.post("/ssh/keys")
def create_ssh_key(data: CreateSshKeyRequest, user=Depends(require_role("admin"))):
    ssh_user = data.ssh_user.strip().lower()
    label = data.label.strip() if data.label else ""
    if not label:
        label = "SSH Key"

    if not SSH_USERNAME_PATTERN.match(ssh_user):
        raise HTTPException(status_code=400, detail="Invalid Linux username")

    parsed = parse_public_ssh_key(data.public_key)

    created = None
    try:
        created = create_ssh_public_key_record(
            ssh_user=ssh_user,
            label=label,
            key_type=parsed["key_type"],
            key_body=parsed["key_body"],
            key_comment=parsed["key_comment"],
            fingerprint_sha256=parsed["fingerprint_sha256"],
            created_by=user["username"],
        )
        sync_managed_ssh_keys(ssh_user)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="This key already exists for the selected Linux user")
    except HTTPException as e:
        if created:
            delete_ssh_public_key_record(created["id"])
        raise e
    except Exception as e:
        if created:
            delete_ssh_public_key_record(created["id"])
        raise HTTPException(status_code=500, detail=f"Failed to store/deploy SSH key: {str(e)}")

    log_audit(
        user["username"],
        "create_ssh_key",
        f"Added SSH key '{label}' for Linux user '{ssh_user}' ({parsed['fingerprint_sha256']})",
    )

    return {"status": "created", "key": created}


@app.delete("/ssh/keys/{key_id}")
def remove_ssh_key(key_id: int, user=Depends(require_role("admin"))):
    existing = get_ssh_public_key_record(key_id)
    if not existing:
        raise HTTPException(status_code=404, detail="SSH key not found")

    if not delete_ssh_public_key_record(key_id):
        raise HTTPException(status_code=404, detail="SSH key not found")

    try:
        sync_managed_ssh_keys(existing["ssh_user"])
    except Exception as e:
        restore_ssh_public_key_record(existing)
        try:
            sync_managed_ssh_keys(existing["ssh_user"])
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"Failed to remove key from authorized_keys: {str(e)}")

    log_audit(
        user["username"],
        "delete_ssh_key",
        f"Deleted SSH key '{existing['label']}' for Linux user '{existing['ssh_user']}' ({existing['fingerprint_sha256']})",
    )

    return {"status": "deleted", "id": key_id}


@app.get("/cloudflared/routes")
def get_cloudflared_routes(user=Depends(require_role("admin"))):
    sync_result = sync_existing_cloudflared_routes_from_config()
    active_path = sync_result["config_path"]
    tunnel_name = get_cloudflared_tunnel_name()
    tunnel_processes = list_cloudflared_tunnel_processes(tunnel_name)
    routes = list_cloudflared_routes()
    config_hostnames = list_cloudflared_config_hostnames(active_path)
    managed_hostnames = {item["hostname"] for item in routes}
    unmanaged_config_hostnames = [hostname for hostname in config_hostnames if hostname not in managed_hostnames]
    return {
        "routes": routes,
        "config_path": active_path,
        "configured_config_path": os.path.abspath(CLOUDFLARED_CONFIG_PATH),
        "fallback_config_path": os.path.abspath(CLOUDFLARED_FALLBACK_CONFIG_PATH),
        "tunnel_name": tunnel_name,
        "dns_auto_route": CLOUDFLARED_DNS_AUTO_ROUTE,
        "cloudflared_cli_available": is_cloudflared_cli_available(),
        "tunnel_running": len(tunnel_processes) > 0,
        "tunnel_process_count": len(tunnel_processes),
        "tunnel_pids": [item["pid"] for item in tunnel_processes],
        "config_hostnames": config_hostnames,
        "unmanaged_config_hostnames": unmanaged_config_hostnames,
        "config_sync_checked": sync_result["checked"],
        "config_sync_updated": sync_result["updated"],
    }


@app.get("/cloudflared/tunnel/status")
def get_cloudflared_tunnel_status(user=Depends(require_role("admin"))):
    active_path = resolve_cloudflared_active_config_path()
    tunnel_name = get_cloudflared_tunnel_name()
    tunnel_processes = list_cloudflared_tunnel_processes(tunnel_name)
    return {
        "tunnel_name": tunnel_name,
        "running": len(tunnel_processes) > 0,
        "process_count": len(tunnel_processes),
        "processes": tunnel_processes,
        "config_path": active_path,
    }


@app.post("/cloudflared/tunnel/restart")
def restart_cloudflared_tunnel(user=Depends(require_role("admin"))):
    tunnel_name = get_cloudflared_tunnel_name()
    if not tunnel_name:
        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to determine Cloudflared tunnel name. Set CLOUDFLARED_TUNNEL_NAME "
                "or add 'tunnel: <name-or-uuid>' in your cloudflared config file."
            ),
        )

    used_config_path = sync_managed_cloudflared_routes()
    stopped_pids = stop_cloudflared_tunnel_processes(tunnel_name)
    started = start_cloudflared_tunnel_process(tunnel_name, used_config_path)
    running_processes = list_cloudflared_tunnel_processes(tunnel_name)

    log_audit(
        user["username"],
        "restart_cloudflared_tunnel",
        f"Restarted Cloudflared tunnel '{tunnel_name}' (stopped={stopped_pids}, started_pid={started['pid']})",
    )

    return {
        "status": "restarted",
        "tunnel_name": tunnel_name,
        "stopped_pids": stopped_pids,
        "started_pid": started["pid"],
        "running": len(running_processes) > 0,
        "process_count": len(running_processes),
        "processes": running_processes,
        "config_path": used_config_path,
        "log_path": started["log_path"],
    }


@app.post("/cloudflared/routes/import-unmanaged")
def import_unmanaged_cloudflared_routes(user=Depends(require_role("admin"))):
    config_entries = parse_cloudflared_config_entries(
        config_path=active_cloudflared_config_path,
        include_managed=False,
    )
    existing_routes = list_cloudflared_routes()
    managed_hostnames = {item["hostname"] for item in existing_routes}

    imported = []
    skipped = []

    for entry in config_entries:
        hostname = (entry.get("hostname") or "").strip().lower().rstrip(".")
        service_value = (entry.get("service") or "").strip()

        if not hostname:
            continue

        if hostname in managed_hostnames:
            skipped.append({"hostname": hostname, "reason": "Already managed"})
            continue

        parsed_service = parse_cloudflared_service_target(service_value)
        if not parsed_service:
            skipped.append({"hostname": hostname, "reason": f"Unsupported service format: {service_value}"})
            continue

        try:
            normalized_hostname = normalize_cloudflared_hostname(hostname)
            normalized_scheme = normalize_cloudflared_service_scheme(parsed_service["scheme"])
            normalized_host = normalize_cloudflared_service_host(parsed_service["host"])
            normalized_port = int(parsed_service["port"])

            if normalized_port < 1 or normalized_port > 65535:
                raise HTTPException(status_code=400, detail="service_port must be between 1 and 65535")

            created = create_cloudflared_route_record(
                hostname=normalized_hostname,
                service_scheme=normalized_scheme,
                service_host=normalized_host,
                service_port=normalized_port,
                created_by=user["username"],
            )
            imported.append(created)
            managed_hostnames.add(normalized_hostname)

            try:
                ensure_cloudflared_dns_route(normalized_hostname)
            except Exception:
                # DNS errors should not block import from existing config.
                pass
        except sqlite3.IntegrityError:
            skipped.append({"hostname": hostname, "reason": "Hostname already exists"})
        except HTTPException as e:
            detail = e.detail if isinstance(e.detail, str) else "Invalid route"
            skipped.append({"hostname": hostname, "reason": detail})
        except Exception as e:
            skipped.append({"hostname": hostname, "reason": str(e)})

    cleanup_targets = {item["hostname"] for item in imported}

    try:
        used_config_path = sync_managed_cloudflared_routes(cleanup_hostnames=cleanup_targets)
    except Exception:
        if imported:
            for created in imported:
                try:
                    delete_cloudflared_route_record(created["id"])
                except Exception:
                    pass
            try:
                sync_managed_cloudflared_routes()
            except Exception:
                pass
        raise

    log_audit(
        user["username"],
        "import_cloudflared_routes",
        (
            f"Imported {len(imported)} unmanaged Cloudflared route(s) from config "
            f"({', '.join(item['hostname'] for item in imported) if imported else 'none'})"
        ),
    )

    return {
        "status": "imported",
        "imported_count": len(imported),
        "imported": imported,
        "skipped_count": len(skipped),
        "skipped": skipped,
        "config_path": used_config_path,
    }


@app.post("/cloudflared/routes")
def create_cloudflared_route(data: CreateCloudflaredRouteRequest, user=Depends(require_role("admin"))):
    hostname = normalize_cloudflared_hostname(data.hostname)
    service_scheme = normalize_cloudflared_service_scheme(data.service_scheme)
    service_host = normalize_cloudflared_service_host(data.service_host)

    if data.service_port < 1 or data.service_port > 65535:
        raise HTTPException(status_code=400, detail="service_port must be between 1 and 65535")

    created = None
    used_config_path = active_cloudflared_config_path
    dns_result = {
        "dns_routed": False,
        "dns_message": "DNS route step skipped",
        "tunnel_name": get_cloudflared_tunnel_name(),
    }

    def _rollback_created_route():
        if not created:
            return
        delete_cloudflared_route_record(created["id"])
        try:
            sync_managed_cloudflared_routes()
        except Exception:
            pass

    try:
        created = create_cloudflared_route_record(
            hostname=hostname,
            service_scheme=service_scheme,
            service_host=service_host,
            service_port=data.service_port,
            created_by=user["username"],
        )
        used_config_path = sync_managed_cloudflared_routes()
        dns_result = ensure_cloudflared_dns_route(hostname)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="This hostname already exists in Cloudflared routes")
    except HTTPException as e:
        _rollback_created_route()
        raise e
    except Exception as e:
        _rollback_created_route()
        raise HTTPException(status_code=500, detail=f"Failed to store/deploy Cloudflared route: {str(e)}")

    log_audit(
        user["username"],
        "create_cloudflared_route",
        f"Added Cloudflared route '{hostname}' -> {service_scheme}://{service_host}:{data.service_port}",
    )

    return {
        "status": "created",
        "route": created,
        "config_path": used_config_path,
        "configured_config_path": os.path.abspath(CLOUDFLARED_CONFIG_PATH),
        "fallback_config_path": os.path.abspath(CLOUDFLARED_FALLBACK_CONFIG_PATH),
        "dns_routed": dns_result["dns_routed"],
        "dns_message": dns_result["dns_message"],
        "tunnel_name": dns_result["tunnel_name"],
        "public_url": f"https://{hostname}",
    }


@app.delete("/cloudflared/routes/{route_id}")
def remove_cloudflared_route(route_id: int, user=Depends(require_role("admin"))):
    existing = get_cloudflared_route_record(route_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Cloudflared route not found")

    if not delete_cloudflared_route_record(route_id):
        raise HTTPException(status_code=404, detail="Cloudflared route not found")

    try:
        used_config_path = sync_managed_cloudflared_routes()
    except HTTPException as e:
        restore_cloudflared_route_record(existing)
        try:
            sync_managed_cloudflared_routes()
        except Exception:
            pass
        raise e
    except Exception as e:
        restore_cloudflared_route_record(existing)
        try:
            sync_managed_cloudflared_routes()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"Failed to remove route from Cloudflared config: {str(e)}")

    log_audit(
        user["username"],
        "delete_cloudflared_route",
        f"Deleted Cloudflared route '{existing['hostname']}' -> {existing['service_scheme']}://{existing['service_host']}:{existing['service_port']}",
    )

    return {
        "status": "deleted",
        "id": route_id,
        "config_path": used_config_path,
        "configured_config_path": os.path.abspath(CLOUDFLARED_CONFIG_PATH),
        "fallback_config_path": os.path.abspath(CLOUDFLARED_FALLBACK_CONFIG_PATH),
    }


@app.patch("/cloudflared/routes/{route_id}")
def update_cloudflared_route(route_id: int, data: UpdateCloudflaredRouteRequest, user=Depends(require_role("admin"))):
    existing = get_cloudflared_route_record(route_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Cloudflared route not found")

    if (
        data.hostname is None
        and data.service_scheme is None
        and data.service_host is None
        and data.service_port is None
    ):
        raise HTTPException(status_code=400, detail="At least one field must be provided to update")

    final_hostname = normalize_cloudflared_hostname(data.hostname) if data.hostname is not None else existing["hostname"]
    final_service_scheme = (
        normalize_cloudflared_service_scheme(data.service_scheme)
        if data.service_scheme is not None
        else existing["service_scheme"]
    )
    final_service_host = (
        normalize_cloudflared_service_host(data.service_host)
        if data.service_host is not None
        else existing["service_host"]
    )

    if data.service_port is not None:
        if data.service_port < 1 or data.service_port > 65535:
            raise HTTPException(status_code=400, detail="service_port must be between 1 and 65535")
        final_service_port = data.service_port
    else:
        final_service_port = existing["service_port"]

    try:
        changed = update_cloudflared_route_record(
            route_id=route_id,
            hostname=final_hostname,
            service_scheme=final_service_scheme,
            service_host=final_service_host,
            service_port=final_service_port,
        )
        if not changed:
            raise HTTPException(status_code=404, detail="Cloudflared route not found")

        used_config_path = sync_managed_cloudflared_routes()
        dns_result = ensure_cloudflared_dns_route(final_hostname)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="This hostname already exists in Cloudflared routes")
    except HTTPException as e:
        try:
            update_cloudflared_route_record(
                route_id=route_id,
                hostname=existing["hostname"],
                service_scheme=existing["service_scheme"],
                service_host=existing["service_host"],
                service_port=existing["service_port"],
            )
            sync_managed_cloudflared_routes()
        except Exception:
            pass
        raise e
    except Exception as e:
        try:
            update_cloudflared_route_record(
                route_id=route_id,
                hostname=existing["hostname"],
                service_scheme=existing["service_scheme"],
                service_host=existing["service_host"],
                service_port=existing["service_port"],
            )
            sync_managed_cloudflared_routes()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"Failed to update Cloudflared route: {str(e)}")

    updated_record = get_cloudflared_route_record(route_id)

    log_audit(
        user["username"],
        "update_cloudflared_route",
        (
            f"Updated Cloudflared route '{existing['hostname']}' -> '{final_hostname}' "
            f"({final_service_scheme}://{final_service_host}:{final_service_port})"
        ),
    )

    return {
        "status": "updated",
        "route": updated_record,
        "config_path": used_config_path,
        "configured_config_path": os.path.abspath(CLOUDFLARED_CONFIG_PATH),
        "fallback_config_path": os.path.abspath(CLOUDFLARED_FALLBACK_CONFIG_PATH),
        "dns_routed": dns_result["dns_routed"],
        "dns_message": dns_result["dns_message"],
        "tunnel_name": dns_result["tunnel_name"],
        "public_url": f"https://{final_hostname}",
    }


@app.get("/files/browse")
def browse_files(path: str | None = Query(None), user=Depends(require_role("admin"))):
    """Browse directory contents (admin only)"""
    if not path:
        path = os.getcwd()

    if not is_safe_path(path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Path not found")

    if os.path.isfile(path):
        # Return file info if it's a file
        info = get_file_info(path)
        return {"type": "file", "info": info, "parent": os.path.dirname(path)}

    # List directory contents
    items = list_directory(path)
    if items is None:
        raise HTTPException(status_code=500, detail="Failed to read directory")

    parent = os.path.dirname(path) if path != "/" else None

    return {
        "type": "directory",
        "path": path,
        "parent": parent,
        "items": items
    }


@app.post("/files/read")
def read_file(data: FileReadRequest, user=Depends(require_role("admin"))):
    """Read file contents (admin only)"""
    if not is_safe_path(data.path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(data.path):
        raise HTTPException(status_code=404, detail="File not found")

    if not os.path.isfile(data.path):
        raise HTTPException(status_code=400, detail="Path is not a file")

    try:
        with open(data.path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        log_audit(user["username"], "read_file", f"Read file: {data.path}")

        return {
            "path": data.path,
            "content": content,
            "size": len(content)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read file: {str(e)}")


@app.post("/files/write")
def write_file(data: FileWriteRequest, user=Depends(require_role("admin"))):
    """Write file contents (admin only)"""
    if not is_safe_path(data.path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    try:
        # Create parent directory if it doesn't exist
        parent_dir = os.path.dirname(data.path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, mode=0o755, exist_ok=True)

        with open(data.path, "w", encoding="utf-8") as f:
            f.write(data.content)

        log_audit(user["username"], "write_file", f"Wrote file: {data.path}")

        return {"status": "success", "path": data.path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write file: {str(e)}")


@app.post("/files/delete")
def delete_file(data: FileDeleteRequest, user=Depends(require_role("admin"))):
    """Delete file or directory (admin only)"""
    if not is_safe_path(data.path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(data.path):
        raise HTTPException(status_code=404, detail="Path not found")

    try:
        if os.path.isfile(data.path):
            os.remove(data.path)
            log_audit(user["username"], "delete_file", f"Deleted file: {data.path}")
        elif os.path.isdir(data.path):
            import shutil
            shutil.rmtree(data.path)
            log_audit(user["username"], "delete_directory", f"Deleted directory: {data.path}")

        return {"status": "deleted", "path": data.path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete: {str(e)}")


@app.post("/files/mkdir")
def create_directory(data: CreateDirectoryRequest, user=Depends(require_role("admin"))):
    """Create a directory (admin only)"""
    if not is_safe_path(data.path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if os.path.exists(data.path):
        raise HTTPException(status_code=409, detail="Path already exists")

    try:
        os.makedirs(data.path, mode=0o755)
        log_audit(user["username"], "create_directory", f"Created directory: {data.path}")

        return {"status": "created", "path": data.path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create directory: {str(e)}")


@app.post("/files/git-clone")
def git_clone_repository(data: GitCloneRequest, user=Depends(require_role("admin"))):
    """Clone a git repository into a target directory (admin only)."""
    base_path = os.path.abspath((data.path or "").strip())
    repo_url = (data.repo_url or "").strip()
    folder_name = (data.folder_name or "").strip()

    if not base_path:
        raise HTTPException(status_code=400, detail="Target directory path is required")

    if not is_safe_path(base_path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(base_path) or not os.path.isdir(base_path):
        raise HTTPException(status_code=404, detail="Target directory not found")

    if not repo_url:
        raise HTTPException(status_code=400, detail="Repository URL is required")

    if any(ch in repo_url for ch in ("\n", "\r", "\x00")):
        raise HTTPException(status_code=400, detail="Invalid repository URL")

    if repo_url.startswith("-"):
        raise HTTPException(status_code=400, detail="Invalid repository URL")

    if not folder_name:
        folder_name = suggest_git_clone_folder_name(repo_url)

    if not GIT_CLONE_FOLDER_PATTERN.match(folder_name):
        raise HTTPException(
            status_code=400,
            detail="Folder name must be 1-128 chars using letters, numbers, dot, dash, underscore",
        )

    target_path = os.path.abspath(os.path.join(base_path, folder_name))
    base_prefix = base_path.rstrip(os.sep) + os.sep
    if target_path != base_path and not target_path.startswith(base_prefix):
        raise HTTPException(status_code=403, detail="Invalid target path")

    if not is_safe_path(target_path):
        raise HTTPException(status_code=403, detail="Access to target path is forbidden")

    if os.path.exists(target_path):
        raise HTTPException(status_code=409, detail="Target folder already exists")

    try:
        result = subprocess.run(
            ["git", "clone", "--", repo_url, target_path],
            cwd=base_path,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="git is not installed on this server")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="git clone timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to execute git clone: {str(e)}")

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "git clone failed").strip()
        raise HTTPException(status_code=400, detail=detail[:1000])

    log_audit(
        user["username"],
        "git_clone_repository",
        f"Cloned repository '{repo_url}' into '{target_path}'",
    )

    return {
        "status": "cloned",
        "repo_url": repo_url,
        "path": target_path,
        "folder_name": folder_name,
    }


@app.post("/files/chmod")
def change_permissions(data: FilePermissionsRequest, user=Depends(require_role("admin"))):
    """Change file permissions (admin only)"""
    if not is_safe_path(data.path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(data.path):
        raise HTTPException(status_code=404, detail="Path not found")

    try:
        # Validate permissions format (e.g., "755", "644")
        if not re.match(r"^[0-7]{3}$", data.permissions):
            raise HTTPException(status_code=400, detail="Invalid permissions format (use 3 octal digits)")

        mode = int(data.permissions, 8)
        os.chmod(data.path, mode)

        log_audit(user["username"], "change_permissions", f"Changed permissions of {data.path} to {data.permissions}")

        return {"status": "updated", "path": data.path, "permissions": data.permissions}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid permissions format")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to change permissions: {str(e)}")


@app.get("/files/download")
def download_file(path: str, user=Depends(require_role("operator"))):
    """Download a file (operator/admin)"""
    if not is_safe_path(path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(path) or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="File not found")

    log_audit(user["username"], "download_file", f"Downloaded file: {path}")
    return FileResponse(path, filename=os.path.basename(path))


@app.get("/files/download-folder")
def download_folder(path: str, user=Depends(require_role("operator"))):
    """Download a directory as a zip archive (operator/admin)"""
    if not is_safe_path(path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(path) or not os.path.isdir(path):
        raise HTTPException(status_code=404, detail="Directory not found")

    folder_name = os.path.basename(path.rstrip(os.sep)) or "folder"
    tmp_zip = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp_zip_path = tmp_zip.name
    tmp_zip.close()

    try:
        shutil.make_archive(tmp_zip_path.replace(".zip", ""), "zip", path)
        log_audit(user["username"], "download_folder", f"Downloaded folder: {path}")

        def _cleanup():
            try:
                os.unlink(tmp_zip_path)
            except OSError:
                pass

        return FileResponse(
            tmp_zip_path,
            media_type="application/zip",
            filename=f"{folder_name}.zip",
            background=BackgroundTask(_cleanup),
        )
    except Exception as e:
        try:
            os.unlink(tmp_zip_path)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail=f"Failed to create zip: {str(e)}")


@app.post("/files/upload")
async def upload_file(path: str, file: UploadFile = File(...), user=Depends(require_role("admin"))):
    """Upload a file to the specified directory (admin only)"""
    if not is_safe_path(path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(path) or not os.path.isdir(path):
        raise HTTPException(status_code=404, detail="Target directory not found")

    target_path = os.path.join(path, file.filename)
    if not is_safe_path(target_path):
        raise HTTPException(status_code=403, detail="Access to target path is forbidden")

    try:
        with open(target_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        log_audit(user["username"], "upload_file", f"Uploaded file: {target_path}")
        return {"status": "uploaded", "path": target_path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload file: {str(e)}")


@app.post("/files/upload-folder")
async def upload_folder(path: str, files: list[UploadFile] = File(...), paths: list[str] = Form(default=[]), user=Depends(require_role("admin"))):
    """Upload multiple files/folders to the specified directory (admin only)"""
    if not is_safe_path(path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(path) or not os.path.isdir(path):
        raise HTTPException(status_code=404, detail="Target directory not found")

    relative_paths = [p.strip() for p in paths if p.strip()] if paths else []

    if len(relative_paths) != len(files):
        relative_paths = [f.filename for f in files]

    uploaded = []
    errors = []
    for file_obj, rel_path in zip(files, relative_paths):
        try:
            safe_rel = rel_path.replace("\\", "/")
            while safe_rel.startswith("/"):
                safe_rel = safe_rel[1:]
            if ".." in safe_rel.split("/"):
                errors.append({"file": rel_path, "error": "Path traversal not allowed"})
                continue

            target_path = os.path.join(path, safe_rel)
            if not is_safe_path(target_path):
                errors.append({"file": rel_path, "error": "Access to target path is forbidden"})
                continue

            target_dir = os.path.dirname(target_path)
            os.makedirs(target_dir, exist_ok=True)

            with open(target_path, "wb") as buffer:
                shutil.copyfileobj(file_obj.file, buffer)

            uploaded.append(target_path)
        except Exception as e:
            errors.append({"file": rel_path, "error": str(e)})

    if uploaded:
        log_audit(user["username"], "upload_folder", f"Uploaded {len(uploaded)} file(s) to {path}")

    return {"status": "completed", "uploaded": len(uploaded), "errors": len(errors), "files": uploaded, "error_details": errors}


@app.websocket("/ws/terminal")
async def websocket_terminal(websocket: WebSocket):
    """Browser terminal over WebSocket with PTY (operator/admin)."""
    session_id = websocket.cookies.get(SESSION_COOKIE_NAME)
    session = get_valid_session(session_id)

    if not session:
        await websocket.close(code=4401, reason="Not authenticated")
        return

    role_rank = ROLE_ORDER.get(session.get("role", ""), 0)
    if role_rank < ROLE_ORDER["operator"]:
        await websocket.close(code=4403, reason="operator role required")
        return

    if not TERMINAL_BACKEND_AVAILABLE:
        await websocket.close(code=4403, reason="Web terminal is not supported on this OS")
        return

    await websocket.accept()

    if (websocket.query_params.get("protocol") or "").strip().lower() == "v2":
        try:
            await websocket.send_text(TERMINAL_PROTOCOL_V2_MARKER)
        except Exception:
            pass

    pid = None
    master_fd = None

    try:
        pid, master_fd = pty.fork()

        if pid == 0:
            shell = os.environ.get("SHELL") or "/bin/bash"
            if not os.path.exists(shell):
                shell = "/bin/sh"
            os.execvp(shell, [shell, "-i"])

        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        def set_pty_window_size(rows: int, cols: int):
            safe_rows = max(5, min(200, int(rows)))
            safe_cols = max(20, min(500, int(cols)))
            winsize = struct.pack("HHHH", safe_rows, safe_cols, 0, 0)
            fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)

        try:
            set_pty_window_size(24, 80)
        except Exception:
            pass

        log_audit(session["username"], "terminal_open", "Opened web terminal session")

        async def pty_to_websocket():
            while True:
                try:
                    data = os.read(master_fd, 4096)
                    if not data:
                        break
                    await websocket.send_text(data.decode("utf-8", errors="replace"))
                except BlockingIOError:
                    await asyncio.sleep(0.02)
                except OSError:
                    break

        async def websocket_to_pty():
            while True:
                data = await websocket.receive_text()
                if master_fd is None:
                    break

                payload = None
                try:
                    payload = json.loads(data)
                except Exception:
                    payload = None

                if isinstance(payload, dict):
                    message_type = str(payload.get("type", "")).strip().lower()

                    if message_type == "resize":
                        try:
                            rows = int(payload.get("rows", 24))
                            cols = int(payload.get("cols", 80))
                            set_pty_window_size(rows, cols)
                            if pid:
                                try:
                                    os.kill(pid, signal.SIGWINCH)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        continue

                    if message_type == "input":
                        input_data = payload.get("data", "")
                        if isinstance(input_data, str) and input_data:
                            os.write(master_fd, input_data.encode("utf-8", errors="ignore"))
                        continue

                if data:
                    os.write(master_fd, data.encode("utf-8", errors="ignore"))

        await asyncio.gather(pty_to_websocket(), websocket_to_pty())

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_text(f"\r\n[terminal error] {str(e)}\r\n")
        except Exception:
            pass
    finally:
        if master_fd is not None:
            try:
                os.close(master_fd)
            except Exception:
                pass

        if pid:
            try:
                os.kill(pid, signal.SIGHUP)
            except Exception:
                pass

        log_audit(session["username"], "terminal_close", "Closed web terminal session")


# 🤖 AI ASSISTANT ENDPOINTS
from ai.models import AIChatRequest, AIActionConfirmation, AIAnalyzeRequest


def _get_ai_chat(user: dict):
    if AI_PROVIDER == "nvidia" and NVIDIA_API_KEY:
        return NvidiaChat(user)
    return GeminiChat(user)


@app.post("/ai/chat")
async def ai_chat(
    request: AIChatRequest,
    user: dict = Depends(get_current_user),
):
    if not check_chat_rate_limit(user["session_id"]):
        raise HTTPException(429, detail="Rate limit exceeded. Try again in a minute.")

    image_patterns = ['data:image', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp']
    if any(p in request.message.lower() for p in image_patterns):
        async def error_stream():
            import json
            yield f"data: {json.dumps({'type': 'error', 'message': 'Image input is not supported. Please describe what you need instead.'})}\n\n"
        return StreamingResponse(error_stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})

    async def event_stream():
        chat = _get_ai_chat(user)
        async for event in chat.chat_stream(request.message):
            import json
            yield f"data: {json.dumps(event)}\n\n"

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
    if AI_PROVIDER == "nvidia":
        has_key = bool(NVIDIA_API_KEY)
        return {
            "available": has_key,
            "provider": "nvidia",
            "model": NVIDIA_MODEL if has_key else None,
            "configured": has_key,
        }
    has_key = bool(GEMINI_API_KEY and GEMINI_API_KEY != "YOUR_KEY")
    return {
        "available": has_key,
        "provider": "gemini",
        "model": GEMINI_MODEL if has_key else None,
        "configured": has_key,
    }


@app.post("/ai/analyze")
async def ai_analyze(
    data: AIAnalyzeRequest,
    user: dict = Depends(require_role("operator")),
):
    chat = _get_ai_chat(user)
    analysis = await chat.analyze(data.trigger, data.context)
    return analysis


@app.get("/ai/conversations")
async def ai_conversations(
    user: dict = Depends(get_current_user),
    limit: int = Query(default=50, le=100),
):
    conn = sqlite3.connect(USERS_DB_PATH)
    cursor = conn.execute(
        "SELECT id, action, details, timestamp FROM audit_logs "
        "WHERE action LIKE 'ai_%' AND details LIKE ? "
        "ORDER BY timestamp DESC LIMIT ?",
        (f"%{user['session_id']}%", limit),
    )
    rows = cursor.fetchall()
    conn.close()
    rows = cursor.fetchall()
    conn.close()
    return {"conversations": [{"id": r[0], "action": r[1], "details": r[2], "timestamp": r[3]} for r in rows]}


# ─── PM2 Manager Integration ──────────────────────────────────────────────────

def get_pm2_cmd() -> str:
    # Try finding globally on system path
    pm2_path = shutil.which("pm2")
    if pm2_path:
        return pm2_path
    
    # Try common Windows global npm path
    appdata = os.environ.get("APPDATA")
    if appdata:
        win_path = os.path.join(appdata, "npm", "pm2.cmd")
        if os.path.exists(win_path):
            return win_path
            
    # Try Unix npm global path or fallback
    return "pm2"


def parse_pm2_jlist(output: str) -> list:
    # Filter out [PM2] status messages
    lines = []
    for line in output.splitlines():
        if line.strip().startswith("[PM2]"):
            continue
        lines.append(line)
    clean_output = "\n".join(lines).strip()
    # Find start of JSON array
    start_idx = clean_output.find("[")
    if start_idx != -1:
        clean_output = clean_output[start_idx:]
    if not clean_output:
        return []
    return json.loads(clean_output)


def validate_app_name(name: str):
    if not name or not re.match(r"^[a-zA-Z0-9\-_.]+$", name):
        raise HTTPException(status_code=400, detail="Invalid application name. Only alphanumeric characters, dashes, underscores, and dots are allowed.")


def validate_path(path: str):
    if not path:
        return
    # Allow safe characters for file paths on Windows/Linux (letters, digits, slash, backslash, colon, dot, space, dash, underscore, tilde, at-sign)
    if not re.match(r"^[a-zA-Z0-9\-_./\\: ~@]+$", path):
        raise HTTPException(status_code=400, detail="Invalid path characters.")


class PM2StartRequest(BaseModel):
    name: str
    script: str
    cwd: str | None = None
    interpreter: str | None = None
    args: str | None = None
    env_vars: dict | None = None
    autorestart: bool = True
    watch: bool = False
    instances: int | None = None
    max_memory_restart: str | None = None
    startup_delay: int | None = None
    cron_restart: str | None = None


class PM2ActionRequest(BaseModel):
    action: str  # start, stop, restart, delete, reload, restart_all, stop_all, save, reload_pm2, kill, startup
    app_name: str | None = None  # target app name or id (if applicable)


@app.get("/api/pm2/list")
async def pm2_list(user: dict = Depends(require_role("admin"))):
    pm2_cmd = get_pm2_cmd()
    try:
        # Run pm2 jlist
        result = subprocess.run(
            [pm2_cmd, "jlist"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=15
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=result.stderr or "PM2 jlist execution failed")
        
        apps = parse_pm2_jlist(result.stdout)
        
        formatted = []
        for app in apps:
            pm2_env = app.get("pm2_env", {})
            monit = app.get("monit", {})
            
            cpu = monit.get("cpu", 0)
            memory = monit.get("memory", 0)
            
            uptime = 0
            pm_uptime = pm2_env.get("pm_uptime", 0)
            if pm_uptime:
                uptime = int(time.time() * 1000) - pm_uptime
                if uptime < 0:
                    uptime = 0
            
            formatted.append({
                "id": app.get("pm_id"),
                "name": app.get("name"),
                "pid": app.get("pid"),
                "status": pm2_env.get("status"),
                "cpu": cpu,
                "memory": memory,
                "uptime": uptime,
                "restarts": pm2_env.get("restart_time", 0),
                "version": pm2_env.get("version", "N/A"),
                "cwd": pm2_env.get("pm_cwd") or pm2_env.get("cwd") or "N/A",
                "script": pm2_env.get("pm_exec_path", "N/A"),
                "instances": pm2_env.get("instances", 1),
                "node_version": pm2_env.get("node_version", "N/A"),
                "out_log": pm2_env.get("pm_out_log_path"),
                "err_log": pm2_env.get("pm_err_log_path"),
            })
        return formatted
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="PM2 command timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to query PM2: {str(e)}")


@app.post("/api/pm2/action")
async def pm2_action(data: PM2ActionRequest, user: dict = Depends(require_role("admin"))):
    pm2_cmd = get_pm2_cmd()
    action = data.action
    app_name = data.app_name
    
    if app_name:
        if not app_name.isdigit():
            validate_app_name(app_name)
            
    cmd_args = [pm2_cmd]
    
    if action == "start":
        if not app_name:
            raise HTTPException(status_code=400, detail="App name is required for start action")
        cmd_args.extend(["start", app_name])
        audit_desc = f"Started PM2 app: {app_name}"
    elif action == "stop":
        if not app_name:
            raise HTTPException(status_code=400, detail="App name is required for stop action")
        cmd_args.extend(["stop", app_name])
        audit_desc = f"Stopped PM2 app: {app_name}"
    elif action == "restart":
        if not app_name:
            raise HTTPException(status_code=400, detail="App name is required for restart action")
        cmd_args.extend(["restart", app_name])
        audit_desc = f"Restarted PM2 app: {app_name}"
    elif action == "delete":
        if not app_name:
            raise HTTPException(status_code=400, detail="App name is required for delete action")
        cmd_args.extend(["delete", app_name])
        audit_desc = f"Deleted PM2 app: {app_name}"
    elif action == "reload":
        if not app_name:
            raise HTTPException(status_code=400, detail="App name is required for reload action")
        cmd_args.extend(["reload", app_name])
        audit_desc = f"Reloaded PM2 app: {app_name}"
    elif action == "restart_all":
        cmd_args.extend(["restart", "all"])
        audit_desc = "Restarted all PM2 apps"
    elif action == "stop_all":
        cmd_args.extend(["stop", "all"])
        audit_desc = "Stopped all PM2 apps"
    elif action == "save":
        cmd_args.extend(["save"])
        audit_desc = "Saved PM2 process list"
    elif action == "reload_pm2":
        cmd_args.extend(["reload", "all"])
        audit_desc = "Reloaded PM2 daemon/all processes"
    elif action == "kill":
        cmd_args.extend(["kill"])
        audit_desc = "Killed PM2 daemon"
    elif action == "startup":
        cmd_args.extend(["startup"])
        audit_desc = "Ran PM2 startup configuration"
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported action: {action}")
        
    try:
        result = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=30
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=result.stderr or result.stdout or f"PM2 {action} failed")
        
        log_audit(user["username"], f"pm2_{action}", audit_desc)
        return {"status": "success", "message": result.stdout}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="PM2 command timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def expand_home_dir(path_str: str) -> str:
    if not path_str:
        return path_str
    if path_str == "~":
        return os.path.expanduser("~")
    if path_str.startswith("~/") or path_str.startswith("~\\"):
        return os.path.join(os.path.expanduser("~"), path_str[2:])
    return path_str


@app.post("/api/pm2/start-app")
async def pm2_start_app(data: PM2StartRequest, user: dict = Depends(require_role("admin"))):
    pm2_cmd = get_pm2_cmd()
    
    validate_app_name(data.name)
    
    import shlex
    script_str = data.script.strip()
    try:
        parts = shlex.split(script_str)
    except Exception:
        parts = script_str.split()
        
    if len(parts) > 1:
        actual_script = parts[0]
        extra_args = parts[1:]
        if data.args:
            try:
                extra_args.extend(shlex.split(data.args))
            except Exception:
                extra_args.extend(data.args.split())
        actual_args = " ".join(extra_args)
    else:
        actual_script = script_str
        actual_args = data.args
        
    actual_script = expand_home_dir(actual_script)
    validate_path(actual_script)
    if data.cwd:
        validate_path(data.cwd)
        
    cmd_args = [pm2_cmd, "start", actual_script, "--name", data.name]
    
    if data.interpreter and data.interpreter.lower() != "auto":
        valid_interpreters = {"node", "node.js", "python", "python3", "bun", "bash", "php"}
        interpreter_val = data.interpreter.lower()
        if interpreter_val in valid_interpreters or re.match(r"^[a-zA-Z0-9\-./\\_]+$", data.interpreter):
            cmd_args.extend(["--interpreter", data.interpreter])
            
    if data.cwd:
        cmd_args.extend(["--cwd", data.cwd])
        
    if not data.autorestart:
        cmd_args.append("--no-autorestart")
        
    if data.watch:
        cmd_args.append("--watch")
        
    if data.instances is not None:
        cmd_args.extend(["-i", str(data.instances)])
        
    if data.max_memory_restart:
        if re.match(r"^\d+[KMGkmg]$", data.max_memory_restart):
            cmd_args.extend(["--max-memory-restart", data.max_memory_restart])
            
    if data.startup_delay:
        cmd_args.extend(["--restart-delay", str(data.startup_delay * 1000)])
        
    if data.cron_restart:
        if re.match(r"^[0-9\s*/,\-]+$", data.cron_restart):
            cmd_args.extend(["--cron-restart", data.cron_restart])
            
    if actual_args:
        try:
            split_args = shlex.split(actual_args)
        except Exception:
            split_args = actual_args.split()
        split_args = [expand_home_dir(arg) for arg in split_args]
        cmd_args.extend(["--", *split_args])
        
    env = os.environ.copy()
    if data.env_vars:
        for k, v in data.env_vars.items():
            if re.match(r"^[a-zA-Z0-9_]+$", k):
                env[k] = str(v)
                
    try:
        result = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            env=env,
            timeout=30
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=result.stderr or result.stdout or "Failed to start application")
            
        log_audit(user["username"], "pm2_start_app", f"Started PM2 application: {data.name}")
        return {"status": "success", "message": result.stdout}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="PM2 command timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/pm2/logs/{app_name}")
async def pm2_get_logs(
    app_name: str,
    limit: int = Query(default=100, ge=1, le=5000),
    user: dict = Depends(require_role("admin"))
):
    pm2_cmd = get_pm2_cmd()
    
    if not app_name.isdigit():
        validate_app_name(app_name)
        
    # Attempt direct file reading first for better performance
    try:
        # Find paths via jlist
        jlist_res = subprocess.run(
            [pm2_cmd, "jlist"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=10
        )
        apps = parse_pm2_jlist(jlist_res.stdout)
        target_app = None
        for app in apps:
            if str(app.get("pm_id")) == app_name or app.get("name") == app_name:
                target_app = app
                break
                
        if target_app:
            pm2_env = target_app.get("pm2_env", {})
            out_path = pm2_env.get("pm_out_log_path")
            err_path = pm2_env.get("pm_err_log_path")
            
            logs = []
            def read_file_tail(path, label):
                if path and os.path.exists(path):
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        return f"--- {label} (last {min(len(lines), limit)} lines) ---\n" + "".join(lines[-limit:])
                return ""
                
            stdout_logs = read_file_tail(out_path, "STDOUT")
            stderr_logs = read_file_tail(err_path, "STDERR")
            
            if stdout_logs:
                logs.append(stdout_logs)
            if stderr_logs:
                logs.append(stderr_logs)
                
            if logs:
                return {"logs": "\n\n".join(logs)}
    except Exception:
        pass

    # Fallback to execution
    try:
        result = subprocess.run(
            [pm2_cmd, "logs", app_name, "--lines", str(limit), "--raw"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=15
        )
        return {"logs": result.stdout or result.stderr or "No logs retrieved."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read logs: {str(e)}")


@app.websocket("/ws/pm2/logs/{app_name}/stream")
async def ws_pm2_logs_stream(websocket: WebSocket, app_name: str):
    session_id = websocket.cookies.get(SESSION_COOKIE_NAME)
    session = get_valid_session(session_id)
    if not session or ROLE_ORDER.get(session.get("role", ""), 0) < ROLE_ORDER["admin"]:
        await websocket.close(code=4403, reason="Admin role required")
        return
        
    if not app_name.isdigit():
        try:
            validate_app_name(app_name)
        except Exception:
            await websocket.close(code=4400, reason="Invalid app name")
            return
            
    await websocket.accept()
    
    pm2_cmd = get_pm2_cmd()
    proc = None
    try:
        proc = subprocess.Popen(
            [pm2_cmd, "logs", app_name, "--raw"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="ignore",
            bufsize=1
        )
        
        loop = asyncio.get_event_loop()
        
        async def read_stdout():
            while True:
                line = await loop.run_in_executor(None, proc.stdout.readline)
                if not line:
                    break
                await websocket.send_text(line)
                
        async def receive_messages():
            try:
                while True:
                    data = await websocket.receive_text()
                    if data == "ping":
                        await websocket.send_text("pong")
            except WebSocketDisconnect:
                pass
                
        await asyncio.gather(
            read_stdout(),
            receive_messages(),
            return_exceptions=True
        )
        
    except Exception as e:
        try:
            await websocket.send_text(f"Error starting log stream: {str(e)}")
        except Exception:
            pass
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        try:
            await websocket.close()
        except Exception:
            pass


if __name__ == "__main__":
    import uvicorn
    # reload is set to False by default to prevent Uvicorn from watching
    # files and restarting during deployments. Set reload=True if developing.
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False
    )

