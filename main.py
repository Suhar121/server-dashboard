from fastapi import FastAPI, HTTPException, Query, Cookie, Response, Depends, Request, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel
import psutil
import subprocess
import socket
import requests
import os
import signal
import shutil
import asyncio
import pty
import fcntl
from collections import deque
import secrets
import time
import sqlite3
import hashlib
import hmac
import re
import base64
import pwd

app = FastAPI()

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

# 🔑 TELEGRAM CONFIG
BOT_TOKEN = os.getenv("BOT_TOKEN", "YOUR_TOKEN")
CHAT_ID = os.getenv("CHAT_ID", "YOUR_CHAT_ID")
SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))
SESSION_TIMEOUT_SECONDS = max(60, SESSION_TIMEOUT_MINUTES * 60)
SESSION_COOKIE_NAME = "dashboard_session"
USERS_DB_PATH = os.getenv("USERS_DB_PATH", "users.db")
PASSWORD_ITERATIONS = 150_000
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")
SSH_USERNAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")

ROLE_ORDER = {
    "viewer": 1,
    "operator": 2,
    "admin": 3,
}

BATTERY_THRESHOLD = 20
battery_alert_sent = False
managed_services = {}
active_sessions = {}
alert_last_sent = {}  # Track when alerts were last sent to avoid spam
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


class SaveServiceRequest(BaseModel):
    name: str
    port: int
    command: str


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


def normalize_service_name(name: str) -> str:
    allowed = "-_"
    cleaned = "".join(ch for ch in name if ch.isalnum() or ch in allowed).strip("-_")
    return cleaned or "service"


def is_process_running(proc: subprocess.Popen | None) -> bool:
    return proc is not None and proc.poll() is None


def db_connect():
    return sqlite3.connect(USERS_DB_PATH)


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

    cur.execute("PRAGMA table_info(users)")
    user_columns = {row[1] for row in cur.fetchall()}
    if "last_login_at" not in user_columns:
        cur.execute("ALTER TABLE users ADD COLUMN last_login_at INTEGER")

    conn.commit()
    conn.close()

    try:
        os.chmod(USERS_DB_PATH, 0o600)
    except Exception:
        pass


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


def create_session(username: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    active_sessions[token] = {
        "username": username,
        "role": role,
        "expires_at": time.time() + SESSION_TIMEOUT_SECONDS,
    }
    return token


def get_current_user(
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
):
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    session = active_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")

    now = time.time()
    if session["expires_at"] < now:
        active_sessions.pop(session_id, None)
        raise HTTPException(status_code=401, detail="Session expired")

    session["expires_at"] = now + SESSION_TIMEOUT_SECONDS

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
        return None

    now = time.time()
    if session["expires_at"] < now:
        active_sessions.pop(session_id, None)
        return None

    session["expires_at"] = now + SESSION_TIMEOUT_SECONDS
    return session


def update_sessions_for_user(username: str, new_role: str | None = None, delete: bool = False):
    to_remove = []
    for token, session in active_sessions.items():
        if session.get("username") == username:
            if delete:
                to_remove.append(token)
            elif new_role:
                session["role"] = new_role

    for token in to_remove:
        active_sessions.pop(token, None)


def send_telegram(msg):
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        requests.post(url, json={"chat_id": CHAT_ID, "text": msg})
    except Exception as e:
        print("Telegram error:", e)


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


@app.post("/auth/login")
async def login(data: LoginRequest, response: Response):
    username = data.username.strip()
    row = get_user_record(username)

    if not row:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    _, password_hash, salt, role, _, _ = row
    if not verify_password(data.password, password_hash, salt):
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


@app.get("/system")
def system(user=Depends(require_role("viewer"))):
    cpu = psutil.cpu_percent()
    memory = psutil.virtual_memory().percent

    # Check alert rules
    check_alert_rules(cpu, memory)

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
        output = subprocess.check_output(
            "docker ps --format '{{.Names}}|{{.Status}}|{{.Ports}}'",
            shell=True
        ).decode().strip().split("\n")

        containers = []
        for line in output:
            if line:
                name, status, ports = line.split("|")
                containers.append({
                    "name": name,
                    "status": status,
                    "ports": ports
                })

        return containers
    except:
        return []


@app.get("/check-port/{port}")
def check_port(port: int, user=Depends(require_role("viewer"))):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)

    result = s.connect_ex(("127.0.0.1", port))
    s.close()

    return {"port": port, "active": result == 0}


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

    await websocket.accept()

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


