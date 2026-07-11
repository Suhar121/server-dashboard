import sqlite3
import os
import json
import time
import secrets
import hashlib
import hmac
import config

def db_connect():
    return sqlite3.connect(config.USERS_DB_PATH)


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


def hash_password(password: str, salt: bytes | None = None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        config.PASSWORD_ITERATIONS,
    )
    return digest.hex(), salt.hex()


def verify_password(password: str, password_hash_hex: str, salt_hex: str):
    salt = bytes.fromhex(salt_hex)
    expected_digest = bytes.fromhex(password_hash_hex)
    candidate_digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        config.PASSWORD_ITERATIONS,
    )
    return hmac.compare_digest(candidate_digest, expected_digest)


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


def create_alert_rule(metric_type: str, threshold: float):
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
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted > 0


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
            name TEXT UNIQUE NOT NULL,
            port INTEGER UNIQUE NOT NULL,
            command TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS pinned_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port INTEGER UNIQUE NOT NULL,
            service_name TEXT,
            command TEXT,
            setup_command TEXT,
            workdir TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            status TEXT NOT NULL DEFAULT 'success'
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric_type TEXT NOT NULL,
            threshold REAL NOT NULL,
            channel TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ssh_public_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT NOT NULL,
            key_type TEXT NOT NULL,
            public_key TEXT UNIQUE NOT NULL,
            fingerprint TEXT NOT NULL,
            added_at INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cloudflared_routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT UNIQUE NOT NULL,
            service_url TEXT NOT NULL,
            scheme TEXT NOT NULL,
            unmanaged INTEGER NOT NULL DEFAULT 0,
            added_at INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_conversations (
            id TEXT PRIMARY KEY,
            history_json TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS app_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            icon TEXT,
            category TEXT,
            default_port INTEGER,
            env_schema TEXT,
            compose_yaml TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS deployed_apps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            template_id INTEGER,
            status TEXT NOT NULL,
            compose_path TEXT NOT NULL,
            ports TEXT NOT NULL,
            env_vars TEXT NOT NULL,
            container_ids TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(template_id) REFERENCES app_templates(id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS github_deployments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_url TEXT NOT NULL,
            branch TEXT NOT NULL,
            app_name TEXT UNIQUE NOT NULL,
            detected_port INTEGER,
            env_vars TEXT NOT NULL DEFAULT '{}',
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

    # Sync existing github_deployments to deployed_apps table if they are missing
    try:
        cur.execute("SELECT app_name, compose_path, env_vars, container_ids, created_by, status, created_at, detected_port FROM github_deployments")
        gh_deps = cur.fetchall()
        for row in gh_deps:
            app_name, compose_path, env_vars_str, container_ids_str, created_by, status, created_at, detected_port = row
            # Check if already exists in deployed_apps
            cur.execute("SELECT id FROM deployed_apps WHERE name = ?", (app_name,))
            existing = cur.fetchone()
            if not existing and status in ("running", "stopped"):
                port_val = detected_port or 80
                ports_list = [port_val] if port_val else []
                cur.execute(
                    """INSERT INTO deployed_apps (name, template_id, status, compose_path, ports, env_vars, container_ids, created_by, created_at)
                       VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?)""",
                    (app_name, status, compose_path, json.dumps(ports_list), env_vars_str, container_ids_str, created_by, created_at)
                )
    except Exception as e:
        print("Failed to sync github deployments to deployed_apps:", e)

    conn.commit()
    conn.close()

    try:
        os.chmod(config.USERS_DB_PATH, 0o600)
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


def get_deployed_app_by_name(name: str):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""SELECT da.id, da.name, da.template_id, da.status, da.compose_path,
                          da.ports, da.env_vars, da.container_ids, da.created_by, da.created_at,
                          t.name as template_name
                   FROM deployed_apps da LEFT JOIN app_templates t ON da.template_id = t.id
                   WHERE da.name = ?""", (name,))
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


def create_github_deployment(app_name, repo_url, branch, deploy_path, created_by):
    now = int(time.time())
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO github_deployments
           (app_name, repo_url, branch, compose_path, status, step_status, created_by, created_at)
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
    if not row:
        conn.close()
        return None
    cols = [d[0] for d in cur.description] if cur.description else []
    conn.close()
    return dict(zip(cols, row))


def get_github_deployment_by_name(app_name):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM github_deployments WHERE app_name = ?", (app_name,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None
    cols = [d[0] for d in cur.description] if cur.description else []
    conn.close()
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

