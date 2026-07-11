import sqlite3
import os
import json
import time
import sys
import config

def db_connect():
    return sqlite3.connect(config.USERS_DB_PATH)

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

# Alert Rules CRUD
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

# Pinned Services & Pinned Ports CRUD
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

# Todos CRUD
def list_todos():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT id, text, completed FROM todos ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "text": row[1],
            "done": bool(row[2]),
        }
        for row in rows
    ]

def create_todo(text: str):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("INSERT INTO todos(text, completed) VALUES(?, 0)", (text,))
    new_id = cur.lastrowid
    conn.commit()
    conn.close()

    return {
        "id": new_id,
        "text": text,
        "done": False,
    }

def update_todo_done(todo_id: int, done: bool):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("UPDATE todos SET completed = ? WHERE id = ?", (1 if done else 0, todo_id))
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

# SSH Public Keys CRUD
def list_ssh_public_keys(ssh_user: str | None = None):
    conn = db_connect()
    cur = conn.cursor()

    if ssh_user:
        cur.execute(
            """
            SELECT id, name, username, key_type, public_key, fingerprint, added_at
            FROM ssh_public_keys
            WHERE username = ?
            ORDER BY id DESC
            """,
            (ssh_user,),
        )
    else:
        cur.execute(
            """
            SELECT id, name, username, key_type, public_key, fingerprint, added_at
            FROM ssh_public_keys
            ORDER BY id DESC
            """
        )

    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "ssh_user": row[2],
            "label": row[1],
            "key_type": row[3],
            "key_body": row[4],
            "fingerprint_sha256": row[5],
            "created_at": row[6],
        }
        for row in rows
    ]

def list_ssh_public_key_rows_for_user(ssh_user: str):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, key_type, public_key, name
        FROM ssh_public_keys
        WHERE username = ?
        ORDER BY id ASC
        """,
        (ssh_user,),
    )
    rows = cur.fetchall()
    conn.close()
    # Return mapping matching query to original database.py signature
    # Signature used: rows = database.list_ssh_public_key_rows_for_user(ssh_user) -> (id, key_type, key_body, key_comment)
    return [(row[0], row[1], row[2], row[3]) for row in rows]

def get_ssh_public_key_record(key_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, name, username, key_type, public_key, fingerprint, added_at
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
        "ssh_user": row[2],
        "label": row[1],
        "key_type": row[3],
        "key_body": row[4],
        "fingerprint_sha256": row[5],
        "created_at": row[6],
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
    # Note: original database.py table maps (name, username, key_type, public_key, fingerprint, added_at)
    now = int(time.time())
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO ssh_public_keys(
            name,
            username,
            key_type,
            public_key,
            fingerprint,
            added_at
        )
        VALUES(?, ?, ?, ?, ?, ?)
        """,
        (label, ssh_user, key_type, key_body, fingerprint_sha256, now),
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()

    return {
        "id": new_id,
        "ssh_user": ssh_user,
        "label": label,
        "key_type": key_type,
        "key_body": key_body,
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

# Cloudflared Routes CRUD
def list_cloudflared_routes():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, hostname, service_url, scheme, unmanaged, added_at
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
            "service_scheme": row[3],
            # Parse service_url to split service_host and service_port if possible
            "service_host": row[2].split(":")[0] if ":" not in row[2] or row[2].startswith("http") else row[2].split(":")[0],
            "service_port": int(row[2].split(":")[-1]) if ":" in row[2] else 80,
            "created_by": "system" if row[4] else "admin", # map original schema fields to expected dict structure
            "created_at": row[5],
        }
        for row in rows
    ]

def list_cloudflared_route_rows():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, hostname, scheme, service_url
        FROM cloudflared_routes
        ORDER BY id ASC
        """
    )
    rows = cur.fetchall()
    conn.close()
    # Signature used: (id, hostname, service_scheme, service_host, service_port)
    ret = []
    for r in rows:
        srv_url = r[3]
        # remove scheme prefix if any
        clean_url = srv_url
        if "://" in srv_url:
            clean_url = srv_url.split("://", 1)[1]
        host = clean_url.split(":", 1)[0]
        port = int(clean_url.split(":", 1)[1]) if ":" in clean_url else 80
        ret.append((r[0], r[1], r[2], host, port))
    return ret

def get_cloudflared_route_record(route_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, hostname, service_url, scheme, unmanaged, added_at
        FROM cloudflared_routes
        WHERE id = ?
        """,
        (route_id,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None

    srv_url = row[2]
    clean_url = srv_url
    if "://" in srv_url:
        clean_url = srv_url.split("://", 1)[1]
    host = clean_url.split(":", 1)[0]
    port = int(clean_url.split(":", 1)[1]) if ":" in clean_url else 80

    return {
        "id": row[0],
        "hostname": row[1],
        "service_scheme": row[3],
        "service_host": host,
        "service_port": port,
        "created_by": "system" if row[4] else "admin",
        "created_at": row[5],
    }

def create_cloudflared_route_record(
    hostname: str,
    service_scheme: str,
    service_host: str,
    service_port: int,
    created_by: str,
):
    now = int(time.time())
    service_url = f"{service_host}:{service_port}"
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO cloudflared_routes(
            hostname,
            service_url,
            scheme,
            unmanaged,
            added_at
        )
        VALUES(?, ?, ?, 0, ?)
        """,
        (hostname, service_url, service_scheme, now),
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
    service_url = f"{service_host}:{service_port}"
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE cloudflared_routes
        SET hostname = ?, service_url = ?, scheme = ?
        WHERE id = ?
        """,
        (hostname, service_url, service_scheme, route_id),
    )
    updated = cur.rowcount
    conn.commit()
    conn.close()
    return updated > 0

def restore_cloudflared_route_record(record: dict):
    conn = db_connect()
    cur = conn.cursor()
    service_url = f"{record['service_host']}:{record['service_port']}"
    unmanaged = 1 if record.get("created_by") == "system" else 0
    cur.execute(
        """
        INSERT INTO cloudflared_routes(
            id,
            hostname,
            service_url,
            scheme,
            unmanaged,
            added_at
        )
        VALUES(?, ?, ?, ?, ?, ?)
        """,
        (
            record["id"],
            record["hostname"],
            service_url,
            record["service_scheme"],
            unmanaged,
            record["created_at"],
        ),
    )
    conn.commit()
    conn.close()
