import sqlite3
import time
import secrets
import hashlib
import hmac
import config
from db.base import db_connect

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
