import sqlite3
import time
from db.base import db_connect

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
