import json
import time
from db.base import db_connect

# =========================================================================
# MONITORS & HEARTBEATS DAO
# =========================================================================

def db_get_monitors():
    """Returns a list of all monitors with their 50 most recent heartbeats."""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, name, tag, type, url, target, interval, active, status,
               uptime24h, uptime30d, uptime1y, avg_ping, last_ping, last_error,
               threshold, telegram_enabled, telegram_bot_token, telegram_chat_id,
               config_json, created_at
        FROM kuma_monitors
        ORDER BY created_at ASC
    """)
    rows = cur.fetchall()
    monitors = []
    for r in rows:
        m = {
            "id": r[0],
            "name": r[1],
            "tag": r[2] or r[1],
            "type": r[3],
            "url": r[4] or "",
            "target": r[5] or "",
            "interval": r[6] or 60,
            "active": bool(r[7]),
            "status": r[8] or "pending",
            "uptime24h": round(r[9], 2) if r[9] is not None else 100.0,
            "uptime30d": round(r[10], 2) if r[10] is not None else 100.0,
            "uptime1y": round(r[11], 2) if r[11] is not None else 100.0,
            "avgPing": round(r[12], 2) if r[12] is not None else 0.0,
            "lastPing": round(r[13], 2) if r[13] is not None else 0.0,
            "lastError": r[14],
            "threshold": r[15] if r[15] is not None else 90.0,
            "telegramEnabled": bool(r[16]) if r[16] is not None else True,
            "telegramBotToken": r[17] or "",
            "telegramChatId": r[18] or "",
            "createdAt": r[20]
        }
        # Fetch up to 50 recent heartbeats
        cur.execute("""
            SELECT status, ping, msg, time
            FROM kuma_heartbeats
            WHERE monitor_id = ?
            ORDER BY time DESC
            LIMIT 50
        """, (m["id"],))
        hb_rows = cur.fetchall()
        # Reverse to chronological order (oldest to newest)
        m["heartbeats"] = [
            {"status": h[0], "ping": h[1], "msg": h[2], "time": h[3]}
            for h in reversed(hb_rows)
        ]
        monitors.append(m)
    conn.close()
    return monitors

def db_get_monitor(monitor_id: str):
    """Returns a single monitor with its recent heartbeats, or None."""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, name, tag, type, url, target, interval, active, status,
               uptime24h, uptime30d, uptime1y, avg_ping, last_ping, last_error,
               threshold, telegram_enabled, telegram_bot_token, telegram_chat_id,
               config_json, created_at
        FROM kuma_monitors
        WHERE id = ?
    """, (monitor_id,))
    r = cur.fetchone()
    if not r:
        conn.close()
        return None
    m = {
        "id": r[0],
        "name": r[1],
        "tag": r[2] or r[1],
        "type": r[3],
        "url": r[4] or "",
        "target": r[5] or "",
        "interval": r[6] or 60,
        "active": bool(r[7]),
        "status": r[8] or "pending",
        "uptime24h": round(r[9], 2) if r[9] is not None else 100.0,
        "uptime30d": round(r[10], 2) if r[10] is not None else 100.0,
        "uptime1y": round(r[11], 2) if r[11] is not None else 100.0,
        "avgPing": round(r[12], 2) if r[12] is not None else 0.0,
        "lastPing": round(r[13], 2) if r[13] is not None else 0.0,
        "lastError": r[14],
        "threshold": r[15] if r[15] is not None else 90.0,
        "telegramEnabled": bool(r[16]) if r[16] is not None else True,
        "telegramBotToken": r[17] or "",
        "telegramChatId": r[18] or "",
        "createdAt": r[20]
    }
    cur.execute("""
        SELECT status, ping, msg, time
        FROM kuma_heartbeats
        WHERE monitor_id = ?
        ORDER BY time DESC
        LIMIT 50
    """, (monitor_id,))
    hb_rows = cur.fetchall()
    m["heartbeats"] = [
        {"status": h[0], "ping": h[1], "msg": h[2], "time": h[3]}
        for h in reversed(hb_rows)
    ]
    conn.close()
    return m

def db_save_monitor(m: dict):
    """Inserts or updates a monitor record in the database."""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO kuma_monitors (
            id, name, tag, type, url, target, interval, active, status,
            uptime24h, uptime30d, uptime1y, avg_ping, last_ping, last_error,
            threshold, telegram_enabled, telegram_bot_token, telegram_chat_id,
            config_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        str(m.get("id")),
        m.get("name", "New Monitor"),
        m.get("tag") or m.get("name"),
        m.get("type", "http"),
        m.get("url", ""),
        m.get("target", ""),
        int(m.get("interval", 60)),
        1 if m.get("active", True) else 0,
        m.get("status", "pending"),
        float(m.get("uptime24h", 100.0)),
        float(m.get("uptime30d", 100.0)),
        float(m.get("uptime1y", 100.0)),
        float(m.get("avgPing", 0.0)),
        float(m.get("lastPing", 0.0)),
        m.get("lastError"),
        float(m.get("threshold", 90.0)),
        1 if m.get("telegramEnabled", True) else 0,
        m.get("telegramBotToken", ""),
        m.get("telegramChatId", ""),
        json.dumps(m.get("config", {})),
        int(m.get("createdAt", time.time() * 1000))
    ))
    conn.commit()
    conn.close()

def db_delete_monitor(monitor_id: str):
    """Deletes a monitor and its heartbeats."""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM kuma_monitors WHERE id = ?", (monitor_id,))
    cur.execute("DELETE FROM kuma_heartbeats WHERE monitor_id = ?", (monitor_id,))
    conn.commit()
    conn.close()

def db_add_heartbeat(monitor_id: str, hb: dict):
    """Inserts a new heartbeat record and trims older ones beyond 1000 per monitor."""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO kuma_heartbeats (monitor_id, status, ping, msg, time)
        VALUES (?, ?, ?, ?, ?)
    """, (
        monitor_id,
        hb.get("status", "up"),
        float(hb.get("ping", 0.0)),
        hb.get("msg", ""),
        int(hb.get("time", time.time() * 1000))
    ))
    # Optional trim to keep DB lean: retain last 500 heartbeats
    cur.execute("""
        DELETE FROM kuma_heartbeats
        WHERE monitor_id = ? AND id NOT IN (
            SELECT id FROM kuma_heartbeats
            WHERE monitor_id = ?
            ORDER BY time DESC
            LIMIT 500
        )
    """, (monitor_id, monitor_id))
    conn.commit()
    conn.close()

def db_clear_heartbeats(monitor_id: str):
    """Clears all heartbeat history for a monitor."""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM kuma_heartbeats WHERE monitor_id = ?", (monitor_id,))
    cur.execute("""
        UPDATE kuma_monitors
        SET uptime24h = 100.0, uptime30d = 100.0, uptime1y = 100.0,
            avg_ping = 0.0, last_ping = 0.0, last_error = NULL
        WHERE id = ?
    """, (monitor_id,))
    conn.commit()
    conn.close()


# =========================================================================
# SETTINGS DAO (TELEGRAM & CONFIGS)
# =========================================================================

def db_get_telegram_settings() -> dict:
    """Returns global Telegram settings."""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT value FROM settings WHERE key = 'telegram'")
    row = cur.fetchone()
    conn.close()
    if row:
        try:
            return json.loads(row[0])
        except Exception:
            pass
    return {
        "enabled": False,
        "botToken": "",
        "chatId": ""
    }

def db_save_telegram_settings(settings: dict):
    """Persists global Telegram settings."""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO settings(key, value) VALUES('telegram', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (json.dumps(settings),)
    )
    conn.commit()
    conn.close()


# =========================================================================
# STATUS PAGE DAO
# =========================================================================

def db_get_all_status_pages() -> list:
    """Returns list of summaries for all status pages."""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT slug, title, description, is_public FROM status_pages ORDER BY rowid ASC")
    rows = cur.fetchall()
    conn.close()
    if not rows:
        def_page = db_get_status_page("monitor")
        return [{
            "slug": def_page["slug"],
            "title": def_page["title"],
            "description": def_page["description"],
            "isPublic": def_page["isPublic"]
        }]
    return [
        {
            "slug": r[0],
            "title": r[1],
            "description": r[2] or "",
            "isPublic": bool(r[3] != 0)
        }
        for r in rows
    ]

def db_get_status_page(slug: str = "monitor") -> dict:
    """Returns complete status page configuration with groups and active incidents."""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        SELECT slug, title, description, footer_text, refresh_interval, theme,
               show_tags, show_powered_by, show_certificate_expiry,
               show_only_last_heartbeat, domain_names, groups_json, is_public
        FROM status_pages
        WHERE slug = ?
    """, (slug,))
    row = cur.fetchone()

    cur.execute("""
        SELECT id, title, content, style, created_at
        FROM status_page_incidents
        WHERE status_page_slug = ?
        ORDER BY created_at DESC
    """, (slug,))
    inc_rows = cur.fetchall()
    incidents = [
        {
            "id": i[0],
            "title": i[1],
            "content": i[2] or "",
            "style": i[3] or "warning",
            "createdAt": i[4]
        }
        for i in inc_rows
    ]

    if not row:
        if slug in ("monitor", "status", "default"):
            def_config = {
                "slug": slug,
                "title": "System Status",
                "description": "Live service and infrastructure telemetry",
                "footerText": "Powered by Server Dashboard",
                "refreshInterval": 300,
                "theme": "auto",
                "showTags": False,
                "showPoweredBy": True,
                "showCertificateExpiry": False,
                "showOnlyLastHeartbeat": False,
                "domainNames": [],
                "groups": [
                    {
                        "id": "g1",
                        "name": "Services",
                        "monitorIds": []
                    }
                ],
                "incidents": incidents,
                "isPublic": True
            }
            conn.close()
            db_save_status_page(def_config)
            return def_config
        conn.close()
        return None

    groups = []
    try:
        groups = json.loads(row[11] or "[]")
    except Exception:
        pass

    domain_names = []
    try:
        domain_names = json.loads(row[10] or "[]")
    except Exception:
        pass

    res = {
        "slug": row[0],
        "title": row[1],
        "description": row[2] or "",
        "footerText": row[3] or "",
        "refreshInterval": row[4] or 300,
        "theme": row[5] or "auto",
        "showTags": bool(row[6]),
        "showPoweredBy": bool(row[7]),
        "showCertificateExpiry": bool(row[8]),
        "showOnlyLastHeartbeat": bool(row[9]),
        "domainNames": domain_names,
        "groups": groups,
        "isPublic": bool(row[12] != 0),
        "incidents": incidents
    }
    conn.close()
    return res

def db_save_status_page(config: dict):
    """Inserts or updates a status page config."""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO status_pages (
            slug, title, description, footer_text, refresh_interval, theme,
            show_tags, show_powered_by, show_certificate_expiry, show_only_last_heartbeat,
            domain_names, groups_json, is_public
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        config.get("slug", "monitor"),
        config.get("title", "System Status"),
        config.get("description", ""),
        config.get("footerText", "Powered by Server Dashboard"),
        int(config.get("refreshInterval", 300)),
        config.get("theme", "auto"),
        1 if config.get("showTags") else 0,
        1 if config.get("showPoweredBy", True) else 0,
        1 if config.get("showCertificateExpiry") else 0,
        1 if config.get("showOnlyLastHeartbeat") else 0,
        json.dumps(config.get("domainNames", [])),
        json.dumps(config.get("groups", [])),
        1 if config.get("isPublic", True) else 0
    ))
    conn.commit()
    conn.close()

def db_delete_status_page(slug: str):
    """Deletes a status page and its incidents."""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM status_pages WHERE slug = ?", (slug,))
    cur.execute("DELETE FROM status_page_incidents WHERE status_page_slug = ?", (slug,))
    conn.commit()
    conn.close()

def db_add_incident(slug: str, incident: dict):
    """Adds or updates an incident for a status page."""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO status_page_incidents (
            id, status_page_slug, title, content, style, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
    """, (
        incident.get("id"),
        slug,
        incident.get("title", "Service Degradation"),
        incident.get("content", ""),
        incident.get("style", "warning"),
        incident.get("createdAt")
    ))
    conn.commit()
    conn.close()

def db_delete_incident(incident_id: str):
    """Deletes an incident by ID."""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM status_page_incidents WHERE id = ?", (incident_id,))
    conn.commit()
    conn.close()
