import json
import time
import psutil
from fastapi import APIRouter, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import config
import database
from routers.auth import require_role, get_valid_session
from uptime.engine import monitor_engine
from uptime.telegram import send_telegram_notification

router = APIRouter(tags=["uptime-kuma"])

# =========================================================================
# SYSTEM DRIVES ENDPOINT
# =========================================================================

@router.get("/api/system/drives")
async def get_system_drives(session: dict = Depends(require_role("viewer"))):
    """Returns local disk drives and their capacity/usage."""
    drives = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            drives.append({
                "mount": part.mountpoint,
                "size": usage.total,
                "used": usage.used,
                "available": usage.free,
                "usePercent": round(usage.percent, 1)
            })
        except Exception:
            continue
    return drives


# =========================================================================
# MONITORS API
# =========================================================================

@router.get("/api/monitors")
async def list_monitors(session: dict = Depends(require_role("viewer"))):
    """Returns all monitors with their latest heartbeat history."""
    return monitor_engine.get_monitors()

@router.post("/api/monitors", status_code=201)
async def create_monitor(request: Request, session: dict = Depends(require_role("operator"))):
    """Creates a new monitor and begins heartbeat monitoring."""
    body = await request.json()
    new_monitor = monitor_engine.add_monitor(body)
    return new_monitor

@router.get("/api/monitors/{monitor_id}")
async def get_monitor(monitor_id: str, session: dict = Depends(require_role("viewer"))):
    """Returns details for a specific monitor."""
    m = next((m for m in monitor_engine.get_monitors() if str(m["id"]) == str(monitor_id)), None)
    if not m:
        raise HTTPException(status_code=404, detail="Monitor not found")
    return m

@router.put("/api/monitors/{monitor_id}")
async def update_monitor(monitor_id: str, request: Request, session: dict = Depends(require_role("operator"))):
    """Updates an existing monitor's configuration."""
    body = await request.json()
    updated = monitor_engine.update_monitor(monitor_id, body)
    if not updated:
        raise HTTPException(status_code=404, detail="Monitor not found")
    return updated

@router.delete("/api/monitors/{monitor_id}")
async def delete_monitor(monitor_id: str, session: dict = Depends(require_role("operator"))):
    """Deletes a monitor and stops its checks."""
    monitor_engine.delete_monitor(monitor_id)
    return {"success": True}

@router.post("/api/monitors/{monitor_id}/pause")
async def toggle_pause_monitor(monitor_id: str, session: dict = Depends(require_role("operator"))):
    """Toggles monitor pause state."""
    updated = monitor_engine.toggle_pause(monitor_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Monitor not found")
    return updated

@router.post("/api/monitors/{monitor_id}/clear")
async def clear_monitor_history(monitor_id: str, session: dict = Depends(require_role("operator"))):
    """Clears a monitor's historical heartbeat ticks."""
    monitor_engine.clear_data(monitor_id)
    return {"success": True}

@router.post("/api/monitors/{monitor_id}/toggle-telegram")
async def toggle_monitor_telegram(monitor_id: str, session: dict = Depends(require_role("operator"))):
    """Quickly toggles Telegram notifications on or off for a monitor."""
    updated = monitor_engine.toggle_telegram(monitor_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Monitor not found")
    return updated


# =========================================================================
# TELEGRAM NOTIFICATIONS SETTINGS
# =========================================================================

@router.get("/api/settings")
async def get_settings(session: dict = Depends(require_role("viewer"))):
    """Returns application integration settings (e.g. Telegram)."""
    return {
        "telegram": database.db_get_telegram_settings()
    }

@router.post("/api/settings")
async def save_settings(request: Request, session: dict = Depends(require_role("admin"))):
    """Saves application integration settings."""
    body = await request.json()
    if "telegram" in body:
        database.db_save_telegram_settings(body["telegram"])
    return {"success": True, "settings": body}

@router.post("/api/settings/telegram/test")
async def test_telegram_notification(request: Request, session: dict = Depends(require_role("admin"))):
    """Sends a test Telegram alert message."""
    body = await request.json()
    bot_token = body.get("botToken", "").strip()
    chat_id = body.get("chatId", "").strip()

    if not bot_token or not chat_id:
        return {"success": False, "error": "Bot Token and Chat ID are required."}

    text = (
        "🎉 <b>Server Dashboard Test Notification</b>\n\n"
        "Your Telegram bot is successfully connected and ready to send downtime and recovery alerts!"
    )
    try:
        result = await send_telegram_notification(bot_token, chat_id, text)
        return {"success": True, "result": result}
    except Exception as err:
        return {"success": False, "error": str(err)}


# =========================================================================
# STATUS PAGE ENDPOINTS
# =========================================================================

@router.get("/api/status-pages")
async def get_all_status_pages(session: dict = Depends(require_role("viewer"))):
    """Lists all available status page configs."""
    return database.db_get_all_status_pages()

def _resolve_status_page(slug: str, session: dict | None = None):
    page = database.db_get_status_page(slug)
    if not page:
        raise HTTPException(status_code=404, detail="Status page not found")

    # If status page is private, ensure valid user session
    if page.get("isPublic") is False:
        if not session:
            return {
                "slug": page.get("slug"),
                "title": page.get("title"),
                "isPublic": False,
                "isRestricted": True,
                "message": "This status page is private. Please sign in to view."
            }

    # Inject latest monitor records for convenience
    all_monitors = {str(m["id"]): m for m in monitor_engine.get_monitors()}
    groups_with_monitors = []
    for g in page.get("groups", []):
        m_list = []
        for mid in g.get("monitorIds", []):
            if str(mid) in all_monitors:
                m_list.append(all_monitors[str(mid)])
        groups_with_monitors.append({
            "id": g.get("id"),
            "name": g.get("name"),
            "monitors": m_list,
            "monitorIds": g.get("monitorIds", [])
        })

    enriched = dict(page)
    enriched["groupDetails"] = groups_with_monitors
    return enriched

@router.get("/api/status-page")
async def get_default_status_page(request: Request):
    """Fetches default 'monitor' status page (zero-auth if public)."""
    session_id = request.cookies.get(config.SESSION_COOKIE_NAME)
    session = get_valid_session(session_id)
    return _resolve_status_page("monitor", session)

@router.get("/api/status-page/{slug}")
async def get_status_page_by_slug(slug: str, request: Request):
    """Fetches specific status page by slug (zero-auth if public)."""
    session_id = request.cookies.get(config.SESSION_COOKIE_NAME)
    session = get_valid_session(session_id)
    return _resolve_status_page(slug, session)

@router.post("/api/status-page")
async def save_status_page(request: Request, session: dict = Depends(require_role("admin"))):
    """Creates or updates a status page configuration."""
    body = await request.json()
    database.db_save_status_page(body)
    return {"success": True, "config": body}

@router.delete("/api/status-page/{slug}")
async def delete_status_page(slug: str, session: dict = Depends(require_role("admin"))):
    """Deletes a status page."""
    database.db_delete_status_page(slug)
    return {"success": True}

@router.post("/api/status-page/incident")
async def create_status_incident(request: Request, session: dict = Depends(require_role("operator"))):
    """Posts an incident banner to a status page."""
    body = await request.json()
    slug = body.get("slug", "monitor")
    new_inc = {
        "id": f"inc-{int(time.time() * 1000)}",
        "title": body.get("title", "Service Degradation"),
        "content": body.get("content", ""),
        "style": body.get("style", "warning"),
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    database.db_add_incident(slug, new_inc)
    return {"success": True, "incident": new_inc, "config": database.db_get_status_page(slug)}

@router.delete("/api/status-page/incident/{incident_id}")
async def delete_status_incident(incident_id: str, slug: str = "monitor", session: dict = Depends(require_role("operator"))):
    """Removes an incident banner."""
    database.db_delete_incident(incident_id)
    return {"success": True, "config": database.db_get_status_page(slug)}


# =========================================================================
# WEBSOCKET STREAM (/ws/uptime)
# =========================================================================

@router.websocket("/ws/uptime")
async def ws_uptime(websocket: WebSocket):
    """Streams real-time heartbeat ticks and monitor updates."""
    session_id = websocket.cookies.get(config.SESSION_COOKIE_NAME)
    session = get_valid_session(session_id)

    # Allow authenticated users (viewer or above)
    if not session:
        await websocket.close(code=4401, reason="Not authenticated")
        return

    await websocket.accept()
    monitor_engine.ws_clients.add(websocket)

    # Send initial state
    try:
        await websocket.send_json({
            "type": "INIT",
            "payload": {
                "monitors": monitor_engine.get_monitors()
            }
        })
    except Exception:
        pass

    try:
        while True:
            # Keepalive listener
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        monitor_engine.ws_clients.discard(websocket)
