import os
import sys
import time
import pytest
from fastapi.testclient import TestClient

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

import config
import database
from main import app
from uptime.engine import monitor_engine

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_test_db():
    database.init_user_db()
    # Create admin user for tests if not exists
    admin = database.get_user_record("test_admin")
    if not admin:
        database.create_user_record("test_admin", "adminpass123", "admin", overwrite=False)

def get_admin_cookies():
    # Login and get session cookie
    res = client.post("/auth/login", json={"username": "test_admin", "password": "adminpass123"})
    assert res.status_code == 200
    cookies = res.cookies
    return cookies

def test_database_monitor_dao():
    # 1. Create Monitor
    m_data = {
        "id": f"test-{int(time.time()*1000)}",
        "name": "Test Web Endpoint",
        "tag": "API",
        "type": "http",
        "url": "https://httpbin.org/status/200",
        "interval": 15,
        "active": True,
        "threshold": 90.0,
        "telegramEnabled": True
    }
    database.db_save_monitor(m_data)

    # 2. Retrieve Monitor
    retrieved = database.db_get_monitor(m_data["id"])
    assert retrieved is not None
    assert retrieved["name"] == "Test Web Endpoint"
    assert retrieved["type"] == "http"
    assert retrieved["telegramEnabled"] is True

    # 3. Add Heartbeats
    hb = {"status": "up", "ping": 42.5, "msg": "200 OK", "time": int(time.time()*1000)}
    database.db_add_heartbeat(m_data["id"], hb)
    retrieved = database.db_get_monitor(m_data["id"])
    assert len(retrieved["heartbeats"]) >= 1
    assert retrieved["heartbeats"][0]["status"] == "up"

    # 4. Clear Heartbeats
    database.db_clear_heartbeats(m_data["id"])
    retrieved = database.db_get_monitor(m_data["id"])
    assert len(retrieved["heartbeats"]) == 0

    # 5. Delete Monitor
    database.db_delete_monitor(m_data["id"])
    assert database.db_get_monitor(m_data["id"]) is None

def test_status_page_dao():
    test_slug = f"test-page-{int(time.time())}"
    config_data = {
        "slug": test_slug,
        "title": "Client Status",
        "description": "Public facing operational status",
        "footerText": "Test Footer",
        "refreshInterval": 120,
        "theme": "auto",
        "showTags": True,
        "groups": [{"id": "g1", "name": "Core APIs", "monitorIds": ["m1", "m2"]}],
        "isPublic": True
    }
    database.db_save_status_page(config_data)

    page = database.db_get_status_page(test_slug)
    assert page is not None
    assert page["title"] == "Client Status"
    assert page["isPublic"] is True
    assert len(page["groups"]) == 1

    # Add Incident
    incident = {
        "id": f"inc-{int(time.time()*1000)}",
        "title": "Scheduled Maintenance",
        "content": "Upgrading core database instances.",
        "style": "info",
        "createdAt": "2026-10-22T10:00:00Z"
    }
    database.db_add_incident(test_slug, incident)

    page = database.db_get_status_page(test_slug)
    assert len(page["incidents"]) == 1
    assert page["incidents"][0]["title"] == "Scheduled Maintenance"

    # Delete Incident
    database.db_delete_incident(incident["id"])
    page = database.db_get_status_page(test_slug)
    assert len(page["incidents"]) == 0

    # Delete Status Page
    database.db_delete_status_page(test_slug)
    assert database.db_get_status_page(test_slug) is None

def test_telegram_settings_dao():
    initial = database.db_get_telegram_settings()
    assert isinstance(initial, dict)

    new_settings = {
        "enabled": True,
        "botToken": "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
        "chatId": "987654321"
    }
    database.db_save_telegram_settings(new_settings)
    saved = database.db_get_telegram_settings()
    assert saved["enabled"] is True
    assert saved["botToken"] == new_settings["botToken"]
    assert saved["chatId"] == new_settings["chatId"]

def test_api_monitors_crud():
    cookies = get_admin_cookies()

    # 1. Create monitor via API
    create_payload = {
        "name": "Integration Test API",
        "type": "http",
        "url": "https://httpbin.org/status/200",
        "interval": 30,
        "threshold": 90,
        "telegramEnabled": True
    }
    res = client.post("/api/monitors", json=create_payload, cookies=cookies)
    assert res.status_code == 201
    created = res.json()
    monitor_id = created["id"]
    assert created["name"] == "Integration Test API"

    # 2. Get monitors list
    res = client.get("/api/monitors", cookies=cookies)
    assert res.status_code == 200
    all_monitors = res.json()
    assert any(str(m["id"]) == str(monitor_id) for m in all_monitors)

    # 3. Toggle telegram
    res = client.post(f"/api/monitors/{monitor_id}/toggle-telegram", cookies=cookies)
    assert res.status_code == 200
    updated = res.json()
    assert updated["telegramEnabled"] is False

    # 4. Toggle pause
    res = client.post(f"/api/monitors/{monitor_id}/pause", cookies=cookies)
    assert res.status_code == 200
    paused = res.json()
    assert paused["active"] is False
    assert paused["status"] == "paused"

    # 5. Clear history
    res = client.post(f"/api/monitors/{monitor_id}/clear", cookies=cookies)
    assert res.status_code == 200

    # 6. Delete monitor
    res = client.delete(f"/api/monitors/{monitor_id}", cookies=cookies)
    assert res.status_code == 200

def test_api_system_drives():
    cookies = get_admin_cookies()
    res = client.get("/api/system/drives", cookies=cookies)
    assert res.status_code == 200
    drives = res.json()
    assert isinstance(drives, list)
    if drives:
        assert "mount" in drives[0]
        assert "usePercent" in drives[0]

def test_public_status_page():
    # Public status page can be viewed without cookies
    res = client.get("/status")
    assert res.status_code == 200
    assert "System Status" in res.text or "<!DOCTYPE html>" in res.text

    # Default API endpoint works without cookies when public
    res = client.get("/api/status-page/monitor")
    assert res.status_code == 200
    data = res.json()
    assert data["slug"] == "monitor"
    assert data["isPublic"] is True
