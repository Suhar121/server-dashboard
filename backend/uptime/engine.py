import asyncio
import time
import random
import psutil
import httpx
import database
from uptime.telegram import trigger_alert

class MonitorEngine:
    def __init__(self):
        self.monitors = []
        self.ws_clients = set()
        self.tasks = {}
        self._running = False

    def set_ws_clients(self, clients):
        self.ws_clients = clients

    def _dispatch_broadcast(self, event_type: str, payload: dict):
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.broadcast(event_type, payload))
        except RuntimeError:
            pass

    async def broadcast(self, event_type: str, payload: dict):
        """Sends a JSON message to all active WebSocket clients."""
        dead_clients = set()
        msg = {"type": event_type, "payload": payload}
        for ws in list(self.ws_clients):
            try:
                await ws.send_json(msg)
            except Exception:
                dead_clients.add(ws)
        self.ws_clients.difference_update(dead_clients)

    async def start(self):
        """Loads all monitors and schedules background checks."""
        self._running = True
        self.monitors = database.db_get_monitors()
        print(f"[Uptime Engine] Starting monitoring engine for {len(self.monitors)} monitors...")
        for monitor in self.monitors:
            if monitor.get("active", True):
                self.schedule_monitor(monitor)

    async def stop(self):
        """Cancels all active monitoring tasks."""
        self._running = False
        for mid, task in list(self.tasks.items()):
            task.cancel()
        self.tasks.clear()
        print("[Uptime Engine] Monitoring engine stopped.")

    def schedule_monitor(self, monitor: dict):
        """Starts an async loop for checking the given monitor."""
        mid = str(monitor["id"])
        if mid in self.tasks:
            self.tasks[mid].cancel()

        interval_sec = max(int(monitor.get("interval", 30)), 5)

        async def _loop():
            # Initial random stagger between 1.0 and 3.5 seconds
            await asyncio.sleep(random.uniform(1.0, 3.5))
            while self._running:
                try:
                    await self.run_check(mid)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    print(f"[Uptime Engine] Error in check for monitor {mid}: {e}")
                await asyncio.sleep(interval_sec)

        self.tasks[mid] = asyncio.create_task(_loop())

    async def run_check(self, monitor_id: str):
        monitor = next((m for m in self.monitors if str(m["id"]) == str(monitor_id)), None)
        if not monitor or not monitor.get("active", True):
            return

        start_time = time.time()
        status = "down"
        ping = 0.0
        msg = ""
        last_error = None
        m_type = monitor.get("type", "http").lower()

        try:
            if m_type == "http":
                url = monitor.get("url", "")
                if not url.startswith("http://") and not url.startswith("https://"):
                    url = "https://" + url

                async with httpx.AsyncClient(timeout=6.0, follow_redirects=True, headers={"User-Agent": "ServerDashboard-Uptime/1.0"}) as client:
                    res = await client.get(url)
                    ping = round((time.time() - start_time) * 1000, 2)
                    if 200 <= res.status_code < 400:
                        status = "up"
                        msg = f"{res.status_code} {res.reason_phrase}"
                    else:
                        status = "down"
                        msg = f"HTTP Error {res.status_code}"
                        last_error = f"[{monitor.get('name')}] [DOWN] HTTP status {res.status_code} at {url}"

            elif m_type == "port":
                url_str = monitor.get("url") or monitor.get("target") or "localhost:80"
                parts = url_str.split(":")
                host = parts[0].strip() or "127.0.0.1"
                port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 80

                _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=4.0)
                ping = round((time.time() - start_time) * 1000, 2)
                status = "up"
                msg = f"Port {port} open"
                writer.close()
                await writer.wait_closed()

            elif m_type == "disk":
                target_mount = (monitor.get("target") or "C:").upper()
                drives = []
                for p in psutil.disk_partitions(all=False):
                    try:
                        u = psutil.disk_usage(p.mountpoint)
                        drives.append({"mount": p.mountpoint, "usePercent": round(u.percent, 1)})
                    except Exception:
                        pass

                matched = next((d for d in drives if d["mount"].upper().startswith(target_mount)), None)
                if not matched and drives:
                    matched = drives[0]

                if matched:
                    ping = float(matched["usePercent"])
                    threshold = float(monitor.get("threshold", 90))
                    if matched["usePercent"] >= threshold:
                        status = "down"
                        msg = f"High Disk Usage: {matched['usePercent']}% >= {threshold}%"
                        last_error = f"[{monitor.get('name')}] [DOWN] Disk {matched['mount']} at {matched['usePercent']}% (Threshold {threshold}%)"
                    else:
                        status = "up"
                        msg = f"Disk {matched['mount']}: {matched['usePercent']}% used"
                else:
                    status = "down"
                    msg = "No matching drive partition found"
                    last_error = f"[{monitor.get('name')}] [DOWN] Partition {target_mount} not found"

            elif m_type == "memory":
                mem = psutil.virtual_memory()
                ping = float(round(mem.percent, 1))
                threshold = float(monitor.get("threshold", 90))
                if mem.percent >= threshold:
                    status = "down"
                    msg = f"High Memory Usage: {mem.percent}% >= {threshold}%"
                    last_error = f"[{monitor.get('name')}] [DOWN] RAM at {mem.percent}% (Threshold {threshold}%)"
                else:
                    status = "up"
                    msg = f"RAM: {mem.percent}% used"

            elif m_type == "cpu":
                cpu_val = float(round(psutil.cpu_percent(interval=None), 1))
                ping = cpu_val
                threshold = float(monitor.get("threshold", 90))
                if cpu_val >= threshold:
                    status = "down"
                    msg = f"High CPU Usage: {cpu_val}% >= {threshold}%"
                    last_error = f"[{monitor.get('name')}] [DOWN] CPU at {cpu_val}% (Threshold {threshold}%)"
                else:
                    status = "up"
                    msg = f"CPU: {cpu_val}% load"

        except Exception as err:
            status = "down"
            ping = 0.0
            msg = str(err) or "Check failed"
            last_error = f"[{monitor.get('name')}] [DOWN] {str(err) or 'Connection refused'}"

        # Construct Heartbeat
        heartbeat = {
            "time": int(time.time() * 1000),
            "status": status,
            "ping": ping,
            "msg": msg
        }

        if "heartbeats" not in monitor or monitor["heartbeats"] is None:
            monitor["heartbeats"] = []
        monitor["heartbeats"].append(heartbeat)
        if len(monitor["heartbeats"]) > 50:
            monitor["heartbeats"].pop(0)

        # Status transition check & Telegram Alert
        previous_status = monitor.get("status")
        if previous_status and previous_status != "pending" and previous_status != status:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(trigger_alert(monitor, status, previous_status, last_error or msg))
            except RuntimeError:
                pass

        # Update stats
        monitor["status"] = status
        monitor["lastPing"] = ping
        if last_error:
            monitor["lastError"] = last_error

        total_checks = len(monitor["heartbeats"])
        up_checks = sum(1 for h in monitor["heartbeats"] if h.get("status") == "up")
        monitor["uptime24h"] = round((up_checks / total_checks) * 100, 2) if total_checks > 0 else 100.0
        monitor["uptime30d"] = monitor["uptime24h"]
        monitor["uptime1y"] = monitor["uptime24h"]

        valid_pings = [h["ping"] for h in monitor["heartbeats"] if h.get("status") == "up" and h.get("ping", 0) > 0]
        if valid_pings:
            monitor["avgPing"] = round(sum(valid_pings) / len(valid_pings), 2)

        # Persist to database
        database.db_add_heartbeat(monitor["id"], heartbeat)
        database.db_save_monitor(monitor)

        # Broadcast live update to WebSockets
        await self.broadcast("HEARTBEAT", {
            "monitorId": monitor["id"],
            "heartbeat": heartbeat,
            "monitor": monitor
        })

    def get_monitors(self):
        return self.monitors

    def add_monitor(self, data: dict) -> dict:
        new_id = str(int(time.time() * 1000))
        new_monitor = {
            "id": new_id,
            "name": data.get("name") or "New Monitor",
            "tag": data.get("tag") or data.get("name") or "New Monitor",
            "type": data.get("type", "http"),
            "url": data.get("url", ""),
            "target": data.get("target", "C:"),
            "threshold": float(data.get("threshold", 90)),
            "interval": int(data.get("interval", 30)),
            "telegramEnabled": data.get("telegramEnabled", True),
            "telegramBotToken": data.get("telegramBotToken", ""),
            "telegramChatId": data.get("telegramChatId", ""),
            "active": True,
            "heartbeats": [],
            "status": "pending",
            "lastPing": 0.0,
            "avgPing": 0.0,
            "uptime24h": 100.0,
            "uptime30d": 100.0,
            "uptime1y": 100.0,
            "lastError": None,
            "createdAt": int(time.time() * 1000)
        }
        self.monitors.append(new_monitor)
        database.db_save_monitor(new_monitor)
        if self._running:
            self.schedule_monitor(new_monitor)
        self._dispatch_broadcast("MONITOR_ADDED", new_monitor)
        return new_monitor

    def update_monitor(self, monitor_id: str, data: dict):
        monitor = next((m for m in self.monitors if str(m["id"]) == str(monitor_id)), None)
        if not monitor:
            return None

        if "name" in data:
            monitor["name"] = data["name"]
        if "tag" in data:
            monitor["tag"] = data["tag"]
        if "type" in data:
            monitor["type"] = data["type"]
        if "url" in data:
            monitor["url"] = data["url"]
        if "target" in data:
            monitor["target"] = data["target"]
        if "threshold" in data:
            monitor["threshold"] = float(data["threshold"])
        if "telegramEnabled" in data:
            monitor["telegramEnabled"] = bool(data["telegramEnabled"])
        if "telegramBotToken" in data:
            monitor["telegramBotToken"] = data["telegramBotToken"]
        if "telegramChatId" in data:
            monitor["telegramChatId"] = data["telegramChatId"]

        reschedule = False
        if "interval" in data and int(data["interval"]) != monitor.get("interval"):
            monitor["interval"] = int(data["interval"])
            reschedule = True

        database.db_save_monitor(monitor)
        if reschedule and monitor.get("active", True) and self._running:
            self.schedule_monitor(monitor)

        self._dispatch_broadcast("MONITOR_UPDATED", monitor)
        return monitor

    def toggle_telegram(self, monitor_id: str):
        monitor = next((m for m in self.monitors if str(m["id"]) == str(monitor_id)), None)
        if not monitor:
            return None
        monitor["telegramEnabled"] = not monitor.get("telegramEnabled", True)
        database.db_save_monitor(monitor)
        self._dispatch_broadcast("MONITOR_UPDATED", monitor)
        return monitor

    def toggle_pause(self, monitor_id: str):
        monitor = next((m for m in self.monitors if str(m["id"]) == str(monitor_id)), None)
        if not monitor:
            return None

        mid = str(monitor_id)
        monitor["active"] = not monitor.get("active", True)
        if monitor["active"]:
            if self._running:
                self.schedule_monitor(monitor)
        else:
            if mid in self.tasks:
                self.tasks[mid].cancel()
                del self.tasks[mid]
            monitor["status"] = "paused"

        database.db_save_monitor(monitor)
        self._dispatch_broadcast("MONITOR_UPDATED", monitor)
        return monitor

    def delete_monitor(self, monitor_id: str):
        mid = str(monitor_id)
        if mid in self.tasks:
            self.tasks[mid].cancel()
            del self.tasks[mid]
        self.monitors = [m for m in self.monitors if str(m["id"]) != mid]
        database.db_delete_monitor(mid)
        self._dispatch_broadcast("MONITOR_DELETED", {"id": mid})

    def clear_data(self, monitor_id: str):
        monitor = next((m for m in self.monitors if str(m["id"]) == str(monitor_id)), None)
        if monitor:
            monitor["heartbeats"] = []
            monitor["lastError"] = None
            monitor["uptime24h"] = 100.0
            monitor["avgPing"] = 0.0
            database.db_clear_heartbeats(str(monitor_id))
            self._dispatch_broadcast("MONITOR_UPDATED", monitor)


# Global Singleton instance
monitor_engine = MonitorEngine()

async def start_uptime_engine():
    await monitor_engine.start()

async def stop_uptime_engine():
    await monitor_engine.stop()
