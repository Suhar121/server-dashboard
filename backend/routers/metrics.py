import os
import time
import socket
import subprocess
import psutil
import sqlite3
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
import config
import database
from routers.auth import require_role

router = APIRouter(tags=["metrics"])

# Shared metrics cache
system_metrics_cache = {
    "cpu": 0.0,
    "memory": 0.0,
    "vmem": {
        "total": 0,
        "available": 0,
        "used": 0,
        "free": 0,
        "percent": 0.0
    },
    "battery": None
}

def start_metrics_poller():
    import threading
    
    def poll_metrics():
        # First call to initialize psutil CPU calculation
        try:
            psutil.cpu_percent()
        except Exception:
            pass
            
        while True:
            try:
                cpu = psutil.cpu_percent(interval=1.0)
                mem = psutil.virtual_memory()
                battery = psutil.sensors_battery()
                
                system_metrics_cache["cpu"] = cpu
                system_metrics_cache["memory"] = mem.percent
                system_metrics_cache["vmem"] = {
                    "total": mem.total,
                    "available": mem.available,
                    "used": mem.used,
                    "free": mem.free,
                    "percent": mem.percent
                }
                if battery:
                    system_metrics_cache["battery"] = {
                        "percent": battery.percent,
                        "charging": battery.is_charging
                    }
                else:
                    system_metrics_cache["battery"] = None
            except Exception as e:
                print("[MetricsPoller] Error:", e)
            time.sleep(1.0)

    t = threading.Thread(target=poll_metrics, daemon=True, name="MetricsPoller")
    t.start()
    print("[MetricsPoller] Background metrics daemon thread started.")


class SavePinnedPortRequest(BaseModel):
    port: int

class UpdatePinnedPortServiceRequest(BaseModel):
    service_name: str | None = None
    command: str | None = None
    setup_command: str | None = None
    workdir: str | None = None


def is_local_port_active(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        return sock.connect_ex(("127.0.0.1", int(port))) == 0
    finally:
        sock.close()


def check_alert_rules(cpu_percent: float, ram_percent: float):
    """Check if any alert rules are triggered and send notifications"""
    try:
        rules = database.list_alert_rules()
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
                last_sent = config.alert_last_sent.get(rule_id, 0)

                if current_time - last_sent >= ALERT_COOLDOWN:
                    metric_name = "CPU" if metric_type == "cpu" else "RAM"
                    msg = f"🚨 Alert: {metric_name} usage is {current_value:.1f}% (threshold: {threshold}%)"
                    config.send_telegram(msg)
                    config.alert_last_sent[rule_id] = current_time
                    database.log_audit("system", "alert_triggered", msg)
    except Exception as e:
        print("Alert check error:", e)


def check_pinned_port_alerts():
    """Send Telegram alerts when a pinned port goes down (once per downtime event)."""
    try:
        pinned_ports = database.list_pinned_ports()
        active_port_set = set()

        for pin in pinned_ports:
            port = int(pin["port"])
            if port < 1 or port > 65535:
                continue

            active_port_set.add(port)
            is_up = is_local_port_active(port)
            was_alerted_down = bool(config.pinned_port_down_alert_state.get(port, False))

            if not is_up and not was_alerted_down:
                config.send_telegram(f"🚨 Port Down: Pinned port {port} is not reachable on 127.0.0.1")
                config.pinned_port_down_alert_state[port] = True
                if os.getenv("AI_AUTO_REMEDIATION", "").lower() in ("1", "true", "yes"):
                    try:
                        from ai.remediation import on_port_down
                        on_port_down(port=port)
                    except Exception:
                        pass
            elif is_up and was_alerted_down:
                config.send_telegram(f"✅ Port Up: Pinned port {port} is back online on 127.0.0.1")
                config.pinned_port_down_alert_state[port] = False

        # Cleanup state for ports that are no longer pinned.
        stale_ports = [port for port in config.pinned_port_down_alert_state.keys() if port not in active_port_set]
        for stale_port in stale_ports:
            config.pinned_port_down_alert_state.pop(stale_port, None)

    except Exception as e:
        print("Pinned port alert check error:", e)


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


@router.get("/battery")
def get_battery(user=Depends(require_role("viewer"))):
    batt = psutil.sensors_battery()

    if batt:
        percent = batt.percent
        plugged = batt.power_plugged

        if percent < config.BATTERY_THRESHOLD and not plugged:
            if not config.battery_alert_sent:
                config.send_telegram(f"🚨 Battery Low: {percent}%")
                config.battery_alert_sent = True
        else:
            config.battery_alert_sent = False

        return {"percent": percent, "plugged": plugged}

    return {"percent": None, "plugged": False}


@router.get("/server-info")
def get_server_info():
    return {
        "server_name": config.SERVER_NAME or socket.gethostname(),
        "hostname": socket.gethostname(),
    }


@router.get("/system")
def get_system(user=Depends(require_role("viewer"))):
    cpu = system_metrics_cache["cpu"]
    memory = system_metrics_cache["memory"]

    check_alert_rules(cpu, memory)
    check_pinned_port_alerts()
    try:
        from routers.docker_manager import check_docker_container_alerts
        check_docker_container_alerts()
    except ImportError:
        pass

    if os.getenv("AI_AUTO_REMEDIATION", "").lower() in ("1", "true", "yes"):
        try:
            from ai.remediation import on_cpu_alert
            if cpu > 80:
                on_cpu_alert(threshold=80, current_cpu=cpu, session_id=user.get("session_id"))
        except Exception:
            pass

    return {
        "cpu": cpu,
        "memory": memory,
        "vmem": system_metrics_cache["vmem"]
    }


@router.get("/ports")
def get_ports(user=Depends(require_role("viewer"))):
    import sys
    parsed = []
    try:
        if sys.platform == "win32":
            import psutil
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == 'LISTEN' or conn.type == 2: # 2 is SOCK_DGRAM (UDP)
                    proto = "tcp" if conn.type == 1 else "udp"
                    state = conn.status if conn.status else "LISTEN"
                    ip, port = conn.laddr
                    if ":" in ip:
                        local = f"[{ip}]:{port}"
                    else:
                        local = f"{ip}:{port}"
                    parsed.append({
                        "protocol": proto,
                        "state": state,
                        "local": local
                    })
        else:
            output = subprocess.check_output("ss -tuln", shell=True).decode()
            lines = output.split("\n")[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    parsed.append({
                        "protocol": parts[0].lower(),
                        "state": parts[1],
                        "local": parts[4]
                    })
    except Exception:
        pass
    return parsed


@router.get("/check-port/{port}")
def get_check_port(port: int, user=Depends(require_role("viewer"))):
    return {"port": port, "active": is_local_port_active(port)}


@router.post("/ports/{port}/terminate")
def terminate_port_processes(port: int, user=Depends(require_role("operator"))):
    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="Port must be between 1 and 65535")

    outcome = terminate_processes_for_port(port)
    remaining_pids = list_process_ids_by_port(port)

    database.log_audit(
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


@router.get("/state/pinned-ports")
def get_pinned_ports(user=Depends(require_role("viewer"))):
    return {"ports": database.list_pinned_ports()}


@router.post("/state/pinned-ports")
def add_pinned_port(data: SavePinnedPortRequest, user=Depends(require_role("operator"))):
    port = data.port
    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="Invalid port number")

    try:
        created = database.create_pinned_port(port)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Port already pinned")

    database.log_audit(user["username"], "pin_port", f"Pinned port {port}")
    return {"status": "created", "pinned_port": created}


@router.delete("/state/pinned-ports/{pin_id}")
def remove_pinned_port(pin_id: int, user=Depends(require_role("admin"))):
    port_rec = database.get_pinned_port(pin_id)
    if not port_rec:
         raise HTTPException(status_code=404, detail="Pinned port not found")
    
    if database.delete_pinned_port(pin_id):
        database.log_audit(user["username"], "unpin_port", f"Unpinned port {port_rec['port']}")
        return {"status": "deleted", "id": pin_id}
    
    raise HTTPException(status_code=404, detail="Pinned port not found")


@router.patch("/state/pinned-ports/{pin_id}/service")
def patch_pinned_port_service(pin_id: int, data: UpdatePinnedPortServiceRequest, user=Depends(require_role("operator"))):
    port_rec = database.get_pinned_port(pin_id)
    if not port_rec:
        raise HTTPException(status_code=404, detail="Pinned port not found")

    service_name = data.service_name.strip() if data.service_name else None
    command = data.command.strip() if data.command else None
    setup_command = data.setup_command.strip() if data.setup_command else None
    workdir = data.workdir.strip() if data.workdir else None

    if database.update_pinned_port_service(pin_id, service_name, command, setup_command, workdir):
        database.log_audit(user["username"], "update_pinned_port_service", f"Updated service settings for pinned port {port_rec['port']}")
        return {"status": "updated"}

    raise HTTPException(status_code=500, detail="Failed to update service config")
