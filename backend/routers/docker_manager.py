import time
import re
import subprocess
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
import config
import database
from routers.auth import require_role

router = APIRouter(prefix="/docker", tags=["docker"])

class DockerActionRequest(BaseModel):
    container_id: str
    action: str


def run_docker_command(args: list[str], timeout: int = 60):
    commands = [
        ["docker", *args],
        ["sudo", "docker", *args],
    ]
    last_error = ""

    for command in commands:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            continue
        except Exception as e:
            last_error = str(e)
            continue

        if result.returncode == 0:
            return result

        stderr_text = (result.stderr or "").strip()
        stdout_text = (result.stdout or "").strip()
        lowered = f"{stderr_text}\n{stdout_text}".lower()

        if command[0] == "docker" and (
            "permission denied" in lowered
            or "cannot connect to the docker daemon" in lowered
        ):
            last_error = stderr_text or stdout_text
            continue

        raise HTTPException(
            status_code=500,
            detail=(stderr_text or stdout_text or "Docker command failed")[:500],
        )

    raise HTTPException(
        status_code=500,
        detail=f"Docker not available or permission denied. Error: {last_error}",
    )


def list_docker_container_snapshots():
    result = run_docker_command(
        [
            "ps",
            "-a",
            "--format",
            "{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|{{.Status}}|{{.Ports}}",
        ],
        timeout=30,
    )
    output = (result.stdout or "").strip().split("\n")

    containers = []
    for line in output:
        if not line:
            continue

        parts = line.split("|", 5)
        if len(parts) < 6:
            continue

        container_id, name, image, state, status, ports = parts
        containers.append(
            {
                "id": container_id,
                "name": name,
                "image": image,
                "state": state,
                "status": status,
                "ports": ports,
            }
        )

    return containers


def parse_docker_exit_code(status_text: str):
    if not status_text:
        return None

    matched = re.search(r"exited\s*\(([-]?\d+)\)", status_text, re.IGNORECASE)
    if not matched:
        return None

    try:
        return int(matched.group(1))
    except ValueError:
        return None


def docker_container_has_error(snapshot: dict) -> bool:
    state = (snapshot.get("state") or "").strip().lower()
    status = (snapshot.get("status") or "").strip().lower()

    if state in {"dead", "restarting"}:
        return True

    if "unhealthy" in status or "error" in status:
        return True

    exit_code = parse_docker_exit_code(status)
    return exit_code is not None and exit_code != 0


def format_docker_ports_for_alert(snapshot: dict) -> str:
    ports = (snapshot.get("ports") or "").strip()
    return ports if ports else "no published ports"


def check_docker_container_alerts(force: bool = False):
    """Send Telegram alerts for Docker container start/stop/error transitions."""
    now = time.time()
    if not force and (now - config.docker_last_alert_scan_at) < config.DOCKER_ALERT_SCAN_INTERVAL_SECONDS:
        return
    config.docker_last_alert_scan_at = now

    try:
        snapshots = list_docker_container_snapshots()
    except Exception as e:
        print("Docker alert check error:", e)
        return

    current_by_id = {}

    for raw_snapshot in snapshots:
        container_id = (raw_snapshot.get("id") or "").strip()
        if not container_id:
            continue

        snapshot = {
            "id": container_id,
            "name": (raw_snapshot.get("name") or "").strip(),
            "image": (raw_snapshot.get("image") or "").strip(),
            "state": (raw_snapshot.get("state") or "").strip(),
            "status": (raw_snapshot.get("status") or "").strip(),
            "ports": (raw_snapshot.get("ports") or "").strip(),
        }
        current_by_id[container_id] = snapshot

        previous = config.docker_container_alert_state.get(container_id)
        if not previous:
            continue

        previous_state = (previous.get("state") or "").strip().lower()
        current_state = (snapshot.get("state") or "").strip().lower()

        started = previous_state != "running" and current_state == "running"
        stopped = previous_state == "running" and current_state != "running"
        previous_error = docker_container_has_error(previous)
        current_error = docker_container_has_error(snapshot)

        display_name = snapshot["name"] or container_id[:12]
        ports_text = format_docker_ports_for_alert(snapshot if snapshot.get("ports") else previous)

        if started:
            config.send_telegram(
                f"✅ Docker Started: {display_name} ({container_id[:12]}) is running. Ports: {ports_text}"
            )

        if stopped:
            if current_error:
                config.send_telegram(
                    (
                        f"🚨 Docker Error: {display_name} ({container_id[:12]}) stopped with an error. "
                        f"State: {snapshot['state'] or 'unknown'}, Status: {snapshot['status'] or 'unknown'}, "
                        f"Ports: {ports_text}"
                    )
                )
            else:
                config.send_telegram(
                    (
                        f"⚠️ Docker Stopped: {display_name} ({container_id[:12]}) stopped. "
                        f"State: {snapshot['state'] or 'unknown'}, Status: {snapshot['status'] or 'unknown'}, "
                        f"Ports: {ports_text}"
                    )
                )
        elif current_error and not previous_error:
            config.send_telegram(
                (
                    f"🚨 Docker Error: {display_name} ({container_id[:12]}) entered error state. "
                    f"State: {snapshot['state'] or 'unknown'}, Status: {snapshot['status'] or 'unknown'}, "
                    f"Ports: {ports_text}"
                )
            )

    previous_ids = set(config.docker_container_alert_state.keys())
    current_ids = set(current_by_id.keys())
    removed_ids = previous_ids - current_ids

    for removed_id in removed_ids:
        previous = config.docker_container_alert_state.get(removed_id, {})
        previous_state = (previous.get("state") or "").strip().lower()
        if previous_state != "running":
            continue

        display_name = (previous.get("name") or "").strip() or removed_id[:12]
        ports_text = format_docker_ports_for_alert(previous)
        config.send_telegram(
            (
                f"⚠️ Docker Stopped: {display_name} ({removed_id[:12]}) is no longer running "
                f"(container removed or not found). Ports: {ports_text}"
            )
        )

    config.docker_container_alert_state = current_by_id


@router.get("")
def get_docker_containers(user=Depends(require_role("viewer"))):
    try:
        return list_docker_container_snapshots()
    except Exception:
        return []


@router.post("/action")
def post_docker_action(data: DockerActionRequest, user=Depends(require_role("operator"))):
    container_id = (data.container_id or "").strip()
    action = (data.action or "").strip().lower()

    if action not in {"start", "stop", "restart"}:
        raise HTTPException(status_code=400, detail="action must be start, stop, or restart")

    if not config.DOCKER_CONTAINER_ID_PATTERN.match(container_id):
        raise HTTPException(status_code=400, detail="Invalid container identifier")

    result = run_docker_command([action, container_id], timeout=60)
    details = (result.stdout or result.stderr or "").strip()
    database.log_audit(user["username"], "docker_action", f"{action} container '{container_id}'")
    return {"status": "ok", "action": action, "container_id": container_id, "details": details}


@router.get("/logs/{container_id}")
def get_docker_logs(container_id: str, lines: int = Query(100, ge=1, le=2000), user=Depends(require_role("viewer"))):
    target = (container_id or "").strip()
    if not config.DOCKER_CONTAINER_ID_PATTERN.match(target):
        raise HTTPException(status_code=400, detail="Invalid container identifier")

    result = run_docker_command(["logs", "--tail", str(lines), target], timeout=60)
    combined = ""
    if result.stdout:
        combined += result.stdout
    if result.stderr:
        combined += result.stderr

    return {"logs": combined.splitlines(keepends=True)}
