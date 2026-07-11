import os
import re
import time
import shutil
import json
import subprocess
import asyncio
import sqlite3
from fastapi import APIRouter, HTTPException, Depends, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import config
import database
from routers.auth import require_role, get_valid_session

router = APIRouter(tags=["services"])

class PM2ActionRequest(BaseModel):
    action: str  # start, stop, restart, delete, reload, restart_all, stop_all, save, reload_pm2, kill, startup
    app_name: str | None = None  # target app name or id (if applicable)

class PM2StartRequest(BaseModel):
    name: str
    script: str
    cwd: str | None = None
    interpreter: str | None = None
    args: str | None = None
    env_vars: dict | None = None
    autorestart: bool = True
    watch: bool = False
    instances: int | None = None
    max_memory_restart: str | None = None
    startup_delay: int | None = None
    cron_restart: str | None = None

class SaveServiceRequest(BaseModel):
    name: str
    port: int
    command: str


def get_pm2_cmd() -> str:
    # Try finding globally on system path
    pm2_path = shutil.which("pm2")
    if pm2_path:
        return pm2_path
    
    # Try common Windows global npm path
    appdata = os.environ.get("APPDATA")
    if appdata:
        win_path = os.path.join(appdata, "npm", "pm2.cmd")
        if os.path.exists(win_path):
            return win_path
            
    # Try Unix npm global path or fallback
    return "pm2"


def parse_pm2_jlist(output: str) -> list:
    lines = []
    for line in output.splitlines():
        if line.strip().startswith("[PM2]"):
            continue
        lines.append(line)
    clean_output = "\n".join(lines).strip()
    start_idx = clean_output.find("[")
    if start_idx != -1:
        clean_output = clean_output[start_idx:]
    if not clean_output:
        return []
    return json.loads(clean_output)


def validate_app_name(name: str):
    if not name or not re.match(r"^[a-zA-Z0-9\-_.]+$", name):
        raise HTTPException(status_code=400, detail="Invalid application name. Only alphanumeric characters, dashes, underscores, and dots are allowed.")


def validate_path(path: str):
    if not path:
        return
    if not re.match(r"^[a-zA-Z0-9\-_./\\: ~@]+$", path):
        raise HTTPException(status_code=400, detail="Invalid path characters.")


def expand_home_dir(path_str: str) -> str:
    if not path_str:
        return path_str
    if path_str == "~":
        return os.path.expanduser("~")
    if path_str.startswith("~/") or path_str.startswith("~\\"):
        return os.path.join(os.path.expanduser("~"), path_str[2:])
    return path_str


@router.get("/api/pm2/list")
async def pm2_list(user: dict = Depends(require_role("admin"))):
    pm2_cmd = get_pm2_cmd()
    try:
        result = subprocess.run(
            [pm2_cmd, "jlist"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=15
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=result.stderr or "PM2 jlist execution failed")
        
        apps = parse_pm2_jlist(result.stdout)
        
        formatted = []
        for app in apps:
            pm2_env = app.get("pm2_env", {})
            monit = app.get("monit", {})
            
            cpu = monit.get("cpu", 0)
            memory = monit.get("memory", 0)
            
            uptime = 0
            pm_uptime = pm2_env.get("pm_uptime", 0)
            if pm_uptime:
                uptime = int(time.time() * 1000) - pm_uptime
                if uptime < 0:
                    uptime = 0
            
            formatted.append({
                "id": app.get("pm_id"),
                "name": app.get("name"),
                "pid": app.get("pid"),
                "status": pm2_env.get("status"),
                "cpu": cpu,
                "memory": memory,
                "uptime": uptime,
                "restarts": pm2_env.get("restart_time", 0),
                "version": pm2_env.get("version", "N/A"),
                "cwd": pm2_env.get("pm_cwd") or pm2_env.get("cwd") or "N/A",
                "script": pm2_env.get("pm_exec_path", "N/A"),
                "instances": pm2_env.get("instances", 1),
                "node_version": pm2_env.get("node_version", "N/A"),
                "out_log": pm2_env.get("pm_out_log_path"),
                "err_log": pm2_env.get("pm_err_log_path"),
            })
        return formatted
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="PM2 command timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to query PM2: {str(e)}")


@router.post("/api/pm2/action")
async def pm2_action(data: PM2ActionRequest, user: dict = Depends(require_role("admin"))):
    pm2_cmd = get_pm2_cmd()
    action = data.action
    app_name = data.app_name
    
    if app_name:
        if not app_name.isdigit():
            validate_app_name(app_name)
            
    cmd_args = [pm2_cmd]
    
    if action == "start":
        if not app_name:
            raise HTTPException(status_code=400, detail="App name is required for start action")
        cmd_args.extend(["start", app_name])
        audit_desc = f"Started PM2 app: {app_name}"
    elif action == "stop":
        if not app_name:
            raise HTTPException(status_code=400, detail="App name is required for stop action")
        cmd_args.extend(["stop", app_name])
        audit_desc = f"Stopped PM2 app: {app_name}"
    elif action == "restart":
        if not app_name:
            raise HTTPException(status_code=400, detail="App name is required for restart action")
        cmd_args.extend(["restart", app_name])
        audit_desc = f"Restarted PM2 app: {app_name}"
    elif action == "delete":
        if not app_name:
            raise HTTPException(status_code=400, detail="App name is required for delete action")
        cmd_args.extend(["delete", app_name])
        audit_desc = f"Deleted PM2 app: {app_name}"
    elif action == "reload":
        if not app_name:
            raise HTTPException(status_code=400, detail="App name is required for reload action")
        cmd_args.extend(["reload", app_name])
        audit_desc = f"Reloaded PM2 app: {app_name}"
    elif action == "restart_all":
        cmd_args.append("restart all")
        audit_desc = "Restarted all PM2 apps"
    elif action == "stop_all":
        cmd_args.append("stop all")
        audit_desc = "Stopped all PM2 apps"
    elif action == "save":
        cmd_args.append("save")
        audit_desc = "Saved PM2 process list"
    elif action == "reload_pm2":
        cmd_args.append("update")
        audit_desc = "Reloaded PM2 daemon"
    elif action == "kill":
        cmd_args.append("kill")
        audit_desc = "Killed PM2 daemon"
    elif action == "startup":
        cmd_args.append("startup")
        audit_desc = "Generated PM2 startup script"
    else:
        raise HTTPException(status_code=400, detail="Invalid action")
        
    try:
        # Run the command
        # On Windows, pm2 command needs shell=True or direct exec
        result = subprocess.run(
            " ".join(cmd_args),
            shell=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=30
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=result.stderr or result.stdout or f"Failed to execute action {action}")
            
        database.log_audit(user["username"], "pm2_action", audit_desc)
        return {"status": "success", "message": result.stdout}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="PM2 command timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/pm2/start-app")
async def pm2_start_app(data: PM2StartRequest, user: dict = Depends(require_role("admin"))):
    pm2_cmd = get_pm2_cmd()
    
    validate_app_name(data.name)
    
    import shlex
    script_str = data.script.strip()
    try:
        parts = shlex.split(script_str)
    except Exception:
        parts = script_str.split()
        
    if len(parts) > 1:
        actual_script = parts[0]
        extra_args = parts[1:]
        if data.args:
            try:
                extra_args.extend(shlex.split(data.args))
            except Exception:
                extra_args.extend(data.args.split())
        actual_args = " ".join(extra_args)
    else:
        actual_script = script_str
        actual_args = data.args
        
    actual_script = expand_home_dir(actual_script)
    validate_path(actual_script)
    if data.cwd:
        validate_path(data.cwd)
        
    cmd_args = [pm2_cmd, "start", actual_script, "--name", data.name]
    
    if data.interpreter and data.interpreter.lower() != "auto":
        valid_interpreters = {"node", "node.js", "python", "python3", "bun", "bash", "php"}
        interpreter_val = data.interpreter.lower()
        if interpreter_val in valid_interpreters or re.match(r"^[a-zA-Z0-9\-./\\_]+$", data.interpreter):
            cmd_args.extend(["--interpreter", data.interpreter])
            
    if data.cwd:
        cmd_args.extend(["--cwd", data.cwd])
        
    if not data.autorestart:
        cmd_args.append("--no-autorestart")
        
    if data.watch:
        cmd_args.append("--watch")
        
    if data.instances is not None:
        cmd_args.extend(["-i", str(data.instances)])
        
    if data.max_memory_restart:
        if re.match(r"^\d+[KMGkmg]$", data.max_memory_restart):
            cmd_args.extend(["--max-memory-restart", data.max_memory_restart])
            
    if data.startup_delay:
        cmd_args.extend(["--restart-delay", str(data.startup_delay * 1000)])
        
    if data.cron_restart:
        if re.match(r"^[0-9\s*/,\-]+$", data.cron_restart):
            cmd_args.extend(["--cron-restart", data.cron_restart])
            
    if actual_args:
        try:
            split_args = shlex.split(actual_args)
        except Exception:
            split_args = actual_args.split()
        split_args = [expand_home_dir(arg) for arg in split_args]
        cmd_args.extend(["--", *split_args])
        
    env = os.environ.copy()
    if data.env_vars:
        for k, v in data.env_vars.items():
            if re.match(r"^[a-zA-Z0-9_]+$", k):
                env[k] = str(v)
                
    try:
        result = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            env=env,
            timeout=30
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=result.stderr or result.stdout or "Failed to start application")
            
        database.log_audit(user["username"], "pm2_start_app", f"Started PM2 application: {data.name}")
        return {"status": "success", "message": result.stdout}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="PM2 command timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/pm2/logs/{app_name}")
async def pm2_get_logs(
    app_name: str,
    limit: int = Query(default=100, ge=1, le=5000),
    user: dict = Depends(require_role("admin"))
):
    pm2_cmd = get_pm2_cmd()
    
    if not app_name.isdigit():
        validate_app_name(app_name)
        
    try:
        jlist_res = subprocess.run(
            [pm2_cmd, "jlist"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=10
        )
        apps = parse_pm2_jlist(jlist_res.stdout)
        target_app = None
        for app in apps:
            if str(app.get("pm_id")) == app_name or app.get("name") == app_name:
                target_app = app
                break
                
        if target_app:
            pm2_env = target_app.get("pm2_env", {})
            out_path = pm2_env.get("pm_out_log_path")
            err_path = pm2_env.get("pm_err_log_path")
            
            logs = []
            def read_file_tail(path, label):
                if path and os.path.exists(path):
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        return f"--- {label} (last {min(len(lines), limit)} lines) ---\n" + "".join(lines[-limit:])
                return ""
                
            stdout_logs = read_file_tail(out_path, "STDOUT")
            stderr_logs = read_file_tail(err_path, "STDERR")
            
            if stdout_logs:
                logs.append(stdout_logs)
            if stderr_logs:
                logs.append(stderr_logs)
                
            if logs:
                return {"logs": "\n\n".join(logs)}
    except Exception:
        pass

    # Fallback to execution
    try:
        result = subprocess.run(
            [pm2_cmd, "logs", app_name, "--lines", str(limit), "--raw"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=15
        )
        return {"logs": result.stdout or result.stderr or "No logs retrieved."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read logs: {str(e)}")


@router.websocket("/ws/pm2/logs/{app_name}/stream")
async def ws_pm2_logs_stream(websocket: WebSocket, app_name: str):
    session_id = websocket.cookies.get(config.SESSION_COOKIE_NAME)
    session = get_valid_session(session_id)
    if not session or config.ROLE_ORDER.get(session.get("role", ""), 0) < config.ROLE_ORDER["admin"]:
        await websocket.close(code=4403, reason="Admin role required")
        return
        
    if not app_name.isdigit():
        try:
            validate_app_name(app_name)
        except Exception:
            await websocket.close(code=4400, reason="Invalid app name")
            return
            
    await websocket.accept()
    
    pm2_cmd = get_pm2_cmd()
    proc = None
    try:
        proc = subprocess.Popen(
            [pm2_cmd, "logs", app_name, "--raw"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="ignore",
            bufsize=1
        )
        
        loop = asyncio.get_event_loop()
        
        async def read_stdout():
            while True:
                line = await loop.run_in_executor(None, proc.stdout.readline)
                if not line:
                    break
                await websocket.send_text(line)
                
        async def receive_messages():
            try:
                while True:
                    data = await websocket.receive_text()
                    if data == "ping":
                        await websocket.send_text("pong")
            except WebSocketDisconnect:
                pass
                
        await asyncio.gather(
            read_stdout(),
            receive_messages(),
            return_exceptions=True
        )
        
    except Exception as e:
        try:
            await websocket.send_text(f"Error streaming logs: {str(e)}")
        except Exception:
            pass
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                pass


@router.get("/state/services")
def get_state_services(user=Depends(require_role("viewer"))):
    return {"services": database.list_pinned_services()}


@router.post("/state/services")
def add_state_service(data: SaveServiceRequest, user=Depends(require_role("operator"))):
    name = data.name.strip()
    command = data.command.strip()

    if not name:
        raise HTTPException(status_code=400, detail="Service name is required")
    if not command:
        raise HTTPException(status_code=400, detail="Service command is required")

    try:
        created = database.create_pinned_service(name=name, port=data.port, command=command)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Service name already pinned")

    return {"status": "created", "service": created}


@router.delete("/state/services/{service_id}")
def remove_state_service(service_id: int, user=Depends(require_role("admin"))):
    if not database.delete_pinned_service(service_id):
        raise HTTPException(status_code=404, detail="Service not found")
    return {"status": "deleted", "id": service_id}


class StopServiceRequest(BaseModel):
    name: str

class RunServiceRequest(BaseModel):
    name: str
    port: int | None = None
    command: str


def is_process_running(proc: subprocess.Popen | None) -> bool:
    return proc is not None and proc.poll() is None


def normalize_service_name(name: str) -> str:
    allowed = "-_"
    cleaned = "".join(ch for ch in name if ch.isalnum() or ch in allowed).strip("-_")
    return cleaned or "service"


@router.post("/state/pinned-ports/{pin_id}/start")
async def start_pinned_port_service(pin_id: int, user=Depends(require_role("operator"))):
    pin = database.get_pinned_port(pin_id)
    if not pin:
        raise HTTPException(status_code=404, detail="Pinned port not found")

    command = pin.get("command")
    if not command:
        raise HTTPException(status_code=400, detail="No start command configured for this pinned port. Use Configure to set one.")

    service_name = pin.get("service_name") or f"port-{pin['port']}"
    setup_command = pin.get("setup_command")
    workdir = pin.get("workdir") or None

    existing = config.managed_services.get(service_name)
    if existing and is_process_running(existing.get("process")):
        return {"status": "already_running", "name": service_name}

    if setup_command:
        try:
            setup_proc = subprocess.run(
                setup_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=workdir,
            )
            if setup_proc.returncode != 0:
                return {
                    "status": "setup_failed",
                    "name": service_name,
                    "stderr": (setup_proc.stderr or "")[-500:],
                    "stdout": (setup_proc.stdout or "")[-500:],
                }
        except subprocess.TimeoutExpired:
            return {"status": "setup_failed", "name": service_name, "stderr": "Setup command timed out after 120s"}
        except Exception as e:
            return {"status": "setup_failed", "name": service_name, "stderr": str(e)}

    log_path = f"{config.LOG_DIR}/{normalize_service_name(service_name)}.log"
    logfile = open(log_path, "a", encoding="utf-8")

    logfile.write(f"\n===== START: {service_name} (from pinned port {pin['port']}) =====\n")
    logfile.flush()

    # Import signal inside function or globally
    import signal
    proc = subprocess.Popen(
        command,
        shell=True,
        stdout=logfile,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        text=True,
        cwd=workdir,
    )

    config.managed_services[service_name] = {
        "process": proc,
        "logfile": logfile,
        "command": command,
        "port": pin["port"],
    }

    database.log_audit(user["username"], "start_pinned_port_service", f"Started service '{service_name}' on port {pin['port']} (PID: {proc.pid})")
    return {"status": "started", "name": service_name, "pid": proc.pid}


@router.post("/state/pinned-ports/{pin_id}/stop")
async def stop_pinned_port_service(pin_id: int, user=Depends(require_role("operator"))):
    pin = database.get_pinned_port(pin_id)
    if not pin:
        raise HTTPException(status_code=404, detail="Pinned port not found")

    service_name = pin.get("service_name") or f"port-{pin['port']}"
    entry = config.managed_services.get(service_name)

    if not entry:
        return {"status": "not_managed", "name": service_name}

    proc = entry.get("process")
    logfile = entry.get("logfile")

    if not is_process_running(proc):
        if logfile and not logfile.closed:
            logfile.write(f"===== STOP: {service_name} (already exited) =====\n")
            logfile.flush()
            logfile.close()
        config.managed_services.pop(service_name, None)
        return {"status": "already_stopped", "name": service_name}

    import signal
    try:
        if proc and proc.pid:
            os.killpg(proc.pid, signal.SIGTERM)
    except Exception:
        proc.terminate()

    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()

    if logfile and not logfile.closed:
        logfile.write(f"===== STOP: {service_name} =====\n")
        logfile.flush()
        logfile.close()

    config.managed_services.pop(service_name, None)

    database.log_audit(user["username"], "stop_pinned_port_service", f"Stopped service '{service_name}' on port {pin['port']}")
    return {"status": "stopped", "name": service_name}


@router.get("/logs/{service}")
def get_logs(
    service: str,
    lines: int = Query(100, ge=1, le=1000),
    user=Depends(require_role("viewer")),
):
    path = f"{config.LOG_DIR}/{normalize_service_name(service)}.log"
    if not os.path.exists(path):
        return {"logs": ["No logs yet"]}

    from collections import deque
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        last_lines = list(deque(f, maxlen=lines))

    return {"logs": last_lines}


@router.post("/run")
async def run_service(data: RunServiceRequest, user=Depends(require_role("operator"))):
    if not data.command.strip():
        raise HTTPException(status_code=400, detail="Service command is required")

    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Service name is required")

    existing = config.managed_services.get(name)
    if existing and is_process_running(existing.get("process")):
        return {"status": "already_running", "name": name}

    log_path = f"{config.LOG_DIR}/{normalize_service_name(name)}.log"
    logfile = open(log_path, "a", encoding="utf-8")

    logfile.write(f"\n===== START: {name} =====\n")
    logfile.flush()

    proc = subprocess.Popen(
        data.command,
        shell=True,
        stdout=logfile,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        text=True
    )

    config.managed_services[name] = {
        "process": proc,
        "logfile": logfile,
        "command": data.command,
        "port": data.port,
    }

    database.log_audit(user["username"], "start_service", f"Started service '{name}' (PID: {proc.pid})")

    return {"status": "started", "name": name, "pid": proc.pid}


@router.post("/stop")
async def stop_service(data: StopServiceRequest, user=Depends(require_role("operator"))):
    name = data.name.strip()
    entry = config.managed_services.get(name)

    if not entry:
        return {"status": "not_managed", "name": name}

    proc = entry.get("process")
    logfile = entry.get("logfile")

    if not is_process_running(proc):
        if logfile and not logfile.closed:
            logfile.write(f"===== STOP: {name} (already exited) =====\n")
            logfile.flush()
            logfile.close()
        config.managed_services.pop(name, None)
        return {"status": "already_stopped", "name": name}

    import signal
    try:
        if proc and proc.pid:
            os.killpg(proc.pid, signal.SIGTERM)
    except Exception:
        proc.terminate()

    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()

    if logfile and not logfile.closed:
        logfile.write(f"===== STOP: {name} =====\n")
        logfile.flush()
        logfile.close()

    config.managed_services.pop(name, None)

    database.log_audit(user["username"], "stop_service", f"Stopped service '{name}'")

    return {"status": "stopped", "name": name}

