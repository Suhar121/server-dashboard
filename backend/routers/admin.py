import os
import re
import time
import shutil
import tempfile
import subprocess
import psutil
import sqlite3
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
import config
import database
from routers.auth import require_role

router = APIRouter(tags=["admin"])

try:
    import pwd
except ImportError:
    pwd = None

class CreateAlertRuleRequest(BaseModel):
    metric_type: str
    threshold: float

class UpdateAlertRuleRequest(BaseModel):
    threshold: float | None = None
    enabled: bool | None = None

class CreateSshKeyRequest(BaseModel):
    ssh_user: str
    label: str
    key_type: str
    key_body: str
    key_comment: str | None = ""

class CreateCloudflaredRouteRequest(BaseModel):
    hostname: str
    service_scheme: str
    service_host: str
    service_port: int

class UpdateCloudflaredRouteRequest(BaseModel):
    hostname: str | None = None
    service_scheme: str | None = None
    service_host: str | None = None
    service_port: int | None = None

class NotifyRequest(BaseModel):
    msg: str

class SaveTodoRequest(BaseModel):
    text: str

class UpdateTodoRequest(BaseModel):
    done: bool


# ──────────────────────────────────────────────────────────────────
#  SSH KEYS HELPER FUNCTIONS
# ──────────────────────────────────────────────────────────────────

def remove_managed_ssh_block(content: str) -> str:
    pattern = re.compile(
        rf"\n?{re.escape(config.SSH_MANAGED_BLOCK_BEGIN)}.*?{re.escape(config.SSH_MANAGED_BLOCK_END)}\n?",
        re.DOTALL,
    )
    cleaned = re.sub(pattern, "\n", content)
    return cleaned.strip("\n")


def build_managed_ssh_block(ssh_user: str) -> str:
    key_rows = database.list_ssh_public_key_rows_for_user(ssh_user)
    if not key_rows:
        return ""

    lines = [config.SSH_MANAGED_BLOCK_BEGIN]
    for row in key_rows:
        key_id, key_type, key_body, key_comment = row
        label_comment = f" dashboard-key-id:{key_id}"
        key_line = f"{key_type} {key_body}"
        if key_comment:
            key_line += f" {key_comment}"
        key_line += label_comment
        lines.append(key_line)
    lines.append(config.SSH_MANAGED_BLOCK_END)
    return "\n".join(lines)


def sync_managed_ssh_keys(ssh_user: str):
    if pwd is None:
        raise HTTPException(
            status_code=501,
            detail="SSH key deployment is supported only on Unix/Linux hosts",
        )

    try:
        user_info = pwd.getpwnam(ssh_user)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Linux user '{ssh_user}' not found on this server")

    home_dir = user_info.pw_dir
    ssh_dir = os.path.join(home_dir, ".ssh")
    authorized_keys_path = os.path.join(ssh_dir, "authorized_keys")

    os.makedirs(ssh_dir, mode=0o700, exist_ok=True)

    existing = ""
    if os.path.exists(authorized_keys_path):
        with open(authorized_keys_path, "r", encoding="utf-8", errors="replace") as f:
            existing = f.read()

    cleaned = remove_managed_ssh_block(existing)
    managed_block = build_managed_ssh_block(ssh_user)

    if cleaned and managed_block:
        merged = f"{cleaned}\n\n{managed_block}\n"
    elif managed_block:
        merged = f"{managed_block}\n"
    elif cleaned:
        merged = f"{cleaned}\n"
    else:
        merged = ""

    tmp_path = authorized_keys_path + ".tmp-dashboard"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(merged)

    os.replace(tmp_path, authorized_keys_path)

    try:
        os.chmod(ssh_dir, 0o700)
        os.chmod(authorized_keys_path, 0o600)
    except Exception:
        pass

    try:
        os.chown(ssh_dir, user_info.pw_uid, user_info.pw_gid)
        os.chown(authorized_keys_path, user_info.pw_uid, user_info.pw_gid)
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────
#  CLOUDFLARED CONFIG HELPERS
# ──────────────────────────────────────────────────────────────────

def remove_managed_cloudflared_block(content: str) -> str:
    lines = content.splitlines()
    cleaned_lines = []
    inside_managed_block = False

    for line in lines:
        stripped = line.strip()

        if stripped == config.CLOUDFLARED_MANAGED_BLOCK_BEGIN:
            inside_managed_block = True
            continue

        if stripped == config.CLOUDFLARED_MANAGED_BLOCK_END:
            inside_managed_block = False
            continue

        if not inside_managed_block:
            cleaned_lines.append(line)

    return "\n".join(cleaned_lines).strip("\n")


def normalize_cloudflared_ingress_indentation(config_content: str) -> str:
    ingress_header_pattern = re.compile(r"^\s*ingress\s*:\s*(?:#.*)?$")
    top_level_key_pattern = re.compile(r"^[A-Za-z0-9_-]+\s*:\s*(?:#.*)?$")

    lines = config_content.splitlines()
    normalized = []
    in_ingress = False

    for line in lines:
        stripped = line.strip()

        if not in_ingress:
            normalized.append(line)
            if ingress_header_pattern.match(line):
                in_ingress = True
            continue

        if stripped and not line.startswith(" ") and top_level_key_pattern.match(line):
            in_ingress = False
            normalized.append(line)
            continue

        if not stripped:
            normalized.append("")
            continue

        if stripped.startswith("#"):
            normalized.append(f"  {stripped}")
            continue

        if stripped.startswith("- "):
            normalized.append(f"  {stripped}")
            continue

        leading_spaces = len(line) - len(line.lstrip(" "))
        if leading_spaces < 4:
            normalized.append(f"    {stripped}")
        else:
            normalized.append(line)

    return "\n".join(normalized).strip("\n")


def build_managed_cloudflared_block() -> str:
    route_rows = database.list_cloudflared_route_rows()
    if not route_rows:
        return ""

    lines = [f"  {config.CLOUDFLARED_MANAGED_BLOCK_BEGIN}"]
    for row in route_rows:
        route_id, hostname, service_scheme, service_host, service_port = row
        lines.append(f"  # dashboard-route-id:{route_id}")
        lines.append(f"  - hostname: {hostname}")
        lines.append(f"    service: {service_scheme}://{service_host}:{service_port}")
    lines.append(f"  {config.CLOUDFLARED_MANAGED_BLOCK_END}")
    return "\n".join(lines)


def insert_managed_cloudflared_block(config_content: str, managed_block: str) -> str:
    ingress_pattern = re.compile(r"^\s*ingress\s*:\s*(?:#.*)?$")
    lines = config_content.splitlines()
    output = []
    inserted = False

    for line in lines:
        output.append(line)
        if not inserted and ingress_pattern.match(line):
            inserted = True
            if managed_block:
                output.append(managed_block)

    if not inserted:
        if output:
            output.append("")
        output.append("ingress:")
        if managed_block:
            output.append(managed_block)
        output.append("  - service: http_status:404")

    return "\n".join(output).strip("\n") + "\n"


def remove_unmanaged_cloudflared_hostname_items(config_content: str, hostnames_to_remove):
    targets = {
        (hostname or "").strip().lower().rstrip(".")
        for hostname in (hostnames_to_remove or [])
        if (hostname or "").strip()
    }
    if not targets:
        return config_content

    ingress_header_pattern = re.compile(r"^\s*ingress\s*:\s*(?:#.*)?$")
    top_level_key_pattern = re.compile(r"^[A-Za-z0-9_-]+\s*:\s*(?:#.*)?$")
    hostname_line_pattern = re.compile(r"^\s*-\s*hostname\s*:\s*(.+?)\s*(?:#.*)?$")
    item_start_pattern = re.compile(r"^\s*-\s+")

    lines = config_content.splitlines()
    output = []
    in_ingress = False
    item_buffer = []
    item_hostname = None
    item_indent = 0

    def flush_item():
        nonlocal item_buffer, item_hostname, item_indent
        if not item_buffer:
            return
        if item_hostname not in targets:
            output.extend(item_buffer)
        item_buffer = []
        item_hostname = None
        item_indent = 0

    for line in lines:
        stripped = line.strip()

        if not in_ingress:
            output.append(line)
            if ingress_header_pattern.match(line):
                in_ingress = True
            continue

        if stripped and not line.startswith(" ") and top_level_key_pattern.match(line):
            flush_item()
            in_ingress = False
            output.append(line)
            continue

        is_item_start = bool(item_start_pattern.match(line))
        if is_item_start:
            flush_item()
            item_buffer = [line]
            item_indent = len(line) - len(line.lstrip(" "))
            host_match = hostname_line_pattern.match(line)
            item_hostname = (
                host_match.group(1).strip().strip('"').strip("'").lower().rstrip(".")
                if host_match
                else None
            )
            continue

        if item_buffer:
            if not stripped:
                item_buffer.append(line)
                continue

            current_indent = len(line) - len(line.lstrip(" "))
            if current_indent > item_indent:
                item_buffer.append(line)
                continue

            flush_item()

        output.append(line)

    flush_item()
    return "\n".join(output).strip("\n")


def parse_cloudflared_tunnel_name_from_config(config_path: str) -> str | None:
    if not config_path or not os.path.exists(config_path):
        return None

    try:
        with open(config_path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("tunnel:"):
                    value = line.split(":", 1)[1].strip().strip('"').strip("'")
                    return value or None
    except Exception:
        return None

    return None


def get_cloudflared_candidate_config_paths(config_path: str | None = None):
    if config_path:
        return [os.path.abspath(config_path)]

    return [
        os.path.abspath(config.active_cloudflared_config_path),
        os.path.abspath(config.CLOUDFLARED_CONFIG_PATH),
        os.path.abspath(config.CLOUDFLARED_FALLBACK_CONFIG_PATH),
    ]


def parse_cloudflared_config_entries(config_path: str | None = None, include_managed: bool = True):
    candidate_paths = get_cloudflared_candidate_config_paths(config_path)
    seen_paths = set()

    ingress_header_pattern = re.compile(r"^\s*ingress\s*:\s*(?:#.*)?$")
    top_level_key_pattern = re.compile(r"^[A-Za-z0-9_-]+\s*:\s*(?:#.*)?$")
    hostname_line_pattern = re.compile(r"^\s*-\s*hostname\s*:\s*(.+?)\s*(?:#.*)?$")
    service_line_pattern = re.compile(r"^\s*service\s*:\s*(.+?)\s*(?:#.*)?$")

    for path in candidate_paths:
        if not path or path in seen_paths:
            continue
        seen_paths.add(path)

        if not os.path.exists(path):
            continue

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except Exception:
            if config_path:
                return []
            continue

        in_ingress = False
        in_managed = False
        current = None
        entries = []

        def _flush_current():
            nonlocal current
            if not current:
                return
            if current.get("hostname") and current.get("service"):
                if include_managed or not current.get("managed"):
                    entries.append(
                        {
                            "hostname": current["hostname"],
                            "service": current["service"],
                            "managed": bool(current.get("managed")),
                            "config_path": path,
                        }
                    )
            current = None

        for line in lines:
            stripped = line.strip()

            if stripped == config.CLOUDFLARED_MANAGED_BLOCK_BEGIN:
                in_managed = True
                continue
            if stripped == config.CLOUDFLARED_MANAGED_BLOCK_END:
                in_managed = False
                continue

            if not in_ingress:
                if ingress_header_pattern.match(line):
                    in_ingress = True
                continue

            if stripped and not line.startswith(" ") and top_level_key_pattern.match(line):
                _flush_current()
                in_ingress = False
                continue

            host_match = hostname_line_pattern.match(line)
            if host_match:
                _flush_current()
                hostname = host_match.group(1).strip().strip('"').strip("'").lower().rstrip(".")
                current = {
                    "hostname": hostname,
                    "service": None,
                    "managed": in_managed,
                } if hostname else None
                continue

            if current:
                service_match = service_line_pattern.match(line)
                if service_match:
                    service_value = service_match.group(1).strip().strip('"').strip("'")
                    if service_value:
                        current["service"] = service_value
                elif stripped.startswith("- "):
                    _flush_current()

        _flush_current()
        return entries

    return []


def list_cloudflared_config_hostnames(config_path: str | None = None):
    entries = parse_cloudflared_config_entries(config_path=config_path, include_managed=True)
    hostnames = []
    seen = set()
    for entry in entries:
        hostname = entry.get("hostname")
        if not hostname or hostname in seen:
            continue
        seen.add(hostname)
        hostnames.append(hostname)
    return hostnames


def parse_cloudflared_service_target(service_value: str):
    raw = (service_value or "").strip()
    matched = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://([^:/\s]+):(\d{1,5})$", raw)
    if not matched:
        return None

    return {
        "scheme": matched.group(1).lower(),
        "host": matched.group(2).strip().lower(),
        "port": int(matched.group(3)),
        "raw": raw,
    }


def resolve_cloudflared_active_config_path(config_path: str | None = None) -> str:
    candidates = get_cloudflared_candidate_config_paths(config_path)
    seen = set()

    for candidate in candidates:
        abs_path = os.path.abspath(candidate)
        if abs_path in seen:
            continue
        seen.add(abs_path)
        if os.path.exists(abs_path):
            config.active_cloudflared_config_path = abs_path
            return abs_path

    fallback = os.path.abspath(config_path) if config_path else os.path.abspath(config.CLOUDFLARED_CONFIG_PATH)
    config.active_cloudflared_config_path = fallback
    return fallback


def sync_existing_cloudflared_routes_from_config(config_path: str | None = None):
    active_path = resolve_cloudflared_active_config_path(config_path)
    config_entries = parse_cloudflared_config_entries(config_path=active_path, include_managed=True)
    if not config_entries:
        return {
            "config_path": active_path,
            "checked": 0,
            "updated": 0,
        }

    existing_routes = database.list_cloudflared_routes()
    routes_by_hostname = {
        (item.get("hostname") or "").strip().lower().rstrip("."): item
        for item in existing_routes
        if item.get("hostname")
    }

    checked_count = 0
    updated_count = 0

    for entry in config_entries:
        hostname = (entry.get("hostname") or "").strip().lower().rstrip(".")
        service_value = (entry.get("service") or "").strip()

        if not hostname or hostname not in routes_by_hostname:
            continue

        parsed_service = parse_cloudflared_service_target(service_value)
        if not parsed_service:
            continue

        try:
            normalized_scheme = normalize_cloudflared_service_scheme(parsed_service["scheme"])
            normalized_host = normalize_cloudflared_service_host(parsed_service["host"])
            normalized_port = int(parsed_service["port"])
        except HTTPException:
            continue
        except Exception:
            continue

        if normalized_port < 1 or normalized_port > 65535:
            continue

        current = routes_by_hostname[hostname]
        checked_count += 1

        if (
            current["service_scheme"] == normalized_scheme
            and current["service_host"] == normalized_host
            and int(current["service_port"]) == normalized_port
        ):
            continue

        changed = database.update_cloudflared_route_record(
            route_id=current["id"],
            hostname=current["hostname"],
            service_scheme=normalized_scheme,
            service_host=normalized_host,
            service_port=normalized_port,
        )
        if changed:
            current["service_scheme"] = normalized_scheme
            current["service_host"] = normalized_host
            current["service_port"] = normalized_port
            updated_count += 1

    return {
        "config_path": active_path,
        "checked": checked_count,
        "updated": updated_count,
    }


def get_cloudflared_tunnel_name() -> str | None:
    if config.CLOUDFLARED_TUNNEL_NAME:
        return config.CLOUDFLARED_TUNNEL_NAME

    candidate_paths = [
        config.active_cloudflared_config_path,
        os.path.abspath(config.CLOUDFLARED_CONFIG_PATH),
        os.path.abspath(config.CLOUDFLARED_FALLBACK_CONFIG_PATH),
    ]

    seen = set()
    for path in candidate_paths:
        if path in seen:
            continue
        seen.add(path)
        tunnel_name = parse_cloudflared_tunnel_name_from_config(path)
        if tunnel_name:
            return tunnel_name

    return None


def is_cloudflared_cli_available() -> bool:
    if os.path.sep in config.CLOUDFLARED_BIN_PATH:
        return os.path.exists(config.CLOUDFLARED_BIN_PATH) and os.access(config.CLOUDFLARED_BIN_PATH, os.X_OK)
    return shutil.which(config.CLOUDFLARED_BIN_PATH) is not None


def _is_cloudflared_tunnel_process(cmdline: list[str], process_name: str = "") -> bool:
    cmd_tokens = [str(token).strip().lower() for token in (cmdline or []) if str(token).strip()]
    cmd_joined = " ".join(cmd_tokens)
    process_name = (process_name or "").strip().lower()
    configured_bin = os.path.basename(config.CLOUDFLARED_BIN_PATH).strip().lower()

    is_cloudflared_binary = (
        "cloudflared" in process_name
        or "cloudflared" in cmd_joined
        or (configured_bin and configured_bin in cmd_joined)
    )
    if not is_cloudflared_binary:
        return False

    has_tunnel_run_tokens = "tunnel" in cmd_tokens and "run" in cmd_tokens
    has_tunnel_run_phrase = " tunnel " in f" {cmd_joined} " and " run " in f" {cmd_joined} "
    return has_tunnel_run_tokens or has_tunnel_run_phrase


def list_cloudflared_tunnel_processes(tunnel_name: str | None = None):
    expected_tunnel = (tunnel_name or "").strip().lower()
    processes = []

    for proc in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
        try:
            info = proc.info
            cmdline = info.get("cmdline") or []
            process_name = info.get("name") or ""

            if not _is_cloudflared_tunnel_process(cmdline, process_name):
                continue

            command = " ".join(str(part) for part in cmdline)
            if expected_tunnel and expected_tunnel not in command.lower():
                continue

            processes.append(
                {
                    "pid": int(info.get("pid")),
                    "command": command,
                    "started_at": int(info.get("create_time") or 0),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    processes.sort(key=lambda item: item["pid"])
    return processes


def stop_cloudflared_tunnel_processes(tunnel_name: str | None = None):
    matched = list_cloudflared_tunnel_processes(tunnel_name)
    if not matched:
        return []

    pid_to_process = {}
    for item in matched:
        pid = item["pid"]
        try:
            pid_to_process[pid] = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    for process in pid_to_process.values():
        try:
            process.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    gone, alive = psutil.wait_procs(
        list(pid_to_process.values()),
        timeout=config.CLOUDFLARED_TUNNEL_STOP_TIMEOUT_SECONDS,
    )

    stopped_pids = [proc.pid for proc in gone]

    for process in alive:
        try:
            process.kill()
            stopped_pids.append(process.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return sorted(set(stopped_pids))


def start_cloudflared_tunnel_process(tunnel_name: str, config_path: str):
    tunnel_name = (tunnel_name or "").strip()
    if not tunnel_name:
        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to determine Cloudflared tunnel name. Set CLOUDFLARED_TUNNEL_NAME "
                "or add 'tunnel: <name-or-uuid>' in your cloudflared config file."
            ),
        )

    if not is_cloudflared_cli_available():
        raise HTTPException(
            status_code=500,
            detail=(
                "Cloudflared CLI not found. Install cloudflared or set CLOUDFLARED_BIN_PATH "
                "to the executable path."
            ),
        )

    active_config = os.path.abspath(config_path or config.active_cloudflared_config_path)
    command = [
        config.CLOUDFLARED_BIN_PATH,
        "--config",
        active_config,
        "tunnel",
        "run",
        tunnel_name,
    ]

    try:
        os.makedirs(config.LOG_DIR, exist_ok=True)
        with open(config.CLOUDFLARED_TUNNEL_LOG_PATH, "a", encoding="utf-8") as logfile:
            logfile.write(f"\n===== CLOUDFLARED START: {tunnel_name} @ {int(time.time())} =====\n")
            logfile.flush()
            proc = subprocess.Popen(
                command,
                stdout=logfile,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                text=True,
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start Cloudflared tunnel process: {str(e)}")

    return {
        "pid": proc.pid,
        "command": " ".join(command),
        "log_path": os.path.abspath(config.CLOUDFLARED_TUNNEL_LOG_PATH),
    }


def ensure_cloudflared_dns_route(hostname: str):
    if not config.CLOUDFLARED_DNS_AUTO_ROUTE:
        return {
            "dns_routed": False,
            "dns_message": "Auto DNS route creation is disabled",
            "tunnel_name": get_cloudflared_tunnel_name(),
        }

    if not is_cloudflared_cli_available():
        raise HTTPException(
            status_code=500,
            detail=(
                "Cloudflared CLI not found. Install cloudflared or set CLOUDFLARED_BIN_PATH "
                "to the executable path."
            ),
        )

    tunnel_name = get_cloudflared_tunnel_name()
    if not tunnel_name:
        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to determine Cloudflared tunnel name. Set CLOUDFLARED_TUNNEL_NAME "
                "or add 'tunnel: <name-or-uuid>' in your cloudflared config file."
            ),
        )

    tmp_config_path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yml", delete=False) as tmp_file:
            tmp_file.write(f"tunnel: {tunnel_name}\n")
            tmp_config_path = tmp_file.name

        result = subprocess.run(
            [
                config.CLOUDFLARED_BIN_PATH,
                "--config",
                tmp_config_path,
                "tunnel",
                "route",
                "dns",
                tunnel_name,
                hostname,
            ],
            capture_output=True,
            text=True,
            timeout=config.CLOUDFLARED_DNS_ROUTE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Timed out while creating Cloudflared DNS route")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to execute cloudflared DNS route command: {str(e)}")
    finally:
        if tmp_config_path:
            try:
                os.remove(tmp_config_path)
            except Exception:
                pass

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "cloudflared DNS route failed").strip()
        if "already exists" in detail.lower():
            return {
                "dns_routed": True,
                "dns_message": "DNS route already existed",
                "tunnel_name": tunnel_name,
            }
        raise HTTPException(
            status_code=500,
            detail=(
                f"Failed to create DNS route for '{hostname}' via tunnel '{tunnel_name}': "
                f"{detail[:500]}"
            ),
        )

    return {
        "dns_routed": True,
        "dns_message": "DNS route created",
        "tunnel_name": tunnel_name,
    }


def sync_managed_cloudflared_routes_to_path(config_path: str, cleanup_hostnames: set[str] | None = None):
    config_path = os.path.abspath(config_path)
    config_dir = os.path.dirname(config_path)
    if config_dir:
        os.makedirs(config_dir, mode=0o755, exist_ok=True)

    existing = ""
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8", errors="replace") as f:
            existing = f.read()

    cleaned = remove_managed_cloudflared_block(existing)
    if cleanup_hostnames:
        cleaned = remove_unmanaged_cloudflared_hostname_items(cleaned, cleanup_hostnames)
    normalized = normalize_cloudflared_ingress_indentation(cleaned)
    managed_block = build_managed_cloudflared_block()
    merged = insert_managed_cloudflared_block(normalized, managed_block)

    tmp_path = config_path + ".tmp-dashboard"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(merged)

    os.replace(tmp_path, config_path)
    return config_path


def sync_managed_cloudflared_routes(cleanup_hostnames: set[str] | None = None):
    primary_path = os.path.abspath(config.CLOUDFLARED_CONFIG_PATH)
    fallback_path = os.path.abspath(config.CLOUDFLARED_FALLBACK_CONFIG_PATH)

    candidates = [primary_path]
    if fallback_path != primary_path:
        candidates.append(fallback_path)

    permission_denied_paths = []

    for candidate in candidates:
        try:
            used_path = sync_managed_cloudflared_routes_to_path(candidate, cleanup_hostnames=cleanup_hostnames)
            config.active_cloudflared_config_path = used_path
            return used_path
        except PermissionError:
            permission_denied_paths.append(candidate)
        except OSError as e:
            if getattr(e, "errno", None) == 13:
                permission_denied_paths.append(candidate)
            else:
                raise

    if permission_denied_paths:
        tried = ", ".join(permission_denied_paths)
        raise HTTPException(
            status_code=500,
            detail=(
                "Permission denied while writing Cloudflared config. "
                f"Tried: {tried}. "
                "Set CLOUDFLARED_CONFIG_PATH (or CLOUDFLARED_FALLBACK_CONFIG_PATH) to a writable path."
            ),
        )

    raise HTTPException(status_code=500, detail="Failed to write Cloudflared config")


def normalize_cloudflared_hostname(val: str | None) -> str:
    cleaned = (val or "").strip().lower().rstrip(".")
    if not cleaned:
        raise HTTPException(status_code=400, detail="hostname cannot be empty")
    if not config.CLOUDFLARED_HOSTNAME_PATTERN.match(cleaned):
        raise HTTPException(status_code=400, detail="Invalid hostname format")
    return cleaned


def normalize_cloudflared_service_scheme(val: str | None) -> str:
    normalized = (val or "").strip().lower()
    if normalized not in config.SUPPORTED_CLOUDFLARED_SCHEMES:
        raise HTTPException(status_code=400, detail="service_scheme must be http, https, or tcp")
    return normalized


def normalize_cloudflared_service_host(val: str | None) -> str:
    cleaned = (val or "").strip().lower()
    if not cleaned:
        raise HTTPException(status_code=400, detail="service_host cannot be empty")
    if not config.CLOUDFLARED_SERVICE_HOST_PATTERN.match(cleaned):
        raise HTTPException(status_code=400, detail="Invalid service_host format")
    return cleaned


# ──────────────────────────────────────────────────────────────────
#  ENDPOINTS
# ──────────────────────────────────────────────────────────────────

@router.get("/audit-logs")
def get_audit_logs(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(require_role("admin"))
):
    logs = database.list_audit_logs(limit=limit, offset=offset)
    return {"logs": logs}


@router.get("/alert-rules")
def get_alert_rules(user=Depends(require_role("admin"))):
    rules = database.list_alert_rules()
    return {"rules": rules}


@router.post("/alert-rules")
def add_alert_rule(data: CreateAlertRuleRequest, user=Depends(require_role("admin"))):
    metric_type = data.metric_type.strip().lower()

    if metric_type not in ["cpu", "ram"]:
        raise HTTPException(status_code=400, detail="metric_type must be 'cpu' or 'ram'")

    if data.threshold < 0 or data.threshold > 100:
        raise HTTPException(status_code=400, detail="threshold must be between 0 and 100")

    rule = database.create_alert_rule(metric_type=metric_type, threshold=data.threshold)
    database.log_audit(user["username"], "create_alert_rule", f"Created {metric_type} alert rule with threshold {data.threshold}%")

    return {"status": "created", "rule": rule}


@router.patch("/alert-rules/{rule_id}")
def update_alert_rule_endpoint(
    rule_id: int,
    data: UpdateAlertRuleRequest,
    user=Depends(require_role("admin"))
):
    if data.threshold is not None and (data.threshold < 0 or data.threshold > 100):
        raise HTTPException(status_code=400, detail="threshold must be between 0 and 100")

    if not database.update_alert_rule(rule_id=rule_id, threshold=data.threshold, enabled=data.enabled):
        raise HTTPException(status_code=404, detail="Alert rule not found")

    details = []
    if data.threshold is not None:
        details.append(f"threshold={data.threshold}%")
    if data.enabled is not None:
        details.append(f"enabled={data.enabled}")

    database.log_audit(user["username"], "update_alert_rule", f"Updated alert rule {rule_id}: {', '.join(details)}")

    return {"status": "updated", "id": rule_id}


@router.delete("/alert-rules/{rule_id}")
def remove_alert_rule(rule_id: int, user=Depends(require_role("admin"))):
    if not database.delete_alert_rule(rule_id):
        raise HTTPException(status_code=404, detail="Alert rule not found")

    database.log_audit(user["username"], "delete_alert_rule", f"Deleted alert rule {rule_id}")

    return {"status": "deleted", "id": rule_id}


@router.get("/settings/login-alerts")
def get_login_alerts_setting(user=Depends(require_role("admin"))):
    return {"enabled": database.get_setting("login_alerts_enabled", "true") == "true"}


@router.patch("/settings/login-alerts")
def toggle_login_alerts(data: dict, user=Depends(require_role("admin"))):
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        raise HTTPException(status_code=400, detail="enabled must be a boolean")
    database.set_setting("login_alerts_enabled", "true" if enabled else "false")
    database.log_audit(user["username"], "toggle_login_alerts", f"Login alerts {'enabled' if enabled else 'disabled'}")
    return {"enabled": enabled}


@router.get("/ssh/keys")
def get_ssh_keys(user=Depends(require_role("admin"))):
    return {"keys": database.list_ssh_public_keys()}


@router.post("/ssh/keys")
def add_ssh_key(data: CreateSshKeyRequest, user=Depends(require_role("admin"))):
    ssh_user = data.ssh_user.strip()
    label = data.label.strip()
    key_type = data.key_type.strip()
    key_body = data.key_body.strip()
    key_comment = data.key_comment.strip() if data.key_comment else ""

    if not config.SSH_USERNAME_PATTERN.match(ssh_user):
        raise HTTPException(status_code=400, detail="Invalid target SSH username format")

    if not label:
        raise HTTPException(status_code=400, detail="Label is required")

    if key_type not in config.SUPPORTED_SSH_KEY_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported SSH key type. Supported: {', '.join(config.SUPPORTED_SSH_KEY_TYPES)}",
        )

    if not re.match(r"^[A-Za-z0-9+/=]+$", key_body):
        raise HTTPException(status_code=400, detail="Invalid SSH public key body (must be base64-encoded)")

    import hashlib
    import base64
    try:
        raw_bytes = base64.b64decode(key_body)
        sha256_hash = hashlib.sha256(raw_bytes).digest()
        fingerprint = "SHA256:" + base64.b64encode(sha256_hash).decode("utf-8").replace("=", "")
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to calculate key fingerprint")

    try:
        created = database.create_ssh_public_key_record(
            ssh_user=ssh_user,
            label=label,
            key_type=key_type,
            key_body=key_body,
            key_comment=key_comment,
            fingerprint_sha256=fingerprint,
            created_by=user["username"],
        )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="An SSH key with this fingerprint already exists")

    try:
        sync_managed_ssh_keys(ssh_user)
        deploy_status = "deployed"
        deploy_error = None
    except HTTPException as e:
        deploy_status = "saved_locally_only"
        deploy_error = e.detail
    except Exception as e:
        deploy_status = "saved_locally_only"
        deploy_error = str(e)

    database.log_audit(
        user["username"],
        "add_ssh_key",
        f"Added SSH key '{label}' for user '{ssh_user}' (deploy_status: {deploy_status})",
    )

    return {
        "status": "created",
        "key": created,
        "deployment": {
            "status": deploy_status,
            "error": deploy_error,
        },
    }


@router.delete("/ssh/keys/{key_id}")
def remove_ssh_key(key_id: int, user=Depends(require_role("admin"))):
    existing = database.get_ssh_public_key_record(key_id)
    if not existing:
        raise HTTPException(status_code=404, detail="SSH public key not found")

    if not database.delete_ssh_public_key_record(key_id):
        raise HTTPException(status_code=404, detail="SSH public key not found")

    try:
        sync_managed_ssh_keys(existing["ssh_user"])
        deploy_status = "deployed"
        deploy_error = None
    except HTTPException as e:
        deploy_status = "removed_locally_only"
        deploy_error = e.detail
    except Exception as e:
        deploy_status = "removed_locally_only"
        deploy_error = str(e)

    database.log_audit(
        user["username"],
        "delete_ssh_key",
        f"Deleted SSH key '{existing['label']}' for user '{existing['ssh_user']}' (deploy_status: {deploy_status})",
    )

    return {
        "status": "deleted",
        "id": key_id,
        "deployment": {
            "status": deploy_status,
            "error": deploy_error,
        },
    }


@router.get("/cloudflared/routes")
def get_cloudflared_routes(user=Depends(require_role("admin"))):
    try:
        sync_existing_cloudflared_routes_from_config()
    except Exception:
        pass
    return {"routes": database.list_cloudflared_routes()}


@router.get("/cloudflared/tunnel/status")
def get_cloudflared_tunnel_status(user=Depends(require_role("admin"))):
    tunnel_name = get_cloudflared_tunnel_name()
    procs = list_cloudflared_tunnel_processes(tunnel_name)

    return {
        "tunnel_name": tunnel_name,
        "configured_tunnel_name": config.CLOUDFLARED_TUNNEL_NAME or None,
        "is_cli_available": is_cloudflared_cli_available(),
        "running": len(procs) > 0,
        "processes": procs,
        "log_path": os.path.abspath(config.CLOUDFLARED_TUNNEL_LOG_PATH) if os.path.exists(config.CLOUDFLARED_TUNNEL_LOG_PATH) else None,
    }


@router.post("/cloudflared/tunnel/restart")
def restart_cloudflared_tunnel(user=Depends(require_role("admin"))):
    tunnel_name = get_cloudflared_tunnel_name()
    if not tunnel_name:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unable to determine Cloudflared tunnel name. Set CLOUDFLARED_TUNNEL_NAME "
                "or add 'tunnel: <name-or-uuid>' in your cloudflared config file."
            ),
        )

    stopped_pids = stop_cloudflared_tunnel_processes(tunnel_name)
    started_info = start_cloudflared_tunnel_process(tunnel_name, config.active_cloudflared_config_path)

    database.log_audit(
        user["username"],
        "restart_cloudflared_tunnel",
        f"Restarted Cloudflared tunnel process (stopped={stopped_pids}, started_pid={started_info['pid']})",
    )

    return {
        "status": "restarted",
        "tunnel_name": tunnel_name,
        "stopped_pids": stopped_pids,
        "started": started_info,
    }


@router.post("/cloudflared/routes")
def add_cloudflared_route(data: CreateCloudflaredRouteRequest, user=Depends(require_role("admin"))):
    hostname = normalize_cloudflared_hostname(data.hostname)
    service_scheme = normalize_cloudflared_service_scheme(data.service_scheme)
    service_host = normalize_cloudflared_service_host(data.service_host)

    if data.service_port < 1 or data.service_port > 65535:
        raise HTTPException(status_code=400, detail="service_port must be between 1 and 65535")

    try:
        created = database.create_cloudflared_route_record(
            hostname=hostname,
            service_scheme=service_scheme,
            service_host=service_host,
            service_port=data.service_port,
            created_by=user["username"],
        )
        used_config_path = sync_managed_cloudflared_routes()
        dns_result = ensure_cloudflared_dns_route(hostname)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="This hostname already exists in Cloudflared routes")
    except HTTPException as e:
        if "created" in locals():
            database.delete_cloudflared_route_record(created["id"])
            try:
                sync_managed_cloudflared_routes()
            except Exception:
                pass
        raise e
    except Exception as e:
        if "created" in locals():
            database.delete_cloudflared_route_record(created["id"])
            try:
                sync_managed_cloudflared_routes()
            except Exception:
                pass
        raise HTTPException(status_code=500, detail=f"Failed to update Cloudflared configuration: {str(e)}")

    database.log_audit(
        user["username"],
        "add_cloudflared_route",
        f"Added Cloudflared route '{hostname}' -> {service_scheme}://{service_host}:{data.service_port}",
    )

    return {
        "status": "created",
        "route": created,
        "config_path": used_config_path,
        "dns": dns_result,
        "configured_config_path": os.path.abspath(config.CLOUDFLARED_CONFIG_PATH),
        "fallback_config_path": os.path.abspath(config.CLOUDFLARED_FALLBACK_CONFIG_PATH),
    }


@router.delete("/cloudflared/routes/{route_id}")
def remove_cloudflared_route(route_id: int, user=Depends(require_role("admin"))):
    existing = database.get_cloudflared_route_record(route_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Cloudflared route not found")

    if not database.delete_cloudflared_route_record(route_id):
        raise HTTPException(status_code=404, detail="Cloudflared route not found")

    try:
        used_config_path = sync_managed_cloudflared_routes()
    except HTTPException as e:
        database.restore_cloudflared_route_record(existing)
        try:
            sync_managed_cloudflared_routes()
        except Exception:
            pass
        raise e
    except Exception as e:
        database.restore_cloudflared_route_record(existing)
        try:
            sync_managed_cloudflared_routes()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"Failed to remove route from Cloudflared config: {str(e)}")

    database.log_audit(
        user["username"],
        "delete_cloudflared_route",
        f"Deleted Cloudflared route '{existing['hostname']}' -> {existing['service_scheme']}://{existing['service_host']}:{existing['service_port']}",
    )

    return {
        "status": "deleted",
        "id": route_id,
        "config_path": used_config_path,
        "configured_config_path": os.path.abspath(config.CLOUDFLARED_CONFIG_PATH),
        "fallback_config_path": os.path.abspath(config.CLOUDFLARED_FALLBACK_CONFIG_PATH),
    }


@router.patch("/cloudflared/routes/{route_id}")
def update_cloudflared_route(route_id: int, data: UpdateCloudflaredRouteRequest, user=Depends(require_role("admin"))):
    existing = database.get_cloudflared_route_record(route_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Cloudflared route not found")

    if (
        data.hostname is None
        and data.service_scheme is None
        and data.service_host is None
        and data.service_port is None
    ):
        raise HTTPException(status_code=400, detail="At least one field must be provided to update")

    final_hostname = normalize_cloudflared_hostname(data.hostname) if data.hostname is not None else existing["hostname"]
    final_service_scheme = (
        normalize_cloudflared_service_scheme(data.service_scheme)
        if data.service_scheme is not None
        else existing["service_scheme"]
    )
    final_service_host = (
        normalize_cloudflared_service_host(data.service_host)
        if data.service_host is not None
        else existing["service_host"]
    )

    if data.service_port is not None:
        if data.service_port < 1 or data.service_port > 65535:
            raise HTTPException(status_code=400, detail="service_port must be between 1 and 65535")
        final_service_port = data.service_port
    else:
        final_service_port = existing["service_port"]

    try:
        changed = database.update_cloudflared_route_record(
            route_id=route_id,
            hostname=final_hostname,
            service_scheme=final_service_scheme,
            service_host=final_service_host,
            service_port=final_service_port,
        )
        if not changed:
            raise HTTPException(status_code=404, detail="Cloudflared route not found")

        used_config_path = sync_managed_cloudflared_routes()
        dns_result = ensure_cloudflared_dns_route(final_hostname)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="This hostname already exists in Cloudflared routes")
    except HTTPException as e:
        try:
            database.update_cloudflared_route_record(
                route_id=route_id,
                hostname=existing["hostname"],
                service_scheme=existing["service_scheme"],
                service_host=existing["service_host"],
                service_port=existing["service_port"],
            )
            sync_managed_cloudflared_routes()
        except Exception:
            pass
        raise e
    except Exception as e:
        try:
            database.update_cloudflared_route_record(
                route_id=route_id,
                hostname=existing["hostname"],
                service_scheme=existing["service_scheme"],
                service_host=existing["service_host"],
                service_port=existing["service_port"],
            )
            sync_managed_cloudflared_routes()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"Failed to update Cloudflared configuration: {str(e)}")

    database.log_audit(
        user["username"],
        "update_cloudflared_route",
        f"Updated Cloudflared route '{existing['hostname']}' (ID: {route_id}) to '{final_hostname}' -> {final_service_scheme}://{final_service_host}:{final_service_port}",
    )

    return {
        "status": "updated",
        "id": route_id,
        "config_path": used_config_path,
        "dns": dns_result,
        "configured_config_path": os.path.abspath(config.CLOUDFLARED_CONFIG_PATH),
        "fallback_config_path": os.path.abspath(config.CLOUDFLARED_FALLBACK_CONFIG_PATH),
    }


@router.post("/cloudflared/routes/import")
def import_cloudflared_routes(config_path: str | None = Query(None), user=Depends(require_role("admin"))):
    active_path = resolve_cloudflared_active_config_path(config_path)
    if not os.path.exists(active_path):
        raise HTTPException(status_code=404, detail=f"Config file not found: {active_path}")

    config_entries = parse_cloudflared_config_entries(config_path=active_path, include_managed=False)
    if not config_entries:
        return {
            "status": "no_entries",
            "config_path": active_path,
            "imported": 0,
            "skipped": 0,
        }

    imported_count = 0
    skipped_count = 0
    errors = []

    for entry in config_entries:
        raw_hostname = entry.get("hostname")
        raw_service = entry.get("service")

        if not raw_hostname or not raw_service:
            skipped_count += 1
            continue

        try:
            hostname = normalize_cloudflared_hostname(raw_hostname)
        except HTTPException:
            skipped_count += 1
            continue

        parsed_service = parse_cloudflared_service_target(raw_service)
        if not parsed_service:
            skipped_count += 1
            continue

        try:
            scheme = normalize_cloudflared_service_scheme(parsed_service["scheme"])
            host = normalize_cloudflared_service_host(parsed_service["host"])
            port = int(parsed_service["port"])
        except HTTPException:
            skipped_count += 1
            continue

        if port < 1 or port > 65535:
            skipped_count += 1
            continue

        try:
            database.create_cloudflared_route_record(
                hostname=hostname,
                service_scheme=scheme,
                service_host=host,
                service_port=port,
                created_by=user["username"],
            )
            imported_count += 1
        except sqlite3.IntegrityError:
            skipped_count += 1
        except Exception as e:
            errors.append({"entry": entry, "error": str(e)})

    if imported_count > 0:
        try:
            sync_managed_cloudflared_routes()
        except Exception as e:
            errors.append({"general": f"Failed to sync config back after import: {str(e)}"})

    database.log_audit(
        user["username"],
        "import_cloudflared_routes",
        f"Imported {imported_count} Cloudflared route(s) from {active_path} (skipped={skipped_count})",
    )

    return {
        "status": "imported",
        "config_path": active_path,
        "imported": imported_count,
        "skipped": skipped_count,
        "errors": errors,
    }


@router.post("/notify")
async def notify(data: NotifyRequest, user=Depends(require_role("admin"))):
    config.send_telegram(data.msg)
    return {"status": "sent"}


@router.get("/state/todos")
def get_state_todos(user=Depends(require_role("viewer"))):
    return {"todos": database.list_todos()}


@router.post("/state/todos")
def add_state_todo(data: SaveTodoRequest, user=Depends(require_role("operator"))):
    text = data.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Todo text is required")

    created = database.create_todo(text=text)
    return {"status": "created", "todo": created}


@router.patch("/state/todos/{todo_id}")
def patch_state_todo(todo_id: int, data: UpdateTodoRequest, user=Depends(require_role("operator"))):
    if not database.update_todo_done(todo_id=todo_id, done=data.done):
        raise HTTPException(status_code=404, detail="Todo not found")
    return {"status": "updated", "id": todo_id, "done": data.done}


@router.delete("/state/todos/{todo_id}")
def remove_state_todo(todo_id: int, user=Depends(require_role("operator"))):
    if not database.delete_todo(todo_id):
        raise HTTPException(status_code=404, detail="Todo not found")
    return {"status": "deleted", "id": todo_id}
