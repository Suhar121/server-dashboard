import os
import re
import time
import shutil
import tempfile
import subprocess
import threading
import json
import yaml
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
import config
import database
from routers.auth import require_role

router = APIRouter(tags=["deploy"])

class DeployAppRequest(BaseModel):
    app_name: str
    template_id: int | None = None
    port_override: int | None = None
    env_vars: dict[str, str] = {}

class DeployedAppActionRequest(BaseModel):
    action: str

class GitHubAnalyzeRequest(BaseModel):
    repo_url: str
    branch: str = "main"
    username: str | None = None
    password: str | None = None

class GitHubDeployRequest(BaseModel):
    repo_url: str
    app_name: str
    branch: str = "main"
    env_vars: dict[str, str] = {}
    port_override: int | None = None
    port_overrides: dict[str, int] = {}
    username: str | None = None
    password: str | None = None


# ──────────────────────────────────────────────────────────────────
#  HELPER FUNCTIONS FOR GITHUB DEPLOY PIPELINE
# ──────────────────────────────────────────────────────────────────

def safe_rmtree(path, ignore_errors=False):
    import stat
    def remove_readonly(func, p, excinfo):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            if not ignore_errors:
                raise

    if os.path.exists(path):
        try:
            shutil.rmtree(path, onerror=remove_readonly)
        except Exception:
            if not ignore_errors:
                raise


def _read_file_safe(path, max_bytes=65536):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes)
    except Exception:
        return ""


def _scan_env_file(repo_path):
    env_vars = []
    for name in (".env.example", ".env.sample", ".env.template"):
        p = os.path.join(repo_path, name)
        if os.path.isfile(p):
            content = _read_file_safe(p)
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, default = line.partition("=")
                    env_vars.append({"key": key.strip(), "default": default.strip().strip('"').strip("'")})
            return env_vars, name
    return [], None


def parse_compose_services(compose_path: str) -> list[dict]:
    try:
        with open(compose_path, "r") as f:
            data = yaml.safe_load(f)
    except Exception:
        return []

    if not data or not isinstance(data, dict):
        return []

    services = []
    for svc_name, svc_config in (data.get("services") or {}).items():
        if not isinstance(svc_config, dict):
            continue

        ports = []
        for p in svc_config.get("ports") or []:
            if isinstance(p, str):
                parts = p.split(":")
                if len(parts) == 2:
                    try:
                        ports.append({"host": int(parts[0]), "container": int(parts[1])})
                    except ValueError:
                        ports.append({"host": None, "container": parts[1]})
                elif len(parts) == 3:
                    try:
                        ports.append({"host": int(parts[1]), "container": int(parts[2])})
                    except ValueError:
                        ports.append({"host": None, "container": parts[2]})
            elif isinstance(p, dict):
                try:
                    host = int(p.get("published", 0)) if p.get("published") else None
                except (ValueError, TypeError):
                    host = None
                try:
                    container = int(p.get("target", 0)) if p.get("target") else None
                except (ValueError, TypeError):
                    container = None
                ports.append({"host": host, "container": container})

        env_vars = []
        env = svc_config.get("environment") or {}
        if isinstance(env, dict):
            for k, v in env.items():
                env_vars.append({"key": k, "value": str(v) if v is not None else ""})
        elif isinstance(env, list):
            for item in env:
                if isinstance(item, str) and "=" in item:
                    k, v = item.split("=", 1)
                    env_vars.append({"key": k.strip(), "value": v.strip()})

        depends_on = svc_config.get("depends_on") or {}
        if isinstance(depends_on, dict):
            depends_on = list(depends_on.keys())
        elif isinstance(depends_on, list):
            depends_on = [d if isinstance(d, str) else "" for d in depends_on]
        else:
            depends_on = []

        services.append({
            "name": svc_name,
            "image": svc_config.get("image"),
            "build": svc_config.get("build"),
            "ports": ports,
            "env_vars": env_vars,
            "depends_on": depends_on,
            "has_env_file": bool(svc_config.get("env_file")),
        })

    return services


def apply_port_overrides(compose_path: str, port_overrides: dict[str, int]) -> str | None:
    try:
        with open(compose_path, "r") as f:
            data = yaml.safe_load(f)
    except Exception:
        return None

    if not data or not isinstance(data, dict):
        return None

    changed = False
    for svc_name, new_port in port_overrides.items():
        svc = (data.get("services") or {}).get(svc_name)
        if not svc or not isinstance(svc, dict):
            continue
        ports = svc.get("ports")
        if not isinstance(ports, list):
            continue
        for i, p in enumerate(ports):
            if isinstance(p, str):
                parts = p.split(":")
                container_port = parts[-1]
                if len(parts) == 2:
                    ports[i] = f"{new_port}:{container_port}"
                    changed = True
                elif len(parts) == 3:
                    parts[1] = str(new_port)
                    ports[i] = ":".join(parts)
                    changed = True
            elif isinstance(p, dict):
                p["published"] = str(new_port)
                changed = True

    if not changed:
        return None

    return yaml.dump(data, default_flow_style=False)


def _detect_python(repo_path):
    framework = "none"
    port = 8000
    entry = "main.py"
    deps_file = None
    start_cmd = None

    for f in ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile"):
        if os.path.isfile(os.path.join(repo_path, f)):
            deps_file = f
            break

    candidates = ("main.py", "app.py", "server.py", "wsgi.py", "manage.py")
    for c in candidates:
        if os.path.isfile(os.path.join(repo_path, c)):
            entry = c
            break

    content = _read_file_safe(os.path.join(repo_path, entry))
    if "from fastapi" in content or "FastAPI()" in content:
        framework = "fastapi"
        port = 8000
        start_cmd = f"uvicorn main:app --host 0.0.0.0 --port {port}"
    elif "from flask" in content or "Flask(__name__)" in content:
        framework = "flask"
        port = 5000
        start_cmd = f"python {entry}"
    elif "from django" in content:
        framework = "django"
        port = 8000
        start_cmd = f"python manage.py runserver 0.0.0.0:{port}"
    else:
        start_cmd = f"python {entry}"

    return {
        "type": "python",
        "framework": framework,
        "port": port,
        "start_command": start_cmd,
        "build_command": None,
        "dependencies_file": deps_file,
        "entry_point": entry,
    }


def _detect_node(repo_path):
    framework = "none"
    port = 3000
    start_cmd = "node index.js"
    build_cmd = None
    pkg_path = os.path.join(repo_path, "package.json")
    content = _read_file_safe(pkg_path)
    if not content:
        return None

    try:
        pkg = json.loads(content)
    except Exception:
        return None

    all_deps = {}
    all_deps.update(pkg.get("dependencies", {}))
    all_deps.update(pkg.get("devDependencies", {}))
    scripts = pkg.get("scripts", {})

    if "next" in all_deps:
        framework = "nextjs"
        port = 3000
        build_cmd = "npm run build"
        start_cmd = "npm start"
    elif "nuxt" in all_deps:
        framework = "nuxt"
        port = 3000
        build_cmd = "npm run build"
        start_cmd = "npm start"
    elif "express" in all_deps:
        framework = "express"
        port = 3000
        start_cmd = scripts.get("start", "node index.js")
    elif "@vue/cli-service" in all_deps or "vue" in all_deps:
        framework = "vue"
        port = 8080
        build_cmd = "npm run build"
        start_cmd = "npm run serve"
    elif "react-scripts" in all_deps or "react" in all_deps:
        framework = "react"
        port = 3000
        build_cmd = "npm run build"
        start_cmd = "npm start"
    elif "start" in scripts:
        start_cmd = "npm start"

    return {
        "type": "node",
        "framework": framework,
        "port": port,
        "start_command": start_cmd,
        "build_command": build_cmd,
        "dependencies_file": "package.json",
        "entry_point": pkg.get("main", "index.js"),
    }


def _detect_go(repo_path):
    return {
        "type": "go",
        "framework": "none",
        "port": 8080,
        "start_command": "./app",
        "build_command": "go build -o app .",
        "dependencies_file": "go.mod",
        "entry_point": "main.go",
    }


def _detect_rust(repo_path):
    return {
        "type": "rust",
        "framework": "none",
        "port": 8080,
        "start_command": "./target/release/app",
        "build_command": "cargo build --release",
        "dependencies_file": "Cargo.toml",
        "entry_point": "src/main.rs",
    }


def detect_project_type(repo_path):
    files = set(os.listdir(repo_path)) if os.path.isdir(repo_path) else set()

    has_dockerfile = "Dockerfile" in files
    has_compose = any(f in files for f in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"))
    env_vars, env_file = _scan_env_file(repo_path)

    result = None

    if "requirements.txt" in files or "pyproject.toml" in files or "setup.py" in files or "Pipfile" in files:
        result = _detect_python(repo_path)
    elif "package.json" in files:
        result = _detect_node(repo_path)
    elif "go.mod" in files:
        result = _detect_go(repo_path)
    elif "Cargo.toml" in files:
        result = _detect_rust(repo_path)
    elif "index.html" in files and "package.json" not in files:
        result = {
            "type": "static",
            "framework": "none",
            "port": 80,
            "start_command": None,
            "build_command": None,
            "dependencies_file": None,
            "entry_point": "index.html",
        }
    elif has_dockerfile or has_compose:
        result = {
            "type": "docker",
            "framework": "none",
            "port": 80,
            "start_command": None,
            "build_command": None,
            "dependencies_file": None,
            "entry_point": None,
        }
    else:
        result = {
            "type": "unknown",
            "framework": "none",
            "port": 80,
            "start_command": None,
            "build_command": None,
            "dependencies_file": None,
            "entry_point": None,
        }

    result["has_dockerfile"] = has_dockerfile
    result["has_compose"] = has_compose
    result["env_file"] = env_file
    result["env_vars"] = env_vars
    return result


def generate_dockerfile(detected, repo_path):
    if detected.get("has_dockerfile"):
        return _read_file_safe(os.path.join(repo_path, "Dockerfile"))

    dtype = detected["type"]
    port = detected["port"]
    fw = detected.get("framework", "none")

    if dtype == "python":
        deps = detected.get("dependencies_file", "requirements.txt")
        if fw == "fastapi":
            cmd = f'CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "{port}"]'
        elif fw == "flask":
            entry = detected.get("entry_point", "app.py")
            cmd = f'CMD ["python", "{entry}"]'
        elif fw == "django":
            cmd = f'CMD ["python", "manage.py", "runserver", "0.0.0.0:{port}"]'
        else:
            entry = detected.get("entry_point", "main.py")
            cmd = f'CMD ["python", "{entry}"]'

        return f"""FROM python:3.12-slim
WORKDIR /app
COPY {deps} .
RUN pip install --no-cache-dir -r {deps}
COPY . .
EXPOSE {port}
{cmd}
"""

    if dtype == "node":
        lines = [
            "FROM node:20-alpine",
            "WORKDIR /app",
            "COPY package*.json ./",
            "RUN npm install",
            "COPY . .",
        ]
        if detected.get("build_command"):
            lines.append(f"RUN {detected['build_command']}")
        lines.append(f"EXPOSE {port}")
        lines.append(f'CMD ["sh", "-c", "{detected["start_command"]}"]')
        return "\n".join(lines) + "\n"

    if dtype == "static":
        return """FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE 80
"""

    if dtype == "go":
        return f"""FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o app .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/app .
EXPOSE {port}
CMD ["./app"]
"""

    if dtype == "rust":
        return f"""FROM rust:1.77 AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/app .
EXPOSE {port}
CMD ["./app"]
"""

    return f"""FROM ubuntu:22.04
WORKDIR /app
COPY . .
EXPOSE {port}
CMD ["echo", "No start command detected — edit this Dockerfile"]
"""


def generate_compose_yaml(app_name, detected, port):
    internal_port = detected["port"]
    return f"""services:
  {app_name}:
    build: .
    container_name: {app_name}
    ports:
      - "{port}:{internal_port}"
    restart: unless-stopped
"""


def suggest_git_clone_folder_name(repo_url: str) -> str:
    cleaned = (repo_url or "").strip().rstrip("/")
    if not cleaned:
        return "repo-clone"

    tail = cleaned.split("/")[-1].strip()
    if tail.endswith(".git"):
        tail = tail[:-4]

    sanitized = re.sub(r"[^A-Za-z0-9._-]", "-", tail).strip(".-_")
    return sanitized or "repo-clone"


def inject_git_credentials(url: str, username: str | None, password: str | None) -> str:
    if not username and not password:
        return url
    if url.startswith("https://") or url.startswith("http://"):
        prefix = "https://" if url.startswith("https://") else "http://"
        rest = url[len(prefix):]
        if "@" in rest:
            parts = rest.split("@", 1)
            rest = parts[1]
        user_pass = ""
        if username and password:
            from urllib.parse import quote_plus
            user_pass = f"{quote_plus(username)}:{quote_plus(password)}@"
        elif username:
            from urllib.parse import quote_plus
            user_pass = f"{quote_plus(username)}@"
        elif password:
            from urllib.parse import quote_plus
            user_pass = f"{quote_plus(password)}@"
        return f"{prefix}{user_pass}{rest}"
    return url


def _render_compose_yaml(template_yaml: str, app_name: str, env_vars: dict, port_override: int | None) -> str:
    rendered = template_yaml
    port = str(port_override) if port_override else ""
    rendered = rendered.replace("${PORT:-80}", port or "80")
    rendered = rendered.replace("${PORT:-3000}", port or "3000")
    rendered = rendered.replace("${PORT:-5000}", port or "5000")
    rendered = rendered.replace("${PORT:-5432}", port or "5432")
    rendered = rendered.replace("${PORT:-6379}", port or "6379")
    rendered = rendered.replace("${PORT:-3306}", port or "3306")
    rendered = rendered.replace("${PORT:-8080}", port or "8080")
    rendered = rendered.replace("${PORT:-27017}", port or "27017")
    for key, value in env_vars.items():
        rendered = rendered.replace(f"${{{key}:-", f"${{{key}:-")
    return rendered


def _run_docker_compose(compose_path: str, args: list[str], timeout: int = 120, log_callback=None):
    commands = [
        ["docker", "compose", "-f", compose_path, *args],
        ["docker-compose", "-f", compose_path, *args],
        ["sudo", "docker", "compose", "-f", compose_path, *args],
    ]
    last_error = ""
    for command in commands:
        try:
            if log_callback:
                import queue
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    encoding="utf-8",
                    errors="replace"
                )
                
                q = queue.Queue()
                def enqueue_output(out, queue_obj):
                    try:
                        for line in iter(out.readline, ''):
                            queue_obj.put(line)
                    except Exception:
                        pass
                    finally:
                        out.close()
                
                t = threading.Thread(target=enqueue_output, args=(process.stdout, q), daemon=True)
                t.start()
                
                start_time = time.time()
                output_lines = []
                
                while True:
                    if time.time() - start_time > timeout:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                        raise subprocess.TimeoutExpired(command, timeout, output="".join(output_lines))
                        
                    try:
                        line = q.get_nowait()
                    except queue.Empty:
                        if process.poll() is not None:
                            while not q.empty():
                                line = q.get_nowait()
                                stripped = line.rstrip("\r\n")
                                log_callback(stripped)
                                output_lines.append(line)
                            break
                        time.sleep(0.1)
                        continue
                        
                    stripped = line.rstrip("\r\n")
                    log_callback(stripped)
                    output_lines.append(line)
                
                returncode = process.wait()
                result = subprocess.CompletedProcess(
                    args=command,
                    returncode=returncode,
                    stdout="".join(output_lines),
                    stderr=""
                )
            else:
                result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
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
        if "permission denied" in lowered or "cannot connect to the docker daemon" in lowered:
            last_error = stderr_text or stdout_text
            continue
        raise HTTPException(status_code=500, detail=(stderr_text or stdout_text or "Docker compose failed")[:500])
    raise HTTPException(status_code=500, detail=(last_error or "Docker compose is not available")[:500])


def _get_compose_container_ids(compose_path: str) -> list[str]:
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", compose_path, "ps", "-q"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            result = subprocess.run(
                ["docker-compose", "-f", compose_path, "ps", "-q"],
                capture_output=True, text=True, timeout=30,
            )
        ids = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
        return ids
    except Exception:
        return []


def run_github_deploy_pipeline(deploy_id):
    dep = database.get_github_deployment(deploy_id)
    if not dep:
        return

    app_name = dep["app_name"]
    repo_url = dep["repo_url"]
    branch = dep.get("branch", "main")
    deploy_path = dep["compose_path"]  # stored in compose_path column in DB
    env_vars = json.loads(dep.get("env_vars", "{}"))
    port_override = env_vars.pop("__port_override__", None)
    port_overrides_str = env_vars.pop("__port_overrides__", None)
    port_overrides = json.loads(port_overrides_str) if port_overrides_str else {}

    steps = {
        "clone": "pending",
        "detect": "pending",
        "configure": "pending",
        "build": "pending",
        "deploy": "pending",
        "health": "pending",
    }

    class ThrottledLogger:
        def __init__(self, deploy_id, initial_logs=""):
            self.deploy_id = deploy_id
            self.logs = initial_logs
            self.last_update = 0.0
            self.pending_write = False
            self.lock = threading.Lock()

        def log(self, msg):
            with self.lock:
                self.logs += f"\n{msg}"
                now = time.time()
                if now - self.last_update > 0.3:
                    self._write_to_db()
                else:
                    self.pending_write = True

        def flush(self):
            with self.lock:
                if self.pending_write:
                    self._write_to_db()

        def _write_to_db(self):
            database.update_github_deployment_fields(self.deploy_id, logs=self.logs)
            self.last_update = time.time()
            self.pending_write = False

    logger = ThrottledLogger(deploy_id, dep.get("logs", ""))

    def _fail(step, msg):
        steps[step] = "failed"
        database.update_github_deployment_status(deploy_id, "failed", steps)
        logger.log(f"[FAIL] {step}: {msg}")
        logger.flush()
        try:
            existing_app = database.get_deployed_app_by_name(app_name)
            if existing_app:
                database.update_deployed_app_status(existing_app["id"], "failed")
        except Exception:
            pass

    def _log(msg):
        logger.log(msg)

    try:
        # Step 1: Clone
        steps["clone"] = "running"
        database.update_github_deployment_status(deploy_id, "cloning", steps)
        _log(f"[clone] Cloning {repo_url} (branch: {branch})...")

        tmp_clone = tempfile.mkdtemp(prefix="gh-clone-")
        try:
            import queue
            env = os.environ.copy()
            env["GIT_TERMINAL_PROMPT"] = "0"
            env["GIT_ASKPASS"] = "true"
            
            command = ["git", "clone", "--depth", "1", "-b", branch, repo_url, tmp_clone]
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                encoding="utf-8",
                errors="replace",
                env=env
            )
            
            q = queue.Queue()
            def enqueue_output(out, queue_obj):
                try:
                    for line in iter(out.readline, ''):
                        queue_obj.put(line)
                except Exception:
                    pass
                finally:
                    out.close()
            
            t = threading.Thread(target=enqueue_output, args=(process.stdout, q), daemon=True)
            t.start()
            
            start_time = time.time()
            output_lines = []
            
            while True:
                if time.time() - start_time > 300:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    _fail("clone", "Clone timed out after 300 seconds")
                    safe_rmtree(tmp_clone, ignore_errors=True)
                    return
                    
                try:
                    line = q.get_nowait()
                except queue.Empty:
                    if process.poll() is not None:
                        while not q.empty():
                            line = q.get_nowait()
                            _log(line.rstrip("\r\n"))
                            output_lines.append(line)
                        break
                    time.sleep(0.1)
                    continue
                
                _log(line.rstrip("\r\n"))
                output_lines.append(line)
            
            returncode = process.wait()
            if returncode != 0:
                error_msg = "".join(output_lines)
                if "terminal prompts disabled" in error_msg or "Authentication failed" in error_msg or "could not read Username" in error_msg or "repository not found" in error_msg.lower():
                    _log("[clone] [TIP] This seems to be a private repository.")
                    _log("[clone] [TIP] To clone a private repository, please either:")
                    _log("[clone]   1. Use a Personal Access Token (PAT) in the URL, e.g.:")
                    _log("[clone]      https://your_token@github.com/username/repo.git")
                    _log("[clone]   2. Configure SSH keys in the dashboard and use the SSH URL, e.g.:")
                    _log("[clone]      git@github.com:username/repo.git")
                _fail("clone", f"Clone failed with exit code {returncode}")
                safe_rmtree(tmp_clone, ignore_errors=True)
                return
        except Exception as e:
            _fail("clone", f"Clone execution failed: {str(e)[:300]}")
            safe_rmtree(tmp_clone, ignore_errors=True)
            return

        _log("[clone] Repository cloned to temp directory.")

        os.makedirs(deploy_path, exist_ok=True)
        copied_count = 0
        for item in os.listdir(tmp_clone):
            if item == ".git":
                continue
            src = os.path.join(tmp_clone, item)
            dst = os.path.join(deploy_path, item)
            try:
                if os.path.islink(src):
                    try:
                        linkto = os.readlink(src)
                        if os.path.exists(dst) or os.path.islink(dst):
                            os.unlink(dst)
                        os.symlink(linkto, dst)
                    except Exception:
                        pass
                elif os.path.isdir(src):
                    shutil.copytree(src, dst, dirs_exist_ok=True, ignore_dangling_symlinks=True)
                else:
                    shutil.copy2(src, dst)
                copied_count += 1
            except Exception as copy_err:
                _log(f"[clone] [WARNING] Skipped copying item '{item}': {copy_err}")
        _log(f"[clone] Copied {copied_count} items to deployment directory.")
        safe_rmtree(tmp_clone, ignore_errors=True)

        steps["clone"] = "done"
        _log("[clone] Done.")

        # Step 2: Detect
        steps["detect"] = "running"
        database.update_github_deployment_status(deploy_id, "detecting", steps)
        _log("[detect] Analyzing project...")
        detected = detect_project_type(deploy_path)
        steps["detect"] = "done"
        _log(f"[detect] Type={detected['type']}, Framework={detected['framework']}, Port={detected['port']}")

        database.update_github_deployment_fields(
            deploy_id,
            detected_type=detected["type"],
            detected_framework=detected["framework"],
            detected_port=detected["port"],
        )

        # Step 3: Configure
        steps["configure"] = "running"
        database.update_github_deployment_status(deploy_id, "configuring", steps)
        _log("[configure] Setting up Docker configuration...")

        port = port_override or detected["port"]

        dockerfile_content = generate_dockerfile(detected, deploy_path)
        if not detected.get("has_dockerfile"):
            with open(os.path.join(deploy_path, "Dockerfile"), "w") as f:
                f.write(dockerfile_content)
            _log("[configure] Generated Dockerfile.")
        else:
            _log("[configure] Using existing Dockerfile.")

        compose_path = None
        for candidate in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            p = os.path.join(deploy_path, candidate)
            if os.path.exists(p):
                compose_path = p
                break

        if compose_path:
            _log(f"[configure] Found existing {os.path.basename(compose_path)} — preserving it.")

            if port_overrides:
                _log(f"[configure] Applying port overrides: {port_overrides}")
                modified = apply_port_overrides(compose_path, port_overrides)
                if modified:
                    with open(compose_path, "w") as f:
                        f.write(modified)
                    _log("[configure] Port overrides applied.")
                else:
                    _log("[configure] No port overrides needed or could not apply.")
        else:
            compose_content = generate_compose_yaml(app_name, detected, port)
            compose_path = os.path.join(deploy_path, "docker-compose.yml")
            with open(compose_path, "w") as f:
                f.write(compose_content)
            _log("[configure] Generated docker-compose.yml.")

        if env_vars:
            env_lines = []
            for k, v in env_vars.items():
                env_lines.append(f"{k}={v}")
            with open(os.path.join(deploy_path, ".env"), "w") as f:
                f.write("\n".join(env_lines) + "\n")
            _log(f"[configure] Wrote .env with {len(env_vars)} variables.")

        steps["configure"] = "done"
        database.update_github_deployment_fields(deploy_id, compose_path=compose_path)
        _log("[configure] Done.")

        # Step 4: Build
        steps["build"] = "running"
        database.update_github_deployment_status(deploy_id, "building", steps)
        _log("[build] Building Docker image (this may take a while)...")

        build_result = _run_docker_compose(compose_path, ["build"], timeout=600, log_callback=_log)
        steps["build"] = "done"
        _log("[build] Build complete.")

        # Step 5: Deploy
        steps["deploy"] = "running"
        database.update_github_deployment_status(deploy_id, "deploying", steps)
        _log("[deploy] Starting containers...")

        deploy_result = _run_docker_compose(compose_path, ["up", "-d"], timeout=180, log_callback=_log)
        steps["deploy"] = "done"
        _log("[deploy] Containers started.")

        # Step 6: Health
        steps["health"] = "running"
        database.update_github_deployment_status(deploy_id, "health_check", steps)
        _log("[health] Checking container health...")

        time.sleep(3)
        container_ids = _get_compose_container_ids(compose_path)

        if container_ids:
            steps["health"] = "done"
            database.update_github_deployment_status(deploy_id, "running", steps, container_ids)
            _log(f"[health] OK — {len(container_ids)} container(s) running.")
            
            existing_app = database.get_deployed_app_by_name(app_name)
            port_val = port_override or detected.get("port") or 80
            ports_list = [port_val] if port_val else []
            
            if existing_app:
                conn = database.db_connect()
                cur = conn.cursor()
                cur.execute(
                    "UPDATE deployed_apps SET status = 'running', compose_path = ?, ports = ?, env_vars = ?, container_ids = ?, created_by = ? WHERE id = ?",
                    (compose_path, json.dumps(ports_list), json.dumps(env_vars), json.dumps(container_ids), dep["created_by"], existing_app["id"])
                )
                conn.commit()
                conn.close()
            else:
                conn = database.db_connect()
                cur = conn.cursor()
                cur.execute(
                    """INSERT INTO deployed_apps (name, template_id, status, compose_path, ports, env_vars, container_ids, created_by, created_at)
                       VALUES (?, NULL, 'running', ?, ?, ?, ?, ?, ?)""",
                    (app_name, compose_path, json.dumps(ports_list), json.dumps(env_vars), json.dumps(container_ids), dep["created_by"], int(time.time()))
                )
                conn.commit()
                conn.close()
        else:
            steps["health"] = "failed"
            _fail("health", "No running containers detected after start.")

    except subprocess.TimeoutExpired as e:
        _fail("build" if steps["build"] == "running" else "clone", f"Timeout: {e}")
    except Exception as e:
        current_step = [k for k, v in steps.items() if v == "running"]
        step_name = current_step[0] if current_step else "unknown"
        _fail(step_name, str(e)[:300])
    finally:
        logger.flush()


# ──────────────────────────────────────────────────────────────────
#  ROUTES
# ──────────────────────────────────────────────────────────────────

@router.get("/deploy/templates")
def get_deploy_templates(user=Depends(require_role("viewer"))):
    return {"templates": database.list_app_templates()}


@router.get("/deploy/templates/{template_id}")
def get_deploy_template(template_id: int, user=Depends(require_role("viewer"))):
    template = database.get_app_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    return template


@router.post("/deploy")
def deploy_app(data: DeployAppRequest, user=Depends(require_role("operator"))):
    app_name = data.app_name.strip()
    if not app_name:
        raise HTTPException(status_code=400, detail="App name is required")

    if not all(ch.isalnum() or ch in "-_" for ch in app_name):
        raise HTTPException(status_code=400, detail="App name must be alphanumeric with dashes/underscores only")

    template = None
    if data.template_id:
        template = database.get_app_template(data.template_id)
        if not template:
            raise HTTPException(status_code=404, detail="Template not found")

    compose_dir = os.path.join("deployed_apps", app_name)
    os.makedirs(compose_dir, exist_ok=True)
    compose_path = os.path.join(compose_dir, "docker-compose.yml")

    env_file_path = os.path.join(compose_dir, ".env")
    env_lines = [f"PORT={data.port_override or template['default_port'] if template else data.port_override or 80}"]
    for key, value in data.env_vars.items():
        env_lines.append(f"{key}={value}")
    with open(env_file_path, "w") as f:
        f.write("\n".join(env_lines) + "\n")

    if template:
        compose_content = _render_compose_yaml(template["compose_yaml"], app_name, data.env_vars, data.port_override)
    else:
        raise HTTPException(status_code=400, detail="Template is required for deployment")

    with open(compose_path, "w") as f:
        f.write(compose_content)

    ports = []
    if data.port_override:
        ports.append(data.port_override)
    elif template and template.get("default_port"):
        ports.append(template["default_port"])

    app_id = database.create_deployed_app(
        name=app_name,
        template_id=data.template_id,
        compose_path=compose_path,
        ports=ports,
        env_vars=data.env_vars,
        created_by=user["username"],
    )

    try:
        env = os.environ.copy()
        env.update(data.env_vars)
        env["PORT"] = str(data.port_override or (template["default_port"] if template else 80))

        commands = [
            ["docker", "compose", "-f", compose_path, "up", "-d"],
            ["docker-compose", "-f", compose_path, "up", "-d"],
            ["sudo", "docker", "compose", "-f", compose_path, "up", "-d"],
        ]
        last_error = ""
        deployed = False
        for command in commands:
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=180, env=env, cwd=compose_dir)
            except FileNotFoundError:
                continue
            except Exception as e:
                last_error = str(e)
                continue
            if result.returncode == 0:
                deployed = True
                break
            stderr_text = (result.stderr or "").strip()
            if "permission denied" in stderr_text.lower() or "cannot connect" in stderr_text.lower():
                last_error = stderr_text
                continue
            last_error = stderr_text
            break

        if deployed:
            container_ids = _get_compose_container_ids(compose_path)
            database.update_deployed_app_status(app_id, "running", container_ids)
            database.log_audit(user["username"], "deploy_app", f"Deployed app '{app_name}' from template '{template['name'] if template else 'custom'}'")
            return {"status": "running", "app_id": app_id, "name": app_name, "container_ids": container_ids}
        else:
            database.update_deployed_app_status(app_id, "failed")
            database.log_audit(user["username"], "deploy_app_failed", f"Failed to deploy '{app_name}': {last_error[:200]}")
            raise HTTPException(status_code=500, detail=f"Deployment failed: {last_error[:300]}")

    except HTTPException:
        raise
    except Exception as e:
        database.update_deployed_app_status(app_id, "failed")
        raise HTTPException(status_code=500, detail=f"Deployment error: {str(e)[:300]}")


@router.get("/deploy/apps")
def get_deploy_apps(user=Depends(require_role("viewer"))):
    apps = database.list_deployed_apps()
    for app in apps:
        if app["status"] == "running" and app["compose_path"] and os.path.exists(app["compose_path"]):
            container_ids = _get_compose_container_ids(app["compose_path"])
            app["container_ids"] = container_ids
    return {"apps": apps}


@router.post("/deploy/apps/{app_id}/action")
def deploy_app_action(app_id: int, data: DeployedAppActionRequest, user=Depends(require_role("operator"))):
    app = database.get_deployed_app(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Deployed app not found")

    action = data.action.strip().lower()
    compose_path = app["compose_path"]
    compose_dir = os.path.dirname(compose_path) if compose_path else None

    if action in ("start", "stop", "restart"):
        if not compose_path or not os.path.exists(compose_path):
            raise HTTPException(status_code=400, detail="Compose file not found for this app")

    if action == "start":
        _run_docker_compose(compose_path, ["up", "-d"], timeout=180)
        container_ids = _get_compose_container_ids(compose_path)
        database.update_deployed_app_status(app_id, "running", container_ids)
        gh_dep = database.get_github_deployment_by_name(app["name"])
        if gh_dep:
            database.update_github_deployment_status(gh_dep["id"], "running", container_ids=container_ids)
        database.log_audit(user["username"], "deploy_app_start", f"Started app '{app['name']}'")
        return {"status": "running", "container_ids": container_ids}

    elif action == "stop":
        _run_docker_compose(compose_path, ["down"], timeout=60)
        database.update_deployed_app_status(app_id, "stopped", [])
        gh_dep = database.get_github_deployment_by_name(app["name"])
        if gh_dep:
            database.update_github_deployment_status(gh_dep["id"], "stopped", container_ids=[])
        database.log_audit(user["username"], "deploy_app_stop", f"Stopped app '{app['name']}'")
        return {"status": "stopped"}

    elif action == "restart":
        _run_docker_compose(compose_path, ["down"], timeout=60)
        _run_docker_compose(compose_path, ["up", "-d"], timeout=180)
        container_ids = _get_compose_container_ids(compose_path)
        database.update_deployed_app_status(app_id, "running", container_ids)
        gh_dep = database.get_github_deployment_by_name(app["name"])
        if gh_dep:
            database.update_github_deployment_status(gh_dep["id"], "running", container_ids=container_ids)
        database.log_audit(user["username"], "deploy_app_restart", f"Restarted app '{app['name']}'")
        return {"status": "running", "container_ids": container_ids}

    elif action == "delete":
        if compose_path and os.path.exists(compose_path):
            try:
                _run_docker_compose(compose_path, ["down", "-v"], timeout=60)
            except Exception:
                pass
        if compose_dir and os.path.exists(compose_dir):
            try:
                safe_rmtree(compose_dir, ignore_errors=True)
            except Exception:
                pass
        database.delete_deployed_app(app_id)
        gh_dep = database.get_github_deployment_by_name(app["name"])
        if gh_dep:
            database.delete_github_deployment(gh_dep["id"])
        database.log_audit(user["username"], "deploy_app_delete", f"Deleted app '{app['name']}'")
        return {"status": "deleted"}

    else:
        raise HTTPException(status_code=400, detail="Action must be start, stop, restart, or delete")


@router.get("/deploy/apps/{app_id}/logs")
def deploy_app_logs(app_id: int, lines: int = Query(100, ge=1, le=2000), user=Depends(require_role("viewer"))):
    app = database.get_deployed_app(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Deployed app not found")

    compose_path = app["compose_path"]
    if not compose_path or not os.path.exists(compose_path):
        return {"logs": ["No compose file found for this app."]}

    try:
        result = _run_docker_compose(compose_path, ["logs", "--tail", str(lines)], timeout=60)
        combined = ""
        if result.stdout:
            combined += result.stdout
        if result.stderr:
            combined += result.stderr
        return {"logs": combined.splitlines(keepends=True)}
    except Exception as e:
        return {"logs": [f"Error fetching logs: {str(e)}"]}


@router.post("/deploy/github/analyze")
def github_analyze(data: GitHubAnalyzeRequest, user=Depends(require_role("operator"))):
    repo_url = data.repo_url.strip()
    branch = data.branch.strip() or "main"
    if not repo_url:
        raise HTTPException(status_code=400, detail="Repository URL is required")

    tmp_dir = tempfile.mkdtemp(prefix="gh-analyze-")
    try:
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_ASKPASS"] = "true"
        
        clone_url = inject_git_credentials(repo_url, data.username, data.password)
        
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "-b", branch, clone_url, tmp_dir],
            capture_output=True, text=True, timeout=60, env=env
        )
        if result.returncode != 0:
            stderr = result.stderr or ""
            if "terminal prompts disabled" in stderr or "Authentication failed" in stderr or "could not read Username" in stderr or "repository not found" in stderr.lower():
                raise HTTPException(status_code=400, detail="AUTH_REQUIRED")
            raise HTTPException(status_code=400, detail=f"Clone failed: {stderr[:300]}")

        detected = detect_project_type(tmp_dir)
        repo_name = suggest_git_clone_folder_name(repo_url)

        compose_services = []
        compose_content = None
        compose_path = None
        for candidate in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            p = os.path.join(tmp_dir, candidate)
            if os.path.exists(p):
                compose_path = p
                compose_content = _read_file_safe(p)
                compose_services = parse_compose_services(p)
                break

        dockerfile_content = None
        if detected.get("has_dockerfile"):
            dockerfile_content = _read_file_safe(os.path.join(tmp_dir, "Dockerfile"))
        else:
            dockerfile_content = generate_dockerfile(detected, tmp_dir)

        if not compose_content:
            compose_content = generate_compose_yaml(repo_name, detected, detected["port"])

        database.log_audit(user["username"], "github_analyze", f"Analyzed repo: {repo_url}")
        return {
            "repo_name": repo_name,
            "repo_url": repo_url,
            "branch": branch,
            "dockerfile_content": dockerfile_content,
            "compose_content": compose_content,
            "compose_services": compose_services,
            **detected,
        }
    except HTTPException:
        raise
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Clone timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)[:300])
    finally:
        safe_rmtree(tmp_dir, ignore_errors=True)


@router.post("/deploy/github/deploy")
def github_deploy(data: GitHubDeployRequest, user=Depends(require_role("operator"))):
    repo_url = data.repo_url.strip()
    app_name = data.app_name.strip()
    branch = data.branch.strip() or "main"

    if not repo_url:
        raise HTTPException(status_code=400, detail="Repository URL is required")
    if not app_name:
        raise HTTPException(status_code=400, detail="App name is required")
    if not all(ch.isalnum() or ch in "-_" for ch in app_name):
        raise HTTPException(status_code=400, detail="App name must be alphanumeric with dashes/underscores only")

    existing = database.get_github_deployment_by_name(app_name)
    if existing:
        old_status = existing.get("status", "")
        if old_status == "running":
            raise HTTPException(status_code=409, detail=f"App '{app_name}' is currently running. Stop it first.")
        old_path = existing.get("compose_path")
        if old_path and os.path.isdir(os.path.dirname(old_path)):
            safe_rmtree(os.path.dirname(old_path), ignore_errors=True)
        database.delete_github_deployment(existing["id"])

    deploy_path = os.path.join("deployed_apps", app_name)

    env_vars = dict(data.env_vars)
    if data.port_override:
        env_vars["__port_override__"] = str(data.port_override)
    if data.port_overrides:
        env_vars["__port_overrides__"] = json.dumps(data.port_overrides)

    authed_repo_url = inject_git_credentials(repo_url, data.username, data.password)

    deploy_id = database.create_github_deployment(
        app_name=app_name,
        repo_url=authed_repo_url,
        branch=branch,
        deploy_path=deploy_path,
        created_by=user["username"],
    )
    database.update_github_deployment_fields(deploy_id, env_vars=json.dumps(env_vars))

    thread = threading.Thread(target=run_github_deploy_pipeline, args=(deploy_id,), daemon=True)
    thread.start()

    database.log_audit(user["username"], "github_deploy", f"Started deploy of '{app_name}' from {repo_url}")
    return {"deploy_id": deploy_id, "app_name": app_name, "status": "pending"}


@router.get("/deploy/github/status/{deploy_id}")
def github_deploy_status(deploy_id: int, user=Depends(require_role("viewer"))):
    dep = database.get_github_deployment(deploy_id)
    if not dep:
        raise HTTPException(status_code=404, detail="Deployment not found")
    step_status = dep.get("step_status", "{}")
    if isinstance(step_status, str):
        try:
            step_status = json.loads(step_status)
        except Exception:
            step_status = {}
    dep["step_status"] = step_status
    container_ids = dep.get("container_ids", "[]")
    if isinstance(container_ids, str):
        try:
            container_ids = json.loads(container_ids)
        except Exception:
            container_ids = []
    dep["container_ids"] = container_ids
    env_vars = dep.get("env_vars", "{}")
    if isinstance(env_vars, str):
        try:
            env_vars = json.loads(env_vars)
        except Exception:
            env_vars = {}
    env_vars.pop("__port_override__", None)
    env_vars.pop("__port_overrides__", None)
    dep["env_vars"] = env_vars
    return dep


@router.delete("/deploy/github/{deploy_id}")
def github_deploy_delete(deploy_id: int, user=Depends(require_role("operator"))):
    dep = database.get_github_deployment(deploy_id)
    if not dep:
        raise HTTPException(status_code=404, detail="Deployment not found")

    deploy_path = dep.get("compose_path")
    if deploy_path and os.path.isdir(os.path.dirname(deploy_path)):
        safe_rmtree(os.path.dirname(deploy_path), ignore_errors=True)

    database.delete_github_deployment(deploy_id)
    database.log_audit(user["username"], "github_deploy_delete", f"Deleted GitHub deployment registration for '{dep['app_name']}'")
    return {"status": "deleted"}
