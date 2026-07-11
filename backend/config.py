import os
import re
import requests

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# 🔑 TELEGRAM CONFIG
BOT_TOKEN = os.getenv("BOT_TOKEN", "YOUR_TOKEN")
CHAT_ID = os.getenv("CHAT_ID", "YOUR_CHAT_ID")
SERVER_NAME = os.getenv("SERVER_NAME", "").strip()
SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))
SESSION_TIMEOUT_SECONDS = max(60, SESSION_TIMEOUT_MINUTES * 60)
SESSION_COOKIE_NAME = "dashboard_session"
USERS_DB_PATH = os.getenv("USERS_DB_PATH", "users.db")
PASSWORD_ITERATIONS = 150_000

# Regular Expressions
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")
SSH_USERNAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
CLOUDFLARED_HOSTNAME_PATTERN = re.compile(r"^(?:\*\.)?(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$")
CLOUDFLARED_SERVICE_HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9]$|^[A-Za-z0-9]$")
DOCKER_CONTAINER_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
GIT_CLONE_FOLDER_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

ROLE_ORDER = {
    "viewer": 1,
    "operator": 2,
    "admin": 3,
}

BATTERY_THRESHOLD = 20
SSH_MANAGED_BLOCK_BEGIN = "# >>> dashboard-managed-ssh-keys >>>"
SSH_MANAGED_BLOCK_END = "# <<< dashboard-managed-ssh-keys <<<"
SUPPORTED_SSH_KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
}

CLOUDFLARED_CONFIG_PATH = os.getenv("CLOUDFLARED_CONFIG_PATH", "/etc/cloudflared/config.yml")
CLOUDFLARED_FALLBACK_CONFIG_PATH = os.getenv(
    "CLOUDFLARED_FALLBACK_CONFIG_PATH",
    os.path.join(os.getcwd(), "cloudflared", "config.yml"),
)
CLOUDFLARED_MANAGED_BLOCK_BEGIN = "# >>> dashboard-managed-cloudflared-routes >>>"
CLOUDFLARED_MANAGED_BLOCK_END = "# <<< dashboard-managed-cloudflared-routes <<<"
SUPPORTED_CLOUDFLARED_SCHEMES = {"http", "https", "tcp"}
active_cloudflared_config_path = os.path.abspath(CLOUDFLARED_CONFIG_PATH)
CLOUDFLARED_BIN_PATH = (os.getenv("CLOUDFLARED_BIN_PATH", "cloudflared") or "cloudflared").strip()
CLOUDFLARED_TUNNEL_NAME = os.getenv("CLOUDFLARED_TUNNEL_NAME", "").strip()
CLOUDFLARED_DNS_AUTO_ROUTE = (os.getenv("CLOUDFLARED_DNS_AUTO_ROUTE", "true") or "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

try:
    _cf_dns_timeout = int(os.getenv("CLOUDFLARED_DNS_ROUTE_TIMEOUT_SECONDS", "20"))
except ValueError:
    _cf_dns_timeout = 20
CLOUDFLARED_DNS_ROUTE_TIMEOUT_SECONDS = max(5, min(120, _cf_dns_timeout))

try:
    _cf_tunnel_stop_timeout = int(os.getenv("CLOUDFLARED_TUNNEL_STOP_TIMEOUT_SECONDS", "10"))
except ValueError:
    _cf_tunnel_stop_timeout = 10
CLOUDFLARED_TUNNEL_STOP_TIMEOUT_SECONDS = max(2, min(30, _cf_tunnel_stop_timeout))

try:
    _docker_alert_scan_interval = int(os.getenv("DOCKER_ALERT_SCAN_INTERVAL_SECONDS", "8"))
except ValueError:
    _docker_alert_scan_interval = 8
DOCKER_ALERT_SCAN_INTERVAL_SECONDS = max(3, min(300, _docker_alert_scan_interval))

CLOUDFLARED_TUNNEL_LOG_PATH = os.path.join(LOG_DIR, "cloudflared_tunnel.log")
TERMINAL_PROTOCOL_V2_MARKER = "__DASH_TERM_PROTOCOL_V2__"

# 🤖 AI CONFIG
AI_PROVIDER = os.getenv("AI_PROVIDER", "gemini").lower()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")
NVIDIA_MODEL = os.getenv("NVIDIA_MODEL", "z-ai/glm-5.1")

# Shared mutable global state
battery_alert_sent = False
managed_services = {}
active_sessions = {}  # in-memory cache, DB is source of truth
alert_last_sent = {}  # Track when alerts were last sent to avoid spam
pinned_port_down_alert_state = {}  # port -> bool (True when already alerted as down)
docker_container_alert_state = {}  # container_id -> snapshot
docker_last_alert_scan_at = 0.0


def send_telegram(msg):
    try:
        if SERVER_NAME:
            msg = f"🖥️ [{SERVER_NAME}]\n{msg}"
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        requests.post(url, json={"chat_id": CHAT_ID, "text": msg})
    except Exception as e:
        print("Telegram error:", e)

