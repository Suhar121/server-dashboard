import os
import json
import time
import config
from db.base import db_connect

DEFAULT_TEMPLATES = [
    {
        "name": "Nginx",
        "description": "High-performance web server and reverse proxy",
        "icon": "globe",
        "category": "web",
        "default_port": 80,
        "env_schema": json.dumps([
            {"key": "NGINX_HOST", "label": "Server Name", "default": "localhost"},
        ]),
        "compose_yaml": """services:
  nginx:
    image: nginx:alpine
    container_name: nginx-app
    ports:
      - "${PORT:-80}:80"
    volumes:
      - ./html:/usr/share/nginx/html
    restart: unless-stopped
""",
    },
    {
        "name": "Node.js",
        "description": "JavaScript runtime with Express.js starter",
        "icon": "code-2",
        "category": "dev",
        "default_port": 3000,
        "env_schema": json.dumps([
            {"key": "NODE_ENV", "label": "Environment", "default": "production"},
        ]),
        "compose_yaml": """services:
  node-app:
    image: node:20-alpine
    container_name: node-app
    ports:
      - "${PORT:-3000}:3000"
    working_dir: /app
    volumes:
      - ./app:/app
    command: sh -c "npm install && node index.js"
    restart: unless-stopped
""",
    },
    {
        "name": "Python",
        "description": "Python Flask/FastAPI application server",
        "icon": "terminal",
        "category": "dev",
        "default_port": 5000,
        "env_schema": json.dumps([
            {"key": "FLASK_ENV", "label": "Environment", "default": "production"},
            {"key": "PYTHONUNBUFFERED", "label": "Unbuffered Output", "default": "1"},
        ]),
        "compose_yaml": """services:
  python-app:
    image: python:3.12-slim
    container_name: python-app
    ports:
      - "${PORT:-5000}:5000"
    working_dir: /app
    volumes:
      - ./app:/app
    command: sh -c "pip install -r requirements.txt && python app.py"
    restart: unless-stopped
""",
    },
    {
        "name": "PostgreSQL",
        "description": "Advanced open-source relational database",
        "icon": "database",
        "category": "database",
        "default_port": 5432,
        "env_schema": json.dumps([
            {"key": "POSTGRES_USER", "label": "Username", "default": "admin"},
            {"key": "POSTGRES_PASSWORD", "label": "Password", "default": "changeme"},
            {"key": "POSTGRES_DB", "label": "Database Name", "default": "mydb"},
        ]),
        "compose_yaml": """services:
  postgres:
    image: postgres:16-alpine
    container_name: postgres-db
    ports:
      - "${PORT:-5432}:5432"
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-admin}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme}
      POSTGRES_DB: ${POSTGRES_DB:-mydb}
    volumes:
      - pgdata:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  pgdata:
""",
    },
    {
        "name": "Redis",
        "description": "In-memory data store for caching and queues",
        "icon": "zap",
        "category": "database",
        "default_port": 6379,
        "env_schema": json.dumps([
            {"key": "REDIS_PASSWORD", "label": "Password (optional)", "default": ""},
        ]),
        "compose_yaml": """services:
  redis:
    image: redis:7-alpine
    container_name: redis-cache
    ports:
      - "${PORT:-6379}:6379"
    command: redis-server ${REDIS_PASSWORD:+--requirepass $REDIS_PASSWORD}
    volumes:
      - redisdata:/data
    restart: unless-stopped

volumes:
  redisdata:
""",
    },
    {
        "name": "MySQL",
        "description": "Popular open-source relational database",
        "icon": "database",
        "category": "database",
        "default_port": 3306,
        "env_schema": json.dumps([
            {"key": "MYSQL_ROOT_PASSWORD", "label": "Root Password", "default": "changeme"},
            {"key": "MYSQL_DATABASE", "label": "Database Name", "default": "mydb"},
            {"key": "MYSQL_USER", "label": "Username", "default": "admin"},
            {"key": "MYSQL_PASSWORD", "label": "Password", "default": "changeme"},
        ]),
        "compose_yaml": """services:
  mysql:
    image: mysql:8
    container_name: mysql-db
    ports:
      - "${PORT:-3306}:3306"
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD:-changeme}
      MYSQL_DATABASE: ${MYSQL_DATABASE:-mydb}
      MYSQL_USER: ${MYSQL_USER:-admin}
      MYSQL_PASSWORD: ${MYSQL_PASSWORD:-changeme}
    volumes:
      - mysqldata:/var/lib/mysql
    restart: unless-stopped

volumes:
  mysqldata:
""",
    },
    {
        "name": "WordPress",
        "description": "Full WordPress site with MySQL and PHP",
        "icon": "layout",
        "category": "web",
        "default_port": 8080,
        "env_schema": json.dumps([
            {"key": "WORDPRESS_DB_USER", "label": "DB Username", "default": "wordpress"},
            {"key": "WORDPRESS_DB_PASSWORD", "label": "DB Password", "default": "wordpress"},
            {"key": "WORDPRESS_DB_NAME", "label": "DB Name", "default": "wordpress"},
        ]),
        "compose_yaml": """services:
  wordpress:
    image: wordpress:latest
    container_name: wordpress-site
    ports:
      - "${PORT:-8080}:80"
    environment:
      WORDPRESS_DB_HOST: wp-db
      WORDPRESS_DB_USER: ${WORDPRESS_DB_USER:-wordpress}
      WORDPRESS_DB_PASSWORD: ${WORDPRESS_DB_PASSWORD:-wordpress}
      WORDPRESS_DB_NAME: ${WORDPRESS_DB_NAME:-wordpress}
    volumes:
      - wpdata:/var/www/html
    depends_on:
      - wp-db
    restart: unless-stopped

  wp-db:
    image: mysql:8
    container_name: wordpress-db
    environment:
      MYSQL_DATABASE: ${WORDPRESS_DB_NAME:-wordpress}
      MYSQL_USER: ${WORDPRESS_DB_USER:-wordpress}
      MYSQL_PASSWORD: ${WORDPRESS_DB_PASSWORD:-wordpress}
      MYSQL_ROOT_PASSWORD: ${WORDPRESS_DB_PASSWORD:-wordpress}
    volumes:
      - wpdbdata:/var/lib/mysql
    restart: unless-stopped

volumes:
  wpdata:
  wpdbdata:
""",
    },
    {
        "name": "MongoDB",
        "description": "NoSQL document database",
        "icon": "database",
        "category": "database",
        "default_port": 27017,
        "env_schema": json.dumps([
            {"key": "MONGO_INITDB_ROOT_USERNAME", "label": "Username", "default": "admin"},
            {"key": "MONGO_INITDB_ROOT_PASSWORD", "label": "Password", "default": "changeme"},
        ]),
        "compose_yaml": """services:
  mongo:
    image: mongo:7
    container_name: mongodb
    ports:
      - "${PORT:-27017}:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME: ${MONGO_INITDB_ROOT_USERNAME:-admin}
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_INITDB_ROOT_PASSWORD:-changeme}
    volumes:
      - mongodata:/data/db
    restart: unless-stopped

volumes:
  mongodata:
""",
    },
]

def init_user_db():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_login_at INTEGER
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            expires_at REAL NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS pinned_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            port INTEGER UNIQUE NOT NULL,
            command TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS pinned_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port INTEGER UNIQUE NOT NULL,
            service_name TEXT,
            command TEXT,
            setup_command TEXT,
            workdir TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            status TEXT NOT NULL DEFAULT 'success'
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric_type TEXT NOT NULL,
            threshold REAL NOT NULL,
            channel TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ssh_public_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT NOT NULL,
            key_type TEXT NOT NULL,
            public_key TEXT UNIQUE NOT NULL,
            fingerprint TEXT NOT NULL,
            added_at INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cloudflared_routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT UNIQUE NOT NULL,
            service_url TEXT NOT NULL,
            scheme TEXT NOT NULL,
            unmanaged INTEGER NOT NULL DEFAULT 0,
            added_at INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_conversations (
            id TEXT PRIMARY KEY,
            history_json TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS app_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            icon TEXT,
            category TEXT,
            default_port INTEGER,
            env_schema TEXT,
            compose_yaml TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS deployed_apps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            template_id INTEGER,
            status TEXT NOT NULL,
            compose_path TEXT NOT NULL,
            ports TEXT NOT NULL,
            env_vars TEXT NOT NULL,
            container_ids TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(template_id) REFERENCES app_templates(id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS github_deployments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_name TEXT UNIQUE NOT NULL,
            repo_url TEXT NOT NULL,
            branch TEXT NOT NULL DEFAULT 'main',
            compose_path TEXT NOT NULL,
            status TEXT NOT NULL,
            step_status TEXT NOT NULL,
            container_ids TEXT NOT NULL DEFAULT '[]',
            logs TEXT NOT NULL DEFAULT '',
            env_vars TEXT NOT NULL DEFAULT '{}',
            detected_type TEXT,
            detected_framework TEXT,
            detected_port INTEGER,
            created_by TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )

    # Migrations & database seeding
    cur.execute("PRAGMA table_info(alert_rules)")
    ar_columns = {row[1] for row in cur.fetchall()}
    if "created_at" not in ar_columns:
        cur.execute("ALTER TABLE alert_rules ADD COLUMN created_at INTEGER")

    cur.execute("PRAGMA table_info(users)")
    u_columns = {row[1] for row in cur.fetchall()}
    if "last_login_at" not in u_columns:
        cur.execute("ALTER TABLE users ADD COLUMN last_login_at INTEGER")

    cur.execute("PRAGMA table_info(pinned_ports)")
    pp_columns = {row[1] for row in cur.fetchall()}
    for col, col_type in [
        ("service_name", "TEXT"),
        ("command", "TEXT"),
        ("setup_command", "TEXT"),
        ("workdir", "TEXT"),
    ]:
        if col not in pp_columns:
            cur.execute(f"ALTER TABLE pinned_ports ADD COLUMN {col} {col_type}")

    # Sync existing github_deployments to deployed_apps table if they are missing
    try:
        cur.execute("SELECT app_name, compose_path, env_vars, container_ids, created_by, status, created_at, detected_port FROM github_deployments")
        gh_deps = cur.fetchall()
        for row in gh_deps:
            app_name, compose_path, env_vars_str, container_ids_str, created_by, status, created_at, detected_port = row
            # Check if already exists in deployed_apps
            cur.execute("SELECT id FROM deployed_apps WHERE name = ?", (app_name,))
            existing = cur.fetchone()
            if not existing and status in ("running", "stopped"):
                port_val = detected_port or 80
                ports_list = [port_val] if port_val else []
                cur.execute(
                    """INSERT INTO deployed_apps (name, template_id, status, compose_path, ports, env_vars, container_ids, created_by, created_at)
                       VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?)""",
                    (app_name, status, compose_path, json.dumps(ports_list), env_vars_str, container_ids_str, created_by, created_at)
                )
    except Exception as e:
        print("Failed to sync github deployments to deployed_apps:", e)

    conn.commit()
    conn.close()

    try:
        os.chmod(config.USERS_DB_PATH, 0o600)
    except Exception:
        pass

def seed_app_templates():
    now = int(time.time())
    conn = db_connect()
    cur = conn.cursor()
    for t in DEFAULT_TEMPLATES:
        cur.execute(
            """INSERT OR IGNORE INTO app_templates (name, description, icon, category, compose_yaml, env_schema, default_port, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (t["name"], t["description"], t["icon"], t["category"], t["compose_yaml"], t["env_schema"], t["default_port"], now),
        )
    conn.commit()
    conn.close()
