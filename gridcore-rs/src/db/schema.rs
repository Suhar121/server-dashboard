use sqlx::{Pool, Sqlite};

pub async fn create_tables(pool: &Pool<Sqlite>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_login_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            expires_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pinned_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            port INTEGER UNIQUE NOT NULL,
            command TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pinned_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port INTEGER UNIQUE NOT NULL,
            service_name TEXT,
            command TEXT,
            setup_command TEXT,
            workdir TEXT
        );

        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            status TEXT NOT NULL DEFAULT 'success'
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric_type TEXT NOT NULL,
            threshold REAL NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS saved_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            command TEXT NOT NULL,
            category TEXT,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS app_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            icon TEXT,
            category TEXT,
            default_port INTEGER,
            env_schema TEXT,
            compose_yaml TEXT
        );

        CREATE TABLE IF NOT EXISTS deployments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            repo_url TEXT,
            branch TEXT,
            status TEXT NOT NULL,
            port INTEGER,
            pid INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS monitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            target TEXT NOT NULL,
            interval INTEGER NOT NULL DEFAULT 60,
            status TEXT NOT NULL DEFAULT 'up',
            latency REAL DEFAULT 0.0,
            uptime_pct REAL DEFAULT 100.0,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS heartbeats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            monitor_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            latency REAL,
            timestamp INTEGER NOT NULL,
            message TEXT
        );

        CREATE TABLE IF NOT EXISTS status_pages (
            slug TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            footer_text TEXT,
            refresh_interval INTEGER DEFAULT 300,
            is_public INTEGER DEFAULT 1,
            groups_json TEXT DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS status_page_incidents (
            id TEXT PRIMARY KEY,
            status_page_slug TEXT DEFAULT 'monitor',
            title TEXT NOT NULL,
            content TEXT,
            style TEXT DEFAULT 'warning',
            created_at TEXT NOT NULL
        );

        INSERT OR IGNORE INTO status_pages (slug, title, description, footer_text, refresh_interval, is_public, groups_json)
        VALUES ('monitor', 'System Status', 'Live uptime & operational health', 'Powered by GridCore', 300, 1, '[]');
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn seed_templates(pool: &Pool<Sqlite>) -> Result<(), sqlx::Error> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM app_templates")
        .fetch_one(pool)
        .await?;

    if count.0 > 0 {
        return Ok(());
    }

    let default_templates = [
        ("Nginx", "High-performance web server and reverse proxy", "globe", "web", 80),
        ("Node.js", "JavaScript runtime with Express.js starter", "code-2", "dev", 3000),
        ("Python", "Python Flask/FastAPI application server", "terminal", "dev", 5000),
        ("PostgreSQL", "Advanced open-source relational database", "database", "database", 5432),
        ("MongoDB", "NoSQL document database", "database", "database", 27017),
    ];

    for (name, desc, icon, category, port) in default_templates {
        let _ = sqlx::query(
            "INSERT INTO app_templates (name, description, icon, category, default_port, env_schema, compose_yaml) VALUES (?, ?, ?, ?, ?, '[]', '')",
        )
        .bind(name)
        .bind(desc)
        .bind(icon)
        .bind(category)
        .bind(port)
        .execute(pool)
        .await;
    }

    Ok(())
}

