use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub host: String,
    pub bot_token: String,
    pub chat_id: String,
    pub server_name: String,
    pub session_timeout_minutes: u64,
    pub session_timeout_seconds: u64,
    pub session_cookie_name: String,
    pub users_db_path: String,
    pub password_iterations: u32,
    pub admin_username: String,
    pub admin_password: String,
    pub log_dir: String,
}

impl Config {
    pub fn from_env() -> Self {
        let _ = dotenvy::dotenv();

        let session_timeout_minutes: u64 = env::var("SESSION_TIMEOUT_MINUTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);

        let port: u16 = env::var("PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8000);

        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());

        let users_db_path = env::var("USERS_DB_PATH").unwrap_or_else(|_| "../users.db".to_string());

        Self {
            port,
            host,
            bot_token: env::var("BOT_TOKEN").unwrap_or_default(),
            chat_id: env::var("CHAT_ID").unwrap_or_default(),
            server_name: env::var("SERVER_NAME").unwrap_or_default(),
            session_timeout_minutes,
            session_timeout_seconds: session_timeout_minutes * 60,
            session_cookie_name: "dashboard_session".to_string(),
            users_db_path,
            password_iterations: 150_000,
            admin_username: env::var("ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_string()),
            admin_password: env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "admin123".to_string()),
            log_dir: "logs".to_string(),
        }
    }
}
