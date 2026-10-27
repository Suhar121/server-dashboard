use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use sqlx::{Pool, Sqlite};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct User {
    pub username: String,
    pub password_hash: String,
    pub salt: String,
    pub role: String,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct Session {
    pub token: String,
    pub username: String,
    pub role: String,
    pub expires_at: f64,
}

pub fn now_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn now_timestamp_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub fn hash_password(password: &str, salt: Option<&[u8]>, iterations: u32) -> (String, String) {
    let generated_salt: [u8; 16] = if let Some(s) = salt {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(s);
        arr
    } else {
        rand::random::<[u8; 16]>()
    };

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &generated_salt, iterations, &mut key);
    (hex::encode(key), hex::encode(generated_salt))
}

pub fn verify_password(password: &str, password_hash_hex: &str, salt_hex: &str, iterations: u32) -> bool {
    let Ok(salt) = hex::decode(salt_hex) else { return false; };
    let Ok(expected_key) = hex::decode(password_hash_hex) else { return false; };

    let mut candidate_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut candidate_key);

    candidate_key.as_slice() == expected_key.as_slice()
}

pub async fn get_user(pool: &Pool<Sqlite>, username: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT username, password_hash, salt, role, created_at, last_login_at FROM users WHERE username = ?",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
}

pub async fn create_user(
    pool: &Pool<Sqlite>,
    username: &str,
    password: &str,
    role: &str,
    iterations: u32,
) -> Result<User, sqlx::Error> {
    let (hash, salt) = hash_password(password, None, iterations);
    let now = now_timestamp();

    sqlx::query(
        "INSERT INTO users (username, password_hash, salt, role, created_at, last_login_at) VALUES (?, ?, ?, ?, ?, NULL)",
    )
    .bind(username)
    .bind(&hash)
    .bind(&salt)
    .bind(role)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(User {
        username: username.to_string(),
        password_hash: hash,
        salt,
        role: role.to_string(),
        created_at: now,
        last_login_at: None,
    })
}

pub async fn update_last_login(pool: &Pool<Sqlite>, username: &str) -> Result<(), sqlx::Error> {
    let now = now_timestamp();
    sqlx::query("UPDATE users SET last_login_at = ? WHERE username = ?")
        .bind(now)
        .bind(username)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn save_session(
    pool: &Pool<Sqlite>,
    token: &str,
    username: &str,
    role: &str,
    expires_at: f64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT OR REPLACE INTO sessions (token, username, role, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(token)
    .bind(username)
    .bind(role)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_session(pool: &Pool<Sqlite>, token: &str) -> Result<Option<Session>, sqlx::Error> {
    let now = now_timestamp_f64();
    sqlx::query_as::<_, Session>(
        "SELECT token, username, role, expires_at FROM sessions WHERE token = ? AND expires_at > ?",
    )
    .bind(token)
    .bind(now)
    .fetch_optional(pool)
    .await
}

pub async fn delete_session(pool: &Pool<Sqlite>, token: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions WHERE token = ?")
        .bind(token)
        .execute(pool)
        .await?;
    Ok(())
}
