use crate::error::AppError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    routing::{delete, get, patch, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize)]
pub struct CreateAlertRulePayload {
    pub metric_type: String,
    pub threshold: f64,
}

#[derive(Deserialize)]
pub struct PatchAlertRulePayload {
    pub enabled: Option<bool>,
    pub threshold: Option<f64>,
}

#[derive(Deserialize)]
pub struct CreateTodoPayload {
    pub text: String,
}

#[derive(Deserialize)]
pub struct PatchTodoPayload {
    pub completed: bool,
}

#[derive(Deserialize)]
pub struct NotifyPayload {
    pub message: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct AuditLog {
    pub id: i64,
    pub timestamp: i64,
    pub username: String,
    pub role: String,
    pub action: String,
    pub details: Option<String>,
    pub ip_address: Option<String>,
    pub status: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct AlertRule {
    pub id: i64,
    pub metric_type: String,
    pub threshold: f64,
    pub enabled: i64,
    pub created_at: i64,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct TodoItem {
    pub id: i64,
    pub text: String,
    pub completed: i64,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/audit-logs", get(get_audit_logs))
        .route("/alert-rules", get(list_alert_rules).post(create_alert_rule))
        .route("/alert-rules/:id", patch(patch_alert_rule).delete(delete_alert_rule))
        .route("/settings/login-alerts", get(get_login_alerts).patch(set_login_alerts))
        .route("/state/todos", get(list_todos).post(create_todo))
        .route("/state/todos/:id", patch(patch_todo).delete(delete_todo))
        .route("/state/pinned-ports", get(list_pinned_ports).post(add_pinned_port))
        .route("/state/pinned-ports/:port", delete(remove_pinned_port))
        .route("/ssh/keys", get(list_ssh_keys).post(create_ssh_key))
        .route("/ssh/keys/:id", delete(delete_ssh_key))
        .route("/cloudflared/routes", get(list_cloudflared_routes))
        .route("/notify", post(notify))
}

async fn get_audit_logs(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<AuditLog>>, AppError> {
    auth.require_role("admin")?;

    let logs = sqlx::query_as::<_, AuditLog>(
        "SELECT id, timestamp, username, role, action, details, ip_address, status FROM audit_logs ORDER BY timestamp DESC LIMIT 200",
    )
    .fetch_all(&state.db)
    .await?;

    Ok(Json(logs))
}

async fn list_alert_rules(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<AlertRule>>, AppError> {
    auth.require_role("viewer")?;

    let rules = sqlx::query_as::<_, AlertRule>(
        "SELECT id, metric_type, threshold, enabled, created_at FROM alert_rules ORDER BY id ASC",
    )
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rules))
}

async fn create_alert_rule(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<CreateAlertRulePayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("admin")?;

    let now = chrono::Utc::now().timestamp();
    let res = sqlx::query(
        "INSERT INTO alert_rules (metric_type, threshold, enabled, created_at) VALUES (?, ?, 1, ?)",
    )
    .bind(&payload.metric_type)
    .bind(payload.threshold)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok(Json(json!({
        "id": res.last_insert_rowid(),
        "metric_type": payload.metric_type,
        "threshold": payload.threshold,
        "enabled": true,
        "created_at": now
    })))
}

async fn patch_alert_rule(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<i64>,
    Json(payload): Json<PatchAlertRulePayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("admin")?;

    if let Some(enabled) = payload.enabled {
        let val = if enabled { 1 } else { 0 };
        sqlx::query("UPDATE alert_rules SET enabled = ? WHERE id = ?")
            .bind(val)
            .bind(id)
            .execute(&state.db)
            .await?;
    }

    if let Some(threshold) = payload.threshold {
        sqlx::query("UPDATE alert_rules SET threshold = ? WHERE id = ?")
            .bind(threshold)
            .bind(id)
            .execute(&state.db)
            .await?;
    }

    Ok(Json(json!({ "status": "ok" })))
}

async fn delete_alert_rule(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("admin")?;

    sqlx::query("DELETE FROM alert_rules WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({ "status": "ok" })))
}

async fn get_login_alerts(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("admin")?;

    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM settings WHERE key = 'login_alerts_enabled'")
        .fetch_optional(&state.db)
        .await?;

    let enabled = row.map(|r| r.0 == "true").unwrap_or(true);
    Ok(Json(json!({ "enabled": enabled })))
}

async fn set_login_alerts(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("admin")?;

    let enabled = payload.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
    let val_str = if enabled { "true" } else { "false" };

    sqlx::query("INSERT INTO settings (key, value) VALUES ('login_alerts_enabled', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind(val_str)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({ "status": "ok", "enabled": enabled })))
}

async fn list_todos(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<TodoItem>>, AppError> {
    auth.require_role("viewer")?;

    let todos = sqlx::query_as::<_, TodoItem>(
        "SELECT id, text, completed FROM todos ORDER BY id ASC",
    )
    .fetch_all(&state.db)
    .await?;

    Ok(Json(todos))
}

async fn create_todo(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<CreateTodoPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    let res = sqlx::query("INSERT INTO todos (text, completed) VALUES (?, 0)")
        .bind(&payload.text)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({
        "id": res.last_insert_rowid(),
        "text": payload.text,
        "completed": 0
    })))
}

async fn patch_todo(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<i64>,
    Json(payload): Json<PatchTodoPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    let val = if payload.completed { 1 } else { 0 };
    sqlx::query("UPDATE todos SET completed = ? WHERE id = ?")
        .bind(val)
        .bind(id)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({ "status": "ok" })))
}

async fn delete_todo(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    sqlx::query("DELETE FROM todos WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({ "status": "ok" })))
}

async fn notify(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<NotifyPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("admin")?;

    if !state.config.bot_token.is_empty() && !state.config.chat_id.is_empty() {
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            state.config.bot_token
        );
        let client = reqwest::Client::new();
        let _ = client
            .post(&url)
            .json(&json!({
                "chat_id": state.config.chat_id,
                "text": payload.message
            }))
            .send()
            .await;
    }

    Ok(Json(json!({ "status": "ok" })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct PinnedPort {
    pub id: i64,
    pub port: i64,
    pub service_name: Option<String>,
    pub command: Option<String>,
}

#[derive(Deserialize)]
pub struct AddPinnedPortPayload {
    pub port: i64,
    pub service_name: Option<String>,
    pub command: Option<String>,
}

async fn list_pinned_ports(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("viewer")?;

    let ports = sqlx::query_as::<_, PinnedPort>(
        "SELECT id, port, service_name, command FROM pinned_ports ORDER BY port ASC",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    Ok(Json(json!({ "ports": ports })))
}

async fn add_pinned_port(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<AddPinnedPortPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    let _ = sqlx::query(
        "INSERT INTO pinned_ports (port, service_name, command) VALUES (?, ?, ?) ON CONFLICT(port) DO UPDATE SET service_name = excluded.service_name, command = excluded.command",
    )
    .bind(payload.port)
    .bind(payload.service_name)
    .bind(payload.command)
    .execute(&state.db)
    .await;

    Ok(Json(json!({ "status": "ok" })))
}

async fn remove_pinned_port(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(port): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    let _ = sqlx::query("DELETE FROM pinned_ports WHERE port = ?")
        .bind(port)
        .execute(&state.db)
        .await;

    Ok(Json(json!({ "status": "ok" })))
}

async fn list_ssh_keys(auth: AuthUser) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("viewer")?;
    Ok(Json(json!({ "keys": [] })))
}

async fn create_ssh_key(auth: AuthUser, Json(_payload): Json<serde_json::Value>) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("admin")?;
    Ok(Json(json!({ "status": "ok" })))
}

async fn delete_ssh_key(auth: AuthUser, Path(_id): Path<String>) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("admin")?;
    Ok(Json(json!({ "status": "ok" })))
}

async fn list_cloudflared_routes(auth: AuthUser) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("viewer")?;
    Ok(Json(json!({
        "routes": [],
        "tunnel_running": false
    })))
}

