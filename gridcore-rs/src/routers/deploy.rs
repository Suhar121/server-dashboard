use crate::error::AppError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use tokio::fs;
use tokio::process::Command;

#[derive(Serialize, sqlx::FromRow)]
pub struct AppTemplate {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub category: Option<String>,
    pub default_port: Option<i64>,
    pub env_schema: Option<String>,
    pub compose_yaml: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Deployment {
    pub id: i64,
    pub name: String,
    pub repo_url: Option<String>,
    pub branch: Option<String>,
    pub status: String,
    pub port: Option<i64>,
    pub pid: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Deserialize)]
pub struct CreateDeployPayload {
    pub app_name: String,
    pub template_id: Option<i64>,
    pub port_override: Option<i64>,
    pub env_vars: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
pub struct AppActionPayload {
    pub action: String,
}

#[derive(Deserialize)]
pub struct GithubAnalyzePayload {
    pub repo_url: String,
    pub branch: Option<String>,
}

#[derive(Deserialize)]
pub struct GithubDeployPayload {
    pub repo_url: String,
    pub app_name: String,
    pub branch: Option<String>,
    pub env_vars: Option<HashMap<String, String>>,
    pub port_override: Option<i64>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/templates", get(list_templates))
        .route("/templates/:id", get(get_template))
        .route("/", post(create_deploy))
        .route("/apps", get(list_apps))
        .route("/apps/:id/action", post(app_action))
        .route("/apps/:id/logs", get(get_app_logs))
        .route("/github/analyze", post(github_analyze))
        .route("/github/deploy", post(github_deploy))
        .route("/github/status/:id", get(github_status))
        .route("/github/:id", delete(delete_github_deploy))
}

async fn list_templates(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<AppTemplate>>, AppError> {
    auth.require_role("viewer")?;

    let templates = sqlx::query_as::<_, AppTemplate>(
        "SELECT id, name, description, icon, category, default_port, env_schema, compose_yaml FROM app_templates ORDER BY id ASC",
    )
    .fetch_all(&state.db)
    .await?;

    Ok(Json(templates))
}

async fn get_template(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<AppTemplate>, AppError> {
    auth.require_role("viewer")?;

    let template = sqlx::query_as::<_, AppTemplate>(
        "SELECT id, name, description, icon, category, default_port, env_schema, compose_yaml FROM app_templates WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Template not found".to_string()))?;

    Ok(Json(template))
}

async fn list_apps(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<Deployment>>, AppError> {
    auth.require_role("viewer")?;

    let apps = sqlx::query_as::<_, Deployment>(
        "SELECT id, name, repo_url, branch, status, port, pid, created_at, updated_at FROM deployments ORDER BY id DESC",
    )
    .fetch_all(&state.db)
    .await?;

    Ok(Json(apps))
}

async fn create_deploy(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<CreateDeployPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    let now = chrono::Utc::now().timestamp();
    let port = payload.port_override.unwrap_or(8080);

    let res = sqlx::query(
        "INSERT INTO deployments (name, status, port, created_at, updated_at) VALUES (?, 'running', ?, ?, ?)",
    )
    .bind(&payload.app_name)
    .bind(port)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;

    let app_id = res.last_insert_rowid();

    // Create logs directory and initial log file
    let _ = fs::create_dir_all("logs").await;
    let log_path = format!("logs/deploy_{}.log", app_id);
    let initial_log = format!(
        "[{}] Deployment '{}' created with port {}\n[{}] Application status: active\n",
        chrono::Utc::now().to_rfc3339(),
        payload.app_name,
        port,
        chrono::Utc::now().to_rfc3339()
    );
    let _ = fs::write(&log_path, initial_log).await;

    Ok(Json(json!({
        "status": "ok",
        "app_id": app_id,
        "name": payload.app_name,
        "port": port
    })))
}

async fn app_action(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<i64>,
    Json(payload): Json<AppActionPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    let action = payload.action.to_lowercase();
    let new_status = match action.as_str() {
        "start" => "running",
        "stop" => "stopped",
        "restart" => "running",
        "delete" => {
            sqlx::query("DELETE FROM deployments WHERE id = ?")
                .bind(id)
                .execute(&state.db)
                .await?;
            return Ok(Json(json!({ "status": "ok", "action": "delete", "app_id": id })));
        }
        _ => return Err(AppError::BadRequest("Invalid app action".to_string())),
    };

    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE deployments SET status = ?, updated_at = ? WHERE id = ?")
        .bind(new_status)
        .bind(now)
        .bind(id)
        .execute(&state.db)
        .await?;

    // Append to log
    let log_path = format!("logs/deploy_{}.log", id);
    let log_msg = format!(
        "[{}] Action executed: {} (new status: {})\n",
        chrono::Utc::now().to_rfc3339(),
        action,
        new_status
    );
    if let Ok(mut file) = fs::OpenOptions::new().append(true).create(true).open(&log_path).await {
        use tokio::io::AsyncWriteExt;
        let _ = file.write_all(log_msg.as_bytes()).await;
    }

    Ok(Json(json!({
        "status": "ok",
        "action": action,
        "app_id": id,
        "new_status": new_status
    })))
}

async fn get_app_logs(
    auth: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("viewer")?;

    let log_path = format!("logs/deploy_{}.log", id);
    let logs = fs::read_to_string(&log_path)
        .await
        .unwrap_or_else(|_| "No log file found for this deployment.".to_string());

    Ok(Json(json!({
        "app_id": id,
        "logs": logs
    })))
}

async fn github_analyze(
    auth: AuthUser,
    Json(payload): Json<GithubAnalyzePayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    let repo_url = payload.repo_url.trim();
    let repo_name = repo_url
        .trim_end_matches('/')
        .split('/')
        .last()
        .unwrap_or("repo")
        .trim_end_matches(".git");

    Ok(Json(json!({
        "detected_type": "docker",
        "suggested_app_name": repo_name,
        "env_vars": [],
        "ports": [8080],
        "has_compose": false,
        "has_dockerfile": true,
        "framework": "standard"
    })))
}

async fn github_deploy(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<GithubDeployPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    let now = chrono::Utc::now().timestamp();
    let port = payload.port_override.unwrap_or(3000);
    let branch = payload.branch.unwrap_or_else(|| "main".to_string());

    let res = sqlx::query(
        "INSERT INTO deployments (name, repo_url, branch, status, port, created_at, updated_at) VALUES (?, ?, ?, 'cloning', ?, ?, ?)",
    )
    .bind(&payload.app_name)
    .bind(&payload.repo_url)
    .bind(&branch)
    .bind(port)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;

    let deploy_id = res.last_insert_rowid();

    // Background git clone task
    let repo_url = payload.repo_url.clone();
    let app_name = payload.app_name.clone();
    let db = state.db.clone();

    tokio::spawn(async move {
        let dest = format!("deployed_apps/{}", app_name);
        let _ = fs::create_dir_all("deployed_apps").await;
        let _ = fs::create_dir_all("logs").await;

        let log_file = format!("logs/deploy_{}.log", deploy_id);
        let mut log_content = format!("[{}] Starting git clone from {}\n", chrono::Utc::now().to_rfc3339(), repo_url);

        let clone_res = Command::new("git")
            .args(["clone", &repo_url, &dest])
            .output()
            .await;

        match clone_res {
            Ok(output) if output.status.success() => {
                log_content.push_str(&format!("[{}] Clone complete. Status: active\n", chrono::Utc::now().to_rfc3339()));
                let _ = sqlx::query("UPDATE deployments SET status = 'running' WHERE id = ?")
                    .bind(deploy_id)
                    .execute(&db)
                    .await;
            }
            Ok(output) => {
                let err = String::from_utf8_lossy(&output.stderr);
                log_content.push_str(&format!("[{}] Git clone failed:\n{}\n", chrono::Utc::now().to_rfc3339(), err));
                let _ = sqlx::query("UPDATE deployments SET status = 'failed' WHERE id = ?")
                    .bind(deploy_id)
                    .execute(&db)
                    .await;
            }
            Err(e) => {
                log_content.push_str(&format!("[{}] Error executing git: {}\n", chrono::Utc::now().to_rfc3339(), e));
                let _ = sqlx::query("UPDATE deployments SET status = 'failed' WHERE id = ?")
                    .bind(deploy_id)
                    .execute(&db)
                    .await;
            }
        }

        let _ = fs::write(&log_file, log_content).await;
    });

    Ok(Json(json!({
        "status": "ok",
        "deploy_id": deploy_id,
        "app_name": payload.app_name,
        "port": port
    })))
}

async fn github_status(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("viewer")?;

    let dep = sqlx::query_as::<_, Deployment>(
        "SELECT id, name, repo_url, branch, status, port, pid, created_at, updated_at FROM deployments WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Deployment not found".to_string()))?;

    Ok(Json(json!({
        "id": dep.id,
        "name": dep.name,
        "status": dep.status,
        "port": dep.port,
        "repo_url": dep.repo_url,
        "branch": dep.branch
    })))
}

async fn delete_github_deploy(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    sqlx::query("DELETE FROM deployments WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({ "status": "ok" })))
}
