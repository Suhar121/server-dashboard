use crate::error::AppError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;
use axum::{
    extract::Query,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::process::Command;

#[derive(Deserialize)]
pub struct DockerActionPayload {
    pub container_id: String,
    pub action: String,
}

#[derive(Deserialize)]
pub struct DockerLogsQuery {
    pub container_id: String,
    pub tail: Option<u32>,
}

#[derive(Serialize)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub ports: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_containers))
        .route("/containers", get(list_containers))
        .route("/action", post(docker_action))
        .route("/logs", get(get_logs))
        .route("/logs/:id", get(get_logs_by_id))
}

async fn get_logs_by_id(
    auth: AuthUser,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("viewer")?;

    let output = Command::new("docker")
        .args(["logs", "--tail", "200", &id])
        .output()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to retrieve docker logs: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let logs = format!("{}{}", stdout, stderr);

    Ok(Json(json!({
        "container_id": id,
        "logs": logs
    })))
}

async fn list_containers(auth: AuthUser) -> Result<Json<Vec<ContainerInfo>>, AppError> {
    auth.require_role("viewer")?;

    let output = Command::new("docker")
        .args([
            "ps",
            "-a",
            "--format",
            "{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|{{.Status}}|{{.Ports}}",
        ])
        .output()
        .await;

    let output = match output {
        Ok(out) => out,
        Err(_) => {
            // Docker may not be installed or daemon not running
            return Ok(Json(Vec::new()));
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut containers = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 6 {
            containers.push(ContainerInfo {
                id: parts[0].to_string(),
                name: parts[1].to_string(),
                image: parts[2].to_string(),
                state: parts[3].to_string(),
                status: parts[4].to_string(),
                ports: parts[5].to_string(),
            });
        }
    }

    Ok(Json(containers))
}

async fn docker_action(
    auth: AuthUser,
    Json(payload): Json<DockerActionPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    let action = payload.action.to_lowercase();
    if !["start", "stop", "restart", "pause", "unpause"].contains(&action.as_str()) {
        return Err(AppError::BadRequest("Invalid Docker action".to_string()));
    }

    let output = Command::new("docker")
        .arg(&action)
        .arg(&payload.container_id)
        .output()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to execute docker command: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(stderr.to_string()));
    }

    Ok(Json(json!({
        "status": "ok",
        "action": action,
        "container_id": payload.container_id
    })))
}

async fn get_logs(
    auth: AuthUser,
    Query(query): Query<DockerLogsQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("viewer")?;

    let tail_str = query.tail.unwrap_or(100).to_string();

    let output = Command::new("docker")
        .args(["logs", "--tail", &tail_str, &query.container_id])
        .output()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to retrieve docker logs: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let logs = format!("{}{}", stdout, stderr);

    Ok(Json(json!({
        "container_id": query.container_id,
        "logs": logs
    })))
}
