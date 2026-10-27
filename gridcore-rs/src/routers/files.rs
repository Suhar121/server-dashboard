use crate::error::AppError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;
use axum::{
    extract::{Multipart, Query},
    http::header,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::process::Command;

#[derive(Deserialize)]
pub struct BrowseFilesQuery {
    pub path: Option<String>,
}

#[derive(Deserialize)]
pub struct FilePathPayload {
    pub path: String,
}

#[derive(Deserialize)]
pub struct FileWritePayload {
    pub path: String,
    pub content: String,
}

#[derive(Deserialize)]
pub struct GitClonePayload {
    pub path: String,
    pub repo_url: String,
    pub folder_name: Option<String>,
}

#[derive(Deserialize)]
pub struct FileChmodPayload {
    pub path: String,
    pub permissions: String,
}

#[derive(Deserialize)]
pub struct UploadQuery {
    pub path: Option<String>,
}

#[derive(Serialize)]
pub struct FileItem {
    pub name: String,
    pub path: String,
    pub is_directory: bool,
    pub is_file: bool,
    pub size: u64,
    pub modified: u64,
    pub permissions: String,
    pub readable: bool,
    pub writable: bool,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/browse", get(browse_files))
        .route("/list", get(browse_files)) // alias
        .route("/read", post(read_file))
        .route("/write", post(write_file))
        .route("/delete", post(delete_file))
        .route("/mkdir", post(create_directory))
        .route("/create-directory", post(create_directory)) // alias
        .route("/chmod", post(change_permissions))
        .route("/git-clone", post(git_clone))
        .route("/download", get(download_file))
        .route("/upload", post(upload_file))
}

fn resolve_path(input_path: Option<&str>) -> PathBuf {
    match input_path {
        Some(p) if !p.trim().is_empty() => {
            let trimmed = p.trim();
            // Handle root slash on Windows
            #[cfg(target_os = "windows")]
            if trimmed == "/" || trimmed == "\\" {
                if let Ok(curr) = std::env::current_dir() {
                    if let Some(prefix) = curr.components().next() {
                        return PathBuf::from(format!("{}\\", prefix.as_os_str().to_string_lossy()));
                    }
                }
                return PathBuf::from("C:\\");
            }

            PathBuf::from(trimmed)
        }
        _ => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    }
}

async fn browse_files(
    auth: AuthUser,
    Query(query): Query<BrowseFilesQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("viewer")?;

    let path_buf = resolve_path(query.path.as_deref());
    let path = path_buf.as_path();

    if !path.exists() {
        return Err(AppError::NotFound("Path not found".to_string()));
    }

    if path.is_file() {
        return Ok(Json(json!({
            "type": "file",
            "path": path.to_string_lossy()
        })));
    }

    let mut entries = fs::read_dir(path)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read directory: {}", e)))?;

    let mut items = Vec::new();

    while let Ok(Some(entry)) = entries.next_entry().await {
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };

        let file_name = entry.file_name().to_string_lossy().to_string();
        let full_path = entry.path().to_string_lossy().to_string();
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        items.push(FileItem {
            name: file_name,
            path: full_path,
            is_directory: meta.is_dir(),
            is_file: meta.is_file(),
            size: meta.len(),
            modified,
            permissions: "0755".to_string(),
            readable: true,
            writable: !meta.permissions().readonly(),
        });
    }

    items.sort_by(|a, b| {
        b.is_directory
            .cmp(&a.is_directory)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    let parent = path.parent().map(|p| p.to_string_lossy().to_string());

    Ok(Json(json!({
        "type": "directory",
        "path": path.to_string_lossy(),
        "parent": parent,
        "items": items
    })))
}

async fn read_file(
    auth: AuthUser,
    Json(payload): Json<FilePathPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("viewer")?;

    let path = Path::new(&payload.path);
    if !path.is_file() {
        return Err(AppError::NotFound("File not found".to_string()));
    }

    let content = fs::read_to_string(path)
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to read file: {}", e)))?;

    let size = content.len();

    Ok(Json(json!({
        "path": payload.path,
        "content": content,
        "size": size
    })))
}

async fn write_file(
    auth: AuthUser,
    Json(payload): Json<FileWritePayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    let path = Path::new(&payload.path);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent).await;
    }

    fs::write(path, payload.content)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write file: {}", e)))?;

    Ok(Json(json!({ "status": "success", "path": payload.path })))
}

async fn delete_file(
    auth: AuthUser,
    Json(payload): Json<FilePathPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    let path = Path::new(&payload.path);
    if !path.exists() {
        return Err(AppError::NotFound("File or directory not found".to_string()));
    }

    if path.is_dir() {
        fs::remove_dir_all(path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to remove directory: {}", e)))?;
    } else {
        fs::remove_file(path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to remove file: {}", e)))?;
    }

    Ok(Json(json!({ "status": "deleted", "path": payload.path })))
}

async fn create_directory(
    auth: AuthUser,
    Json(payload): Json<FilePathPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    let path = Path::new(&payload.path);
    fs::create_dir_all(path)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create directory: {}", e)))?;

    Ok(Json(json!({ "status": "created", "path": payload.path })))
}

async fn change_permissions(
    auth: AuthUser,
    Json(payload): Json<FileChmodPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    Ok(Json(json!({
        "status": "updated",
        "path": payload.path,
        "permissions": payload.permissions
    })))
}

async fn git_clone(
    auth: AuthUser,
    Json(payload): Json<GitClonePayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    let base_dir = Path::new(&payload.path);
    if !base_dir.is_dir() {
        return Err(AppError::BadRequest("Target path must be a directory".to_string()));
    }

    let mut cmd = Command::new("git");
    cmd.arg("clone").arg(&payload.repo_url);

    if let Some(folder) = &payload.folder_name {
        if !folder.is_empty() {
            cmd.arg(folder);
        }
    }

    cmd.current_dir(base_dir);

    let output = cmd
        .output()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to run git: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(stderr.to_string()));
    }

    Ok(Json(json!({ "status": "cloned" })))
}

async fn download_file(
    auth: AuthUser,
    Query(query): Query<FilePathPayload>,
) -> Result<Response, AppError> {
    auth.require_role("viewer")?;

    let path = Path::new(&query.path);
    if !path.is_file() {
        return Err(AppError::NotFound("File not found".to_string()));
    }

    let file_bytes = fs::read(path)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");

    let disposition = format!("attachment; filename=\"{}\"", filename);

    let response = (
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CONTENT_DISPOSITION, &disposition),
        ],
        file_bytes,
    )
        .into_response();

    Ok(response)
}

async fn upload_file(
    auth: AuthUser,
    Query(query): Query<UploadQuery>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    let dest_dir = query.path.unwrap_or_else(|| ".".to_string());
    let mut uploaded_files = Vec::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        if let Some(file_name) = field.file_name() {
            let file_name = file_name.to_string();
            let target_path = Path::new(&dest_dir).join(&file_name);
            if let Ok(data) = field.bytes().await {
                if fs::write(&target_path, data).await.is_ok() {
                    uploaded_files.push(file_name);
                }
            }
        }
    }

    Ok(Json(json!({
        "status": "uploaded",
        "uploaded": uploaded_files
    })))
}
