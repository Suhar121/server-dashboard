use axum::{
    extract::Path,
    http::{header, StatusCode},
    response::IntoResponse,
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../frontend/"]
pub struct FrontendAssets;

pub async fn serve_index() -> impl IntoResponse {
    // Priority 1: Check disk if running in development
    if let Ok(content) = tokio::fs::read_to_string("../frontend/index.html").await {
        return (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            content,
        )
            .into_response();
    }
    if let Ok(content) = tokio::fs::read_to_string("frontend/index.html").await {
        return (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            content,
        )
            .into_response();
    }

    // Priority 2: Serve embedded asset from binary
    match FrontendAssets::get("index.html") {
        Some(file) => {
            let mime = "text/html; charset=utf-8";
            ([(header::CONTENT_TYPE, mime)], file.data).into_response()
        }
        None => (StatusCode::NOT_FOUND, "index.html not found").into_response(),
    }
}

pub async fn serve_status() -> impl IntoResponse {
    // Priority 1: Check disk if running in development
    if let Ok(content) = tokio::fs::read_to_string("../frontend/status.html").await {
        return (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            content,
        )
            .into_response();
    }
    if let Ok(content) = tokio::fs::read_to_string("frontend/status.html").await {
        return (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            content,
        )
            .into_response();
    }

    // Priority 2: Serve embedded asset from binary
    match FrontendAssets::get("status.html") {
        Some(file) => {
            let mime = "text/html; charset=utf-8";
            ([(header::CONTENT_TYPE, mime)], file.data).into_response()
        }
        None => (StatusCode::NOT_FOUND, "status.html not found").into_response(),
    }
}

pub async fn serve_logo() -> impl IntoResponse {
    // Priority 1: Check disk
    if let Ok(bytes) = tokio::fs::read("../frontend/gridcore.jpg").await {
        return ([(header::CONTENT_TYPE, "image/jpeg")], bytes).into_response();
    }
    if let Ok(bytes) = tokio::fs::read("frontend/gridcore.jpg").await {
        return ([(header::CONTENT_TYPE, "image/jpeg")], bytes).into_response();
    }

    // Priority 2: Serve embedded
    match FrontendAssets::get("gridcore.jpg") {
        Some(file) => ([(header::CONTENT_TYPE, "image/jpeg")], file.data).into_response(),
        None => (StatusCode::NOT_FOUND, "Logo not found").into_response(),
    }
}

pub async fn serve_static(Path(path): Path<String>) -> impl IntoResponse {
    let disk_path = format!("../frontend/static/{}", path);
    if let Ok(bytes) = tokio::fs::read(&disk_path).await {
        let mime = mime_guess::from_path(&path)
            .first_or_octet_stream()
            .to_string();
        return ([(header::CONTENT_TYPE, mime)], bytes).into_response();
    }

    let asset_path = format!("static/{}", path);
    match FrontendAssets::get(&asset_path) {
        Some(file) => {
            let mime = mime_guess::from_path(&path)
                .first_or_octet_stream()
                .to_string();
            ([(header::CONTENT_TYPE, mime)], file.data).into_response()
        }
        None => (StatusCode::NOT_FOUND, "Asset not found").into_response(),
    }
}
