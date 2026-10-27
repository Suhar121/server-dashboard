use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    BadRequest(String),
    Internal(String),
    Sqlx(sqlx::Error),
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::Sqlx(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AppError::Sqlx(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", err),
            ),
        };

        let body = Json(json!({
            "detail": message,
            "error": message
        }));

        (status, body).into_response()
    }
}
