use crate::db::users::{get_session, Session};
use crate::error::AppError;
use crate::state::AppState;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub username: String,
    pub role: String,
    pub token: String,
}

impl AuthUser {
    pub fn role_level(&self) -> u8 {
        match self.role.as_str() {
            "admin" => 3,
            "operator" => 2,
            "viewer" => 1,
            _ => 0,
        }
    }

    pub fn require_role(&self, min_role: &str) -> Result<(), AppError> {
        let min_level = match min_role {
            "admin" => 3,
            "operator" => 2,
            "viewer" => 1,
            _ => 0,
        };

        if self.role_level() < min_level {
            return Err(AppError::Forbidden(format!(
                "{} role required",
                min_role
            )));
        }
        Ok(())
    }
}

// Axum extractor to inject AuthUser into handlers automatically
#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let cookie_header = parts
            .headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();

        let mut session_token = None;
        for item in cookie_header.split(';') {
            let item = item.trim();
            if let Some((k, v)) = item.split_once('=') {
                if k == app_state.config.session_cookie_name {
                    session_token = Some(v.to_string());
                    break;
                }
            }
        }

        let token = session_token
            .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?;

        let session: Option<Session> = get_session(&app_state.db, &token)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let session = session
            .ok_or_else(|| AppError::Unauthorized("Session expired or invalid".to_string()))?;

        Ok(AuthUser {
            username: session.username,
            role: session.role,
            token,
        })
    }
}
