use crate::db::users::{
    create_user, delete_session, get_user, now_timestamp_f64, save_session,
    update_last_login, verify_password, User,
};
use crate::error::AppError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
    Json, Router,
};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize)]
pub struct LoginPayload {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct CreateUserPayload {
    pub username: String,
    pub password: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct UpdateUserRolePayload {
    pub role: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordPayload {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct UserPublicInfo {
    pub username: String,
    pub role: String,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/status", get(auth_status))
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/logout", post(logout))
        .route("/me", get(get_me))
        .route("/change-password", post(change_password))
        .route("/users", get(list_users).post(create_user_admin))
        .route("/users/:username/role", patch(update_user_role))
        .route("/users/:username", axum::routing::delete(delete_user_admin))
}

async fn auth_status(State(state): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await?;

    Ok(Json(json!({
        "needs_setup": count.0 == 0
    })))
}

async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginPayload>,
) -> Result<Response, AppError> {
    let username = payload.username.trim();
    let user = get_user(&state.db, username).await?;

    let user = match user {
        Some(u) => u,
        None => return Err(AppError::Unauthorized("Invalid username or password".to_string())),
    };

    if !verify_password(
        &payload.password,
        &user.password_hash,
        &user.salt,
        state.config.password_iterations,
    ) {
        return Err(AppError::Unauthorized("Invalid username or password".to_string()));
    }

    let _ = update_last_login(&state.db, username).await;

    // Generate random 32-char token
    let token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let expires_at = now_timestamp_f64() + (state.config.session_timeout_seconds as f64);
    save_session(&state.db, &token, username, &user.role, expires_at).await?;

    // Create Set-Cookie header
    let cookie_value = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        state.config.session_cookie_name, token, state.config.session_timeout_seconds
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie_value).map_err(|e| AppError::Internal(e.to_string()))?,
    );

    let body = Json(json!({
        "status": "ok",
        "username": username,
        "role": user.role
    }));

    Ok((headers, body).into_response())
}

async fn register(
    State(state): State<AppState>,
    Json(payload): Json<LoginPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    let username = payload.username.trim();
    if username.len() < 3 || username.len() > 64 {
        return Err(AppError::BadRequest(
            "Username must be 3-64 chars".to_string(),
        ));
    }

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await?;

    if count.0 > 0 {
        return Err(AppError::BadRequest(
            "Registration is disabled after initial setup".to_string(),
        ));
    }

    create_user(
        &state.db,
        username,
        &payload.password,
        "admin",
        state.config.password_iterations,
    )
    .await?;

    Ok(Json(json!({ "status": "ok" })))
}

async fn logout(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Response, AppError> {
    delete_session(&state.db, &auth.token).await?;

    let cookie_value = format!(
        "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        state.config.session_cookie_name
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie_value).map_err(|e| AppError::Internal(e.to_string()))?,
    );

    let body = Json(json!({ "status": "ok" }));
    Ok((headers, body).into_response())
}

async fn get_me(auth: AuthUser) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(json!({
        "username": auth.username,
        "role": auth.role,
        "session_id": auth.token
    })))
}

async fn change_password(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<ChangePasswordPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user = get_user(&state.db, &auth.username)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    if !verify_password(
        &payload.old_password,
        &user.password_hash,
        &user.salt,
        state.config.password_iterations,
    ) {
        return Err(AppError::BadRequest("Invalid old password".to_string()));
    }

    let (new_hash, new_salt) = crate::db::users::hash_password(
        &payload.new_password,
        None,
        state.config.password_iterations,
    );

    sqlx::query("UPDATE users SET password_hash = ?, salt = ? WHERE username = ?")
        .bind(new_hash)
        .bind(new_salt)
        .bind(&auth.username)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({ "status": "ok" })))
}

async fn list_users(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<UserPublicInfo>>, AppError> {
    auth.require_role("admin")?;

    let users = sqlx::query_as::<_, User>(
        "SELECT username, password_hash, salt, role, created_at, last_login_at FROM users ORDER BY created_at ASC",
    )
    .fetch_all(&state.db)
    .await?;

    let result = users
        .into_iter()
        .map(|u| UserPublicInfo {
            username: u.username,
            role: u.role,
            created_at: u.created_at,
            last_login_at: u.last_login_at,
        })
        .collect();

    Ok(Json(result))
}

async fn create_user_admin(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<CreateUserPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("admin")?;

    let username = payload.username.trim();
    if username.len() < 3 || username.len() > 64 {
        return Err(AppError::BadRequest(
            "Username must be 3-64 chars".to_string(),
        ));
    }

    if get_user(&state.db, username).await?.is_some() {
        return Err(AppError::BadRequest("User already exists".to_string()));
    }

    if !["admin", "operator", "viewer"].contains(&payload.role.as_str()) {
        return Err(AppError::BadRequest("Invalid role".to_string()));
    }

    create_user(
        &state.db,
        username,
        &payload.password,
        &payload.role,
        state.config.password_iterations,
    )
    .await?;

    Ok(Json(json!({ "status": "ok" })))
}

async fn update_user_role(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(username): Path<String>,
    Json(payload): Json<UpdateUserRolePayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("admin")?;

    if username == auth.username {
        return Err(AppError::BadRequest(
            "Cannot change your own role".to_string(),
        ));
    }

    if !["admin", "operator", "viewer"].contains(&payload.role.as_str()) {
        return Err(AppError::BadRequest("Invalid role".to_string()));
    }

    sqlx::query("UPDATE users SET role = ? WHERE username = ?")
        .bind(&payload.role)
        .bind(&username)
        .execute(&state.db)
        .await?;

    // Invalidate sessions for that user
    sqlx::query("DELETE FROM sessions WHERE username = ?")
        .bind(&username)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({ "status": "ok" })))
}

async fn delete_user_admin(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(username): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("admin")?;

    if username == auth.username {
        return Err(AppError::BadRequest(
            "Cannot delete yourself".to_string(),
        ));
    }

    sqlx::query("DELETE FROM users WHERE username = ?")
        .bind(&username)
        .execute(&state.db)
        .await?;

    sqlx::query("DELETE FROM sessions WHERE username = ?")
        .bind(&username)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({ "status": "ok" })))
}
