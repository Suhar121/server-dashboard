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

#[derive(Serialize, sqlx::FromRow)]
pub struct Monitor {
    pub id: i64,
    pub name: String,
    pub r#type: String,
    pub target: String,
    pub interval: i64,
    pub status: String,
    pub latency: Option<f64>,
    pub uptime_pct: Option<f64>,
    pub created_at: i64,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Heartbeat {
    pub id: i64,
    pub monitor_id: i64,
    pub status: String,
    pub latency: Option<f64>,
    pub timestamp: i64,
}

#[derive(Deserialize)]
pub struct CreateMonitorPayload {
    pub name: String,
    pub r#type: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    pub interval: Option<i64>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/monitors", get(list_monitors).post(create_monitor))
        .route("/monitors/:id", get(get_monitor).put(update_monitor).delete(delete_monitor))
        .route("/monitors/:id/heartbeats", get(get_monitor_heartbeats))
        .route("/monitors/:id/clear", post(clear_monitor_history))
        .route("/monitors/:id/pause", post(pause_monitor))
        .route("/settings/telegram/test", post(test_telegram))
        .route("/status-pages", get(list_status_pages))
        .route("/status-page", get(get_default_status_page).post(save_status_page))
        .route("/status-page/:slug", get(get_status_page_by_slug).delete(delete_status_page))
        .route("/status-page/incident", post(post_status_incident))
        .route("/status-page/incident/:id", delete(delete_status_incident))
        .route("/system/drives", get(get_system_drives))
}

async fn get_system_drives(auth: AuthUser) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    auth.require_role("viewer")?;

    let disks = sysinfo::Disks::new_with_refreshed_list();
    let mut result = Vec::new();

    for d in disks.list() {
        let total = d.total_space();
        let free = d.available_space();
        let used = total.saturating_sub(free);
        let pct = if total > 0 {
            ((used as f64) / (total as f64)) * 100.0
        } else {
            0.0
        };

        result.push(json!({
            "device": d.name().to_string_lossy(),
            "mountpoint": d.mount_point().to_string_lossy(),
            "total": total,
            "used": used,
            "free": free,
            "percent": (pct * 10.0).round() / 10.0
        }));
    }

    Ok(Json(result))
}

async fn list_monitors(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    auth.require_role("viewer")?;

    let monitors = sqlx::query_as::<_, Monitor>(
        "SELECT id, name, type, target, interval, status, latency, uptime_pct, created_at FROM monitors ORDER BY id ASC",
    )
    .fetch_all(&state.db)
    .await?;

    let mut result = Vec::new();
    for m in monitors {
        let heartbeats = sqlx::query_as::<_, Heartbeat>(
            "SELECT id, monitor_id, status, latency, timestamp FROM heartbeats WHERE monitor_id = ? ORDER BY timestamp DESC LIMIT 36",
        )
        .bind(m.id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        let url = if m.r#type == "http" || m.r#type == "port" {
            m.target.clone()
        } else {
            String::new()
        };

        result.push(json!({
            "id": m.id,
            "name": m.name,
            "type": m.r#type,
            "target": m.target,
            "url": url,
            "interval": m.interval,
            "status": m.status,
            "latency": m.latency.unwrap_or(0.0),
            "uptime_pct": m.uptime_pct.unwrap_or(100.0),
            "heartbeats": heartbeats,
            "created_at": m.created_at
        }));
    }

    Ok(Json(result))
}

async fn get_monitor(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("viewer")?;

    let m = sqlx::query_as::<_, Monitor>(
        "SELECT id, name, type, target, interval, status, latency, uptime_pct, created_at FROM monitors WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Monitor not found".to_string()))?;

    let heartbeats = sqlx::query_as::<_, Heartbeat>(
        "SELECT id, monitor_id, status, latency, timestamp FROM heartbeats WHERE monitor_id = ? ORDER BY timestamp DESC LIMIT 36",
    )
    .bind(m.id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let url = if m.r#type == "http" || m.r#type == "port" {
        m.target.clone()
    } else {
        String::new()
    };

    Ok(Json(json!({
        "id": m.id,
        "name": m.name,
        "type": m.r#type,
        "target": m.target,
        "url": url,
        "interval": m.interval,
        "status": m.status,
        "latency": m.latency.unwrap_or(0.0),
        "uptime_pct": m.uptime_pct.unwrap_or(100.0),
        "heartbeats": heartbeats,
        "created_at": m.created_at
    })))
}

async fn get_monitor_heartbeats(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<Vec<Heartbeat>>, AppError> {
    auth.require_role("viewer")?;

    let heartbeats = sqlx::query_as::<_, Heartbeat>(
        "SELECT id, monitor_id, status, latency, timestamp FROM heartbeats WHERE monitor_id = ? ORDER BY timestamp DESC LIMIT 60",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(heartbeats))
}

async fn clear_monitor_history(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    sqlx::query("DELETE FROM heartbeats WHERE monitor_id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({ "status": "ok" })))
}

async fn pause_monitor(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    sqlx::query("UPDATE monitors SET status = 'paused' WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({ "status": "ok", "status": "paused" })))
}

async fn create_monitor(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<CreateMonitorPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    let now = chrono::Utc::now().timestamp();
    let interval = payload.interval.unwrap_or(60);
    let target = payload
        .target
        .filter(|s| !s.trim().is_empty())
        .or_else(|| payload.url.filter(|s| !s.trim().is_empty()))
        .unwrap_or_default();

    let res = sqlx::query(
        "INSERT INTO monitors (name, type, target, interval, status, latency, uptime_pct, created_at) VALUES (?, ?, ?, ?, 'up', 0.0, 100.0, ?)",
    )
    .bind(&payload.name)
    .bind(&payload.r#type)
    .bind(&target)
    .bind(interval)
    .bind(now)
    .execute(&state.db)
    .await?;

    let url = if payload.r#type == "http" || payload.r#type == "port" {
        target.clone()
    } else {
        String::new()
    };

    Ok(Json(json!({
        "id": res.last_insert_rowid(),
        "name": payload.name,
        "type": payload.r#type,
        "target": target,
        "url": url,
        "interval": interval,
        "status": "up",
        "latency": 0.0,
        "uptime_pct": 100.0,
        "heartbeats": [],
        "created_at": now
    })))
}

async fn update_monitor(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<i64>,
    Json(payload): Json<CreateMonitorPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    let interval = payload.interval.unwrap_or(60);
    let target = payload
        .target
        .filter(|s| !s.trim().is_empty())
        .or_else(|| payload.url.filter(|s| !s.trim().is_empty()))
        .unwrap_or_default();

    sqlx::query(
        "UPDATE monitors SET name = ?, type = ?, target = ?, interval = ? WHERE id = ?",
    )
    .bind(&payload.name)
    .bind(&payload.r#type)
    .bind(&target)
    .bind(interval)
    .bind(id)
    .execute(&state.db)
    .await?;

    let m = sqlx::query_as::<_, Monitor>(
        "SELECT id, name, type, target, interval, status, latency, uptime_pct, created_at FROM monitors WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Monitor not found".to_string()))?;

    let heartbeats = sqlx::query_as::<_, Heartbeat>(
        "SELECT id, monitor_id, status, latency, timestamp FROM heartbeats WHERE monitor_id = ? ORDER BY timestamp DESC LIMIT 36",
    )
    .bind(m.id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let url = if m.r#type == "http" || m.r#type == "port" {
        m.target.clone()
    } else {
        String::new()
    };

    Ok(Json(json!({
        "id": m.id,
        "name": m.name,
        "type": m.r#type,
        "target": m.target,
        "url": url,
        "interval": m.interval,
        "status": m.status,
        "latency": m.latency.unwrap_or(0.0),
        "uptime_pct": m.uptime_pct.unwrap_or(100.0),
        "heartbeats": heartbeats,
        "created_at": m.created_at
    })))
}

async fn delete_monitor(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("operator")?;

    sqlx::query("DELETE FROM monitors WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;

    sqlx::query("DELETE FROM heartbeats WHERE monitor_id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({ "status": "ok" })))
}

async fn test_telegram(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("admin")?;

    if state.config.bot_token.is_empty() || state.config.chat_id.is_empty() {
        return Err(AppError::BadRequest("Telegram BOT_TOKEN or CHAT_ID not configured".to_string()));
    }

    let url = format!(
        "https://api.telegram.org/bot{}/sendMessage",
        state.config.bot_token
    );
    let client = reqwest::Client::new();
    let res = client
        .post(&url)
        .json(&json!({
            "chat_id": state.config.chat_id,
            "text": "🔔 GridCore Rust: Telegram notification test successful!"
        }))
        .send()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({ "status": "ok", "delivered": res.status().is_success() })))
}

async fn list_status_pages(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    auth.require_role("viewer")?;

    #[derive(sqlx::FromRow)]
    struct StatusPageRow {
        slug: String,
        title: String,
        description: Option<String>,
        footer_text: Option<String>,
        refresh_interval: Option<i64>,
        is_public: Option<i64>,
        groups_json: Option<String>,
    }

    let rows = sqlx::query_as::<_, StatusPageRow>(
        "SELECT slug, title, description, footer_text, refresh_interval, is_public, groups_json FROM status_pages ORDER BY rowid ASC",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let mut list: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            let groups: serde_json::Value = serde_json::from_str(&r.groups_json.unwrap_or_else(|| "[]".into()))
                .unwrap_or_else(|_| json!([]));
            json!({
                "slug": r.slug,
                "title": r.title,
                "description": r.description.unwrap_or_default(),
                "footerText": r.footer_text.unwrap_or_default(),
                "refreshInterval": r.refresh_interval.unwrap_or(300),
                "isPublic": r.is_public.unwrap_or(1) != 0,
                "groups": groups,
            })
        })
        .collect();

    if list.is_empty() {
        list.push(json!({
            "slug": "monitor",
            "title": "System Status",
            "description": "Live uptime & operational health",
            "footerText": "Powered by GridCore",
            "refreshInterval": 300,
            "isPublic": true,
            "groups": []
        }));
    }

    Ok(Json(list))
}

async fn check_optional_auth(state: &AppState, headers: &axum::http::HeaderMap) -> bool {
    let cookie_header = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let mut session_token = None;
    for item in cookie_header.split(';') {
        let item = item.trim();
        if let Some((k, v)) = item.split_once('=') {
            if k == state.config.session_cookie_name {
                session_token = Some(v.to_string());
                break;
            }
        }
    }

    if let Some(token) = session_token {
        if let Ok(Some(_)) = crate::db::users::get_session(&state.db, &token).await {
            return true;
        }
    }
    false
}

async fn resolve_status_page(
    state: &AppState,
    slug: &str,
    is_authenticated: bool,
) -> Result<serde_json::Value, AppError> {
    #[derive(sqlx::FromRow)]
    struct StatusPageRow {
        slug: String,
        title: String,
        description: Option<String>,
        footer_text: Option<String>,
        refresh_interval: Option<i64>,
        is_public: Option<i64>,
        groups_json: Option<String>,
    }

    let row = sqlx::query_as::<_, StatusPageRow>(
        "SELECT slug, title, description, footer_text, refresh_interval, is_public, groups_json FROM status_pages WHERE slug = ?",
    )
    .bind(slug)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let page = match row {
        Some(p) => p,
        None => {
            if slug == "monitor" || slug == "status" || slug == "default" {
                StatusPageRow {
                    slug: slug.to_string(),
                    title: "System Status".to_string(),
                    description: Some("Live service and infrastructure telemetry".to_string()),
                    footer_text: Some("Powered by GridCore".to_string()),
                    refresh_interval: Some(300),
                    is_public: Some(1),
                    groups_json: Some("[]".to_string()),
                }
            } else {
                return Err(AppError::NotFound(format!("Status page '{}' not found", slug)));
            }
        }
    };

    let is_public = page.is_public.unwrap_or(1) != 0;
    if !is_public && !is_authenticated {
        return Ok(json!({
            "slug": page.slug,
            "title": page.title,
            "isPublic": false,
            "isRestricted": true,
            "message": "This status page is private. Please sign in to view."
        }));
    }

    #[derive(sqlx::FromRow)]
    struct IncidentRow {
        id: String,
        title: String,
        content: Option<String>,
        style: Option<String>,
        created_at: String,
    }

    let inc_rows = sqlx::query_as::<_, IncidentRow>(
        "SELECT id, title, content, style, created_at FROM status_page_incidents WHERE status_page_slug = ? ORDER BY created_at DESC",
    )
    .bind(&page.slug)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let incidents: Vec<serde_json::Value> = inc_rows
        .into_iter()
        .map(|i| {
            json!({
                "id": i.id,
                "title": i.title,
                "content": i.content.unwrap_or_default(),
                "style": i.style.unwrap_or_else(|| "warning".into()),
                "createdAt": i.created_at
            })
        })
        .collect();

    let groups: Vec<serde_json::Value> = serde_json::from_str(&page.groups_json.clone().unwrap_or_else(|| "[]".into()))
        .unwrap_or_default();

    let monitors = sqlx::query_as::<_, Monitor>(
        "SELECT id, name, type, target, interval, status, latency, uptime_pct, created_at FROM monitors ORDER BY id ASC",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let mut monitors_map = std::collections::HashMap::new();
    for m in &monitors {
        let heartbeats = sqlx::query_as::<_, Heartbeat>(
            "SELECT id, monitor_id, status, latency, timestamp FROM heartbeats WHERE monitor_id = ? ORDER BY timestamp DESC LIMIT 36",
        )
        .bind(m.id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        let hb_list: Vec<serde_json::Value> = heartbeats
            .into_iter()
            .map(|h| {
                json!({
                    "status": h.status,
                    "latency": h.latency.unwrap_or(0.0),
                    "time": h.timestamp * 1000
                })
            })
            .collect();

        monitors_map.insert(
            m.id.to_string(),
            json!({
                "id": m.id,
                "name": m.name,
                "type": m.r#type,
                "target": m.target,
                "url": m.target,
                "status": m.status,
                "latency": m.latency.unwrap_or(0.0),
                "uptime24h": m.uptime_pct.unwrap_or(100.0),
                "heartbeats": hb_list
            }),
        );
    }

    let mut group_details = Vec::new();
    for g in &groups {
        let gid = g.get("id").and_then(|v| v.as_str()).unwrap_or_default();
        let gname = g.get("name").and_then(|v| v.as_str()).unwrap_or("Services");
        let mids = g.get("monitorIds").and_then(|v| v.as_array());

        let mut g_monitors = Vec::new();
        if let Some(arr) = mids {
            for mid_val in arr {
                let mid_str = if let Some(s) = mid_val.as_str() {
                    s.to_string()
                } else if let Some(n) = mid_val.as_i64() {
                    n.to_string()
                } else {
                    continue;
                };

                if let Some(m_json) = monitors_map.get(&mid_str) {
                    g_monitors.push(m_json.clone());
                }
            }
        }

        group_details.push(json!({
            "id": gid,
            "name": gname,
            "monitorIds": g.get("monitorIds").cloned().unwrap_or_else(|| json!([])),
            "monitors": g_monitors
        }));
    }

    if group_details.is_empty() && !monitors.is_empty() {
        let all_m_list: Vec<serde_json::Value> = monitors_map.values().cloned().collect();
        group_details.push(json!({
            "id": "default-services",
            "name": "Services",
            "monitorIds": monitors.iter().map(|m| m.id.to_string()).collect::<Vec<_>>(),
            "monitors": all_m_list
        }));
    }

    Ok(json!({
        "slug": page.slug,
        "title": page.title,
        "description": page.description.unwrap_or_default(),
        "footerText": page.footer_text.unwrap_or_default(),
        "refreshInterval": page.refresh_interval.unwrap_or(300),
        "isPublic": is_public,
        "isRestricted": false,
        "groups": groups,
        "groupDetails": group_details,
        "incidents": incidents,
        "monitors": monitors
    }))
}

async fn get_default_status_page(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let is_auth = check_optional_auth(&state, &headers).await;
    let data = resolve_status_page(&state, "monitor", is_auth).await?;
    Ok(Json(data))
}

async fn get_status_page_by_slug(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let is_auth = check_optional_auth(&state, &headers).await;
    let data = resolve_status_page(&state, &slug, is_auth).await?;
    Ok(Json(data))
}

async fn save_status_page(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("admin")?;

    let slug = payload.get("slug")
        .and_then(|v| v.as_str())
        .unwrap_or("monitor")
        .trim();
    let title = payload.get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("System Status")
        .trim();
    let description = payload.get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let footer_text = payload.get("footerText")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let refresh_interval = payload.get("refreshInterval")
        .and_then(|v| v.as_i64())
        .unwrap_or(300);
    let is_public = if payload.get("isPublic").and_then(|v| v.as_bool()) == Some(false) { 0 } else { 1 };
    let groups_json = payload.get("groups")
        .map(|v| v.to_string())
        .unwrap_or_else(|| "[]".to_string());

    sqlx::query(
        r#"
        INSERT INTO status_pages (slug, title, description, footer_text, refresh_interval, is_public, groups_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(slug) DO UPDATE SET
            title = excluded.title,
            description = excluded.description,
            footer_text = excluded.footer_text,
            refresh_interval = excluded.refresh_interval,
            is_public = excluded.is_public,
            groups_json = excluded.groups_json
        "#,
    )
    .bind(slug)
    .bind(title)
    .bind(description)
    .bind(footer_text)
    .bind(refresh_interval)
    .bind(is_public)
    .bind(groups_json)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({ "status": "ok", "page": payload })))
}

async fn delete_status_page(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("admin")?;

    if slug == "monitor" {
        return Err(AppError::BadRequest("Default 'monitor' status page cannot be deleted".into()));
    }

    sqlx::query("DELETE FROM status_pages WHERE slug = ?")
        .bind(&slug)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    sqlx::query("DELETE FROM status_page_incidents WHERE status_page_slug = ?")
        .bind(&slug)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({ "status": "ok" })))
}

#[derive(Deserialize)]
pub struct IncidentPayload {
    pub slug: Option<String>,
    pub title: String,
    pub content: Option<String>,
    pub style: Option<String>,
}

async fn post_status_incident(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<IncidentPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("admin")?;

    let slug = payload.slug.unwrap_or_else(|| "monitor".to_string());
    let id = format!("inc-{}", chrono::Utc::now().timestamp_millis());
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO status_page_incidents (id, status_page_slug, title, content, style, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&slug)
    .bind(&payload.title)
    .bind(payload.content.unwrap_or_default())
    .bind(payload.style.unwrap_or_else(|| "warning".to_string()))
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let config = resolve_status_page(&state, &slug, true).await?;
    Ok(Json(json!({ "status": "ok", "config": config })))
}

#[derive(Deserialize)]
pub struct IncidentQuery {
    pub slug: Option<String>,
}

async fn delete_status_incident(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<IncidentQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("admin")?;

    let slug = query.slug.unwrap_or_else(|| "monitor".to_string());

    sqlx::query("DELETE FROM status_page_incidents WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let config = resolve_status_page(&state, &slug, true).await?;
    Ok(Json(json!({ "status": "ok", "config": config })))
}
