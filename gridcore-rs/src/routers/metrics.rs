use crate::error::AppError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use serde_json::json;
use std::time::Duration;
use tokio::net::TcpStream;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/server-info", get(server_info))
        .route("/system", get(get_system))
        .route("/battery", get(get_battery))
        .route("/ports", get(get_ports))
        .route("/check-port/:port", get(check_port))
}

async fn server_info(State(state): State<AppState>) -> Json<serde_json::Value> {
    let hostname = sysinfo::System::host_name().unwrap_or_else(|| "localhost".to_string());
    let server_name = if state.config.server_name.is_empty() {
        hostname.clone()
    } else {
        state.config.server_name.clone()
    };

    Json(json!({
        "server_name": server_name,
        "hostname": hostname
    }))
}

async fn get_system(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("viewer")?;

    let mut sys = state.sys.lock().await;
    sys.refresh_cpu_all();
    sys.refresh_memory();

    let cpu = sys.global_cpu_usage() as f64;
    let cpus: Vec<f64> = sys.cpus()
        .iter()
        .map(|c| ((c.cpu_usage() as f64) * 10.0).round() / 10.0)
        .collect();
    let total_mem = sys.total_memory();
    let used_mem = sys.used_memory();
    let free_mem = sys.free_memory();
    let available_mem = sys.available_memory();

    let mem_percent = if total_mem > 0 {
        ((used_mem as f64) / (total_mem as f64)) * 100.0
    } else {
        0.0
    };

    Ok(Json(json!({
        "cpu": (cpu * 10.0).round() / 10.0,
        "cpus": cpus,
        "memory": (mem_percent * 10.0).round() / 10.0,
        "vmem": {
            "total": total_mem,
            "available": available_mem,
            "used": used_mem,
            "free": free_mem,
            "percent": (mem_percent * 10.0).round() / 10.0
        }
    })))
}

async fn get_battery(
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("viewer")?;

    // Return dummy battery for now or integrate battery crate
    Ok(Json(json!({
        "percent": null,
        "plugged": true
    })))
}

async fn get_ports(
    auth: AuthUser,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    auth.require_role("viewer")?;

    // Check standard common local ports (e.g. 80, 443, 3000, 5000, 8000, 8080, 27017, 5432, 6379, etc.)
    let common_ports = [
        22, 53, 80, 443, 3000, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 9000, 27017,
    ];

    let mut list = Vec::new();

    for port in common_ports {
        let addr = format!("127.0.0.1:{}", port);
        if let Ok(Ok(_)) = tokio::time::timeout(
            Duration::from_millis(150),
            TcpStream::connect(&addr),
        )
        .await
        {
            list.push(json!({
                "protocol": "tcp",
                "state": "LISTEN",
                "local": addr
            }));
        }
    }

    Ok(Json(list))
}

async fn check_port(
    auth: AuthUser,
    Path(port): Path<u16>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("viewer")?;

    let addr = format!("127.0.0.1:{}", port);
    let active = match tokio::time::timeout(
        Duration::from_millis(500),
        TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(_)) => true,
        _ => false,
    };

    Ok(Json(json!({
        "port": port,
        "active": active
    })))
}
