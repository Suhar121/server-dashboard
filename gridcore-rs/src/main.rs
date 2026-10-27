mod config;
mod db;
mod error;
mod middleware;
mod routers;
mod services;
mod state;
mod static_embed;

use config::Config;
use db::users::{create_user, get_user};
use state::AppState;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gridcore=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg = Config::from_env();
    tracing::info!("Initializing database at {}", cfg.users_db_path);

    let pool = db::init_db(&cfg.users_db_path).await?;

    // Seed admin user if not exists
    let existing_admin = get_user(&pool, &cfg.admin_username).await?;
    if existing_admin.is_none() {
        tracing::info!("Bootstrapping default admin user: {}", cfg.admin_username);
        let _ = create_user(
            &pool,
            &cfg.admin_username,
            &cfg.admin_password,
            "admin",
            cfg.password_iterations,
        )
        .await?;
    }

    // Start background uptime monitor engine
    services::uptime_engine::start_uptime_engine(pool.clone(), cfg.clone());

    let state = AppState::new(cfg.clone(), pool);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build the main Axum application
    let app = axum::Router::new()
        .nest("/auth", routers::auth::router())
        .nest("/docker", routers::docker::router())
        .nest("/files", routers::files::router())
        .nest("/ai", routers::ai::router())
        .nest("/api", routers::uptime::router())
        .nest("/deploy", routers::deploy::router())
        .merge(routers::metrics::router())
        .merge(routers::admin::router())
        .merge(routers::terminal::router())
        // Static assets and single-page application routes
        .route("/", axum::routing::get(static_embed::serve_index))
        .route("/status", axum::routing::get(static_embed::serve_status))
        .route("/status/:slug", axum::routing::get(static_embed::serve_status))
        .route("/logo", axum::routing::get(static_embed::serve_logo))
        .route("/static/*path", axum::routing::get(static_embed::serve_static))
        .route("/ws/uptime", axum::routing::get(handle_ws_uptime))
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
    tracing::info!("GridCore Rust server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn handle_ws_uptime(ws: axum::extract::ws::WebSocketUpgrade) -> axum::response::Response {
    use axum::response::IntoResponse;
    use futures_util::StreamExt;
    ws.on_upgrade(|mut socket| async move {
        while let Some(Ok(msg)) = socket.next().await {
            if let axum::extract::ws::Message::Close(_) = msg {
                break;
            }
        }
    })
    .into_response()
}
