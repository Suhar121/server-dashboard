use crate::config::Config;
use crate::db::DbPool;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::sleep;

#[derive(sqlx::FromRow)]
struct MonitorTarget {
    id: i64,
    name: String,
    r#type: String,
    target: String,
    status: String,
}

pub fn start_uptime_engine(db: DbPool, config: Config) {
    tokio::spawn(async move {
        tracing::info!("Starting background Uptime Monitoring Engine");
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        loop {
            sleep(Duration::from_secs(10)).await;

            let monitors = match sqlx::query_as::<_, MonitorTarget>(
                "SELECT id, name, type, target, status FROM monitors",
            )
            .fetch_all(&db)
            .await
            {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("Failed to fetch monitors: {}", e);
                    continue;
                }
            };

            for mon in monitors {
                let start = Instant::now();
                let is_up = match mon.r#type.to_lowercase().as_str() {
                    "http" | "https" => {
                        match http_client.get(&mon.target).send().await {
                            Ok(resp) => resp.status().as_u16() < 500,
                            Err(_) => false,
                        }
                    }
                    "tcp" | "port" => {
                        tokio::time::timeout(
                            Duration::from_millis(1500),
                            TcpStream::connect(&mon.target),
                        )
                        .await
                        .map(|res| res.is_ok())
                        .unwrap_or(false)
                    }
                    _ => true,
                };

                let latency = start.elapsed().as_secs_f64() * 1000.0;
                let new_status = if is_up { "up" } else { "down" };
                let now = chrono::Utc::now().timestamp();

                // Alert on state transition
                if new_status != mon.status {
                    let icon = if is_up { "✅" } else { "🚨" };
                    let msg = format!(
                        "{} Monitor Alert: '{}' is now {}! (Target: {})",
                        icon, mon.name, new_status.to_uppercase(), mon.target
                    );

                    if !config.bot_token.is_empty() && !config.chat_id.is_empty() {
                        let url = format!(
                            "https://api.telegram.org/bot{}/sendMessage",
                            config.bot_token
                        );
                        let _ = http_client
                            .post(&url)
                            .json(&serde_json::json!({
                                "chat_id": config.chat_id,
                                "text": msg
                            }))
                            .send()
                            .await;
                    }
                }

                // Insert heartbeat
                let _ = sqlx::query(
                    "INSERT INTO heartbeats (monitor_id, status, latency, timestamp, message) VALUES (?, ?, ?, ?, NULL)",
                )
                .bind(mon.id)
                .bind(new_status)
                .bind(latency)
                .bind(now)
                .execute(&db)
                .await;

                // Update monitor current status and latency
                let _ = sqlx::query(
                    "UPDATE monitors SET status = ?, latency = ? WHERE id = ?",
                )
                .bind(new_status)
                .bind(latency)
                .bind(mon.id)
                .execute(&db)
                .await;

                // Prune heartbeats older than 100 entries
                let _ = sqlx::query(
                    "DELETE FROM heartbeats WHERE monitor_id = ? AND id NOT IN (SELECT id FROM heartbeats WHERE monitor_id = ? ORDER BY timestamp DESC LIMIT 100)",
                )
                .bind(mon.id)
                .bind(mon.id)
                .execute(&db)
                .await;
            }
        }
    });
}
