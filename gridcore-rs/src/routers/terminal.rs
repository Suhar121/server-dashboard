use crate::db::users::get_session;
use crate::state::AppState;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::header,
    response::IntoResponse,
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::Value;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

#[derive(Deserialize)]
pub struct TerminalQuery {
    pub protocol: Option<String>,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/ws/terminal", get(ws_terminal_handler))
}

async fn ws_terminal_handler(
    State(state): State<AppState>,
    Query(query): Query<TerminalQuery>,
    ws: WebSocketUpgrade,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let cookie_header = headers
        .get(header::COOKIE)
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

    let is_authorized = match session_token {
        Some(token) => {
            if let Ok(Some(session)) = get_session(&state.db, &token).await {
                session.role == "admin" || session.role == "operator"
            } else {
                false
            }
        }
        None => false,
    };

    if !is_authorized {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            "Unauthorized terminal access",
        )
            .into_response();
    }

    let protocol_v2 = query.protocol.as_deref() == Some("v2");

    ws.on_upgrade(move |socket| handle_terminal_socket(socket, protocol_v2))
        .into_response()
}

async fn handle_terminal_socket(socket: WebSocket, protocol_v2: bool) {
    let (mut ws_sender, mut ws_receiver) = socket.split();

    if protocol_v2 {
        let _ = ws_sender
            .send(Message::Text("__DASH_TERM_PROTOCOL_V2__".to_string()))
            .await;
    }

    // Determine default shell
    #[cfg(target_os = "windows")]
    let (shell_cmd, shell_args) = ("powershell.exe", vec!["-NoLogo"]);
    #[cfg(not(target_os = "windows"))]
    let (shell_cmd, shell_args) = {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        (shell.leak() as &str, vec!["-i"])
    };

    let mut child = match Command::new(shell_cmd)
        .args(&shell_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = ws_sender
                .send(Message::Text(format!("Failed to spawn shell: {}\r\n", e)))
                .await;
            return;
        }
    };

    let mut stdin = child.stdin.take().expect("Failed to open child stdin");
    let mut stdout = child.stdout.take().expect("Failed to open child stdout");
    let mut stderr = child.stderr.take().expect("Failed to open child stderr");

    // Task 1: read stdout and pipe to WebSocket
    let mut ws_sender_stdout = ws_sender;
    let stdout_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let text = String::from_utf8_lossy(&buf[..n]).to_string();
                    if ws_sender_stdout.send(Message::Text(text)).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        ws_sender_stdout
    });

    // Task 2: read stderr and pipe to WebSocket
    // For simplicity, spawn reading stderr
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stderr.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
    });

    // Task 3: read WebSocket and pipe to stdin
    while let Some(Ok(msg)) = ws_receiver.next().await {
        match msg {
            Message::Text(text) => {
                let input_str = if let Ok(val) = serde_json::from_str::<Value>(&text) {
                    if val.get("type").and_then(|v| v.as_str()) == Some("input") {
                        val.get("data")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string()
                    } else {
                        String::new()
                    }
                } else {
                    text
                };

                if !input_str.is_empty() {
                    let _ = stdin.write_all(input_str.as_bytes()).await;
                    let _ = stdin.flush().await;
                }
            }
            Message::Binary(bin) => {
                let _ = stdin.write_all(&bin).await;
                let _ = stdin.flush().await;
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    let _ = child.kill().await;
    let _ = stdout_task.await;
}
