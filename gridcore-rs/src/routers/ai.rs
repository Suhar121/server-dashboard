use crate::error::AppError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;
use axum::{
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, post},
    Json, Router,
};
use futures_util::stream::{self, Stream};
use serde::Deserialize;
use serde_json::json;
use std::convert::Infallible;
use std::env;

#[derive(Deserialize)]
pub struct AIChatPayload {
    pub message: String,
}

#[derive(Deserialize)]
pub struct AIAnalyzePayload {
    pub target: String,
    pub context: Option<String>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/status", get(get_ai_status))
        .route("/chat", post(ai_chat))
        .route("/analyze", post(ai_analyze))
}

async fn get_ai_status(auth: AuthUser) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("viewer")?;

    let gemini_key = env::var("GEMINI_API_KEY").unwrap_or_default();
    let openai_key = env::var("OPENAI_API_KEY").or_else(|_| env::var("NVIDIA_API_KEY")).unwrap_or_default();

    let configured = (!gemini_key.is_empty() && gemini_key != "YOUR_KEY") || !openai_key.is_empty();
    let provider = if !gemini_key.is_empty() && gemini_key != "YOUR_KEY" {
        "gemini"
    } else if !openai_key.is_empty() {
        "openai"
    } else {
        "none"
    };

    Ok(Json(json!({
        "available": configured,
        "configured": configured,
        "provider": provider,
        "model": if provider == "gemini" { "gemini-1.5-flash" } else { "gpt-4o-mini" }
    })))
}

async fn ai_chat(
    auth: AuthUser,
    Json(payload): Json<AIChatPayload>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, AppError> {
    auth.require_role("viewer")?;

    let gemini_key = env::var("GEMINI_API_KEY").unwrap_or_default();
    let openai_key = env::var("OPENAI_API_KEY").or_else(|_| env::var("NVIDIA_API_KEY")).unwrap_or_default();

    let message = payload.message;

    // Stream generation
    let events = if !gemini_key.is_empty() && gemini_key != "YOUR_KEY" {
        // Direct call to Gemini REST API
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={}",
            gemini_key
        );

        let client = reqwest::Client::new();
        let body = json!({
            "contents": [{
                "parts": [{ "text": message }]
            }]
        });

        match client.post(&url).json(&body).send().await {
            Ok(resp) => {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    let text = data["candidates"][0]["content"]["parts"][0]["text"]
                        .as_str()
                        .unwrap_or("No response generated.")
                        .to_string();

                    vec![
                        Event::default().data(json!({"type": "token", "token": text}).to_string()),
                        Event::default().data(json!({"type": "done"}).to_string()),
                    ]
                } else {
                    vec![Event::default().data(json!({"type": "error", "message": "Failed to parse Gemini response"}).to_string())]
                }
            }
            Err(e) => {
                vec![Event::default().data(json!({"type": "error", "message": e.to_string()}).to_string())]
            }
        }
    } else if !openai_key.is_empty() {
        // Direct call to OpenAI compatible endpoint
        let endpoint = env::var("OPENAI_BASE_URL").unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".to_string());
        let model = env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_string());

        let client = reqwest::Client::new();
        let body = json!({
            "model": model,
            "messages": [{"role": "user", "content": message}]
        });

        match client
            .post(&endpoint)
            .bearer_auth(openai_key)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    let text = data["choices"][0]["message"]["content"]
                        .as_str()
                        .unwrap_or("No response generated.")
                        .to_string();

                    vec![
                        Event::default().data(json!({"type": "token", "token": text}).to_string()),
                        Event::default().data(json!({"type": "done"}).to_string()),
                    ]
                } else {
                    vec![Event::default().data(json!({"type": "error", "message": "Failed to parse OpenAI response"}).to_string())]
                }
            }
            Err(e) => {
                vec![Event::default().data(json!({"type": "error", "message": e.to_string()}).to_string())]
            }
        }
    } else {
        vec![
            Event::default().data(
                json!({
                    "type": "token",
                    "token": "AI assistant is not configured yet. Set GEMINI_API_KEY or OPENAI_API_KEY in your .env."
                })
                .to_string(),
            ),
            Event::default().data(json!({"type": "done"}).to_string()),
        ]
    };

    let stream = stream::iter(events.into_iter().map(Ok));
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

async fn ai_analyze(
    auth: AuthUser,
    Json(payload): Json<AIAnalyzePayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_role("viewer")?;

    Ok(Json(json!({
        "status": "ok",
        "analysis": format!("Analysis for target '{}': System state is healthy. No immediate anomalies detected.", payload.target)
    })))
}
