//! Thin client for the Anthropic Messages API (`POST /v1/messages`).
//!
//! There is no official Rust SDK, so the request is built by hand and sent
//! with `ureq` (rustls).  Everything model-facing goes through the
//! [`LlmClient`] trait so that the agent loop can be tested with the scripted
//! [`ScriptedClient`] without any network access.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fmt;
use std::sync::Mutex;
use std::time::Duration;
use thiserror::Error;

/// Cost-efficient default model.
pub const DEFAULT_MODEL: &str = "claude-sonnet-5-5";
/// Most capable model of the Opus line, for deep audits (`--model`).
pub const DEEP_MODEL: &str = "claude-opus-5-5";
pub const DEFAULT_API_BASE: &str = "https://api.anthropic.com";
pub const ANTHROPIC_VERSION: &str = "2023-06-01";
/// Beta header for `fallbacks: "default"` (server-side refusal fallback).
pub const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";
/// Environment variable holding the API key unless configured otherwise.
pub const DEFAULT_KEY_ENV: &str = "ANTHROPIC_API_KEY";

#[derive(Debug, Error)]
pub enum LlmError {
    #[error("Verbindung zur Anthropic-API fehlgeschlagen: {0}")]
    Transport(String),
    #[error("Anthropic-API meldet HTTP {status} ({kind}): {message}")]
    Api {
        status: u16,
        kind: String,
        message: String,
    },
    #[error("Antwort der Anthropic-API ungültig: {0}")]
    Invalid(String),
}

/// One conversation turn.  Content blocks are kept as raw JSON so that
/// assistant turns (including `thinking` blocks with their signatures) can be
/// sent back exactly as they were received.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: Vec<Value>,
}

impl Message {
    pub fn user_text(text: impl Into<String>) -> Self {
        Message {
            role: "user".into(),
            content: vec![json!({"type": "text", "text": text.into()})],
        }
    }

    pub fn user_blocks(content: Vec<Value>) -> Self {
        Message {
            role: "user".into(),
            content,
        }
    }

    pub fn assistant(content: Vec<Value>) -> Self {
        Message {
            role: "assistant".into(),
            content,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MessagesRequest {
    pub model: String,
    pub max_tokens: u32,
    pub system: String,
    pub tools: Vec<Value>,
    pub messages: Vec<Message>,
    /// `output_config.effort` (`low` … `max`); `None` uses the model default.
    pub effort: Option<String>,
    /// Opt into the server-side refusal fallback (`fallbacks: "default"`).
    pub fallback: bool,
}

impl MessagesRequest {
    /// JSON body for `POST /v1/messages`.  Thinking is left at the model
    /// default (adaptive); top-level `cache_control` lets the API cache the
    /// stable prefix (tools, system prompt, earlier turns) automatically.
    pub fn to_body(&self) -> Value {
        let mut body = json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": [{"type": "text", "text": self.system}],
            "messages": self.messages,
            "cache_control": {"type": "ephemeral"},
        });
        if !self.tools.is_empty() {
            body["tools"] = Value::Array(self.tools.clone());
        }
        if let Some(e) = &self.effort {
            body["output_config"] = json!({"effort": e});
        }
        if self.fallback {
            body["fallbacks"] = json!("default");
        }
        body
    }
}

fn null_as_zero<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    Ok(Option::<u64>::deserialize(d)?.unwrap_or(0))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    #[serde(default, deserialize_with = "null_as_zero")]
    pub input_tokens: u64,
    #[serde(default, deserialize_with = "null_as_zero")]
    pub output_tokens: u64,
    #[serde(default, deserialize_with = "null_as_zero")]
    pub cache_creation_input_tokens: u64,
    #[serde(default, deserialize_with = "null_as_zero")]
    pub cache_read_input_tokens: u64,
}

impl Usage {
    /// All input tokens the request processed (uncached + cache write + cache read).
    pub fn total_input(&self) -> u64 {
        self.input_tokens + self.cache_creation_input_tokens + self.cache_read_input_tokens
    }

    pub fn add(&mut self, other: &Usage) {
        self.input_tokens += other.input_tokens;
        self.output_tokens += other.output_tokens;
        self.cache_creation_input_tokens += other.cache_creation_input_tokens;
        self.cache_read_input_tokens += other.cache_read_input_tokens;
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MessagesResponse {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub content: Vec<Value>,
    #[serde(default)]
    pub stop_reason: Option<String>,
    #[serde(default)]
    pub stop_details: Option<Value>,
    #[serde(default)]
    pub usage: Usage,
}

impl MessagesResponse {
    /// Concatenated `text` blocks.
    pub fn text(&self) -> String {
        self.content
            .iter()
            .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// `(id, name, input)` of every `tool_use` block.
    pub fn tool_uses(&self) -> Vec<(String, String, Value)> {
        self.content
            .iter()
            .filter(|b| b.get("type").and_then(Value::as_str) == Some("tool_use"))
            .map(|b| {
                (
                    b.get("id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    b.get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    b.get("input").cloned().unwrap_or(Value::Null),
                )
            })
            .collect()
    }
}

/// Anything that can answer a Messages API request.
pub trait LlmClient {
    fn create_message(&self, request: &MessagesRequest) -> Result<MessagesResponse, LlmError>;
}

/// HTTP client for the Anthropic API.
pub struct AnthropicClient {
    agent: ureq::Agent,
    base: String,
    api_key: String,
    /// Attempts for retryable errors (429, 5xx, 529, transport).
    pub max_attempts: u32,
}

impl fmt::Debug for AnthropicClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnthropicClient")
            .field("base", &self.base)
            .field("api_key", &"***")
            .finish()
    }
}

impl AnthropicClient {
    pub fn new(api_key: impl Into<String>, base: Option<&str>) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(600)))
            .http_status_as_error(false)
            .build();
        AnthropicClient {
            agent: config.into(),
            base: base
                .unwrap_or(DEFAULT_API_BASE)
                .trim_end_matches('/')
                .to_string(),
            api_key: api_key.into(),
            max_attempts: 4,
        }
    }

    fn send_once(
        &self,
        request: &MessagesRequest,
        body: &str,
    ) -> Result<(u16, Option<u64>, String), LlmError> {
        let mut req = self
            .agent
            .post(format!("{}/v1/messages", self.base))
            .header("content-type", "application/json")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header(
                "user-agent",
                concat!("ecomsec/", env!("CARGO_PKG_VERSION"), " (audit)"),
            );
        if request.fallback {
            req = req.header("anthropic-beta", FALLBACK_BETA);
        }
        let mut resp = req
            .send(body)
            .map_err(|e| LlmError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        let text = resp
            .body_mut()
            .with_config()
            .limit(32 * 1024 * 1024)
            .read_to_string()
            .map_err(|e| LlmError::Transport(e.to_string()))?;
        Ok((status, retry_after, text))
    }
}

fn api_error(status: u16, text: &str) -> LlmError {
    let parsed: Option<Value> = serde_json::from_str(text).ok();
    let kind = parsed
        .as_ref()
        .and_then(|v| v.pointer("/error/type"))
        .and_then(Value::as_str)
        .unwrap_or("unbekannt")
        .to_string();
    let mut message = parsed
        .as_ref()
        .and_then(|v| v.pointer("/error/message"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| text.chars().take(300).collect());
    if status == 401 {
        message = format!("API-Schlüssel ungültig oder ohne Berechtigung ({message})");
    }
    LlmError::Api {
        status,
        kind,
        message,
    }
}

fn retryable(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504 | 529)
}

impl LlmClient for AnthropicClient {
    fn create_message(&self, request: &MessagesRequest) -> Result<MessagesResponse, LlmError> {
        let body = serde_json::to_string(&request.to_body())
            .map_err(|e| LlmError::Invalid(e.to_string()))?;
        let mut attempt = 0;
        loop {
            attempt += 1;
            let result = self.send_once(request, &body);
            let wait = |retry_after: Option<u64>| {
                Duration::from_secs(retry_after.unwrap_or(1u64 << attempt.min(5)).min(60))
            };
            match result {
                Ok((status, _, text)) if (200..300).contains(&status) => {
                    return serde_json::from_str(&text)
                        .map_err(|e| LlmError::Invalid(e.to_string()));
                }
                Ok((status, retry_after, text)) => {
                    if retryable(status) && attempt < self.max_attempts {
                        let d = wait(retry_after);
                        log::warn!(
                            "Anthropic API HTTP {status}, retry {attempt}/{} in {}s",
                            self.max_attempts - 1,
                            d.as_secs()
                        );
                        std::thread::sleep(d);
                        continue;
                    }
                    return Err(api_error(status, &text));
                }
                Err(e) => {
                    if attempt < self.max_attempts {
                        let d = wait(None);
                        log::warn!(
                            "Anthropic API transport error ({e}), retry in {}s",
                            d.as_secs()
                        );
                        std::thread::sleep(d);
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }
}

/// Client that replays scripted responses and records every request.  Used
/// by the tests (no network) and handy for dry runs of the agent loop.
#[derive(Default)]
pub struct ScriptedClient {
    responses: Mutex<VecDeque<Result<MessagesResponse, LlmError>>>,
    requests: Mutex<Vec<MessagesRequest>>,
}

impl ScriptedClient {
    pub fn new(responses: Vec<MessagesResponse>) -> Self {
        ScriptedClient {
            responses: Mutex::new(responses.into_iter().map(Ok).collect()),
            requests: Mutex::new(Vec::new()),
        }
    }

    pub fn push_error(&self, error: LlmError) {
        self.responses.lock().expect("lock").push_back(Err(error));
    }

    /// Requests received so far.
    pub fn requests(&self) -> Vec<MessagesRequest> {
        self.requests.lock().expect("lock").clone()
    }

    /// Response that calls the given tools (`(name, input)`).
    pub fn tool_calls(calls: &[(&str, Value)], usage: Usage) -> MessagesResponse {
        let content = calls
            .iter()
            .enumerate()
            .map(|(i, (name, input))| {
                json!({"type": "tool_use", "id": format!("toolu_{i}_{name}"), "name": name, "input": input})
            })
            .collect();
        MessagesResponse {
            id: "msg_scripted".into(),
            model: DEFAULT_MODEL.into(),
            content,
            stop_reason: Some("tool_use".into()),
            stop_details: None,
            usage,
        }
    }

    /// Final text response.
    pub fn final_text(text: &str, usage: Usage) -> MessagesResponse {
        MessagesResponse {
            id: "msg_scripted".into(),
            model: DEFAULT_MODEL.into(),
            content: vec![json!({"type": "text", "text": text})],
            stop_reason: Some("end_turn".into()),
            stop_details: None,
            usage,
        }
    }
}

impl LlmClient for ScriptedClient {
    fn create_message(&self, request: &MessagesRequest) -> Result<MessagesResponse, LlmError> {
        self.requests.lock().expect("lock").push(request.clone());
        self.responses
            .lock()
            .expect("lock")
            .pop_front()
            .unwrap_or_else(|| Err(LlmError::Invalid("Skript erschöpft".into())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_body_has_expected_shape() {
        let req = MessagesRequest {
            model: DEFAULT_MODEL.into(),
            max_tokens: 16000,
            system: "sys".into(),
            tools: vec![json!({"name": "t", "input_schema": {"type": "object"}})],
            messages: vec![Message::user_text("hi")],
            effort: Some("medium".into()),
            fallback: true,
        };
        let body = req.to_body();
        assert_eq!(body["model"], "claude-sonnet-5-5");
        assert_eq!(body["system"][0]["text"], "sys");
        assert_eq!(body["output_config"]["effort"], "medium");
        assert_eq!(body["fallbacks"], "default");
        assert_eq!(body["cache_control"]["type"], "ephemeral");
        assert_eq!(body["messages"][0]["content"][0]["text"], "hi");
        assert!(body.get("thinking").is_none());
    }

    #[test]
    fn parses_response_with_null_usage_fields() {
        let r: MessagesResponse = serde_json::from_str(
            r#"{"id":"m","model":"claude-sonnet-5-5","stop_reason":"tool_use",
                "content":[{"type":"thinking","thinking":"","signature":"s"},
                           {"type":"text","text":"Ich prüfe."},
                           {"type":"tool_use","id":"t1","name":"read_file","input":{"path":"a"}}],
                "usage":{"input_tokens":10,"output_tokens":5,"cache_creation_input_tokens":null}}"#,
        )
        .unwrap();
        assert_eq!(r.text(), "Ich prüfe.");
        assert_eq!(r.tool_uses()[0].1, "read_file");
        assert_eq!(r.usage.total_input(), 10);
    }
}
