use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use proxyapi::content_filter::{ContentFilter, FilterVerdict, HttpFilterContext, WsFilterContext};
use reqwest::Client;
use serde_json::{json, Value};

use crate::config::Settings;

pub const DEFAULT_BLOCK_MESSAGE: &str = "Blocked by Guardian: content failed safety check";

#[derive(Debug, Clone)]
pub enum FilterInput<'a> {
    HttpResponse {
        method: &'a str,
        url: &'a str,
        status: u16,
        scheme: &'a str,
        body: &'a [u8],
    },
    WsFrame {
        direction: &'a str,
        opcode: &'a str,
        payload: &'a [u8],
    },
    ToolPayload {
        bytes: &'a [u8],
    },
}

#[derive(Debug, Clone)]
pub enum FilterOutcome {
    Allowed,
    Blocked { message: String },
    FilterResponse { body: String },
}

pub struct TrypanophobeClient {
    url: String,
    block_message: String,
    body_limit: usize,
    http: Client,
}

impl TrypanophobeClient {
    pub fn from_settings(settings: &Settings) -> Result<Self> {
        let url = settings
            .trypanophobe_filter
            .clone()
            .context("--tpf / trypanophobe_filter is required for filtering")?;
        Self::new(
            url,
            settings.block_message.clone(),
            settings.filter_timeout_secs,
            settings.filter_body_limit,
        )
    }

    pub fn new(
        url: String,
        block_message: String,
        timeout_secs: u64,
        body_limit: usize,
    ) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .context("failed to build Trypanophobe HTTP client")?;
        Ok(Self {
            url,
            block_message,
            body_limit,
            http,
        })
    }

    pub async fn check(&self, input: FilterInput<'_>) -> Result<FilterOutcome> {
        let (kind, metadata, payload_bytes) = match input {
            FilterInput::HttpResponse {
                method,
                url,
                status,
                scheme,
                body,
            } => (
                "http_response",
                json!({
                    "url": url,
                    "method": method,
                    "status": status,
                    "scheme": scheme,
                }),
                truncate_payload(body, self.body_limit),
            ),
            FilterInput::WsFrame {
                direction,
                opcode,
                payload,
            } => (
                "ws_frame",
                json!({
                    "ws_direction": direction,
                    "ws_opcode": opcode,
                }),
                truncate_payload(payload, self.body_limit),
            ),
            FilterInput::ToolPayload { bytes } => (
                "tool_payload",
                json!({}),
                truncate_payload(bytes, self.body_limit),
            ),
        };

        let request_body = json!({
            "kind": kind,
            "payload": STANDARD.encode(&payload_bytes),
            "metadata": metadata,
        });

        let response = self
            .http
            .post(&self.url)
            .json(&request_body)
            .send()
            .await
            .context("Trypanophobe filter request failed")?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if status.is_success() {
            if body_contains_unsafe(&body) {
                return Ok(FilterOutcome::Blocked {
                    message: self.block_message.clone(),
                });
            }
            return Ok(FilterOutcome::FilterResponse { body });
        }

        Ok(FilterOutcome::Blocked {
            message: self.block_message.clone(),
        })
    }

    fn block_bytes(&self) -> Bytes {
        Bytes::from(self.block_message.clone())
    }
}

fn truncate_payload(body: &[u8], limit: usize) -> Vec<u8> {
    if body.len() <= limit {
        body.to_vec()
    } else {
        body[..limit].to_vec()
    }
}

fn body_contains_unsafe(body: &str) -> bool {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.get("safe").and_then(|s| s.as_bool()))
        .is_some_and(|safe| !safe)
}

#[async_trait]
impl ContentFilter for TrypanophobeClient {
    async fn check_http_response(&self, ctx: HttpFilterContext<'_>) -> FilterVerdict {
        match self
            .check(FilterInput::HttpResponse {
                method: ctx.method,
                url: ctx.url,
                status: ctx.status,
                scheme: ctx.scheme,
                body: ctx.body,
            })
            .await
        {
            Ok(FilterOutcome::Allowed | FilterOutcome::FilterResponse { .. }) => {
                FilterVerdict::Allow
            }
            Ok(FilterOutcome::Blocked { message }) => FilterVerdict::Block {
                message: Bytes::from(message),
            },
            Err(e) => {
                tracing::warn!(target: "guardian", "Trypanophobe HTTP filter error: {e:#}");
                FilterVerdict::Block {
                    message: self.block_bytes(),
                }
            }
        }
    }

    async fn check_ws_frame(&self, ctx: WsFilterContext<'_>) -> FilterVerdict {
        match self
            .check(FilterInput::WsFrame {
                direction: ctx.direction,
                opcode: ctx.opcode,
                payload: ctx.payload,
            })
            .await
        {
            Ok(FilterOutcome::Allowed | FilterOutcome::FilterResponse { .. }) => {
                FilterVerdict::Allow
            }
            Ok(FilterOutcome::Blocked { message }) => FilterVerdict::Block {
                message: Bytes::from(message),
            },
            Err(e) => {
                tracing::warn!(target: "guardian", "Trypanophobe WS filter error: {e:#}");
                FilterVerdict::Block {
                    message: self.block_bytes(),
                }
            }
        }
    }
}

pub async fn run_payload(settings: &Settings) -> Result<i32> {
    use std::io::{self, Read, Write};

    let payload = if let Some(text) = &settings.payload {
        text.as_bytes().to_vec()
    } else {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .context("failed to read payload from stdin")?;
        buf
    };

    let Some(url) = settings.trypanophobe_filter.clone() else {
        io::stdout()
            .write_all(&payload)
            .context("failed to write payload to stdout")?;
        return Ok(0);
    };

    let client = TrypanophobeClient::new(
        url,
        settings.block_message.clone(),
        settings.filter_timeout_secs,
        settings.filter_body_limit,
    )?;

    match client
        .check(FilterInput::ToolPayload { bytes: &payload })
        .await?
    {
        FilterOutcome::Allowed => {
            io::stdout()
                .write_all(&payload)
                .context("failed to write payload to stdout")?;
            Ok(0)
        }
        FilterOutcome::FilterResponse { body } => {
            io::stdout()
                .write_all(body.as_bytes())
                .context("failed to write filter response to stdout")?;
            Ok(0)
        }
        FilterOutcome::Blocked { message } => {
            io::stdout()
                .write_all(message.as_bytes())
                .context("failed to write block message to stdout")?;
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    use proxyapi::content_filter::{ContentFilter, HttpFilterContext, WsFilterContext};

    use super::*;

    fn spawn_mock(status: u16, body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
        listener.set_nonblocking(true).expect("set_nonblocking");
        let port = listener.local_addr().expect("local addr").port();
        let body = body.to_string();
        thread::spawn(move || {
            for _ in 0..32 {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0u8; 8192];
                        let _ = stream.read(&mut buf);
                        let response = format!(
                            "HTTP/1.1 {status} \r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len(),
                        );
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(25));
                    }
                    Err(_) => break,
                }
            }
        });
        format!("http://127.0.0.1:{port}/pass")
    }

    fn client_for(url: &str) -> TrypanophobeClient {
        TrypanophobeClient::new(url.to_string(), DEFAULT_BLOCK_MESSAGE.to_string(), 5, 1024)
            .expect("client")
    }

    #[test]
    fn truncate_payload_respects_limit() {
        let data: Vec<u8> = (0..20).collect();
        assert_eq!(truncate_payload(&data, 20).len(), 20);
        assert_eq!(truncate_payload(&data, 10).len(), 10);
        assert_eq!(truncate_payload(&data, 10), data[..10]);
    }

    #[test]
    fn body_contains_unsafe_detects_false_safe() {
        assert!(body_contains_unsafe(r#"{"safe":false}"#));
        assert!(!body_contains_unsafe(r#"{"safe":true}"#));
        assert!(!body_contains_unsafe("not json"));
    }

    #[tokio::test]
    async fn check_tool_payload_pass_returns_filter_response() {
        let url = spawn_mock(200, r#"{"safe":true}"#);
        thread::sleep(Duration::from_millis(50));
        let client = client_for(&url);
        let outcome = client
            .check(FilterInput::ToolPayload { bytes: b"hello" })
            .await
            .expect("check");
        match outcome {
            FilterOutcome::FilterResponse { body } => assert!(body.contains("safe")),
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_200_with_unsafe_body_blocks() {
        let url = spawn_mock(200, r#"{"safe":false}"#);
        thread::sleep(Duration::from_millis(200));
        let client = client_for(&url);
        let outcome = client
            .check(FilterInput::ToolPayload { bytes: b"x" })
            .await
            .expect("check");
        assert!(matches!(outcome, FilterOutcome::Blocked { .. }));
    }

    #[tokio::test]
    async fn check_tool_payload_reject_status_blocks() {
        let url = spawn_mock(503, r#"{"safe":false}"#);
        thread::sleep(Duration::from_millis(50));
        let client = client_for(&url);
        let outcome = client
            .check(FilterInput::ToolPayload { bytes: b"x" })
            .await
            .expect("check");
        match outcome {
            FilterOutcome::Blocked { message } => {
                assert!(message.contains("Blocked by Guardian"));
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_http_response_variant() {
        let url = spawn_mock(200, r#"{"safe":true}"#);
        thread::sleep(Duration::from_millis(50));
        let client = client_for(&url);
        let outcome = client
            .check(FilterInput::HttpResponse {
                method: "GET",
                url: "http://example.com/",
                status: 200,
                scheme: "http",
                body: b"body",
            })
            .await
            .expect("http check");
        assert!(matches!(outcome, FilterOutcome::FilterResponse { .. }));
    }

    #[tokio::test]
    async fn check_ws_frame_variant() {
        let url = spawn_mock(200, r#"{"safe":true}"#);
        thread::sleep(Duration::from_millis(50));
        let client = client_for(&url);
        let outcome = client
            .check(FilterInput::WsFrame {
                direction: "server",
                opcode: "text",
                payload: b"frame",
            })
            .await
            .expect("ws check");
        assert!(matches!(outcome, FilterOutcome::FilterResponse { .. }));
    }

    #[tokio::test]
    async fn content_filter_blocks_on_http_error() {
        let client = client_for("http://127.0.0.1:1/pass");
        let verdict = client
            .check_http_response(HttpFilterContext {
                method: "GET",
                url: "http://example.com/",
                status: 200,
                scheme: "http",
                body: b"",
            })
            .await;
        assert!(matches!(verdict, FilterVerdict::Block { .. }));
    }

    #[tokio::test]
    async fn content_filter_ws_error_blocks() {
        let client = client_for("http://127.0.0.1:1/pass");
        let verdict = client
            .check_ws_frame(WsFilterContext {
                direction: "server",
                opcode: "text",
                payload: b"",
            })
            .await;
        assert!(matches!(verdict, FilterVerdict::Block { .. }));
    }
}
