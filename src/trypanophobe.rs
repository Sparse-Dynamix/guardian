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
