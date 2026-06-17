use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderMap;
use proxyapi::content_filter::{ContentFilter, FilterVerdict, HttpFilterContext, WsFilterContext};
use reqwest::Client;
use serde::Deserialize;

use crate::config::Settings;

pub const DEFAULT_BLOCK_MESSAGE: &str = "Blocked by Guardian: content failed safety check";
pub const PAYLOAD_SOURCE_URL: &str = "guardian://payload";

#[derive(Debug, Clone)]
pub enum FilterInput<'a> {
    HttpResponse {
        url: &'a str,
        content_type: Option<&'a str>,
        body: &'a [u8],
    },
    WsFrame {
        direction: &'a str,
        opcode: &'a str,
        url: Option<&'a str>,
        payload: &'a [u8],
    },
    ToolPayload {
        bytes: &'a [u8],
    },
}

#[derive(Debug, Clone)]
pub enum FilterOutcome {
    Allowed,
    Replace { body: Bytes, headers: HeaderMap },
    Blocked { message: String },
}

#[derive(Debug, Deserialize)]
struct BlockedBody {
    error: String,
    stage: String,
    reason: String,
    detail: Option<String>,
}

pub struct TrypanophobeClient {
    url: String,
    block_message: String,
    swap: bool,
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
            settings.trypanophobe_swap,
        )
    }

    pub fn new(url: String, block_message: String, timeout_secs: u64, swap: bool) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .context("failed to build Trypanophobe HTTP client")?;
        Ok(Self {
            url,
            block_message,
            swap,
            http,
        })
    }

    pub async fn check(&self, input: FilterInput<'_>) -> Result<FilterOutcome> {
        let (body_bytes, source_url, content_type) = match input {
            FilterInput::HttpResponse {
                url,
                content_type,
                body,
            } => (
                body.to_vec(),
                url.to_string(),
                content_type.map(str::to_string),
            ),
            FilterInput::WsFrame {
                direction,
                opcode,
                url,
                payload,
            } => {
                let source = url
                    .map(str::to_string)
                    .unwrap_or_else(|| ws_source_url(direction, opcode));
                let ct = ws_content_type(opcode).map(str::to_string);
                (payload.to_vec(), source, ct)
            }
            FilterInput::ToolPayload { bytes } => (
                bytes.to_vec(),
                PAYLOAD_SOURCE_URL.to_string(),
                Some("application/octet-stream".to_string()),
            ),
        };

        let mut query = vec![("url", source_url.as_str())];
        if self.swap {
            query.push(("format", "md"));
        }

        let mut request = self.http.post(&self.url).query(&query).body(body_bytes);
        if let Some(ct) = content_type.as_deref() {
            request = request.header(http::header::CONTENT_TYPE, ct);
        }

        let response = request
            .send()
            .await
            .context("Trypanophobe filter request failed")?;

        let status = response.status();
        let status_code = status.as_u16();

        if status_is_allowed(status_code, self.swap) {
            if self.swap {
                let headers = response_headers(&response);
                let body = response.bytes().await.context("failed to read TPF body")?;
                return Ok(FilterOutcome::Replace { body, headers });
            }
            return Ok(FilterOutcome::Allowed);
        }

        let body = response.bytes().await.unwrap_or_default();
        Ok(FilterOutcome::Blocked {
            message: block_message_for_response(
                status_code,
                &body,
                &self.block_message,
                &source_url,
            ),
        })
    }
}

fn status_is_allowed(status_code: u16, swap: bool) -> bool {
    if status_code == 200 {
        return true;
    }
    swap && status_code == 206
}

fn ws_source_url(direction: &str, opcode: &str) -> String {
    format!("guardian://websocket/{direction}/{opcode}")
}

fn ws_content_type(opcode: &str) -> Option<&'static str> {
    match opcode {
        "text" => Some("text/plain"),
        "binary" => Some("application/octet-stream"),
        _ => None,
    }
}

pub fn stage_label(stage: &str) -> String {
    match stage {
        "url_check" => "URL check".to_string(),
        "nsfw_image" => "Image moderation".to_string(),
        "chunk_moderation" => "Content moderation".to_string(),
        "response_format" => "Partial content (format=og)".to_string(),
        other => format!("Filter stage: {other}"),
    }
}

pub fn format_blocked_message(
    reason: &str,
    stage: &str,
    detail: Option<&str>,
    source_url: &str,
) -> String {
    let mut lines = vec![
        format!("Blocked by Guardian: {reason}"),
        format!("Stage: {}", stage_label(stage)),
    ];
    if let Some(detail) = detail.filter(|s| !s.is_empty()) {
        lines.push(format!("Detail: {detail}"));
    }
    lines.push(format!("Source: {source_url}"));
    lines.join("\n")
}

fn parse_blocked_message(body: &[u8], source_url: &str, fallback: &str) -> String {
    let Ok(blocked) = serde_json::from_slice::<BlockedBody>(body) else {
        return fallback.to_string();
    };
    if blocked.error != "content_blocked" || blocked.reason.is_empty() {
        return fallback.to_string();
    }
    format_blocked_message(
        &blocked.reason,
        &blocked.stage,
        blocked.detail.as_deref(),
        source_url,
    )
}

fn block_message_for_response(
    status_code: u16,
    body: &[u8],
    fallback: &str,
    source_url: &str,
) -> String {
    if status_code == 406 {
        return parse_blocked_message(body, source_url, fallback);
    }
    if status_code == 0 {
        return fallback.to_string();
    }
    format!("{fallback} (filter HTTP {status_code})")
}

fn response_headers(response: &reqwest::Response) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in response.headers().iter() {
        if let Ok(v) = http::HeaderValue::from_bytes(value.as_bytes()) {
            map.insert(name, v);
        }
    }
    map
}

#[async_trait]
impl ContentFilter for TrypanophobeClient {
    async fn check_http_response(&self, ctx: HttpFilterContext<'_>) -> FilterVerdict {
        match self
            .check(FilterInput::HttpResponse {
                url: ctx.url,
                content_type: ctx.content_type,
                body: ctx.body,
            })
            .await
        {
            Ok(FilterOutcome::Allowed) => FilterVerdict::Allow,
            Ok(FilterOutcome::Replace { body, headers }) => {
                FilterVerdict::Replace { body, headers }
            }
            Ok(FilterOutcome::Blocked { message }) => FilterVerdict::Block {
                message: Bytes::from(message),
            },
            Err(e) => FilterVerdict::Block {
                message: Bytes::from(e.to_string()),
            },
        }
    }

    async fn check_ws_frame(&self, ctx: WsFilterContext<'_>) -> FilterVerdict {
        match self
            .check(FilterInput::WsFrame {
                direction: ctx.direction,
                opcode: ctx.opcode,
                url: ctx.url,
                payload: ctx.payload,
            })
            .await
        {
            Ok(FilterOutcome::Allowed) => FilterVerdict::Allow,
            Ok(FilterOutcome::Replace { .. }) => FilterVerdict::Allow,
            Ok(FilterOutcome::Blocked { message }) => FilterVerdict::Block {
                message: Bytes::from(message),
            },
            Err(e) => FilterVerdict::Block {
                message: Bytes::from(e.to_string()),
            },
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
        settings.trypanophobe_swap,
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
        FilterOutcome::Replace { body, .. } => {
            io::stdout()
                .write_all(&body)
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
    use super::*;

    #[test]
    fn stage_label_maps_known_stages() {
        assert_eq!(stage_label("url_check"), "URL check");
        assert_eq!(stage_label("nsfw_image"), "Image moderation");
        assert_eq!(stage_label("chunk_moderation"), "Content moderation");
        assert_eq!(
            stage_label("response_format"),
            "Partial content (format=og)"
        );
        assert_eq!(stage_label("custom"), "Filter stage: custom");
    }

    #[test]
    fn format_blocked_message_includes_optional_detail() {
        let msg = format_blocked_message(
            "All content chunks flagged",
            "chunk_moderation",
            Some("sentinel, wolf"),
            PAYLOAD_SOURCE_URL,
        );
        assert!(msg.contains("Blocked by Guardian: All content chunks flagged"));
        assert!(msg.contains("Stage: Content moderation"));
        assert!(msg.contains("Detail: sentinel, wolf"));
        assert!(msg.contains("Source: guardian://payload"));
    }

    #[test]
    fn format_blocked_message_omits_empty_detail() {
        let msg = format_blocked_message("blocked", "url_check", Some(""), "http://x/");
        assert!(!msg.contains("Detail:"));
    }

    #[test]
    fn parse_blocked_message_uses_fallback_on_bad_json() {
        assert_eq!(
            parse_blocked_message(b"not json", "http://x/", DEFAULT_BLOCK_MESSAGE),
            DEFAULT_BLOCK_MESSAGE
        );
    }

    #[test]
    fn parse_blocked_message_uses_fallback_on_wrong_error() {
        let body = br#"{"error":"other","stage":"url_check","reason":"nope"}"#;
        assert_eq!(
            parse_blocked_message(body, "http://x/", DEFAULT_BLOCK_MESSAGE),
            DEFAULT_BLOCK_MESSAGE
        );
    }

    #[test]
    fn parse_blocked_message_formats_valid_body() {
        let body = br#"{"error":"content_blocked","stage":"url_check","reason":"URL blocked by DNS blocklist","detail":"example.com"}"#;
        let msg = parse_blocked_message(body, "https://example.com/", DEFAULT_BLOCK_MESSAGE);
        assert!(msg.contains("URL blocked by DNS blocklist"));
        assert!(msg.contains("Stage: URL check"));
        assert!(msg.contains("Detail: example.com"));
    }

    #[test]
    fn status_is_allowed_rules() {
        assert!(status_is_allowed(200, false));
        assert!(!status_is_allowed(206, false));
        assert!(status_is_allowed(206, true));
        assert!(!status_is_allowed(406, false));
    }

    #[test]
    fn block_message_for_response_non_406_includes_status() {
        let msg = block_message_for_response(400, b"", DEFAULT_BLOCK_MESSAGE, "http://x/");
        assert!(msg.contains("filter HTTP 400"));
    }

    #[test]
    fn ws_source_url_and_content_type_helpers() {
        assert_eq!(
            ws_source_url("server_to_client", "text"),
            "guardian://websocket/server_to_client/text"
        );
        assert_eq!(ws_content_type("text"), Some("text/plain"));
        assert_eq!(ws_content_type("binary"), Some("application/octet-stream"));
        assert_eq!(ws_content_type("ping"), None);
    }
}
