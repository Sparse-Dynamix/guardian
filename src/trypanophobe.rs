use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderMap;
use proxyapi::content_filter::{ContentFilter, FilterVerdict, HttpFilterContext, WsFilterContext};
use reqwest::Client;

use crate::config::Settings;

pub const DEFAULT_BLOCK_MESSAGE: &str = "Blocked by Guardian: content failed safety check";

#[derive(Debug, Clone)]
pub enum FilterInput<'a> {
    HttpResponse { url: &'a str, body: &'a [u8] },
    WsFrame { payload: &'a [u8] },
    ToolPayload { bytes: &'a [u8] },
}

#[derive(Debug, Clone)]
pub enum FilterOutcome {
    Allowed,
    Replace { body: Bytes, headers: HeaderMap },
    Blocked { message: String },
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
        let (body_bytes, query_url) = match input {
            FilterInput::HttpResponse { url, body } => (body.to_vec(), Some(url)),
            FilterInput::WsFrame { payload } => (payload.to_vec(), None),
            FilterInput::ToolPayload { bytes } => (bytes.to_vec(), None),
        };

        let mut request = self.http.post(&self.url).body(body_bytes);
        if let Some(url) = query_url {
            request = request.query(&[("url", url)]);
        }

        let response = request
            .send()
            .await
            .context("Trypanophobe filter request failed")?;

        let status = response.status();
        if !status.is_success() {
            return Ok(FilterOutcome::Blocked {
                message: self.block_message.clone(),
            });
        }

        if self.swap {
            let headers = response_headers(&response);
            let body = response.bytes().await.context("failed to read TPF body")?;
            return Ok(FilterOutcome::Replace { body, headers });
        }

        Ok(FilterOutcome::Allowed)
    }
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

    fn payload_settings(tpf: Option<&str>, swap: bool, payload: &str) -> crate::config::Settings {
        crate::config::Settings {
            bind: "127.0.0.1".parse().unwrap(),
            port: None,
            trypanophobe_filter: tpf.map(str::to_string),
            trypanophobe_swap: swap,
            payload: Some(payload.into()),
            filter: String::new(),
            ca_dir: std::path::PathBuf::from("/tmp/guardian-test"),
            filter_timeout_secs: 5,
            block_message: DEFAULT_BLOCK_MESSAGE.to_string(),
            port_min: 1024,
            port_max: 65535,
            proxy_ready_timeout_secs: 5,
            process_poll_interval_ms: 50,
            ca_bundle_name: "guardian-ca-bundle.pem".into(),
            java_truststore_name: "guardian-java-truststore.p12".into(),
            java_truststore_password: "guardian".into(),
            deno_tls_ca_store: "system,mozilla".into(),
            node_options_append: "--use-openssl-ca".into(),
            program: String::new(),
            args: vec![],
            trust_stores: vec!["system".into()],
            upstream_tls: Default::default(),
            skip_cert_regen: false,
        }
    }

    #[tokio::test]
    async fn content_filter_ws_frame_block_on_connection_error() {
        let client = TrypanophobeClient::new(
            "http://127.0.0.1:1/pass".into(),
            DEFAULT_BLOCK_MESSAGE.to_string(),
            5,
            false,
        )
        .expect("client");
        let verdict = client
            .check_ws_frame(proxyapi::content_filter::WsFilterContext {
                direction: "server_to_client",
                opcode: "text",
                payload: b"frame",
            })
            .await;
        assert!(matches!(verdict, FilterVerdict::Block { .. }));
    }

    #[tokio::test]
    async fn check_tool_payload_connection_error_returns_err() {
        let client = TrypanophobeClient::new(
            "http://127.0.0.1:1/pass".into(),
            DEFAULT_BLOCK_MESSAGE.to_string(),
            5,
            false,
        )
        .expect("client");
        let err = client
            .check(FilterInput::ToolPayload { bytes: b"x" })
            .await
            .expect_err("dead port should fail");
        assert!(err
            .to_string()
            .contains("Trypanophobe filter request failed"));
    }

    #[tokio::test]
    async fn content_filter_http_error_returns_block_with_error() {
        let client = TrypanophobeClient::new(
            "http://127.0.0.1:1/pass".into(),
            DEFAULT_BLOCK_MESSAGE.to_string(),
            5,
            false,
        )
        .expect("client");
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
    async fn run_payload_without_tpf_echoes() {
        let settings = payload_settings(None, false, "hello");
        assert_eq!(super::run_payload(&settings).await.unwrap(), 0);
    }
}
