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
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    #[derive(Default)]
    struct MockRecord {
        body: Vec<u8>,
        query: String,
    }

    fn wait_for_mock_ready(port: u16) {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("mock server did not start on port {port}");
    }

    fn write_mock_response(
        stream: &mut TcpStream,
        status: u16,
        body: &str,
        content_type: Option<&str>,
    ) {
        use std::net::Shutdown;

        let ct_line = content_type
            .map(|t| format!("Content-Type: {t}\r\n"))
            .unwrap_or_default();
        let response = format!(
            "HTTP/1.1 {status} OK\r\n{ct_line}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
        let _ = stream.shutdown(Shutdown::Write);
    }

    fn handle_mock_connection(
        mut stream: TcpStream,
        status: u16,
        body: &str,
        content_type: Option<&str>,
        record: Option<Arc<Mutex<MockRecord>>>,
    ) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        if !buf.is_empty() {
            let req = String::from_utf8_lossy(&buf);
            if req
                .lines()
                .next()
                .is_some_and(|line| line.starts_with("POST "))
            {
                if let Some(rec) = &record {
                    let query = req
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("")
                        .split('?')
                        .nth(1)
                        .unwrap_or("")
                        .to_string();
                    let body_start = req.find("\r\n\r\n").map(|i| i + 4).unwrap_or(buf.len());
                    let mut guard = rec.lock().expect("lock");
                    guard.query = query;
                    guard.body = buf[body_start..].to_vec();
                }
            }
        }

        write_mock_response(&mut stream, status, body, content_type);
    }

    fn spawn_mock(
        status: u16,
        body: &str,
        content_type: Option<&str>,
        record: Option<Arc<Mutex<MockRecord>>>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
        let port = listener.local_addr().expect("local addr").port();
        let body = body.to_string();
        let ct = content_type.map(str::to_string);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                handle_mock_connection(
                    stream,
                    status,
                    &body,
                    ct.as_deref(),
                    record.clone(),
                );
            }
        });
        wait_for_mock_ready(port);
        format!("http://127.0.0.1:{port}/pass")
    }

    fn client_for(url: &str, swap: bool) -> TrypanophobeClient {
        let http = Client::builder()
            .timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(0)
            .build()
            .expect("client");
        TrypanophobeClient {
            url: url.to_string(),
            block_message: DEFAULT_BLOCK_MESSAGE.to_string(),
            swap,
            http,
        }
    }

    #[tokio::test]
    async fn check_tool_payload_200_allowed_without_swap() {
        let url = spawn_mock(200, "", None, None);
        let client = client_for(&url, false);
        let outcome = client
            .check(FilterInput::ToolPayload { bytes: b"hello" })
            .await
            .expect("check");
        assert!(matches!(outcome, FilterOutcome::Allowed));
    }

    #[tokio::test]
    async fn check_tool_payload_reject_status_blocks() {
        let url = spawn_mock(503, "", None, None);
        let client = client_for(&url, false);
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
    async fn check_http_posts_raw_body_with_url_query() {
        let record = Arc::new(Mutex::new(MockRecord::default()));
        let url = spawn_mock(200, "", None, Some(record.clone()));
        let client = client_for(&url, false);
        let _ = client
            .check(FilterInput::HttpResponse {
                url: "http://example.com/path",
                body: b"response-bytes",
            })
            .await
            .expect("http check");
        let guard = record.lock().expect("lock");
        assert!(guard.query.contains("url="));
        assert!(guard.query.contains("example.com"));
        assert_eq!(guard.body, b"response-bytes");
    }

    #[tokio::test]
    async fn check_swap_returns_body_and_headers() {
        let url = spawn_mock(200, "swapped", Some("text/markdown"), None);
        let client = client_for(&url, true);
        let outcome = client
            .check(FilterInput::ToolPayload { bytes: b"x" })
            .await
            .expect("check");
        match outcome {
            FilterOutcome::Replace { body, headers } => {
                assert_eq!(&body[..], b"swapped");
                assert_eq!(
                    headers.get(http::header::CONTENT_TYPE).unwrap(),
                    "text/markdown"
                );
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[tokio::test]
    async fn content_filter_http_error_returns_block_with_error() {
        let client = client_for("http://127.0.0.1:1/pass", false);
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
    async fn run_payload_without_tpf_echoes() {
        let settings = payload_settings(None, false, "hello");
        assert_eq!(super::run_payload(&settings).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn run_payload_allowed_returns_zero() {
        let url = spawn_mock(200, "", None, None);
        let settings = payload_settings(Some(&url), false, "hello");
        assert_eq!(super::run_payload(&settings).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn run_payload_swap_returns_zero() {
        let url = spawn_mock(200, "swapped-out", Some("text/plain"), None);
        let settings = payload_settings(Some(&url), true, "hello");
        assert_eq!(super::run_payload(&settings).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn run_payload_blocked_returns_one() {
        let url = spawn_mock(503, "", None, None);
        let settings = payload_settings(Some(&url), false, "hello");
        assert_eq!(super::run_payload(&settings).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn content_filter_http_replace_on_swap() {
        let url = spawn_mock(200, "replaced", Some("text/plain"), None);
        let port = url
            .trim_start_matches("http://127.0.0.1:")
            .split('/')
            .next()
            .expect("mock port");
        wait_for_mock_ready(port.parse().expect("mock port"));
        let client = client_for(&url, true);
        let verdict = client
            .check_http_response(HttpFilterContext {
                method: "GET",
                url: "http://example.com/page",
                status: 200,
                scheme: "http",
                body: b"upstream",
            })
            .await;
        match verdict {
            FilterVerdict::Replace { body, headers } => {
                assert_eq!(&body[..], b"replaced");
                assert_eq!(
                    headers.get(http::header::CONTENT_TYPE).unwrap(),
                    "text/plain"
                );
            }
            other => panic!("unexpected verdict: {other:?}"),
        }
    }
}
