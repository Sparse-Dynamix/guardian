use std::collections::HashMap;
use std::io::{self, Write};

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use proxyapi::event::ProxyEvent;
use proxyapi_models::{ProxiedRequest, ProxiedResponse};
use serde_json::{json, Value};

pub fn write_event(out: &mut impl Write, event: &ProxyEvent, body_limit: usize) -> Result<()> {
    let value = event_to_json(event, body_limit)?;
    if let Some(v) = value {
        serde_json::to_writer(&mut *out, &v)?;
        out.write_all(b"\n")?;
    }
    Ok(())
}

fn event_to_json(event: &ProxyEvent, body_limit: usize) -> Result<Option<Value>> {
    match event {
        ProxyEvent::RequestComplete {
            id,
            request,
            response,
        } => Ok(Some(json!({
            "type": "http",
            "id": id,
            "request": request_json(request, body_limit),
            "response": response_json(response, body_limit),
        }))),
        ProxyEvent::RequestIntercepted { .. } => Ok(None),
        ProxyEvent::Error { message } => Ok(Some(json!({
            "type": "error",
            "message": message,
        }))),
        ProxyEvent::WebSocketConnected {
            id,
            request,
            response,
        } => Ok(Some(json!({
            "type": "websocket_connect",
            "conn_id": id,
            "request": request_json(request, body_limit),
            "response": response_json(response, body_limit),
        }))),
        ProxyEvent::WebSocketFrame { conn_id, frame } => {
            use proxyapi_models::WsDirection;
            let payload = frame.payload.as_ref();
            let (preview, truncated, payload_b64) = payload_preview(payload, body_limit);
            let opcode = format!("{:?}", frame.opcode).to_lowercase();
            let direction = match frame.direction {
                WsDirection::ClientToServer => "client_to_server",
                WsDirection::ServerToClient => "server_to_client",
            };
            let mut obj = json!({
                "type": "websocket_frame",
                "conn_id": conn_id,
                "direction": direction,
                "opcode": opcode,
                "payload": preview,
                "payload_truncated": truncated || frame.truncated,
                "payload_len": payload.len(),
                "time_ms": frame.time,
            });
            if let Some(b64) = payload_b64 {
                obj["payload_b64"] = Value::String(b64);
            }
            Ok(Some(obj))
        }
        ProxyEvent::WebSocketClosed { conn_id } => Ok(Some(json!({
            "type": "websocket_close",
            "conn_id": conn_id,
        }))),
    }
}

fn headers_map(headers: &http::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or("<binary>").to_string(),
            )
        })
        .collect()
}

fn body_field(body: &[u8], limit: usize) -> (Value, bool, usize) {
    let full_len = body.len();
    let slice = if body.len() > limit { &body[..limit] } else { body };
    let truncated = full_len > limit;
    if let Ok(text) = std::str::from_utf8(slice) {
        (Value::String(text.to_string()), truncated, full_len)
    } else {
        (
            Value::String(STANDARD.encode(slice)),
            truncated,
            full_len,
        )
    }
}

fn request_json(req: &ProxiedRequest, limit: usize) -> Value {
    let (body, body_truncated, body_len) = body_field(req.body(), limit);
    json!({
        "method": req.method().as_str(),
        "uri": req.uri().to_string(),
        "headers": headers_map(req.headers()),
        "body": body,
        "body_truncated": body_truncated,
        "body_len": body_len,
        "time_ms": req.time(),
    })
}

fn response_json(resp: &ProxiedResponse, limit: usize) -> Value {
    let (body, body_truncated, body_len) = body_field(resp.body(), limit);
    json!({
        "status": resp.status().as_u16(),
        "headers": headers_map(resp.headers()),
        "body": body,
        "body_truncated": body_truncated,
        "body_len": body_len,
        "time_ms": resp.time(),
    })
}

fn payload_preview(payload: &[u8], limit: usize) -> (String, bool, Option<String>) {
    let truncated = payload.len() > limit;
    let slice = if truncated { &payload[..limit] } else { payload };
    if std::str::from_utf8(slice).is_ok() {
        (
            String::from_utf8_lossy(slice).into_owned(),
            truncated,
            None,
        )
    } else {
        (
            String::new(),
            truncated,
            Some(STANDARD.encode(slice)),
        )
    }
}

pub async fn run_sink(
    mut rx: tokio::sync::mpsc::Receiver<ProxyEvent>,
    silent: bool,
    body_limit: usize,
) {
    while let Some(event) = rx.recv().await {
        if silent {
            continue;
        }
        let mut stderr = io::stderr().lock();
        if let Err(e) = write_event(&mut stderr, &event, body_limit) {
            tracing::warn!("jsonl write failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{Method, StatusCode, Uri, Version};
    use proxyapi_models::ProxiedResponse;
    use std::str::FromStr;

    fn sample_request() -> ProxiedRequest {
        ProxiedRequest::new(
            Method::GET,
            Uri::from_str("https://example.com/path").unwrap(),
            Version::HTTP_11,
            http::HeaderMap::new(),
            Bytes::from_static(b"hello"),
            1_710_000_000_123,
        )
    }

    fn sample_response() -> ProxiedResponse {
        ProxiedResponse::new(
            StatusCode::OK,
            Version::HTTP_11,
            http::HeaderMap::new(),
            Bytes::from_static(b"world"),
            1_710_000_000_456,
        )
    }

    #[test]
    fn http_event_serializes() {
        let event = ProxyEvent::RequestComplete {
            id: 1,
            request: Box::new(sample_request()),
            response: Box::new(sample_response()),
        };
        let mut buf = Vec::new();
        write_event(&mut buf, &event, 256).unwrap();
        let line = String::from_utf8(buf).unwrap();
        assert!(line.starts_with('{'));
        let v: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["type"], "http");
        assert_eq!(v["request"]["method"], "GET");
    }

    #[test]
    fn truncates_body() {
        let big = vec![b'x'; 512];
        let req = ProxiedRequest::new(
            Method::POST,
            Uri::from_str("http://example.com").unwrap(),
            Version::HTTP_11,
            http::HeaderMap::new(),
            Bytes::from(big),
            0,
        );
        let event = ProxyEvent::RequestComplete {
            id: 2,
            request: Box::new(req),
            response: Box::new(sample_response()),
        };
        let mut buf = Vec::new();
        write_event(&mut buf, &event, 64).unwrap();
        let v: Value = serde_json::from_str(String::from_utf8(buf).unwrap().trim()).unwrap();
        assert_eq!(v["request"]["body_truncated"], true);
        assert_eq!(v["request"]["body_len"], 512);
    }

    #[test]
    fn skips_intercepted() {
        let event = ProxyEvent::RequestIntercepted {
            id: 3,
            request: Box::new(sample_request()),
        };
        let mut buf = Vec::new();
        write_event(&mut buf, &event, 256).unwrap();
        assert!(buf.is_empty());
    }
}
