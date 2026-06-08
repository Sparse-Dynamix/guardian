mod common;

use std::fs;
use std::io::Read;

use common::require_network;
use tempfile::TempDir;

#[test]
fn binary_request_body_serializes_in_jsonl() {
    if !require_network() {
        return;
    }

    let payload_dir = TempDir::new().expect("payload dir");
    let payload_path = payload_dir.path().join("payload.bin");
    let bytes: Vec<u8> = (0..=255).collect();
    fs::write(&payload_path, &bytes).expect("write payload");

    let mut last_stderr = String::new();
    for _attempt in 1..=3 {
        let curl = common::curl_program();
        let ca_dir = TempDir::new().expect("ca dir");
        let args = vec![
            "--body-limit".to_string(),
            "48".to_string(),
            "--ca-dir".to_string(),
            ca_dir.path().display().to_string(),
            "--".to_string(),
            curl,
            "-sS".to_string(),
            "--ipv4".to_string(),
            "-X".to_string(),
            "POST".to_string(),
            "--data-binary".to_string(),
            format!("@{}", payload_path.display()),
            "http://httpbingo.org/post".to_string(),
        ];

        let bin = common::guardian_bin();
        let mut child = std::process::Command::new(&bin)
            .args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn guardian");
        let mut stdout_bytes = Vec::new();
        let mut stderr = String::new();
        if let Some(mut out) = child.stdout.take() {
            out.read_to_end(&mut stdout_bytes).unwrap();
        }
        if let Some(mut err) = child.stderr.take() {
            err.read_to_string(&mut stderr).unwrap();
        }
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(0), "stderr:\n{stderr}");

        let jsonl = common::parse_jsonl(&stderr);
        let req_body = jsonl
            .iter()
            .find(|v| v.get("type").and_then(|t| t.as_str()) == Some("http"))
            .and_then(|http| {
                http.get("request")
                    .and_then(|r| r.get("body"))
                    .and_then(|b| b.as_str())
            });
        if req_body.is_some_and(|body| !body.is_empty()) {
            return;
        }
        last_stderr = stderr;
    }

    panic!("expected non-empty serialized request body preview; stderr:\n{last_stderr}");
}
