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

    let host = common::url_host("http://httpbin.org/post");
    let ip = std::process::Command::new("getent")
        .args(["ahostsv4", &host])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.lines()
                .next()
                .and_then(|l| l.split_whitespace().next())
                .map(str::to_string)
        });

    let curl = common::curl_program();
    let ca_dir = TempDir::new().expect("ca dir");
    let mut args = vec![
        "--body-limit".to_string(),
        "48".to_string(),
        "--ca-dir".to_string(),
        ca_dir.path().display().to_string(),
        "--".to_string(),
        curl,
        "-sSf".to_string(),
        "-X".to_string(),
        "POST".to_string(),
        "--data-binary".to_string(),
        format!("@{}", payload_path.display()),
    ];
    if let Some(ip) = ip {
        args.push("--resolve".to_string());
        args.push(format!("{host}:80:{ip}"));
    }
    args.push("http://httpbin.org/post".to_string());

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
    let http = jsonl
        .iter()
        .find(|v| v.get("type").and_then(|t| t.as_str()) == Some("http"))
        .expect("http JSONL event");
    let req_body = http
        .get("request")
        .and_then(|r| r.get("body"))
        .and_then(|b| b.as_str())
        .expect("request body preview");
    assert!(
        !req_body.is_empty(),
        "expected non-empty serialized request body preview"
    );
}
