mod common;

use std::io::Read;

use common::{guardian_bin, parse_jsonl, require_network};
use tempfile::TempDir;

fn ws_smoke_bin() -> std::path::PathBuf {
    std::env::var("CARGO_BIN_EXE_guardian-ws-smoke")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("target/debug/guardian-ws-smoke"))
}

#[test]
fn wss_echo_logs_websocket_jsonl() {
    if !require_network() {
        return;
    }
    let ws_bin = ws_smoke_bin();
    assert!(
        ws_bin.is_file(),
        "guardian-ws-smoke not found at {} — build with --features ws-smoke",
        ws_bin.display()
    );

    let ca_dir = TempDir::new().expect("ca dir");
    let mut last_stderr = String::new();
    for attempt in 0..3 {
        let mut child = std::process::Command::new(guardian_bin());
        child.args([
            "--ca-dir",
            ca_dir.path().to_str().unwrap(),
            "--",
            ws_bin.to_str().unwrap(),
            "wss://echo.websocket.org/",
        ]);
        child.stdout(std::process::Stdio::piped());
        child.stderr(std::process::Stdio::piped());
        let mut process = child.spawn().expect("spawn guardian");
        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(mut out) = process.stdout.take() {
            out.read_to_string(&mut stdout).unwrap();
        }
        if let Some(mut err) = process.stderr.take() {
            err.read_to_string(&mut stderr).unwrap();
        }
        let status = process.wait().unwrap();
        last_stderr = stderr.clone();
        if status.code() == Some(0) && !stdout.trim().is_empty() {
            let jsonl = parse_jsonl(&stderr);
            let types: Vec<_> = jsonl
                .iter()
                .filter_map(|v| v.get("type").and_then(|t| t.as_str()))
                .collect();
            assert!(
                types.contains(&"websocket_connect"),
                "expected websocket_connect JSONL; got {types:?}"
            );
            assert!(
                types.contains(&"websocket_frame"),
                "expected websocket_frame JSONL; got {types:?}"
            );
            return;
        }
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }
    panic!("websocket smoke failed after retries; last stderr:\n{last_stderr}");
}
