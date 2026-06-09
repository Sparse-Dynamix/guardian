mod common;

use std::io::Read;

use common::{assert_child_success, assert_no_jsonl_stderr, guardian_bin, require_network};
use tempfile::TempDir;

fn ws_smoke_bin() -> std::path::PathBuf {
    std::env::var("CARGO_BIN_EXE_guardian-ws-smoke")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("target/debug/guardian-ws-smoke"))
}

#[test]
fn wss_echo_passthrough_runs_child() {
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
    let mut child = std::process::Command::new(guardian_bin());
    child.args([
        "--ca-dir",
        ca_dir.path().to_str().unwrap(),
        "--",
        ws_bin.to_str().unwrap(),
        "wss://echo.websocket.org/",
    ]);
    child.stdin(std::process::Stdio::null());
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
    let run = common::GuardianRun {
        exit_code: status.code().unwrap_or(-1),
        stdout,
        stderr,
        _ca_dir: ca_dir,
    };
    assert_child_success(&run);
    assert_no_jsonl_stderr(&run);
}
