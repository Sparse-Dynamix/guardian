mod common;

use std::fs;
use std::io::Read;

use common::{assert_child_success, assert_no_jsonl_stderr, require_network};
use tempfile::TempDir;

#[test]
fn binary_post_passthrough_succeeds() {
    if !require_network() {
        return;
    }

    let payload_dir = TempDir::new().expect("payload dir");
    let payload_path = payload_dir.path().join("payload.bin");
    let bytes: Vec<u8> = (0..=255).collect();
    fs::write(&payload_path, &bytes).expect("write payload");

    let curl = common::curl_program();
    let ca_dir = TempDir::new().expect("ca dir");
    let args = vec![
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
        .stdin(std::process::Stdio::null())
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
    let run = common::GuardianRun {
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr,
        _ca_dir: ca_dir,
    };
    assert_child_success(&run);
    assert_no_jsonl_stderr(&run);
}
