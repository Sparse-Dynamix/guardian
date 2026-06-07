mod common;

use std::process::{Command, Stdio};

use common::{guardian_bin, curl_program};

/// Denylisted port 22 must not produce proxy HTTP JSONL events.
#[test]
fn ssh_port_not_intercepted() {
    let bin = guardian_bin();
    assert!(bin.is_file(), "guardian binary missing at {}", bin.display());

    let ca_dir = tempfile::TempDir::new().expect("tempdir");
    let curl = curl_program();

    let output = Command::new(&bin)
        .args([
            "--ca-dir",
            ca_dir.path().to_str().unwrap(),
            "--",
            &curl,
            "-sS",
            "--connect-timeout",
            "1",
            "http://127.0.0.1:22/",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to spawn guardian");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(r#""type":"http""#) && !stderr.contains(r#""type": "http""#),
        "denylisted port 22 should not produce http JSONL; stderr:\n{stderr}"
    );
}
