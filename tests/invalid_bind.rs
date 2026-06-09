mod common;

use common::guardian_bin;
use tempfile::TempDir;

#[test]
fn rejects_ipv6_bind_before_spawn() {
    let ca_dir = TempDir::new().expect("ca dir");
    let status = std::process::Command::new(guardian_bin())
        .args([
            "--bind",
            "::1",
            "--ca-dir",
            ca_dir.path().to_str().unwrap(),
            "--",
            "true",
        ])
        .stdin(std::process::Stdio::null())
        .status()
        .expect("spawn guardian");
    assert!(!status.success());
}

#[test]
fn rejects_invalid_bind_string() {
    let ca_dir = TempDir::new().expect("ca dir");
    let status = std::process::Command::new(guardian_bin())
        .args([
            "--bind",
            "not-an-ip",
            "--ca-dir",
            ca_dir.path().to_str().unwrap(),
            "--",
            "true",
        ])
        .stdin(std::process::Stdio::null())
        .status()
        .expect("spawn guardian");
    assert!(!status.success());
}
