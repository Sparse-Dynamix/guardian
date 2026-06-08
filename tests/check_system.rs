mod common;

use std::process::Command;

use common::{guardian_bin, require_network};
use proxyapi::ca::Ssl;
use tempfile::TempDir;

#[test]
fn check_system_reports_missing_install() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let ca_dir = TempDir::new().expect("ca dir");
    Ssl::load_or_generate(ca_dir.path()).expect("generate CA");

    let output = Command::new(guardian_bin())
        .args([
            "check-system",
            "--ca-dir",
            ca_dir.path().to_str().unwrap(),
            "--stores",
            "system",
        ])
        .output()
        .expect("guardian check-system");

    assert!(
        !output.status.success(),
        "expected check-system to fail when CA is not installed in system store"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("system") && stderr.contains("not installed"),
        "expected system store warning, got: {stderr}"
    );
}
