mod common;

use std::process::Command;

use common::{guardian_bin, require_network};
use proxyapi::ca::Ssl;
use tempfile::TempDir;

#[test]
fn check_system_honors_no_color_flag() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let ca_dir = TempDir::new().expect("ca dir");
    Ssl::load_or_generate(ca_dir.path()).expect("generate CA");

    let output = Command::new(guardian_bin())
        .args([
            "check-system",
            "--no-color",
            "--ca-dir",
            ca_dir.path().to_str().unwrap(),
            "--stores",
            "system",
        ])
        .output()
        .expect("guardian check-system --no-color");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("\x1b["),
        "expected plain stderr without ANSI color codes"
    );
}
