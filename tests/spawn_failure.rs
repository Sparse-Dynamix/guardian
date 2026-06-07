mod common;

use common::guardian_bin;
use tempfile::TempDir;

#[test]
fn missing_child_program_exits_with_failure() {
    let ca_dir = TempDir::new().expect("ca dir");
    let status = std::process::Command::new(guardian_bin())
        .args([
            "--ca-dir",
            ca_dir.path().to_str().unwrap(),
            "--",
            "/nonexistent/guardian-child-binary",
        ])
        .status()
        .expect("spawn guardian");
    assert!(!status.success());
}
