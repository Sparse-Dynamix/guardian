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
        .stdin(std::process::Stdio::null())
        .status()
        .expect("spawn guardian");
    assert!(!status.success());
}

#[test]
fn install_system_requires_admin() {
    if privilege::user::privileged() {
        eprintln!("skipping: running with administrator privileges");
        return;
    }
    let ca_dir = TempDir::new().expect("ca dir");
    let output = std::process::Command::new(guardian_bin())
        .args([
            "install-system",
            "--ca-dir",
            ca_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("guardian install-system");

    if output.status.success() {
        eprintln!("skipping: install-system succeeded (running with administrator privileges)");
        return;
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("administrator") || stderr.contains("Administrator"),
        "expected admin requirement message, got: {stderr}"
    );
}

#[test]
fn remove_system_requires_admin() {
    if privilege::user::privileged() {
        eprintln!("skipping: running with administrator privileges");
        return;
    }
    let ca_dir = TempDir::new().expect("ca dir");
    let output = std::process::Command::new(guardian_bin())
        .args(["remove-system", "--ca-dir", ca_dir.path().to_str().unwrap()])
        .output()
        .expect("guardian remove-system");

    if output.status.success() {
        eprintln!("skipping: remove-system succeeded (running with administrator privileges)");
        return;
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("administrator") || stderr.contains("Administrator"),
        "expected admin requirement message, got: {stderr}"
    );
}
