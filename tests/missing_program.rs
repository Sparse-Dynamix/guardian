mod common;

use std::process::Command;

use common::guardian_bin;

#[test]
fn run_mode_requires_child_program() {
    let output = Command::new(guardian_bin())
        .output()
        .expect("guardian with no args");

    assert!(
        !output.status.success(),
        "expected guardian without a child program to fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("program is required"),
        "expected missing program error, got: {stderr}"
    );
}
