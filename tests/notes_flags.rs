mod common;

use std::process::Command;

use common::guardian_bin;

#[test]
fn legal_notes_prints_notice() {
    let output = Command::new(guardian_bin())
        .arg("legal-notes")
        .output()
        .expect("guardian legal-notes");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("PART 1"),
        "expected NOTICE content, got: {}",
        &stdout[..stdout.len().min(200)]
    );
}

#[test]
fn license_notes_prints_gpl() {
    let output = Command::new(guardian_bin())
        .arg("license-notes")
        .output()
        .expect("guardian license-notes");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("GNU GENERAL PUBLIC LICENSE"));
}

#[test]
fn security_notes_prints_security_md() {
    let output = Command::new(guardian_bin())
        .arg("security-notes")
        .output()
        .expect("guardian security-notes");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Security model"));
}
