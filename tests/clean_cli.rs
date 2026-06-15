mod common;

use std::process::Command;

use common::guardian_bin;
use tempfile::TempDir;

#[test]
fn clean_subcommand_succeeds_for_empty_ca_dir() {
    let ca_dir = TempDir::new().expect("ca dir");
    let output = Command::new(guardian_bin())
        .args([
            "clean",
            "--ca-dir",
            ca_dir.path().to_str().expect("ca dir path"),
        ])
        .output()
        .expect("guardian clean");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn clean_subcommand_removes_marker_file() {
    let ca_dir = TempDir::new().expect("ca dir");
    let marker = ca_dir.path().join("marker.txt");
    std::fs::write(&marker, b"x").expect("write marker");

    let output = Command::new(guardian_bin())
        .args([
            "clean",
            "--ca-dir",
            ca_dir.path().to_str().expect("ca dir path"),
        ])
        .output()
        .expect("guardian clean");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!marker.exists(), "expected clean to remove ca dir contents");
}
