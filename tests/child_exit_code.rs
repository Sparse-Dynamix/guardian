mod common;

use std::process::Command;
use std::process::Stdio;

use common::{guardian_bin, spawn_tpf_mock};
use tempfile::TempDir;

const EXPECTED_EXIT: i32 = 7;

fn exit_child_args() -> Vec<String> {
    vec![
        env!("CARGO_BIN_EXE_guardian-exit-code").to_string(),
        EXPECTED_EXIT.to_string(),
    ]
}

fn run_guardian(args: &[String]) -> i32 {
    let ca_dir = TempDir::new().expect("ca dir");
    let mut cmd = Command::new(guardian_bin());
    cmd.arg("--ca-dir")
        .arg(ca_dir.path())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn guardian");
    let mut stderr = String::new();
    if let Some(mut err) = child.stderr.take() {
        std::io::Read::read_to_string(&mut err, &mut stderr).unwrap();
    }
    let status = child.wait().expect("wait guardian");
    let code = status.code().unwrap_or(-1);
    assert_eq!(
        code, EXPECTED_EXIT,
        "guardian exit {code}, expected {EXPECTED_EXIT}; stderr:\n{stderr}"
    );
    code
}

#[test]
fn mitm_passthrough_propagates_nonzero_exit() {
    let mut args = vec!["--".to_string()];
    args.extend(exit_child_args());
    run_guardian(&args);
}

#[test]
fn mitm_filtered_propagates_nonzero_exit() {
    let _guard = common::acquire_mitm_test_lock();
    let tpf = spawn_tpf_mock();
    let mut args = vec!["--tpf".to_string(), tpf.pass_url.clone(), "--".to_string()];
    args.extend(exit_child_args());
    run_guardian(&args);
}
