mod common;

use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::Duration;

use common::{guardian_bin, spawn_tpf_mock};
use tempfile::TempDir;

const EXPECTED_EXIT: i32 = 7;
const MITM_EXIT_RETRIES: usize = 5;

fn exit_child_args() -> Vec<String> {
    vec![
        env!("CARGO_BIN_EXE_guardian-exit-code").to_string(),
        EXPECTED_EXIT.to_string(),
    ]
}

fn run_guardian_once(args: &[String]) -> (i32, String) {
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
    (status.code().unwrap_or(-1), stderr)
}

fn run_guardian(args: &[String]) {
    let (code, stderr) = run_guardian_once(args);
    assert_eq!(
        code, EXPECTED_EXIT,
        "guardian exit {code}, expected {EXPECTED_EXIT}; stderr:\n{stderr}"
    );
}

fn run_guardian_with_retry(args: &[String]) {
    let mut last = (0, String::new());
    for attempt in 0..MITM_EXIT_RETRIES {
        last = run_guardian_once(args);
        if last.0 == EXPECTED_EXIT {
            return;
        }
        if attempt + 1 < MITM_EXIT_RETRIES {
            thread::sleep(Duration::from_millis(2000));
        }
    }
    assert_eq!(
        last.0, EXPECTED_EXIT,
        "guardian exit {}, expected {EXPECTED_EXIT}; stderr:\n{}",
        last.0, last.1
    );
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
    run_guardian_with_retry(&args);
}
