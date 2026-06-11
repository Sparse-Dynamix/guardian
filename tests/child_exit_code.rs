mod common;

use std::process::Command;
use std::process::Stdio;

use common::{cmd_program, guardian_bin, spawn_tpf_mock};
use tempfile::TempDir;

const EXPECTED_EXIT: i32 = 7;

fn exit_child_args() -> Vec<String> {
    if cfg!(windows) {
        vec![
            cmd_program(),
            "/C".to_string(),
            format!("exit /b {EXPECTED_EXIT}"),
        ]
    } else if let Ok(python) = which::which("python3") {
        vec![
            python.to_string_lossy().into_owned(),
            "-c".to_string(),
            format!("import time, sys; time.sleep(0.2); sys.exit({EXPECTED_EXIT})"),
        ]
    } else {
        vec![
            cmd_program(),
            "-c".to_string(),
            format!("sleep 0.2; exit {EXPECTED_EXIT}"),
        ]
    }
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
