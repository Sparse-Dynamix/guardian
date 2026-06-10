mod common;

use common::{spawn_test_servers, staged_curl_program, staged_sh_program, TestServersConfig};
use std::process::{Command, Stdio};
use tempfile::TempDir;

#[test]
#[cfg(target_os = "macos")]
fn shell_exec_replacement_surfaces_reinstrument_failure() {
    let Some(sh) = staged_sh_program() else {
        eprintln!("skipping: staged guardian-sh not found (run scripts/coverage-mac.zx.ts once)");
        return;
    };
    let Some(curl) = staged_curl_program() else {
        eprintln!("skipping: staged guardian-curl not found (run scripts/coverage-mac.zx.ts once)");
        return;
    };

    let servers = spawn_test_servers(TestServersConfig::default());
    let url = servers.http_get_url.clone();
    let inner = format!("{curl} -sSf '{url}'");

    let _mitm_guard = common::acquire_mitm_test_lock();
    let ca_dir = TempDir::new().expect("ca dir");
    let mut child = Command::new(common::guardian_bin());
    child.args([
        "--ca-dir",
        ca_dir.path().to_str().unwrap(),
        "--tpf",
        &servers.pass_url,
        "--",
        &sh,
        "-c",
        &inner,
    ]);
    child.stdin(Stdio::null());
    child.stdout(Stdio::piped());
    child.stderr(Stdio::piped());
    let mut process = child.spawn().expect("spawn guardian");
    let mut stderr = String::new();
    if let Some(mut err) = process.stderr.take() {
        std::io::Read::read_to_string(&mut err, &mut stderr).unwrap();
    }
    let _ = process.stdout.take();
    let status = process.wait().unwrap();

    assert_eq!(status.code(), Some(1), "stderr:\n{stderr}");
    assert!(
        stderr.contains("process replacement"),
        "expected process replacement re-instrument error; stderr:\n{stderr}"
    );
}
