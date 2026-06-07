mod common;

use common::{
    require_network, smoke_url, staged_curl_program, staged_sh_program, url_host,
    resolve_ipv4,
};
use std::process::{Command, Stdio};
use tempfile::TempDir;

#[test]
#[cfg(target_os = "macos")]
fn shell_exec_replacement_surfaces_reinstrument_failure() {
    if !require_network() {
        return;
    }
    let Some(sh) = staged_sh_program() else {
        eprintln!("skipping: staged guardian-sh not found (run coverage-mac.sh once)");
        return;
    };
    let Some(curl) = staged_curl_program() else {
        eprintln!("skipping: staged guardian-curl not found (run coverage-mac.sh once)");
        return;
    };

    let url = smoke_url();
    let host = url_host(&url);
    let port = if url.starts_with("https://") { "443" } else { "80" };
    let resolve = resolve_ipv4(&host)
        .map(|ip| format!("--resolve {host}:{port}:{ip}"))
        .unwrap_or_default();
    let inner = format!("{curl} -sSf {resolve} '{url}'");

    let ca_dir = TempDir::new().expect("ca dir");
    let mut child = Command::new(common::guardian_bin());
    child.args([
        "--ca-dir",
        ca_dir.path().to_str().unwrap(),
        "--",
        &sh,
        "-c",
        &inner,
    ]);
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
