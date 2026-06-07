mod common;

use std::io::Read;
use std::process::Command;

use common::{guardian_bin, parse_jsonl, require_network, GuardianRun};
use tempfile::TempDir;

fn run_guardian_echo_env(var: &str, extra_env: &[(&str, &str)]) -> std::io::Result<GuardianRun> {
    let ca_dir = TempDir::new()?;
    let sh = common::resolve_executable("sh");
    let inner = format!("echo ${var}");
    let args = [
        "--ca-dir",
        ca_dir.path().to_str().unwrap(),
        "--",
        &sh,
        "-c",
        &inner,
    ];

    let mut cmd = Command::new(guardian_bin());
    let jdk = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".cache/jdk-17");
    if jdk.join("bin/keytool").is_file() {
        cmd.env("JAVA_HOME", &jdk);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.args(args);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut process = cmd.spawn()?;
    let mut stdout_bytes = Vec::new();
    let mut stderr = String::new();
    if let Some(mut out) = process.stdout.take() {
        out.read_to_end(&mut stdout_bytes)?;
    }
    if let Some(mut err) = process.stderr.take() {
        err.read_to_string(&mut stderr)?;
    }
    let status = process.wait()?;
    Ok(GuardianRun {
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: stderr.clone(),
        jsonl: parse_jsonl(&stderr),
        _ca_dir: ca_dir,
    })
}

#[test]
fn child_inherits_merged_node_options() {
    if !require_network() {
        return;
    }
    let run = run_guardian_echo_env("NODE_OPTIONS", &[("NODE_OPTIONS", "--max-old-space-size=128")])
        .expect("failed to spawn guardian");
    assert_eq!(run.exit_code, 0);
    assert!(
        run.stdout.contains("--use-openssl-ca"),
        "expected NODE_OPTIONS merge in child env: {}",
        run.stdout
    );
    assert!(
        run.stdout.contains("--max-old-space-size=128"),
        "expected existing NODE_OPTIONS preserved: {}",
        run.stdout
    );
}

#[test]
fn child_inherits_java_tool_options_when_jdk_available() {
    if !require_network() {
        return;
    }
    let jdk = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".cache/jdk-17");
    if !jdk.join("bin/keytool").is_file() {
        eprintln!("skipping: portable JDK not found at .cache/jdk-17");
        return;
    }
    let run = run_guardian_echo_env("JAVA_TOOL_OPTIONS", &[("JAVA_TOOL_OPTIONS", "-Dfoo=bar")])
        .expect("failed to spawn guardian");
    assert_eq!(run.exit_code, 0);
    assert!(
        run.stdout.contains("javax.net.ssl.trustStore="),
        "expected JAVA_TOOL_OPTIONS truststore flags: {}",
        run.stdout
    );
    assert!(
        run.stdout.contains("-Dfoo=bar"),
        "expected existing JAVA_TOOL_OPTIONS preserved: {}",
        run.stdout
    );
}

#[test]
fn child_inherits_ca_bundle_env() {
    if !require_network() {
        return;
    }
    let run = run_guardian_echo_env("CURL_CA_BUNDLE", &[])
        .expect("failed to spawn guardian");
    assert_eq!(run.exit_code, 0);
    assert!(
        run.stdout.contains("guardian-ca-bundle.pem"),
        "expected CA bundle path in child env: {}",
        run.stdout
    );
}
