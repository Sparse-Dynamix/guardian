mod common;

use std::io::Read;
use std::process::Command;

use common::{guardian_bin, parse_jsonl, require_network, GuardianRun};
use tempfile::TempDir;

fn run_guardian_echo(var: &str, preset: &[(&str, &str)]) -> std::io::Result<GuardianRun> {
    run_guardian_echo_with_java(var, preset, std::path::Path::new(""))
}

fn run_guardian_echo_with_java(
    var: &str,
    preset: &[(&str, &str)],
    java_home: &std::path::Path,
) -> std::io::Result<GuardianRun> {
    let ca_dir = TempDir::new()?;
    let sh = common::resolve_executable("sh");
    let inner = format!("echo ${var}");
    let mut cmd = Command::new(guardian_bin());
    if java_home.join("bin/keytool").is_file() {
        cmd.env("JAVA_HOME", java_home);
    }
    for (k, v) in preset {
        cmd.env(k, v);
    }
    cmd.args([
        "--ca-dir",
        ca_dir.path().to_str().unwrap(),
        "--",
        &sh,
        "-c",
        &inner,
    ]);
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
fn skips_ca_env_when_parent_already_sets_bundle() {
    if !require_network() {
        return;
    }
    let run = run_guardian_echo("CURL_CA_BUNDLE", &[("CURL_CA_BUNDLE", "/etc/ssl/certs/ca.pem")])
        .expect("spawn guardian");
    assert_eq!(run.exit_code, 0);
    assert_eq!(run.stdout.trim(), "/etc/ssl/certs/ca.pem");
}

#[test]
fn skips_java_tool_options_when_truststore_already_set() {
    if !require_network() {
        return;
    }
    let jdk = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".cache/jdk-17");
    if !jdk.join("bin/keytool").is_file() {
        eprintln!("skipping: portable JDK not found at .cache/jdk-17");
        return;
    }
    let existing = "-Djavax.net.ssl.trustStore=/existing.p12 -Dfoo=bar";
    let run = run_guardian_echo_with_java(
        "JAVA_TOOL_OPTIONS",
        &[("JAVA_TOOL_OPTIONS", existing)],
        &jdk,
    )
    .expect("spawn guardian");
    assert_eq!(run.exit_code, 0);
    assert_eq!(run.stdout.trim(), existing);
}

#[test]
fn skips_node_options_when_flag_already_present() {
    if !require_network() {
        return;
    }
    let run = run_guardian_echo(
        "NODE_OPTIONS",
        &[("NODE_OPTIONS", "--use-openssl-ca --max-old-space-size=64")],
    )
    .expect("spawn guardian");
    assert_eq!(run.exit_code, 0);
    assert_eq!(
        run.stdout.trim(),
        "--use-openssl-ca --max-old-space-size=64"
    );
}
