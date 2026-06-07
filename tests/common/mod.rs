//! Shared helpers for real end-to-end integration tests (no mocks).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;
use tempfile::TempDir;

const DEFAULT_SMOKE_URL: &str = "http://httpbin.org/get";

pub struct GuardianRun {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub jsonl: Vec<Value>,
    #[allow(dead_code)]
    pub _ca_dir: TempDir,
}

pub fn smoke_url() -> String {
    std::env::var("SMOKE_URL").unwrap_or_else(|_| DEFAULT_SMOKE_URL.to_string())
}

pub fn guardian_bin() -> PathBuf {
    if let Ok(path) = std::env::var("GUARDIAN_BIN") {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_guardian") {
        return PathBuf::from(path);
    }
    PathBuf::from("target/debug/guardian")
}

pub fn curl_program() -> String {
    resolve_executable(if cfg!(windows) { "curl.exe" } else { "curl" })
}

pub fn cmd_program() -> String {
    if cfg!(windows) {
        std::env::var("COMSPEC").unwrap_or_else(|_| resolve_executable("cmd.exe"))
    } else {
        resolve_executable("sh")
    }
}

pub fn resolve_executable(name: &str) -> String {
    let which = if cfg!(windows) { "where.exe" } else { "which" };
    Command::new(which)
        .arg(name)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.lines().next().unwrap_or(name).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| name.to_string())
}

fn resolve_ipv4(host: &str) -> Option<String> {
    Command::new("getent")
        .args(["ahostsv4", host])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|stdout| {
            stdout
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().next())
                .map(str::to_string)
        })
        .filter(|ip| !ip.is_empty())
}

fn curl_args(url: &str) -> Vec<String> {
    let mut args = vec![curl_program(), "-sSf".to_string()];
    let host = url_host(url);
    if let Some(ip) = resolve_ipv4(&host) {
        let port = if url.starts_with("https://") { "443" } else { "80" };
        args.push("--resolve".to_string());
        args.push(format!("{host}:{port}:{ip}"));
    }
    args.push(url.to_string());
    args
}

pub fn run_guardian_echo_env_var(
    var: &str,
    preset: &[(&str, &str)],
    java_home: Option<&Path>,
) -> std::io::Result<GuardianRun> {
    let ca_dir = TempDir::new()?;
    let child_args: Vec<String> = if cfg!(windows) {
        vec![
            cmd_program(),
            "/c".to_string(),
            format!("echo %{}%", var),
        ]
    } else {
        let sh = resolve_executable("sh");
        vec![
            sh,
            "-c".to_string(),
            format!("echo ${var}"),
        ]
    };

    let mut args = vec![
        "--ca-dir".to_string(),
        ca_dir.path().display().to_string(),
        "--".to_string(),
    ];
    args.extend(child_args);

    let mut cmd = Command::new(guardian_bin());
    if let Some(home) = java_home {
        if home.join("bin/keytool").is_file() {
            cmd.env("JAVA_HOME", home);
        }
    }
    for (k, v) in preset {
        cmd.env(k, v);
    }
    cmd.args(&args);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

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
    let jsonl = parse_jsonl(&stderr);
    Ok(GuardianRun {
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr,
        jsonl,
        _ca_dir: ca_dir,
    })
}

pub fn run_guardian_direct_https(silent: bool) -> std::io::Result<GuardianRun> {
    run_guardian_with_options(GuardianOptions {
        silent,
        ..GuardianOptions::default()
    })
}

pub struct GuardianOptions {
    pub silent: bool,
    pub verbose: bool,
    pub port: Option<u16>,
    pub body_limit: Option<usize>,
    pub url: Option<String>,
    pub config: Option<PathBuf>,
}

impl Default for GuardianOptions {
    fn default() -> Self {
        Self {
            silent: false,
            verbose: false,
            port: None,
            body_limit: None,
            url: None,
            config: None,
        }
    }
}

pub fn run_guardian_with_options(opts: GuardianOptions) -> std::io::Result<GuardianRun> {
    let url = opts.url.unwrap_or_else(smoke_url);
    let mut args = Vec::new();
    if opts.silent {
        args.push("--silent".to_string());
    }
    if opts.verbose {
        args.push("-v".to_string());
    }
    if let Some(port) = opts.port {
        args.push("--port".to_string());
        args.push(port.to_string());
    }
    if let Some(limit) = opts.body_limit {
        args.push("--body-limit".to_string());
        args.push(limit.to_string());
    }
    if let Some(config) = &opts.config {
        args.push("--config".to_string());
        args.push(config.display().to_string());
    }
    args.push("--ca-dir".to_string());
    let ca_dir = TempDir::new()?;
    args.push(ca_dir.path().display().to_string());
    args.push("--".to_string());
    args.extend(curl_args(&url));
    let extra_env = if opts.verbose {
        vec![("RUST_LOG", "guardian=trace")]
    } else {
        vec![]
    };
    run_guardian_with_args(&args, ca_dir, &extra_env)
}

pub fn run_guardian_child_spawn(silent: bool) -> std::io::Result<GuardianRun> {
    let url = smoke_url();
    let mut args = Vec::new();
    if silent {
        args.push("--silent".to_string());
    }
    args.push("--ca-dir".to_string());
    let ca_dir = TempDir::new()?;
    args.push(ca_dir.path().display().to_string());
    args.push("--".to_string());

    let host = url_host(&url);
    let port = if url.starts_with("https://") { "443" } else { "80" };

    if cfg!(windows) {
        args.push(cmd_program());
        args.push("/c".to_string());
        args.push(curl_program());
        args.push("-sSf".to_string());
        if let Some(ip) = resolve_ipv4(&host) {
            args.push("--resolve".to_string());
            args.push(format!("{host}:{port}:{ip}"));
        }
        args.push(url);
    } else {
        let resolve = resolve_ipv4(&host)
            .map(|ip| format!("--resolve {host}:{port}:{ip}"))
            .unwrap_or_default();
        let sh = resolve_executable("sh");
        let inner = format!("{} -sSf {} '{}'", curl_program(), resolve, url);
        args.push(sh);
        args.push("-c".to_string());
        args.push(inner);
    }

    run_guardian_with_args(&args, ca_dir, &[])
}

fn run_guardian_with_args(
    args: &[String],
    ca_dir: TempDir,
    extra_env: &[(&str, &str)],
) -> std::io::Result<GuardianRun> {
    let bin = guardian_bin();
    assert!(
        bin.is_file(),
        "guardian binary not found at {} — run `cargo build` first",
        bin.display()
    );

    let mut child = Command::new(&bin);
    child.args(args);
    for (key, value) in extra_env {
        child.env(key, value);
    }
    child.stdout(Stdio::piped());
    child.stderr(Stdio::piped());

    let mut process = child.spawn()?;

    let mut stdout_bytes = Vec::new();
    let mut stderr = String::new();
    if let Some(mut out) = process.stdout.take() {
        out.read_to_end(&mut stdout_bytes)?;
    }
    if let Some(mut err) = process.stderr.take() {
        err.read_to_string(&mut stderr)?;
    }
    let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();

    let status = process.wait()?;
    let exit_code = status.code().unwrap_or(-1);
    let jsonl = parse_jsonl(&stderr);

    Ok(GuardianRun {
        exit_code,
        stdout,
        stderr,
        jsonl,
        _ca_dir: ca_dir,
    })
}

pub fn parse_jsonl(stderr: &str) -> Vec<Value> {
    stderr
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('{') {
                serde_json::from_str(trimmed).ok()
            } else {
                None
            }
        })
        .collect()
}

pub fn assert_http_jsonl(run: &GuardianRun) {
    assert_eq!(
        run.exit_code, 0,
        "guardian exited with {}; stderr:\n{}",
        run.exit_code, run.stderr
    );
    assert!(
        !run.stdout.trim().is_empty(),
        "expected non-empty child stdout; stderr:\n{}",
        run.stderr
    );
    let http_events: Vec<_> = run
        .jsonl
        .iter()
        .filter(|v| v.get("type").and_then(|t| t.as_str()) == Some("http"))
        .collect();
    assert!(
        !http_events.is_empty(),
        "expected at least one http JSONL event; stderr:\n{}",
        run.stderr
    );
    let url = smoke_url();
    let host = url_host(&url);
    let matched = http_events.iter().any(|ev| {
        ev.get("request")
            .and_then(|r| r.get("uri"))
            .and_then(|u| u.as_str())
            .is_some_and(|uri| uri.contains(&host))
    });
    assert!(
        matched,
        "expected request.uri to reference {host}; events: {http_events:?}"
    );
}

pub fn url_host(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("httpbin.org")
        .to_string()
}

/// Integration tests need network; skip quickly when offline.
pub fn require_network() -> bool {
    if std::env::var("GUARDIAN_SKIP_NETWORK").is_ok() {
        return false;
    }
    let curl = curl_program();
    let probe_url = smoke_url();
    let mut probe_args = curl_args(&probe_url);
    probe_args.insert(1, "--connect-timeout".to_string());
    probe_args.insert(2, "5".to_string());
    let probe = Command::new(&curl)
        .args(&probe_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    probe.map(|s| s.success()).unwrap_or(false)
}

#[allow(dead_code)]
pub fn smoke_timeout() -> Duration {
    Duration::from_secs(120)
}

#[allow(dead_code)]
pub fn assert_bin_under(path: &Path) {
    assert!(path.is_file(), "missing binary at {}", path.display());
}
