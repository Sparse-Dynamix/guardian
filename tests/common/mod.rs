//! Shared helpers for real end-to-end integration tests (no mocks).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tempfile::TempDir;

const DEFAULT_SMOKE_URL: &str = "http://httpbingo.org/get";
const DEFAULT_HTTPS_SMOKE_URL: &str = "https://httpbingo.org/get";

#[derive(Clone, Default, Debug)]
pub struct RecordedTpfRequest {
    pub path_and_query: String,
    pub body: Vec<u8>,
}

pub struct GuardianRun {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    #[allow(dead_code)]
    pub _ca_dir: TempDir,
}

pub fn smoke_url() -> String {
    std::env::var("SMOKE_URL").unwrap_or_else(|_| DEFAULT_SMOKE_URL.to_string())
}

pub fn smoke_https_url() -> String {
    std::env::var("SMOKE_HTTPS_URL").unwrap_or_else(|_| DEFAULT_HTTPS_SMOKE_URL.to_string())
}

pub fn portable_jdk_home() -> Option<PathBuf> {
    let jdk = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".cache/jdk-17");
    let keytool = if cfg!(windows) {
        jdk.join("bin/keytool.exe")
    } else {
        jdk.join("bin/keytool")
    };
    keytool.is_file().then_some(jdk)
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
    if let Some(curl) = staged_curl_program() {
        return curl;
    }
    resolve_executable(if cfg!(windows) { "curl.exe" } else { "curl" })
}

pub fn cmd_program() -> String {
    if cfg!(windows) {
        std::env::var("COMSPEC").unwrap_or_else(|_| resolve_executable("cmd.exe"))
    } else {
        resolve_executable("sh")
    }
}

pub fn child_wrapper_program() -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for sub in ["target/debug/guardian-env", "target/release/guardian-env"] {
        let path = manifest.join(sub);
        if path.is_file() {
            return Some(path.display().to_string());
        }
    }
    None
}

fn staged_mac_binary(name: &str) -> Option<String> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for sub in [
        format!("target/debug/{name}"),
        format!("target/release/{name}"),
    ] {
        let path = manifest.join(&sub);
        if path.is_file() {
            return Some(path.display().to_string());
        }
    }
    None
}

pub fn staged_printenv_program() -> Option<String> {
    if cfg!(target_os = "macos") {
        staged_mac_binary("guardian-printenv")
    } else {
        None
    }
}

pub fn staged_curl_program() -> Option<String> {
    if cfg!(target_os = "macos") {
        staged_mac_binary("guardian-curl")
    } else {
        None
    }
}

pub fn staged_sh_program() -> Option<String> {
    if cfg!(target_os = "macos") {
        staged_mac_binary("guardian-sh")
    } else {
        None
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

fn curl_args(url: &str, ca_dir: Option<&Path>, include_headers: bool) -> Vec<String> {
    let mut args = vec![curl_program(), "-sS".to_string()];
    if include_headers {
        args.push("-i".to_string());
    }
    if cfg!(target_os = "macos") {
        args.push("--ipv4".to_string());
    }
    if cfg!(windows) && url.starts_with("https://") {
        args.push("--ipv4".to_string());
        args.push("--ssl-no-revoke".to_string());
        if let Some(ca_dir) = ca_dir {
            args.push("--cacert".to_string());
            args.push(ca_dir.join("guardian-ca-bundle.pem").display().to_string());
        }
    }
    args.push(url.to_string());
    args
}

pub fn run_guardian_echo_env_var(
    var: &str,
    preset: &[(&str, &str)],
    java_home: Option<&Path>,
    tpf_url: Option<&str>,
) -> std::io::Result<GuardianRun> {
    let ca_dir = TempDir::new()?;
    let child_args: Vec<String> = if cfg!(windows) {
        vec![cmd_program(), "/c".to_string(), format!("echo %{}%", var)]
    } else if let Some(printenv) = staged_printenv_program() {
        vec![printenv, var.to_string()]
    } else {
        let sh = resolve_executable("sh");
        vec![sh, "-c".to_string(), format!("echo ${var}")]
    };

    let mut args = vec!["--ca-dir".to_string(), ca_dir.path().display().to_string()];
    if let Some(url) = tpf_url {
        args.push("--tpf".to_string());
        args.push(url.to_string());
    }
    args.push("--".to_string());
    args.extend(child_args);

    let mut cmd = Command::new(guardian_bin());
    if let Some(home) = java_home {
        cmd.env("JAVA_HOME", home);
    }
    for (k, v) in preset {
        cmd.env(k, v);
    }
    cmd.args(&args);
    cmd.stdin(Stdio::null());
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
    Ok(GuardianRun {
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr,
        _ca_dir: ca_dir,
    })
}

pub fn run_guardian_direct_https() -> std::io::Result<GuardianRun> {
    run_guardian_with_options(GuardianOptions {
        url: Some(smoke_https_url()),
        ..GuardianOptions::default()
    })
}

#[derive(Clone)]
pub struct GuardianOptions {
    pub port: Option<u16>,
    pub url: Option<String>,
    pub config: Option<PathBuf>,
    pub trypanophobe_filter: Option<String>,
    pub trypanophobe_swap: bool,
    pub curl_include_headers: bool,
}

impl Default for GuardianOptions {
    fn default() -> Self {
        Self {
            port: None,
            url: None,
            config: None,
            trypanophobe_filter: None,
            trypanophobe_swap: false,
            curl_include_headers: false,
        }
    }
}

pub fn run_guardian_with_options(opts: GuardianOptions) -> std::io::Result<GuardianRun> {
    run_guardian_http_with_retry(
        || run_guardian_with_options_once(&opts),
        |run| child_stdout_ok(run),
    )
}

fn run_guardian_with_options_once(opts: &GuardianOptions) -> std::io::Result<GuardianRun> {
    let url = opts.url.clone().unwrap_or_else(smoke_url);
    let mut args = Vec::new();
    if let Some(port) = opts.port {
        args.push("--port".to_string());
        args.push(port.to_string());
    }
    if let Some(config) = &opts.config {
        args.push("--config".to_string());
        args.push(config.display().to_string());
    }
    if let Some(tpf) = &opts.trypanophobe_filter {
        args.push("--tpf".to_string());
        args.push(tpf.clone());
    }
    if opts.trypanophobe_swap {
        args.push("--tps".to_string());
    }
    args.push("--ca-dir".to_string());
    let ca_dir = TempDir::new()?;
    args.push(ca_dir.path().display().to_string());
    args.push("--".to_string());
    let ca_bundle = opts.trypanophobe_filter.is_some().then(|| ca_dir.path());
    args.extend(curl_args(&url, ca_bundle, opts.curl_include_headers));
    run_guardian_with_args(&args, ca_dir, &[])
}

pub fn run_guardian_child_spawn() -> std::io::Result<GuardianRun> {
    run_guardian_http_with_retry(
        || run_guardian_child_spawn_once(),
        |run| child_stdout_ok(run),
    )
}

fn run_guardian_child_spawn_once() -> std::io::Result<GuardianRun> {
    let url = smoke_url();
    let mut args = Vec::new();
    args.push("--ca-dir".to_string());
    let ca_dir = TempDir::new()?;
    args.push(ca_dir.path().display().to_string());
    args.push("--".to_string());

    if cfg!(windows) {
        args.push(cmd_program());
        args.push("/c".to_string());
        args.push(curl_program());
        args.push("-sS".to_string());
        args.push(url);
    } else if let Some(wrapper) = child_wrapper_program() {
        args.push(wrapper);
        args.push(curl_program());
        args.push("-sS".to_string());
        args.push(url);
    } else {
        let sh = resolve_executable("sh");
        let inner = format!("{} -sS '{}'", curl_program(), url);
        args.push(sh);
        args.push("-c".to_string());
        args.push(inner);
    }

    run_guardian_with_args(&args, ca_dir, &[])
}

pub struct TpfMockServer {
    pub pass_url: String,
    pub reject_url: String,
    pub swap_url: String,
    pub last_request: Arc<Mutex<RecordedTpfRequest>>,
    pub requests: Arc<Mutex<Vec<RecordedTpfRequest>>>,
    _thread: std::thread::JoinHandle<()>,
}

fn parse_http_request(buf: &[u8]) -> (String, Vec<u8>) {
    let n = buf.len();
    let text = String::from_utf8_lossy(buf);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let path_and_query = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let mut content_length = 0usize;
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix("Content-Length:") {
            content_length = rest.trim().parse().unwrap_or(0);
        }
    }
    let header_end = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(buf.len());
    let body = if content_length > 0 {
        buf[header_end..header_end.saturating_add(content_length)].to_vec()
    } else {
        buf[header_end..n].to_vec()
    };
    (path_and_query, body)
}

pub fn spawn_tpf_mock() -> TpfMockServer {
    spawn_tpf_mock_with_swap_body(b"SWAPPED_BODY")
}

pub fn spawn_tpf_mock_with_swap_body(swap_body: &[u8]) -> TpfMockServer {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tpf mock");
    let port = listener.local_addr().expect("local addr").port();
    let base = format!("http://127.0.0.1:{port}");
    let pass_url = format!("{base}/pass");
    let reject_url = format!("{base}/reject");
    let swap_url = format!("{base}/swap");
    let last_request = Arc::new(Mutex::new(RecordedTpfRequest::default()));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let swap_body = swap_body.to_vec();
    listener.set_nonblocking(true).expect("set_nonblocking");
    let last = Arc::clone(&last_request);
    let all = Arc::clone(&requests);
    let thread = thread::spawn(move || loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut buf = [0u8; 65536];
                let n = stream.read(&mut buf).unwrap_or(0);
                let (path_and_query, body) = parse_http_request(&buf[..n]);
                let recorded = RecordedTpfRequest {
                    path_and_query: path_and_query.clone(),
                    body: body.clone(),
                };
                {
                    let mut last = last.lock().unwrap();
                    *last = recorded.clone();
                    all.lock().unwrap().push(recorded);
                }
                let path = path_and_query.split('?').next().unwrap_or("");
                let (status, resp_body, content_type) = if path.ends_with("/reject") {
                    (503, Vec::new(), "text/plain")
                } else if path.ends_with("/swap") {
                    (200, swap_body.clone(), "text/markdown; charset=utf-8")
                } else {
                    (200, Vec::new(), "text/plain")
                };
                let response = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    resp_body.len(),
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(&resp_body);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    });
    TpfMockServer {
        pass_url,
        reject_url,
        swap_url,
        last_request,
        requests,
        _thread: thread,
    }
}

pub fn run_guardian_payload(args: &[&str], stdin: Option<&[u8]>) -> std::io::Result<GuardianRun> {
    let ca_dir = TempDir::new()?;
    let bin = guardian_bin();
    let mut child = Command::new(&bin);
    child.args(args);
    if let Some(input) = stdin {
        child.stdin(Stdio::piped());
        child.stdout(Stdio::piped());
        child.stderr(Stdio::piped());
        let mut process = child.spawn()?;
        if let Some(mut stdin_pipe) = process.stdin.take() {
            use std::io::Write;
            stdin_pipe.write_all(input)?;
        }
        let mut stdout_bytes = Vec::new();
        let mut stderr = String::new();
        if let Some(mut out) = process.stdout.take() {
            out.read_to_end(&mut stdout_bytes)?;
        }
        if let Some(mut err) = process.stderr.take() {
            err.read_to_string(&mut stderr)?;
        }
        let status = process.wait()?;
        return Ok(GuardianRun {
            exit_code: status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
            stderr,
            _ca_dir: ca_dir,
        });
    }
    child.stdin(Stdio::null());
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
    let status = process.wait()?;
    Ok(GuardianRun {
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr,
        _ca_dir: ca_dir,
    })
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
    child.stdin(Stdio::null());
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

    Ok(GuardianRun {
        exit_code,
        stdout,
        stderr,
        _ca_dir: ca_dir,
    })
}

const GUARDIAN_HTTP_RETRIES: usize = 3;

fn run_guardian_http_with_retry<F, P>(
    mut run_once: F,
    mut is_complete: P,
) -> std::io::Result<GuardianRun>
where
    F: FnMut() -> std::io::Result<GuardianRun>,
    P: FnMut(&GuardianRun) -> bool,
{
    let mut last = None;
    for attempt in 0..GUARDIAN_HTTP_RETRIES {
        let run = run_once()?;
        if is_complete(&run) {
            return Ok(run);
        }
        last = Some(run);
        if attempt + 1 < GUARDIAN_HTTP_RETRIES {
            std::thread::sleep(Duration::from_millis(2000));
        }
    }
    Ok(last.expect("guardian run"))
}

fn child_stdout_ok(run: &GuardianRun) -> bool {
    run.exit_code == 0 && !run.stdout.trim().is_empty()
}

pub fn assert_child_success(run: &GuardianRun) {
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
}

pub fn assert_no_jsonl_stderr(run: &GuardianRun) {
    assert!(
        !run.stderr.lines().any(|line| {
            let t = line.trim();
            t.starts_with('{') && t.contains("\"type\"")
        }),
        "expected no JSONL on stderr; got:\n{}",
        run.stderr
    );
}

/// Integration tests need network; skip quickly when offline.
pub fn require_network() -> bool {
    if std::env::var("GUARDIAN_SKIP_NETWORK").is_ok() {
        return false;
    }
    let curl = curl_program();
    let probe_url = smoke_url();
    let null_out = if cfg!(windows) { "NUL" } else { "/dev/null" };
    for attempt in 0..3 {
        let probe = Command::new(&curl)
            .args([
                "-sS",
                "--connect-timeout",
                "10",
                "--max-time",
                "20",
                "-o",
                null_out,
                &probe_url,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if probe.map(|s| s.success()).unwrap_or(false) {
            return true;
        }
        if attempt < 2 {
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    false
}

#[allow(dead_code)]
pub fn smoke_timeout() -> Duration {
    Duration::from_secs(120)
}

#[allow(dead_code)]
pub fn assert_bin_under(path: &Path) {
    assert!(path.is_file(), "missing binary at {}", path.display());
}
