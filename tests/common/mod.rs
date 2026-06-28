//! Shared helpers for real end-to-end integration tests (no mocks).

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

static MITM_TEST_LOCK: Mutex<()> = Mutex::new(());

pub fn acquire_mitm_test_lock() -> Option<MutexGuard<'static, ()>> {
    Some(MITM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()))
}

fn mitm_test_lock() -> Option<MutexGuard<'static, ()>> {
    acquire_mitm_test_lock()
}

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

pub fn http_smoke_program() -> Option<String> {
    if !cfg!(windows) {
        return None;
    }
    if let Some(path) = option_env!("CARGO_BIN_EXE_guardian-http-smoke") {
        return Some(path.to_string());
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let exe = if cfg!(windows) {
        "guardian-http-smoke.exe"
    } else {
        "guardian-http-smoke"
    };
    for sub in [
        format!("target/debug/{exe}"),
        format!("target/release/{exe}"),
    ] {
        let path = manifest.join(&sub);
        if path.is_file() {
            return Some(path.display().to_string());
        }
    }
    None
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

fn curl_args(
    url: &str,
    ca_dir: Option<&Path>,
    include_headers: bool,
    extra_flags: &[String],
) -> Vec<String> {
    if cfg!(windows) && extra_flags.iter().any(|flag| flag.starts_with("--http2")) {
        if let Some(http_smoke) = http_smoke_program() {
            let mut args = vec![http_smoke];
            if extra_flags
                .iter()
                .any(|flag| flag == "--http2-prior-knowledge")
            {
                args.push("--http2-prior-knowledge".to_string());
            } else {
                args.push("--http2".to_string());
            }
            if url.starts_with("https://") {
                args.push("--ipv4".to_string());
            }
            args.push(url.to_string());
            return args;
        }
    }

    let mut args = vec![curl_program(), "-sS".to_string()];
    args.extend(extra_flags.iter().cloned());
    if include_headers {
        args.push("-i".to_string());
    }
    if cfg!(target_os = "macos") {
        args.push("--ipv4".to_string());
    }
    if url.starts_with("https://") {
        if let Some(ca_dir) = ca_dir {
            args.push("--cacert".to_string());
            args.push(ca_dir.join("guardian-ca-bundle.pem").display().to_string());
        }
        if cfg!(windows) {
            args.push("--ipv4".to_string());
            args.push("--ssl-no-revoke".to_string());
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
    let _mitm_guard = tpf_url.is_some().then(mitm_test_lock).flatten();
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

pub fn run_guardian_direct_https(url: &str) -> std::io::Result<GuardianRun> {
    run_guardian_with_options(GuardianOptions {
        url: Some(url.to_string()),
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
    pub curl_flags: Vec<String>,
    pub extra_env: Vec<(String, String)>,
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
            curl_flags: Vec::new(),
            extra_env: Vec::new(),
        }
    }
}

pub fn run_guardian_with_options(opts: GuardianOptions) -> std::io::Result<GuardianRun> {
    run_guardian_http_with_retry(|| run_guardian_with_options_once(&opts), child_stdout_ok)
}

pub fn run_guardian_with_options_until<F>(
    opts: GuardianOptions,
    is_complete: F,
) -> std::io::Result<GuardianRun>
where
    F: FnMut(&GuardianRun) -> bool,
{
    run_guardian_http_with_retry(|| run_guardian_with_options_once(&opts), is_complete)
}

pub fn run_guardian_with_options_once(opts: &GuardianOptions) -> std::io::Result<GuardianRun> {
    let url = opts
        .url
        .clone()
        .expect("GuardianOptions.url is required (use spawn_test_servers URLs)");
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
    args.extend(curl_args(
        &url,
        ca_bundle,
        opts.curl_include_headers,
        &opts.curl_flags,
    ));
    let env_refs: Vec<(&str, &str)> = opts
        .extra_env
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    run_guardian_with_args(&args, ca_dir, &env_refs)
}

pub fn run_guardian_child_spawn(url: &str) -> std::io::Result<GuardianRun> {
    run_guardian_http_with_retry(
        || run_guardian_child_spawn_once(url),
        |run| child_stdout_ok(run),
    )
}

fn run_guardian_child_spawn_once(url: &str) -> std::io::Result<GuardianRun> {
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
        args.push(url.to_string());
    } else if let Some(wrapper) = child_wrapper_program() {
        args.push(wrapper);
        args.push(curl_program());
        args.push("-sS".to_string());
        args.push(url.to_string());
    } else {
        let sh = resolve_executable("sh");
        let inner = format!("{} -sS '{}'", curl_program(), url);
        args.push(sh);
        args.push("-c".to_string());
        args.push(inner);
    }

    run_guardian_with_args(&args, ca_dir, &[])
}

const TEST_SERVERS_MANIFEST_PREFIX: &str = "GUARDIAN_TEST_SERVERS ";

#[derive(Clone, Debug)]
pub struct TestServersConfig {
    pub tpf_swap_body: Option<String>,
    pub tpf_reject_needle: Option<String>,
    pub sse_events: Option<Vec<String>>,
}

impl Default for TestServersConfig {
    fn default() -> Self {
        Self {
            tpf_swap_body: None,
            tpf_reject_needle: None,
            sse_events: None,
        }
    }
}

pub struct TestServers {
    pub pass_url: String,
    pub reject_url: String,
    pub swap_url: String,
    pub image_swap_url: String,
    pub partial_url: String,
    pub http_get_url: String,
    pub http_loopback_get_url: String,
    pub http_post_url: String,
    pub http_image_png_url: String,
    pub http2_get_url: String,
    pub http2c_get_url: String,
    pub sse_base_url: String,
    pub sse_stream_url: String,
    pub ipv6_base_url: String,
    pub origin_ca_pem: PathBuf,
    tpf_base_url: String,
    child: Child,
}

impl Drop for TestServers {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct TpfMockServer {
    pub pass_url: String,
    pub reject_url: String,
    pub swap_url: String,
    pub partial_url: String,
    servers: TestServers,
}

pub struct LocalHttpServer {
    pub base_url: String,
    _servers: TestServers,
}

pub fn spawn_test_servers(config: TestServersConfig) -> TestServers {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let script = manifest_dir.join("scripts/test-servers.ts");
    assert!(
        script.is_file(),
        "test servers script not found at {}",
        script.display()
    );

    let mut cmd = Command::new("node");
    cmd.arg("--import")
        .arg("tsx")
        .arg(&script)
        .env("GUARDIAN_TEST_SERVERS_CHILD", "1");
    if let Some(body) = &config.tpf_swap_body {
        cmd.env("GUARDIAN_TEST_TPF_SWAP_BODY", body);
    }
    if let Some(needle) = &config.tpf_reject_needle {
        cmd.env("GUARDIAN_TEST_TPF_REJECT_NEEDLE", needle);
    }
    if let Some(events) = &config.sse_events {
        cmd.env("GUARDIAN_TEST_SSE_EVENTS", events.join(","));
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());

    let mut child = cmd.spawn().expect("spawn test-servers");
    let stdout = child.stdout.take().expect("test-servers stdout");
    let mut reader = BufReader::new(stdout);
    let deadline = Instant::now() + Duration::from_secs(15);
    let manifest_line = loop {
        let mut line = String::new();
        if reader
            .read_line(&mut line)
            .expect("read test-servers stdout")
            == 0
        {
            panic!("test-servers exited before manifest");
        }
        if let Some(json) = line.strip_prefix(TEST_SERVERS_MANIFEST_PREFIX) {
            break json.trim().to_string();
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for test-servers manifest");
        }
    };

    let manifest: serde_json::Value =
        serde_json::from_str(&manifest_line).expect("parse test-servers manifest");
    let tpf = &manifest["tpf"];
    let http = &manifest["http"];
    let http2 = &manifest["http2"];
    let http2c = &manifest["http2c"];
    let sse = &manifest["sse"];
    let ipv6 = &manifest["ipv6"];

    TestServers {
        pass_url: tpf["passUrl"].as_str().expect("passUrl").to_string(),
        reject_url: tpf["rejectUrl"].as_str().expect("rejectUrl").to_string(),
        swap_url: tpf["swapUrl"].as_str().expect("swapUrl").to_string(),
        image_swap_url: tpf["imageSwapUrl"]
            .as_str()
            .expect("imageSwapUrl")
            .to_string(),
        partial_url: tpf["partialUrl"].as_str().expect("partialUrl").to_string(),
        tpf_base_url: tpf["baseUrl"].as_str().expect("tpf baseUrl").to_string(),
        http_get_url: http["getUrl"].as_str().expect("getUrl").to_string(),
        http_loopback_get_url: http["loopbackGetUrl"]
            .as_str()
            .expect("loopbackGetUrl")
            .to_string(),
        http_post_url: http["postUrl"].as_str().expect("postUrl").to_string(),
        http_image_png_url: http["imagePngUrl"]
            .as_str()
            .expect("imagePngUrl")
            .to_string(),
        http2_get_url: http2["getUrl"].as_str().expect("http2 getUrl").to_string(),
        http2c_get_url: http2c["getUrl"]
            .as_str()
            .expect("http2c getUrl")
            .to_string(),
        sse_base_url: sse["baseUrl"].as_str().expect("sse baseUrl").to_string(),
        sse_stream_url: sse["streamUrl"]
            .as_str()
            .expect("sse streamUrl")
            .to_string(),
        ipv6_base_url: ipv6["baseUrl"].as_str().expect("ipv6 baseUrl").to_string(),
        origin_ca_pem: PathBuf::from(manifest["originCaPem"].as_str().expect("originCaPem")),
        child,
    }
}

pub fn fetch_tpf_requests(servers: &TestServers) -> Vec<RecordedTpfRequest> {
    let url = format!("{}/_debug/requests", servers.tpf_base_url);
    let output = Command::new(resolve_executable("curl"))
        .args(["-sS", &url])
        .output()
        .expect("fetch TPF debug requests");
    if !output.status.success() {
        panic!(
            "failed to fetch TPF requests: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let raw: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("parse TPF debug requests");
    raw.into_iter()
        .map(|entry| {
            let path_and_query = entry["pathAndQuery"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let body_b64 = entry["bodyBase64"].as_str().unwrap_or_default();
            let body = base64_decode(body_b64);
            RecordedTpfRequest {
                path_and_query,
                body,
            }
        })
        .collect()
}

fn base64_decode(input: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .unwrap_or_default()
}

pub fn wait_for_tpf_url_query(servers: &TestServers, timeout: Duration) -> RecordedTpfRequest {
    let deadline = Instant::now() + timeout;
    loop {
        let requests = fetch_tpf_requests(servers);
        if let Some(r) = requests
            .into_iter()
            .find(|r| r.path_and_query.contains("url="))
        {
            return r;
        }
        if Instant::now() >= deadline {
            let recorded: Vec<_> = fetch_tpf_requests(servers)
                .into_iter()
                .map(|r| r.path_and_query)
                .collect();
            panic!("expected TPF POST with url= query; recorded paths: {recorded:?}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn spawn_tpf_mock() -> TpfMockServer {
    tpf_from_servers(spawn_test_servers(TestServersConfig::default()))
}

pub fn spawn_tpf_mock_with_swap_body(swap_body: &[u8]) -> TpfMockServer {
    tpf_from_servers(spawn_test_servers(TestServersConfig {
        tpf_swap_body: Some(String::from_utf8_lossy(swap_body).into_owned()),
        ..TestServersConfig::default()
    }))
}

pub fn spawn_tpf_mock_reject_body_containing(needle: &str) -> TpfMockServer {
    tpf_from_servers(spawn_test_servers(TestServersConfig {
        tpf_reject_needle: Some(needle.to_string()),
        ..TestServersConfig::default()
    }))
}

fn tpf_from_servers(servers: TestServers) -> TpfMockServer {
    TpfMockServer {
        pass_url: servers.pass_url.clone(),
        reject_url: servers.reject_url.clone(),
        swap_url: servers.swap_url.clone(),
        partial_url: servers.partial_url.clone(),
        servers,
    }
}

impl TpfMockServer {
    pub fn servers(&self) -> &TestServers {
        &self.servers
    }
}

pub fn spawn_sse_origin(events: &[&str]) -> LocalHttpServer {
    let servers = spawn_test_servers(TestServersConfig {
        sse_events: Some(events.iter().map(|s| (*s).to_string()).collect()),
        ..TestServersConfig::default()
    });
    LocalHttpServer {
        base_url: servers.sse_base_url.clone(),
        _servers: servers,
    }
}

pub fn spawn_ipv6_echo_server() -> LocalHttpServer {
    let servers = spawn_test_servers(TestServersConfig::default());
    LocalHttpServer {
        base_url: servers.ipv6_base_url.clone(),
        _servers: servers,
    }
}

pub fn run_guardian_payload_until<F>(
    args: &[&str],
    stdin: Option<&[u8]>,
    is_complete: F,
) -> std::io::Result<GuardianRun>
where
    F: FnMut(&GuardianRun) -> bool,
{
    run_guardian_http_with_retry(|| run_guardian_payload(args, stdin), is_complete)
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
    let _mitm_guard = args
        .windows(2)
        .any(|w| w[0] == "--tpf")
        .then(mitm_test_lock)
        .flatten();
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

    let mitm = args.windows(2).any(|w| w[0] == "--tpf");
    let deadline = Instant::now()
        + if mitm {
            GUARDIAN_RUN_DEADLINE
        } else {
            Duration::from_secs(60)
        };

    let mut process = child.spawn()?;

    let (stdout_tx, stdout_rx) = mpsc::channel();
    let (stderr_tx, stderr_rx) = mpsc::channel();
    if let Some(mut out) = process.stdout.take() {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = out.read_to_end(&mut bytes);
            let _ = stdout_tx.send(bytes);
        });
    } else {
        let _ = stdout_tx.send(Vec::new());
    }
    if let Some(mut err) = process.stderr.take() {
        thread::spawn(move || {
            let mut text = String::new();
            let _ = err.read_to_string(&mut text);
            let _ = stderr_tx.send(text);
        });
    } else {
        let _ = stderr_tx.send(String::new());
    }

    let status = wait_for_child(&mut process, deadline)?;
    let exit_code = status.code().unwrap_or(-1);

    let stdout_bytes = stdout_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_default();
    let stderr = stderr_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_default();
    let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();

    Ok(GuardianRun {
        exit_code,
        stdout,
        stderr,
        _ca_dir: ca_dir,
    })
}

const GUARDIAN_HTTP_RETRIES: usize = 5;

/// Hard cap for a single guardian invocation (MITM uses Frida + proxy; must not hang the suite).
pub const GUARDIAN_RUN_DEADLINE: Duration = Duration::from_secs(30);

fn wait_for_child(
    process: &mut Child,
    deadline: Instant,
) -> std::io::Result<std::process::ExitStatus> {
    loop {
        if let Some(status) = process.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = process.kill();
            let _ = process.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("guardian did not exit within {:?}", deadline.elapsed()),
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

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

/// Integration tests may skip when GUARDIAN_SKIP_NETWORK is set.
pub fn require_network() -> bool {
    !std::env::var("GUARDIAN_SKIP_NETWORK").is_ok()
}

#[allow(dead_code)]
pub fn smoke_timeout() -> Duration {
    Duration::from_secs(120)
}

#[allow(dead_code)]
pub fn assert_bin_under(path: &Path) {
    assert!(path.is_file(), "missing binary at {}", path.display());
}
