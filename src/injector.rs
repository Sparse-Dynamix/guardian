use std::collections::HashMap;
use std::ffi::CString;
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

use anyhow::{Context, Result};
use frida::{DeviceManager, DeviceType, Frida, ScriptOption, SpawnOptions, SpawnStdio};
use kill_tree::blocking::kill_tree_with_config;
use kill_tree::Config;
use serde_json::json;

use crate::ca::CaTrust;
use crate::child_exit::ChildExitWaiter;
use crate::config::Settings;
use crate::frida_ext::{
    connect_device_child_signals, connect_session_detached, enable_child_gating,
    is_process_replaced, DeviceSignalHandle, SessionSignalHandle,
};
use crate::port::resolve_listen_port;

const CONNECT_HOOK_TEMPLATE: &str = include_str!("../assets/connect_hook.js");
const CONNECT_BYPASS_LIB: &str = include_str!("../assets/connect_bypass_lib.js");
const CONNECT_HANDSHAKE_LIB: &str = include_str!("../assets/connect_handshake_lib.js");
const ENV_INJECT_TEMPLATE: &str = include_str!("../assets/env_inject.js");

#[derive(Clone)]
pub struct HookBundle {
    pub connect_hook: String,
    pub env_inject: String,
}

enum ProcessEvent {
    ChildAdded(u32),
    ChildRemoved(u32),
    ProcessReplaced(u32),
}

struct TrackedSession<'a> {
    _session: frida::Session<'a>,
    _detached: SessionSignalHandle,
}

pub fn build_hook_bundle(
    port: u16,
    filter: &str,
    bind_ip: std::net::Ipv4Addr,
    ca_trust: &CaTrust,
) -> Result<HookBundle> {
    let octets = bind_ip.octets();
    let bind_host = bind_ip.to_string();
    let connect_hook = CONNECT_HOOK_TEMPLATE
        .replace("{{PORT}}", &port.to_string())
        .replace("{{FILTER}}", filter)
        .replace("{{BIND_HOST}}", &bind_host)
        .replace("{{BIND_HOST_0}}", &octets[0].to_string())
        .replace("{{BIND_HOST_1}}", &octets[1].to_string())
        .replace("{{BIND_HOST_2}}", &octets[2].to_string())
        .replace("{{BIND_HOST_3}}", &octets[3].to_string())
        .replace("{{CONNECT_BYPASS_LIB}}", CONNECT_BYPASS_LIB)
        .replace("{{CONNECT_HANDSHAKE_LIB}}", CONNECT_HANDSHAKE_LIB);

    let ca_env = json!(ca_trust.env_pairs_for_injection());
    let env_inject = ENV_INJECT_TEMPLATE.replace("{{CA_ENV_JSON}}", &ca_env.to_string());

    Ok(HookBundle {
        connect_hook,
        env_inject,
    })
}

fn instrument<'a>(
    device: &'a frida::Device<'a>,
    sessions: &mut HashMap<u32, TrackedSession<'a>>,
    pid: u32,
    hook_bundle: &HookBundle,
    event_tx: &Sender<ProcessEvent>,
    root_pid: u32,
) -> Result<()> {
    let session = device
        .attach(pid)
        .with_context(|| format!("failed to attach to pid {pid}"))?;
    enable_child_gating(&session)?;

    let tx_replace = event_tx.clone();
    let tx_root_removed = event_tx.clone();
    let detached = connect_session_detached(&session, move |reason| {
        if is_process_replaced(reason) {
            let _ = tx_replace.send(ProcessEvent::ProcessReplaced(pid));
        } else if pid == root_pid {
            // Wakeup hint only; exit code comes exclusively from ChildExitWaiter.
            let _ = tx_root_removed.send(ProcessEvent::ChildRemoved(pid));
        }
    });

    let mut network_opt = ScriptOption::new();
    let network_script = session
        .create_script(&hook_bundle.connect_hook, &mut network_opt)
        .context("failed to create connect hook script")?;
    network_script
        .load()
        .context("failed to load connect hook script")?;
    std::mem::forget(network_script);

    let mut env_opt = ScriptOption::new();
    let env_script = session
        .create_script(&hook_bundle.env_inject, &mut env_opt)
        .context("failed to create env inject script")?;
    env_script
        .load()
        .context("failed to load env inject script")?;
    std::mem::forget(env_script);

    sessions.insert(
        pid,
        TrackedSession {
            _session: session,
            _detached: detached,
        },
    );
    Ok(())
}

fn resume_pid(device: &frida::Device<'_>, pid: u32) -> Result<()> {
    device
        .resume(pid)
        .with_context(|| format!("failed to resume pid {pid}"))
}

pub struct SpawnOutcome {
    pub exit_code: i32,
}

/// Spawn paused, resolve port, notify coordinator, wait for proxy, instrument, wait for exit.
pub fn run_injection_coordinated(
    settings: &Settings,
    ca_trust: &CaTrust,
    bind_ip: IpAddr,
    port_tx: Sender<u16>,
    proxy_ready_rx: Receiver<()>,
    interrupt_rx: Receiver<()>,
) -> Result<SpawnOutcome> {
    let parent_env: Vec<(String, String)> = std::env::vars().collect();
    let spawn_env = ca_trust.spawn_env_merged(&parent_env);

    let frida = unsafe { Frida::obtain() };
    let device_manager = DeviceManager::obtain(&frida);
    let mut device = device_manager
        .get_device_by_type(DeviceType::Local)
        .context("failed to get local Frida device")?;

    let (event_tx, event_rx) = std::sync::mpsc::channel::<ProcessEvent>();

    let _device_signals: DeviceSignalHandle = connect_device_child_signals(
        &device,
        {
            let tx = event_tx.clone();
            move |pid| {
                let _ = tx.send(ProcessEvent::ChildAdded(pid));
            }
        },
        {
            let tx = event_tx.clone();
            move |pid| {
                let _ = tx.send(ProcessEvent::ChildRemoved(pid));
            }
        },
    )?;

    let mut spawn_options = SpawnOptions::new()
        .argv(
            std::iter::once(settings.program.as_str())
                .chain(settings.args.iter().map(String::as_str)),
        )
        .stdio(SpawnStdio::Inherit)
        .envp(spawn_env);

    if let Ok(cwd) = std::env::current_dir() {
        if let Some(cwd_str) = cwd.to_str() {
            spawn_options = spawn_options.cwd(CString::new(cwd_str).context("cwd contains NUL")?);
        }
    }

    let root_pid = device
        .spawn(&settings.program, &mut spawn_options)
        .context("frida spawn failed")?;

    let port = resolve_listen_port(bind_ip, settings.port, settings.port_min, settings.port_max)
        .context("failed to resolve proxy listen port")?;

    port_tx
        .send(port)
        .map_err(|_| anyhow::anyhow!("proxy coordinator dropped before port allocation"))?;

    if recv_or_interrupted(&proxy_ready_rx, &interrupt_rx, 100)?.is_none() {
        terminate_process_tree(root_pid);
        return Ok(SpawnOutcome { exit_code: 130 });
    }

    let hook_bundle = build_hook_bundle(port, &settings.filter, settings.bind, ca_trust)?;
    let mut sessions: HashMap<u32, TrackedSession<'_>> = HashMap::new();

    instrument(
        &device,
        &mut sessions,
        root_pid,
        &hook_bundle,
        &event_tx,
        root_pid,
    )
    .context("failed to instrument root process")?;

    // Arm a blocking OS exit wait (pidfd / kqueue / process handle) before resume.
    let exit_waiter = ChildExitWaiter::start(root_pid)?;
    resume_pid(&device, root_pid)?;

    let exit_code = wait_for_root(
        root_pid,
        exit_waiter,
        &event_rx,
        &interrupt_rx,
        &device,
        &mut sessions,
        &hook_bundle,
        &event_tx,
        settings.process_poll_interval_ms,
    )?;

    Ok(SpawnOutcome { exit_code })
}

fn recv_or_interrupted<T>(
    data_rx: &Receiver<T>,
    interrupt_rx: &Receiver<()>,
    poll_ms: u64,
) -> Result<Option<T>> {
    loop {
        if interrupt_rx.try_recv().is_ok() {
            return Ok(None);
        }
        match data_rx.recv_timeout(Duration::from_millis(poll_ms)) {
            Ok(value) => return Ok(Some(value)),
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                anyhow::bail!("coordinator channel closed unexpectedly");
            }
        }
    }
}

pub(crate) fn terminate_process_tree(pid: u32) {
    #[cfg(unix)]
    {
        for signal in ["SIGINT", "SIGTERM", "SIGKILL"] {
            let config = Config {
                signal: signal.to_string(),
                ..Default::default()
            };
            let _ = kill_tree_with_config(pid, &config);
            std::thread::sleep(Duration::from_millis(100));
            if matches!(probe_pid(pid), PidProbe::Gone) {
                return;
            }
        }
    }

    #[cfg(windows)]
    {
        let config = Config::default();
        let _ = kill_tree_with_config(pid, &config);
    }
}

enum PidProbe {
    Running,
    Gone,
}

fn is_authoritative_root_exit(event: &ProcessEvent, root_pid: u32) -> bool {
    matches!(event, ProcessEvent::ChildRemoved(pid) if *pid == root_pid)
}

fn probe_pid(pid: u32) -> PidProbe {
    match try_wait_pid(pid) {
        WaitStatus::StillRunning => PidProbe::Running,
        WaitStatus::NotRunning | WaitStatus::Error(_) => PidProbe::Gone,
    }
}

fn wait_for_root<'a>(
    root_pid: u32,
    exit_waiter: ChildExitWaiter,
    event_rx: &std::sync::mpsc::Receiver<ProcessEvent>,
    interrupt_rx: &std::sync::mpsc::Receiver<()>,
    device: &'a frida::Device<'a>,
    sessions: &mut HashMap<u32, TrackedSession<'a>>,
    hook_bundle: &HookBundle,
    event_tx: &Sender<ProcessEvent>,
    process_poll_interval_ms: u64,
) -> Result<i32> {
    let poll = Duration::from_millis(process_poll_interval_ms);

    loop {
        if interrupt_rx.try_recv().is_ok() {
            terminate_process_tree(root_pid);
            sessions.clear();
            return Ok(130);
        }

        // Collect exit status before tearing down Frida sessions: dropping the root session
        // on detach can reap the zombie before our exit waiter returns.
        if let Some(code) = exit_waiter.try_recv_exit(Duration::ZERO)? {
            sessions.clear();
            return Ok(code);
        }

        while let Ok(event) = event_rx.try_recv() {
            match event {
                ProcessEvent::ChildRemoved(pid) => {
                    if pid != root_pid {
                        sessions.remove(&pid);
                    }
                }
                ProcessEvent::ProcessReplaced(pid) => {
                    sessions.remove(&pid);
                    instrument(device, sessions, pid, hook_bundle, event_tx, root_pid)
                        .with_context(|| {
                            format!("failed to re-instrument pid {pid} after process replacement")
                        })?;
                    resume_pid(device, pid)?;
                }
                ProcessEvent::ChildAdded(pid) => {
                    instrument(device, sessions, pid, hook_bundle, event_tx, root_pid)
                        .with_context(|| format!("failed to instrument child {pid}"))?;
                    resume_pid(device, pid)?;
                }
            }
        }

        if let Some(code) = exit_waiter.try_recv_exit(poll)? {
            sessions.clear();
            return Ok(code);
        }

        match interrupt_rx.recv_timeout(poll) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                terminate_process_tree(root_pid);
                sessions.clear();
                return Ok(130);
            }
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}

enum WaitStatus {
    StillRunning,
    NotRunning,
    Error(std::io::Error),
}

fn try_wait_pid(pid: u32) -> WaitStatus {
    #[cfg(unix)]
    {
        let ret = unsafe { libc::kill(pid as i32, 0) };
        if ret == 0 {
            return WaitStatus::StillRunning;
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ESRCH) => WaitStatus::NotRunning,
            Some(libc::EPERM) => WaitStatus::StillRunning,
            _ => WaitStatus::Error(err),
        }
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        const STILL_ACTIVE: u32 = 259;

        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            let err = std::io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(87) | Some(5)) {
                return WaitStatus::NotRunning;
            }
            return WaitStatus::Error(err);
        }

        let mut code: u32 = 0;
        let ok = unsafe { GetExitCodeProcess(handle, &mut code) };
        unsafe { CloseHandle(handle) };
        if ok == 0 {
            return WaitStatus::Error(std::io::Error::last_os_error());
        }
        if code == STILL_ACTIVE {
            return WaitStatus::StillRunning;
        }
        WaitStatus::NotRunning
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::mpsc;

    use crate::ca::CaTrust;
    use crate::config::Settings;

    use super::{
        build_hook_bundle, is_authoritative_root_exit, probe_pid, recv_or_interrupted,
        terminate_process_tree, try_wait_pid, PidProbe, ProcessEvent, WaitStatus,
    };
    use crate::child_exit::try_reap_child_exit;

    fn test_settings() -> Settings {
        Settings {
            bind: Ipv4Addr::LOCALHOST,
            port: None,
            trypanophobe_filter: Some("http://127.0.0.1:1/pass".into()),
            trypanophobe_swap: false,
            payload: None,
            filter: "true".to_string(),
            ca_dir: std::path::PathBuf::from("/tmp/guardian-test-ca"),
            filter_timeout_secs: 10,
            block_message: crate::trypanophobe::DEFAULT_BLOCK_MESSAGE.to_string(),
            port_min: 1024,
            port_max: 65535,
            proxy_ready_timeout_secs: 5,
            process_poll_interval_ms: 50,
            ca_bundle_name: "guardian-ca-bundle.pem".to_string(),
            java_truststore_name: "guardian-java-truststore.p12".to_string(),
            java_truststore_password: "guardian".to_string(),
            deno_tls_ca_store: "system,mozilla".to_string(),
            node_options_append: "--use-openssl-ca".to_string(),
            program: "true".to_string(),
            args: vec![],
            trust_stores: vec!["system".into()],
            upstream_tls: Default::default(),
            skip_cert_regen: false,
        }
    }

    #[test]
    fn hook_bundle_includes_host_in_filter_call() {
        let ca = CaTrust::from_settings(&test_settings());
        let bundle = build_hook_bundle(9999, "true", Ipv4Addr::LOCALHOST, &ca).unwrap();
        assert!(bundle.connect_hook.contains("__guardianHostByIp"));
        assert!(bundle
            .connect_hook
            .contains("filter(this.sa_family, this.addrKey, this.port, host)"));
    }

    #[test]
    fn hook_bundle_has_no_loopback_bypass_switch() {
        let ca = CaTrust::from_settings(&test_settings());
        let bundle = build_hook_bundle(9999, "true", Ipv4Addr::LOCALHOST, &ca).unwrap();
        assert!(!bundle.connect_hook.contains("BYPASS_LOOPBACK"));
    }

    #[test]
    fn hook_bundle_includes_js_bypass_helpers() {
        let ca = CaTrust::from_settings(&test_settings());
        let bundle = build_hook_bundle(9999, "true", Ipv4Addr::LOCALHOST, &ca).unwrap();
        assert!(bundle.connect_hook.contains("shouldBypassAddress"));
        assert!(bundle.connect_hook.contains("isIpv4LoopbackOrUnspecified"));
        assert!(!bundle.connect_hook.contains(concat!("new Rust", "Module")));
        assert!(!bundle.connect_hook.contains("Proxy-Connection"));
    }

    #[test]
    fn hook_bundle_uses_minimal_connect_request() {
        let ca = CaTrust::from_settings(&test_settings());
        let bundle = build_hook_bundle(9999, "true", Ipv4Addr::LOCALHOST, &ca).unwrap();
        assert!(bundle.connect_hook.contains("CONNECT "));
        assert!(bundle.connect_hook.contains("Host: "));
        assert!(bundle.connect_hook.contains("storeCarry"));
        assert!(bundle.connect_hook.contains("retval.toInt32() !== 0"));
        assert!(bundle.connect_hook.contains("isConnectPendingError"));
        assert!(bundle
            .connect_hook
            .contains("restoreSocketFlags(sockfd, originalFlags);"));
    }

    #[test]
    fn hook_bundle_substitutes_literal_host_filter() {
        let ca = CaTrust::from_settings(&test_settings());
        let expr = r#"host === "api.example.com""#;
        let bundle = build_hook_bundle(12345, expr, Ipv4Addr::LOCALHOST, &ca).unwrap();
        assert!(bundle.connect_hook.contains(expr));
    }

    #[test]
    fn hook_bundle_substitutes_regex_host_filter() {
        let ca = CaTrust::from_settings(&test_settings());
        let expr = r#"host && /\.example\.com$/.test(host)"#;
        let bundle = build_hook_bundle(12345, expr, Ipv4Addr::LOCALHOST, &ca).unwrap();
        assert!(bundle.connect_hook.contains(expr));
    }

    #[test]
    fn hook_bundle_substitutes_port_and_bind() {
        let ca = CaTrust::from_settings(&test_settings());
        let bundle = build_hook_bundle(12345, "true", Ipv4Addr::LOCALHOST, &ca).unwrap();
        assert!(bundle.connect_hook.contains("12345"));
        assert!(bundle.connect_hook.contains("true"));
        assert!(bundle.connect_hook.contains("127.0.0.1"));
        assert!(bundle.env_inject.contains("SSL_CERT_FILE"));
    }

    #[test]
    fn recv_or_interrupted_returns_value() {
        let (tx, rx) = mpsc::channel();
        let (_itx, irx) = mpsc::channel::<()>();
        tx.send(42).unwrap();
        assert_eq!(recv_or_interrupted(&rx, &irx, 10).unwrap(), Some(42));
    }

    #[test]
    fn recv_or_interrupted_returns_none_on_interrupt() {
        let (_tx, rx) = mpsc::channel::<i32>();
        let (itx, irx) = mpsc::channel();
        itx.send(()).unwrap();
        assert!(recv_or_interrupted(&rx, &irx, 10).unwrap().is_none());
    }

    #[test]
    fn recv_or_interrupted_errors_when_sender_dropped() {
        let (tx, rx) = mpsc::channel::<i32>();
        let (_itx, irx) = mpsc::channel::<()>();
        drop(tx);
        let err = recv_or_interrupted(&rx, &irx, 10).unwrap_err();
        assert!(err.to_string().contains("coordinator channel closed"));
    }

    #[test]
    fn try_wait_current_pid_still_running() {
        let pid = std::process::id();
        assert!(matches!(try_wait_pid(pid), WaitStatus::StillRunning));
    }

    #[test]
    fn try_wait_missing_pid_not_running() {
        assert!(matches!(try_wait_pid(4_000_000), WaitStatus::NotRunning));
    }

    #[test]
    fn probe_pid_detects_running_self() {
        let pid = std::process::id();
        assert!(matches!(probe_pid(pid), PidProbe::Running));
    }

    #[test]
    fn child_removed_is_authoritative_root_exit() {
        assert!(is_authoritative_root_exit(
            &ProcessEvent::ChildRemoved(42),
            42
        ));
        assert!(!is_authoritative_root_exit(
            &ProcessEvent::ProcessReplaced(42),
            42
        ));
        assert!(!is_authoritative_root_exit(
            &ProcessEvent::ChildRemoved(7),
            42
        ));
    }

    #[test]
    fn probe_pid_missing_is_gone() {
        assert!(matches!(probe_pid(4_000_000), PidProbe::Gone));
    }

    #[test]
    fn try_reap_child_exit_returns_none_for_missing_pid() {
        assert!(try_reap_child_exit(4_000_000).is_none());
    }

    #[test]
    fn try_wait_exited_child_is_not_running() {
        use std::process::{Command, Stdio};

        #[cfg(windows)]
        let mut child = Command::new("cmd.exe")
            .args(["/C", "exit", "0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");
        #[cfg(not(windows))]
        let mut child = Command::new("sh")
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");

        let pid = child.id();
        let _ = child.wait().expect("wait child");
        assert!(matches!(try_wait_pid(pid), WaitStatus::NotRunning));
        assert!(matches!(probe_pid(pid), PidProbe::Gone));
    }

    #[test]
    #[cfg(unix)]
    fn terminate_process_tree_escalates_past_sigint() {
        use std::process::{Command, Stdio};

        let mut child = Command::new("bash")
            .args(["-c", "trap '' INT; while true; do sleep 1; done"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bash sleeper");
        let pid = child.id();
        terminate_process_tree(pid);
        let status = child.wait().expect("wait child");
        assert!(!status.success());
    }

    #[test]
    #[cfg(windows)]
    fn terminate_process_tree_kills_cmd_child() {
        use std::process::{Command, Stdio};

        let mut child = Command::new("cmd.exe")
            .args(["/C", "timeout", "/t", "30", "/nobreak"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn cmd sleeper");
        let pid = child.id();
        terminate_process_tree(pid);
        let status = child.wait().expect("wait child");
        assert!(!status.success());
    }
}
