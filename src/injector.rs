use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, Sender};

use anyhow::{Context, Result};
use frida::{DeviceManager, DeviceType, Frida, ScriptOption, SpawnOptions, SpawnStdio};
use serde_json::json;

use crate::ca::CaTrust;
use crate::config::Settings;
use crate::frida_ext::{
    connect_device_child_signals, connect_session_detached, enable_child_gating,
    is_process_replaced, DeviceSignalHandle, SessionSignalHandle,
};
use crate::port::resolve_listen_port;

const CONNECT_HOOK_TEMPLATE: &str = include_str!("../assets/connect_hook.js");
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
    let connect_hook = CONNECT_HOOK_TEMPLATE
        .replace("{{PORT}}", &port.to_string())
        .replace("{{FILTER}}", filter)
        .replace("{{BIND_HOST_0}}", &octets[0].to_string())
        .replace("{{BIND_HOST_1}}", &octets[1].to_string())
        .replace("{{BIND_HOST_2}}", &octets[2].to_string())
        .replace("{{BIND_HOST_3}}", &octets[3].to_string());

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
) -> Result<()> {
    let session = device
        .attach(pid)
        .with_context(|| format!("failed to attach to pid {pid}"))?;
    enable_child_gating(&session)?;

    let tx = event_tx.clone();
    let detached = connect_session_detached(&session, move |reason| {
        if is_process_replaced(reason) {
            let _ = tx.send(ProcessEvent::ProcessReplaced(pid));
        }
    });

    let mut connect_opt = ScriptOption::new();
    let connect_script = session
        .create_script(&hook_bundle.connect_hook, &mut connect_opt)
        .context("failed to create connect hook script")?;
    connect_script
        .load()
        .context("failed to load connect hook script")?;

    // Frida unloads scripts when the Rust Script handle drops; leak the handle so the hook
    // stays active for the lifetime of the session.
    std::mem::forget(connect_script);

    let mut env_opt = ScriptOption::new();
    let env_script = session
        .create_script(&hook_bundle.env_inject, &mut env_opt)
        .context("failed to create env inject script")?;
    env_script
        .load()
        .context("failed to load env inject script")?;
    std::mem::forget(env_script);

    device
        .resume(pid)
        .with_context(|| format!("failed to resume pid {pid}"))?;

    sessions.insert(
        pid,
        TrackedSession {
            _session: session,
            _detached: detached,
        },
    );
    Ok(())
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
    let spawn_env = ca_trust.env_for_child(&parent_env);

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
                tracing::debug!(target: "guardian", "child-added pid={pid}");
                let _ = tx.send(ProcessEvent::ChildAdded(pid));
            }
        },
        {
            let tx = event_tx.clone();
            move |pid| {
                tracing::debug!(target: "guardian", "child-removed pid={pid}");
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
        .env(spawn_env);

    let root_pid = device
        .spawn(&settings.program, &mut spawn_options)
        .context("frida spawn failed")?;

    let port = resolve_listen_port(
        bind_ip,
        settings.port,
        settings.port_min,
        settings.port_max,
    )
    .context("failed to resolve proxy listen port")?;

    port_tx
        .send(port)
        .map_err(|_| anyhow::anyhow!("proxy coordinator dropped before port allocation"))?;

    proxy_ready_rx
        .recv()
        .map_err(|_| anyhow::anyhow!("proxy coordinator dropped before ready"))?;

    let hook_bundle = build_hook_bundle(port, &settings.filter, settings.bind, ca_trust)?;
    let mut sessions: HashMap<u32, TrackedSession<'_>> = HashMap::new();

    instrument(
        &device,
        &mut sessions,
        root_pid,
        &hook_bundle,
        &event_tx,
    )
    .context("failed to instrument root process")?;

    let exit_code = wait_for_root(
        root_pid,
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

fn wait_for_root<'a>(
    root_pid: u32,
    event_rx: &std::sync::mpsc::Receiver<ProcessEvent>,
    interrupt_rx: &std::sync::mpsc::Receiver<()>,
    device: &'a frida::Device<'a>,
    sessions: &mut HashMap<u32, TrackedSession<'a>>,
    hook_bundle: &HookBundle,
    event_tx: &Sender<ProcessEvent>,
    process_poll_interval_ms: u64,
) -> Result<i32> {
    loop {
        if interrupt_rx.try_recv().is_ok() {
            sessions.clear();
            return Ok(130);
        }

        while let Ok(event) = event_rx.try_recv() {
            match event {
                ProcessEvent::ChildRemoved(pid) => {
                    sessions.remove(&pid);
                }
                ProcessEvent::ProcessReplaced(pid) => {
                    sessions.remove(&pid);
                    instrument(device, sessions, pid, hook_bundle, event_tx)
                        .with_context(|| format!("failed to re-instrument pid {pid} after process replacement"))?;
                }
                ProcessEvent::ChildAdded(pid) => {
                    instrument(device, sessions, pid, hook_bundle, event_tx)
                        .with_context(|| format!("failed to instrument child {pid}"))?;
                }
            }
        }

        match try_wait_pid(root_pid) {
            WaitStatus::Exited(code) => return Ok(code),
            WaitStatus::StillRunning => {
                std::thread::sleep(std::time::Duration::from_millis(
                    process_poll_interval_ms,
                ));
            }
            WaitStatus::Error(e) => {
                anyhow::bail!("wait failed for {root_pid}: {e}");
            }
        }
    }
}

enum WaitStatus {
    Exited(i32),
    StillRunning,
    Error(std::io::Error),
}

fn try_wait_pid(pid: u32) -> WaitStatus {
    #[cfg(unix)]
    {
        // Frida-spawned children are not descendants of guardian; waitpid(2) returns
        // ECHILD. Poll with kill(pid, 0) like the Windows OpenProcess path.
        let ret = unsafe { libc::kill(pid as i32, 0) };
        if ret == 0 {
            return WaitStatus::StillRunning;
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ESRCH) => WaitStatus::Exited(0),
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
            // Root process may have exited and PID is no longer openable (Frida spawn).
            if matches!(err.raw_os_error(), Some(87) | Some(5)) {
                return WaitStatus::Exited(0);
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
        WaitStatus::Exited(code as i32)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::ca::CaTrust;
    use crate::config::Settings;

    use super::build_hook_bundle;

    #[test]
    fn hook_bundle_substitutes_port_and_bind() {
        let settings = Settings {
            bind: Ipv4Addr::LOCALHOST,
            port: None,
            body_limit: 256,
            filter: "true".to_string(),
            ca_dir: std::path::PathBuf::from("/tmp/guardian-test-ca"),
            silent: false,
            port_min: 1024,
            port_max: 65535,
            proxy_event_channel_capacity: 100,
            proxy_ready_timeout_secs: 5,
            proxy_ready_poll_ms: 10,
            process_poll_interval_ms: 50,
            ca_bundle_name: "guardian-ca-bundle.pem".to_string(),
            java_truststore_name: "guardian-java-truststore.p12".to_string(),
            java_truststore_password: "guardian".to_string(),
            deno_tls_ca_store: "system,mozilla".to_string(),
            node_options_append: "--use-openssl-ca".to_string(),
            tracing_prefix: "guardian: ".to_string(),
            tracing_default_level: "guardian=debug".to_string(),
            program: "true".to_string(),
            args: vec![],
        };
        let ca = CaTrust::from_settings(&settings);
        let bundle = build_hook_bundle(12345, "true", Ipv4Addr::LOCALHOST, &ca).unwrap();
        assert!(bundle.connect_hook.contains("12345"));
        assert!(bundle.connect_hook.contains("true"));
        assert!(bundle.env_inject.contains("SSL_CERT_FILE"));
    }
}
