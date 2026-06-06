use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, Sender};

use anyhow::{Context, Result};
use frida::{DeviceManager, DeviceType, Frida, ScriptOption, SpawnOptions, SpawnStdio};
use serde_json::json;

use crate::ca::CaTrust;
use crate::config::Settings;
use crate::frida_ext::{connect_device_child_signals, enable_child_gating, DeviceSignalHandle};
use crate::port::resolve_listen_port;

const CONNECT_HOOK_TEMPLATE: &str = include_str!("../assets/connect_hook.js");
const ENV_INJECT_TEMPLATE: &str = include_str!("../assets/env_inject.js");

#[derive(Clone)]
pub struct HookBundle {
    pub connect_hook: String,
    pub env_inject: String,
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
    sessions: &mut HashMap<u32, frida::Session<'a>>,
    pid: u32,
    hook_bundle: &HookBundle,
) -> Result<()> {
    if sessions.contains_key(&pid) {
        return Ok(());
    }

    let session = device
        .attach(pid)
        .with_context(|| format!("failed to attach to pid {pid}"))?;
    enable_child_gating(&session)?;

    let mut connect_opt = ScriptOption::new().set_name("guardian-connect");
    let connect_script = session
        .create_script(&hook_bundle.connect_hook, &mut connect_opt)
        .context("failed to create connect hook script")?;
    connect_script
        .load()
        .context("failed to load connect hook script")?;

    let mut env_opt = ScriptOption::new().set_name("guardian-env");
    let env_script = session
        .create_script(&hook_bundle.env_inject, &mut env_opt)
        .context("failed to create env inject script")?;
    env_script
        .load()
        .context("failed to load env inject script")?;

    drop(connect_script);
    drop(env_script);

    device
        .resume(pid)
        .with_context(|| format!("failed to resume pid {pid}"))?;
    sessions.insert(pid, session);
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
) -> Result<SpawnOutcome> {
    let parent_env: Vec<(String, String)> = std::env::vars().collect();
    let spawn_env = ca_trust.env_for_child(&parent_env);

    let frida = unsafe { Frida::obtain() };
    let device_manager = DeviceManager::obtain(&frida);
    let mut device = device_manager
        .get_device_by_type(DeviceType::Local)
        .context("failed to get local Frida device")?;

    let (child_tx, child_rx) = std::sync::mpsc::channel::<u32>();

    let _device_signals: DeviceSignalHandle = connect_device_child_signals(
        &device,
        {
            let tx = child_tx.clone();
            move |pid| {
                tracing::debug!(target: "guardian", "child-added pid={pid}");
                let _ = tx.send(pid);
            }
        },
        {
            let tx = child_tx.clone();
            move |pid| {
                tracing::debug!(target: "guardian", "child-removed pid={pid}");
                let _ = tx.send(pid.wrapping_add(1_000_000_000));
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

    let port = resolve_listen_port(root_pid, bind_ip, settings.port)
        .context("failed to resolve proxy listen port")?;

    port_tx
        .send(port)
        .map_err(|_| anyhow::anyhow!("proxy coordinator dropped before port allocation"))?;

    proxy_ready_rx
        .recv()
        .map_err(|_| anyhow::anyhow!("proxy coordinator dropped before ready"))?;

    let hook_bundle = build_hook_bundle(port, &settings.filter, settings.bind, ca_trust)?;
    let mut sessions: HashMap<u32, frida::Session<'_>> = HashMap::new();

    instrument(&device, &mut sessions, root_pid, &hook_bundle)
        .context("failed to instrument root process")?;

    let exit_code = wait_for_root(
        root_pid,
        &child_rx,
        &device,
        &mut sessions,
        &hook_bundle,
    )?;

    Ok(SpawnOutcome { exit_code })
}

fn wait_for_root<'a>(
    root_pid: u32,
    child_rx: &std::sync::mpsc::Receiver<u32>,
    device: &'a frida::Device<'a>,
    sessions: &mut HashMap<u32, frida::Session<'a>>,
    hook_bundle: &HookBundle,
) -> Result<i32> {
    loop {
        while let Ok(event_pid) = child_rx.try_recv() {
            if event_pid >= 1_000_000_000 {
                let removed = event_pid - 1_000_000_000;
                sessions.remove(&removed);
                continue;
            }
            if let Err(e) = instrument(device, sessions, event_pid, hook_bundle) {
                tracing::warn!(target: "guardian", "failed to instrument child {event_pid}: {e}");
            }
        }

        match try_wait_pid(root_pid) {
            WaitStatus::Exited(code) => return Ok(code),
            WaitStatus::StillRunning => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            WaitStatus::Error(e) => {
                anyhow::bail!("waitpid failed for {root_pid}: {e}");
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
        let mut status: i32 = 0;
        let ret = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
        if ret == 0 {
            return WaitStatus::StillRunning;
        }
        if ret < 0 {
            return WaitStatus::Error(std::io::Error::last_os_error());
        }
        if libc::WIFEXITED(status) {
            return WaitStatus::Exited(libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            return WaitStatus::Exited(128 + libc::WTERMSIG(status));
        }
        WaitStatus::Exited(1)
    }

    #[cfg(not(unix))]
    {
        let _ = pid;
        WaitStatus::StillRunning
    }
}
