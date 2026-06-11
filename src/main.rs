mod ca;
mod child_exit;
mod clean;
mod cli;
mod config;
mod filter;
mod frida_ext;
mod injector;
mod install;
mod mkcert;
mod notes;
mod port;
mod proxy;
mod secure_file;
mod signals;
mod system_trust;
#[cfg(test)]
mod test_lock;
mod trypanophobe;

use std::net::IpAddr;
use std::process::{Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use crate::ca::{load_or_generate_ca, CaTrust};
use crate::cli::{Cli, Commands};
use crate::config::{
    is_payload_mode, resolve_ca_dir, resolve_payload_settings, resolve_settings,
    resolve_trust_stores, validate_mode_exclusivity, Settings,
};
use crate::injector::SpawnOutcome;
use crate::system_trust::TrustStore;
use crate::trypanophobe::run_payload;
use anyhow::{bail, Context, Result};
use clap::Parser;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

fn normalize_exit_code(code: i32) -> i32 {
    if cfg!(windows) && code > 255 {
        code & 0xFF
    } else {
        code
    }
}

fn run_mitm_passthrough(settings: &Settings) -> Result<i32> {
    let status = Command::new(&settings.program)
        .args(&settings.args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("failed to spawn {}", settings.program))?;
    Ok(normalize_exit_code(status.code().unwrap_or(-1)))
}

async fn run_mitm_filtered(settings: Settings) -> Result<i32> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut ca_trust = CaTrust::from_settings(&settings);
    load_or_generate_ca(&settings.ca_dir)?;
    ca_trust
        .ensure_artifacts(&settings)
        .context("failed to prepare CA trust artifacts")?;

    let bind_ip: IpAddr = settings.bind.into();
    let (port_tx, port_rx) = mpsc::channel::<u16>();
    let (proxy_ready_tx, proxy_ready_rx) = mpsc::channel::<()>();
    let (interrupt_tx, interrupt_rx) = mpsc::channel::<()>();

    let settings_arc = Arc::new(settings.clone());
    let ca_arc = Arc::new(ca_trust);

    let injection = tokio::task::spawn_blocking({
        let settings = settings_arc.clone();
        let ca = ca_arc.clone();
        move || {
            injector::run_injection_coordinated(
                &settings,
                &ca,
                bind_ip,
                port_tx,
                proxy_ready_rx,
                interrupt_rx,
            )
        }
    });

    let port = match tokio::task::spawn_blocking(move || port_rx.recv())
        .await
        .context("port channel join failed")?
    {
        Ok(port) => port,
        Err(_) => {
            return match injection.await.context("injection join failed")? {
                Ok(_) => Err(anyhow::anyhow!("failed to receive allocated port")),
                Err(e) => Err(e),
            };
        }
    };

    let proxy_handle = proxy::start_proxy_and_wait(&settings, bind_ip, port)
        .await
        .context("failed to start embedded proxy")?;

    proxy_ready_tx
        .send(())
        .context("failed to signal proxy ready to injector")?;

    let proxy_cancel = proxy_handle.cancel.clone();
    let mut injection = injection;

    enum ShutdownPath {
        Normal(SpawnOutcome),
        Interrupted(SpawnOutcome),
        Forced,
    }

    let path = tokio::select! {
        join = &mut injection => ShutdownPath::Normal(join.context("injection join failed")??),
        res = signals::shutdown_signal() => {
            res?;
            let _ = interrupt_tx.send(());
            proxy_cancel.cancel();
            tokio::select! {
                res = tokio::time::timeout(SHUTDOWN_GRACE, &mut injection) => {
                    let outcome = match res {
                        Ok(Ok(Ok(outcome))) => outcome,
                        _ => SpawnOutcome { exit_code: 130 },
                    };
                    ShutdownPath::Interrupted(outcome)
                }
                _ = signals::force_shutdown_signal() => {
                    injection.abort();
                    ShutdownPath::Forced
                }
            }
        }
    };

    let mut exit_code = match path {
        ShutdownPath::Forced => 130,
        ShutdownPath::Normal(outcome) | ShutdownPath::Interrupted(outcome) => outcome.exit_code,
    };

    let proxy_forced = tokio::select! {
        res = proxy_handle.shutdown(SHUTDOWN_GRACE) => {
            res?;
            false
        }
        _ = signals::force_shutdown_signal() => {
            proxy_cancel.cancel();
            true
        }
    };
    if proxy_forced {
        exit_code = 130;
    }

    Ok(normalize_exit_code(exit_code))
}

async fn run_mitm(settings: Settings) -> Result<i32> {
    if settings.trypanophobe_filter.is_none() {
        run_mitm_passthrough(&settings)
    } else {
        run_mitm_filtered(settings).await
    }
}

fn exit_code_from_run(result: Result<i32>) -> ExitCode {
    match result {
        Ok(code) => ExitCode::from(normalize_exit_code(code) as u8),
        Err(e) => {
            eprintln!("Error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error: failed to start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    exit_code_from_run(runtime.block_on(async_main()))
}

async fn async_main() -> Result<i32> {
    let cli = Cli::parse();

    match &cli.command {
        Some(cmd @ (Commands::LegalNotes | Commands::LicenseNotes | Commands::SecurityNotes)) => {
            notes::print(cmd);
            Ok(0)
        }
        Some(Commands::InstallSystem(opts)) => {
            let ca_dir = resolve_ca_dir(&cli)?;
            let stores = TrustStore::parse_all(&resolve_trust_stores(&cli, Some(opts)));
            install::run_install_system(&ca_dir, &stores)?;
            Ok(0)
        }
        Some(Commands::RemoveSystem(opts)) => {
            let ca_dir = resolve_ca_dir(&cli)?;
            let stores = TrustStore::parse_all(&resolve_trust_stores(&cli, Some(opts)));
            install::run_remove_system(&ca_dir, &stores)?;
            Ok(0)
        }
        Some(Commands::CheckSystem(opts)) => {
            let ca_dir = resolve_ca_dir(&cli)?;
            let stores = TrustStore::parse_all(&resolve_trust_stores(&cli, Some(opts)));
            let ok = system_trust::run_check_system(&ca_dir, &stores)?;
            if ok {
                Ok(0)
            } else {
                Ok(1)
            }
        }
        Some(Commands::Clean(opts)) => {
            let ca_dir = resolve_ca_dir(&cli)?;
            let stores = TrustStore::parse_all(&resolve_trust_stores(&cli, Some(opts)));
            clean::run_clean(&ca_dir, &stores)?;
            Ok(0)
        }
        None => {
            validate_mode_exclusivity(&cli)?;

            if is_payload_mode(&cli) {
                let settings = resolve_payload_settings(&cli)?;
                return run_payload(&settings).await;
            }

            if cli.program.is_empty() {
                bail!(
                    "program is required after --, or use --payload / pipe stdin for payload mode"
                );
            }

            let settings = resolve_settings(&cli)?;
            run_mitm(settings).await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    use clap::Parser;

    use super::{exit_code_from_run, normalize_exit_code, run_mitm, run_mitm_passthrough};
    use crate::cli::Cli;
    use crate::config::resolve_settings;

    #[test]
    fn normalize_exit_code_passes_through_on_unix() {
        assert_eq!(normalize_exit_code(0), 0);
        assert_eq!(normalize_exit_code(130), 130);
    }

    #[test]
    fn normalize_exit_code_masks_high_byte_on_windows() {
        if cfg!(windows) {
            assert_eq!(normalize_exit_code(260), 4);
        }
    }

    #[test]
    fn exit_code_from_run_maps_success_and_failure() {
        assert_eq!(exit_code_from_run(Ok(0)), ExitCode::SUCCESS);
        assert_eq!(exit_code_from_run(Ok(42)), ExitCode::from(42));
        assert_eq!(
            exit_code_from_run(Err(anyhow::anyhow!("boom"))),
            ExitCode::FAILURE
        );
    }

    fn true_settings() -> crate::config::Settings {
        let argv: Vec<&str> = if cfg!(windows) {
            vec!["guardian", "--", "cmd.exe", "/C", "exit", "0"]
        } else {
            vec!["guardian", "--", "true"]
        };
        let cli = Cli::try_parse_from(argv).unwrap();
        resolve_settings(&cli).unwrap()
    }

    #[test]
    fn run_mitm_passthrough_runs_child() {
        let settings = true_settings();
        assert_eq!(run_mitm_passthrough(&settings).unwrap(), 0);
    }

    #[tokio::test]
    async fn run_mitm_without_tpf_passthrough() {
        let settings = true_settings();
        assert!(settings.trypanophobe_filter.is_none());
        assert_eq!(run_mitm(settings).await.unwrap(), 0);
    }
}
