mod ca;
mod cli;
mod config;
mod filter;
mod frida_ext;
mod injector;
mod install;
mod mkcert;
mod port;
mod proxy;
mod signals;
mod system_trust;
mod trypanophobe;
mod ui;

use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use proxyapi::ca::Ssl;
use tracing_subscriber::EnvFilter;

use crate::ca::CaTrust;
use crate::cli::{Cli, Commands};
use crate::config::{
    is_payload_mode, resolve_ca_dir, resolve_no_color, resolve_payload_settings, resolve_settings,
    resolve_trust_stores, validate_mode_exclusivity, Settings,
};
use crate::injector::SpawnOutcome;
use crate::system_trust::TrustStore;
use crate::trypanophobe::run_payload;
use crate::ui::Ui;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

struct PrefixedWriter<W: Write> {
    inner: W,
    prefix: String,
    pending_prefix: bool,
}

impl<W: Write> PrefixedWriter<W> {
    fn new(inner: W, prefix: String) -> Self {
        Self {
            inner,
            prefix,
            pending_prefix: true,
        }
    }
}

impl<W: Write> Write for PrefixedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written = 0;
        for chunk in buf.split(|&b| b == b'\n') {
            if written > 0 {
                self.inner.write_all(b"\n")?;
                written += 1;
                self.pending_prefix = true;
            }
            if !chunk.is_empty() || written == 0 {
                if self.pending_prefix || written == 0 {
                    self.inner.write_all(self.prefix.as_bytes())?;
                    self.pending_prefix = false;
                }
                self.inner.write_all(chunk)?;
                written += chunk.len();
            }
        }
        if buf.last() == Some(&b'\n') {
            self.inner.write_all(b"\n")?;
            self.pending_prefix = true;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn init_tracing(verbose: bool, settings: &Settings) {
    let env_filter = if verbose || std::env::var_os("RUST_LOG").is_some() {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(&settings.tracing_default_level))
    } else {
        EnvFilter::new("off")
    };

    let writer = Mutex::new(PrefixedWriter::new(
        std::io::stderr(),
        settings.tracing_prefix.clone(),
    ));
    let use_ansi = !settings.no_color;

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(writer)
        .with_ansi(use_ansi)
        .with_target(false)
        .without_time()
        .compact()
        .init();
}

fn normalize_exit_code(code: i32) -> i32 {
    if cfg!(windows) && code > 255 {
        code & 0xFF
    } else {
        code
    }
}

fn print_run_warnings(settings: &Settings, ui: &Ui) -> Result<()> {
    ui.warn(
        "Guardian may not capture all network traffic. We do our best, but some apps, protocols, or pinned TLS may bypass interception.",
    );

    let stores: Vec<TrustStore> = TrustStore::parse_all(&settings.trust_stores);
    if !system_trust::is_installed(&settings.ca_dir, &stores)? {
        ui.warn(
            "The Guardian CA is not installed in your system trust store. Run `guardian install-system` with administrator privileges to improve HTTPS interception.",
        );
    }
    Ok(())
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

async fn run_mitm_filtered(settings: Settings, ui: &Ui) -> Result<i32> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    print_run_warnings(&settings, ui)?;

    let mut ca_trust = CaTrust::from_settings(&settings);
    Ssl::load_or_generate(&settings.ca_dir).context("failed to load/generate Guardian CA")?;
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

    let outcome = tokio::select! {
        join = &mut injection => join.context("injection join failed")??,
        res = signals::shutdown_signal() => {
            res?;
            let _ = interrupt_tx.send(());
            proxy_cancel.cancel();
            match tokio::time::timeout(SHUTDOWN_GRACE, &mut injection).await {
                Ok(Ok(Ok(outcome))) => outcome,
                _ => SpawnOutcome { exit_code: 130 },
            }
        }
    };

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    proxy_handle.cancel.cancel();

    Ok(normalize_exit_code(outcome.exit_code))
}

async fn run_mitm(settings: Settings, ui: &Ui) -> Result<i32> {
    if settings.trypanophobe_filter.is_none() {
        run_mitm_passthrough(&settings)
    } else {
        run_mitm_filtered(settings, ui).await
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
        Some(Commands::InstallSystem(opts)) => {
            let ca_dir = resolve_ca_dir(&cli)?;
            let no_color = resolve_no_color(&cli)?;
            let settings = Settings {
                ca_dir: ca_dir.clone(),
                no_color,
                ..minimal_settings(ca_dir)
            };
            let ui = Ui::from_settings(&settings);
            init_tracing(cli.verbose, &settings);
            let stores = TrustStore::parse_all(&resolve_trust_stores(&cli, Some(opts)));
            install::run_install_system(&settings.ca_dir, &stores, &ui)?;
            Ok(0)
        }
        Some(Commands::RemoveSystem(opts)) => {
            let ca_dir = resolve_ca_dir(&cli)?;
            let no_color = resolve_no_color(&cli)?;
            let settings = Settings {
                ca_dir: ca_dir.clone(),
                no_color,
                ..minimal_settings(ca_dir)
            };
            let ui = Ui::from_settings(&settings);
            init_tracing(cli.verbose, &settings);
            let stores = TrustStore::parse_all(&resolve_trust_stores(&cli, Some(opts)));
            install::run_remove_system(&settings.ca_dir, &stores, &ui)?;
            Ok(0)
        }
        Some(Commands::CheckSystem(opts)) => {
            let ca_dir = resolve_ca_dir(&cli)?;
            let no_color = resolve_no_color(&cli)?;
            let settings = Settings {
                ca_dir: ca_dir.clone(),
                no_color,
                ..minimal_settings(ca_dir)
            };
            let ui = Ui::from_settings(&settings);
            init_tracing(cli.verbose, &settings);
            let stores = TrustStore::parse_all(&resolve_trust_stores(&cli, Some(opts)));
            let ok = system_trust::run_check_system(&settings.ca_dir, &stores, &ui)?;
            if ok {
                Ok(0)
            } else {
                Ok(1)
            }
        }
        None => {
            validate_mode_exclusivity(&cli)?;

            if is_payload_mode(&cli) {
                let settings = resolve_payload_settings(&cli)?;
                init_tracing(cli.verbose, &settings);
                return run_payload(&settings).await;
            }

            if cli.program.is_empty() {
                bail!(
                    "program is required after --, or use --payload / pipe stdin for payload mode"
                );
            }

            let settings = resolve_settings(&cli)?;
            let ui = Ui::from_settings(&settings);
            init_tracing(cli.verbose, &settings);
            run_mitm(settings, &ui).await
        }
    }
}

fn minimal_settings(ca_dir: std::path::PathBuf) -> Settings {
    Settings {
        bind: "127.0.0.1".parse().unwrap(),
        port: None,
        trypanophobe_filter: None,
        payload: None,
        filter: String::new(),
        ca_dir,
        no_color: false,
        filter_timeout_secs: 10,
        filter_body_limit: 1_048_576,
        block_message: trypanophobe::DEFAULT_BLOCK_MESSAGE.to_string(),
        port_min: 1024,
        port_max: 65535,
        proxy_event_channel_capacity: 10_000,
        proxy_ready_timeout_secs: 5,
        proxy_ready_poll_ms: 10,
        process_poll_interval_ms: 50,
        ca_bundle_name: "guardian-ca-bundle.pem".into(),
        java_truststore_name: "guardian-java-truststore.p12".into(),
        java_truststore_password: "guardian".into(),
        deno_tls_ca_store: "system,mozilla".into(),
        node_options_append: "--use-openssl-ca".into(),
        tracing_prefix: "guardian: ".into(),
        tracing_default_level: "guardian=debug".into(),
        program: String::new(),
        args: vec![],
        trust_stores: system_trust::default_trust_stores(),
    }
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    use super::{exit_code_from_run, normalize_exit_code};

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

    #[test]
    fn prefixed_writer_inserts_prefix_per_line() {
        use super::PrefixedWriter;
        use std::io::Write;

        let mut buf = Vec::new();
        {
            let mut writer = PrefixedWriter::new(&mut buf, "pfx: ".into());
            writer.write_all(b"one\n").unwrap();
            writer.write_all(b"two").unwrap();
            writer.flush().unwrap();
        }
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("pfx: one"));
        assert!(out.contains("pfx: two"));
    }
}
