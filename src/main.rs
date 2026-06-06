mod ca;
mod cli;
mod config;
mod frida_ext;
mod injector;
mod jsonl;
mod port;
mod proxy;

use std::io::Write;
use std::net::IpAddr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::Parser;
use proxyapi::ca::Ssl;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use crate::ca::CaTrust;
use crate::cli::Cli;
use crate::config::{resolve_settings, Settings};

struct PrefixedStderr {
    inner: std::io::Stderr,
    pending_prefix: bool,
}

impl Write for PrefixedStderr {
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
                    self.inner.write_all(b"guardian: ")?;
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

fn init_tracing(verbose: bool) {
    let env_filter = if verbose || std::env::var_os("RUST_LOG").is_some() {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("guardian=debug"))
    } else {
        EnvFilter::new("off")
    };

    let writer = Mutex::new(PrefixedStderr {
        inner: std::io::stderr(),
        pending_prefix: true,
    });

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(writer)
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

async fn run(settings: Settings) -> Result<i32> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut ca_trust = CaTrust::from_ca_dir(&settings.ca_dir);
    Ssl::load_or_generate(&settings.ca_dir).context("failed to load/generate Proxelar CA")?;
    ca_trust
        .ensure_artifacts()
        .context("failed to prepare CA trust artifacts")?;

    let bind_ip: IpAddr = settings.bind.into();
    let (port_tx, port_rx) = mpsc::channel::<u16>();
    let (proxy_ready_tx, proxy_ready_rx) = mpsc::channel::<()>();

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
            )
        }
    });

    let port = tokio::task::spawn_blocking(move || port_rx.recv())
        .await
        .context("port channel join failed")?
        .context("failed to receive allocated port")?;

    let proxy_handle = proxy::start_proxy_and_wait(
        bind_ip,
        port,
        &settings.ca_dir,
        settings.body_limit,
    )
    .await
    .context("failed to start embedded proxy")?;

    proxy_ready_tx
        .send(())
        .context("failed to signal proxy ready to injector")?;

    let cancel = CancellationToken::new();
    let jsonl_cancel = cancel.clone();
    let silent = settings.silent;
    let body_limit = settings.body_limit;
    let event_rx = proxy_handle.event_rx;

    let jsonl_task = tokio::spawn(async move {
        jsonl::run_sink(event_rx, silent, body_limit).await;
        jsonl_cancel.cancel();
    });

    let ctrl_c = cancel.clone();
    let proxy_cancel = proxy_handle.cancel.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        ctrl_c.cancel();
        proxy_cancel.cancel();
    });

    let outcome = injection.await.context("injection join failed")??;

    proxy_handle.cancel.cancel();
    cancel.cancel();
    let _ = jsonl_task.await;

    Ok(normalize_exit_code(outcome.exit_code))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let settings = resolve_settings(&cli)?;
    let code = run(settings).await?;
    std::process::exit(code);
}
