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
    prefix: String,
    pending_prefix: bool,
}

impl PrefixedStderr {
    fn new(prefix: String) -> Self {
        Self {
            inner: std::io::stderr(),
            prefix,
            pending_prefix: true,
        }
    }
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

    let writer = Mutex::new(PrefixedStderr::new(settings.tracing_prefix.clone()));

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

    let mut ca_trust = CaTrust::from_settings(&settings);
    Ssl::load_or_generate(&settings.ca_dir).context("failed to load/generate Proxelar CA")?;
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

    let cancel = CancellationToken::new();
    let jsonl_cancel = cancel.clone();
    let silent = settings.silent;
    let body_limit = settings.body_limit;
    let event_rx = proxy_handle.event_rx;

    let jsonl_task = tokio::spawn(async move {
        let result = jsonl::run_sink(event_rx, silent, body_limit).await;
        jsonl_cancel.cancel();
        result
    });

    let ctrl_c = cancel.clone();
    let proxy_cancel = proxy_handle.cancel.clone();
    let ctrl_c_task = tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for Ctrl+C");
        let _ = interrupt_tx.send(());
        ctrl_c.cancel();
        proxy_cancel.cancel();
    });

    let outcome = injection.await.context("injection join failed")??;

    ctrl_c_task.abort();
    // Proxelar may emit RequestComplete from spawned tasks after the child exits.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    proxy_handle.cancel.cancel();
    cancel.cancel();
    jsonl_task.await.context("jsonl task join failed")??;

    Ok(normalize_exit_code(outcome.exit_code))
}

#[cfg(test)]
mod tests {
    use super::normalize_exit_code;

    #[test]
    fn normalize_exit_code_passes_through_on_unix() {
        assert_eq!(normalize_exit_code(0), 0);
        assert_eq!(normalize_exit_code(130), 130);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let settings = resolve_settings(&cli)?;
    init_tracing(cli.verbose, &settings);
    let code = run(settings).await?;
    std::process::exit(code);
}
