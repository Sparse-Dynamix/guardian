use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use proxyapi::event::ProxyEvent;
use proxyapi::{Proxy, ProxyConfig, ProxyMode};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::Settings;

pub struct ProxyHandle {
    pub event_rx: mpsc::Receiver<ProxyEvent>,
    pub cancel: CancellationToken,
}

pub fn start_proxy(settings: &Settings, bind_ip: IpAddr, port: u16) -> Result<ProxyHandle> {
    let (event_tx, event_rx) = mpsc::channel(settings.proxy_event_channel_capacity);
    let cancel = CancellationToken::new();

    let proxy_config = ProxyConfig {
        addr: SocketAddr::new(bind_ip, port),
        mode: ProxyMode::Forward,
        event_tx,
        ca_dir: settings.ca_dir.clone(),
        upstream_tls: Default::default(),
        intercept: None,
        // Capture more than the JSONL preview cap so `body_truncated` reflects the full body size.
        body_capture_limit: Some(settings.body_limit.saturating_mul(8).max(512)),
        replay_rx: None,
    };

    let proxy = Proxy::new(proxy_config);
    let cancel_for_proxy = cancel.clone();

    tokio::spawn(async move {
        if let Err(e) = proxy
            .start(cancel_for_proxy.clone().cancelled_owned())
            .await
        {
            tracing::error!(target: "guardian", "proxy error: {e}");
            cancel_for_proxy.cancel();
        }
    });

    Ok(ProxyHandle { event_rx, cancel })
}

async fn wait_for_listener(
    bind_ip: IpAddr,
    port: u16,
    cancel: &CancellationToken,
    settings: &Settings,
) -> Result<()> {
    let addr = SocketAddr::new(bind_ip, port);
    let timeout = Duration::from_secs(settings.proxy_ready_timeout_secs);
    let poll = Duration::from_millis(settings.proxy_ready_poll_ms);
    let deadline = Instant::now() + timeout;
    loop {
        if cancel.is_cancelled() {
            anyhow::bail!("proxy failed to start (check logs for details)");
        }
        if TcpStream::connect(addr).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("proxy failed to start within {timeout:?}");
        }
        tokio::time::sleep(poll).await;
    }
}

pub async fn start_proxy_and_wait(
    settings: &Settings,
    bind_ip: IpAddr,
    port: u16,
) -> Result<ProxyHandle> {
    let handle = start_proxy(settings, bind_ip, port).context("failed to spawn proxy task")?;
    wait_for_listener(bind_ip, port, &handle.cancel, settings).await?;
    Ok(handle)
}
