use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use anyhow::{Context, Result};
use proxyapi::event::ProxyEvent;
use proxyapi::{InterceptConfig, Proxy, ProxyConfig, ProxyMode};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const EVENT_CHANNEL_CAPACITY: usize = 10_000;

pub struct ProxyHandle {
    pub event_rx: mpsc::Receiver<ProxyEvent>,
    pub cancel: CancellationToken,
}

pub fn start_proxy(
    bind_ip: IpAddr,
    port: u16,
    ca_dir: &Path,
    body_limit: usize,
) -> Result<ProxyHandle> {
    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let cancel = CancellationToken::new();

    let proxy_config = ProxyConfig {
        addr: SocketAddr::new(bind_ip, port),
        mode: ProxyMode::Forward,
        event_tx,
        ca_dir: ca_dir.to_path_buf(),
        upstream_tls: Default::default(),
        intercept: Some(InterceptConfig::new()),
        body_capture_limit: Some(body_limit),
        replay_rx: None,
    };

    let proxy = Proxy::new(proxy_config);
    let cancel_for_proxy = cancel.clone();

    tokio::spawn(async move {
        if let Err(e) = proxy.start(cancel_for_proxy.clone().cancelled_owned()).await {
            tracing::error!(target: "guardian", "proxy error: {e}");
            cancel_for_proxy.cancel();
        }
    });

    Ok(ProxyHandle { event_rx, cancel })
}

pub async fn start_proxy_and_wait(
    bind_ip: IpAddr,
    port: u16,
    ca_dir: &Path,
    body_limit: usize,
) -> Result<ProxyHandle> {
    let handle = start_proxy(bind_ip, port, ca_dir, body_limit)
        .context("failed to spawn proxy task")?;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    if handle.cancel.is_cancelled() {
        anyhow::bail!("proxy failed to start (check logs for details)");
    }
    Ok(handle)
}
