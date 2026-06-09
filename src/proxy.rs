use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use proxyapi::content_filter::ContentFilter;
use proxyapi::{Proxy, ProxyConfig, ProxyMode};
use tokio_util::sync::CancellationToken;

use crate::config::Settings;
use crate::trypanophobe::TrypanophobeClient;

pub struct ProxyHandle {
    pub cancel: CancellationToken,
}

pub fn start_proxy(settings: &Settings, bind_ip: IpAddr, port: u16) -> Result<ProxyHandle> {
    let cancel = CancellationToken::new();

    let content_filter: Option<Arc<dyn ContentFilter>> = if settings.trypanophobe_filter.is_some() {
        Some(Arc::new(TrypanophobeClient::from_settings(settings)?) as Arc<dyn ContentFilter>)
    } else {
        None
    };

    let proxy_config = ProxyConfig {
        addr: SocketAddr::new(bind_ip, port),
        mode: ProxyMode::Forward,
        event_tx: None,
        content_filter,
        ca_dir: settings.ca_dir.clone(),
        upstream_tls: Default::default(),
        intercept: None,
        body_capture_limit: None,
        replay_rx: None,
    };

    let proxy = Proxy::new(proxy_config);
    let cancel_for_proxy = cancel.clone();

    tokio::spawn(async move {
        if let Err(e) = proxy
            .start(cancel_for_proxy.clone().cancelled_owned())
            .await
        {
            eprintln!("Error: proxy failed: {e:#}");
            cancel_for_proxy.cancel();
        }
    });

    Ok(ProxyHandle { cancel })
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
