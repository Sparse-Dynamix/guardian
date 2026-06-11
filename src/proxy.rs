use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use proxyapi::content_filter::ContentFilter;
use proxyapi::{Proxy, ProxyConfig, ProxyMode};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::Settings;
use crate::trypanophobe::TrypanophobeClient;

pub struct ProxyHandle {
    pub cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl ProxyHandle {
    pub async fn shutdown(self, grace: Duration) -> Result<()> {
        self.cancel.cancel();
        if tokio::time::timeout(grace, self.task)
            .await
            .ok()
            .and_then(|join| join.err())
            .is_some()
        {
            eprintln!("Warning: proxy task join failed");
        }
        Ok(())
    }
}

pub fn start_proxy(
    settings: &Settings,
    bind_ip: IpAddr,
    port: u16,
) -> Result<(ProxyHandle, oneshot::Receiver<()>)> {
    let cancel = CancellationToken::new();
    let (ready_tx, ready_rx) = oneshot::channel();

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
        upstream_tls: settings.upstream_tls.clone(),
        intercept: None,
        body_capture_limit: None,
        replay_rx: None,
        ready_tx: Some(ready_tx),
    };

    let proxy = Proxy::new(proxy_config);
    let cancel_for_proxy = cancel.clone();

    let task = tokio::spawn(async move {
        if let Err(e) = proxy
            .start(cancel_for_proxy.clone().cancelled_owned())
            .await
        {
            eprintln!("Error: proxy failed: {e:#}");
            cancel_for_proxy.cancel();
        }
    });

    Ok((ProxyHandle { cancel, task }, ready_rx))
}

pub async fn start_proxy_and_wait(
    settings: &Settings,
    bind_ip: IpAddr,
    port: u16,
) -> Result<ProxyHandle> {
    let timeout = Duration::from_secs(settings.proxy_ready_timeout_secs);
    let (handle, ready_rx) =
        start_proxy(settings, bind_ip, port).context("failed to spawn proxy task")?;

    tokio::select! {
        res = ready_rx => {
            res.context("proxy ready channel closed unexpectedly")?;
            Ok(handle)
        }
        _ = handle.cancel.cancelled() => {
            anyhow::bail!("proxy failed to start (check logs for details)");
        }
        _ = tokio::time::sleep(timeout) => {
            anyhow::bail!("proxy failed to start within {timeout:?}");
        }
    }
}
