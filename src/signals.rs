use anyhow::{Context, Result};

pub async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).context("failed to listen for SIGTERM")?;
        tokio::select! {
            res = tokio::signal::ctrl_c() => res.context("failed to listen for Ctrl+C")?,
            _ = sigterm.recv() => {}
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_close, ctrl_c};
        let mut ctrl_c = ctrl_c().context("failed to listen for Ctrl+C")?;
        let mut ctrl_break = ctrl_break().context("failed to listen for Ctrl+Break")?;
        let mut ctrl_close = ctrl_close().context("failed to listen for console close")?;
        tokio::select! {
            res = ctrl_c.recv() => res.context("Ctrl+C stream closed")?,
            res = ctrl_break.recv() => res.context("Ctrl+Break stream closed")?,
            res = ctrl_close.recv() => res.context("console close stream closed")?,
        }
        Ok(())
    }
}
