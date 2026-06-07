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
        tokio::select! {
            res = ctrl_c() => res.context("failed to listen for Ctrl+C")?,
            res = ctrl_break() => res.context("failed to listen for Ctrl+Break")?,
            res = ctrl_close() => res.context("failed to listen for console close")?,
        }
        Ok(())
    }
}
