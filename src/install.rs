use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use privilege::user::privileged;
use proxyapi::ca::Ssl;

use crate::mkcert;
use crate::system_trust::TrustStore;
use crate::ui::Ui;

pub fn require_admin(ui: &Ui, action: &str) -> Result<()> {
    if privileged() {
        return Ok(());
    }
    #[cfg(windows)]
    let msg = format!(
        "{action} requires running as Administrator. Right-click your terminal, choose 'Run as administrator', then try again."
    );
    #[cfg(not(windows))]
    let msg = format!(
        "{action} requires administrator privileges. Re-run with sudo, e.g. `sudo guardian install-system`."
    );
    ui.error(&msg);
    bail!("administrator privileges required");
}

pub fn run_install_system(ca_dir: &Path, stores: &[TrustStore], ui: &Ui) -> Result<()> {
    require_admin(ui, "Installing the Guardian CA system-wide")?;
    std::fs::create_dir_all(ca_dir)
        .with_context(|| format!("failed to create {}", ca_dir.display()))?;
    Ssl::load_or_generate(ca_dir).context("failed to load/generate Guardian CA")?;
    invoke_mkcert(ca_dir, stores, "-install")?;
    ui.success("Guardian CA install finished (see mkcert output above for details)");
    Ok(())
}

pub fn run_remove_system(ca_dir: &Path, stores: &[TrustStore], ui: &Ui) -> Result<()> {
    require_admin(ui, "Removing the Guardian CA from system trust stores")?;
    if !ca_dir.join(crate::ca::ROOT_CA_PEM).exists() {
        bail!(
            "Guardian CA not found at {}",
            ca_dir.join(crate::ca::ROOT_CA_PEM).display()
        );
    }
    invoke_mkcert(ca_dir, stores, "-uninstall")?;
    ui.success("Guardian CA removal finished (see mkcert output above for details)");
    Ok(())
}

fn invoke_mkcert(ca_dir: &Path, stores: &[TrustStore], flag: &str) -> Result<()> {
    let mkcert_path = mkcert::executable_path(ca_dir)?;
    let mut cmd = Command::new(&mkcert_path);
    cmd.env("CAROOT", ca_dir).arg(flag);
    if stores.len() < 3 {
        let list = stores
            .iter()
            .map(|s| match s {
                TrustStore::System => "system",
                TrustStore::Nss => "nss",
                TrustStore::Java => "java",
            })
            .collect::<Vec<_>>()
            .join(",");
        cmd.env("TRUST_STORES", list);
    }
    let status = cmd
        .status()
        .with_context(|| format!("failed to execute {}", mkcert_path.display()))?;
    if !status.success() {
        bail!("mkcert {flag} exited with {status}");
    }
    Ok(())
}
