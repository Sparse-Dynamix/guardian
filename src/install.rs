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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn require_admin_succeeds_when_privileged() {
        if !privileged() {
            return;
        }
        let ui = Ui::new(true);
        require_admin(&ui, "test action").unwrap();
    }

    #[test]
    fn require_admin_fails_when_unprivileged() {
        if privileged() {
            return;
        }
        let ui = Ui::new(true);
        let err = require_admin(&ui, "test action").unwrap_err();
        assert!(
            err.to_string().contains("administrator"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn run_install_system_fails_without_admin() {
        if privileged() {
            return;
        }
        let ui = Ui::new(true);
        let dir = TempDir::new().unwrap();
        assert!(run_install_system(dir.path(), &[TrustStore::System], &ui).is_err());
    }

    #[test]
    fn run_remove_system_fails_without_admin() {
        if privileged() {
            return;
        }
        let ui = Ui::new(true);
        let dir = TempDir::new().unwrap();
        assert!(run_remove_system(dir.path(), &[TrustStore::System], &ui).is_err());
    }

    fn write_stub(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        let script = dir.join(name);
        std::fs::write(&script, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        script
    }

    #[test]
    fn invoke_mkcert_fails_when_stub_exits_nonzero() {
        let dir = TempDir::new().unwrap();
        #[cfg(unix)]
        let stub = write_stub(dir.path(), "fail.sh", "#!/bin/sh\nexit 1\n");
        #[cfg(windows)]
        let stub = {
            let script = dir.path().join("fail.cmd");
            std::fs::write(&script, "@exit /b 1\r\n").unwrap();
            script
        };

        let prev = std::env::var_os("GUARDIAN_MKCERT_TEST");
        std::env::set_var("GUARDIAN_MKCERT_TEST", &stub);
        let result = invoke_mkcert(dir.path(), &[TrustStore::Java], "-uninstall");
        match prev {
            Some(value) => std::env::set_var("GUARDIAN_MKCERT_TEST", value),
            None => std::env::remove_var("GUARDIAN_MKCERT_TEST"),
        }

        #[cfg(unix)]
        assert!(result.is_err());
        #[cfg(windows)]
        if result.is_ok() {
            eprintln!("skipping windows nonzero stub assertion");
        }
    }

    #[test]
    fn run_install_system_succeeds_with_stub_mkcert_when_privileged() {
        if !privileged() {
            return;
        }
        let dir = TempDir::new().unwrap();
        let ui = Ui::new(true);
        let prev = std::env::var_os("GUARDIAN_MKCERT_TEST");
        #[cfg(unix)]
        let stub = write_stub(dir.path(), "ok.sh", "#!/bin/sh\nexit 0\n");
        #[cfg(unix)]
        std::env::set_var("GUARDIAN_MKCERT_TEST", &stub);
        let result = run_install_system(dir.path(), &[TrustStore::System], &ui);
        match prev {
            Some(value) => std::env::set_var("GUARDIAN_MKCERT_TEST", value),
            None => std::env::remove_var("GUARDIAN_MKCERT_TEST"),
        }
        result.expect("install should succeed when privileged");
        assert!(dir.path().join(crate::ca::ROOT_CA_PEM).is_file());
    }

    #[test]
    fn invoke_mkcert_accepts_stub_executable() {
        let dir = TempDir::new().unwrap();
        #[cfg(unix)]
        let stub = write_stub(dir.path(), "ok.sh", "#!/bin/sh\nexit 0\n");
        #[cfg(windows)]
        let stub = {
            let script = dir.path().join("stub.cmd");
            std::fs::write(&script, "@exit /b 0\r\n").unwrap();
            script
        };

        let prev = std::env::var_os("GUARDIAN_MKCERT_TEST");
        std::env::set_var("GUARDIAN_MKCERT_TEST", &stub);
        let result = invoke_mkcert(
            dir.path(),
            &[TrustStore::System, TrustStore::Nss],
            "-install",
        );
        match prev {
            Some(value) => std::env::set_var("GUARDIAN_MKCERT_TEST", value),
            None => std::env::remove_var("GUARDIAN_MKCERT_TEST"),
        }

        #[cfg(unix)]
        result.expect("stub mkcert should succeed on unix");
        #[cfg(windows)]
        {
            if result.is_err() {
                eprintln!("skipping windows stub mkcert: {:?}", result.err());
            }
        }
    }

    #[test]
    fn invoke_mkcert_with_all_stores_omits_trust_stores_env() {
        let dir = TempDir::new().unwrap();
        #[cfg(unix)]
        let stub = write_stub(dir.path(), "ok.sh", "#!/bin/sh\nexit 0\n");
        #[cfg(windows)]
        let stub = {
            let script = dir.path().join("stub.cmd");
            std::fs::write(&script, "@exit /b 0\r\n").unwrap();
            script
        };

        let prev = std::env::var_os("GUARDIAN_MKCERT_TEST");
        std::env::set_var("GUARDIAN_MKCERT_TEST", &stub);
        let result = invoke_mkcert(
            dir.path(),
            &[TrustStore::System, TrustStore::Nss, TrustStore::Java],
            "-install",
        );
        match prev {
            Some(value) => std::env::set_var("GUARDIAN_MKCERT_TEST", value),
            None => std::env::remove_var("GUARDIAN_MKCERT_TEST"),
        }

        #[cfg(unix)]
        result.expect("all-store mkcert invocation should succeed on unix");
    }

    #[test]
    fn run_remove_system_errors_when_ca_missing() {
        if !privileged() {
            return;
        }
        let ui = Ui::new(true);
        let dir = TempDir::new().unwrap();
        let err = run_remove_system(dir.path(), &[TrustStore::System], &ui).unwrap_err();
        assert!(err.to_string().contains("Guardian CA not found"));
    }
}
