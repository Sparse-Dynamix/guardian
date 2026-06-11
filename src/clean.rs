use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::Result;
use privilege::user::privileged;

use crate::ca::ROOT_CA_PEM;
use crate::config::{default_guardian_home, expand_tilde};
use crate::install::invoke_mkcert;
use crate::system_trust::TrustStore;

fn warn_system_trust_skipped() {
    #[cfg(windows)]
    eprintln!(
        "Warning: Guardian CA may still be trusted system-wide. Re-run as Administrator to remove system trust (right-click your terminal, choose 'Run as administrator', then run `guardian clean` again)."
    );
    #[cfg(not(windows))]
    eprintln!(
        "Warning: Guardian CA may still be trusted system-wide. Re-run with administrator privileges to remove system trust, e.g. `sudo guardian clean`."
    );
}

fn warn_failed_removals(paths: &[PathBuf]) {
    eprintln!("Warning: could not remove some Guardian files. Delete manually:");
    for path in paths {
        eprintln!("  {}", path.display());
    }
}

fn paths_equal(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

fn remove_path_collect(path: &Path, failed: &mut Vec<PathBuf>) {
    if !path.exists() {
        return;
    }
    let abs = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let result = if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    if let Err(e) = result {
        eprintln!("Warning: failed to remove {}: {e}", path.display());
        failed.push(abs);
    }
}

fn try_remove_empty_dir(path: &Path, failed: &mut Vec<PathBuf>) {
    if !path.is_dir() {
        return;
    }
    let empty = path
        .read_dir()
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(false);
    if !empty {
        return;
    }
    if let Err(e) = fs::remove_dir(path) {
        if e.kind() != io::ErrorKind::NotFound {
            let abs = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
            eprintln!("Warning: failed to remove {}: {e}", path.display());
            failed.push(abs);
        }
    }
}

pub fn run_clean(ca_dir: &Path, stores: &[TrustStore]) -> Result<()> {
    let mut failed = Vec::new();
    let root_ca = ca_dir.join(ROOT_CA_PEM);

    if root_ca.is_file() {
        if privileged() {
            if let Err(e) = invoke_mkcert(ca_dir, stores, "-uninstall") {
                eprintln!("Warning: failed to remove Guardian CA from system trust stores: {e:#}");
            }
        } else {
            warn_system_trust_skipped();
        }
    }

    remove_path_collect(ca_dir, &mut failed);

    if let Ok(default_home) = default_guardian_home() {
        if !paths_equal(ca_dir, &default_home) {
            let user_toml = expand_tilde("~/.guardian/guardian.toml")?;
            remove_path_collect(&user_toml, &mut failed);
            try_remove_empty_dir(&default_home, &mut failed);
        }
    }

    if !failed.is_empty() {
        warn_failed_removals(&failed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_stub(dir: &Path, name: &str, body: &str) -> PathBuf {
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
    fn run_clean_removes_local_ca_dir_when_unprivileged() {
        if privileged() {
            return;
        }
        let _guard = crate::test_lock::env_test_lock();
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(ROOT_CA_PEM), b"pem").unwrap();
        std::fs::write(dir.path().join("other.txt"), b"x").unwrap();

        run_clean(dir.path(), &[TrustStore::System]).unwrap();

        assert!(!dir.path().join(ROOT_CA_PEM).exists());
    }

    #[test]
    fn run_clean_invokes_uninstall_when_privileged_with_stub_mkcert() {
        if !privileged() {
            return;
        }
        let _guard = crate::test_lock::env_test_lock();
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(ROOT_CA_PEM), b"pem").unwrap();

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
        let result = run_clean(dir.path(), &[TrustStore::System]);
        match prev {
            Some(value) => std::env::set_var("GUARDIAN_MKCERT_TEST", value),
            None => std::env::remove_var("GUARDIAN_MKCERT_TEST"),
        }

        #[cfg(unix)]
        result.expect("clean should succeed when privileged");
    }
}
