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
    fn try_remove_empty_dir_removes_when_empty() {
        let dir = TempDir::new().unwrap();
        let empty = dir.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        let mut failed = Vec::new();
        try_remove_empty_dir(&empty, &mut failed);
        assert!(!empty.exists());
        assert!(failed.is_empty());
    }

    #[test]
    fn try_remove_empty_dir_ignores_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("file.txt");
        std::fs::write(&file, b"x").unwrap();
        let mut failed = Vec::new();
        try_remove_empty_dir(&file, &mut failed);
        assert!(file.exists());
        assert!(failed.is_empty());
    }

    #[test]
    fn remove_path_collect_noops_for_missing_path() {
        let mut failed = Vec::new();
        remove_path_collect(
            Path::new("/nonexistent/guardian-clean-missing-path"),
            &mut failed,
        );
        assert!(failed.is_empty());
    }

    #[test]
    fn paths_equal_compares_nonexistent_paths_by_equality() {
        assert!(paths_equal(
            Path::new("/nonexistent/guardian-a"),
            Path::new("/nonexistent/guardian-a"),
        ));
        assert!(!paths_equal(
            Path::new("/nonexistent/guardian-a"),
            Path::new("/nonexistent/guardian-b"),
        ));
    }

    #[test]
    fn paths_equal_returns_false_for_different_paths() {
        let a = TempDir::new().unwrap();
        let b = TempDir::new().unwrap();
        assert!(!paths_equal(a.path(), b.path()));
    }

    #[test]
    fn remove_path_collect_removes_directory() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir_all(nested.join("sub")).unwrap();
        std::fs::write(nested.join("sub/file.txt"), b"x").unwrap();
        let mut failed = Vec::new();
        remove_path_collect(&nested, &mut failed);
        assert!(!nested.exists());
        assert!(failed.is_empty());
    }

    #[test]
    fn paths_equal_compares_same_path() {
        let dir = TempDir::new().unwrap();
        assert!(paths_equal(dir.path(), dir.path()));
    }

    #[test]
    fn remove_path_collect_removes_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("x.txt");
        std::fs::write(&file, b"x").unwrap();
        let mut failed = Vec::new();
        remove_path_collect(&file, &mut failed);
        assert!(!file.exists());
        assert!(failed.is_empty());
    }

    #[test]
    fn run_clean_succeeds_when_ca_dir_has_no_root_pem() {
        let dir = TempDir::new().unwrap();
        run_clean(dir.path(), &[]).expect("clean empty ca dir");
    }

    #[test]
    fn try_remove_empty_dir_skips_nonempty() {
        let dir = TempDir::new().unwrap();
        let nonempty = dir.path().join("nonempty");
        std::fs::create_dir(&nonempty).unwrap();
        std::fs::write(nonempty.join("file.txt"), b"x").unwrap();
        let mut failed = Vec::new();
        try_remove_empty_dir(&nonempty, &mut failed);
        assert!(nonempty.is_dir());
        assert!(failed.is_empty());
    }

    #[test]
    fn run_clean_removes_custom_ca_dir_and_default_home_artifacts() {
        let _guard = crate::test_lock::env_test_lock();
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("marker.txt"), b"x").unwrap();

        let default_home = default_guardian_home().expect("default guardian home");
        let user_toml = expand_tilde("~/.guardian/guardian.toml").expect("user toml path");
        let prev_toml = user_toml
            .exists()
            .then(|| std::fs::read(&user_toml).unwrap());
        if let Some(parent) = user_toml.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&user_toml, b"[test]\n").unwrap();

        run_clean(dir.path(), &[]).expect("clean custom ca dir");

        assert!(!dir.path().join("marker.txt").exists());
        if !paths_equal(dir.path(), &default_home) {
            assert!(!user_toml.exists());
        }
        match prev_toml {
            Some(bytes) => std::fs::write(&user_toml, bytes).unwrap(),
            None => {
                let _ = std::fs::remove_file(&user_toml);
                try_remove_empty_dir(&default_home, &mut Vec::new());
            }
        }
    }

    #[test]
    fn run_clean_warns_when_mkcert_uninstall_fails() {
        if !privileged() {
            return;
        }
        let _guard = crate::test_lock::env_test_lock();
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(ROOT_CA_PEM), b"pem").unwrap();

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
        let result = run_clean(dir.path(), &[TrustStore::System]);
        match prev {
            Some(value) => std::env::set_var("GUARDIAN_MKCERT_TEST", value),
            None => std::env::remove_var("GUARDIAN_MKCERT_TEST"),
        }

        result.expect("clean should succeed even when mkcert uninstall fails");
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

        result.expect("clean should succeed when privileged");
    }

    #[test]
    fn warn_failed_removals_prints_each_path() {
        warn_failed_removals(&[
            PathBuf::from("/tmp/guardian-clean-missing-a"),
            PathBuf::from("/tmp/guardian-clean-missing-b"),
        ]);
    }

    #[test]
    fn warn_system_trust_skipped_prints_notice() {
        warn_system_trust_skipped();
    }

    fn make_undeletable_dir(parent: &Path) -> PathBuf {
        let nested = parent.join("nested");
        std::fs::create_dir_all(nested.join("inner")).unwrap();
        std::fs::write(nested.join("inner/file.txt"), b"x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o555)).unwrap();
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let inner = nested.join("inner/file.txt");
            let _lock = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0)
                .open(&inner)
                .expect("exclusive lock");
            std::mem::forget(_lock);
        }
        nested
    }

    #[test]
    fn remove_path_collect_records_undeletable_file() {
        let dir = TempDir::new().unwrap();
        let nested = make_undeletable_dir(dir.path());

        let mut failed = Vec::new();
        remove_path_collect(&nested, &mut failed);
        assert!(!failed.is_empty());
        assert!(nested.exists());
    }

    #[test]
    fn run_clean_warns_when_ca_dir_cannot_be_removed() {
        let dir = TempDir::new().unwrap();
        let _nested = make_undeletable_dir(dir.path());

        run_clean(dir.path(), &[]).expect("clean should succeed with warnings");
        assert!(dir.path().join("nested").exists());
    }

    #[cfg(unix)]
    #[test]
    fn try_remove_empty_dir_records_failure_when_parent_is_read_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let parent = dir.path().join("parent");
        let empty = parent.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o555)).unwrap();

        let mut failed = Vec::new();
        try_remove_empty_dir(&empty, &mut failed);
        assert!(!failed.is_empty());
        let _ = std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755));
    }
}
