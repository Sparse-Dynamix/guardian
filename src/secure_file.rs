use std::fs;
use std::path::Path;

#[cfg(windows)]
use std::process::Command;

#[cfg(windows)]
use anyhow::bail;
use anyhow::{Context, Result};

pub fn restrict_private_key(path: &Path) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to restrict permissions on {}", path.display()))?;
    }

    #[cfg(windows)]
    {
        let username = std::env::var("USERNAME").context("USERNAME not set")?;
        let grant = format!("{username}:(F)");
        let status = Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r", &grant])
            .status()
            .with_context(|| format!("failed to run icacls on {}", path.display()))?;
        if !status.success() {
            bail!("icacls failed for {}", path.display());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn restrict_private_key_noops_when_missing() {
        let dir = TempDir::new().unwrap();
        restrict_private_key(&dir.path().join("missing.pem")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn restrict_private_key_sets_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("key.pem");
        fs::write(&path, b"secret").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        restrict_private_key(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(windows)]
    #[test]
    fn restrict_private_key_runs_icacls() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("key.pem");
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(b"secret").unwrap();
        drop(file);

        restrict_private_key(&path).unwrap();
    }
}
