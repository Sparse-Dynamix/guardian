use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

#[cfg(windows)]
const MKCERT_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/mkcert.exe"));
#[cfg(not(windows))]
const MKCERT_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/mkcert"));

#[cfg(windows)]
const MKCERT_NAME: &str = "mkcert.exe";
#[cfg(not(windows))]
const MKCERT_NAME: &str = "mkcert";

pub fn mkcert_bin_dir(ca_dir: &Path) -> PathBuf {
    ca_dir.join("bin")
}

pub fn executable_path(ca_dir: &Path) -> Result<PathBuf> {
    if std::env::var_os("GUARDIAN_MKCERT_TEST").is_some() {
        return test_mkcert_path();
    }

    let bin_dir = mkcert_bin_dir(ca_dir);
    fs::create_dir_all(&bin_dir)
        .with_context(|| format!("failed to create {}", bin_dir.display()))?;
    let dest = bin_dir.join(MKCERT_NAME);

    let needs_write = match fs::metadata(&dest) {
        Ok(meta) => meta.len() as usize != MKCERT_BYTES.len(),
        Err(_) => true,
    };

    if needs_write {
        let mut file = fs::File::create(&dest)
            .with_context(|| format!("failed to write {}", dest.display()))?;
        file.write_all(MKCERT_BYTES)
            .context("failed to write embedded mkcert bytes")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dest, fs::Permissions::from_mode(0o755))?;
        }
    }

    Ok(dest)
}

fn test_mkcert_path() -> Result<PathBuf> {
    let path = std::env::var_os("GUARDIAN_MKCERT_TEST")
        .map(PathBuf::from)
        .context("GUARDIAN_MKCERT_TEST unset")?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn embedded_bytes_non_empty() {
        assert!(!MKCERT_BYTES.is_empty());
    }

    #[test]
    fn extract_writes_expected_size() {
        let dir = TempDir::new().unwrap();
        let path = executable_path(dir.path()).unwrap();
        assert!(path.is_file());
        assert_eq!(
            fs::metadata(&path).unwrap().len() as usize,
            MKCERT_BYTES.len()
        );
    }
}
