use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;

use crate::ca::ROOT_CA_PEM;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStore {
    System,
    Nss,
    Java,
}

impl TrustStore {
    pub fn parse_all(stores: &[String]) -> Vec<Self> {
        let mut out = Vec::new();
        for s in stores {
            match s.as_str() {
                "system" if !out.contains(&Self::System) => out.push(Self::System),
                "nss" if !out.contains(&Self::Nss) => out.push(Self::Nss),
                "java" if !out.contains(&Self::Java) => out.push(Self::Java),
                _ => {}
            }
        }
        if out.is_empty() {
            out.extend([Self::System, Self::Nss, Self::Java]);
        }
        out
    }
}

pub fn default_trust_stores() -> Vec<String> {
    vec!["system".into(), "nss".into(), "java".into()]
}

pub fn ca_sha256_fingerprint(ca_dir: &Path) -> Result<Vec<u8>> {
    let pem_path = ca_dir.join(ROOT_CA_PEM);
    let pem_bytes = std::fs::read(&pem_path)
        .with_context(|| format!("failed to read {}", pem_path.display()))?;
    let (_, pem) = parse_x509_pem(&pem_bytes).context("failed to parse root CA PEM")?;
    Ok(Sha256::digest(&pem.contents).to_vec())
}

pub fn ca_unique_name(ca_dir: &Path) -> Result<String> {
    let pem_path = ca_dir.join(ROOT_CA_PEM);
    let pem_bytes = std::fs::read(&pem_path)
        .with_context(|| format!("failed to read {}", pem_path.display()))?;
    let (_, pem) = parse_x509_pem(&pem_bytes).context("failed to parse root CA PEM")?;
    let (_, cert) = parse_x509_certificate(&pem.contents).context("failed to parse root CA DER")?;
    let serial = cert.tbs_certificate.serial;
    Ok(format!("mkcert development CA {serial}"))
}

fn fingerprint_hex(fp: &[u8]) -> String {
    hex::encode(fp).to_uppercase()
}

pub fn check_system_store(ca_dir: &Path) -> Result<bool> {
    let fp = ca_sha256_fingerprint(ca_dir)?;
    let needle = fingerprint_hex(&fp);
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let digest = Sha256::digest(&cert);
        if fingerprint_hex(&digest) == needle {
            return Ok(true);
        }
    }
    Ok(false)
}

fn find_certutil() -> Option<std::path::PathBuf> {
    which::which("certutil").ok()
}

fn nss_profile_dirs(home: &str) -> Vec<String> {
    let mut profiles = vec![format!("sql:{home}/.pki/nssdb")];
    for base in [
        format!("{home}/.mozilla/firefox"),
        format!("{home}/snap/firefox/common/.mozilla/firefox"),
    ] {
        for p in list_subdirs(&base) {
            profiles.push(format!("sql:{p}"));
        }
    }
    let chromium = format!("{home}/snap/chromium/current/.pki/nssdb");
    if Path::new(&chromium).is_dir() {
        profiles.push(format!("sql:{chromium}"));
    }
    profiles
}

pub fn check_nss_store(ca_dir: &Path) -> Result<bool> {
    let certutil = match find_certutil() {
        Some(p) => p,
        None => return Ok(false),
    };
    let alias = ca_unique_name(ca_dir)?;
    let profiles = std::env::var("HOME")
        .ok()
        .map(|home| nss_profile_dirs(&home))
        .unwrap_or_default();

    for profile in profiles {
        let status = Command::new(&certutil)
            .args(["-V", "-d", &profile, "-u", "L", "-n", &alias])
            .status()
            .with_context(|| format!("certutil -V failed for {profile}"))?;
        if status.success() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn list_subdirs(base: &str) -> Vec<String> {
    let path = Path::new(base);
    let Ok(entries) = std::fs::read_dir(path) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.path().display().to_string())
        .collect()
}

fn find_keytool() -> Option<std::path::PathBuf> {
    if let Ok(java_home) = std::env::var("JAVA_HOME") {
        #[cfg(windows)]
        let candidate = std::path::PathBuf::from(&java_home).join("bin/keytool.exe");
        #[cfg(not(windows))]
        let candidate = std::path::PathBuf::from(&java_home).join("bin/keytool");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    which::which("keytool").ok()
}

pub fn check_java_store(ca_dir: &Path) -> Result<bool> {
    let keytool = match find_keytool() {
        Some(p) => p,
        None => return Ok(false),
    };
    let java_home = std::env::var("JAVA_HOME").ok();
    let cacerts = java_home.as_ref().and_then(|home| {
        let p = std::path::PathBuf::from(home).join("lib/security/cacerts");
        p.is_file().then_some(p)
    });
    let Some(cacerts) = cacerts else {
        return Ok(false);
    };

    let output = Command::new(&keytool)
        .args([
            "-list",
            "-keystore",
            cacerts.to_str().unwrap(),
            "-storepass",
            "changeit",
        ])
        .output()
        .context("keytool -list failed")?;
    if !output.status.success() {
        return Ok(false);
    }

    let fp = ca_sha256_fingerprint(ca_dir)?;
    let fp_hex = fingerprint_hex(&fp);
    let stdout = String::from_utf8_lossy(&output.stdout).replace(':', "");
    Ok(stdout.contains(&fp_hex))
}

pub fn is_store_installed(store: TrustStore, ca_dir: &Path) -> Result<bool> {
    if !ca_dir.join(ROOT_CA_PEM).exists() {
        return Ok(false);
    }
    match store {
        TrustStore::System => check_system_store(ca_dir),
        TrustStore::Nss => check_nss_store(ca_dir),
        TrustStore::Java => check_java_store(ca_dir),
    }
}

pub fn is_installed(ca_dir: &Path, stores: &[TrustStore]) -> Result<bool> {
    if stores.is_empty() {
        return Ok(false);
    }
    for store in stores {
        if !is_store_installed(*store, ca_dir)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn run_check_system(ca_dir: &Path, stores: &[TrustStore]) -> Result<bool> {
    if !ca_dir.join(ROOT_CA_PEM).exists() {
        eprintln!(
            "Warning: Guardian CA not found at {}; run guardian once to generate it",
            ca_dir.join(ROOT_CA_PEM).display()
        );
        return Ok(false);
    }

    let mut all_ok = true;
    for store in stores {
        let ok = is_store_installed(*store, ca_dir)?;
        let label = match store {
            TrustStore::System => "system",
            TrustStore::Nss => "nss",
            TrustStore::Java => "java",
        };
        if ok {
            eprintln!("{label}: Guardian CA is installed");
        } else {
            eprintln!("Warning: {label}: Guardian CA is not installed");
            all_ok = false;
        }
    }
    Ok(all_ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxyapi::ca::Ssl;
    use tempfile::TempDir;

    fn generated_ca_dir() -> TempDir {
        let dir = TempDir::new().unwrap();
        Ssl::load_or_generate(dir.path()).unwrap();
        dir
    }

    #[test]
    fn parse_stores_defaults_when_empty() {
        let stores = TrustStore::parse_all(&[]);
        assert_eq!(stores.len(), 3);
    }

    #[test]
    fn parse_stores_subset() {
        let stores = TrustStore::parse_all(&["system".into()]);
        assert_eq!(stores, vec![TrustStore::System]);
    }

    #[test]
    fn parse_stores_ignores_unknown_and_duplicates() {
        let stores = TrustStore::parse_all(&[
            "system".into(),
            "bogus".into(),
            "system".into(),
            "java".into(),
        ]);
        assert_eq!(stores, vec![TrustStore::System, TrustStore::Java]);
    }

    #[test]
    fn default_trust_stores_lists_all() {
        assert_eq!(default_trust_stores().len(), 3);
    }

    #[test]
    fn ca_fingerprint_and_name_match_generated_ca() {
        let dir = generated_ca_dir();
        let fp = ca_sha256_fingerprint(dir.path()).unwrap();
        assert_eq!(fp.len(), 32);
        let name = ca_unique_name(dir.path()).unwrap();
        assert!(name.starts_with("mkcert development CA "));
    }

    #[test]
    fn check_system_store_returns_false_for_fresh_ca() {
        let dir = generated_ca_dir();
        assert!(!check_system_store(dir.path()).unwrap());
    }

    #[test]
    fn check_nss_store_returns_false_without_profiles() {
        let dir = generated_ca_dir();
        assert!(!check_nss_store(dir.path()).unwrap());
    }

    #[test]
    fn is_installed_empty_store_list_returns_false() {
        let dir = generated_ca_dir();
        assert!(!is_installed(dir.path(), &[]).unwrap());
    }

    #[test]
    fn parse_stores_includes_nss() {
        let stores = TrustStore::parse_all(&["nss".into()]);
        assert_eq!(stores, vec![TrustStore::Nss]);
    }

    #[test]
    fn check_java_store_without_java_home_returns_false() {
        let _guard = crate::test_lock::env_test_lock();
        let dir = generated_ca_dir();
        let prev = std::env::var_os("JAVA_HOME");
        std::env::remove_var("JAVA_HOME");
        let result = check_java_store(dir.path()).unwrap();
        if let Some(value) = prev {
            std::env::set_var("JAVA_HOME", value);
        }
        assert!(!result);
    }

    #[test]
    fn is_installed_false_when_ca_missing() {
        let dir = TempDir::new().unwrap();
        assert!(!is_installed(dir.path(), &[TrustStore::System]).unwrap());
    }

    #[test]
    fn is_store_installed_false_for_missing_ca() {
        let dir = TempDir::new().unwrap();
        assert!(!is_store_installed(TrustStore::System, dir.path()).unwrap());
    }

    #[test]
    fn run_check_system_warns_when_ca_missing() {
        let dir = TempDir::new().unwrap();
        assert!(!run_check_system(dir.path(), &[TrustStore::System]).unwrap());
    }

    #[test]
    fn run_check_system_reports_uninstalled_stores() {
        let dir = generated_ca_dir();
        assert!(!run_check_system(dir.path(), &[TrustStore::System]).unwrap());
    }

    #[test]
    fn run_check_system_reports_nss_and_java_labels() {
        let dir = generated_ca_dir();
        assert!(!run_check_system(dir.path(), &[TrustStore::Nss, TrustStore::Java]).unwrap());
    }

    #[test]
    fn list_subdirs_returns_directories_only() {
        let base = TempDir::new().unwrap();
        std::fs::create_dir(base.path().join("child")).unwrap();
        std::fs::write(base.path().join("file.txt"), b"x").unwrap();
        let dirs = list_subdirs(base.path().to_str().unwrap());
        assert_eq!(dirs.len(), 1);
        assert!(dirs[0].ends_with("child"));
    }

    #[test]
    fn list_subdirs_missing_base_returns_empty() {
        assert!(list_subdirs("/nonexistent/guardian-nss-profiles").is_empty());
    }

    #[test]
    fn nss_profile_dirs_includes_standard_locations() {
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".pki/nssdb")).unwrap();
        std::fs::create_dir_all(home.path().join(".mozilla/firefox/abc.default")).unwrap();
        std::fs::create_dir_all(home.path().join("snap/chromium/current/.pki/nssdb")).unwrap();
        let home_str = home.path().to_str().unwrap();
        let profiles = nss_profile_dirs(home_str);
        assert!(profiles.iter().any(|p| p.ends_with(".pki/nssdb")));
        assert!(profiles.iter().any(|p| p.contains("abc.default")));
        assert!(profiles.iter().any(|p| p.contains("chromium")));
    }

    #[test]
    fn check_nss_store_runs_when_certutil_available() {
        let _guard = crate::test_lock::env_test_lock();
        if which::which("certutil").is_err() {
            eprintln!("skipping: certutil not installed");
            return;
        }
        let dir = generated_ca_dir();
        let home = TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".pki/nssdb")).unwrap();
        std::fs::create_dir_all(home.path().join(".mozilla/firefox/abc.default")).unwrap();
        std::fs::create_dir_all(home.path().join("snap/chromium/current/.pki/nssdb")).unwrap();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", home.path());
        assert!(!check_nss_store(dir.path()).unwrap());
        assert!(!is_store_installed(TrustStore::Nss, dir.path()).unwrap());
        if let Some(value) = prev_home {
            std::env::set_var("HOME", value);
        } else {
            std::env::remove_var("HOME");
        }
    }

    #[test]
    fn check_java_store_falls_back_to_path_keytool() {
        let _guard = crate::test_lock::env_test_lock();
        let jdk = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".cache/jdk-17");
        let keytool = if cfg!(windows) {
            jdk.join("bin/keytool.exe")
        } else {
            jdk.join("bin/keytool")
        };
        if !keytool.is_file() {
            return;
        }

        let dir = generated_ca_dir();
        let prev_home = std::env::var_os("JAVA_HOME");
        let prev_path = std::env::var_os("PATH");
        std::env::remove_var("JAVA_HOME");
        let jdk_bin = jdk.join("bin");
        let path = std::env::var_os("PATH").unwrap_or_default();
        let new_path =
            std::env::join_paths([jdk_bin].into_iter().chain(std::env::split_paths(&path)))
                .unwrap();
        std::env::set_var("PATH", new_path);
        assert!(!check_java_store(dir.path()).unwrap());
        if let Some(value) = prev_home {
            std::env::set_var("JAVA_HOME", value);
        } else {
            std::env::remove_var("JAVA_HOME");
        }
        if let Some(value) = prev_path {
            std::env::set_var("PATH", value);
        }
    }

    #[test]
    fn check_java_store_runs_when_portable_jdk_available() {
        let _guard = crate::test_lock::env_test_lock();
        let jdk = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".cache/jdk-17");
        let keytool = if cfg!(windows) {
            jdk.join("bin/keytool.exe")
        } else {
            jdk.join("bin/keytool")
        };
        if !keytool.is_file() {
            eprintln!("skipping: portable JDK not found at .cache/jdk-17");
            return;
        }

        let dir = generated_ca_dir();
        let prev = std::env::var_os("JAVA_HOME");
        std::env::set_var("JAVA_HOME", &jdk);
        assert!(!check_java_store(dir.path()).unwrap());
        assert!(!is_store_installed(TrustStore::Java, dir.path()).unwrap());
        if let Some(value) = prev {
            std::env::set_var("JAVA_HOME", value);
        } else {
            std::env::remove_var("JAVA_HOME");
        }
    }

    #[test]
    fn is_installed_requires_all_requested_stores() {
        let dir = generated_ca_dir();
        assert!(!is_installed(dir.path(), &[TrustStore::System, TrustStore::Java]).unwrap());
    }

    #[test]
    fn is_store_installed_dispatches_java_store() {
        let _guard = crate::test_lock::env_test_lock();
        let jdk = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".cache/jdk-17");
        let keytool = if cfg!(windows) {
            jdk.join("bin/keytool.exe")
        } else {
            jdk.join("bin/keytool")
        };
        if !keytool.is_file() {
            return;
        }
        let dir = generated_ca_dir();
        let prev = std::env::var_os("JAVA_HOME");
        std::env::set_var("JAVA_HOME", &jdk);
        assert!(!is_store_installed(TrustStore::Java, dir.path()).unwrap());
        if let Some(value) = prev {
            std::env::set_var("JAVA_HOME", value);
        } else {
            std::env::remove_var("JAVA_HOME");
        }
    }
}
