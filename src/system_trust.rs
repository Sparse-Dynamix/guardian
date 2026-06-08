use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;

use crate::ca::ROOT_CA_PEM;
use crate::ui::Ui;

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

pub fn check_nss_store(ca_dir: &Path) -> Result<bool> {
    let certutil = match find_certutil() {
        Some(p) => p,
        None => return Ok(false),
    };
    let alias = ca_unique_name(ca_dir)?;
    let mut profiles = vec![];

    if let Ok(home) = std::env::var("HOME") {
        profiles.push(format!("sql:{home}/.pki/nssdb"));
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
    }

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

pub fn run_check_system(ca_dir: &Path, stores: &[TrustStore], ui: &Ui) -> Result<bool> {
    if !ca_dir.join(ROOT_CA_PEM).exists() {
        ui.warn(&format!(
            "Guardian CA not found at {}; run guardian once to generate it",
            ca_dir.join(ROOT_CA_PEM).display()
        ));
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
            ui.success(&format!("{label}: Guardian CA is installed"));
        } else {
            ui.warn(&format!("{label}: Guardian CA is not installed"));
            all_ok = false;
        }
    }
    Ok(all_ok)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
