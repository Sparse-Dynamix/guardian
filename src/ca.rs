use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

const BUNDLE_NAME: &str = "guardian-ca-bundle.pem";
const PROXELAR_CA: &str = "proxelar-ca.pem";
const JAVA_TRUSTSTORE: &str = "guardian-java-truststore.p12";
const JAVA_PASSWORD: &str = "guardian";

/// PEM path env vars pointing at the combined CA bundle.
const PEM_ENV_VARS: &[&str] = &[
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "PIP_CERT",
    "HTTPLIB2_CA_CERTS",
    "NODE_EXTRA_CA_CERTS",
    "DENO_CERT",
    "AWS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "CARGO_HTTP_CAINFO",
    "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
    "PERL_LWP_SSL_CA_FILE",
    "HTTPS_CA_FILE",
    "NIX_SSL_CERT_FILE",
    "SSL_CERTIFICATE_AUTHORITIES",
];

pub struct CaTrust {
    caroot: PathBuf,
    ca_bundle: PathBuf,
    java_truststore: Option<PathBuf>,
}

impl CaTrust {
    pub fn from_ca_dir(ca_dir: &Path) -> Self {
        let caroot = ca_dir.to_path_buf();
        Self {
            ca_bundle: caroot.join(BUNDLE_NAME),
            caroot,
            java_truststore: None,
        }
    }

    pub fn ensure_artifacts(&mut self) -> Result<()> {
        fs::create_dir_all(&self.caroot).with_context(|| {
            format!("failed to create CA directory {}", self.caroot.display())
        })?;

        let proxelar_ca = self.caroot.join(PROXELAR_CA);
        if !proxelar_ca.exists() {
            anyhow::bail!(
                "Proxelar CA not found at {}; call Ssl::load_or_generate first",
                proxelar_ca.display()
            );
        }

        let system_pem = load_system_roots_pem()?;
        let proxelar_pem = fs::read(&proxelar_ca)
            .with_context(|| format!("failed to read {}", proxelar_ca.display()))?;
        let mut bundle = system_pem;
        if !bundle.is_empty() && !bundle.ends_with(b"\n") {
            bundle.push(b'\n');
        }
        bundle.extend_from_slice(&proxelar_pem);
        fs::write(&self.ca_bundle, &bundle)
            .with_context(|| format!("failed to write {}", self.ca_bundle.display()))?;

        self.java_truststore = build_java_truststore(&self.caroot, &proxelar_ca).ok();
        Ok(())
    }

    pub fn env_for_child(&self, parent_env: &[(String, String)]) -> Vec<(String, String)> {
        let parent: HashMap<_, _> = parent_env.iter().cloned().collect();
        let mut out = Vec::new();
        let bundle = self.ca_bundle.display().to_string();

        for &key in PEM_ENV_VARS {
            if !parent.contains_key(key) {
                out.push((key.to_string(), bundle.clone()));
            }
        }

        if !parent.contains_key("DENO_TLS_CA_STORE") {
            out.push(("DENO_TLS_CA_STORE".to_string(), "system,mozilla".to_string()));
        }

        if !parent.contains_key("NODE_OPTIONS") {
            out.push(("NODE_OPTIONS".to_string(), "--use-openssl-ca".to_string()));
        } else if let Some(existing) = parent.get("NODE_OPTIONS") {
            if !existing.contains("--use-openssl-ca") {
                out.push((
                    "NODE_OPTIONS".to_string(),
                    format!("{existing} --use-openssl-ca"),
                ));
            }
        }

        if let Some(store) = &self.java_truststore {
            let flag = format!(
                "-Djavax.net.ssl.trustStore={} -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword={JAVA_PASSWORD}",
                store.display()
            );
            if !parent.contains_key("JAVA_TOOL_OPTIONS") {
                out.push(("JAVA_TOOL_OPTIONS".to_string(), flag));
            } else if let Some(existing) = parent.get("JAVA_TOOL_OPTIONS") {
                if !existing.contains("javax.net.ssl.trustStore=") {
                    out.push(("JAVA_TOOL_OPTIONS".to_string(), format!("{existing} {flag}")));
                }
            }
        }

        out
    }

    pub fn env_pairs_for_injection(&self) -> Vec<String> {
        self.env_for_child(&[])
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect()
    }

    pub fn caroot(&self) -> &Path {
        &self.caroot
    }
}

pub fn merge_env_pairs(
    existing: &[(String, String)],
    ca_pairs: &[(String, String)],
) -> Vec<(String, String)> {
    let mut map: HashMap<String, String> = existing.iter().cloned().collect();
    for (k, v) in ca_pairs {
        map.entry(k.clone()).or_insert_with(|| v.clone());
    }
    map.into_iter().collect()
}

fn load_system_roots_pem() -> Result<Vec<u8>> {
    let mut pem = Vec::new();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        pem.extend_from_slice(&cert);
        if !pem.ends_with(b"\n") {
            pem.push(b'\n');
        }
    }
    if !pem.is_empty() {
        return Ok(pem);
    }

    #[cfg(target_os = "linux")]
    {
        for path in [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ] {
            if Path::new(path).exists() {
                return Ok(fs::read(path)?);
            }
        }
    }

    Ok(pem)
}

fn find_keytool() -> Option<PathBuf> {
    if let Ok(java_home) = std::env::var("JAVA_HOME") {
        let candidate = PathBuf::from(&java_home).join("bin/keytool");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join("keytool");
            candidate.is_file().then_some(candidate)
        })
    })
}

fn build_java_truststore(caroot: &Path, proxelar_ca: &Path) -> Result<PathBuf> {
    let keytool = find_keytool().context("keytool not found")?;
    let out = caroot.join(JAVA_TRUSTSTORE);
    let tmp = caroot.join("guardian-java-truststore.jks");

    let cacerts = std::env::var("JAVA_HOME")
        .ok()
        .map(|jh| PathBuf::from(jh).join("lib/security/cacerts"))
        .filter(|p| p.exists());

    if let Some(cacerts) = cacerts {
        let status = Command::new(&keytool)
            .args([
                "-importkeystore",
                "-srckeystore",
                cacerts.to_str().unwrap(),
                "-destkeystore",
                tmp.to_str().unwrap(),
                "-deststoretype",
                "JKS",
                "-srcstorepass",
                "changeit",
                "-deststorepass",
                JAVA_PASSWORD,
                "-noprompt",
            ])
            .status()
            .context("keytool importkeystore failed")?;
        if !status.success() {
            anyhow::bail!("keytool importkeystore exited with {status}");
        }
    } else {
        let status = Command::new(&keytool)
            .args([
                "-genkeypair",
                "-alias",
                "dummy",
                "-keystore",
                tmp.to_str().unwrap(),
                "-storepass",
                JAVA_PASSWORD,
                "-keypass",
                JAVA_PASSWORD,
                "-dname",
                "CN=guardian",
                "-noprompt",
            ])
            .status()
            .context("keytool genkeypair failed")?;
        if !status.success() {
            anyhow::bail!("keytool genkeypair exited with {status}");
        }
        let _ = Command::new(&keytool)
            .args([
                "-delete",
                "-alias",
                "dummy",
                "-keystore",
                tmp.to_str().unwrap(),
                "-storepass",
                JAVA_PASSWORD,
                "-noprompt",
            ])
            .status();
    }

    let status = Command::new(&keytool)
        .args([
            "-importcert",
            "-file",
            proxelar_ca.to_str().unwrap(),
            "-alias",
            "guardian-proxelar",
            "-keystore",
            tmp.to_str().unwrap(),
            "-storepass",
            JAVA_PASSWORD,
            "-noprompt",
        ])
        .status()
        .context("keytool importcert failed")?;
    if !status.success() {
        anyhow::bail!("keytool importcert exited with {status}");
    }

    let status = Command::new(&keytool)
        .args([
            "-importkeystore",
            "-srckeystore",
            tmp.to_str().unwrap(),
            "-destkeystore",
            out.to_str().unwrap(),
            "-deststoretype",
            "PKCS12",
            "-srcstorepass",
            JAVA_PASSWORD,
            "-deststorepass",
            JAVA_PASSWORD,
            "-noprompt",
        ])
        .status()
        .context("keytool PKCS12 conversion failed")?;
    let _ = fs::remove_file(&tmp);
    if !status.success() {
        anyhow::bail!("keytool PKCS12 conversion exited with {status}");
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_env_skips_existing_keys() {
        let existing = vec![
            ("SSL_CERT_FILE".to_string(), "/custom.pem".to_string()),
            ("PATH".to_string(), "/usr/bin".to_string()),
        ];
        let ca = vec![
            ("SSL_CERT_FILE".to_string(), "/bundle.pem".to_string()),
            ("CURL_CA_BUNDLE".to_string(), "/bundle.pem".to_string()),
        ];
        let merged = merge_env_pairs(&existing, &ca);
        let map: HashMap<_, _> = merged.into_iter().collect();
        assert_eq!(map.get("SSL_CERT_FILE").unwrap(), "/custom.pem");
        assert_eq!(map.get("CURL_CA_BUNDLE").unwrap(), "/bundle.pem");
    }
}
