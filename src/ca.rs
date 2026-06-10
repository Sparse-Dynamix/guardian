use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};

use crate::config::Settings;

pub const ROOT_CA_PEM: &str = "rootCA.pem";

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
    java_truststore_password: String,
    deno_tls_ca_store: String,
    node_options_append: String,
}

impl CaTrust {
    pub fn from_settings(settings: &Settings) -> Self {
        let caroot = settings.ca_dir.clone();
        Self {
            ca_bundle: caroot.join(&settings.ca_bundle_name),
            caroot,
            java_truststore: None,
            java_truststore_password: settings.java_truststore_password.clone(),
            deno_tls_ca_store: settings.deno_tls_ca_store.clone(),
            node_options_append: settings.node_options_append.clone(),
        }
    }

    pub fn ensure_artifacts(&mut self, settings: &Settings) -> Result<()> {
        fs::create_dir_all(&self.caroot)
            .with_context(|| format!("failed to create CA directory {}", self.caroot.display()))?;

        let root_ca = self.caroot.join(ROOT_CA_PEM);
        if !root_ca.exists() {
            anyhow::bail!(
                "Guardian CA not found at {}; call Ssl::load_or_generate first",
                root_ca.display()
            );
        }

        let system_pem = load_system_roots_pem()?;
        let proxelar_pem =
            fs::read(&root_ca).with_context(|| format!("failed to read {}", root_ca.display()))?;
        let mut bundle = system_pem;
        if !bundle.is_empty() && !bundle.ends_with(b"\n") {
            bundle.push(b'\n');
        }
        bundle.extend_from_slice(&proxelar_pem);
        fs::write(&self.ca_bundle, &bundle)
            .with_context(|| format!("failed to write {}", self.ca_bundle.display()))?;

        self.java_truststore = build_java_truststore(&self.caroot, &root_ca, settings).ok();
        Ok(())
    }

    pub fn env_for_child(&self, parent_env: &[(String, String)]) -> Vec<(String, String)> {
        self.ca_env_overrides(parent_env)
    }

    /// Full environment for Frida spawn: parent vars plus CA trust overrides.
    pub fn spawn_env_merged(&self, parent_env: &[(String, String)]) -> Vec<(String, String)> {
        let mut map: HashMap<String, String> = parent_env.iter().cloned().collect();
        for (key, value) in self.ca_env_overrides(parent_env) {
            map.insert(key, value);
        }
        map.into_iter().collect()
    }

    fn ca_env_overrides(&self, parent_env: &[(String, String)]) -> Vec<(String, String)> {
        let parent: HashMap<_, _> = parent_env.iter().cloned().collect();
        let mut out = Vec::new();
        let bundle = self.ca_bundle.display().to_string();

        for &key in PEM_ENV_VARS {
            if !parent.contains_key(key) {
                out.push((key.to_string(), bundle.clone()));
            }
        }

        if !parent.contains_key("DENO_TLS_CA_STORE") {
            out.push((
                "DENO_TLS_CA_STORE".to_string(),
                self.deno_tls_ca_store.clone(),
            ));
        }

        let node_flag = &self.node_options_append;
        if !parent.contains_key("NODE_OPTIONS") {
            out.push(("NODE_OPTIONS".to_string(), node_flag.clone()));
        } else if let Some(existing) = parent.get("NODE_OPTIONS") {
            if !existing.contains(node_flag) {
                out.push((
                    "NODE_OPTIONS".to_string(),
                    format!("{existing} {node_flag}"),
                ));
            }
        }

        if let Some(store) = &self.java_truststore {
            let pwd = &self.java_truststore_password;
            let flag = format!(
                "-Djavax.net.ssl.trustStore={} -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword={pwd}",
                store.display()
            );
            if !parent.contains_key("JAVA_TOOL_OPTIONS") {
                out.push(("JAVA_TOOL_OPTIONS".to_string(), flag));
            } else if let Some(existing) = parent.get("JAVA_TOOL_OPTIONS") {
                if !existing.contains("javax.net.ssl.trustStore=") {
                    out.push((
                        "JAVA_TOOL_OPTIONS".to_string(),
                        format!("{existing} {flag}"),
                    ));
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
}

fn der_cert_to_pem(der: &[u8]) -> Vec<u8> {
    let encoded = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem.into_bytes()
}

fn load_system_roots_pem() -> Result<Vec<u8>> {
    let mut pem = Vec::new();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        pem.extend_from_slice(&der_cert_to_pem(&cert));
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

fn keytool_in_bin_dir(bin_dir: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let exe = bin_dir.join("keytool.exe");
        if exe.is_file() {
            return exe;
        }
    }
    bin_dir.join("keytool")
}

fn find_keytool() -> Option<PathBuf> {
    if let Ok(java_home) = std::env::var("JAVA_HOME") {
        let candidate = keytool_in_bin_dir(&PathBuf::from(&java_home).join("bin"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let candidate = keytool_in_bin_dir(&dir);
            candidate.is_file().then_some(candidate)
        })
    })
}

fn build_java_truststore(caroot: &Path, root_ca: &Path, settings: &Settings) -> Result<PathBuf> {
    let keytool = find_keytool().context("keytool not found")?;
    let password = &settings.java_truststore_password;
    let out = caroot.join(&settings.java_truststore_name);
    let tmp = caroot.join("guardian-java-truststore.jks");

    let java_home = std::env::var("JAVA_HOME").context("JAVA_HOME not set")?;
    let cacerts = PathBuf::from(&java_home).join("lib/security/cacerts");
    if !cacerts.is_file() {
        anyhow::bail!("JVM cacerts not found at {}", cacerts.display());
    }

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
            password,
            "-noprompt",
        ])
        .status()
        .context("keytool importkeystore failed")?;
    if !status.success() {
        anyhow::bail!("keytool importkeystore exited with {status}");
    }

    let status = Command::new(&keytool)
        .args([
            "-importcert",
            "-file",
            root_ca.to_str().unwrap(),
            "-alias",
            "guardian-root-ca",
            "-keystore",
            tmp.to_str().unwrap(),
            "-storepass",
            password,
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
            password,
            "-deststorepass",
            password,
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
    use std::path::PathBuf;

    use super::CaTrust;

    #[test]
    fn env_for_child_skips_existing_pem_vars() {
        let trust = CaTrust {
            caroot: PathBuf::from("/tmp/guardian-ca"),
            ca_bundle: PathBuf::from("/tmp/guardian-ca/guardian-ca-bundle.pem"),
            java_truststore: None,
            java_truststore_password: "guardian".into(),
            deno_tls_ca_store: "system,mozilla".into(),
            node_options_append: "--use-openssl-ca".into(),
        };
        let env = trust.env_for_child(&[("SSL_CERT_FILE".into(), "/existing.pem".into())]);
        assert!(!env.iter().any(|(k, _)| k == "SSL_CERT_FILE"));
    }

    #[test]
    fn env_for_child_merges_node_options_when_flag_missing() {
        let trust = CaTrust {
            caroot: PathBuf::from("/tmp/guardian-ca"),
            ca_bundle: PathBuf::from("/tmp/guardian-ca/guardian-ca-bundle.pem"),
            java_truststore: None,
            java_truststore_password: "guardian".into(),
            deno_tls_ca_store: "system,mozilla".into(),
            node_options_append: "--use-openssl-ca".into(),
        };
        let env = trust.env_for_child(&[("NODE_OPTIONS".into(), "--max-old-space-size=64".into())]);
        assert!(env.iter().any(|(k, v)| {
            k == "NODE_OPTIONS"
                && v.contains("--use-openssl-ca")
                && v.contains("--max-old-space-size=64")
        }));
    }

    #[test]
    fn spawn_env_merged_includes_parent_and_ca() {
        let trust = CaTrust {
            caroot: PathBuf::from("/tmp/guardian-ca"),
            ca_bundle: PathBuf::from("/tmp/guardian-ca/guardian-ca-bundle.pem"),
            java_truststore: None,
            java_truststore_password: "guardian".into(),
            deno_tls_ca_store: "system,mozilla".into(),
            node_options_append: "--use-openssl-ca".into(),
        };
        let parent = vec![
            ("HOME".into(), "/home/test".into()),
            ("PATH".into(), "/usr/bin".into()),
        ];
        let merged = trust.spawn_env_merged(&parent);
        let map: std::collections::HashMap<_, _> = merged.into_iter().collect();
        assert_eq!(map.get("HOME").map(String::as_str), Some("/home/test"));
        assert_eq!(map.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert!(map.contains_key("SSL_CERT_FILE"));
    }

    #[test]
    fn env_for_child_appends_java_truststore_when_missing() {
        let trust = CaTrust {
            caroot: PathBuf::from("/tmp/guardian-ca"),
            ca_bundle: PathBuf::from("/tmp/guardian-ca/guardian-ca-bundle.pem"),
            java_truststore: Some(PathBuf::from(
                "/tmp/guardian-ca/guardian-java-truststore.p12",
            )),
            java_truststore_password: "guardian".into(),
            deno_tls_ca_store: "system,mozilla".into(),
            node_options_append: "--use-openssl-ca".into(),
        };
        let env = trust.env_for_child(&[("JAVA_TOOL_OPTIONS".into(), "-Xmx64m".into())]);
        assert!(env.iter().any(|(k, v)| {
            k == "JAVA_TOOL_OPTIONS"
                && v.contains("-Xmx64m")
                && v.contains("javax.net.ssl.trustStore=")
        }));
    }

    #[test]
    fn env_for_child_skips_existing_java_truststore_flag() {
        let trust = CaTrust {
            caroot: PathBuf::from("/tmp/guardian-ca"),
            ca_bundle: PathBuf::from("/tmp/guardian-ca/guardian-ca-bundle.pem"),
            java_truststore: Some(PathBuf::from(
                "/tmp/guardian-ca/guardian-java-truststore.p12",
            )),
            java_truststore_password: "guardian".into(),
            deno_tls_ca_store: "system,mozilla".into(),
            node_options_append: "--use-openssl-ca".into(),
        };
        let env = trust.env_for_child(&[(
            "JAVA_TOOL_OPTIONS".into(),
            "-Djavax.net.ssl.trustStore=/existing.p12".into(),
        )]);
        assert!(!env.iter().any(|(k, v)| {
            k == "JAVA_TOOL_OPTIONS" && v.contains("guardian-java-truststore.p12")
        }));
    }

    #[test]
    fn ensure_artifacts_errors_when_root_ca_missing() {
        use crate::config::Settings;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let settings = Settings {
            ca_dir: dir.path().to_path_buf(),
            ca_bundle_name: "guardian-ca-bundle.pem".into(),
            java_truststore_name: "guardian-java-truststore.p12".into(),
            java_truststore_password: "guardian".into(),
            deno_tls_ca_store: "system,mozilla".into(),
            node_options_append: "--use-openssl-ca".into(),
            bind: "127.0.0.1".parse().unwrap(),
            port: None,
            trypanophobe_filter: None,
            trypanophobe_swap: false,
            payload: None,
            filter: String::new(),
            filter_timeout_secs: 10,
            block_message: crate::trypanophobe::DEFAULT_BLOCK_MESSAGE.to_string(),
            port_min: 1024,
            port_max: 65535,
            proxy_ready_timeout_secs: 5,
            proxy_ready_poll_ms: 10,
            process_poll_interval_ms: 50,
            program: String::new(),
            args: vec![],
            trust_stores: vec!["system".into()],
            upstream_tls: Default::default(),
        };
        let mut trust = CaTrust::from_settings(&settings);
        let err = trust.ensure_artifacts(&settings).unwrap_err();
        assert!(err.to_string().contains("Guardian CA not found"));
    }

    #[test]
    fn ensure_artifacts_builds_java_truststore_when_jdk_available() {
        let _guard = crate::test_lock::env_test_lock();
        use crate::config::Settings;
        use proxyapi::ca::Ssl;
        use tempfile::TempDir;

        let jdk = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".cache/jdk-17");
        let keytool = if cfg!(windows) {
            jdk.join("bin/keytool.exe")
        } else {
            jdk.join("bin/keytool")
        };
        if !keytool.is_file() {
            return;
        }

        let dir = TempDir::new().unwrap();
        Ssl::load_or_generate(dir.path()).unwrap();
        let settings = Settings {
            ca_dir: dir.path().to_path_buf(),
            ca_bundle_name: "guardian-ca-bundle.pem".into(),
            java_truststore_name: "guardian-java-truststore.p12".into(),
            java_truststore_password: "guardian".into(),
            deno_tls_ca_store: "system,mozilla".into(),
            node_options_append: "--use-openssl-ca".into(),
            bind: "127.0.0.1".parse().unwrap(),
            port: None,
            trypanophobe_filter: None,
            trypanophobe_swap: false,
            payload: None,
            filter: String::new(),
            filter_timeout_secs: 10,
            block_message: crate::trypanophobe::DEFAULT_BLOCK_MESSAGE.to_string(),
            port_min: 1024,
            port_max: 65535,
            proxy_ready_timeout_secs: 5,
            proxy_ready_poll_ms: 10,
            process_poll_interval_ms: 50,
            program: String::new(),
            args: vec![],
            trust_stores: vec!["system".into()],
            upstream_tls: Default::default(),
        };
        let prev = std::env::var_os("JAVA_HOME");
        std::env::set_var("JAVA_HOME", &jdk);
        let mut trust = CaTrust::from_settings(&settings);
        trust.ensure_artifacts(&settings).unwrap();
        if let Some(value) = prev {
            std::env::set_var("JAVA_HOME", value);
        } else {
            std::env::remove_var("JAVA_HOME");
        }
        assert!(dir.path().join("guardian-java-truststore.p12").is_file());
        assert!(dir.path().join("guardian-ca-bundle.pem").is_file());
    }

    #[test]
    fn find_keytool_from_path_when_java_home_unset() {
        use crate::config::Settings;
        use proxyapi::ca::Ssl;
        use tempfile::TempDir;

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

        let prev_home = std::env::var_os("JAVA_HOME");
        let prev_path = std::env::var_os("PATH");
        std::env::remove_var("JAVA_HOME");
        let jdk_bin = jdk.join("bin");
        let path = std::env::var_os("PATH").unwrap_or_default();
        let new_path =
            std::env::join_paths([jdk_bin].into_iter().chain(std::env::split_paths(&path)))
                .unwrap();
        std::env::set_var("PATH", new_path);

        let dir = TempDir::new().unwrap();
        proxyapi::ca::Ssl::load_or_generate(dir.path()).unwrap();
        let settings = Settings {
            ca_dir: dir.path().to_path_buf(),
            ca_bundle_name: "guardian-ca-bundle.pem".into(),
            java_truststore_name: "guardian-java-truststore.p12".into(),
            java_truststore_password: "guardian".into(),
            deno_tls_ca_store: "system,mozilla".into(),
            node_options_append: "--use-openssl-ca".into(),
            bind: "127.0.0.1".parse().unwrap(),
            port: None,
            trypanophobe_filter: None,
            trypanophobe_swap: false,
            payload: None,
            filter: String::new(),
            filter_timeout_secs: 10,
            block_message: crate::trypanophobe::DEFAULT_BLOCK_MESSAGE.to_string(),
            port_min: 1024,
            port_max: 65535,
            proxy_ready_timeout_secs: 5,
            proxy_ready_poll_ms: 10,
            process_poll_interval_ms: 50,
            program: String::new(),
            args: vec![],
            trust_stores: vec!["system".into()],
            upstream_tls: Default::default(),
        };
        let mut trust = CaTrust::from_settings(&settings);
        trust.ensure_artifacts(&settings).unwrap();

        if let Some(value) = prev_home {
            std::env::set_var("JAVA_HOME", value);
        } else {
            std::env::remove_var("JAVA_HOME");
        }
        if let Some(value) = prev_path {
            std::env::set_var("PATH", value);
        }
        assert!(dir.path().join("guardian-ca-bundle.pem").is_file());
    }

    #[test]
    fn env_for_child_skips_node_options_when_flag_already_present() {
        let trust = CaTrust {
            caroot: PathBuf::from("/tmp/guardian-ca"),
            ca_bundle: PathBuf::from("/tmp/guardian-ca/guardian-ca-bundle.pem"),
            java_truststore: None,
            java_truststore_password: "guardian".into(),
            deno_tls_ca_store: "system,mozilla".into(),
            node_options_append: "--use-openssl-ca".into(),
        };
        let env = trust.env_for_child(&[("NODE_OPTIONS".into(), "--use-openssl-ca".into())]);
        assert!(!env.iter().any(|(k, _)| k == "NODE_OPTIONS"));
    }

    #[test]
    fn env_pairs_for_injection_serializes_key_values() {
        let trust = CaTrust {
            caroot: PathBuf::from("/tmp/guardian-ca"),
            ca_bundle: PathBuf::from("/tmp/guardian-ca/guardian-ca-bundle.pem"),
            java_truststore: None,
            java_truststore_password: "guardian".into(),
            deno_tls_ca_store: "system,mozilla".into(),
            node_options_append: "--use-openssl-ca".into(),
        };
        let pairs = trust.env_pairs_for_injection();
        assert!(pairs
            .iter()
            .any(|p| { p == "CURL_CA_BUNDLE=/tmp/guardian-ca/guardian-ca-bundle.pem" }));
        assert!(pairs.iter().any(|p| p == "NODE_OPTIONS=--use-openssl-ca"));
    }
}
