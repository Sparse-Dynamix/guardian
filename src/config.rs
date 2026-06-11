use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use config::{Config, Environment, File};
use serde::Deserialize;

use proxyapi::UpstreamTlsConfig;

use crate::cli::{parse_bind_ipv4, Cli, SystemOpts};
use crate::filter::{connect_filter_from_ports, DEFAULT_IGNORED_PORTS};
use crate::system_trust::default_trust_stores;
use crate::trypanophobe::DEFAULT_BLOCK_MESSAGE;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FileSettings {
    pub bind: String,
    pub port: Option<u16>,
    pub trypanophobe_filter: Option<String>,
    pub trypanophobe_swap: bool,
    pub filter: Option<String>,
    #[serde(default = "default_ignored_ports")]
    pub ignored_ports: Vec<u16>,
    pub ca_dir: String,
    pub filter_timeout_secs: u64,
    pub block_message: String,
    pub port_min: u16,
    pub port_max: u16,
    pub proxy_ready_timeout_secs: u64,
    pub process_poll_interval_ms: u64,
    pub ca_bundle_name: String,
    pub java_truststore_name: String,
    pub java_truststore_password: String,
    pub deno_tls_ca_store: String,
    pub node_options_append: String,
    pub trust_stores: Option<Vec<String>>,
    pub upstream_tls: Option<String>,
    pub skip_cert_regen: bool,
}

impl Default for FileSettings {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1".to_string(),
            port: None,
            trypanophobe_filter: None,
            trypanophobe_swap: false,
            filter: None,
            ignored_ports: default_ignored_ports(),
            ca_dir: "~/.guardian".to_string(),
            filter_timeout_secs: 10,
            block_message: DEFAULT_BLOCK_MESSAGE.to_string(),
            port_min: 1024,
            port_max: 65535,
            proxy_ready_timeout_secs: 5,
            process_poll_interval_ms: 50,
            ca_bundle_name: "guardian-ca-bundle.pem".to_string(),
            java_truststore_name: "guardian-java-truststore.p12".to_string(),
            java_truststore_password: "guardian".to_string(),
            deno_tls_ca_store: "system,mozilla".to_string(),
            node_options_append: "--use-openssl-ca".to_string(),
            trust_stores: None,
            upstream_tls: None,
            skip_cert_regen: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub bind: Ipv4Addr,
    pub port: Option<u16>,
    pub trypanophobe_filter: Option<String>,
    pub trypanophobe_swap: bool,
    pub payload: Option<String>,
    pub filter: String,
    pub ca_dir: PathBuf,
    pub filter_timeout_secs: u64,
    pub block_message: String,
    pub port_min: u16,
    pub port_max: u16,
    pub proxy_ready_timeout_secs: u64,
    pub process_poll_interval_ms: u64,
    pub ca_bundle_name: String,
    pub java_truststore_name: String,
    pub java_truststore_password: String,
    pub deno_tls_ca_store: String,
    pub node_options_append: String,
    pub program: String,
    pub args: Vec<String>,
    pub trust_stores: Vec<String>,
    pub upstream_tls: UpstreamTlsConfig,
    pub skip_cert_regen: bool,
}

fn home_dir_for_tilde() -> Result<PathBuf> {
    for key in ["USERPROFILE", "HOME"] {
        if let Some(home) = std::env::var_os(key) {
            if !home.is_empty() {
                return Ok(PathBuf::from(home));
            }
        }
    }
    dirs::home_dir().context("home directory not found (required for ~ paths)")
}

pub fn expand_tilde(path: &str) -> Result<PathBuf> {
    if let Some(rest) = path.strip_prefix("~/") {
        Ok(home_dir_for_tilde()?.join(rest))
    } else if path == "~" {
        home_dir_for_tilde()
    } else {
        Ok(PathBuf::from(path))
    }
}

pub fn default_guardian_home() -> Result<PathBuf> {
    expand_tilde("~/.guardian")
}

fn default_ignored_ports() -> Vec<u16> {
    DEFAULT_IGNORED_PORTS.to_vec()
}

pub fn load_file_settings(config_path: Option<&Path>) -> Result<FileSettings> {
    let mut builder = Config::builder();

    let shipped = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/guardian.toml");
    if shipped.exists() {
        builder = builder.add_source(File::from(shipped));
    }

    let user = expand_tilde("~/.guardian/guardian.toml")?;
    if user.exists() {
        builder = builder.add_source(File::from(user));
    }

    let cwd = PathBuf::from("guardian.toml");
    if cwd.exists() {
        builder = builder.add_source(File::from(cwd));
    }

    if let Some(path) = config_path {
        builder = builder.add_source(File::from(path));
    }

    builder = builder.add_source(
        Environment::with_prefix("GUARDIAN")
            .try_parsing(true)
            .ignore_empty(true),
    );

    let cfg = builder.build().context("failed to build configuration")?;
    cfg.try_deserialize()
        .context("failed to deserialize configuration")
}

fn looks_like_path(program: &str) -> bool {
    program.contains('/') || program.contains('\\')
}

pub fn resolve_program(program: &str) -> Result<PathBuf> {
    let path = Path::new(program);

    if path.is_absolute() {
        if path.exists() {
            return Ok(path.to_path_buf());
        }
        anyhow::bail!("program '{program}' not found");
    }

    if looks_like_path(program) {
        let candidate = std::env::current_dir()
            .context("failed to get current directory")?
            .join(path);
        if candidate.exists() {
            return candidate
                .canonicalize()
                .with_context(|| format!("failed to canonicalize '{program}'"));
        }
        anyhow::bail!("program '{program}' not found");
    }

    which::which(program).with_context(|| format!("program '{program}' not found in PATH"))
}

pub fn resolve_ca_dir(cli: &Cli) -> Result<PathBuf> {
    let file = load_file_settings(cli.config.as_deref())?;
    match &cli.ca_dir {
        Some(dir) => Ok(dir.clone()),
        None => expand_tilde(&file.ca_dir),
    }
}

pub fn resolve_trust_stores(cli: &Cli, opts: Option<&SystemOpts>) -> Vec<String> {
    if let Some(opts) = opts {
        if let Some(stores) = &opts.stores {
            return stores.clone();
        }
    }
    let file = load_file_settings(cli.config.as_deref()).ok();
    file.and_then(|f| f.trust_stores.clone())
        .unwrap_or_else(default_trust_stores)
}

fn merge_tpf(cli: &Cli, file: &FileSettings) -> Option<String> {
    cli.trypanophobe_filter
        .clone()
        .or_else(|| file.trypanophobe_filter.clone())
        .filter(|url| !url.is_empty())
}

pub fn resolve_payload_settings(cli: &Cli) -> Result<Settings> {
    let file = load_file_settings(cli.config.as_deref())?;

    let bind_str = cli.bind.as_deref().unwrap_or(&file.bind);
    let port = cli.port.or(file.port);
    let trypanophobe_filter = merge_tpf(cli, &file);
    let trypanophobe_swap = cli.trypanophobe_swap || file.trypanophobe_swap;
    let skip_cert_regen = cli.skip_cert_regen || file.skip_cert_regen;
    if trypanophobe_swap && trypanophobe_filter.is_none() {
        anyhow::bail!("--trypanophobe-swap / --tps requires --tpf / trypanophobe_filter");
    }
    let ignored_ports = cli
        .ignored_ports
        .clone()
        .filter(|ports| !ports.is_empty())
        .unwrap_or_else(|| file.ignored_ports.clone());
    let filter = cli
        .filter
        .clone()
        .or(file.filter.clone())
        .unwrap_or_else(|| connect_filter_from_ports(&ignored_ports));
    let ca_dir = resolve_ca_dir(cli)?;

    let trust_stores = file
        .trust_stores
        .clone()
        .unwrap_or_else(default_trust_stores);

    let upstream_tls = file
        .upstream_tls
        .as_deref()
        .map(UpstreamTlsConfig::from_str)
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid upstream_tls: {e}"))?
        .unwrap_or_default();

    Ok(Settings {
        bind: parse_bind_ipv4(bind_str)?,
        port,
        trypanophobe_filter,
        trypanophobe_swap,
        payload: cli.payload.clone(),
        filter,
        ca_dir,
        filter_timeout_secs: file.filter_timeout_secs,
        block_message: file.block_message.clone(),
        port_min: file.port_min,
        port_max: file.port_max,
        proxy_ready_timeout_secs: file.proxy_ready_timeout_secs,
        process_poll_interval_ms: file.process_poll_interval_ms,
        ca_bundle_name: file.ca_bundle_name,
        java_truststore_name: file.java_truststore_name,
        java_truststore_password: file.java_truststore_password,
        deno_tls_ca_store: file.deno_tls_ca_store,
        node_options_append: file.node_options_append,
        program: String::new(),
        args: vec![],
        trust_stores,
        upstream_tls,
        skip_cert_regen,
    })
}

pub fn resolve_settings(cli: &Cli) -> Result<Settings> {
    let mut settings = resolve_payload_settings(cli)?;

    let program_raw = cli
        .program
        .first()
        .cloned()
        .context("program is required after --")?;
    let program = resolve_program(&program_raw)?
        .to_string_lossy()
        .into_owned();
    let args = cli.program.iter().skip(1).cloned().collect();

    settings.program = program;
    settings.args = args;
    Ok(settings)
}

pub fn is_payload_mode(cli: &Cli) -> bool {
    cli.payload.is_some() || is_stdin_piped()
}

pub fn validate_mode_exclusivity(cli: &Cli) -> Result<()> {
    if is_payload_mode(cli) && !cli.program.is_empty() {
        anyhow::bail!(
            "payload mode (--payload or piped stdin) cannot be combined with a program after --"
        );
    }
    Ok(())
}

pub fn is_stdin_piped() -> bool {
    use std::io::IsTerminal;

    !std::io::stdin().is_terminal() && !is_stdin_null()
}

fn is_stdin_null() -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let fd = std::io::stdin().as_raw_fd();
        #[cfg(target_os = "linux")]
        {
            let path = format!("/proc/self/fd/{fd}");
            if let Ok(target) = std::fs::read_link(path) {
                if target == std::path::Path::new("/dev/null") {
                    return true;
                }
            }
        }

        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return false;
        }
        let stat = unsafe { stat.assume_init() };
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFCHR {
            return false;
        }

        let mut null_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let null_fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        if null_fd < 0 {
            return false;
        }
        let same = unsafe {
            libc::fstat(null_fd, null_stat.as_mut_ptr()) == 0
                && null_stat.assume_init().st_rdev == stat.st_rdev
        };
        unsafe {
            libc::close(null_fd);
        }
        same
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileType, FILE_TYPE_CHAR, FILE_TYPE_UNKNOWN,
        };
        use windows_sys::Win32::System::Console::GetConsoleMode;

        let handle = std::io::stdin().as_raw_handle();
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return true;
        }
        let file_type = unsafe { GetFileType(handle) };
        if file_type == FILE_TYPE_UNKNOWN {
            return true;
        }
        if file_type == FILE_TYPE_CHAR {
            let mut mode = 0u32;
            return unsafe { GetConsoleMode(handle, &mut mode) == 0 };
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    fn test_echo_program() -> &'static str {
        if cfg!(windows) {
            "cmd.exe"
        } else {
            "echo"
        }
    }

    fn test_echo_args() -> Vec<&'static str> {
        if cfg!(windows) {
            vec!["/C", "echo", "hi"]
        } else {
            vec!["hi"]
        }
    }

    fn test_true_args() -> Vec<&'static str> {
        if cfg!(windows) {
            vec!["cmd.exe", "/C", "exit", "0"]
        } else {
            vec!["true"]
        }
    }

    #[test]
    fn cli_overrides_file() {
        let dir = TempDir::new().unwrap();
        let cfg_path = dir.path().join("guardian.toml");
        let mut f = fs::File::create(&cfg_path).unwrap();
        writeln!(f, "bind = \"127.0.0.1\"").unwrap();
        writeln!(f, "trypanophobe_swap = true").unwrap();
        writeln!(f, "trypanophobe_filter = \"http://127.0.0.1:1/pass\"").unwrap();
        writeln!(f, "port = 9000").unwrap();

        let mut argv = vec![
            "guardian",
            "--config",
            cfg_path.to_str().unwrap(),
            "--",
            test_echo_program(),
        ];
        argv.extend(test_echo_args());
        let cli = Cli::try_parse_from(argv).unwrap();

        let settings = resolve_settings(&cli).unwrap();
        assert!(settings.trypanophobe_swap);
        assert_eq!(settings.port, Some(9000));
        assert_eq!(
            settings.program,
            which::which(test_echo_program()).unwrap().to_string_lossy()
        );
        assert_eq!(
            settings.args,
            test_echo_args()
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn resolve_program_bare_name() {
        let resolved = resolve_program(test_echo_program()).unwrap();
        assert!(resolved.is_absolute());
        assert!(resolved.exists());
    }

    #[test]
    fn resolve_program_absolute_path() {
        let echo = which::which(test_echo_program()).unwrap();
        let resolved = resolve_program(echo.to_str().unwrap()).unwrap();
        assert_eq!(resolved, echo);
    }

    #[test]
    fn resolve_program_unknown_bare_name() {
        let err = resolve_program("guardian-nonexistent-program-xyz").unwrap_err();
        assert!(
            err.to_string().contains("not found in PATH"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn expand_tilde_resolves_home() {
        let home = dirs::home_dir().expect("home dir");
        assert_eq!(expand_tilde("~").unwrap(), home);
    }

    #[test]
    fn expand_tilde_leaves_absolute_path() {
        assert_eq!(
            expand_tilde("/etc/hosts").unwrap(),
            std::path::PathBuf::from("/etc/hosts")
        );
    }

    #[test]
    fn default_guardian_home_expands_tilde() {
        let home = default_guardian_home().unwrap();
        assert!(home.ends_with(".guardian"));
        assert!(!home.to_string_lossy().starts_with('~'));
    }

    #[test]
    fn expand_tilde_resolves_home_relative_path() {
        let home = dirs::home_dir().expect("home dir");
        let expanded = expand_tilde("~/guardian-test").unwrap();
        assert_eq!(expanded, home.join("guardian-test"));
    }

    #[test]
    fn default_ca_dir_is_guardian_home() {
        let file = FileSettings::default();
        assert_eq!(file.ca_dir, "~/.guardian");
    }

    #[test]
    fn default_filter_from_settings_when_unset() {
        let mut argv = vec!["guardian", "--"];
        argv.extend(test_true_args());
        let cli = Cli::try_parse_from(argv).unwrap();
        let settings = resolve_settings(&cli).unwrap();
        assert!(settings.filter.contains("includes(port)"));
        assert!(settings.filter.contains("22"));
    }

    #[test]
    fn ignored_ports_cli_override() {
        let mut argv = vec!["guardian", "--ignored-ports", "22,8080", "--"];
        argv.extend(test_true_args());
        let cli = Cli::try_parse_from(argv).unwrap();

        let settings = resolve_settings(&cli).unwrap();
        assert!(settings.filter.contains("8080"));
        assert!(!settings.filter.contains("5432"));
    }

    #[test]
    fn ignored_ports_from_file_when_filter_unset() {
        let dir = TempDir::new().unwrap();
        let cfg_path = dir.path().join("guardian.toml");
        let mut f = fs::File::create(&cfg_path).unwrap();
        writeln!(f, "ignored_ports = [22, 8080]").unwrap();

        let mut argv = vec!["guardian", "--config", cfg_path.to_str().unwrap(), "--"];
        argv.extend(test_true_args());
        let cli = Cli::try_parse_from(argv).unwrap();

        let settings = resolve_settings(&cli).unwrap();
        assert!(settings.filter.contains("8080"));
        assert!(settings.filter.contains("22"));
    }

    fn with_env_var<F>(key: &str, value: Option<&str>, f: F)
    where
        F: FnOnce(),
    {
        let prev = std::env::var_os(key);
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        f();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    fn minimal_config_cli(dir: &TempDir) -> Cli {
        let cfg_path = dir.path().join("guardian.toml");
        std::fs::write(&cfg_path, "bind = \"127.0.0.1\"\n").unwrap();
        Cli::try_parse_from([
            "guardian",
            "--config",
            cfg_path.to_str().unwrap(),
            "--payload",
            "x",
        ])
        .unwrap()
    }

    #[test]
    fn env_trypanophobe_filter() {
        let _guard = crate::test_lock::env_test_lock();
        let dir = TempDir::new().unwrap();
        with_env_var(
            "GUARDIAN_TRYPANOPHOBE_FILTER",
            Some("http://127.0.0.1:9/pass"),
            || {
                let settings = resolve_payload_settings(&minimal_config_cli(&dir)).unwrap();
                assert_eq!(
                    settings.trypanophobe_filter.as_deref(),
                    Some("http://127.0.0.1:9/pass")
                );
            },
        );
    }

    #[test]
    fn env_filter_timeout_secs() {
        let _guard = crate::test_lock::env_test_lock();
        let dir = TempDir::new().unwrap();
        with_env_var("GUARDIAN_FILTER_TIMEOUT_SECS", Some("42"), || {
            let settings = resolve_payload_settings(&minimal_config_cli(&dir)).unwrap();
            assert_eq!(settings.filter_timeout_secs, 42);
        });
    }

    #[test]
    fn env_bind() {
        let _guard = crate::test_lock::env_test_lock();
        let dir = TempDir::new().unwrap();
        with_env_var("GUARDIAN_BIND", Some("10.0.0.5"), || {
            let settings = resolve_payload_settings(&minimal_config_cli(&dir)).unwrap();
            assert_eq!(settings.bind, Ipv4Addr::new(10, 0, 0, 5));
        });
    }

    #[test]
    fn env_upstream_tls() {
        let _guard = crate::test_lock::env_test_lock();
        let dir = TempDir::new().unwrap();
        with_env_var("GUARDIAN_UPSTREAM_TLS", Some("insecure"), || {
            let settings = resolve_payload_settings(&minimal_config_cli(&dir)).unwrap();
            assert_eq!(settings.upstream_tls, UpstreamTlsConfig::Insecure);
        });
    }

    #[test]
    fn skip_cert_regen_from_file() {
        let dir = TempDir::new().unwrap();
        let cfg_path = dir.path().join("guardian.toml");
        std::fs::write(&cfg_path, "skip_cert_regen = true\n").unwrap();
        let mut argv = vec!["guardian", "--config", cfg_path.to_str().unwrap(), "--"];
        argv.extend(test_true_args());
        let cli = Cli::try_parse_from(argv).unwrap();
        let settings = resolve_settings(&cli).unwrap();
        assert!(settings.skip_cert_regen);
    }

    #[test]
    fn skip_cert_regen_from_cli() {
        let mut argv = vec!["guardian", "--skip-cert-regen", "--"];
        argv.extend(test_true_args());
        let cli = Cli::try_parse_from(argv).unwrap();
        let settings = resolve_settings(&cli).unwrap();
        assert!(settings.skip_cert_regen);
    }

    #[test]
    fn env_skip_cert_regen() {
        let _guard = crate::test_lock::env_test_lock();
        let dir = TempDir::new().unwrap();
        with_env_var("GUARDIAN_SKIP_CERT_REGEN", Some("true"), || {
            let settings = resolve_payload_settings(&minimal_config_cli(&dir)).unwrap();
            assert!(settings.skip_cert_regen);
        });
    }

    #[test]
    fn tps_without_tpf_errors() {
        let _guard = crate::test_lock::env_test_lock();
        let dir = TempDir::new().unwrap();
        let cfg_path = dir.path().join("guardian.toml");
        std::fs::write(&cfg_path, "bind = \"127.0.0.1\"\n").unwrap();
        let prev_filter = std::env::var_os("GUARDIAN_TRYPANOPHOBE_FILTER");
        std::env::remove_var("GUARDIAN_TRYPANOPHOBE_FILTER");
        let cli = Cli::try_parse_from([
            "guardian",
            "--config",
            cfg_path.to_str().unwrap(),
            "--tps",
            "--payload",
            "x",
        ])
        .unwrap();
        let err = resolve_payload_settings(&cli).unwrap_err();
        assert!(err.to_string().contains("requires --tpf"));
        if let Some(value) = prev_filter {
            std::env::set_var("GUARDIAN_TRYPANOPHOBE_FILTER", value);
        }
    }

    #[test]
    fn custom_filter_from_cli() {
        let mut argv = vec!["guardian", "--filter", "host === \"api.example.com\"", "--"];
        argv.extend(test_true_args());
        let cli = Cli::try_parse_from(argv).unwrap();
        let settings = resolve_settings(&cli).unwrap();
        assert!(settings.filter.contains("api.example.com"));
    }

    #[test]
    fn bind_from_file_when_cli_omitted() {
        let dir = TempDir::new().unwrap();
        let cfg_path = dir.path().join("guardian.toml");
        let mut f = fs::File::create(&cfg_path).unwrap();
        writeln!(f, "bind = \"10.0.0.1\"").unwrap();

        let mut argv = vec!["guardian", "--config", cfg_path.to_str().unwrap(), "--"];
        argv.extend(test_true_args());
        let cli = Cli::try_parse_from(argv).unwrap();

        let settings = resolve_settings(&cli).unwrap();
        assert_eq!(settings.bind, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn resolve_trust_stores_prefers_subcommand_stores() {
        use crate::cli::{Cli, Commands, SystemOpts};
        let cli = Cli {
            command: Some(Commands::CheckSystem(SystemOpts {
                stores: Some(vec!["java".into()]),
            })),
            ..Cli::try_parse_from(["guardian", "check-system"]).unwrap()
        };
        let stores = resolve_trust_stores(
            &cli,
            match &cli.command {
                Some(Commands::CheckSystem(opts)) => Some(opts),
                _ => None,
            },
        );
        assert_eq!(stores, vec!["java".to_string()]);
    }

    #[test]
    fn tpf_from_cli() {
        let cli = Cli::try_parse_from([
            "guardian",
            "--tpf",
            "http://127.0.0.1:1/pass",
            "--payload",
            "x",
        ])
        .unwrap();
        let settings = resolve_payload_settings(&cli).unwrap();
        assert_eq!(
            settings.trypanophobe_filter.as_deref(),
            Some("http://127.0.0.1:1/pass")
        );
    }

    #[test]
    fn is_payload_mode_true_when_payload_flag_set() {
        let cli = Cli::try_parse_from(["guardian", "--payload", "hello"]).unwrap();
        assert!(is_payload_mode(&cli));
    }

    #[test]
    fn payload_mode_rejects_program_after_dash_dash() {
        let cli = Cli::try_parse_from(["guardian", "--payload", "hello", "--", "echo"]).unwrap();
        assert!(validate_mode_exclusivity(&cli).is_err());
    }

    #[test]
    fn resolve_program_relative_path_in_cwd() {
        let _guard = crate::test_lock::env_test_lock();
        let dir = TempDir::new().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        #[cfg(windows)]
        let (script, rel) = {
            let script = dir.path().join("guardian-test-prog.bat");
            fs::write(&script, "@exit /b 0\r\n").unwrap();
            (script, ".\\guardian-test-prog.bat")
        };
        #[cfg(not(windows))]
        let (script, rel) = {
            let script = dir.path().join("guardian-test-prog");
            fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            (script, "./guardian-test-prog")
        };

        let resolved = resolve_program(rel).unwrap();
        assert_eq!(resolved, script.canonicalize().unwrap());
        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn resolve_program_missing_absolute_path_errors() {
        let err = resolve_program("/nonexistent/guardian-test-prog").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn load_settings_merges_user_guardian_toml() {
        let _guard = crate::test_lock::env_test_lock();
        let home = TempDir::new().unwrap();
        let user_cfg = home.path().join(".guardian");
        fs::create_dir_all(&user_cfg).unwrap();
        fs::write(
            user_cfg.join("guardian.toml"),
            "filter_timeout_secs = 777\n",
        )
        .unwrap();

        let prev_home = std::env::var_os("HOME");
        #[cfg(windows)]
        let prev_profile = std::env::var_os("USERPROFILE");
        std::env::set_var("HOME", home.path());
        #[cfg(windows)]
        std::env::set_var("USERPROFILE", home.path());
        let mut argv = vec!["guardian", "--"];
        argv.extend(test_true_args());
        let cli = Cli::try_parse_from(argv).unwrap();
        let settings = resolve_settings(&cli).unwrap();
        if let Some(value) = prev_home {
            std::env::set_var("HOME", value);
        } else {
            std::env::remove_var("HOME");
        }
        #[cfg(windows)]
        if let Some(value) = prev_profile {
            std::env::set_var("USERPROFILE", value);
        } else {
            std::env::remove_var("USERPROFILE");
        }
        assert_eq!(settings.filter_timeout_secs, 777);
    }

    #[test]
    fn merge_tpf_ignores_empty_string_in_file() {
        let dir = TempDir::new().unwrap();
        let cfg_path = dir.path().join("guardian.toml");
        fs::write(&cfg_path, "trypanophobe_filter = \"\"\n").unwrap();
        let cli = Cli::try_parse_from([
            "guardian",
            "--config",
            cfg_path.to_str().unwrap(),
            "--payload",
            "x",
        ])
        .unwrap();
        let settings = resolve_payload_settings(&cli).unwrap();
        assert!(settings.trypanophobe_filter.is_none());
    }

    #[test]
    fn load_settings_merges_cwd_guardian_toml() {
        let _guard = crate::test_lock::env_test_lock();
        let dir = TempDir::new().unwrap();
        let cfg_path = dir.path().join("guardian.toml");
        let mut f = fs::File::create(&cfg_path).unwrap();
        writeln!(f, "trypanophobe_filter = \"http://127.0.0.1:1/pass\"").unwrap();
        writeln!(f, "trypanophobe_swap = true").unwrap();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let mut argv = vec!["guardian", "--"];
        argv.extend(test_true_args());
        let cli = Cli::try_parse_from(argv).unwrap();
        let settings = resolve_settings(&cli).unwrap();
        std::env::set_current_dir(prev).unwrap();
        assert!(settings.trypanophobe_swap);
    }

    #[test]
    fn is_stdin_null_true_when_stdin_is_null() {
        use std::process::{Command, Stdio};

        let output = Command::new(std::env::current_exe().unwrap())
            .env("GUARDIAN_STDIN_NULL_PROBE", "1")
            .args(["is_stdin_null_dev_null_probe", "--exact", "--nocapture"])
            .stdin(Stdio::null())
            .output()
            .expect("spawn stdin-null probe");
        assert!(
            output.status.success(),
            "is_stdin_null probe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn is_stdin_null_dev_null_probe() {
        if std::env::var_os("GUARDIAN_STDIN_NULL_PROBE").is_none() {
            return;
        }
        assert!(is_stdin_null());
    }
}
