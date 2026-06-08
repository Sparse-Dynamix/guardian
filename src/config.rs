use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use config::{Config, Environment, File};
use serde::Deserialize;

use crate::cli::{parse_bind_ipv4, Cli, SystemOpts};
use crate::filter::{connect_filter_from_ports, DEFAULT_IGNORED_PORTS};
use crate::system_trust::default_trust_stores;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FileSettings {
    pub bind: String,
    pub port: Option<u16>,
    pub body_limit: usize,
    pub filter: Option<String>,
    #[serde(default = "default_ignored_ports")]
    pub ignored_ports: Vec<u16>,
    pub ca_dir: String,
    pub silent: bool,
    pub no_color: bool,
    pub port_min: u16,
    pub port_max: u16,
    pub proxy_event_channel_capacity: usize,
    pub proxy_ready_timeout_secs: u64,
    pub proxy_ready_poll_ms: u64,
    pub process_poll_interval_ms: u64,
    pub ca_bundle_name: String,
    pub java_truststore_name: String,
    pub java_truststore_password: String,
    pub deno_tls_ca_store: String,
    pub node_options_append: String,
    pub tracing_prefix: String,
    pub tracing_default_level: String,
    pub trust_stores: Option<Vec<String>>,
}

impl Default for FileSettings {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1".to_string(),
            port: None,
            body_limit: 256,
            filter: None,
            ignored_ports: default_ignored_ports(),
            ca_dir: "~/.guardian".to_string(),
            silent: false,
            no_color: false,
            port_min: 1024,
            port_max: 65535,
            proxy_event_channel_capacity: 10_000,
            proxy_ready_timeout_secs: 5,
            proxy_ready_poll_ms: 10,
            process_poll_interval_ms: 50,
            ca_bundle_name: "guardian-ca-bundle.pem".to_string(),
            java_truststore_name: "guardian-java-truststore.p12".to_string(),
            java_truststore_password: "guardian".to_string(),
            deno_tls_ca_store: "system,mozilla".to_string(),
            node_options_append: "--use-openssl-ca".to_string(),
            tracing_prefix: "guardian: ".to_string(),
            tracing_default_level: "guardian=debug".to_string(),
            trust_stores: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub bind: Ipv4Addr,
    pub port: Option<u16>,
    pub body_limit: usize,
    pub filter: String,
    pub ca_dir: PathBuf,
    pub silent: bool,
    pub no_color: bool,
    pub port_min: u16,
    pub port_max: u16,
    pub proxy_event_channel_capacity: usize,
    pub proxy_ready_timeout_secs: u64,
    pub proxy_ready_poll_ms: u64,
    pub process_poll_interval_ms: u64,
    pub ca_bundle_name: String,
    pub java_truststore_name: String,
    pub java_truststore_password: String,
    pub deno_tls_ca_store: String,
    pub node_options_append: String,
    pub tracing_prefix: String,
    pub tracing_default_level: String,
    pub program: String,
    pub args: Vec<String>,
    pub trust_stores: Vec<String>,
}

fn default_ignored_ports() -> Vec<u16> {
    DEFAULT_IGNORED_PORTS.to_vec()
}

pub fn expand_tilde(path: &str) -> Result<PathBuf> {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = dirs::home_dir().context("home directory not found (required for ~ paths)")?;
        Ok(home.join(rest))
    } else if path == "~" {
        dirs::home_dir().context("home directory not found (required for ~ path)")
    } else {
        Ok(PathBuf::from(path))
    }
}

pub fn default_guardian_home() -> Result<PathBuf> {
    expand_tilde("~/.guardian")
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

    builder = builder.add_source(Environment::with_prefix("GUARDIAN").separator("_"));

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

pub fn resolve_no_color(cli: &Cli) -> Result<bool> {
    let file = load_file_settings(cli.config.as_deref())?;
    Ok(cli.no_color || file.no_color)
}

pub fn resolve_settings(cli: &Cli) -> Result<Settings> {
    let file = load_file_settings(cli.config.as_deref())?;

    let bind_str = cli.bind.as_deref().unwrap_or(&file.bind);
    let port = cli.port.or(file.port);
    let body_limit = cli.body_limit.unwrap_or(file.body_limit);
    let filter = cli
        .filter
        .clone()
        .or(file.filter.clone())
        .unwrap_or_else(|| {
            let ports = cli
                .ignored_ports
                .as_ref()
                .filter(|ports| !ports.is_empty())
                .cloned()
                .unwrap_or(file.ignored_ports);
            connect_filter_from_ports(&ports)
        });
    let ca_dir = resolve_ca_dir(cli)?;
    let silent = cli.silent || file.silent;
    let no_color = cli.no_color || file.no_color;

    let program_raw = cli
        .program
        .first()
        .cloned()
        .context("program is required after --")?;
    let program = resolve_program(&program_raw)?
        .to_string_lossy()
        .into_owned();
    let args = cli.program.iter().skip(1).cloned().collect();

    let trust_stores = file
        .trust_stores
        .clone()
        .unwrap_or_else(default_trust_stores);

    Ok(Settings {
        bind: parse_bind_ipv4(bind_str)?,
        port,
        body_limit,
        filter,
        ca_dir,
        silent,
        no_color,
        port_min: file.port_min,
        port_max: file.port_max,
        proxy_event_channel_capacity: file.proxy_event_channel_capacity,
        proxy_ready_timeout_secs: file.proxy_ready_timeout_secs,
        proxy_ready_poll_ms: file.proxy_ready_poll_ms,
        process_poll_interval_ms: file.process_poll_interval_ms,
        ca_bundle_name: file.ca_bundle_name,
        java_truststore_name: file.java_truststore_name,
        java_truststore_password: file.java_truststore_password,
        deno_tls_ca_store: file.deno_tls_ca_store,
        node_options_append: file.node_options_append,
        tracing_prefix: file.tracing_prefix,
        tracing_default_level: file.tracing_default_level,
        program,
        args,
        trust_stores,
    })
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
        writeln!(f, "body_limit = 128").unwrap();
        writeln!(f, "port = 9000").unwrap();

        let mut argv = vec![
            "guardian",
            "--config",
            cfg_path.to_str().unwrap(),
            "--body-limit",
            "512",
            "--",
            test_echo_program(),
        ];
        argv.extend(test_echo_args());
        let cli = Cli::try_parse_from(argv).unwrap();

        let settings = resolve_settings(&cli).unwrap();
        assert_eq!(settings.body_limit, 512);
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
    fn no_color_from_cli() {
        let mut argv = vec!["guardian", "--no-color", "--"];
        argv.extend(test_true_args());
        let cli = Cli::try_parse_from(argv).unwrap();
        let settings = resolve_settings(&cli).unwrap();
        assert!(settings.no_color);
    }
}
