use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use config::{Config, Environment, File};
use serde::Deserialize;

use crate::cli::{default_filter, parse_bind_ipv4, Cli};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FileSettings {
    pub bind: String,
    pub port: Option<u16>,
    pub body_limit: usize,
    pub filter: Option<String>,
    pub ca_dir: String,
    pub silent: bool,
}

impl Default for FileSettings {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1".to_string(),
            port: None,
            body_limit: 256,
            filter: None,
            ca_dir: "~/.proxelar".to_string(),
            silent: false,
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
    pub program: String,
    pub args: Vec<String>,
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        dirs::home_dir()
            .map(|h| h.join(rest))
            .unwrap_or_else(|| PathBuf::from(path))
    } else if path == "~" {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
    } else {
        PathBuf::from(path)
    }
}

pub fn load_file_settings(config_path: Option<&Path>) -> Result<FileSettings> {
    let mut builder = Config::builder();

    let shipped = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/guardian.toml");
    if shipped.exists() {
        builder = builder.add_source(File::from(shipped));
    }

    if let Some(dir) = dirs::config_dir() {
        let user = dir.join("guardian/guardian.toml");
        if user.exists() {
            builder = builder.add_source(File::from(user));
        }
    }

    let cwd = PathBuf::from("guardian.toml");
    if cwd.exists() {
        builder = builder.add_source(File::from(cwd));
    }

    if let Some(path) = config_path {
        builder = builder.add_source(File::from(path));
    }

    builder = builder.add_source(Environment::with_prefix("GUARDIAN").separator("_"));

    let cfg = builder
        .build()
        .context("failed to build configuration")?;
    cfg.try_deserialize()
        .context("failed to deserialize configuration")
}

pub fn resolve_settings(cli: &Cli) -> Result<Settings> {
    let file = load_file_settings(cli.config.as_deref())?;

    let bind_str = cli.bind.clone();
    let port = cli.port.or(file.port);
    let body_limit = cli.body_limit.unwrap_or(file.body_limit);
    let filter = cli
        .filter
        .clone()
        .or(file.filter)
        .unwrap_or_else(|| default_filter().to_string());
    let ca_dir = cli
        .ca_dir
        .clone()
        .unwrap_or_else(|| expand_tilde(&file.ca_dir));
    let silent = cli.silent || file.silent;

    let program = cli
        .program
        .first()
        .cloned()
        .context("program is required after --")?;
    let args = cli.program.iter().skip(1).cloned().collect();

    Ok(Settings {
        bind: parse_bind_ipv4(&bind_str)?,
        port,
        body_limit,
        filter,
        ca_dir,
        silent,
        program,
        args,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn cli_overrides_file() {
        let dir = TempDir::new().unwrap();
        let cfg_path = dir.path().join("guardian.toml");
        let mut f = fs::File::create(&cfg_path).unwrap();
        writeln!(f, "bind = \"127.0.0.1\"").unwrap();
        writeln!(f, "body_limit = 128").unwrap();
        writeln!(f, "port = 9000").unwrap();

        let cli = Cli::try_parse_from([
            "guardian",
            "--config",
            cfg_path.to_str().unwrap(),
            "--body-limit",
            "512",
            "--",
            "echo",
            "hi",
        ])
        .unwrap();

        let settings = resolve_settings(&cli).unwrap();
        assert_eq!(settings.body_limit, 512);
        assert_eq!(settings.port, Some(9000));
        assert_eq!(settings.program, "echo");
        assert_eq!(settings.args, vec!["hi".to_string()]);
    }
}
