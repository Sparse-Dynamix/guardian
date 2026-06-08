use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "guardian",
    version = env!("CARGO_PKG_VERSION"),
    about = "Intercept and log HTTP/S and WebSocket traffic for any command",
    trailing_var_arg = true,
    allow_hyphen_values = true
)]
pub struct Cli {
    /// Suppress JSONL network log lines on stderr.
    #[arg(long, global = true)]
    pub silent: bool,

    /// Proxy listen port (overrides auto allocation).
    #[arg(short = 'p', long, global = true)]
    pub port: Option<u16>,

    /// Proxy bind IPv4 address (also used as BIND_HOST in connect hook).
    #[arg(short = 'b', long, global = true)]
    pub bind: Option<String>,

    /// Guardian data directory (CA certificates and config).
    #[arg(long, global = true)]
    pub ca_dir: Option<PathBuf>,

    /// Max request/response/WS frame bytes captured in JSONL previews.
    #[arg(long, global = true)]
    pub body_limit: Option<usize>,

    /// JS expression for connect() filter (sa_family, addr, port).
    #[arg(long, global = true)]
    pub filter: Option<String>,

    /// Non-HTTP TCP ports to leave unhooked when `--filter` is unset (comma-separated).
    #[arg(long, value_delimiter = ',', global = true)]
    pub ignored_ports: Option<Vec<u16>>,

    /// Config file path.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Enable internal tracing to stderr (also respects RUST_LOG).
    #[arg(short = 'v', long, global = true)]
    pub verbose: bool,

    /// Disable colored stderr output for Guardian messages and JSONL.
    #[arg(long, global = true)]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Subcommand program and arguments (run mode; use after `--`).
    #[arg(required = false)]
    pub program: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Install the Guardian CA into system trust stores (requires administrator).
    #[command(name = "install-system")]
    InstallSystem(SystemOpts),
    /// Remove the Guardian CA from system trust stores (requires administrator).
    #[command(name = "remove-system")]
    RemoveSystem(SystemOpts),
    /// Check whether the Guardian CA is installed in system trust stores.
    #[command(name = "check-system")]
    CheckSystem(SystemOpts),
}

#[derive(Debug, Parser, Clone)]
pub struct SystemOpts {
    /// Trust stores to target: system, nss, java (default: all).
    #[arg(long, value_delimiter = ',')]
    pub stores: Option<Vec<String>>,
}

pub fn parse_bind_ipv4(bind: &str) -> Result<Ipv4Addr> {
    let addr: std::net::IpAddr = bind
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid bind address: {bind}"))?;
    match addr {
        std::net::IpAddr::V4(v4) => Ok(v4),
        std::net::IpAddr::V6(_) => bail!("IPv6 bind is not supported in v1"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn parse_bind_accepts_ipv4() {
        assert_eq!(
            parse_bind_ipv4("127.0.0.1").unwrap().to_string(),
            "127.0.0.1"
        );
    }

    #[test]
    fn parse_bind_rejects_ipv6() {
        assert!(parse_bind_ipv4("::1").is_err());
    }

    #[test]
    fn parse_bind_rejects_garbage() {
        assert!(parse_bind_ipv4("not-an-ip").is_err());
    }

    #[test]
    fn version_flag_does_not_require_child() {
        let err = Cli::try_parse_from(["guardian", "--version"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DisplayVersion);
    }

    #[test]
    fn install_system_subcommand_parses() {
        let cli = Cli::try_parse_from(["guardian", "install-system"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::InstallSystem(_))));
    }

    #[test]
    fn check_system_with_stores() {
        let cli =
            Cli::try_parse_from(["guardian", "check-system", "--stores", "system,nss"]).unwrap();
        match cli.command {
            Some(Commands::CheckSystem(opts)) => {
                assert_eq!(opts.stores, Some(vec!["system".into(), "nss".into()]));
            }
            _ => panic!("expected check-system"),
        }
    }
}
