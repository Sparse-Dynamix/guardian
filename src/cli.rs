use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("GUARDIAN_GIT_SHA"),
    ")"
);

#[derive(Debug, Parser)]
#[command(
    name = "guardian",
    version = VERSION,
    about = "Harden AI harnesses by filtering web traffic and tool-call payloads",
    trailing_var_arg = true,
    allow_hyphen_values = true
)]
pub struct Cli {
    /// Trypanophobe filter endpoint (POST raw body; 200 = pass).
    #[arg(long = "trypanophobe-filter", alias = "tpf", global = true)]
    pub trypanophobe_filter: Option<String>,

    /// Replace harness-visible content with the TPF response body and headers (requires --tpf).
    #[arg(long = "trypanophobe-swap", alias = "tps", global = true)]
    pub trypanophobe_swap: bool,

    /// Tool-call payload for payload-only mode (omit to read stdin).
    #[arg(long, global = true)]
    pub payload: Option<String>,

    /// Proxy listen port (overrides auto allocation).
    #[arg(short = 'p', long, global = true)]
    pub port: Option<u16>,

    /// Proxy bind IPv4 address (also used as BIND_HOST in connect hook).
    #[arg(short = 'b', long, global = true)]
    pub bind: Option<String>,

    /// Guardian data directory (CA certificates and config).
    #[arg(long, global = true)]
    pub ca_dir: Option<PathBuf>,

    /// JS expression for connect() filter (sa_family, addr, port, host).
    #[arg(long, global = true)]
    pub filter: Option<String>,

    /// Non-HTTP TCP ports to leave unhooked when `--filter` is unset (comma-separated).
    #[arg(long, value_delimiter = ',', global = true)]
    pub ignored_ports: Option<Vec<u16>>,

    /// Config file path.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Subcommand program and arguments (MITM mode; use after `--`).
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
    /// Delete Guardian local artifacts; remove system trust when run as administrator.
    #[command(name = "clean")]
    Clean(SystemOpts),
    /// Print legal notice and third-party attributions (NOTICE.txt).
    #[command(name = "legal-notes")]
    LegalNotes,
    /// Print the Guardian GPL license text (LICENSE).
    #[command(name = "license-notes")]
    LicenseNotes,
    /// Print the security model (SECURITY.md).
    #[command(name = "security-notes")]
    SecurityNotes,
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
        std::net::IpAddr::V6(_) => bail!("IPv6 bind is not supported in v1beta"),
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
    fn remove_system_subcommand_parses() {
        let cli = Cli::try_parse_from(["guardian", "remove-system"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::RemoveSystem(_))));
    }

    #[test]
    fn clean_subcommand_parses() {
        let cli = Cli::try_parse_from(["guardian", "clean", "--stores", "system"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Clean(_))));
    }

    #[test]
    fn ignored_ports_parses_comma_list() {
        let cli = Cli::try_parse_from(["guardian", "--ignored-ports", "22,8080", "--payload", "x"])
            .unwrap();
        assert_eq!(cli.ignored_ports, Some(vec![22, 8080]));
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

    #[test]
    fn tpf_alias_parses() {
        let cli = Cli::try_parse_from([
            "guardian",
            "--tpf",
            "http://127.0.0.1:9999/pass",
            "--payload",
            "hello",
        ])
        .unwrap();
        assert_eq!(
            cli.trypanophobe_filter.as_deref(),
            Some("http://127.0.0.1:9999/pass")
        );
        assert_eq!(cli.payload.as_deref(), Some("hello"));
    }

    #[test]
    fn tps_alias_parses() {
        let cli = Cli::try_parse_from([
            "guardian",
            "--tpf",
            "http://127.0.0.1:9999/pass",
            "--tps",
            "--payload",
            "hello",
        ])
        .unwrap();
        assert!(cli.trypanophobe_swap);
    }

    #[test]
    fn legal_notes_subcommand_parses() {
        let cli = Cli::try_parse_from(["guardian", "legal-notes"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::LegalNotes)));
    }

    #[test]
    fn license_notes_subcommand_parses() {
        let cli = Cli::try_parse_from(["guardian", "license-notes"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::LicenseNotes)));
    }

    #[test]
    fn security_notes_subcommand_parses() {
        let cli = Cli::try_parse_from(["guardian", "security-notes"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::SecurityNotes)));
    }
}
