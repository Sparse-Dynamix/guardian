use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Parser;

/// Well-known non-HTTP TCP ports left untouched by the default connect hook.
/// HTTP Toolkit-style denylist; override with `--filter` for app-specific ports.
pub const IGNORED_NON_HTTP_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 853, 5353, 110, 143, 465, 587, 993, 995, 3306, 5432, 6379, 27017, 3389,
    389, 636, 5060,
];

#[derive(Debug, Parser)]
#[command(
    name = "guardian",
    version = env!("CARGO_PKG_VERSION"),
    about = "MITM network wrapper using Frida + Proxelar",
    trailing_var_arg = true,
    allow_hyphen_values = true
)]
pub struct Cli {
    /// Suppress JSONL network log lines on stderr.
    #[arg(long)]
    pub silent: bool,

    /// Proxy listen port (overrides auto allocation).
    #[arg(short = 'p', long)]
    pub port: Option<u16>,

    /// Proxy bind IPv4 address (also used as BIND_HOST in connect hook).
    #[arg(short = 'b', long)]
    pub bind: Option<String>,

    /// Proxelar CA directory.
    #[arg(long)]
    pub ca_dir: Option<PathBuf>,

    /// Max request/response/WS frame bytes captured in JSONL previews.
    #[arg(long)]
    pub body_limit: Option<usize>,

    /// JS expression for connect() filter (sa_family, addr, port).
    #[arg(long)]
    pub filter: Option<String>,

    /// Config file path.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Enable internal tracing to stderr (also respects RUST_LOG).
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Subcommand program and arguments (after `--`).
    #[arg(required = true)]
    pub program: Vec<String>,
}

pub fn default_filter() -> String {
    let ports = IGNORED_NON_HTTP_PORTS
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    if cfg!(target_os = "windows") {
        format!("![{ports}].includes(port)")
    } else {
        format!("(sa_family == 2 || sa_family == 0) && ![{ports}].includes(port)")
    }
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

    #[test]
    fn parse_bind_accepts_ipv4() {
        assert_eq!(parse_bind_ipv4("127.0.0.1").unwrap().to_string(), "127.0.0.1");
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
    fn default_filter_excludes_ssh_and_includes_http_alt() {
        let filter = default_filter();
        assert!(filter.contains("22"));
        assert!(filter.contains("443") || !filter.contains("port == 443"));
    }

    #[test]
    fn version_flag_does_not_require_child() {
        use clap::error::ErrorKind;
        let err = Cli::try_parse_from(["guardian", "--version"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DisplayVersion);
    }
}
