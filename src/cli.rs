use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "guardian",
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

pub fn default_filter() -> &'static str {
    if cfg!(target_os = "windows") {
        "true"
    } else {
        "sa_family == 2 || sa_family == 0"
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
