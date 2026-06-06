use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener};

use anyhow::{bail, Context, Result};

pub const MIN_PORT: u16 = 1024;
pub const MAX_PORT: u16 = 65535;
const PORT_SPAN: u32 = (MAX_PORT - MIN_PORT + 1) as u32;

pub fn primary_port(pid: u32) -> u16 {
    MIN_PORT + (pid % PORT_SPAN) as u16
}

pub fn validate_range(port: u16) -> Result<()> {
    if (MIN_PORT..=MAX_PORT).contains(&port) {
        Ok(())
    } else {
        bail!("port {port} out of range [{MIN_PORT}, {MAX_PORT}]")
    }
}

fn try_bind(bind_ip: IpAddr, port: u16) -> io::Result<TcpListener> {
    TcpListener::bind(SocketAddr::new(bind_ip, port))
}

fn bind_or_error(bind_ip: IpAddr, port: u16) -> Result<u16> {
    validate_range(port)?;
    match try_bind(bind_ip, port) {
        Ok(listener) => {
            drop(listener);
            Ok(port)
        }
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
            bail!("port {port} already in use")
        }
        Err(e) => Err(e).with_context(|| format!("failed to bind {bind_ip}:{port}")),
    }
}

pub fn allocate_port_auto(pid: u32, bind_ip: IpAddr) -> Result<u16> {
    let base = (pid % PORT_SPAN) as u16;
    for attempt in 0..PORT_SPAN {
        let port = MIN_PORT + ((base as u32 + attempt) % PORT_SPAN) as u16;
        if try_bind(bind_ip, port).is_ok() {
            return Ok(port);
        }
    }
    bail!("no free port in [{MIN_PORT}, {MAX_PORT}]")
}

pub fn resolve_listen_port(
    pid: u32,
    bind_ip: IpAddr,
    port_override: Option<u16>,
) -> Result<u16> {
    match port_override {
        Some(p) => bind_or_error(bind_ip, p),
        None => allocate_port_auto(pid, bind_ip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn primary_port_mapping() {
        assert_eq!(primary_port(12345), 13369);
        assert_eq!(primary_port(99999), MIN_PORT + (99999 % PORT_SPAN) as u16);
    }

    #[test]
    fn validate_range_rejects() {
        assert!(validate_range(80).is_err());
        assert!(validate_range(1023).is_err());
        assert!(validate_range(8080).is_ok());
        assert!(validate_range(65535).is_ok());
    }

    #[test]
    fn auto_allocate_returns_bindable_port() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let port = allocate_port_auto(std::process::id(), ip).unwrap();
        assert!((MIN_PORT..=MAX_PORT).contains(&port));
        assert!(try_bind(ip, port).is_ok());
    }

    #[test]
    fn override_binds_exact_port() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let listener = TcpListener::bind(SocketAddr::new(ip, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let resolved = resolve_listen_port(42, ip, Some(port)).unwrap();
        assert_eq!(resolved, port);
    }

    #[test]
    fn override_fails_when_in_use() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let listener = TcpListener::bind(SocketAddr::new(ip, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let err = resolve_listen_port(42, ip, Some(port)).unwrap_err();
        assert!(err.to_string().contains("already in use"));
    }
}
