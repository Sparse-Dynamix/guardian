use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener};

use anyhow::{bail, Context, Result};

pub fn validate_range(port: u16, port_min: u16, port_max: u16) -> Result<()> {
    if (port_min..=port_max).contains(&port) {
        Ok(())
    } else {
        bail!("port {port} out of range [{port_min}, {port_max}]")
    }
}

fn bind_or_error(bind_ip: IpAddr, port: u16, port_min: u16, port_max: u16) -> Result<u16> {
    validate_range(port, port_min, port_max)?;
    match TcpListener::bind(SocketAddr::new(bind_ip, port)) {
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

pub fn allocate_port_auto(bind_ip: IpAddr, port_min: u16, port_max: u16) -> Result<u16> {
    let v4 = match bind_ip {
        IpAddr::V4(v) => v,
        IpAddr::V6(_) => bail!("IPv6 bind is not supported in v1beta"),
    };
    let (_, port) = port_check::with_free_ipv4_port(|port| {
        if !(port_min..=port_max).contains(&port) {
            return Err(io::Error::from(io::ErrorKind::AddrInUse));
        }
        TcpListener::bind(SocketAddr::from((v4, port)))?;
        Ok(())
    })
    .ok_or_else(|| anyhow::anyhow!("no free port in [{port_min}, {port_max}]"))?;
    Ok(port)
}

pub fn resolve_listen_port(
    bind_ip: IpAddr,
    port_override: Option<u16>,
    port_min: u16,
    port_max: u16,
) -> Result<u16> {
    match port_override {
        Some(p) => bind_or_error(bind_ip, p, port_min, port_max),
        None => allocate_port_auto(bind_ip, port_min, port_max),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const PORT_MIN: u16 = 1024;
    const PORT_MAX: u16 = 65535;

    #[test]
    fn validate_range_rejects() {
        assert!(validate_range(80, PORT_MIN, PORT_MAX).is_err());
        assert!(validate_range(1023, PORT_MIN, PORT_MAX).is_err());
        assert!(validate_range(8080, PORT_MIN, PORT_MAX).is_ok());
        assert!(validate_range(65535, PORT_MIN, PORT_MAX).is_ok());
    }

    #[test]
    fn auto_allocate_returns_bindable_port() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let port = allocate_port_auto(ip, PORT_MIN, PORT_MAX).unwrap();
        assert!((PORT_MIN..=PORT_MAX).contains(&port));
        assert!(TcpListener::bind(SocketAddr::new(ip, port)).is_ok());
    }

    #[test]
    fn override_binds_exact_port() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let listener = TcpListener::bind(SocketAddr::new(ip, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let resolved = resolve_listen_port(ip, Some(port), PORT_MIN, PORT_MAX).unwrap();
        assert_eq!(resolved, port);
    }

    #[test]
    fn override_fails_when_in_use() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let listener = TcpListener::bind(SocketAddr::new(ip, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let err = resolve_listen_port(ip, Some(port), PORT_MIN, PORT_MAX).unwrap_err();
        assert!(err.to_string().contains("already in use"));
    }

    #[test]
    fn auto_allocate_rejects_ipv6_bind() {
        let ip = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let err = allocate_port_auto(ip, PORT_MIN, PORT_MAX).unwrap_err();
        assert!(err.to_string().contains("IPv6 bind is not supported"));
    }
}
