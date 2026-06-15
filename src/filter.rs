//! Connect-hook filter expressions (HTTP Toolkit-style TCP port denylist).

/// Well-known non-HTTP TCP ports left untouched by the default connect hook.
pub const DEFAULT_IGNORED_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 853, 5353, 110, 143, 465, 587, 993, 995, 3306, 5432, 6379, 27017, 3389,
    389, 636, 5060,
];

pub fn connect_filter_from_ports(ports: &[u16]) -> String {
    let list = ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    if cfg!(target_os = "windows") {
        format!("![{list}].includes(port)")
    } else {
        format!("(sa_family == 2 || sa_family == 0) && ![{list}].includes(port)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ports_include_common_services() {
        assert!(DEFAULT_IGNORED_PORTS.contains(&22));
        assert!(DEFAULT_IGNORED_PORTS.contains(&587));
        assert!(DEFAULT_IGNORED_PORTS.contains(&3306));
        assert!(DEFAULT_IGNORED_PORTS.contains(&5432));
    }

    #[test]
    fn connect_filter_formats_single_port() {
        let filter = connect_filter_from_ports(&[9999]);
        assert!(filter.contains("9999"));
        assert!(filter.contains("includes(port)"));
        if cfg!(windows) {
            assert_eq!(filter, "![9999].includes(port)");
        } else {
            assert!(filter.starts_with("(sa_family == 2 || sa_family == 0)"));
        }
    }

    #[test]
    fn connect_filter_formats_multiple_ports() {
        let filter = connect_filter_from_ports(&[80, 443, 8080]);
        assert!(filter.contains("80"));
        assert!(filter.contains("443"));
        assert!(filter.contains("8080"));
    }

    #[test]
    fn default_ports_exclude_ssh() {
        let filter = connect_filter_from_ports(DEFAULT_IGNORED_PORTS);
        assert!(filter.contains("22"));
        assert!(filter.contains("includes(port)"));
    }

    #[test]
    fn custom_ports_list() {
        let filter = connect_filter_from_ports(&[22, 8080]);
        assert!(filter.contains("22"));
        assert!(filter.contains("8080"));
    }

    #[test]
    fn unix_filter_checks_ipv4_sa_family() {
        if cfg!(not(windows)) {
            let filter = connect_filter_from_ports(&[22]);
            assert!(filter.contains("sa_family == 2"));
        }
    }

    #[test]
    fn windows_filter_omits_sa_family() {
        if cfg!(windows) {
            let filter = connect_filter_from_ports(&[22]);
            assert!(!filter.contains("sa_family"));
            assert!(filter.contains("![22]"));
        }
    }
}
