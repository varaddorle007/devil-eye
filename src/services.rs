//! Static well-known TCP/UDP service port names (no DNS / no network).
//!
//! Used when capture is run without `-n` / `--numeric`. Addresses stay numeric;
//! only ports are mapped from this table (tcpdump-style service names).

/// Look up a well-known service name for `port`, if any.
pub fn service_name(port: u16) -> Option<&'static str> {
    // Keep sorted by port for binary search.
    SERVICES
        .binary_search_by_key(&port, |&(p, _)| p)
        .ok()
        .map(|i| SERVICES[i].1)
}

/// Format a port as a service name when `numeric` is false and the port is known.
pub fn format_port(port: u16, numeric: bool) -> String {
    if numeric {
        return port.to_string();
    }
    match service_name(port) {
        Some(name) => name.to_string(),
        None => port.to_string(),
    }
}

/// Common IANA / lab ports (sorted ascending).
const SERVICES: &[(u16, &str)] = &[
    (20, "ftp-data"),
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "domain"),
    (67, "bootps"),
    (68, "bootpc"),
    (69, "tftp"),
    (80, "http"),
    (110, "pop3"),
    (123, "ntp"),
    (143, "imap"),
    (161, "snmp"),
    (162, "snmptrap"),
    (179, "bgp"),
    (389, "ldap"),
    (443, "https"),
    (445, "microsoft-ds"),
    (465, "smtps"),
    (500, "isakmp"),
    (514, "syslog"),
    (520, "route"),
    (587, "submission"),
    (636, "ldaps"),
    (853, "domain-s"),
    (989, "ftps-data"),
    (990, "ftps"),
    (993, "imaps"),
    (995, "pop3s"),
    (1080, "socks"),
    (1194, "openvpn"),
    (1433, "ms-sql-s"),
    (1521, "oracle"),
    (1883, "mqtt"),
    (2049, "nfs"),
    (3306, "mysql"),
    (3389, "ms-wbt-server"),
    (5432, "postgresql"),
    (5900, "vnc"),
    (6379, "redis"),
    (6443, "https-alt"),
    (8080, "http-alt"),
    (8443, "https-alt"),
    (8888, "http-alt"),
    (9200, "wap-wsp"),
    (9443, "https-alt"),
    (11211, "memcache"),
    (27017, "mongodb"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_common_ports() {
        assert_eq!(service_name(53), Some("domain"));
        assert_eq!(service_name(80), Some("http"));
        assert_eq!(service_name(443), Some("https"));
        assert_eq!(service_name(22), Some("ssh"));
        assert_eq!(service_name(65_000), None);
    }

    #[test]
    fn format_respects_numeric() {
        assert_eq!(format_port(53, true), "53");
        assert_eq!(format_port(53, false), "domain");
        assert_eq!(format_port(49_152, false), "49152");
    }

    #[test]
    fn table_is_sorted() {
        for w in SERVICES.windows(2) {
            assert!(w[0].0 < w[1].0, "ports must be strictly ascending");
        }
    }
}
