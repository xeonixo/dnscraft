//! Network helper functions.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether the host portion of a URL is loopback (`localhost` or an IP loopback).
pub fn is_loopback_host_str(rest: &str) -> bool {
    let host_port = rest.split('/').next().unwrap_or(rest);
    let host = if host_port.starts_with('[') {
        host_port
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// IPv4 private / special-use (RFC 1918, loopback, link-local, CGNAT, this-network, broadcast).
pub fn is_private_v4(v4: Ipv4Addr) -> bool {
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || is_this_network(v4)
        || is_cgnat(v4)
}

/// Whether an address may be treated as private (used for rebind protection, etc.).
pub fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v6(v6: Ipv6Addr) -> bool {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_private_v4(v4);
    }
    if let Some(v4) = nat64_embedded_v4(v6) {
        return is_private_v4(v4);
    }
    v6.is_loopback() || v6.is_unicast_link_local() || v6.is_unique_local() || v6.is_unspecified()
}

/// Shared address space `100.64.0.0/10` (RFC 6598).
pub fn is_cgnat(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

fn nat64_embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let o = v6.octets();
    if o[0] == 0x00
        && o[1] == 0x64
        && o[2] == 0xff
        && o[3] == 0x9b
        && o[4..12].iter().all(|&b| b == 0)
    {
        Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
    } else {
        None
    }
}

fn is_this_network(v4: Ipv4Addr) -> bool {
    v4.octets()[0] == 0
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_host_str("127.0.0.1:8443/"));
        assert!(is_loopback_host_str("[::1]:8443/"));
        assert!(is_loopback_host_str("localhost:8080/path"));
        assert!(!is_loopback_host_str("192.0.2.1:443/"));
    }

    #[test]
    fn classifies_private_v4() {
        assert!(is_private_v4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_v4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_private_v4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_v4(Ipv4Addr::LOCALHOST));
        assert!(is_private_v4(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(is_private_v4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_private_v4(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(is_private_v4(Ipv4Addr::BROADCAST));
        assert!(!is_private_v4(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!is_private_v4(Ipv4Addr::new(100, 63, 0, 1)));
        assert!(!is_private_v4(Ipv4Addr::new(100, 128, 0, 1)));
    }

    #[test]
    fn classifies_cgnat() {
        assert!(is_cgnat(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_cgnat(Ipv4Addr::new(100, 127, 255, 255)));
        assert!(!is_cgnat(Ipv4Addr::new(100, 63, 0, 1)));
        assert!(!is_cgnat(Ipv4Addr::new(100, 128, 0, 1)));
    }

    #[test]
    fn classifies_private_ip() {
        assert!(is_private(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_private(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(is_private(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }
}
