//! Private / special-use address classification for DNS rebind protection.

use std::net::IpAddr;

/// Whether an answer address is treated as private for rebind stripping.
///
/// Covers RFC 1918, loopback, link-local (v4 + v6), ULA `fc00::/7`,
/// `0.0.0.0/8`, broadcast `255.255.255.255`, CGNAT `100.64.0.0/10`,
/// IPv6 unspecified `::`, NAT64 `64:ff9b::/96` when the embedded IPv4 is
/// private, and IPv4-mapped forms of the IPv4 ranges above.
pub(crate) fn is_private_for_rebind(ip: IpAddr) -> bool {
    dnscraft_common::net::is_private(ip)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn classifies_rfc1918_loopback_link_local_cgnat_and_this_net() {
        assert!(is_private_for_rebind(IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 1
        ))));
        assert!(is_private_for_rebind(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        ))));
        assert!(is_private_for_rebind(IpAddr::V4(Ipv4Addr::new(
            172, 16, 0, 1
        ))));
        assert!(is_private_for_rebind(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_private_for_rebind(IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 1
        ))));
        assert!(is_private_for_rebind(IpAddr::V4(Ipv4Addr::new(
            100, 64, 0, 1
        ))));
        assert!(is_private_for_rebind(IpAddr::V4(Ipv4Addr::new(
            100, 127, 255, 255
        ))));
        assert!(is_private_for_rebind(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(is_private_for_rebind(IpAddr::V4(Ipv4Addr::new(
            0, 255, 255, 255
        ))));
        assert!(!is_private_for_rebind(IpAddr::V4(Ipv4Addr::new(
            192, 0, 2, 1
        ))));
        assert!(!is_private_for_rebind(IpAddr::V4(Ipv4Addr::new(
            100, 63, 0, 1
        ))));
        assert!(!is_private_for_rebind(IpAddr::V4(Ipv4Addr::new(
            100, 128, 0, 1
        ))));
    }

    #[test]
    fn classifies_ula_link_local_loopback_and_mapped() {
        assert!(is_private_for_rebind(IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(is_private_for_rebind(IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(is_private_for_rebind(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_private_for_rebind(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_private_for_rebind(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        ))));
        // ::ffff:10.0.0.1
        let mapped = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001);
        assert_eq!(mapped.to_ipv4_mapped(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_for_rebind(IpAddr::V6(mapped)));
        let mapped_doc = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201);
        assert!(!is_private_for_rebind(IpAddr::V6(mapped_doc)));
    }

    #[test]
    fn classifies_unspecified_broadcast_and_nat64() {
        assert!(is_private_for_rebind(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(is_private_for_rebind(IpAddr::V4(Ipv4Addr::BROADCAST)));
        // 64:ff9b::10.0.0.1
        let nat64_priv = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x0a00, 0x0001);
        assert!(is_private_for_rebind(IpAddr::V6(nat64_priv)));
        // 64:ff9b::192.0.2.1 (documentation — not private)
        let nat64_pub = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xc000, 0x0201);
        assert!(!is_private_for_rebind(IpAddr::V6(nat64_pub)));
    }
}
