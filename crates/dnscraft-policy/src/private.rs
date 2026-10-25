//! Private / special-use address classification for DNS rebind protection.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether an answer address is treated as private for rebind stripping.
///
/// Covers RFC 1918, loopback, link-local (v4 + v6), ULA `fc00::/7`,
/// `0.0.0.0/8`, broadcast `255.255.255.255`, CGNAT `100.64.0.0/10`,
/// IPv6 unspecified `::`, NAT64 `64:ff9b::/96` when the embedded IPv4 is
/// private, and IPv4-mapped forms of the IPv4 ranges above.
pub(crate) fn is_private_for_rebind(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(v4: Ipv4Addr) -> bool {
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || is_this_network(v4)
        || is_cgnat(v4)
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

/// Embedded IPv4 of a NAT64 address in `64:ff9b::/96`, if the prefix matches.
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

/// `0.0.0.0/8` (this network), excluding nothing — every address in the /8.
fn is_this_network(v4: Ipv4Addr) -> bool {
    v4.octets()[0] == 0
}

/// Shared address space `100.64.0.0/10` (RFC 6598).
fn is_cgnat(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

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
