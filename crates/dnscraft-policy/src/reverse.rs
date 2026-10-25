//! Reverse-DNS helpers for ClientDirectory PTR answers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dnscraft_proto::Name;
use ipnet::IpNet;

/// Parses a full reverse name into an IP address.
///
/// Accepts `a.b.c.d.in-addr.arpa` (IPv4) and the 32-nibble `ip6.arpa` form.
/// Incomplete zone names (e.g. `10.in-addr.arpa`) return [`None`].
pub(crate) fn ip_from_reverse(name: &Name) -> Option<IpAddr> {
    let labels: Vec<&[u8]> = name.labels().collect();
    if labels.len() >= 6
        && labels[labels.len() - 2].eq_ignore_ascii_case(b"in-addr")
        && labels[labels.len() - 1].eq_ignore_ascii_case(b"arpa")
    {
        if labels.len() != 6 {
            return None;
        }
        let a = parse_decimal_octet(labels[3])?;
        let b = parse_decimal_octet(labels[2])?;
        let c = parse_decimal_octet(labels[1])?;
        let d = parse_decimal_octet(labels[0])?;
        return Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
    }
    if labels.len() == 34
        && labels[32].eq_ignore_ascii_case(b"ip6")
        && labels[33].eq_ignore_ascii_case(b"arpa")
    {
        let mut bytes = [0u8; 16];
        for (i, pair) in labels[..32].chunks(2).enumerate() {
            // Labels are least-significant nibble first.
            let lo = parse_hex_nibble(pair[0])?;
            let hi = parse_hex_nibble(pair[1])?;
            bytes[15 - i] = (hi << 4) | lo;
        }
        return Some(IpAddr::V6(Ipv6Addr::from(bytes)));
    }
    None
}

/// Whether policy may answer PTR for `ip` from the ClientDirectory.
///
/// Always true for RFC 1918, loopback, and ULA `fc00::/7`. Extra prefixes come
/// from `policy.ptr_prefixes`.
pub(crate) fn ptr_eligible(ip: IpAddr, extra: &[IpNet]) -> bool {
    if is_builtin_ptr_space(ip) {
        return true;
    }
    extra.iter().any(|net| net.contains(&ip))
}

fn is_builtin_ptr_space(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || is_ula(v6),
    }
}

/// Unique local addresses (`fc00::/7`).
fn is_ula(addr: Ipv6Addr) -> bool {
    addr.octets()[0] & 0xfe == 0xfc
}

fn parse_decimal_octet(label: &[u8]) -> Option<u8> {
    if label.is_empty() || label.len() > 3 {
        return None;
    }
    let mut n: u16 = 0;
    for &b in label {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n * 10 + u16::from(b - b'0');
        if n > 255 {
            return None;
        }
    }
    // Reject leading zeros except for "0" itself.
    if label.len() > 1 && label[0] == b'0' {
        return None;
    }
    u8::try_from(n).ok()
}

fn parse_hex_nibble(label: &[u8]) -> Option<u8> {
    if label.len() != 1 {
        return None;
    }
    match label[0] {
        b'0'..=b'9' => Some(label[0] - b'0'),
        b'a'..=b'f' => Some(label[0] - b'a' + 10),
        b'A'..=b'F' => Some(label[0] - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    #[test]
    fn reverse_ipv4_round_trip_labels() {
        assert_eq!(
            ip_from_reverse(&name("10.2.0.192.in-addr.arpa")),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        );
        assert_eq!(
            ip_from_reverse(&name("1.0.0.10.in-addr.arpa.")),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert!(ip_from_reverse(&name("10.in-addr.arpa")).is_none());
        assert!(ip_from_reverse(&name("2.0.192.in-addr.arpa")).is_none());
    }

    #[test]
    fn reverse_ipv6_ula_nibble_form() {
        // fd00::1 → reversed nibbles under ip6.arpa
        let mut labels = Vec::new();
        let octets = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets();
        for byte in octets.iter().rev() {
            labels.push(format!("{:x}", byte & 0x0f));
            labels.push(format!("{:x}", byte >> 4));
        }
        labels.push("ip6".into());
        labels.push("arpa".into());
        let text = labels.join(".");
        assert_eq!(
            ip_from_reverse(&name(&text)),
            Some(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)))
        );
    }

    #[test]
    fn ptr_eligible_covers_rfc1918_ula_loopback_and_extra() {
        assert!(ptr_eligible(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &[]));
        assert!(ptr_eligible(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), &[]));
        assert!(ptr_eligible(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), &[]));
        assert!(!ptr_eligible(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), &[]));
        let doc = [IpNet::from_str("192.0.2.0/24").unwrap()];
        assert!(ptr_eligible(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), &doc));
        assert!(ptr_eligible(
            IpAddr::V6(Ipv6Addr::new(0xfd12, 0, 0, 0, 0, 0, 0, 1)),
            &[]
        ));
        assert!(ptr_eligible(IpAddr::V6(Ipv6Addr::LOCALHOST), &[]));
        assert!(!ptr_eligible(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            &[]
        ));
    }
}
