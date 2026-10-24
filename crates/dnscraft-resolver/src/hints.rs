//! Built-in IANA root hints (root servers a through m).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const V4: [[u8; 4]; 13] = [
    [198, 41, 0, 4],
    [170, 247, 170, 2],
    [192, 33, 4, 12],
    [199, 7, 91, 13],
    [192, 203, 230, 10],
    [192, 5, 5, 241],
    [192, 112, 36, 4],
    [198, 97, 190, 53],
    [192, 36, 148, 17],
    [192, 58, 128, 30],
    [193, 0, 14, 129],
    [199, 7, 83, 42],
    [202, 12, 27, 33],
];

const V6: [[u16; 8]; 13] = [
    [0x2001, 0x503, 0xba3e, 0, 0, 0, 0x2, 0x30],
    [0x2801, 0x1b8, 0x10, 0, 0, 0, 0, 0xb],
    [0x2001, 0x500, 0x2, 0, 0, 0, 0, 0xc],
    [0x2001, 0x500, 0x2d, 0, 0, 0, 0, 0xd],
    [0x2001, 0x500, 0xa8, 0, 0, 0, 0, 0xe],
    [0x2001, 0x500, 0x2f, 0, 0, 0, 0, 0xf],
    [0x2001, 0x500, 0x12, 0, 0, 0, 0, 0xd0d],
    [0x2001, 0x500, 0x1, 0, 0, 0, 0, 0x53],
    [0x2001, 0x7fe, 0, 0, 0, 0, 0, 0x53],
    [0x2001, 0x503, 0xc27, 0, 0, 0, 0x2, 0x30],
    [0x2001, 0x7fd, 0, 0, 0, 0, 0, 0x1],
    [0x2001, 0x500, 0x9f, 0, 0, 0, 0, 0x42],
    [0x2001, 0xdc3, 0, 0, 0, 0, 0, 0x35],
];

/// The IANA root server addresses (IPv4 first, then IPv6) on port 53.
pub fn default_root_hints() -> Vec<SocketAddr> {
    let v4 = V4
        .iter()
        .map(|o| IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])));
    let v6 = V6.iter().map(|s| {
        IpAddr::V6(Ipv6Addr::new(
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ))
    });
    v4.chain(v6).map(|ip| SocketAddr::new(ip, 53)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_26_addresses() {
        let hints = default_root_hints();
        assert_eq!(hints.len(), 26);
        assert!(hints.iter().all(|a| a.port() == 53));
    }
}
