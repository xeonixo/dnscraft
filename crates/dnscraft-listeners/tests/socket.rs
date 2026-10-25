//! Socket helpers: dual-stack wildcards side by side; IPv6 is V6ONLY.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use dnscraft_listeners::{bind_tcp, bind_udp};
use socket2::SockRef;

#[test]
fn socket_udp_v4_and_v6_wildcard_bind_side_by_side() {
    let v4 = bind_udp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).unwrap();
    let port = v4.local_addr().unwrap().port();
    let v6 = bind_udp(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))).unwrap();

    assert_eq!(v6.local_addr().unwrap().port(), port);
    assert!(
        SockRef::from(&v6).only_v6().unwrap(),
        "IPv6 UDP socket must be IPV6_V6ONLY"
    );
    // Keep both alive until end of test.
    drop(v4);
    drop(v6);
}

#[test]
fn socket_tcp_v4_and_v6_wildcard_bind_side_by_side() {
    let v4 = bind_tcp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).unwrap();
    let port = v4.local_addr().unwrap().port();
    let v6 = bind_tcp(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))).unwrap();

    assert_eq!(v6.local_addr().unwrap().port(), port);
    assert!(
        SockRef::from(&v6).only_v6().unwrap(),
        "IPv6 TCP socket must be IPV6_V6ONLY"
    );
    drop(v4);
    drop(v6);
}

#[test]
fn socket_ipv6_loopback_reports_only_v6() {
    let sock = bind_udp(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))).unwrap();
    assert!(SockRef::from(&sock).only_v6().unwrap());
}
