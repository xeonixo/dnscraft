//! Admission: source class, matrix, rate/ban clock, LRU flood.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use dnscraft_listeners::{
    Admission, AdmitDecision, ClientIdState, Clock, Exposure, Limits, ListenerConfig, ManualClock,
    Protocol, PublicConfig, SourceClass, StrikeReason, TokenRate,
};
use dnscraft_policy::{ClientId, ListenerId};

fn listener(protocol: Protocol, exposure: Exposure) -> ListenerConfig {
    ListenerConfig {
        node_id: None,
        id: ListenerId::new("test").unwrap(),
        protocol,
        address: "127.0.0.1:53".parse().unwrap(),
        exposure,
        h3: false,
        tls_policy: None,
    }
}

fn limits(rate_src: u32, rate_cid: u32) -> Limits {
    Limits {
        rate_per_source: TokenRate {
            per_second: rate_src,
            burst: rate_src.saturating_mul(2),
        },
        rate_per_client_id: TokenRate {
            per_second: rate_cid,
            burst: rate_cid.saturating_mul(2),
        },
        ..Limits::default()
    }
}

fn public_cfg(cap: u32, strikes: u32, window: Duration, duration: Duration) -> PublicConfig {
    PublicConfig {
        enabled: true,
        ban_strikes: strikes,
        ban_window: window,
        ban_duration: duration,
        max_tracked_sources: cap,
    }
}

fn cid(s: &str) -> ClientId {
    ClientId::new(s).unwrap()
}

fn registered(s: &str) -> ClientIdState {
    ClientIdState::Registered(cid(s))
}

#[test]
fn source_class_table() {
    // RFC 1918
    assert_eq!(
        SourceClass::of(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        SourceClass::Private
    );
    assert_eq!(
        SourceClass::of(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))),
        SourceClass::Private
    );
    assert_eq!(
        SourceClass::of(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        SourceClass::Private
    );
    // Loopback / link-local / CGNAT
    assert_eq!(
        SourceClass::of(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        SourceClass::Private
    );
    assert_eq!(
        SourceClass::of(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))),
        SourceClass::Private
    );
    assert_eq!(
        SourceClass::of(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
        SourceClass::Private
    );
    assert_eq!(
        SourceClass::of(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254))),
        SourceClass::Private
    );
    // ULA / loopback / link-local IPv6
    assert_eq!(
        SourceClass::of(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))),
        SourceClass::Private
    );
    assert_eq!(
        SourceClass::of(IpAddr::V6(Ipv6Addr::new(0xfd12, 0, 0, 0, 0, 0, 0, 1))),
        SourceClass::Private
    );
    assert_eq!(
        SourceClass::of(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        SourceClass::Private
    );
    assert_eq!(
        SourceClass::of(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))),
        SourceClass::Private
    );
    // IPv4-mapped private
    let mapped_priv = IpAddr::V6(Ipv4Addr::new(192, 168, 0, 2).to_ipv6_mapped());
    assert_eq!(SourceClass::of(mapped_priv), SourceClass::Private);
    let mapped_cgnat = IpAddr::V6(Ipv4Addr::new(100, 64, 1, 2).to_ipv6_mapped());
    assert_eq!(SourceClass::of(mapped_cgnat), SourceClass::Private);

    // Documentation / public examples (must be public)
    assert_eq!(
        SourceClass::of(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        SourceClass::Public
    );
    assert_eq!(
        SourceClass::of(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
        SourceClass::Public
    );
    assert_eq!(
        SourceClass::of(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
        SourceClass::Public
    );
    assert_eq!(
        SourceClass::of(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        SourceClass::Public
    );
    assert_eq!(
        SourceClass::of(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        SourceClass::Public
    );
    assert_eq!(
        SourceClass::of(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))),
        SourceClass::Public
    );
    let mapped_doc = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped());
    assert_eq!(SourceClass::of(mapped_doc), SourceClass::Public);
    // CGNAT boundary just outside /10
    assert_eq!(
        SourceClass::of(IpAddr::V4(Ipv4Addr::new(100, 63, 255, 255))),
        SourceClass::Public
    );
    assert_eq!(
        SourceClass::of(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 0))),
        SourceClass::Public
    );
}

#[test]
fn admission_matrix() {
    let clock = ManualClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(1_000));
    let now = clock.now();
    // High rates so matrix cases are not rate-limited.
    let mut adm = Admission::new(
        &limits(10_000, 10_000),
        &public_cfg(1_000, 5, Duration::from_secs(60), Duration::from_secs(900)),
    );

    let priv_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10));
    let pub_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let abs = ClientIdState::Absent;
    let unk = ClientIdState::Unknown;
    let reg = registered("alice");

    // Do53 public source → Drop (any exposure)
    for exposure in [Exposure::Local, Exposure::Public] {
        for proto in [Protocol::Udp53, Protocol::Tcp53] {
            let l = listener(proto, exposure);
            assert_eq!(
                adm.check(&l, pub_ip, &reg, now),
                AdmitDecision::Drop {
                    code: "listeners.admission.public_do53"
                },
                "{proto:?} {exposure:?}"
            );
        }
    }

    // Do53 private source → Admit (Client ID optional / ignored)
    for proto in [Protocol::Udp53, Protocol::Tcp53] {
        let l = listener(proto, Exposure::Local);
        assert_eq!(adm.check(&l, priv_ip, &abs, now), AdmitDecision::Admit);
        assert_eq!(adm.check(&l, priv_ip, &unk, now), AdmitDecision::Admit);
        assert_eq!(adm.check(&l, priv_ip, &reg, now), AdmitDecision::Admit);
    }

    // Encrypted local + private: Admit regardless of Client ID
    for proto in [Protocol::Dot, Protocol::Doh, Protocol::Doq] {
        let l = listener(proto, Exposure::Local);
        assert_eq!(adm.check(&l, priv_ip, &abs, now), AdmitDecision::Admit);
        assert_eq!(adm.check(&l, priv_ip, &unk, now), AdmitDecision::Admit);
        assert_eq!(adm.check(&l, priv_ip, &reg, now), AdmitDecision::Admit);
    }

    // Encrypted local + public: Client ID not required (not a public listener)
    for proto in [Protocol::Dot, Protocol::Doh, Protocol::Doq] {
        let l = listener(proto, Exposure::Local);
        assert_eq!(adm.check(&l, pub_ip, &abs, now), AdmitDecision::Admit);
        assert_eq!(adm.check(&l, pub_ip, &unk, now), AdmitDecision::Admit);
        assert_eq!(adm.check(&l, pub_ip, &reg, now), AdmitDecision::Admit);
    }

    // Encrypted public + private: Client ID optional
    for proto in [Protocol::Dot, Protocol::Doh, Protocol::Doq] {
        let l = listener(proto, Exposure::Public);
        assert_eq!(adm.check(&l, priv_ip, &abs, now), AdmitDecision::Admit);
        assert_eq!(adm.check(&l, priv_ip, &unk, now), AdmitDecision::Admit);
        assert_eq!(adm.check(&l, priv_ip, &reg, now), AdmitDecision::Admit);
    }

    // Encrypted public + public: registered only
    for proto in [Protocol::Dot, Protocol::Doh, Protocol::Doq] {
        let l = listener(proto, Exposure::Public);
        assert_eq!(
            adm.check(&l, pub_ip, &abs, now),
            AdmitDecision::Refuse {
                code: "listeners.admission.unknown_client_id"
            }
        );
        assert_eq!(
            adm.check(&l, pub_ip, &unk, now),
            AdmitDecision::Refuse {
                code: "listeners.admission.unknown_client_id"
            }
        );
        assert_eq!(adm.check(&l, pub_ip, &reg, now), AdmitDecision::Admit);
    }
}

#[test]
fn rate_and_ban_with_manual_clock() {
    let clock = ManualClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(5_000));
    let mut adm = Admission::new(
        &limits(2, 2), // burst 4
        &public_cfg(100, 3, Duration::from_secs(10), Duration::from_secs(30)),
    );
    let l_udp = listener(Protocol::Udp53, Exposure::Local);
    let l_dot = listener(Protocol::Dot, Exposure::Public);
    let priv_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let reg = registered("bob");

    // Burst then rate-limit (UDP → Drop)
    for _ in 0..4 {
        assert_eq!(
            adm.check(&l_udp, priv_ip, &ClientIdState::Absent, clock.now()),
            AdmitDecision::Admit
        );
    }
    assert_eq!(
        adm.check(&l_udp, priv_ip, &ClientIdState::Absent, clock.now()),
        AdmitDecision::Drop {
            code: "listeners.rate_limited"
        }
    );

    // Refill ~2 tokens/s → after 1s can take 2 more
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        adm.check(&l_udp, priv_ip, &ClientIdState::Absent, clock.now()),
        AdmitDecision::Admit
    );
    assert_eq!(
        adm.check(&l_udp, priv_ip, &ClientIdState::Absent, clock.now()),
        AdmitDecision::Admit
    );
    assert_eq!(
        adm.check(&l_udp, priv_ip, &ClientIdState::Absent, clock.now()),
        AdmitDecision::Drop {
            code: "listeners.rate_limited"
        }
    );

    // TCP/DoT rate limit → Refuse
    let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    for _ in 0..4 {
        assert_eq!(
            adm.check(&l_dot, other, &ClientIdState::Absent, clock.now()),
            AdmitDecision::Admit
        );
    }
    assert_eq!(
        adm.check(&l_dot, other, &ClientIdState::Absent, clock.now()),
        AdmitDecision::Refuse {
            code: "listeners.rate_limited"
        }
    );

    // Per-Client-ID limit on public source (fresh source IP, same Client ID)
    clock.advance(Duration::from_secs(60)); // clear source buckets via time + new IPs
    let pub_a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let pub_b = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
    for _ in 0..4 {
        assert_eq!(
            adm.check(&l_dot, pub_a, &reg, clock.now()),
            AdmitDecision::Admit
        );
    }
    // Same Client ID from another public source still limited
    assert_eq!(
        adm.check(&l_dot, pub_b, &reg, clock.now()),
        AdmitDecision::Refuse {
            code: "listeners.rate_limited"
        }
    );

    // Ban after N strikes
    clock.advance(Duration::from_secs(60));
    let ban_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
    for _ in 0..3 {
        adm.strike(ban_ip, StrikeReason::UnknownClientId, clock.now());
    }
    assert_eq!(
        adm.check(&l_dot, ban_ip, &reg, clock.now()),
        AdmitDecision::Drop {
            code: "listeners.banned"
        }
    );
    // Private strike is a no-op
    let priv2 = IpAddr::V4(Ipv4Addr::new(192, 168, 9, 9));
    for _ in 0..10 {
        adm.strike(priv2, StrikeReason::TlsHandshake, clock.now());
    }
    assert_eq!(
        adm.check(&l_udp, priv2, &ClientIdState::Absent, clock.now()),
        AdmitDecision::Admit
    );

    // Ban expiry
    clock.advance(Duration::from_secs(30));
    assert_eq!(
        adm.check(&l_dot, ban_ip, &reg, clock.now()),
        AdmitDecision::Admit
    );

    // Strike window expiry: 2 strikes, wait past window, 2 more → not banned (need 3)
    let win_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 60));
    adm.strike(win_ip, StrikeReason::MalformedFraming, clock.now());
    adm.strike(win_ip, StrikeReason::MalformedFraming, clock.now());
    clock.advance(Duration::from_secs(11)); // past ban_window of 10s
    adm.strike(win_ip, StrikeReason::MalformedFraming, clock.now());
    adm.strike(win_ip, StrikeReason::MalformedFraming, clock.now());
    assert_eq!(
        adm.check(&l_dot, win_ip, &reg, clock.now()),
        AdmitDecision::Admit
    );
    // One more completes a fresh window of 3
    adm.strike(win_ip, StrikeReason::MalformedFraming, clock.now());
    assert_eq!(
        adm.check(&l_dot, win_ip, &reg, clock.now()),
        AdmitDecision::Drop {
            code: "listeners.banned"
        }
    );
}

#[test]
fn flood_keeps_tables_at_cap() {
    const CAP: u32 = 64;
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(9_000);
    let mut adm = Admission::new(
        &limits(1_000, 1_000),
        &public_cfg(CAP, 5, Duration::from_secs(60), Duration::from_secs(60)),
    );
    let l = listener(Protocol::Dot, Exposure::Public);
    let reg = registered("flood");

    let n = (CAP as usize) * 10;
    for i in 0..n {
        let ip = IpAddr::V4(Ipv4Addr::from(0xC000_0200u32.wrapping_add(i as u32))); // 192.0.2.0+
        let _ = adm.check(&l, ip, &reg, now);
        adm.strike(ip, StrikeReason::UnknownClientId, now);
    }

    assert_eq!(adm.source_bucket_count(), CAP as usize);
    assert_eq!(adm.ban_entry_count(), CAP as usize);
    // Client-ID map stays at 1 (same id)
    assert_eq!(adm.client_bucket_count(), 1);
}
