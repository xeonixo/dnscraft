//! Manual-only [`ClientLookup`] acceptance tests (C3).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dnscraft_clients::{ClientLookup, ClientSource, IpNet, ManualEntry};

fn ip(s: &str) -> IpAddr {
    IpAddr::from_str(s).unwrap()
}

fn entry_ip(name: &str, addr: &str) -> ManualEntry {
    ManualEntry {
        name: name.into(),
        ip: Some(ip(addr)),
        cidr: None,
        domain: None,
    }
}

fn entry_cidr(name: &str, cidr: &str) -> ManualEntry {
    ManualEntry {
        name: name.into(),
        ip: None,
        cidr: Some(IpNet::from_str(cidr).unwrap()),
        domain: None,
    }
}

fn entry_ip_domain(name: &str, addr: &str, domain: &str) -> ManualEntry {
    ManualEntry {
        name: name.into(),
        ip: Some(ip(addr)),
        cidr: None,
        domain: Some(domain.into()),
    }
}

#[test]
fn precedence_exact_over_longer_over_shorter_ipv4() {
    let lookup = ClientLookup::build_manual(
        &[
            entry_ip("exact", "198.51.100.10"),
            entry_cidr("slash28", "198.51.100.0/28"),
            entry_cidr("slash24", "198.51.100.0/24"),
        ],
        "home.arpa",
    )
    .unwrap();

    let exact = lookup.by_ip(ip("198.51.100.10")).unwrap();
    assert_eq!(exact.display_name, "exact");

    // In /28 but not the exact host entry.
    let in28 = lookup.by_ip(ip("198.51.100.5")).unwrap();
    assert_eq!(in28.display_name, "slash28");

    // In /24 but outside /28 (198.51.100.0/28 is .0–.15).
    let in24 = lookup.by_ip(ip("198.51.100.50")).unwrap();
    assert_eq!(in24.display_name, "slash24");

    assert!(lookup.by_ip(ip("203.0.113.1")).is_none());
}

#[test]
fn precedence_ipv6() {
    let lookup = ClientLookup::build_manual(
        &[
            entry_ip("v6-exact", "2001:db8::10"),
            entry_cidr("v6-64", "2001:db8::/64"),
            entry_cidr("v6-48", "2001:db8::/48"),
        ],
        "home.arpa",
    )
    .unwrap();

    assert_eq!(
        lookup.by_ip(ip("2001:db8::10")).unwrap().display_name,
        "v6-exact"
    );
    assert_eq!(
        lookup.by_ip(ip("2001:db8::20")).unwrap().display_name,
        "v6-64"
    );
    // 2001:db8:0:1::1 is outside /64 of 2001:db8::/64 (subnet id 0) but in /48.
    assert_eq!(
        lookup.by_ip(ip("2001:db8:0:1::1")).unwrap().display_name,
        "v6-48"
    );
    assert!(lookup.by_ip(ip("2001:db8:1::1")).is_none());
}

#[test]
fn reverse_follows_by_ip_winner() {
    let lookup = ClientLookup::build_manual(
        &[
            entry_ip("exact", "198.51.100.10"),
            entry_cidr("slash24", "198.51.100.0/24"),
        ],
        "home.arpa",
    )
    .unwrap();
    assert_eq!(
        lookup.reverse(ip("198.51.100.10")).as_deref(),
        Some("exact.home.arpa")
    );
    assert_eq!(
        lookup.reverse(ip("198.51.100.99")).as_deref(),
        Some("slash24.home.arpa")
    );
    assert!(lookup.reverse(ip("203.0.113.1")).is_none());
}

#[test]
fn by_name_fqdn_case_and_trailing_dot() {
    let lookup =
        ClientLookup::build_manual(&[entry_ip("Paperless", "198.51.100.5")], "Home.ARPA.").unwrap();
    let a = lookup.by_name("paperless.home.arpa").unwrap();
    let b = lookup.by_name("Paperless.Home.ARPA.").unwrap();
    assert!(Arc::ptr_eq(&a, &b));
    assert_eq!(a.dns_label, "paperless");
    assert!(lookup.by_name("unknown.home.arpa").is_none());
}

#[test]
fn bare_label_unique_vs_ambiguous() {
    let unique = ClientLookup::build_manual(
        &[
            entry_ip("phone", "198.51.100.1"),
            entry_ip("laptop", "198.51.100.2"),
        ],
        "home.arpa",
    )
    .unwrap();
    assert_eq!(unique.by_name("phone").unwrap().display_name, "phone");

    let ambiguous = ClientLookup::build_manual(
        &[
            entry_ip("phone", "198.51.100.1"),
            entry_ip_domain("phone", "198.51.100.2", "iot.example.com"),
        ],
        "home.arpa",
    )
    .unwrap();
    // Same label under two domains → bare label ambiguous.
    assert!(ambiguous.by_name("phone").is_none());
    assert!(ambiguous.by_name("phone.home.arpa").is_some());
    assert!(ambiguous.by_name("phone.iot.example.com").is_some());
}

#[test]
fn label_collision_first_seen_gets_plain_second_suffixed() {
    let lookup = ClientLookup::build_manual(
        &[
            entry_ip("Docker on server1", "198.51.100.1"),
            entry_ip("docker-on-server1", "198.51.100.2"),
        ],
        "home.arpa",
    )
    .unwrap();
    let first = lookup.by_ip(ip("198.51.100.1")).unwrap();
    let second = lookup.by_ip(ip("198.51.100.2")).unwrap();
    assert_eq!(first.dns_label, "docker-on-server1");
    assert_ne!(second.dns_label, first.dns_label);
    assert!(second.dns_label.starts_with("docker-on-server1-"));
    assert!(lookup.by_name("docker-on-server1.home.arpa").is_some());
    assert!(
        lookup
            .by_name(&format!("{}.home.arpa", second.dns_label))
            .is_some()
    );
}

#[test]
fn local_domains_includes_overrides() {
    let lookup = ClientLookup::build_manual(
        &[
            entry_ip("a", "198.51.100.1"),
            entry_ip_domain("b", "198.51.100.2", "IoT.Example.COM."),
        ],
        "home.arpa",
    )
    .unwrap();
    let domains = lookup.local_domains();
    assert!(domains.iter().any(|d| d == "home.arpa"));
    assert!(domains.iter().any(|d| d == "iot.example.com"));
}

#[test]
fn by_ip_returns_arc_clone_not_deep_copy() {
    let lookup =
        ClientLookup::build_manual(&[entry_ip("paperless", "198.51.100.5")], "home.arpa").unwrap();
    let a = lookup.by_ip(ip("198.51.100.5")).unwrap();
    let b = lookup.by_ip(ip("198.51.100.5")).unwrap();
    assert!(Arc::ptr_eq(&a, &b));
    assert_eq!(a.source, ClientSource::Manual);
    assert_eq!(a.addresses.as_ref(), &[ip("198.51.100.5")]);
}

/// Criterion: 1 000 manuals, `by_ip` p50-ish average &lt; 1 µs (release).
///
/// Debug builds use a looser 20 µs budget (same pattern as policy P2). The
/// measured average is printed so regressions are visible in CI logs.
#[test]
fn by_ip_thousand_manuals_is_fast() {
    let mut manuals = Vec::with_capacity(1000);
    for i in 0..1000u32 {
        let a = ((i >> 8) & 0xff) as u8;
        let b = (i & 0xff) as u8;
        manuals.push(ManualEntry {
            name: format!("host-{i}"),
            ip: Some(IpAddr::from([10, 0, a, b])),
            cidr: None,
            domain: None,
        });
    }
    // Mix in a few CIDRs so the scan path is warm but exact hits dominate.
    manuals.push(entry_cidr("bulk", "10.1.0.0/16"));

    let lookup = ClientLookup::build_manual(&manuals, "home.arpa").unwrap();
    assert_eq!(lookup.len(), 1001);

    let target = ip("10.0.1.2"); // exact hit near the start of the map
    let iters = 50_000u32;
    // Warm-up.
    for _ in 0..1000 {
        std::hint::black_box(lookup.by_ip(target));
    }
    let start = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(lookup.by_ip(target));
    }
    let avg = start.elapsed() / iters;
    eprintln!("by_ip avg over {iters} lookups (1000 manuals): {avg:?}");

    let budget = if cfg!(debug_assertions) {
        Duration::from_micros(20)
    } else {
        Duration::from_micros(1)
    };
    assert!(
        avg < budget,
        "by_ip avg {avg:?} exceeds budget {budget:?} (debug=20µs, release=1µs)"
    );
    assert!(lookup.by_ip(target).is_some());
}
