//! Pure UniFi merge acceptance tests (C5).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use dnscraft_clients::{
    ClientId, ClientSource, ClientsConfig, DEFAULT_IPV6_ADDRESS_TTL, DEFAULT_LOCAL_DOMAIN,
    DEFAULT_OFFLINE_RETAIN, IpNet, LocalDomainMode, ManualEntry, NetworkInfo, State,
    UnifiObservation, build,
};

fn ip(s: &str) -> IpAddr {
    IpAddr::from_str(s).unwrap()
}

fn id(s: &str) -> ClientId {
    ClientId::new(s).unwrap()
}

fn cfg() -> ClientsConfig {
    ClientsConfig {
        local_domain: DEFAULT_LOCAL_DOMAIN.into(),
        local_domain_mode: LocalDomainMode::UnifiThenConfig,
        offline_retain: DEFAULT_OFFLINE_RETAIN,
        ipv6_address_ttl: DEFAULT_IPV6_ADDRESS_TTL,
        ..ClientsConfig::default()
    }
}

fn obs(
    cid: &str,
    name: &str,
    addrs: &[&str],
    network_id: Option<&str>,
    last_seen: Option<SystemTime>,
    online: bool,
) -> UnifiObservation {
    UnifiObservation {
        id: id(cid),
        display_name: name.into(),
        macs: Vec::new(),
        addresses: addrs.iter().map(|a| ip(a)).collect(),
        network_id: network_id.map(str::to_owned),
        last_seen,
        online,
    }
}

fn net(nid: &str, name: &str, vlan: u16, v4: Option<&str>, domain: Option<&str>) -> NetworkInfo {
    NetworkInfo {
        id: nid.into(),
        name: name.into(),
        vlan_id: Some(vlan),
        ipv4_prefix: v4.map(|s| IpNet::from_str(s).unwrap()),
        ipv6_prefix: None,
        domain_name: domain.map(str::to_owned),
    }
}

fn manual_ip(name: &str, addr: &str) -> ManualEntry {
    ManualEntry {
        name: name.into(),
        ip: Some(ip(addr)),
        cidr: None,
        domain: None,
    }
}

#[test]
fn manual_beats_unifi_on_same_ip_and_fqdn() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let out = build(
        &[manual_ip("phone", "198.51.100.10")],
        &[obs(
            "u-phone",
            "phone",
            &["198.51.100.10"],
            None,
            Some(now),
            true,
        )],
        &[],
        &State::default(),
        &cfg(),
        now,
    )
    .unwrap();

    let c = out.lookup.by_ip(ip("198.51.100.10")).unwrap();
    assert_eq!(c.source, ClientSource::Manual);
    assert_eq!(c.dns_label, "phone");

    // UniFi client still present under a suffixed name.
    let unifi: Vec<_> = out
        .lookup
        .clients()
        .iter()
        .filter(|c| c.source == ClientSource::Unifi)
        .collect();
    assert_eq!(unifi.len(), 1);
    assert_ne!(unifi[0].dns_label, "phone");
    assert!(unifi[0].dns_label.starts_with("phone-"));
}

#[test]
fn first_seen_label_stable_against_smaller_newcomer_id() {
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    let mut state = State::default();

    let out1 = build(
        &[],
        &[obs(
            "id-zzzz",
            "Phone",
            &["198.51.100.1"],
            None,
            Some(t0),
            true,
        )],
        &[],
        &state,
        &cfg(),
        t0,
    )
    .unwrap();
    assert_eq!(
        out1.lookup.by_ip(ip("198.51.100.1")).unwrap().dns_label,
        "phone"
    );
    state = out1.state;

    // Newcomer with lexicographically smaller id and same normalised label.
    let t1 = t0 + Duration::from_secs(60);
    let out2 = build(
        &[],
        &[
            obs("id-zzzz", "Phone", &["198.51.100.1"], None, Some(t1), true),
            obs("id-aaaa", "Phone", &["198.51.100.2"], None, Some(t1), true),
        ],
        &[],
        &state,
        &cfg(),
        t1,
    )
    .unwrap();

    let a = out2.lookup.by_ip(ip("198.51.100.1")).unwrap();
    let b = out2.lookup.by_ip(ip("198.51.100.2")).unwrap();
    assert_eq!(a.dns_label, "phone", "existing keeps label");
    assert_ne!(b.dns_label, "phone");
    assert!(b.dns_label.starts_with("phone-"));
}

#[test]
fn ip_conflict_online_beats_retained_offline() {
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(5_000);
    let mut state = State::default();

    let out1 = build(
        &[],
        &[obs(
            "old",
            "OldPhone",
            &["198.51.100.5"],
            None,
            Some(t0),
            true,
        )],
        &[],
        &state,
        &cfg(),
        t0,
    )
    .unwrap();
    state = out1.state;

    // old disappears → retained; new claims same IP while online.
    let t1 = t0 + Duration::from_secs(120);
    let out2 = build(
        &[],
        &[obs(
            "new",
            "NewPhone",
            &["198.51.100.5"],
            None,
            Some(t1),
            true,
        )],
        &[],
        &state,
        &cfg(),
        t1,
    )
    .unwrap();

    let winner = out2.lookup.by_ip(ip("198.51.100.5")).unwrap();
    assert_eq!(winner.id.as_str(), "new");
    assert!(winner.online);
    assert!(out2.stats.ip_conflicts >= 1 || out2.lookup.clients().len() == 2);
    // Retained offline still in snapshot.
    assert!(
        out2.lookup
            .clients()
            .iter()
            .any(|c| c.id.as_str() == "old" && !c.online)
    );
}

#[test]
fn offline_retain_then_evict() {
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
    let mut cfg = cfg();
    cfg.offline_retain = Duration::from_secs(7 * 24 * 3600);

    let out1 = build(
        &[],
        &[obs("dev", "Dev", &["198.51.100.9"], None, Some(t0), true)],
        &[],
        &State::default(),
        &cfg,
        t0,
    )
    .unwrap();
    let state = out1.state;

    // Missing but within retain.
    let t1 = t0 + Duration::from_secs(3 * 24 * 3600);
    let out2 = build(&[], &[], &[], &state, &cfg, t1).unwrap();
    let c = out2.lookup.by_ip(ip("198.51.100.9")).unwrap();
    assert!(!c.online);
    assert_eq!(c.id.as_str(), "dev");

    // Past retain (measured from missing_since = t1) → gone.
    let t2 = t1 + Duration::from_secs(8 * 24 * 3600);
    let out3 = build(&[], &[], &[], &out2.state, &cfg, t2).unwrap();
    assert!(out3.lookup.by_ip(ip("198.51.100.9")).is_none());
}

#[test]
fn ipv6_ttl_and_link_local_skipped() {
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(20_000);
    let mut cfg = cfg();
    cfg.ipv6_address_ttl = Duration::from_secs(24 * 3600);

    let out1 = build(
        &[],
        &[obs(
            "multi",
            "Multi",
            &[
                "198.51.100.20",
                "2001:db8::1",
                "2001:db8::2",
                "2001:db8::3",
                "fe80::1",
            ],
            None,
            Some(t0),
            true,
        )],
        &[],
        &State::default(),
        &cfg,
        t0,
    )
    .unwrap();

    let c = out1.lookup.by_ip(ip("198.51.100.20")).unwrap();
    assert_eq!(c.addresses.len(), 4); // no fe80
    assert!(out1.lookup.by_ip(ip("fe80::1")).is_none());
    for a in ["2001:db8::1", "2001:db8::2", "2001:db8::3"] {
        assert_eq!(out1.lookup.by_ip(ip(a)).unwrap().id.as_str(), "multi");
        assert_eq!(
            out1.lookup.reverse(ip(a)).as_deref(),
            Some("multi.home.arpa")
        );
    }

    // Drop two GUA from observation; within TTL they remain.
    let t1 = t0 + Duration::from_secs(12 * 3600);
    let out2 = build(
        &[],
        &[obs(
            "multi",
            "Multi",
            &["198.51.100.20", "2001:db8::1"],
            None,
            Some(t1),
            true,
        )],
        &[],
        &out1.state,
        &cfg,
        t1,
    )
    .unwrap();
    assert!(out2.lookup.by_ip(ip("2001:db8::2")).is_some());
    assert!(out2.lookup.by_ip(ip("2001:db8::3")).is_some());

    // Past TTL → dropped.
    let t2 = t0 + Duration::from_secs(25 * 3600);
    let out3 = build(
        &[],
        &[obs(
            "multi",
            "Multi",
            &["198.51.100.20", "2001:db8::1"],
            None,
            Some(t2),
            true,
        )],
        &[],
        &out2.state,
        &cfg,
        t2,
    )
    .unwrap();
    assert!(out3.lookup.by_ip(ip("2001:db8::2")).is_none());
    assert!(out3.lookup.by_ip(ip("2001:db8::3")).is_none());
    assert!(out3.lookup.by_ip(ip("2001:db8::1")).is_some());
}

#[test]
fn vlan_join_and_domain_modes() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(30_000);
    let networks = [
        net(
            "n-iot",
            "IoT",
            40,
            Some("198.51.100.0/24"),
            Some("iot.example.com"),
        ),
        net(
            "n-lan",
            "LAN",
            1,
            Some("192.0.2.0/24"),
            Some("lan.example.com"),
        ),
    ];

    let out = build(
        &[],
        &[
            obs(
                "a",
                "Cam",
                &["198.51.100.8"],
                Some("n-iot"),
                Some(now),
                true,
            ),
            obs("b", "Pc", &["192.0.2.8"], Some("n-lan"), Some(now), true),
        ],
        &networks,
        &State::default(),
        &cfg(),
        now,
    )
    .unwrap();

    let cam = out.lookup.by_ip(ip("198.51.100.8")).unwrap();
    assert_eq!(cam.local_domain, "iot.example.com");
    assert_eq!(cam.vlan.as_ref().unwrap().display(), "IoT (40)");
    assert_eq!(
        out.lookup
            .by_name("cam.iot.example.com")
            .unwrap()
            .id
            .as_str(),
        "a"
    );

    let pc = out.lookup.by_ip(ip("192.0.2.8")).unwrap();
    assert_eq!(pc.local_domain, "lan.example.com");

    // Missing domain → config fallback.
    let out2 = build(
        &[],
        &[obs("c", "Orphan", &["203.0.113.5"], None, Some(now), true)],
        &[],
        &State::default(),
        &cfg(),
        now,
    )
    .unwrap();
    assert_eq!(
        out2.lookup.by_ip(ip("203.0.113.5")).unwrap().local_domain,
        "home.arpa"
    );

    // Mode config always uses local_domain.
    let mut forced = cfg();
    forced.local_domain_mode = LocalDomainMode::Config;
    let out3 = build(
        &[],
        &[obs(
            "a",
            "Cam",
            &["198.51.100.8"],
            Some("n-iot"),
            Some(now),
            true,
        )],
        &networks,
        &State::default(),
        &forced,
        now,
    )
    .unwrap();
    assert_eq!(
        out3.lookup.by_ip(ip("198.51.100.8")).unwrap().local_domain,
        "home.arpa"
    );
}

#[test]
fn vlan_longest_prefix_fallback() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(40_000);
    let networks = [net("n1", "Guests", 50, Some("198.51.100.0/24"), None)];
    let out = build(
        &[],
        &[obs(
            "g",
            "Guest",
            &["198.51.100.33"],
            None, // no network_id → LPM
            Some(now),
            true,
        )],
        &networks,
        &State::default(),
        &cfg(),
        now,
    )
    .unwrap();
    let c = out.lookup.by_ip(ip("198.51.100.33")).unwrap();
    assert_eq!(c.vlan.as_ref().unwrap().name, "Guests");
}

#[test]
fn manual_cidr_beats_unifi() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(50_000);
    let manuals = [ManualEntry {
        name: "docker".into(),
        ip: None,
        cidr: Some(IpNet::from_str("198.51.100.0/24").unwrap()),
        domain: None,
    }];
    let out = build(
        &manuals,
        &[obs(
            "u",
            "Container",
            &["198.51.100.50"],
            None,
            Some(now),
            true,
        )],
        &[],
        &State::default(),
        &cfg(),
        now,
    )
    .unwrap();
    assert_eq!(
        out.lookup.by_ip(ip("198.51.100.50")).unwrap().dns_label,
        "docker"
    );
}

#[test]
fn too_many_clients_hard_cap() {
    let now = SystemTime::UNIX_EPOCH;
    let mut obs_list = Vec::new();
    for i in 0..10_001 {
        obs_list.push(obs(
            &format!("id-{i}"),
            &format!("Host{i}"),
            &[],
            None,
            Some(now),
            true,
        ));
    }
    // Give each a unique IP so they aren't empty-address only — actually empty
    // addresses still count as clients.
    let err = build(&[], &obs_list, &[], &State::default(), &cfg(), now).unwrap_err();
    assert_eq!(err.code(), "clients.too_many");
}

#[test]
fn manual_ids_stable_across_reorder_and_restart() {
    // GC6: ids used to be `manual-{index}`, so reordering shifted every id and
    // could mis-attach persisted labels.
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(60_000);
    let phone = manual_ip("phone", "198.51.100.10");
    let printer = manual_ip("printer", "198.51.100.11");

    let out1 = build(
        &[phone.clone(), printer.clone()],
        &[],
        &[],
        &State::default(),
        &cfg(),
        now,
    )
    .unwrap();
    let phone_id = out1.lookup.by_name("phone.home.arpa").unwrap().id.clone();
    let printer_id = out1.lookup.by_name("printer.home.arpa").unwrap().id.clone();
    assert!(phone_id.as_str().starts_with("manual-"));
    assert_ne!(phone_id, printer_id);

    // Reverse order, same persisted state (simulated restart + reorder).
    let out2 = build(&[printer, phone], &[], &[], &out1.state, &cfg(), now).unwrap();
    assert_eq!(
        out2.lookup.by_name("phone.home.arpa").unwrap().id.as_str(),
        phone_id.as_str()
    );
    assert_eq!(
        out2.lookup
            .by_name("printer.home.arpa")
            .unwrap()
            .id
            .as_str(),
        printer_id.as_str()
    );
}

#[test]
fn manual_link_local_ip_is_not_indexed() {
    // GC13: link-local exclusion applies to manuals too.
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(70_000);
    let out = build(
        &[manual_ip("v6-manual", "fe80::1234")],
        &[],
        &[],
        &State::default(),
        &cfg(),
        now,
    )
    .unwrap();
    assert!(out.lookup.by_ip(ip("fe80::1234")).is_none());
    assert!(out.lookup.by_name("v6-manual.home.arpa").is_some());
}
