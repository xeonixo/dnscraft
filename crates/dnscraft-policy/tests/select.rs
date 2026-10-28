//! View selection table tests and a simple timing check.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use dnscraft_filtering::SetId;
use dnscraft_policy::{
    ClientFlags, ClientId, DnsProtocol, ListenerId, NodeId, PolicyConfig, PolicySnapshot,
    ProfileConfig, ProfileId, RequestContext, SafeSearchConfig, SelectionCause, ViewConfig, ViewId,
};
use dnscraft_proto::{Class, Name, RecordType};
use dnscraft_resolver::Query;
use ipnet::IpNet;

fn set(id: &str) -> SetId {
    SetId::new(id).unwrap()
}

fn profile(id: &str) -> ProfileConfig {
    ProfileConfig {
        id: ProfileId::new(id).unwrap(),
        filter_set: set("default"),
        suppress_aaaa: false,
        firefox_canary: false,
        icloud_private_relay: false,
        rebind: None,
        rebind_exceptions: Vec::new(),
        forward_zones: None,
        safesearch: SafeSearchConfig::default(),
        schedules: Vec::new(),
    }
}

fn view(
    id: &str,
    is_default: bool,
    subnets: Vec<IpNet>,
    nodes: Vec<&str>,
    profile: &str,
) -> ViewConfig {
    ViewConfig {
        id: ViewId::new(id).unwrap(),
        is_default,
        subnets,
        nodes: nodes.into_iter().map(|n| NodeId::new(n).unwrap()).collect(),
        profile: ProfileId::new(profile).unwrap(),
    }
}

fn net4(a: u8, b: u8, c: u8, d: u8, len: u8) -> IpNet {
    IpNet::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), len).unwrap()
}

fn net6(addr: Ipv6Addr, len: u8) -> IpNet {
    IpNet::new(IpAddr::V6(addr), len).unwrap()
}

fn ctx(source: IpAddr, client_id: Option<&str>) -> RequestContext {
    ctx_on(source, None, client_id)
}

fn ctx_on(source: IpAddr, node: Option<&str>, client_id: Option<&str>) -> RequestContext {
    RequestContext {
        source_ip: source,
        protocol: DnsProtocol::Udp53,
        listener_id: ListenerId::new("udp-53").unwrap(),
        node_id: node.map(|n| NodeId::new(n).unwrap()),
        client_id: client_id.map(|c| ClientId::new(c).unwrap()),
        query: Query {
            name: Name::from_ascii("example.com").unwrap(),
            qtype: RecordType::A,
            qclass: Class::IN,
        },
        flags: ClientFlags::default(),
        test_query: false,
    }
}

/// LAN /24 + /32 guest host, kids /28, IPv6 /48 + /64, plus default.
fn table_snapshot() -> PolicySnapshot {
    let cfg = PolicyConfig {
        client_ids: vec![ClientId::new("iphone-k7q2x9").unwrap()],
        records: Vec::new(),
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views: vec![
            view(
                "lan",
                false,
                vec![net4(192, 0, 2, 0, 24)],
                vec![],
                "default",
            ),
            view(
                "guest-host",
                false,
                vec![net4(192, 0, 2, 50, 32)],
                vec![],
                "default",
            ),
            view("kids", false, vec![net4(192, 0, 2, 64, 28)], vec![], "kids"),
            view(
                "v6-site",
                false,
                vec![net6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 48)],
                vec![],
                "default",
            ),
            view(
                "v6-lan",
                false,
                vec![net6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 64)],
                vec![],
                "default",
            ),
            view("default", true, vec![], vec![], "default"),
        ],
        profiles: vec![profile("default"), profile("kids")],
    };
    PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap()
}

#[test]
fn select_registered_client_id_never_changes_selection() {
    let snap = table_snapshot();
    // Source is the /32 guest host; a registered Client ID must not move it to lan.
    let with_id = snap.select(&ctx(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
        Some("iphone-k7q2x9"),
    ));
    let without_id = snap.select(&ctx(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)), None));
    assert_eq!(with_id.view_id.as_str(), "guest-host");
    assert_eq!(with_id, without_id);
}

#[test]
fn select_view_not_valid_on_node_is_absent() {
    let cfg = PolicyConfig {
        client_ids: Vec::new(),
        records: Vec::new(),
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views: vec![
            view(
                "lan",
                false,
                vec![net4(192, 0, 2, 0, 24)],
                vec!["node-1"],
                "default",
            ),
            view(
                "guest-host",
                false,
                vec![net4(192, 0, 2, 50, 32)],
                vec!["node-2"],
                "default",
            ),
            view("default", true, vec![], vec![], "default"),
        ],
        profiles: vec![profile("default")],
    };
    let snap = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap();
    let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
    // The /32 view exists only on node-2: on node-1 the /24 view wins.
    let on_node_1 = snap.select(&ctx_on(source, Some("node-1"), None));
    assert_eq!(on_node_1.view_id.as_str(), "lan");
    let on_node_2 = snap.select(&ctx_on(source, Some("node-2"), None));
    assert_eq!(on_node_2.view_id.as_str(), "guest-host");
    // Node-restricted views never match a request without a node id.
    let no_node = snap.select(&ctx_on(source, None, None));
    assert_eq!(no_node.view_id.as_str(), "default");
    let outside = snap.select(&ctx_on(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        None,
        None,
    ));
    assert_eq!(outside.view_id.as_str(), "default");
}

#[test]
fn select_slash28_beats_slash24() {
    let snap = table_snapshot();
    let sel = snap.select(&ctx(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 70)), None));
    assert_eq!(sel.view_id.as_str(), "kids");
    assert_eq!(
        sel.matched_by,
        SelectionCause::Subnet {
            network: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 64)),
            prefix_len: 28,
        }
    );
    assert_eq!(sel.profile_id.as_str(), "kids");
}

#[test]
fn select_slash24_when_outside_slash28() {
    let snap = table_snapshot();
    let sel = snap.select(&ctx(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), None));
    assert_eq!(sel.view_id.as_str(), "lan");
    assert_eq!(
        sel.matched_by,
        SelectionCause::Subnet {
            network: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
            prefix_len: 24,
        }
    );
}

#[test]
fn select_slash32_exact_host() {
    let snap = table_snapshot();
    let sel = snap.select(&ctx(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)), None));
    assert_eq!(sel.view_id.as_str(), "guest-host");
    assert_eq!(
        sel.matched_by,
        SelectionCause::Subnet {
            network: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
            prefix_len: 32,
        }
    );
}

#[test]
fn select_ipv6_slash64_beats_slash48() {
    let snap = table_snapshot();
    let sel = snap.select(&ctx(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1)),
        None,
    ));
    assert_eq!(sel.view_id.as_str(), "v6-lan");
    assert_eq!(
        sel.matched_by,
        SelectionCause::Subnet {
            network: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0)),
            prefix_len: 64,
        }
    );
}

#[test]
fn select_ipv6_slash48_when_outside_slash64() {
    let snap = table_snapshot();
    // 2001:db8:0:1::1 is under the /48 site, not under the /64 lan (2001:db8:1::/64).
    let sel = snap.select(&ctx(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1)),
        None,
    ));
    assert_eq!(sel.view_id.as_str(), "v6-site");
    assert_eq!(
        sel.matched_by,
        SelectionCause::Subnet {
            network: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            prefix_len: 48,
        }
    );
}

#[test]
fn select_unlisted_client_id_falls_through_to_subnet() {
    let snap = table_snapshot();
    let sel = snap.select(&ctx(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        Some("unknown-client"),
    ));
    assert_eq!(sel.view_id.as_str(), "lan");
    assert!(matches!(sel.matched_by, SelectionCause::Subnet { .. }));
}

#[test]
fn select_nothing_matches_default() {
    let snap = table_snapshot();
    let sel = snap.select(&ctx(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), None));
    assert_eq!(sel.view_id.as_str(), "default");
    assert_eq!(sel.matched_by, SelectionCause::Default);
}

#[test]
fn select_ipv4_mapped_ipv6_uses_v4_view() {
    let snap = table_snapshot();
    // ::ffff:192.0.2.10 → lan /24
    let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x020a));
    let sel = snap.select(&ctx(mapped, None));
    assert_eq!(sel.view_id.as_str(), "lan");
    assert_eq!(
        sel.matched_by,
        SelectionCause::Subnet {
            network: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
            prefix_len: 24,
        }
    );
}

#[test]
fn select_p50_under_1us_with_100_views() {
    let mut views = Vec::with_capacity(101);
    for i in 0..100u8 {
        views.push(view(
            &format!("v{i}"),
            false,
            vec![net4(198, 51, 100, i, 32)],
            vec![],
            "default",
        ));
    }
    views.push(view("default", true, vec![], vec![], "default"));
    let cfg = PolicyConfig {
        client_ids: Vec::new(),
        records: Vec::new(),
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views,
        profiles: vec![profile("default")],
    };
    let snap = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap();
    let req = ctx(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)), None);

    // Warm-up.
    for _ in 0..1_000 {
        black_box(snap.select(&req));
    }

    const N: u32 = 50_000;
    let start = Instant::now();
    for _ in 0..N {
        black_box(snap.select(&req));
    }
    let avg = start.elapsed() / N;
    // Budget is for release; debug builds are several times slower.
    let limit = if cfg!(debug_assertions) {
        Duration::from_micros(20)
    } else {
        Duration::from_micros(1)
    };
    assert!(
        avg < limit,
        "select average {avg:?} (≥ {limit:?}) with 100 views"
    );
    let sel = snap.select(&req);
    assert_eq!(sel.view_id.as_str(), "v42");
}
