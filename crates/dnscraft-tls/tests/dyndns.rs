//! DynDNS: echo → compare → upsert (mock Cloudflare + mock echo).

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/mock_cloudflare.rs"]
mod mock_cloudflare;
#[path = "support/mock_echo.rs"]
mod mock_echo;

use std::path::PathBuf;
use std::time::Duration;

use dnscraft_tls::{
    CertMeta, CertStore, CloudflareClient, CloudflareConfig, DynDnsConfig, DynDnsNodeProfile,
    EchoClient, Secret, dyndns_once,
};
use mock_cloudflare::{MockCloudflare, MockZone};
use mock_echo::{MockEcho, trace_body};
use rcgen::generate_simple_self_signed;

const TOKEN: &str = "dyndns-test-token";
const ZONE_ID: &str = "zone-example-com";
const DOMAIN: &str = "example.com";
const NODE: &str = "node1.dns.example.com";

fn zone_fixture() -> MockZone {
    MockZone {
        id: ZONE_ID.into(),
        name: DOMAIN.into(),
        status: "active".into(),
        name_servers: vec!["ada.ns.cloudflare.com".into()],
    }
}

fn cfg(echo_url: &str) -> DynDnsConfig {
    DynDnsConfig {
        enabled: true,
        hostname: NODE.into(),
        public_entry: false,
        nodes: Vec::new(),
        reserved_labels: vec!["node1".into()],
        interval: Duration::from_secs(300),
        echo_url: echo_url.into(),
        ipv4: true,
        ipv6: false,
        proxied: false,
        ipv6_identifier: dnscraft_tls::Ipv6Identifier::default(),
        interfaces: Vec::new(),
        record_inventory: false,
    }
}

async fn mock_cf() -> (MockCloudflare, CloudflareClient) {
    let mock = MockCloudflare::start(TOKEN, zone_fixture()).await;
    let client = CloudflareClient::with_base_url(
        Secret::new(TOKEN),
        DOMAIN,
        &CloudflareConfig { zone_id: None },
        mock.base_url(),
    )
    .unwrap();
    (mock, client)
}

fn write_count(reqs: &[mock_cloudflare::RecordedRequest]) -> usize {
    reqs.iter()
        .filter(|r| r.method == "POST" || r.method == "PUT")
        .filter(|r| r.path.contains("/dns_records"))
        .count()
}

fn names_touched(reqs: &[mock_cloudflare::RecordedRequest]) -> Vec<String> {
    let mut out = Vec::new();
    for r in reqs {
        if !(r.method == "POST" || r.method == "PUT" || r.method == "GET") {
            continue;
        }
        if !r.path.contains("/dns_records") {
            continue;
        }
        // query name=… or JSON body "name":"…"
        if let Some(q) = r.query.split('&').find_map(|p| p.strip_prefix("name=")) {
            let n = urlencoding_decode(q);
            if !out.contains(&n) {
                out.push(n);
            }
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&r.body)
            && let Some(n) = v.get("name").and_then(|x| x.as_str())
            && !out.iter().any(|e| e == n)
        {
            out.push(n.to_owned());
        }
    }
    out
}

fn urlencoding_decode(s: &str) -> String {
    // Cloudflare mock uses plain names; `*` may be `*` or `%2A`.
    s.replace("%2A", "*").replace("%2a", "*")
}

#[tokio::test]
async fn same_ip_zero_writes_changed_ip_one_update() {
    let echo = MockEcho::start([trace_body("203.0.113.10")]).await;
    let (cf_mock, cf) = mock_cf().await;
    let echo_client = EchoClient::unbound().unwrap();
    let dyndns = cfg(&echo.url());

    // First pass creates the A record.
    let r1 = dyndns_once(&dyndns, DOMAIN, &echo_client, &cf)
        .await
        .unwrap();
    assert!(r1.changed);
    assert_eq!(r1.ipv4.unwrap().to_string(), "203.0.113.10");
    let after_create = write_count(&cf_mock.requests().await);
    assert_eq!(after_create, 1);

    // Same IP again → list only, no write.
    echo.set_bodies([trace_body("203.0.113.10")]).await;
    let r2 = dyndns_once(&dyndns, DOMAIN, &echo_client, &cf)
        .await
        .unwrap();
    assert!(!r2.changed);
    assert_eq!(write_count(&cf_mock.requests().await), after_create);

    // Changed IP → exactly one update.
    echo.set_bodies([trace_body("203.0.113.99")]).await;
    let r3 = dyndns_once(&dyndns, DOMAIN, &echo_client, &cf)
        .await
        .unwrap();
    assert!(r3.changed);
    assert_eq!(write_count(&cf_mock.requests().await), after_create + 1);
}

#[tokio::test]
async fn public_entry_cnames_wildcard_and_apex_to_node() {
    let echo = MockEcho::start([trace_body("198.51.100.7")]).await;
    let (cf_mock, cf) = mock_cf().await;
    let echo_client = EchoClient::unbound().unwrap();
    let mut dyndns = cfg(&echo.url());
    dyndns.public_entry = true;

    let r = dyndns_once(&dyndns, DOMAIN, &echo_client, &cf)
        .await
        .unwrap();
    assert!(r.changed);
    // A for node + CNAME for wildcard + CNAME for apex
    assert_eq!(write_count(&cf_mock.requests().await), 3);

    let recs = cf_mock.records().await;
    let node = recs.iter().find(|r| r.name == NODE).expect("node A");
    assert_eq!(node.record_type, "A");
    assert_eq!(node.content, "198.51.100.7");

    for name in ["*.dns.example.com", "dns.example.com"] {
        let cname = recs
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("{name}"));
        assert_eq!(cname.record_type, "CNAME");
        assert_eq!(cname.content, NODE);
        assert!(!cname.proxied);
    }
}

#[tokio::test]
async fn resolve_for_node_entry_writes_cnames_peer_does_not() {
    let echo = MockEcho::start([trace_body("198.51.100.9")]).await;
    let (cf_mock, cf) = mock_cf().await;
    let echo_client = EchoClient::unbound().unwrap();
    let mut dyndns = cfg(&echo.url());
    dyndns.hostname = "ns1.dns.example.com".into();
    dyndns.public_entry = true;
    dyndns.reserved_labels = vec!["ns1".into(), "ns2".into()];
    dyndns.nodes = vec![
        DynDnsNodeProfile {
            node_id: "node1".into(),
            hostname: "ns1.dns.example.com".into(),
            enabled: true,
            ipv4: true,
            ipv6: false,
            public_entry: true,
            ..Default::default()
        },
        DynDnsNodeProfile {
            node_id: "node2".into(),
            hostname: "ns2.dns.example.com".into(),
            enabled: true,
            ipv4: true,
            ipv6: false,
            public_entry: false,
            ..Default::default()
        },
    ];

    let entry = dyndns.resolve_for_node(Some("node1"));
    dyndns_once(&entry, DOMAIN, &echo_client, &cf)
        .await
        .unwrap();
    let recs = cf_mock.records().await;
    assert!(
        recs.iter()
            .any(|r| r.name == "ns1.dns.example.com" && r.record_type == "A")
    );
    assert!(
        recs.iter()
            .any(|r| r.name == "*.dns.example.com" && r.record_type == "CNAME")
    );

    echo.set_bodies([trace_body("198.51.100.10")]).await;
    let peer = dyndns.resolve_for_node(Some("node2"));
    dyndns_once(&peer, DOMAIN, &echo_client, &cf).await.unwrap();
    let recs = cf_mock.records().await;
    let peer_a = recs
        .iter()
        .find(|r| r.name == "ns2.dns.example.com")
        .expect("peer A");
    assert_eq!(peer_a.content, "198.51.100.10");
    // Peer must not retarget the CNAMEs away from the entry host.
    for name in ["*.dns.example.com", "dns.example.com"] {
        let cname = recs.iter().find(|r| r.name == name).unwrap();
        assert_eq!(cname.content, "ns1.dns.example.com");
    }
}

#[tokio::test]
async fn resolve_for_node_opt_out_skips_writes() {
    let echo = MockEcho::start([trace_body("198.51.100.11")]).await;
    let (cf_mock, cf) = mock_cf().await;
    let echo_client = EchoClient::unbound().unwrap();
    let mut dyndns = cfg(&echo.url());
    dyndns.reserved_labels = vec!["ns1".into(), "ns2".into()];
    dyndns.nodes = vec![
        DynDnsNodeProfile {
            node_id: "node1".into(),
            hostname: "ns1.dns.example.com".into(),
            enabled: true,
            ipv4: true,
            ipv6: false,
            public_entry: false,
            ..Default::default()
        },
        DynDnsNodeProfile {
            node_id: "node2".into(),
            hostname: "ns2.dns.example.com".into(),
            enabled: false,
            ipv4: true,
            ipv6: false,
            public_entry: false,
            ..Default::default()
        },
    ];

    let opted_out = dyndns.resolve_for_node(Some("node2"));
    assert!(!opted_out.enabled);
    let r = dyndns_once(&opted_out, DOMAIN, &echo_client, &cf)
        .await
        .unwrap();
    assert!(!r.changed);
    assert_eq!(write_count(&cf_mock.requests().await), 0);
}

#[tokio::test]
async fn non_entry_never_touches_wildcard_or_apex() {
    let echo = MockEcho::start([trace_body("203.0.113.50")]).await;
    let (cf_mock, cf) = mock_cf().await;
    let echo_client = EchoClient::unbound().unwrap();
    let dyndns = cfg(&echo.url()); // public_entry = false

    dyndns_once(&dyndns, DOMAIN, &echo_client, &cf)
        .await
        .unwrap();

    let touched = names_touched(&cf_mock.requests().await);
    assert!(touched.iter().all(|n| n == NODE), "{touched:?}");
    assert!(!touched.iter().any(|n| n == "*.dns.example.com"));
    assert!(!touched.iter().any(|n| n == "dns.example.com"));
}

#[tokio::test]
async fn unreachable_echo_is_dyndns_echo_not_no_route() {
    // Bind then drop so the port is definitely closed (connection refused, not
    // a missing route).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (cf_mock, cf) = mock_cf().await;
    let echo_client = EchoClient::unbound().unwrap();
    let dyndns = cfg(&format!("http://{addr}/cdn-cgi/trace"));

    let err = dyndns_once(&dyndns, DOMAIN, &echo_client, &cf)
        .await
        .expect_err("unreachable echo must fail the pass");
    assert_eq!(err.code(), "tls.dyndns.echo");
    assert!(
        cf_mock.requests().await.is_empty(),
        "must not touch DNS when the echo is unreachable"
    );
}

#[tokio::test]
async fn echo_garbage_is_dyndns_echo() {
    let echo = MockEcho::start(["not a trace body\n".into()]).await;
    let (_cf_mock, cf) = mock_cf().await;
    let echo_client = EchoClient::unbound().unwrap();
    let dyndns = cfg(&echo.url());

    let err = dyndns_once(&dyndns, DOMAIN, &echo_client, &cf)
        .await
        .expect_err("garbage");
    assert_eq!(err.code(), "tls.dyndns.echo");
}

#[tokio::test]
async fn echo_wrong_family_is_dyndns_echo() {
    // IPv4-enabled config, but echo returns an IPv6 address.
    let echo = MockEcho::start([trace_body("2001:db8::9")]).await;
    let (_cf_mock, cf) = mock_cf().await;
    let echo_client = EchoClient::unbound().unwrap();
    let dyndns = cfg(&echo.url());

    let err = dyndns_once(&dyndns, DOMAIN, &echo_client, &cf)
        .await
        .expect_err("wrong family");
    assert_eq!(err.code(), "tls.dyndns.echo");
}

#[tokio::test]
async fn cloudflare_500_is_dyndns_update_cert_untouched() {
    let echo = MockEcho::start([trace_body("203.0.113.77")]).await;
    let (cf_mock, cf) = mock_cf().await;
    let echo_client = EchoClient::unbound().unwrap();
    let dyndns = cfg(&echo.url());

    let data = temp_data_dir("dyndns-cert");
    let store = CertStore::open(&data).unwrap();
    let (chain, key) = self_signed();
    store.save(&chain, &key, &CertMeta::default()).unwrap();
    let before = std::fs::read(data.join("tls").join("cert.pem")).unwrap();
    let key_before = std::fs::read(data.join("tls").join("key.pem")).unwrap();

    // Force failure on the first Cloudflare call (zone lookup or list).
    cf_mock.force_next_status(500, None).await;

    let err = dyndns_once(&dyndns, DOMAIN, &echo_client, &cf)
        .await
        .expect_err("cf 500");
    assert_eq!(err.code(), "tls.dyndns.update");

    let after = std::fs::read(data.join("tls").join("cert.pem")).unwrap();
    let key_after = std::fs::read(data.join("tls").join("key.pem")).unwrap();
    assert_eq!(before, after);
    assert_eq!(key_before, key_after);
}

#[tokio::test]
async fn dual_stack_updates_a_and_aaaa() {
    let echo = MockEcho::start([trace_body("203.0.113.10"), trace_body("2001:db8::10")]).await;
    let (cf_mock, cf) = mock_cf().await;
    let echo_client = EchoClient::unbound().unwrap();
    let mut dyndns = cfg(&echo.url());
    dyndns.ipv6 = true;

    let r = dyndns_once(&dyndns, DOMAIN, &echo_client, &cf)
        .await
        .unwrap();
    assert!(r.changed);
    assert_eq!(r.ipv4.unwrap().to_string(), "203.0.113.10");
    assert_eq!(r.ipv6.unwrap().to_string(), "2001:db8::10");
    assert_eq!(write_count(&cf_mock.requests().await), 2);

    let recs = cf_mock.records().await;
    assert!(
        recs.iter()
            .any(|r| r.record_type == "A" && r.content == "203.0.113.10")
    );
    assert!(
        recs.iter()
            .any(|r| r.record_type == "AAAA" && r.content == "2001:db8::10")
    );
}

fn temp_data_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dnscraft-tls-dyndns-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn self_signed() -> (Vec<u8>, Vec<u8>) {
    let certified = generate_simple_self_signed(vec!["dns.example.com".into()]).unwrap();
    (
        certified.cert.pem().into_bytes(),
        certified.signing_key.serialize_pem().into_bytes(),
    )
}
