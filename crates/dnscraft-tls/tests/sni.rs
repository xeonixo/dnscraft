//! Table and property tests for SNI Client-ID helpers.

use std::collections::HashSet;

use dnscraft_tls::{
    ClientIdRegistry, ReservedLabels, SniKind, accept_public_sni, parse_client_id_sni,
};
use proptest::prelude::*;

const DOMAIN: &str = "example.com";

struct SetRegistry(HashSet<String>);

impl ClientIdRegistry for SetRegistry {
    fn is_registered(&self, client_id: &str) -> bool {
        self.0.contains(&client_id.to_ascii_lowercase())
    }
}

fn reserved_nodes(nodes: &[&str]) -> ReservedLabels {
    ReservedLabels::new(nodes.iter().map(|s| (*s).to_owned()))
}

#[test]
fn sni_table_registered_and_unregistered_client_id() {
    let reserved = reserved_nodes(&["node1", "node2"]);
    let reg = SetRegistry(HashSet::from(["phone".into(), "laptop".into()]));

    assert_eq!(
        parse_client_id_sni("phone.dns.example.com", DOMAIN, &reserved),
        SniKind::ClientId("phone")
    );
    assert!(accept_public_sni(
        Some("phone.dns.example.com"),
        DOMAIN,
        &reserved,
        &reg
    ));
    assert!(!accept_public_sni(
        Some("unknown.dns.example.com"),
        DOMAIN,
        &reserved,
        &reg
    ));
}

#[test]
fn sni_table_node_hostname() {
    let reserved = reserved_nodes(&["node1", "node2"]);
    assert_eq!(
        parse_client_id_sni("node1.dns.example.com", DOMAIN, &reserved),
        SniKind::NodeHostname
    );
    let reg = SetRegistry(HashSet::new());
    assert!(!accept_public_sni(
        Some("node1.dns.example.com"),
        DOMAIN,
        &reserved,
        &reg
    ));
}

#[test]
fn sni_table_apex() {
    let reserved = reserved_nodes(&["node1"]);
    assert_eq!(
        parse_client_id_sni("dns.example.com", DOMAIN, &reserved),
        SniKind::Apex
    );
    assert_eq!(
        parse_client_id_sni("DNS.Example.COM.", DOMAIN, &reserved),
        SniKind::Apex
    );
    let reg = SetRegistry(HashSet::new());
    assert!(!accept_public_sni(
        Some("dns.example.com"),
        DOMAIN,
        &reserved,
        &reg
    ));
}

#[test]
fn sni_table_case_and_trailing_dot_on_client_id() {
    let reserved = reserved_nodes(&["node1"]);
    match parse_client_id_sni("Phone.DNS.Example.COM.", DOMAIN, &reserved) {
        SniKind::ClientId(id) => assert!(id.eq_ignore_ascii_case("phone")),
        other => panic!("expected ClientId, got {other:?}"),
    }
}

#[test]
fn sni_table_two_label_subdomain_is_other() {
    let reserved = reserved_nodes(&["node1"]);
    assert_eq!(
        parse_client_id_sni("a.b.dns.example.com", DOMAIN, &reserved),
        SniKind::Other
    );
}

#[test]
fn sni_table_other_domain() {
    let reserved = reserved_nodes(&["node1"]);
    assert_eq!(
        parse_client_id_sni("phone.dns.example.org", DOMAIN, &reserved),
        SniKind::Other
    );
    assert_eq!(
        parse_client_id_sni("phone.example.com", DOMAIN, &reserved),
        SniKind::Other
    );
}

#[test]
fn sni_table_suffix_trick() {
    let reserved = reserved_nodes(&["node1"]);
    // Must not treat evil.net as under example.com.
    assert_eq!(
        parse_client_id_sni("dns.example.com.evil.net", DOMAIN, &reserved),
        SniKind::Other
    );
    assert_eq!(
        parse_client_id_sni("phone.dns.example.com.evil.net", DOMAIN, &reserved),
        SniKind::Other
    );
}

#[test]
fn sni_table_fixed_reserved_is_node_hostname() {
    let reserved = reserved_nodes(&[]);
    for label in ["dns", "www", "api", "admin", "ns"] {
        let name = format!("{label}.dns.example.com");
        assert_eq!(
            parse_client_id_sni(&name, DOMAIN, &reserved),
            SniKind::NodeHostname,
            "{label}"
        );
    }
}

#[test]
fn sni_table_missing_sni_rejected() {
    let reserved = reserved_nodes(&["node1"]);
    let reg = SetRegistry(HashSet::from(["phone".into()]));
    assert!(!accept_public_sni(None, DOMAIN, &reserved, &reg));
}

proptest! {
    /// Arbitrary SNI-like strings must never panic the parser.
    #[test]
    fn sni_parse_never_panics(sni in "\\PC{0,256}", domain in "[a-z0-9.-]{0,64}") {
        let reserved = ReservedLabels::new(["node1".into()]);
        let _ = parse_client_id_sni(&sni, &domain, &reserved);
    }

    /// A ClientId classification always means the label is not reserved.
    #[test]
    fn sni_client_id_implies_not_reserved(
        label in "[a-z0-9-]{1,63}",
        domain in "[a-z][a-z0-9-]{0,20}\\.[a-z]{2,10}",
        nodes in prop::collection::vec("[a-z][a-z0-9-]{0,20}", 0..8),
    ) {
        let reserved = ReservedLabels::new(nodes);
        let sni = format!("{label}.dns.{domain}");
        match parse_client_id_sni(&sni, &domain, &reserved) {
            SniKind::ClientId(id) => {
                assert!(!reserved.contains(id));
                assert!(id.eq_ignore_ascii_case(&label));
            }
            SniKind::NodeHostname => {
                assert!(reserved.contains(&label));
            }
            SniKind::Apex | SniKind::Other => {
                // domain may itself look odd; still must not panic.
            }
        }
    }
}

#[test]
fn sni_table_second_label_must_be_dns() {
    let reserved = reserved_nodes(&["node1"]);
    for name in ["x.foo.example.com", "x.www.example.com"] {
        assert_eq!(
            parse_client_id_sni(name, DOMAIN, &reserved),
            SniKind::Other,
            "{name}"
        );
    }
}
