//! Custom rules are isolated from list and service rules (D1a item 4), and
//! the custom rule wins on equal rank (item 5).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    DomainName, FilterConfig, FilterSetConfig, ListBodies, ListConfig, ListId, ListSourceSpec,
    RuleSource, ServiceCatalog, SetId, Snapshot, SnapshotBuilder, Verdict,
};

#[derive(Debug, Default)]
struct MapBodies {
    map: HashMap<ListId, Arc<str>>,
}

impl ListBodies for MapBodies {
    fn body(&self, id: &ListId) -> Option<Arc<str>> {
        self.map.get(id).cloned()
    }
}

fn sid(s: &str) -> SetId {
    SetId::new(s).unwrap()
}
fn dn(s: &str) -> DomainName {
    s.parse().unwrap()
}
fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000)
}

fn catalog(rules: &[&str]) -> Arc<ServiceCatalog> {
    let rules: Vec<String> = rules.iter().map(|r| format!("{r:?}")).collect();
    let json = format!(
        r#"{{"blocked_services":[{{"id":"svc","name":"Svc","group":"g","icon_svg":"","rules":[{}]}}],"groups":[{{"id":"g"}}]}}"#,
        rules.join(",")
    );
    Arc::new(ServiceCatalog::parse(&json, None).unwrap())
}

/// One set `s` with optional list `l`, custom rules and service `svc`.
fn build(list_body: Option<&str>, custom: &str, service: Option<&[&str]>) -> Snapshot {
    let lid = ListId::new("l").unwrap();
    let mut bodies = MapBodies::default();
    let mut cfg = FilterConfig::default();
    let mut set = FilterSetConfig::new(sid("s"), "s");
    set.custom_rules = custom.to_owned();
    if let Some(b) = list_body {
        bodies.map.insert(lid.clone(), Arc::from(b));
        cfg.lists.push(ListConfig {
            id: lid.clone(),
            name: "l".into(),
            source: ListSourceSpec::Url("https://example.invalid/l.txt".into()),
            enabled: true,
        });
        set.lists = vec![lid];
    }
    let mut builder = SnapshotBuilder::new(Arc::new(bodies));
    if let Some(rules) = service {
        set.services = vec!["svc".into()];
        builder = builder.with_catalog(Some(catalog(rules)));
    }
    cfg.sets.push(set);
    builder.build(&cfg).unwrap()
}

fn m(snap: &Snapshot, name: &str) -> Verdict {
    snap.match_name(&sid("s"), &dn(name), 1, now()).unwrap()
}

fn assert_custom_block(v: &Verdict) {
    match v {
        Verdict::Blocked(r) => {
            assert!(matches!(r.source, RuleSource::Custom { .. }), "{r:?}");
        }
        other => panic!("expected custom Blocked, got {other:?}"),
    }
}

fn assert_custom_rewrite(v: &Verdict) {
    match v {
        Verdict::Rewrite(_, r) => {
            assert!(matches!(r.source, RuleSource::Custom { .. }), "{r:?}");
        }
        other => panic!("expected custom Rewrite, got {other:?}"),
    }
}

#[test]
fn service_badfilter_does_not_remove_custom_rule() {
    let snap = build(
        None,
        "||blocked.example^\n",
        Some(&["||blocked.example^$badfilter"]),
    );
    assert_custom_block(&m(&snap, "blocked.example"));
}

#[test]
fn list_badfilter_does_not_remove_custom_rule_in_merged_index() {
    // The custom `$badfilter` forces the merged index.
    let snap = build(
        Some("||blocked.example^$badfilter\n"),
        "||blocked.example^\n||unrelated.example^$badfilter\n",
        None,
    );
    assert!(snap.custom_facts(&sid("s")).unwrap().merged_into_list_index);
    assert_custom_block(&m(&snap, "blocked.example"));
}

#[test]
fn service_badfilter_does_not_remove_custom_rule_in_merged_index() {
    let snap = build(
        None,
        "||blocked.example^\n||unrelated.example^$badfilter\n",
        Some(&["||blocked.example^$badfilter"]),
    );
    assert!(snap.custom_facts(&sid("s")).unwrap().merged_into_list_index);
    assert_custom_block(&m(&snap, "blocked.example"));
}

#[test]
fn custom_badfilter_still_removes_list_rule() {
    let snap = build(
        Some("||blocked.example^\n"),
        "||blocked.example^$badfilter\n",
        None,
    );
    assert!(matches!(m(&snap, "blocked.example"), Verdict::Pass));
}

#[test]
fn list_dnsrewrite_disable_does_not_disable_custom_rewrite() {
    let snap = build(
        Some("@@||nas.lan^$dnsrewrite\n"),
        "||nas.lan^$dnsrewrite=192.168.1.5\n||unrelated.example^$badfilter\n",
        None,
    );
    assert!(snap.custom_facts(&sid("s")).unwrap().merged_into_list_index);
    assert_custom_rewrite(&m(&snap, "nas.lan"));
}

#[test]
fn service_dnsrewrite_disable_does_not_disable_custom_rewrite() {
    let snap = build(
        None,
        "||nas.lan^$dnsrewrite=192.168.1.5\n",
        Some(&["@@||nas.lan^$dnsrewrite"]),
    );
    assert_custom_rewrite(&m(&snap, "nas.lan"));
    let snap = build(
        None,
        "||nas.lan^$dnsrewrite=192.168.1.5\n||unrelated.example^$badfilter\n",
        Some(&["@@||nas.lan^$dnsrewrite"]),
    );
    assert_custom_rewrite(&m(&snap, "nas.lan"));
}

#[test]
fn custom_dnsrewrite_disable_still_disables_service_rewrite() {
    let snap = build(
        None,
        "@@||nas.lan^$dnsrewrite\n||unrelated.example^$badfilter\n",
        Some(&["||nas.lan^$dnsrewrite=10.0.0.1"]),
    );
    assert!(!matches!(m(&snap, "nas.lan"), Verdict::Rewrite(..)));
}

#[test]
fn equal_rank_custom_name_rule_wins_over_list() {
    let snap = build(Some("||both.example^\n"), "||both.example^\n", None);
    assert_custom_block(&m(&snap, "both.example"));
    let snap = build(Some("@@||both.example^\n"), "@@||both.example^\n", None);
    match m(&snap, "both.example") {
        Verdict::Allowed(r) => assert!(matches!(r.source, RuleSource::Custom { .. })),
        other => panic!("{other:?}"),
    }
}

#[test]
fn equal_rank_custom_ip_rule_wins_over_list() {
    let snap = build(Some("|1.2.3.4|\n"), "|1.2.3.4|\n", None);
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    match snap.match_answer_ip(&sid("s"), ip, now()).unwrap() {
        Verdict::Blocked(r) => assert!(matches!(r.source, RuleSource::Custom { .. }), "{r:?}"),
        other => panic!("{other:?}"),
    }
}
