#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    DomainName, FilterConfig, FilterSetConfig, IndexBuilder, ListBodies, ListConfig, ListId,
    ListSource, ListSourceSpec, MatchKind, RuleAction, RuleSource, SetId, SnapshotBuilder,
    SourceKind, Verdict, describe_rule, parse_list, parse_rule,
};

fn dn(s: &str) -> DomainName {
    s.parse().unwrap()
}
fn lid(s: &str) -> ListId {
    ListId::new(s).unwrap()
}
fn sid(s: &str) -> SetId {
    SetId::new(s).unwrap()
}
fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}
fn t(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

#[derive(Debug)]
struct MapBodies(std::collections::HashMap<ListId, Arc<str>>);

impl ListBodies for MapBodies {
    fn body(&self, id: &ListId) -> Option<Arc<str>> {
        self.0.get(id).cloned()
    }
}

fn build_index(body: &str) -> dnscraft_filtering::Index {
    let mut b = IndexBuilder::new();
    let s = b
        .add_source_with_body(SourceKind::List(lid("l")), Arc::from(body))
        .unwrap();
    b.add_rules(s, parse_list(body, ListSource::List).rules)
        .unwrap();
    b.build_in_memory()
}

#[test]
fn parse_ipv4_and_ipv6_forms() {
    for line in [
        "||194.63.143.96^",
        "194.63.143.96",
        "|1.2.3.4^",
        "@@||1.2.3.4^",
        "||2001:db8::1^",
        "@@||2001:db8:0:0:0:0:0:1^$important",
    ] {
        let r = parse_rule(line).unwrap_or_else(|e| panic!("{line}: {e}"));
        assert_eq!(r.kind(), MatchKind::Ip, "{line}");
        assert!(r.ip().is_some(), "{line}");
    }
    let r = parse_rule("@@||1.2.3.4^$important").unwrap();
    assert_eq!(r.action(), RuleAction::Allow);
    assert!(r.modifiers().important);
    // IPv6 canonical form.
    assert_eq!(
        parse_rule("||2001:db8:0:0:0:0:0:1^").unwrap().ip(),
        Some(ip("2001:db8::1"))
    );
}

#[test]
fn hosts_ip_name_stays_invalid() {
    let p = parse_list("0.0.0.0 5.0.0.0\n", ListSource::List);
    assert!(p.rules.is_empty());
    assert_eq!(p.skipped.total(), 1);
}

#[test]
fn describe_and_builder_reject_ip_rules() {
    let r = parse_rule("||1.2.3.4^").unwrap();
    assert!(describe_rule(&r).is_none());
}

#[test]
fn match_allow_important_badfilter_and_reason() {
    let idx = build_index(
        "||1.2.3.4^\n@@||1.2.3.4^$important\n||5.6.7.8^\n||5.6.7.8^$badfilter\n||2001:db8::1^\n",
    );
    assert_eq!(idx.ip_count(), 3); // block+important allow for 1.2.3.4, v6 block; 5.6.7.8 removed
    match idx.match_answer_ip(ip("1.2.3.4")) {
        Verdict::Allowed(r) => {
            assert!(r.important);
            assert_eq!(&*r.rule, "@@||1.2.3.4^$important");
            assert_eq!(
                r.source,
                RuleSource::List {
                    list: lid("l"),
                    line: 2
                }
            );
        }
        v => panic!("{v:?}"),
    }
    assert!(matches!(idx.match_answer_ip(ip("5.6.7.8")), Verdict::Pass));
    assert!(matches!(
        idx.match_answer_ip(ip("2001:db8::1")),
        Verdict::Blocked(_)
    ));
    assert_eq!(idx.match_answer_ip(ip("9.9.9.9")), Verdict::Pass);
    // Name matching ignores IP rules.
    assert_eq!(idx.match_name(&dn("1.2.3.4"), 1), Verdict::Pass);
}

#[test]
fn snapshot_unknown_set_and_pause() {
    let bodies = Arc::new(MapBodies(
        [(lid("a"), Arc::from("||1.2.3.4^\n"))]
            .into_iter()
            .collect(),
    ));
    let mut set = FilterSetConfig::new(sid("s"), "s");
    set.lists = vec![lid("a")];
    set.paused_until = Some(t(100));
    let cfg = FilterConfig {
        lists: vec![ListConfig {
            id: lid("a"),
            name: "a".into(),
            source: ListSourceSpec::Url("https://example.invalid/a".into()),
            enabled: true,
        }],
        sets: vec![set],
        ..FilterConfig::default()
    };
    let snap = SnapshotBuilder::new(bodies).build(&cfg).unwrap();
    assert_eq!(
        snap.match_answer_ip(&sid("s"), ip("1.2.3.4"), t(50))
            .unwrap(),
        Verdict::Pass
    );
    assert!(matches!(
        snap.match_answer_ip(&sid("s"), ip("1.2.3.4"), t(200))
            .unwrap(),
        Verdict::Blocked(_)
    ));
    assert_eq!(
        snap.match_answer_ip(&sid("nope"), ip("1.2.3.4"), t(0))
            .unwrap_err()
            .code(),
        "filter_set.unknown"
    );
}
