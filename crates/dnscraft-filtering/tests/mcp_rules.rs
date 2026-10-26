//! Task M2: structured `McpRule` storage, validation and exact expiry.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    Clock, DomainName, FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId,
    ManualClock, McpRule, McpRuleId, RuleSource, SetId, Snapshot, SnapshotBuilder, SnapshotError,
    Verdict,
};
use proptest::prelude::*;

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
fn t(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn rule(id: &str, domain: &str, subdomains: bool) -> McpRule {
    McpRule {
        id: McpRuleId::new(id).unwrap(),
        domain: dn(domain),
        include_subdomains: subdomains,
        created_at: t(0),
        expires_at: t(1_000),
        token_id: "tok".into(),
    }
}

fn config(custom: &str, rules: Vec<McpRule>) -> FilterConfig {
    let mut set = FilterSetConfig::new(sid("s"), "s");
    set.custom_rules = custom.to_owned();
    set.mcp_rules = rules;
    FilterConfig {
        sets: vec![set],
        ..FilterConfig::default()
    }
}

fn build_at(cfg: &FilterConfig, now: SystemTime) -> Result<Snapshot, SnapshotError> {
    SnapshotBuilder::new(Arc::new(MapBodies::default()) as Arc<dyn ListBodies>)
        .with_clock(Arc::new(ManualClock::new(now)))
        .build(cfg)
}

fn block_text(verdict: &Verdict) -> &str {
    match verdict {
        Verdict::Blocked(reason) => reason.rule.as_ref(),
        other => panic!("expected block, got {other:?}"),
    }
}

#[test]
fn mcp_rule_blocks_exact_name_and_optional_subdomains() {
    let cfg = config(
        "",
        vec![
            rule("wide", "example.com", true),
            rule("exact", "exact.example", false),
        ],
    );
    let snap = build_at(&cfg, t(0)).unwrap();
    let at = |name: &str, now| snap.match_name(&sid("s"), &dn(name), 1, now).unwrap();

    assert!(matches!(at("example.com", t(100)), Verdict::Blocked(_)));
    assert!(matches!(at("a.example.com", t(100)), Verdict::Blocked(_)));
    assert!(matches!(at("a.b.example.com", t(100)), Verdict::Blocked(_)));
    assert!(matches!(at("exact.example", t(100)), Verdict::Blocked(_)));
    assert_eq!(at("x.exact.example", t(100)), Verdict::Pass);
    assert_eq!(at("notexample.com", t(100)), Verdict::Pass);

    let blocked = at("example.com", t(100));
    let Verdict::Blocked(reason) = &blocked else {
        unreachable!();
    };
    assert_eq!(reason.rule.as_ref(), "||example.com^");
    assert_eq!(
        reason.source,
        RuleSource::Mcp {
            set: sid("s"),
            id: McpRuleId::new("wide").unwrap(),
        }
    );
    assert!(!reason.important);
    let blocked = at("exact.example", t(100));
    assert_eq!(block_text(&blocked), "|exact.example^");
}

#[test]
fn mcp_rule_expiry_is_exact_without_config_change() {
    let clock = Arc::new(ManualClock::new(t(0)));
    let mut r = rule("r", "ads.example", false);
    r.expires_at = t(100);
    let cfg = config("", vec![r]);
    let snap = SnapshotBuilder::new(Arc::new(MapBodies::default()) as Arc<dyn ListBodies>)
        .with_clock(Arc::clone(&clock) as Arc<dyn dnscraft_filtering::Clock>)
        .build(&cfg)
        .unwrap();
    let eng = FilterEngine::from_snapshot(snap);
    let set = sid("s");

    assert!(matches!(
        eng.match_name(&set, &dn("ads.example"), 1, clock.now())
            .unwrap(),
        Verdict::Blocked(_)
    ));

    clock.advance(Duration::from_secs(100) - Duration::from_nanos(1));
    assert!(matches!(
        eng.match_name(&set, &dn("ads.example"), 1, clock.now())
            .unwrap(),
        Verdict::Blocked(_)
    ));

    clock.advance(Duration::from_nanos(1));
    assert_eq!(
        eng.match_name(&set, &dn("ads.example"), 1, clock.now())
            .unwrap(),
        Verdict::Pass
    );
}

#[test]
fn mcp_rule_rules_expired_at_build_time_are_dropped_silently() {
    let mut expired = rule("r", "old.example", true);
    expired.expires_at = t(500);
    let mut live = rule("live", "new.example", false);
    live.expires_at = t(2_000);
    let cfg = config("", vec![expired, live]);
    let snap = build_at(&cfg, t(1_000)).unwrap();

    assert_eq!(
        snap.match_name(&sid("s"), &dn("old.example"), 1, t(0))
            .unwrap(),
        Verdict::Pass
    );
    assert!(matches!(
        snap.match_name(&sid("s"), &dn("new.example"), 1, t(1_000))
            .unwrap(),
        Verdict::Blocked(_)
    ));
}

#[test]
fn mcp_rule_duplicate_domain_and_scope_is_rejected() {
    let cfg = config(
        "",
        vec![
            rule("a", "example.com", false),
            rule("b", "example.com", false),
        ],
    );
    assert_eq!(
        build_at(&cfg, t(0)).unwrap_err().code(),
        "filtering.config.mcp_rule_duplicate"
    );

    // Same domain with a different scope is allowed.
    let cfg = config(
        "",
        vec![
            rule("a", "example.com", false),
            rule("b", "example.com", true),
        ],
    );
    assert!(build_at(&cfg, t(0)).is_ok());
}

#[test]
fn mcp_rule_duplicate_ids_are_rejected_per_set() {
    let cfg = config(
        "",
        vec![
            rule("same", "a.example", false),
            rule("same", "b.example", false),
        ],
    );
    assert_eq!(
        build_at(&cfg, t(0)).unwrap_err().code(),
        "filtering.config.mcp_rule_id_duplicate"
    );
}

#[test]
fn mcp_rule_expiry_must_be_after_creation() {
    let mut r = rule("r", "a.example", false);
    r.created_at = t(100);
    r.expires_at = t(100);
    assert_eq!(
        build_at(&config("", vec![r]), t(0)).unwrap_err().code(),
        "filtering.config.mcp_rule_expiry"
    );
}

#[test]
fn mcp_rule_rule_that_cannot_be_built_is_rejected() {
    // `DomainName` accepts an IPv4 literal, but the guided builder does not.
    let r = rule("r", "192.0.2.1", false);
    let err = build_at(&config("", vec![r]), t(0)).unwrap_err();
    assert_eq!(err.code(), "filtering.config.mcp_rule_invalid");
    assert!(matches!(
        err,
        SnapshotError::InvalidMcpRule {
            code: "filter_build.pattern_not_allowed",
            ..
        }
    ));
}

#[test]
fn mcp_rule_custom_rules_rank_as_before() {
    // A web-UI allow still beats an MCP block (allow rank before block).
    let cfg = config("@@||example.com^\n", vec![rule("r", "example.com", true)]);
    let snap = build_at(&cfg, t(0)).unwrap();
    assert!(matches!(
        snap.match_name(&sid("s"), &dn("example.com"), 1, t(0))
            .unwrap(),
        Verdict::Allowed(_)
    ));
    assert!(matches!(
        snap.match_name(&sid("s"), &dn("x.example.com"), 1, t(0))
            .unwrap(),
        Verdict::Allowed(_)
    ));

    // A web-UI block keeps blocking names the MCP rule does not cover.
    let cfg = config("||other.example^\n", vec![rule("r", "example.com", false)]);
    let snap = build_at(&cfg, t(0)).unwrap();
    assert!(matches!(
        snap.match_name(&sid("s"), &dn("other.example"), 1, t(0))
            .unwrap(),
        Verdict::Blocked(_)
    ));
}

fn label() -> impl Strategy<Value = String> {
    "[a-z]([a-z0-9_-]{0,10}[a-z0-9])?"
}

fn domain_input() -> impl Strategy<Value = String> {
    proptest::collection::vec(label(), 1..4).prop_map(|labels| labels.join("."))
}

proptest! {
    #[test]
    fn mcp_rule_generated_rule_text_has_no_modifiers(domain in domain_input(), subdomains: bool) {
        let mut r = rule("r", &domain, subdomains);
        r.expires_at = t(1_000);
        let cfg = config("", vec![r]);
        let snap = build_at(&cfg, t(0)).unwrap();
        let v = snap.match_name(&sid("s"), &dn(&domain), 1, t(0)).unwrap();
        let text = block_text(&v);
        prop_assert!(!text.contains('$'), "{text}");
        let prefix = if subdomains { "||" } else { "|" };
        prop_assert_eq!(text, format!("{prefix}{domain}^"));
    }
}
