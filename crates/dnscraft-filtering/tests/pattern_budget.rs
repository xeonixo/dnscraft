//! Per-index caps on regex and glob rules (D1a item 3).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;

use dnscraft_filtering::{
    FilterConfig, FilterSetConfig, ListBodies, ListConfig, ListId, ListSourceSpec, MAX_GLOB_RULES,
    MAX_REGEX_RULES, REGEX_BUDGET_BYTES, REGEX_SIZE_LIMIT, SetId, SkipReason, Snapshot,
    SnapshotBuilder,
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

fn build(body: &str) -> Snapshot {
    let lid = ListId::new("l").unwrap();
    let sid = SetId::new("s").unwrap();
    let mut bodies = MapBodies::default();
    bodies.map.insert(lid.clone(), Arc::from(body));
    let mut set = FilterSetConfig::new(sid, "s");
    set.lists = vec![lid.clone()];
    let cfg = FilterConfig {
        lists: vec![ListConfig {
            id: lid,
            name: "l".into(),
            source: ListSourceSpec::Url("https://example.invalid/l.txt".into()),
            enabled: true,
        }],
        sets: vec![set],
        ..FilterConfig::default()
    };
    SnapshotBuilder::new(Arc::new(bodies)).build(&cfg).unwrap()
}

fn sid() -> SetId {
    SetId::new("s").unwrap()
}

#[test]
fn regex_rules_are_capped_per_index() {
    let n = 20_000usize;
    let body: String = (0..n).map(|i| format!("/^ad{i}x\\.example$/\n")).collect();
    let snap = build(&body);
    let shared = snap.shared_index(&sid()).unwrap();
    assert_eq!(shared.index.pattern_count(), MAX_REGEX_RULES);
    assert_eq!(shared.index.pattern_budget_skipped(), n - MAX_REGEX_RULES);
    let facts = &snap.list_facts(&sid()).unwrap()[0];
    assert_eq!(facts.rules_parsed, n);
    assert_eq!(
        facts.skipped.get(SkipReason::PatternBudget),
        n - MAX_REGEX_RULES
    );
    assert_eq!(facts.unique_contribution, MAX_REGEX_RULES);
    // The kept rules still match; the skipped ones do not.
    let name = "ad0x.example".parse().unwrap();
    let now = std::time::SystemTime::UNIX_EPOCH;
    assert!(matches!(
        snap.match_name(&sid(), &name, 1, now).unwrap(),
        dnscraft_filtering::Verdict::Blocked(_)
    ));
    let name = format!("ad{}x.example", n - 1).parse().unwrap();
    assert!(matches!(
        snap.match_name(&sid(), &name, 1, now).unwrap(),
        dnscraft_filtering::Verdict::Pass
    ));
}

#[test]
fn glob_rules_are_capped_per_index() {
    let n = MAX_GLOB_RULES + 10_000;
    let body: String = (0..n).map(|i| format!("||a{i}*.example^\n")).collect();
    let snap = build(&body);
    let shared = snap.shared_index(&sid()).unwrap();
    assert_eq!(shared.index.pattern_count(), MAX_GLOB_RULES);
    assert_eq!(shared.index.pattern_budget_skipped(), n - MAX_GLOB_RULES);
}

#[test]
fn cumulative_regex_budget_stops_before_the_count_cap() {
    // Long sources are charged the per-regex maximum.
    let pad = "1".repeat(200);
    let body: String = (0..MAX_REGEX_RULES)
        .map(|i| format!("/^{pad}{i}\\.example$/\n"))
        .collect();
    let snap = build(&body);
    let shared = snap.shared_index(&sid()).unwrap();
    let kept = shared.index.pattern_count();
    assert!(kept > 0);
    assert!(kept <= REGEX_BUDGET_BYTES / (REGEX_SIZE_LIMIT.min(512 + 32 * 200)));
    assert!(kept < MAX_REGEX_RULES);
    assert_eq!(
        shared.index.pattern_budget_skipped(),
        MAX_REGEX_RULES - kept
    );
}

#[test]
fn skip_reason_has_a_stable_code() {
    assert_eq!(SkipReason::PatternBudget.as_str(), "pattern_budget");
    assert!(SkipReason::ALL.contains(&SkipReason::PatternBudget));
}

#[test]
fn per_regex_size_limit_is_8_kib() {
    assert_eq!(REGEX_SIZE_LIMIT, 8 * 1024);
}
