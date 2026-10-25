#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use dnscraft_filtering::{
    BlockMode, DomainName, FilterConfig, FilterSetConfig, ListBodies, ListConfig, ListId,
    ListSourceSpec, RuleSource, SetId, SnapshotBuilder, SnapshotError, Verdict,
};

#[derive(Debug, Default)]
struct MapBodies {
    map: HashMap<ListId, Arc<str>>,
    calls: AtomicUsize,
}

impl ListBodies for MapBodies {
    fn body(&self, id: &ListId) -> Option<Arc<str>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.map.get(id).cloned()
    }
}

fn lid(s: &str) -> ListId {
    ListId::new(s).unwrap()
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

fn list_cfg(id: &str, enabled: bool) -> ListConfig {
    ListConfig {
        id: lid(id),
        name: id.to_owned(),
        source: ListSourceSpec::Url(format!("https://example.invalid/{id}.txt")),
        enabled,
    }
}

fn set_cfg(id: &str, lists: &[&str], custom: &str) -> FilterSetConfig {
    let mut s = FilterSetConfig::new(sid(id), id);
    s.lists = lists.iter().map(|l| lid(l)).collect();
    s.custom_rules = custom.to_owned();
    s
}

fn bodies(items: &[(&str, &str)]) -> Arc<MapBodies> {
    Arc::new(MapBodies {
        map: items.iter().map(|(k, v)| (lid(k), Arc::from(*v))).collect(),
        calls: AtomicUsize::new(0),
    })
}

const LIST_A: &str = "! list a\n||ads.example^\n||tracker.example^\n||shared.example^\n";
const LIST_B: &str = "||shared.example^\n||other.example^\n";

fn config(lists: &[(&str, bool)], sets: Vec<FilterSetConfig>) -> FilterConfig {
    FilterConfig {
        lists: lists.iter().map(|(i, e)| list_cfg(i, *e)).collect(),
        sets,
        ..FilterConfig::default()
    }
}

fn verdict(snap: &dnscraft_filtering::Snapshot, set: &str, name: &str, now: SystemTime) -> Verdict {
    snap.match_name(&sid(set), &dn(name), 1, now).unwrap()
}

#[test]
fn identical_combinations_share_one_index() {
    let b = bodies(&[("a", LIST_A), ("b", LIST_B)]);
    let cfg = config(
        &[("a", true), ("b", true)],
        vec![
            set_cfg("one", &["a", "b"], ""),
            set_cfg("two", &["a", "b"], "||mine.example^"),
            set_cfg("three", &["a"], ""),
            set_cfg("four", &["b", "a"], ""),
        ],
    );
    let snap = SnapshotBuilder::new(b).build(&cfg).unwrap();
    let one = snap.shared_index(&sid("one")).unwrap();
    assert!(Arc::ptr_eq(one, snap.shared_index(&sid("two")).unwrap()));
    assert!(!Arc::ptr_eq(one, snap.shared_index(&sid("three")).unwrap()));
    // Order is part of the combination (it decides tie-breaks).
    assert!(!Arc::ptr_eq(one, snap.shared_index(&sid("four")).unwrap()));
    // Memory counts the shared index once.
    let single = one.index.memory().entries;
    assert!(snap.memory().entries < 4 * single);
}

#[test]
fn custom_allow_overrides_list_block() {
    let b = bodies(&[("a", LIST_A)]);
    let cfg = config(
        &[("a", true)],
        vec![set_cfg("s", &["a"], "! mine\n@@||ads.example^\n")],
    );
    let snap = SnapshotBuilder::new(b).build(&cfg).unwrap();
    let Verdict::Allowed(r) = verdict(&snap, "s", "ads.example", t(0)) else {
        panic!("expected allow");
    };
    assert_eq!(&*r.rule, "@@||ads.example^");
    assert_eq!(
        r.source,
        RuleSource::Custom {
            set: sid("s"),
            line: 2
        }
    );
    assert!(matches!(
        verdict(&snap, "s", "tracker.example", t(0)),
        Verdict::Blocked(_)
    ));
    assert_eq!(verdict(&snap, "s", "nothing.example", t(0)), Verdict::Pass);
}

#[test]
fn custom_block_against_list_allow_follows_priority() {
    let b = bodies(&[("a", "@@||ok.example^\n@@||ok2.example^$important\n")]);
    let cfg = config(
        &[("a", true)],
        vec![set_cfg(
            "s",
            &["a"],
            "||ok.example^\n||ok2.example^\n||new.example^\n",
        )],
    );
    let snap = SnapshotBuilder::new(b).build(&cfg).unwrap();
    // Plain allow beats plain block, even across list and custom rules.
    assert!(matches!(
        verdict(&snap, "s", "ok.example", t(0)),
        Verdict::Allowed(r) if matches!(r.source, RuleSource::List { .. })
    ));
    assert!(matches!(
        verdict(&snap, "s", "ok2.example", t(0)),
        Verdict::Allowed(r) if r.important
    ));
    assert!(matches!(
        verdict(&snap, "s", "new.example", t(0)),
        Verdict::Blocked(r) if matches!(r.source, RuleSource::Custom { line: 3, .. })
    ));
}

#[test]
fn custom_important_wins_over_list_allow() {
    let b = bodies(&[("a", "@@||ok.example^\n@@||imp.example^$important\n")]);
    let cfg = config(
        &[("a", true)],
        vec![set_cfg(
            "s",
            &["a"],
            "||ok.example^$important\n||imp.example^$important\n",
        )],
    );
    let snap = SnapshotBuilder::new(b).build(&cfg).unwrap();
    assert!(matches!(
        verdict(&snap, "s", "ok.example", t(0)),
        Verdict::Blocked(r) if r.important
    ));
    // Important allow (list) beats important block (custom).
    assert!(matches!(
        verdict(&snap, "s", "imp.example", t(0)),
        Verdict::Allowed(r) if r.important
    ));
}

#[test]
fn custom_badfilter_disables_list_rule_in_that_set_only() {
    let b = bodies(&[("a", LIST_A)]);
    let cfg = config(
        &[("a", true)],
        vec![
            set_cfg("plain", &["a"], ""),
            set_cfg("bf", &["a"], "||ads.example^$badfilter\n"),
            set_cfg("plain2", &["a"], "||mine.example^"),
        ],
    );
    let snap = SnapshotBuilder::new(b).build(&cfg).unwrap();
    assert!(matches!(
        verdict(&snap, "plain", "ads.example", t(0)),
        Verdict::Blocked(_)
    ));
    assert_eq!(verdict(&snap, "bf", "ads.example", t(0)), Verdict::Pass);
    assert!(matches!(
        verdict(&snap, "bf", "tracker.example", t(0)),
        Verdict::Blocked(_)
    ));
    assert!(matches!(
        verdict(&snap, "plain2", "ads.example", t(0)),
        Verdict::Blocked(_)
    ));
    assert!(
        snap.custom_facts(&sid("bf"))
            .unwrap()
            .merged_into_list_index
    );
    assert!(!Arc::ptr_eq(
        snap.shared_index(&sid("plain")).unwrap(),
        snap.shared_index(&sid("bf")).unwrap()
    ));
    assert!(Arc::ptr_eq(
        snap.shared_index(&sid("plain")).unwrap(),
        snap.shared_index(&sid("plain2")).unwrap()
    ));
}

#[test]
fn badfilter_inside_lists_stays_in_the_combination() {
    let b = bodies(&[("a", "||x.example^\n"), ("b", "||x.example^$badfilter\n")]);
    let cfg = config(
        &[("a", true), ("b", true)],
        vec![
            set_cfg("both", &["a", "b"], ""),
            set_cfg("only-a", &["a"], ""),
        ],
    );
    let snap = SnapshotBuilder::new(b).build(&cfg).unwrap();
    assert_eq!(verdict(&snap, "both", "x.example", t(0)), Verdict::Pass);
    assert!(matches!(
        verdict(&snap, "only-a", "x.example", t(0)),
        Verdict::Blocked(_)
    ));
}

#[test]
fn disabled_list_is_excluded() {
    let b = bodies(&[("a", LIST_A), ("b", LIST_B)]);
    let cfg = config(
        &[("a", true), ("b", false)],
        vec![set_cfg("s", &["a", "b"], ""), set_cfg("only-a", &["a"], "")],
    );
    let snap = SnapshotBuilder::new(b).build(&cfg).unwrap();
    assert_eq!(verdict(&snap, "s", "other.example", t(0)), Verdict::Pass);
    assert!(matches!(
        verdict(&snap, "s", "ads.example", t(0)),
        Verdict::Blocked(_)
    ));
    assert_eq!(snap.list_facts(&sid("s")).unwrap().len(), 1);
    // Same effective combination as "only-a": shared.
    assert!(Arc::ptr_eq(
        snap.shared_index(&sid("s")).unwrap(),
        snap.shared_index(&sid("only-a")).unwrap()
    ));
}

#[test]
fn pause_until_time() {
    let b = bodies(&[("a", LIST_A)]);
    let mut s = set_cfg("s", &["a"], "||mine.example^");
    s.paused_until = Some(t(1000));
    s.block_mode = BlockMode::NxDomain;
    let snap = SnapshotBuilder::new(b)
        .build(&config(&[("a", true)], vec![s]))
        .unwrap();
    assert_eq!(verdict(&snap, "s", "ads.example", t(999)), Verdict::Pass);
    assert_eq!(verdict(&snap, "s", "mine.example", t(0)), Verdict::Pass);
    assert!(matches!(
        verdict(&snap, "s", "ads.example", t(1000)),
        Verdict::Blocked(_)
    ));
    assert_eq!(snap.block_mode(&sid("s")), Some(BlockMode::NxDomain));
    assert_eq!(snap.paused_until(&sid("s")), Some(t(1000)));
}

#[test]
fn unknown_set_has_stable_code() {
    let snap = SnapshotBuilder::new(bodies(&[]))
        .build(&FilterConfig::default())
        .unwrap();
    let err = snap
        .match_name(&sid("nope"), &dn("a.example"), 1, t(0))
        .unwrap_err();
    assert_eq!(err.code(), "filter_set.unknown");
}

#[test]
fn config_errors() {
    let b = bodies(&[("a", LIST_A)]);
    let e = SnapshotBuilder::new(b.clone())
        .build(&config(&[("a", true)], vec![set_cfg("s", &["zzz"], "")]))
        .unwrap_err();
    assert_eq!(e.code(), "filter_set.unknown_list");
    let e = SnapshotBuilder::new(b.clone())
        .build(&config(
            &[("a", true)],
            vec![set_cfg("s", &[], ""), set_cfg("s", &[], "")],
        ))
        .unwrap_err();
    assert!(matches!(e, SnapshotError::DuplicateSet(_)));
    let e = SnapshotBuilder::new(b)
        .build(&config(&[("a", true), ("a", true)], vec![]))
        .unwrap_err();
    assert_eq!(e.code(), "filter_set.duplicate_list");
}

#[test]
fn unique_contribution_is_order_dependent() {
    let b = bodies(&[("a", LIST_A), ("b", LIST_B)]);
    let cfg = config(
        &[("a", true), ("b", true)],
        vec![
            set_cfg("ab", &["a", "b"], ""),
            set_cfg("ba", &["b", "a"], ""),
        ],
    );
    let snap = SnapshotBuilder::new(b).build(&cfg).unwrap();
    let ab = snap.list_facts(&sid("ab")).unwrap();
    assert_eq!((ab[0].rules_parsed, ab[0].unique_contribution), (3, 3));
    assert_eq!((ab[1].rules_parsed, ab[1].unique_contribution), (2, 1));
    let ba = snap.list_facts(&sid("ba")).unwrap();
    assert_eq!((ba[0].rules_parsed, ba[0].unique_contribution), (2, 2));
    assert_eq!((ba[1].rules_parsed, ba[1].unique_contribution), (3, 2));
    assert!(ab[0].body_available);
}

#[test]
fn missing_body_contributes_nothing() {
    let b = bodies(&[("a", LIST_A)]);
    let cfg = config(
        &[("a", true), ("b", true)],
        vec![set_cfg("s", &["a", "b"], "")],
    );
    let snap = SnapshotBuilder::new(b).build(&cfg).unwrap();
    let f = snap.list_facts(&sid("s")).unwrap();
    assert!(!f[1].body_available);
    assert_eq!(f[1].rules_parsed, 0);
}

#[test]
fn custom_facts_count_skipped_lines() {
    let b = bodies(&[]);
    let cfg = config(
        &[],
        vec![set_cfg(
            "s",
            &[],
            "||a.example^\n##.cosmetic\n||b.example^\n",
        )],
    );
    let snap = SnapshotBuilder::new(b).build(&cfg).unwrap();
    let f = snap.custom_facts(&sid("s")).unwrap();
    assert_eq!(f.rules_parsed, 2);
    assert_eq!(f.skipped.total(), 1);
}

#[test]
fn list_rule_text_is_resolved_lazily_from_list_bodies() {
    let b = bodies(&[("a", LIST_A)]);
    let cfg = config(
        &[("a", true)],
        vec![set_cfg("s", &["a"], "||mine.example^")],
    );
    let snap = SnapshotBuilder::new(b.clone()).build(&cfg).unwrap();
    let after_build = b.calls.load(Ordering::SeqCst);
    assert_eq!(after_build, 1, "one parse of the single list");
    let Verdict::Blocked(r) = verdict(&snap, "s", "tracker.example", t(0)) else {
        panic!("expected block");
    };
    assert_eq!(&*r.rule, "||tracker.example^");
    assert_eq!(
        r.source,
        RuleSource::List {
            list: lid("a"),
            line: 3
        }
    );
    assert!(b.calls.load(Ordering::SeqCst) > after_build);
    // Custom text needs no list body.
    let before = b.calls.load(Ordering::SeqCst);
    let Verdict::Blocked(r) = verdict(&snap, "s", "mine.example", t(0)) else {
        panic!("expected block");
    };
    assert_eq!(&*r.rule, "||mine.example^");
    assert_eq!(b.calls.load(Ordering::SeqCst), before);
}

#[test]
fn merged_custom_text_and_priority() {
    let b = bodies(&[("a", LIST_A)]);
    let cfg = config(
        &[("a", true)],
        vec![set_cfg(
            "s",
            &["a"],
            "||ads.example^$badfilter\n@@||tracker.example^\n",
        )],
    );
    let snap = SnapshotBuilder::new(b).build(&cfg).unwrap();
    let Verdict::Allowed(r) = verdict(&snap, "s", "tracker.example", t(0)) else {
        panic!("expected allow");
    };
    assert_eq!(&*r.rule, "@@||tracker.example^");
    assert_eq!(
        r.source,
        RuleSource::Custom {
            set: sid("s"),
            line: 2
        }
    );
    assert_eq!(verdict(&snap, "s", "ads.example", t(0)), Verdict::Pass);
}

// ---------------------------------------------------------------------------
// Real lists (manual): cargo test --release -p dnscraft-filtering --test sets -- --ignored --nocapture

const REAL_FILES: [&str; 19] = [
    "filter_1.txt",
    "filter_2.txt",
    "adaway_hosts.txt",
    "easylistgermany.txt",
    "stevenblack_hosts.txt",
    "filter_7.txt",
    "filter_8.txt",
    "filter_30.txt",
    "filter_10.txt",
    "filter_6.txt",
    "filter_23.txt",
    "easyprivacy.txt",
    "filter_70.txt",
    "filter_27.txt",
    "filter_49.txt",
    "filter_47.txt",
    "filter_63.txt",
    "filter_71.txt",
    "filter_52.txt",
];

fn vm_kib(key: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix(key))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(0)
}

#[test]
#[ignore = "needs target/reference-lists/ (see examples/parse_lists.rs)"]
fn real_lists_snapshot() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/reference-lists");
    if !dir.is_dir() {
        eprintln!("skipped: {} does not exist", dir.display());
        return;
    }
    let mut map = HashMap::new();
    let mut ids = Vec::new();
    let mut body_bytes = 0usize;
    for (i, f) in REAL_FILES.iter().enumerate() {
        let id = format!("ref-{i:02}");
        match std::fs::read_to_string(dir.join(f)) {
            Ok(s) => {
                body_bytes += s.len();
                map.insert(lid(&id), Arc::<str>::from(s));
            }
            Err(e) => eprintln!("missing {f}: {e}"),
        }
        ids.push(id);
    }
    let bodies = Arc::new(MapBodies {
        map,
        calls: AtomicUsize::new(0),
    });
    let lists: Vec<(&str, bool)> = ids.iter().map(|i| (i.as_str(), true)).collect();
    let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let cfg = config(&lists, vec![set_cfg("all", &id_refs, "")]);

    // Bodies are held by the test's map (as the on-disk store would not);
    // the baseline therefore includes them.
    let before = vm_kib("VmHWM:");
    let rss_before = vm_kib("VmRSS:");
    let start = Instant::now();
    let snap = SnapshotBuilder::new(bodies).build(&cfg).unwrap();
    let took = start.elapsed();
    let after = vm_kib("VmHWM:");
    let rss_after = vm_kib("VmRSS:");
    let shared = snap.shared_index(&sid("all")).unwrap();
    let m = shared.index.memory();
    println!("bodies in test map: {:.1} MB", body_bytes as f64 / 1e6);
    println!("build time: {took:?}");
    println!(
        "VmHWM before {:.1} MB, after {:.1} MB; VmRSS before {:.1} MB, after {:.1} MB",
        before as f64 / 1024.0,
        after as f64 / 1024.0,
        rss_before as f64 / 1024.0,
        rss_after as f64 / 1024.0
    );
    println!(
        "index: entries {}, patterns {}, duplicates {}, badfiltered {}",
        m.entries,
        shared.index.pattern_count(),
        shared.index.duplicates(),
        shared.index.badfiltered()
    );
    println!(
        "index bytes: names {:.1} MB + overhead {:.1} MB + side {:.1} MB = {:.1} MB",
        m.name_bytes as f64 / 1e6,
        m.overhead_bytes as f64 / 1e6,
        m.side_bytes as f64 / 1e6,
        (m.name_bytes + m.overhead_bytes + m.side_bytes) as f64 / 1e6
    );
    for f in &shared.lists {
        println!(
            "  {}: parsed {}, skipped {}, unique {}",
            f.list,
            f.rules_parsed,
            f.skipped.total(),
            f.unique_contribution
        );
    }
    assert!(m.entries > 0);
}
