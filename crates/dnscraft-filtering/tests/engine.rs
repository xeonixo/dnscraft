//! Task M3: chain matching, temporary allows, pause, counters.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    DomainName, FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListConfig, ListId,
    ListSourceSpec, RuleSource, SetId, SnapshotBuilder, TempAllow, Verdict,
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

fn engine(lists: &[(&str, &str)], custom: &str) -> FilterEngine {
    let bodies = Arc::new(MapBodies {
        map: lists
            .iter()
            .map(|(id, body)| (lid(id), Arc::from(*body)))
            .collect(),
    });
    let mut set = FilterSetConfig::new(sid("s"), "s");
    set.lists = lists.iter().map(|(id, _)| lid(id)).collect();
    set.custom_rules = custom.to_owned();
    let cfg = FilterConfig {
        lists: lists
            .iter()
            .map(|(id, _)| ListConfig {
                id: lid(id),
                name: (*id).to_owned(),
                source: ListSourceSpec::Url(format!("https://example.invalid/{id}.txt")),
                enabled: true,
            })
            .collect(),
        sets: vec![set],
        ..FilterConfig::default()
    };
    FilterEngine::from_snapshot(SnapshotBuilder::new(bodies).build(&cfg).unwrap())
}

fn chain(eng: &FilterEngine, names: &[&str], now: SystemTime) -> Verdict {
    let owned: Vec<DomainName> = names.iter().map(|n| dn(n)).collect();
    eng.match_chain(&sid("s"), &owned, 1, now).unwrap()
}

fn snap_chain(lists: &[(&str, &str)], custom: &str, names: &[&str], now: SystemTime) -> Verdict {
    let eng = engine(lists, custom);
    let owned: Vec<DomainName> = names.iter().map(|n| dn(n)).collect();
    eng.snapshot()
        .match_chain(&sid("s"), &owned, 1, now)
        .unwrap()
}

// --- chain -----------------------------------------------------------------

#[test]
fn chain_blocked_cname_target_blocks() {
    let v = snap_chain(
        &[("a", "||tracker.example^\n")],
        "",
        &["page.example", "tracker.example"],
        t(0),
    );
    let Verdict::Blocked(r) = v else {
        panic!("expected block, got {v:?}");
    };
    assert!(r.rule.contains("tracker.example"));
}

#[test]
fn chain_non_important_allow_on_qname_does_not_unblock_cname() {
    // @@||safe.example^ on the queried name must not unblock a blocked CNAME.
    let v = snap_chain(
        &[("a", "||tracker.example^\n")],
        "@@||safe.example^\n",
        &["safe.example", "tracker.example"],
        t(0),
    );
    assert!(
        matches!(v, Verdict::Blocked(_)),
        "plain allow on qname must not unblock CNAME: {v:?}"
    );
}

#[test]
fn chain_important_allow_on_qname_unblocks_cname() {
    let v = snap_chain(
        &[("a", "||tracker.example^\n")],
        "@@||safe.example^$important\n",
        &["safe.example", "tracker.example"],
        t(0),
    );
    let Verdict::Allowed(r) = v else {
        panic!("expected important allow, got {v:?}");
    };
    assert!(r.important);
    assert!(r.rule.contains("safe.example"));
}

#[test]
fn chain_important_allow_on_target_unblocks() {
    // Important allow on the CNAME target beats its block; chain returns qname's Pass.
    let v = snap_chain(
        &[("a", "||tracker.example^\n")],
        "@@||tracker.example^$important\n",
        &["page.example", "tracker.example"],
        t(0),
    );
    assert_eq!(v, Verdict::Pass, "got {v:?}");
}

#[test]
fn chain_first_blocking_wins_among_several_cnames() {
    let v = snap_chain(
        &[("a", "||mid.example^\n||end.example^\n")],
        "",
        &["start.example", "mid.example", "end.example"],
        t(0),
    );
    let Verdict::Blocked(r) = v else {
        panic!("expected block, got {v:?}");
    };
    assert!(
        r.rule.contains("mid.example"),
        "first block should win: {}",
        r.rule
    );
}

#[test]
fn chain_empty_is_pass() {
    let eng = engine(&[("a", "||ads.example^\n")], "");
    let v = eng.match_chain(&sid("s"), &[], 1, t(0)).unwrap();
    assert_eq!(v, Verdict::Pass);
}

#[test]
fn chain_qname_block_wins_before_later_names() {
    let v = snap_chain(
        &[("a", "||ads.example^\n||tracker.example^\n")],
        "",
        &["ads.example", "tracker.example"],
        t(0),
    );
    let Verdict::Blocked(r) = v else {
        panic!("expected block, got {v:?}");
    };
    assert!(r.rule.contains("ads.example"));
}

#[test]
fn chain_unknown_set() {
    let eng = engine(&[("a", "")], "");
    let err = eng
        .match_chain(&sid("nope"), &[dn("a.example")], 1, t(0))
        .unwrap_err();
    assert_eq!(err.code(), "filter_set.unknown");
}

// --- temporary allows ------------------------------------------------------

#[test]
fn temp_allow_ranks_like_important_and_expires_exactly() {
    let eng = engine(&[("a", "||ads.example^\n")], "");
    eng.allow_temporarily(
        &sid("s"),
        TempAllow {
            domain: dn("ads.example"),
            include_subdomains: false,
            until: t(100),
        },
    )
    .unwrap();

    let before = eng
        .match_name(&sid("s"), &dn("ads.example"), 1, t(99))
        .unwrap();
    let Verdict::Allowed(r) = before else {
        panic!("expected temp allow, got {before:?}");
    };
    assert!(r.important);
    assert_eq!(r.source, RuleSource::TemporaryAllow);

    let at = eng
        .match_name(&sid("s"), &dn("ads.example"), 1, t(100))
        .unwrap();
    assert!(
        matches!(at, Verdict::Blocked(_)),
        "must expire exactly at until: {at:?}"
    );
}

#[test]
fn temp_allow_include_subdomains_and_list_remove() {
    let eng = engine(&[("a", "||ads.example^\n")], "");
    eng.allow_temporarily(
        &sid("s"),
        TempAllow {
            domain: dn("ads.example"),
            include_subdomains: true,
            until: t(100),
        },
    )
    .unwrap();
    assert!(matches!(
        eng.match_name(&sid("s"), &dn("x.ads.example"), 1, t(0))
            .unwrap(),
        Verdict::Allowed(_)
    ));

    let listed = eng.list_temporary_allows(&sid("s"), t(0)).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].domain, dn("ads.example"));
    assert!(listed[0].include_subdomains);

    assert!(
        eng.remove_temporary_allow(&sid("s"), &dn("ads.example"))
            .unwrap()
    );
    assert!(
        eng.list_temporary_allows(&sid("s"), t(0))
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        eng.match_name(&sid("s"), &dn("ads.example"), 1, t(0))
            .unwrap(),
        Verdict::Blocked(_)
    ));

    // Expired entries are omitted from the list (and pruned).
    eng.allow_temporarily(
        &sid("s"),
        TempAllow {
            domain: dn("ads.example"),
            include_subdomains: true,
            until: t(100),
        },
    )
    .unwrap();
    assert!(
        eng.list_temporary_allows(&sid("s"), t(100))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn temp_allow_on_qname_unblocks_chain_like_important() {
    let eng = engine(&[("a", "||tracker.example^\n")], "");
    eng.allow_temporarily(
        &sid("s"),
        TempAllow {
            domain: dn("page.example"),
            include_subdomains: false,
            until: t(100),
        },
    )
    .unwrap();
    let v = chain(&eng, &["page.example", "tracker.example"], t(0));
    assert!(
        matches!(v, Verdict::Allowed(ref r) if r.source == RuleSource::TemporaryAllow),
        "{v:?}"
    );
}

#[test]
fn temp_allow_on_target_unblocks_chain() {
    let eng = engine(&[("a", "||tracker.example^\n")], "");
    eng.allow_temporarily(
        &sid("s"),
        TempAllow {
            domain: dn("tracker.example"),
            include_subdomains: false,
            until: t(100),
        },
    )
    .unwrap();
    let v = chain(&eng, &["page.example", "tracker.example"], t(0));
    assert_eq!(v, Verdict::Pass, "{v:?}");
}

#[test]
fn temp_allow_does_not_rebuild_snapshot() {
    let eng = engine(&[("a", "||ads.example^\n")], "");
    let before = eng.snapshot_arc();
    eng.allow_temporarily(
        &sid("s"),
        TempAllow {
            domain: dn("ads.example"),
            include_subdomains: false,
            until: t(100),
        },
    )
    .unwrap();
    assert!(
        Arc::ptr_eq(&before, &eng.snapshot_arc()),
        "adding a temp allow must not replace the snapshot"
    );
}

#[test]
fn temp_allow_unknown_set() {
    let eng = engine(&[("a", "")], "");
    let err = eng
        .allow_temporarily(
            &sid("nope"),
            TempAllow {
                domain: dn("a.example"),
                include_subdomains: false,
                until: t(1),
            },
        )
        .unwrap_err();
    assert_eq!(err.code(), "filter_set.unknown");
}

// --- pause -----------------------------------------------------------------

#[test]
fn pause_returns_pass_until_deadline() {
    let bodies = Arc::new(MapBodies {
        map: HashMap::from([(lid("a"), Arc::from("||ads.example^\n"))]),
    });
    let mut set = FilterSetConfig::new(sid("s"), "s");
    set.lists = vec![lid("a")];
    set.paused_until = Some(t(1000));
    let cfg = FilterConfig {
        lists: vec![ListConfig {
            id: lid("a"),
            name: "a".into(),
            source: ListSourceSpec::Url("https://example.invalid/a.txt".into()),
            enabled: true,
        }],
        sets: vec![set],
        ..FilterConfig::default()
    };
    let eng = FilterEngine::from_snapshot(SnapshotBuilder::new(bodies).build(&cfg).unwrap());
    assert_eq!(
        eng.match_name(&sid("s"), &dn("ads.example"), 1, t(999))
            .unwrap(),
        Verdict::Pass
    );
    assert!(matches!(
        eng.match_name(&sid("s"), &dn("ads.example"), 1, t(1000))
            .unwrap(),
        Verdict::Blocked(_)
    ));
    // Temps do not override pause.
    eng.allow_temporarily(
        &sid("s"),
        TempAllow {
            domain: dn("ads.example"),
            include_subdomains: false,
            until: t(2000),
        },
    )
    .unwrap();
    assert_eq!(
        eng.match_name(&sid("s"), &dn("ads.example"), 1, t(500))
            .unwrap(),
        Verdict::Pass
    );
}

// --- counters --------------------------------------------------------------

#[test]
fn stats_increment_once_per_match_call() {
    let eng = engine(
        &[("a", "||ads.example^\n||other.example^\n")],
        "@@||ok.example^\n",
    );

    eng.match_name(&sid("s"), &dn("ads.example"), 1, t(0))
        .unwrap(); // block from list a
    eng.match_name(&sid("s"), &dn("ok.example"), 1, t(0))
        .unwrap(); // allow from custom
    eng.match_name(&sid("s"), &dn("none.example"), 1, t(0))
        .unwrap(); // pass
    // Chain of 3 names, one block: still one match call.
    let _ = chain(&eng, &["page.example", "mid.example", "ads.example"], t(0));

    let stats = eng.stats();
    let set = stats.sets.iter().find(|s| s.set == sid("s")).unwrap();
    assert_eq!(set.matches, 4, "{set:?}");
    assert_eq!(set.blocks, 2, "one name block + one chain block: {set:?}");
    assert_eq!(set.allows, 1, "{set:?}");

    let list = stats.lists.iter().find(|l| l.list == lid("a")).unwrap();
    // List wins on the direct block and the chain block; custom allow does not
    // touch list counters; pass does not either.
    assert_eq!(list.matches, 2, "{list:?}");
    assert_eq!(list.blocks, 2, "{list:?}");
    assert_eq!(list.allows, 0, "{list:?}");
}
