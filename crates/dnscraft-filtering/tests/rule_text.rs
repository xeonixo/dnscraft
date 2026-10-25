//! Rule-text lookup of store-backed snapshots (D1a items 1, 2 and 6).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    DomainName, FilterConfig, FilterSetConfig, IndexBuilder, ListBodies, ListConfig, ListId,
    ListMeta, ListSourceSpec, ListStore, RuleSource, SetId, Snapshot, SnapshotBuilder,
    StoreListBodies, Verdict, parse_rule,
};

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("dnscraft-rt-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn lid() -> ListId {
    ListId::new("l").unwrap()
}
fn sid() -> SetId {
    SetId::new("s").unwrap()
}
fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000)
}

fn config() -> FilterConfig {
    let mut set = FilterSetConfig::new(sid(), "s");
    set.lists = vec![lid()];
    FilterConfig {
        lists: vec![ListConfig {
            id: lid(),
            name: "l".into(),
            source: ListSourceSpec::Url("https://example.invalid/l.txt".into()),
            enabled: true,
        }],
        sets: vec![set],
        ..FilterConfig::default()
    }
}

fn build(bodies: &Arc<StoreListBodies>) -> Snapshot {
    SnapshotBuilder::new(Arc::clone(bodies) as Arc<dyn ListBodies>)
        .build(&config())
        .unwrap()
}

fn blocked(snap: &Snapshot, name: &str) -> (String, u32) {
    let name: DomainName = name.parse().unwrap();
    match snap.match_name(&sid(), &name, 1, now()).unwrap() {
        Verdict::Blocked(r) => {
            let line = match r.source {
                RuleSource::List { line, .. } => line,
                other => panic!("unexpected source {other:?}"),
            };
            (r.rule.to_string(), line)
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
}

fn setup() -> (TempDir, ListStore, Arc<StoreListBodies>) {
    let t = TempDir::new();
    let store = ListStore::open(t.path()).unwrap();
    let bodies = Arc::new(StoreListBodies::new(store.clone(), HashMap::new()));
    (t, store, bodies)
}

#[test]
fn rule_text_is_not_stale_after_body_replacement() {
    let (_t, store, bodies) = setup();
    store
        .write_body(&lid(), "||ads.example^\n", &ListMeta::default())
        .unwrap();
    let old = build(&bodies);
    assert_eq!(blocked(&old, "ads.example"), ("||ads.example^".into(), 1));

    store
        .write_body(&lid(), "||ads2.example^\n", &ListMeta::default())
        .unwrap();
    let new = build(&bodies);
    assert_eq!(blocked(&new, "ads2.example"), ("||ads2.example^".into(), 1));
}

#[test]
fn old_snapshot_keeps_reading_its_own_bytes() {
    let (_t, store, bodies) = setup();
    store
        .write_body(
            &lid(),
            "! header\n! more\n||ads.example^\n||tracker.example^\n",
            &ListMeta::default(),
        )
        .unwrap();
    let old = build(&bodies);

    // The replacement has different content at the same offsets.
    store
        .write_body(&lid(), "||zzz.example^\n", &ListMeta::default())
        .unwrap();
    let new = build(&bodies);

    // Not cached before the replacement: read after it.
    assert_eq!(
        blocked(&old, "tracker.example"),
        ("||tracker.example^".into(), 4)
    );
    assert_eq!(blocked(&old, "ads.example"), ("||ads.example^".into(), 3));
    assert_eq!(blocked(&new, "zzz.example"), ("||zzz.example^".into(), 1));
}

#[test]
fn deep_rules_report_correct_line_and_text() {
    let (_t, store, bodies) = setup();
    let mut body = String::new();
    for i in 0..60_000u32 {
        body.push_str(&format!("||host{i}.example^\n"));
    }
    store
        .write_body(&lid(), &body, &ListMeta::default())
        .unwrap();
    let snap = build(&bodies);
    for i in [0u32, 1, 255, 4_095, 4_096, 30_000, 59_999] {
        let (text, line) = blocked(&snap, &format!("host{i}.example"));
        assert_eq!(text, format!("||host{i}.example^"), "i={i}");
        assert_eq!(line, i + 1, "i={i}");
    }
}

#[test]
fn crlf_and_trailing_blanks_are_trimmed_like_the_parser() {
    let (_t, store, bodies) = setup();
    store
        .write_body(
            &lid(),
            "||a.example^ \t\r\n||b.example^\x0b\x0c\r\n",
            &ListMeta::default(),
        )
        .unwrap();
    let snap = build(&bodies);
    assert_eq!(blocked(&snap, "a.example").0, "||a.example^");
    assert_eq!(blocked(&snap, "b.example").0, "||b.example^");
}

#[test]
fn file_list_source_text_comes_from_the_pinned_file() {
    let t = TempDir::new();
    let store = ListStore::open(t.path()).unwrap();
    let path = t.path().join("mine.txt");
    fs::write(&path, "||ads.example^\n").unwrap();
    let bodies = Arc::new(StoreListBodies::new(
        store,
        HashMap::from([(lid(), path.clone())]),
    ));
    let old = build(&bodies);
    // Atomic replace of the user's file (rename over the path).
    let tmp = t.path().join("mine.txt.new");
    fs::write(&tmp, "! x\n||other.example^\n").unwrap();
    fs::rename(&tmp, &path).unwrap();
    assert_eq!(blocked(&old, "ads.example"), ("||ads.example^".into(), 1));
    let new = build(&bodies);
    assert_eq!(
        blocked(&new, "other.example"),
        ("||other.example^".into(), 2)
    );
}

#[test]
fn invalid_utf8_list_still_reports_text() {
    let (_t, store, bodies) = setup();
    let mut body = b"! caf\xe9 \xff\n||ads.example^\n".to_vec();
    body.extend_from_slice(b"||tracker.example^\n");
    // `write_body` takes &str; write the raw bytes where the store reads them.
    store.write_body(&lid(), "", &ListMeta::default()).unwrap();
    fs::write(store.body_path(&lid()), &body).unwrap();
    let snap = build(&bodies);
    assert_eq!(blocked(&snap, "ads.example"), ("||ads.example^".into(), 2));
    assert_eq!(
        blocked(&snap, "tracker.example"),
        ("||tracker.example^".into(), 3)
    );
}

/// Entries removed by `$badfilter` sit inside their name group; duplicates
/// after them must still be collapsed.
#[test]
fn dedup_continues_past_badfiltered_entries_in_a_name_group() {
    let mut b = IndexBuilder::new();
    let s1 = b
        .add_source(dnscraft_filtering::SourceKind::List(lid()))
        .unwrap();
    let s2 = b
        .add_source(dnscraft_filtering::SourceKind::List(
            ListId::new("m").unwrap(),
        ))
        .unwrap();
    let rule = |t: &str| parse_rule(t).unwrap();
    b.add_rule(rule("||x.example^$dnstype=MX"), s1).unwrap();
    b.add_rule(rule("||x.example^$dnstype=A"), s1).unwrap();
    b.add_rule(rule("||x.example^$dnstype=MX"), s2).unwrap();
    b.add_rule(rule("||x.example^$dnstype=A,badfilter"), s2)
        .unwrap();
    let idx = b.build_in_memory();
    assert_eq!(idx.badfiltered(), 1);
    assert_eq!(idx.duplicates(), 1);
    assert_eq!(idx.len(), 1);
}
