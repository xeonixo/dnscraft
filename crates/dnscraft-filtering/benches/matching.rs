//! Criterion benches for Task M4 / Checkpoint B.
//!
//! Success criteria (SPEC-filtering.md): match p99 < 10 µs warm; reference-set
//! build < 10 s. Run with:
//! ```text
//! cargo bench -p dnscraft-filtering --features testgen --bench matching -- --sample-size 50
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use dnscraft_filtering::testgen::{self, Probes};
use dnscraft_filtering::{
    DomainName, FilterConfig, FilterSetConfig, Index, IndexBuilder, ListBodies, ListConfig, ListId,
    ListMeta, ListSourceSpec, ListStore, SetId, SnapshotBuilder, StoreListBodies, Verdict,
};

const QTYPE_A: u16 = 1;

fn build_index() -> (Index, Probes) {
    testgen::build_reference_index().expect("reference index")
}

/// Collect wall-time samples for a warm match closure; print p50/p99.
fn report_percentiles(label: &str, samples: usize, mut f: impl FnMut()) {
    // Warm up.
    for _ in 0..100 {
        f();
    }
    let mut times = Vec::with_capacity(samples);
    for _ in 0..samples {
        let t0 = Instant::now();
        f();
        times.push(t0.elapsed());
    }
    times.sort_unstable();
    let p50 = times[samples / 2];
    let p99 = times[samples.saturating_mul(99) / 100];
    eprintln!(
        "PERCENTILES {label}: n={samples} p50={:.3}µs p99={:.3}µs",
        p50.as_secs_f64() * 1e6,
        p99.as_secs_f64() * 1e6
    );
}

fn matching(c: &mut Criterion) {
    eprintln!(
        "Building reference index (~{} rules across lists)…",
        testgen::total_rules_across_lists()
    );
    let t0 = Instant::now();
    let (idx, probes) = build_index();
    let build_once = t0.elapsed();
    let mem = idx.memory();
    eprintln!(
        "Build wall time (one-shot, includes generation): {:.3}s; Index::memory entries={} names={:.1}MB overhead={:.1}MB side={:.1}MB",
        build_once.as_secs_f64(),
        mem.entries,
        mem.name_bytes as f64 / (1024.0 * 1024.0),
        mem.overhead_bytes as f64 / (1024.0 * 1024.0),
        mem.side_bytes as f64 / (1024.0 * 1024.0),
    );

    // Explicit p50/p99 from raw samples (criterion CI is around the mean/median).
    const N: usize = 1_000;
    report_percentiles("match_hit", N, || {
        black_box(idx.match_name(black_box(&probes.hit), QTYPE_A));
    });
    report_percentiles("match_miss", N, || {
        black_box(idx.match_name(black_box(&probes.miss), QTYPE_A));
    });
    report_percentiles("match_deep_10", N, || {
        black_box(idx.match_name(black_box(&probes.deep), QTYPE_A));
    });
    report_percentiles("match_chain_3", N, || {
        black_box(match_chain3(&idx, &probes.chain));
    });
    report_percentiles("match_ip", N, || {
        black_box(idx.match_answer_ip(black_box(probes.ip_hit)));
    });

    assert!(
        matches!(idx.match_name(&probes.hit, QTYPE_A), Verdict::Blocked(_)),
        "hit probe must block"
    );
    assert!(
        matches!(idx.match_name(&probes.miss, QTYPE_A), Verdict::Pass),
        "miss probe must pass"
    );
    assert!(
        matches!(idx.match_name(&probes.deep, QTYPE_A), Verdict::Blocked(_)),
        "deep probe must block via suffix"
    );
    assert!(
        matches!(idx.match_answer_ip(probes.ip_hit), Verdict::Blocked(_)),
        "ip hit must block"
    );
    assert!(
        matches!(idx.match_answer_ip(probes.ip_miss), Verdict::Pass),
        "ip miss must pass"
    );

    c.bench_function("match_hit", |b| {
        b.iter(|| black_box(idx.match_name(black_box(&probes.hit), black_box(QTYPE_A))));
    });
    c.bench_function("match_miss", |b| {
        b.iter(|| black_box(idx.match_name(black_box(&probes.miss), black_box(QTYPE_A))));
    });
    c.bench_function("match_deep_10", |b| {
        b.iter(|| black_box(idx.match_name(black_box(&probes.deep), black_box(QTYPE_A))));
    });
    c.bench_function("match_chain_3", |b| {
        b.iter(|| black_box(match_chain3(&idx, black_box(&probes.chain))));
    });
    c.bench_function("match_ip", |b| {
        b.iter(|| black_box(idx.match_answer_ip(black_box(probes.ip_hit))));
    });
}

/// Work of a 3-name CNAME chain: three lookups (first block wins semantics are
/// exercised by the probe setup — names[2] is the blocked target).
fn match_chain3(idx: &Index, names: &[dnscraft_filtering::DomainName; 3]) -> Verdict {
    let mut last = Verdict::Pass;
    for name in names {
        let v = idx.match_name(name, QTYPE_A);
        if matches!(v, Verdict::Blocked(_) | Verdict::Rewrite(_, _)) {
            return v;
        }
        if !matches!(v, Verdict::Pass) {
            last = v;
        }
    }
    last
}

/// Verdicts whose rule text comes from the store-backed, checkpointed reader
/// (a ~44 MB generated body, as in the reference set). Cold = distinct rules
/// at spread-out offsets, so every match reads from disk once.
fn store_backed_text(c: &mut Criterion) {
    const LINES: usize = 2_000_000;
    let dir = std::env::temp_dir().join(format!("dnscraft-bench-text-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let store = ListStore::open(&dir).expect("store");
    let lid = ListId::new("big").expect("list id");
    let mut body = String::with_capacity(LINES * 24);
    for i in 0..LINES {
        body.push_str(&format!("||host{i:07}.example^\n"));
    }
    store
        .write_body(&lid, &body, &ListMeta::default())
        .expect("write body");
    eprintln!("store-backed body: {:.1} MB", body.len() as f64 / 1e6);
    drop(body);

    let sid = SetId::new("s").expect("set id");
    let mut set = FilterSetConfig::new(sid.clone(), "s");
    set.lists = vec![lid.clone()];
    let cfg = FilterConfig {
        lists: vec![ListConfig {
            id: lid,
            name: "big".into(),
            source: ListSourceSpec::Url("https://example.invalid/big.txt".into()),
            enabled: true,
        }],
        sets: vec![set],
        ..FilterConfig::default()
    };
    let bodies = std::sync::Arc::new(StoreListBodies::new(store, Default::default()));
    let snap = SnapshotBuilder::new(bodies as std::sync::Arc<dyn ListBodies>)
        .build(&cfg)
        .expect("snapshot");
    let now = std::time::SystemTime::UNIX_EPOCH;
    let names: Vec<DomainName> = (0..LINES)
        .step_by(LINES / 1_000)
        .map(|i| format!("host{i:07}.example").parse().expect("name"))
        .collect();

    // Cold: first lookup of each of 1000 distinct rules (cache misses).
    let mut times = Vec::with_capacity(names.len());
    for n in &names {
        let t0 = Instant::now();
        black_box(snap.match_name(&sid, n, QTYPE_A, now).expect("match"));
        times.push(t0.elapsed());
    }
    times.sort_unstable();
    eprintln!(
        "PERCENTILES store_text_cold: n={} p50={:.3}µs p99={:.3}µs",
        times.len(),
        times[times.len() / 2].as_secs_f64() * 1e6,
        times[times.len() * 99 / 100].as_secs_f64() * 1e6
    );
    c.bench_function("store_text_warm", |b| {
        b.iter(|| {
            black_box(
                snap.match_name(&sid, black_box(&names[17]), QTYPE_A, now)
                    .expect("match"),
            )
        });
    });
    let _ = std::fs::remove_dir_all(&dir);
}

fn build(c: &mut Criterion) {
    // Few samples: a full reference build is multi-second.
    let mut group = c.benchmark_group("build");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));
    group.warm_up_time(Duration::from_secs(1));
    group.bench_function("reference_set", |b| {
        b.iter_with_large_drop(|| {
            let mut builder = IndexBuilder::new();
            let _probes = testgen::feed_reference_set(&mut builder).expect("feed");
            black_box(builder.build_in_memory())
        });
    });
    group.finish();
}

criterion_group!(benches, matching, store_backed_text, build);
criterion_main!(benches);
