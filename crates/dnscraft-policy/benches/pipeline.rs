//! Criterion bench: cached resolve + filter miss end-to-end (SPEC criterion 5).
//!
//! Success bar: p50 < 1 ms. Run with:
//! ```text
//! cargo bench -p dnscraft-policy --bench pipeline -- --sample-size 30
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use criterion::{Criterion, criterion_group, criterion_main};
use dnscraft_filtering::{
    FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ManualClock, SetId,
    SnapshotBuilder,
};
use dnscraft_policy::{
    ClientFlags, DnsProtocol, ListenerId, NoClients, PolicyConfig, PolicyEngine, ProfileConfig,
    ProfileId, RequestContext, SafeSearchConfig, ViewConfig, ViewId,
};
use dnscraft_proto::{Class, Name, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{Query, Resolver, ResolverConfig};
use dnscraft_testkit::Hierarchy;
use tokio::runtime::Runtime;

#[derive(Debug, Default)]
struct EmptyBodies;

impl ListBodies for EmptyBodies {
    fn body(&self, _id: &ListId) -> Option<Arc<str>> {
        None
    }
}

fn build_engine(rt: &Runtime) -> (Hierarchy, PolicyEngine) {
    rt.block_on(async {
        let h = Hierarchy::start().await.unwrap();
        let overrides = h
            .nameserver_addrs()
            .iter()
            .map(|(n, a)| (Name::from_ascii(&n.to_string()).unwrap(), *a))
            .collect::<HashMap<_, _>>();
        let resolver = Arc::new(
            Resolver::new(ResolverConfig {
                root_hints: h.root_hints(),
                query_timeout: Duration::from_millis(500),
                nameserver_addr_overrides: overrides,
                trust_anchors: TrustAnchors::empty(),
                prefetch: false,
                ..ResolverConfig::default()
            })
            .await
            .unwrap(),
        );
        let set = FilterSetConfig::new(SetId::new("default").unwrap(), "default");
        let filter = Arc::new(FilterEngine::from_snapshot(
            SnapshotBuilder::new(Arc::new(EmptyBodies) as Arc<dyn ListBodies>)
                .build(&FilterConfig {
                    lists: Vec::new(),
                    sets: vec![set],
                    ..FilterConfig::default()
                })
                .unwrap(),
        ));
        let cfg = PolicyConfig {
            client_ids: Vec::new(),
            records: Vec::new(),
            default_rebind: true,
            ptr_prefixes: Vec::new(),
            local_nxdomain_suffixes: Vec::new(),
            rebind_check_forward_zones: Vec::new(),
            views: vec![ViewConfig {
                id: ViewId::new("default").unwrap(),
                is_default: true,
                subnets: Vec::new(),
                nodes: Vec::new(),
                profile: ProfileId::new("default").unwrap(),
            }],
            profiles: vec![ProfileConfig {
                id: ProfileId::new("default").unwrap(),
                filter_set: SetId::new("default").unwrap(),
                suppress_aaaa: false,
                firefox_canary: false,
                icloud_private_relay: false,
                rebind: Some(true),
                rebind_exceptions: Vec::new(),
                forward_zones: None,
                safesearch: SafeSearchConfig::default(),
                schedules: Vec::new(),
            }],
        };
        let clock = Arc::new(ManualClock::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
        ));
        let eng = PolicyEngine::new(cfg, filter, resolver, Arc::new(NoClients), clock).unwrap();
        (h, eng)
    })
}

fn ctx(name: &str) -> RequestContext {
    RequestContext {
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        protocol: DnsProtocol::Udp53,
        listener_id: ListenerId::new("udp-53").unwrap(),
        node_id: None,
        client_id: None,
        query: Query {
            name: Name::from_ascii(name).unwrap(),
            qtype: RecordType::A,
            qclass: Class::IN,
        },
        flags: ClientFlags::default(),
        test_query: false,
    }
}

fn report_percentiles(label: &str, samples: &[Duration]) {
    let mut times = samples.to_vec();
    times.sort_unstable();
    let n = times.len();
    let p50 = times[n / 2];
    let p99 = times[n.saturating_mul(99) / 100];
    eprintln!(
        "PERCENTILES {label}: n={n} p50={:.3}µs p99={:.3}µs",
        p50.as_secs_f64() * 1e6,
        p99.as_secs_f64() * 1e6
    );
    assert!(
        p50 < Duration::from_millis(1),
        "{label} p50 {:?} exceeds 1 ms budget",
        p50
    );
}

fn pipeline(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let (_h, eng) = build_engine(&rt);

    // Warm the resolver cache (and path) with a public name; filter set is empty → miss.
    let name = "www.example.test.";
    for _ in 0..5 {
        let _ = rt.block_on(eng.handle(ctx(name)));
    }

    const N: usize = 200;
    let mut samples = Vec::with_capacity(N);
    for _ in 0..N {
        let t0 = Instant::now();
        let ans = rt.block_on(eng.handle(ctx(name))).unwrap();
        samples.push(t0.elapsed());
        black_box(ans);
    }
    report_percentiles("cache_hit_filter_miss", &samples);

    // Criterion wall-time sample (sync wrapper around the runtime).
    c.bench_function("handle_cached_a", |b| {
        b.iter(|| {
            black_box(rt.block_on(eng.handle(ctx(name))).unwrap());
        });
    });
}

criterion_group!(benches, pipeline);
criterion_main!(benches);
