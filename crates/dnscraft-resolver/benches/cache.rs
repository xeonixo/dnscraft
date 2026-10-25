//! Cache-hit microbench: store one positive A answer, then look it up.
//!
//! Success criterion 4 requires cache-hit p50 < 1 ms. Run with:
//! `cargo bench -p dnscraft-resolver --bench cache`

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::hint::black_box;
use std::net::Ipv4Addr;
use std::time::Instant;

use criterion::{Criterion, criterion_group, criterion_main};
use dnscraft_proto::{Class, Header, Message, Name, Question, RData, Rcode, Record, RecordType};
use dnscraft_resolver::{__BenchCache, __BenchTtlClamp, DnssecStatus, Query};

fn positive_a(name: &Name) -> Message {
    Message {
        header: Header {
            qr: true,
            ra: true,
            rcode_low: Rcode::NOERROR.low(),
            ..Header::default()
        },
        questions: vec![Question {
            name: name.clone(),
            qtype: RecordType::A,
            qclass: Class::IN,
        }],
        answers: vec![Record {
            name: name.clone(),
            class: Class::IN,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(93, 184, 216, 34)),
        }],
        authorities: vec![],
        additionals: vec![],
        edns: None,
    }
}

fn cache_hit(c: &mut Criterion) {
    let name = Name::from_ascii("www.example.test.").expect("name");
    let query = Query {
        name: name.clone(),
        qtype: RecordType::A,
        qclass: Class::IN,
    };
    let message = positive_a(&name);
    let now = Instant::now();
    let cache = __BenchCache::new(64 * 1024 * 1024);
    assert!(
        cache
            .store(
                &query,
                &message,
                DnssecStatus::Secure,
                None,
                now,
                __BenchTtlClamp {
                    min: 0,
                    max: 86_400,
                },
            )
            .is_some()
    );

    c.bench_function("cache_hit", |b| {
        b.iter(|| {
            let answer = cache
                .lookup(black_box(&query), black_box(now))
                .expect("fresh hit");
            black_box(answer);
        });
    });
}

criterion_group!(benches, cache_hit);
criterion_main!(benches);
