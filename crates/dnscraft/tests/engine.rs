//! The injectable policy clock: tests pass a ManualClock, production a SystemClock.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::ManualClock;
use dnscraft_policy::{
    ClientFlags, DecisionRecord, DecisionStep, DnsProtocol, ListenerId, PauseScope, PauseUntil,
    RequestContext,
};
use dnscraft_proto::{Class, Name, RecordType};
use dnscraft_resolver::Query;

/// An ANY query (RFC 8482) answers without recursion, so the resolver is never
/// consulted; it is the cheapest way to observe the pause decision.
fn any_query() -> RequestContext {
    RequestContext {
        source_ip: Ipv4Addr::LOCALHOST.into(),
        protocol: DnsProtocol::Udp53,
        listener_id: ListenerId::new("lan").unwrap(),
        client_id: None,
        query: Query {
            name: Name::from_ascii("localhost.").unwrap(),
            qtype: RecordType::ANY,
            qclass: Class::IN,
        },
        flags: ClientFlags::default(),
        test_query: true,
    }
}

fn is_paused(record: &DecisionRecord) -> bool {
    record
        .steps
        .iter()
        .any(|s| matches!(s, DecisionStep::ProtectionPaused { .. }))
}

#[tokio::test]
async fn engine_uses_the_injected_clock() {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
    ));
    let engine = dnscraft::build_engine(Arc::clone(&clock) as Arc<dyn dnscraft_filtering::Clock>)
        .await
        .unwrap();

    engine
        .pause(PauseScope::Global, PauseUntil::For(Duration::from_secs(10)))
        .unwrap();

    // At t0 the pause is active (recorded in the decision record).
    let first = engine.handle(any_query()).await.unwrap();
    assert!(is_paused(&first.record), "pause must be active at t0");

    // Advancing the injected clock past the deadline expires the pause.
    clock.advance(Duration::from_secs(20));
    let second = engine.handle(any_query()).await.unwrap();
    assert!(
        !is_paused(&second.record),
        "pause must expire once the clock advances"
    );
}
