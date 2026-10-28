//! A12: query-log consumer, storage, filtering, pagination and "why blocked?".
//!
//! All data is in-memory SQLite; addresses are documentation ranges and names
//! use `example.com`. No sockets and no wall-clock waits.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use dnscraft_api::{
    AppState, Audit, ClientEnricher, ClientView, ConfigActor, ConfigService, ConfigStore, Db,
    IpTruncate, ManualClock, ModuleAppliers, Order, OrderBy, QueryLog, QueryLogFilter,
    QueryLogPage,
};
use dnscraft_filtering::{BlockMode, ListId, Reason, RuleSource, SetId};
use dnscraft_listeners::{ManualClock as ListenerClock, QueryEvent, QueryEventSink, emit_event};
use dnscraft_policy::{
    AnswerOrigin, DecisionRecord, DecisionStep, DecisionTimings, DnsProtocol, FilterHit,
    ListenerId, ProfileId, SelectionCause, ViewId,
};
use dnscraft_proto::{Class, Name, Rcode, RecordType};
use dnscraft_resolver::{DnssecStatus, Query};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const BASE_SECS: u64 = 1_700_000_000;

fn at_secs(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn base_time() -> SystemTime {
    at_secs(BASE_SECS)
}

/// One synthetic event. Every 10th query is blocked; names cycle over 100
/// distinct `example.com` hosts; protocols cycle over all five transports.
fn sample_event(time: SystemTime, index: usize) -> QueryEvent {
    let blocked = index.is_multiple_of(10);
    let protocol = match index % 5 {
        0 => DnsProtocol::Udp53,
        1 => DnsProtocol::Tcp53,
        2 => DnsProtocol::DoT,
        3 => DnsProtocol::DoH,
        _ => DnsProtocol::DoQ,
    };
    let name = Name::from_ascii(&format!("host{}.example.com.", index % 100)).unwrap();
    let selection = SelectionCause::Subnet {
        network: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
        prefix_len: 24,
    };
    let (steps, filter, answer_source, rcode) = if blocked {
        (
            vec![
                DecisionStep::Selected { cause: selection },
                DecisionStep::FilterBlocked,
            ],
            Some(FilterHit {
                reason: Reason {
                    rule: Arc::from("||ads.example^"),
                    source: RuleSource::List {
                        list: ListId::new("adguard-dns").unwrap(),
                        line: 7,
                    },
                    important: false,
                },
                block_mode: Some(BlockMode::NxDomain),
            }),
            AnswerOrigin::Filter,
            Rcode::NXDOMAIN,
        )
    } else {
        (
            vec![
                DecisionStep::Selected { cause: selection },
                DecisionStep::Resolve {
                    source: dnscraft_resolver::AnswerSource::Recursion,
                    dnssec: DnssecStatus::Secure,
                },
            ],
            None,
            AnswerOrigin::Resolver,
            Rcode::NOERROR,
        )
    };
    QueryEvent {
        time,
        protocol,
        listener_id: ListenerId::new("lan-udp").unwrap(),
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, (index % 200 + 1) as u8)),
        client_id: (index.is_multiple_of(7))
            .then(|| dnscraft_policy::ClientId::new("iphone-k7q2x9").unwrap()),
        query: Query {
            name,
            qtype: RecordType::A,
            qclass: Class::IN,
        },
        rcode,
        answer_size: 100 + index,
        duration: Duration::from_millis(1),
        decision: DecisionRecord {
            view_id: ViewId::new("lan").unwrap(),
            profile_id: ProfileId::new("default").unwrap(),
            selection,
            client_id: None,
            client_label: None,
            filter_set: SetId::new("default").unwrap(),
            steps,
            filter,
            forward_zone: None,
            dnssec: Some(DnssecStatus::Secure),
            answer_source,
            timings: DecisionTimings {
                select_us: 2,
                filter_us: if blocked { 8 } else { 0 },
                resolve_us: if blocked { 0 } else { 840 },
                total_us: 950,
            },
            rcode,
        },
        loggable: true,
    }
}

/// In-memory log plus the manual clock backing it.
async fn harness(config: dnscraft_api::QueryLogConfig) -> (Arc<QueryLog>, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(base_time()));
    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    let log = QueryLog::new(db, config, "node-a");
    (Arc::new(log), clock)
}

async fn get(log: &Arc<QueryLog>, uri: &str) -> (StatusCode, Value) {
    let state = AppState::new().with_query_log(Arc::clone(log));
    let router = state
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let response = router
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn ids(page: &QueryLogPage) -> Vec<&str> {
    page.records
        .iter()
        .map(|record| record["id"].as_str().unwrap())
        .collect()
}

fn default_filter() -> QueryLogFilter {
    QueryLogFilter {
        order_by: OrderBy::Time,
        order: Order::Desc,
        limit: 50,
        ..QueryLogFilter::default()
    }
}

#[tokio::test]
async fn query_log_filters_order_and_pagination_over_ten_thousand_rows() {
    let (log, _clock) = harness(dnscraft_api::QueryLogConfig::default()).await;
    // Newest record is at BASE-1, oldest at BASE-10000, so every row is
    // inside the 30-day retention window.
    let events: Vec<QueryEvent> = (0..10_000)
        .map(|i| sample_event(at_secs(BASE_SECS - (10_000 - i as u64)), i))
        .collect();
    for chunk in events.chunks(1_000) {
        assert_eq!(log.insert_batch(chunk.to_vec()).await.unwrap(), chunk.len());
    }

    // Default page: newest first, one-row probe for `has_more`.
    let page = log.list(&default_filter()).await.unwrap();
    assert_eq!(page.records.len(), 50);
    assert!(page.has_more);
    assert_eq!(page.next_offset, Some(50));
    assert_eq!(page.records[0]["answer_size"], 100 + 9_999);

    // Two adjacent pages yield disjoint ids.
    let first = log
        .list(&QueryLogFilter {
            limit: 10,
            ..default_filter()
        })
        .await
        .unwrap();
    let second = log
        .list(&QueryLogFilter {
            limit: 10,
            offset: 10,
            ..default_filter()
        })
        .await
        .unwrap();
    let mut seen = std::collections::HashSet::new();
    for id in ids(&first).into_iter().chain(ids(&second)) {
        assert!(seen.insert(id.to_owned()), "duplicate id across pages");
    }
    assert_eq!(seen.len(), 20);

    // Exact domain filter: 100 events share each host name.
    let page = log
        .list(&QueryLogFilter {
            domain: Some("host7.example.com".to_owned()),
            limit: 500,
            ..default_filter()
        })
        .await
        .unwrap();
    assert_eq!(page.records.len(), 100);
    assert!(!page.has_more);
    assert!(
        page.records
            .iter()
            .all(|record| record["query"]["name"] == "host7.example.com")
    );

    // Protocol filter: exactly a fifth of the rows.
    let page = log
        .list(&QueryLogFilter {
            protocol: Some("udp53".to_owned()),
            limit: 500,
            ..default_filter()
        })
        .await
        .unwrap();
    assert_eq!(page.records.len(), 500);
    assert!(page.has_more);

    // only_blocked: every 10th row.
    let page = log
        .list(&QueryLogFilter {
            only_blocked: true,
            limit: 500,
            ..default_filter()
        })
        .await
        .unwrap();
    assert_eq!(page.records.len(), 500);
    assert!(page.has_more);
    assert!(
        page.records
            .iter()
            .all(|record| record["filter"]["block_mode"] == "nxdomain")
    );

    // Ascending domain order starts at the lexicographically smallest host.
    let page = log
        .list(&QueryLogFilter {
            order_by: OrderBy::Domain,
            order: Order::Asc,
            limit: 5,
            ..default_filter()
        })
        .await
        .unwrap();
    assert_eq!(page.records[0]["query"]["name"], "host0.example.com");

    // Time range: [BASE-5000, BASE-1] covers the newest 5000 rows.
    let page = log
        .list(&QueryLogFilter {
            from_us: Some((BASE_SECS as i64 - 5_000) * 1_000_000),
            to_us: Some((BASE_SECS as i64 - 1) * 1_000_000),
            limit: 500,
            ..default_filter()
        })
        .await
        .unwrap();
    assert_eq!(page.records.len(), 500);
    assert!(page.has_more);
}

#[tokio::test]
async fn query_log_row_cap_clamps_the_requested_limit() {
    let (log, _clock) = harness(dnscraft_api::QueryLogConfig {
        max_rows_per_request: 100,
        ..dnscraft_api::QueryLogConfig::default()
    })
    .await;
    let events: Vec<QueryEvent> = (0..300)
        .map(|i| sample_event(at_secs(BASE_SECS - 300 + i as u64), i))
        .collect();
    log.insert_batch(events).await.unwrap();

    let page = log
        .list(&QueryLogFilter {
            limit: 500,
            ..default_filter()
        })
        .await
        .unwrap();
    assert_eq!(page.records.len(), 100);
    assert!(page.has_more);
    assert_eq!(page.next_offset, Some(100));
}

/// A fake directory with one known device.
struct FakeClients;

impl ClientEnricher for FakeClients {
    fn by_ip(&self, ip: IpAddr) -> Option<ClientView> {
        (ip == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))).then(|| ClientView {
            id: "client-0001".to_owned(),
            display_name: "iPhone".to_owned(),
            source: "unifi".to_owned(),
            macs: vec!["aa:bb:cc:dd:ee:ff".to_owned()],
            vlan_id: Some(40),
            vlan_name: Some("IoT".to_owned()),
            local_domain: Some("iot.example.com".to_owned()),
        })
    }
}

#[tokio::test]
async fn query_log_events_are_enriched_with_client_data_and_ip_truncated() {
    let clock = Arc::new(ManualClock::new(base_time()));
    let db = Db::open_in_memory(clock).await.unwrap();
    let config = dnscraft_api::QueryLogConfig {
        ip_truncate: IpTruncate::LastOctet,
        ..dnscraft_api::QueryLogConfig::default()
    };
    let log = QueryLog::new(db, config, "node-a").with_client_enricher(Arc::new(FakeClients));

    log.insert_batch(vec![
        sample_event(at_secs(BASE_SECS - 2), 10), // 192.0.2.11, no client
        sample_event(at_secs(BASE_SECS - 1), 9),  // 192.0.2.10, enriched
    ])
    .await
    .unwrap();

    // `last_octet` truncation is applied at write.
    let page = log
        .list(&QueryLogFilter {
            domain: Some("host9.example.com".to_owned()),
            limit: 10,
            ..default_filter()
        })
        .await
        .unwrap();
    assert_eq!(page.records.len(), 1);
    let record = &page.records[0];
    assert_eq!(record["source_ip"], "192.0.2.0");
    assert_eq!(record["source_ip_truncated"], true);
    assert_eq!(record["client"]["display_name"], "iPhone");
    assert_eq!(record["client"]["source"], "unifi");
    assert_eq!(record["client"]["macs"][0], "aa:bb:cc:dd:ee:ff");
    assert_eq!(record["client"]["vlan_id"], 40);

    // The other source has no matching client.
    let page = log
        .list(&QueryLogFilter {
            domain: Some("host10.example.com".to_owned()),
            limit: 10,
            ..default_filter()
        })
        .await
        .unwrap();
    assert_eq!(page.records[0]["client"], Value::Null);

    // Client-substring and only-with-clients filters.
    let page = log
        .list(&QueryLogFilter {
            client_name_substr: Some("IPH".to_owned()),
            limit: 10,
            ..default_filter()
        })
        .await
        .unwrap();
    assert_eq!(page.records.len(), 1);
    let page = log
        .list(&QueryLogFilter {
            only_with_clients: true,
            limit: 10,
            ..default_filter()
        })
        .await
        .unwrap();
    assert_eq!(page.records.len(), 1);
}

/// Writes one config version whose `control_api_settings` is `settings` (the
/// other sections are empty and have no applier) and returns its version.
async fn put_settings(service: &ConfigService, settings: Value) -> i64 {
    let body = json!({
        "filtering": {}, "clients": {}, "policy": {}, "listeners": {}, "tls": {},
        "control_api_settings": settings,
    });
    service
        .replace(body, &ConfigActor::local(), None)
        .await
        .unwrap()
}

/// Inserts the sample event `index` and returns its stored `(source_ip,
/// source_ip_truncated)`.
async fn insert_and_read_source(log: &QueryLog, index: usize) -> (String, bool) {
    log.insert_batch(vec![sample_event(at_secs(BASE_SECS - 2), index)])
        .await
        .unwrap();
    let page = log
        .list(&QueryLogFilter {
            domain: Some(format!("host{}.example.com", index % 100)),
            limit: 10,
            ..default_filter()
        })
        .await
        .unwrap();
    let record = &page.records[0];
    (
        record["source_ip"].as_str().unwrap().to_owned(),
        record["source_ip_truncated"].as_bool().unwrap(),
    )
}

#[tokio::test]
async fn query_log_ip_truncate_setting_applies_to_later_rows_and_rollback() {
    let clock = Arc::new(ManualClock::new(base_time()));
    let db = Db::open_in_memory(clock).await.unwrap();
    // The bootstrap `[control_api.query_log]` value is `last_octet`.
    let config = dnscraft_api::QueryLogConfig {
        ip_truncate: IpTruncate::LastOctet,
        ..dnscraft_api::QueryLogConfig::default()
    };
    let log = Arc::new(QueryLog::new(db.clone(), config, "node-a"));
    let modules = ModuleAppliers {
        query_log: Some(Arc::clone(&log)),
        ..ModuleAppliers::default()
    };
    let service = ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db),
        modules,
        "node-a",
    );

    // No config version yet: the bootstrap value is in force.
    assert_eq!(
        insert_and_read_source(&log, 10).await,
        ("192.0.2.0".to_owned(), true)
    );

    // An explicit `none` keeps the full address for rows written from now on.
    let none = put_settings(&service, json!({"query_log": {"ip_truncate": "none"}})).await;
    assert_eq!(
        insert_and_read_source(&log, 11).await,
        ("192.0.2.12".to_owned(), false)
    );

    // A version without `ip_truncate` falls back to the bootstrap value.
    put_settings(&service, json!({"query_log": {"retention_days": 30}})).await;
    assert_eq!(
        insert_and_read_source(&log, 12).await,
        ("192.0.2.0".to_owned(), true)
    );

    // Rolling back to the `none` version restores the live setting.
    service
        .rollback(u64::try_from(none).unwrap(), &ConfigActor::local(), None)
        .await
        .unwrap();
    assert_eq!(
        insert_and_read_source(&log, 13).await,
        ("192.0.2.14".to_owned(), false)
    );
}

/// A sample event from `source` carrying a Client ID and, when registered
/// with a label, that label on the decision.
fn client_id_event(
    time: SystemTime,
    source: Ipv4Addr,
    client: &str,
    label: Option<&str>,
) -> QueryEvent {
    let mut event = sample_event(time, 1);
    event.source = IpAddr::V4(source);
    let id = dnscraft_policy::ClientId::new(client).unwrap();
    event.client_id = Some(id.clone());
    event.decision.client_id = Some(id);
    event.decision.client_label = label.map(Arc::from);
    event
}

#[tokio::test]
async fn query_log_shows_client_id_label_unless_a_directory_client_matches() {
    let clock = Arc::new(ManualClock::new(base_time()));
    let db = Db::open_in_memory(clock).await.unwrap();
    let log = QueryLog::new(db, dnscraft_api::QueryLogConfig::default(), "node-a")
        .with_client_enricher(Arc::new(FakeClients));
    log.insert_batch(vec![
        // No directory match by source IP: the label is the name.
        client_id_event(
            at_secs(BASE_SECS - 3),
            Ipv4Addr::new(192, 0, 2, 11),
            "anna-phone",
            Some("Anna's phone"),
        ),
        // Directory match by source IP wins over the label.
        client_id_event(
            at_secs(BASE_SECS - 2),
            Ipv4Addr::new(192, 0, 2, 10),
            "anna-phone",
            Some("Anna's phone"),
        ),
        // Unregistered Client ID: no label, no name.
        client_id_event(
            at_secs(BASE_SECS - 1),
            Ipv4Addr::new(192, 0, 2, 12),
            "ghost",
            None,
        ),
    ])
    .await
    .unwrap();

    // The label is stored in `client_name`, so the name filter finds it.
    let page = log
        .list(&QueryLogFilter {
            client_name_substr: Some("ANNA".to_owned()),
            limit: 10,
            ..default_filter()
        })
        .await
        .unwrap();
    assert_eq!(page.records.len(), 1);
    let record = &page.records[0];
    assert_eq!(record["client"]["display_name"], "Anna's phone");
    assert_eq!(record["client"]["id"], "anna-phone");
    assert_eq!(record["client"]["display_name"], "Anna's phone");
    assert_eq!(record["client"]["source"], "client_id");
    assert_eq!(record["client"]["macs"], serde_json::json!([]));
    assert_eq!(record["client"]["vlan_id"], Value::Null);
    assert_eq!(record["client"]["local_domain"], Value::Null);

    let page = log
        .list(&QueryLogFilter {
            client_id: Some("anna-phone".to_owned()),
            limit: 10,
            ..default_filter()
        })
        .await
        .unwrap();
    assert_eq!(page.records.len(), 2);
    let directory_hit = page
        .records
        .iter()
        .find(|record| record["client"]["display_name"] == "iPhone")
        .unwrap();
    assert_eq!(directory_hit["client"]["display_name"], "iPhone");
    assert_eq!(directory_hit["client"]["source"], "unifi");

    let page = log
        .list(&QueryLogFilter {
            client_id: Some("ghost".to_owned()),
            limit: 10,
            ..default_filter()
        })
        .await
        .unwrap();
    assert_eq!(page.records[0]["client_id"], "ghost");
    assert_eq!(page.records[0]["client"], Value::Null);
}

#[tokio::test]
async fn query_log_outbox_cursor_advances_only_contiguously() {
    let (log, _clock) = harness(dnscraft_api::QueryLogConfig::default()).await;
    assert_eq!(log.next_seq().await.unwrap(), 1);

    log.insert_batch(vec![sample_event(at_secs(BASE_SECS - 3), 0)])
        .await
        .unwrap();
    log.insert_batch(vec![
        sample_event(at_secs(BASE_SECS - 2), 1),
        sample_event(at_secs(BASE_SECS - 1), 2),
    ])
    .await
    .unwrap();

    // Three records allocated (seq 1..=3); nothing acknowledged yet.
    assert_eq!(log.next_seq().await.unwrap(), 1);
    assert_eq!(log.ack(2).await.unwrap(), 2);
    assert_eq!(log.next_seq().await.unwrap(), 3);

    // A stale acknowledgement never moves the cursor backwards.
    assert_eq!(log.ack(1).await.unwrap(), 2);
    assert_eq!(log.next_seq().await.unwrap(), 3);

    // A seq past the last allocated record is rejected and changes nothing.
    assert!(log.ack(4).await.is_err());
    assert_eq!(log.next_seq().await.unwrap(), 3);

    assert_eq!(log.ack(3).await.unwrap(), 3);
    assert_eq!(log.next_seq().await.unwrap(), 4);
}

#[tokio::test]
async fn query_log_outbox_cursors_are_per_node() {
    let clock = Arc::new(ManualClock::new(base_time()));
    let db = Db::open_in_memory(clock).await.unwrap();
    let node_a = QueryLog::new(
        db.clone(),
        dnscraft_api::QueryLogConfig::default(),
        "node-a",
    );
    let node_b = QueryLog::new(db, dnscraft_api::QueryLogConfig::default(), "node-b");

    node_a
        .insert_batch(vec![sample_event(at_secs(BASE_SECS - 2), 0)])
        .await
        .unwrap();
    node_b
        .insert_batch(vec![sample_event(at_secs(BASE_SECS - 1), 1)])
        .await
        .unwrap();
    assert_eq!(node_a.next_seq().await.unwrap(), 1);
    assert_eq!(node_b.next_seq().await.unwrap(), 1);

    node_a.ack(1).await.unwrap();
    assert_eq!(node_a.next_seq().await.unwrap(), 2);
    assert_eq!(node_b.next_seq().await.unwrap(), 1);
}

#[tokio::test]
async fn query_log_retention_deletes_rows_outside_the_configured_window() {
    let (log, clock) = harness(dnscraft_api::QueryLogConfig {
        retention_days: 1,
        ..dnscraft_api::QueryLogConfig::default()
    })
    .await;

    // An already-stored stale row is pruned by the next write...
    log.insert_batch(vec![sample_event(at_secs(BASE_SECS - 2 * 86_400), 0)])
        .await
        .unwrap();
    log.insert_batch(vec![sample_event(at_secs(BASE_SECS - 60), 1)])
        .await
        .unwrap();
    let page = log.list(&default_filter()).await.unwrap();
    assert_eq!(page.records.len(), 1, "stale row survived the next write");

    // ...and an explicit retention pass removes rows that age out later.
    clock.advance(Duration::from_secs(2 * 86_400));
    assert_eq!(log.apply_retention().await.unwrap(), 1);
    assert!(
        log.list(&default_filter())
            .await
            .unwrap()
            .records
            .is_empty()
    );
}

#[tokio::test]
async fn query_log_why_blocked_returns_the_full_decision_record() {
    let (log, _clock) = harness(dnscraft_api::QueryLogConfig::default()).await;
    log.insert_batch(vec![sample_event(at_secs(BASE_SECS - 1), 0)])
        .await
        .unwrap();

    let page = log.list(&default_filter()).await.unwrap();
    let id = page.records[0]["id"].as_str().unwrap().to_owned();
    let (status, body) = get(&log, &format!("/api/v1/query-log/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    let record = &body["data"];
    assert_eq!(record["id"], id);
    assert_eq!(record["view_id"], "lan");
    assert_eq!(record["profile_id"], "default");
    assert_eq!(record["selection"]["cause"], "subnet");
    assert_eq!(record["selection"]["prefix"], "192.0.2.0/24");
    assert_eq!(record["filter"]["block_mode"], "nxdomain");
    assert_eq!(record["filter"]["rule_text"], "||ads.example^");
    assert_eq!(record["filter"]["list_id"], "adguard-dns");
    assert_eq!(record["filter"]["important"], false);
    assert_eq!(record["answer_source"], "filter_block");
    assert_eq!(record["dnssec"], "secure");
    assert_eq!(record["timings"]["filter_us"], 8);
    assert_eq!(record["timings"]["total_us"], 950);
    let stages: Vec<&str> = record["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| step["stage"].as_str().unwrap())
        .collect();
    assert_eq!(stages, ["select", "filter_qname"]);
    assert_eq!(record["steps"][1]["verdict"], "blocked");

    // Unknown id is the documented 404.
    let (status, body) = get(&log, "/api/v1/query-log/does-not-exist").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "control_api.not_found");
}

#[tokio::test]
async fn query_log_http_list_applies_filters_and_pagination() {
    let (log, _clock) = harness(dnscraft_api::QueryLogConfig::default()).await;
    let events: Vec<QueryEvent> = (0..30)
        .map(|i| sample_event(at_secs(BASE_SECS - 30 + i as u64), i))
        .collect();
    log.insert_batch(events).await.unwrap();

    let (status, body) = get(
        &log,
        "/api/v1/query-log?only_blocked=true&limit=2&order_by=time&order=asc",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let queries = body["data"]["queries"].as_array().unwrap();
    assert_eq!(queries.len(), 2);
    assert_eq!(body["data"]["has_more"], true);
    assert_eq!(body["data"]["next_offset"], 2);
    assert_eq!(queries[0]["filter"]["block_mode"], "nxdomain");

    // Malformed filter values are client errors (400 `query_log.invalid`),
    // never server errors.
    for uri in [
        "/api/v1/query-log?order_by=nope",
        "/api/v1/query-log?order=sideways",
        "/api/v1/query-log?from=not-a-date",
        "/api/v1/query-log?only_blocked=maybe",
        "/api/v1/query-log?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z",
    ] {
        let (status, body) = get(&log, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(
            body["error"]["code"], "control_api.query_log.invalid",
            "{uri}"
        );
    }

    // A malformed pagination value keeps its own documented 400 code.
    let (status, body) = get(&log, "/api/v1/query-log?limit=0").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "control_api.pagination.invalid");

    // A viewer-accessible route is mounted even without auth configured.
    let (status, _) = get(&log, "/api/v1/query-log").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn query_log_http_limit_honours_max_rows_per_request_beyond_generic_cap() {
    let (log, _clock) = harness(dnscraft_api::QueryLogConfig::default()).await;
    let events: Vec<QueryEvent> = (0..700)
        .map(|i| sample_event(at_secs(BASE_SECS - 700 + i as u64), i))
        .collect();
    log.insert_batch(events).await.unwrap();

    // 600 exceeds the generic 500 pagination cap but is within the default
    // `max_rows_per_request` (10 000), so it is served rather than clamped.
    let (status, body) = get(&log, "/api/v1/query-log?limit=600").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["queries"].as_array().unwrap().len(), 600);
}

#[tokio::test]
async fn query_log_full_sink_drops_without_blocking_and_counts() {
    let (sink, mut rx) = QueryLog::channel(1);
    let clock = ListenerClock::new(base_time());
    let event = sample_event(at_secs(BASE_SECS), 0);

    emit_event(sink.as_ref(), &clock, event.clone());
    assert_eq!(sink.dropped(), 0);
    // The channel is full: the second event is dropped, not waited on.
    emit_event(sink.as_ref(), &clock, event.clone());
    emit_event(sink.as_ref(), &clock, event.clone());
    assert_eq!(sink.dropped(), 2);
    assert_eq!(sink.events_dropped(), 2);

    // Non-loggable events are never counted as drops.
    let mut quiet = sample_event(at_secs(BASE_SECS), 1);
    quiet.loggable = false;
    emit_event(sink.as_ref(), &clock, quiet);
    assert_eq!(sink.dropped(), 2);

    // The counter is surfaced as `query_log_dropped` in `GET /api/v1/stats/overview`.
    // Draining the channel lets new events through again.
    assert!(rx.try_recv().is_ok());
    emit_event(sink.as_ref(), &clock, event);
    assert_eq!(sink.dropped(), 2);
}

#[tokio::test]
async fn domain_detail_counts_split_blocked_and_allowed_per_name() {
    // WX5: `host1` (index 1, 101, 201) is never blocked; `host0` (0, 100, 200) is.
    let (log, _clock) = harness(dnscraft_api::QueryLogConfig::default()).await;
    let events: Vec<_> = (0..300)
        .map(|i| sample_event(at_secs(BASE_SECS - 1 - i as u64), i))
        .collect();
    log.insert_batch(events).await.unwrap();

    let (status, body) = get(&log, "/api/v1/stats/domains/HOST1.Example.COM.").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let data = &body["data"];
    assert_eq!(data["domain"], "host1.example.com");
    assert_eq!(data["retention_limited"], true);
    assert_eq!(data["counts"]["total"], 3);
    assert_eq!(data["counts"]["blocked"], 0);
    assert_eq!(data["counts"]["allowed"], 3);
    assert!(data["top_clients"].as_array().unwrap().len() <= 10);
    assert_eq!(data["last_decision"]["status"], "allowed");
    assert!(data["last_decision"]["rule_text"].is_null());

    let (status, body) = get(&log, "/api/v1/stats/domains/host0.example.com").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["counts"]["blocked"], 3);
    assert_eq!(body["data"]["last_decision"]["status"], "blocked");
    assert_eq!(body["data"]["last_decision"]["rule_text"], "||ads.example^");
    assert_eq!(body["data"]["last_decision"]["source"], "list");
    assert!(!body["data"]["daily"].as_array().unwrap().is_empty());

    let (status, body) = get(&log, "/api/v1/stats/domains/unseen.example.com").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "control_api.not_found");

    let (status, body) = get(&log, "/api/v1/stats/domains/*.example.com").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "control_api.stats.invalid_domain");

    let (status, body) = get(&log, "/api/v1/stats/domains/host1.example.com?days=5").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "control_api.stats.invalid_domain");
}
