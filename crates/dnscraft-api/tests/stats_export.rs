//! A13: statistics rollups, dashboard endpoints and streaming query-log export.
//!
//! All data is in-memory SQLite with a `ManualClock`; addresses are
//! documentation ranges and names use `example.com`. No sockets and no
//! wall-clock waits.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode, header};
use dnscraft_api::{
    AppState, Db, ManualClock, QueryLog, QueryLogConfig, QueryLogFilter, RollupWindow,
};
use dnscraft_filtering::{BlockMode, ListId, Reason, RuleSource, SetId};
use dnscraft_listeners::{QueryEvent, QueryEventSink};
use dnscraft_policy::{
    AnswerOrigin, ClientId, DecisionRecord, DecisionStep, DecisionTimings, DnsProtocol, FilterHit,
    ListenerId, ProfileId, SelectionCause, ViewId,
};
use dnscraft_proto::{Class, Name, Rcode, RecordType};
use dnscraft_resolver::AnswerSource;
use dnscraft_resolver::{DnssecStatus, Query};
use serde_json::Value;
use tower::ServiceExt as _;

const BASE_SECS: u64 = 1_700_000_000;

fn at_secs(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn base_time() -> SystemTime {
    at_secs(BASE_SECS)
}

/// Synthetic query tuned per test (blocked/cache/client/domain/protocol).
struct Spec {
    time: SystemTime,
    protocol: DnsProtocol,
    domain: String,
    client: Option<String>,
    profile: &'static str,
    blocked: bool,
    cache: bool,
}

impl Spec {
    fn new(time: SystemTime, domain: impl Into<String>) -> Self {
        Self {
            time,
            protocol: DnsProtocol::Udp53,
            domain: domain.into(),
            client: None,
            profile: "default",
            blocked: false,
            cache: false,
        }
    }

    fn event(&self) -> QueryEvent {
        let selection = SelectionCause::Subnet {
            network: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
            prefix_len: 24,
        };
        let (steps, filter, answer_source, rcode) = if self.blocked {
            (
                vec![
                    DecisionStep::Selected { cause: selection },
                    DecisionStep::FilterBlocked,
                ],
                Some(FilterHit {
                    reason: Reason {
                        rule: Arc::from("||ads.example^"),
                        source: RuleSource::List {
                            list: ListId::new("test-list").unwrap(),
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
                        source: if self.cache {
                            AnswerSource::Cache
                        } else {
                            AnswerSource::Recursion
                        },
                        dnssec: DnssecStatus::Secure,
                    },
                ],
                None,
                AnswerOrigin::Resolver,
                Rcode::NOERROR,
            )
        };
        let name = if self.domain.ends_with('.') {
            self.domain.clone()
        } else {
            format!("{}.", self.domain)
        };
        QueryEvent {
            time: self.time,
            protocol: self.protocol,
            listener_id: ListenerId::new("lan-udp").unwrap(),
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            client_id: self.client.as_deref().map(|id| ClientId::new(id).unwrap()),
            query: Query {
                name: Name::from_ascii(&name).unwrap(),
                qtype: RecordType::A,
                qclass: Class::IN,
            },
            rcode,
            answer_size: 100,
            duration: Duration::from_millis(1),
            decision: DecisionRecord {
                view_id: ViewId::new("lan").unwrap(),
                profile_id: ProfileId::new(self.profile).unwrap(),
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
                    filter_us: if self.blocked { 8 } else { 0 },
                    resolve_us: if self.blocked { 0 } else { 840 },
                    total_us: 950,
                },
                rcode,
            },
            loggable: true,
        }
    }
}

async fn harness(config: QueryLogConfig) -> (Arc<QueryLog>, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(base_time()));
    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    let log = QueryLog::new(db, config, "node-a");
    (Arc::new(log), clock)
}

/// Issues one GET through the real router and returns status, headers, bytes.
async fn request(log: &Arc<QueryLog>, uri: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
    let state = AppState::new().with_query_log(Arc::clone(log));
    let router = state
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let response = router
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, headers, bytes)
}

fn json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

fn body_text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn stats_export_ndjson_streams_and_obeys_filters() {
    let (log, _clock) = harness(QueryLogConfig::default()).await;
    let events: Vec<QueryEvent> = (0..10)
        .map(|i| {
            let mut spec = Spec::new(at_secs(BASE_SECS - (10 - i as u64)), "host.example.com");
            spec.protocol = if i % 2 == 0 {
                DnsProtocol::Udp53
            } else {
                DnsProtocol::Tcp53
            };
            spec.blocked = i % 5 == 0;
            spec.event()
        })
        .collect();
    log.insert_batch(events).await.unwrap();

    let (status, headers, body) =
        request(&log, "/api/v1/query-log/export.ndjson?protocol=udp53").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/x-ndjson");
    // A streamed body has no precomputed length.
    assert!(headers.get(header::CONTENT_LENGTH).is_none());

    let text = body_text(&body);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 5, "udp53 only: {text}");
    for line in &lines {
        let record: Value = serde_json::from_str(line).unwrap();
        assert_eq!(record["protocol"], "udp53");
        assert_eq!(record["query"]["name"], "host.example.com");
    }

    // only_blocked and time-range filters compose with the export cursor.
    let (status, _, body) = request(
        &log,
        "/api/v1/query-log/export.ndjson?only_blocked=true&from=2023-11-14T00:00:00Z",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let text = body_text(&body);
    assert_eq!(text.lines().count(), 2);

    for uri in [
        "/api/v1/query-log/export.ndjson?order_by=nope",
        "/api/v1/query-log/export.csv?order=sideways",
        "/api/v1/query-log/export.ndjson?only_blocked=maybe",
        "/api/v1/query-log/export.ndjson?from=not-a-date",
        "/api/v1/query-log/export.csv?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z",
    ] {
        let (status, _, body) = request(&log, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(
            json(&body)["error"]["code"],
            "control_api.query_log.invalid"
        );
    }
}

#[tokio::test]
async fn stats_export_csv_returns_the_same_filtered_set() {
    let (log, _clock) = harness(QueryLogConfig::default()).await;
    let events: Vec<QueryEvent> = (0..12)
        .map(|i| {
            let mut spec = Spec::new(
                at_secs(BASE_SECS - 12 + i as u64),
                format!("h{i}.example.com"),
            );
            spec.blocked = i % 3 == 0;
            spec.client = Some(format!("client-{i:03}"));
            spec.event()
        })
        .collect();
    log.insert_batch(events).await.unwrap();

    let uri_query = "?status=allowed";
    let (status, _, ndjson) =
        request(&log, &format!("/api/v1/query-log/export.ndjson{uri_query}")).await;
    assert_eq!(status, StatusCode::OK);
    let ndjson_ids: HashSet<String> = body_text(&ndjson)
        .lines()
        .map(|line| {
            let record: Value = serde_json::from_str(line).unwrap();
            record["id"].as_str().unwrap().to_owned()
        })
        .collect();

    let (status, headers, csv) =
        request(&log, &format!("/api/v1/query-log/export.csv{uri_query}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "text/csv; charset=utf-8");
    let text = body_text(&csv);
    let mut lines = text.lines();
    assert_eq!(
        lines.next().unwrap(),
        "id,time,node_id,listener_id,protocol,source_ip,source_ip_truncated,client_id,\
         client_name,query_name,query_type,query_class,view_id,profile_id,answer_source,\
         dnssec,rcode,answer_size"
    );
    let csv_ids: HashSet<String> = lines
        .map(|line| line.split(',').next().unwrap().to_owned())
        .collect();
    assert_eq!(csv_ids, ndjson_ids);
    assert_eq!(csv_ids.len(), 8);
}

#[tokio::test]
async fn stats_export_rollups_populate_hourly_and_daily_and_prune_after_a_year() {
    let (log, clock) = harness(QueryLogConfig::default()).await;
    let events = vec![
        Spec::new(at_secs(BASE_SECS - 60), "a.example.com").event(),
        Spec::new(at_secs(BASE_SECS - 120), "b.example.com").event(),
        Spec::new(at_secs(BASE_SECS - 86_400), "c.example.com").event(),
    ];
    log.insert_batch(events).await.unwrap();
    log.run_rollup().await.unwrap();

    let hourly = log.rollup_rows(RollupWindow::Hourly).await.unwrap();
    assert_eq!(hourly.iter().map(|row| row.query_count).sum::<i64>(), 3);
    assert_eq!(
        hourly.iter().filter(|row| row.query_count == 2).count(),
        1,
        "the two same-hour events share one bucket"
    );
    let daily = log.rollup_rows(RollupWindow::Daily).await.unwrap();
    assert_eq!(daily.iter().map(|row| row.query_count).sum::<i64>(), 3);
    assert_eq!(daily.len(), 2);

    // Idempotent: a second pass does not double-count.
    log.run_rollup().await.unwrap();
    let hourly = log.rollup_rows(RollupWindow::Hourly).await.unwrap();
    assert_eq!(hourly.iter().map(|row| row.query_count).sum::<i64>(), 3);

    // One year and a day later the pass prunes every old bucket.
    clock.advance(Duration::from_secs(366 * 86_400));
    log.run_rollup().await.unwrap();
    assert!(
        log.rollup_rows(RollupWindow::Hourly)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        log.rollup_rows(RollupWindow::Daily)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn stats_rollups_and_filters_carry_the_node_id_dimension() {
    let clock = Arc::new(ManualClock::new(base_time()));
    let db = Db::open_in_memory(clock).await.unwrap();
    let node_a = Arc::new(QueryLog::new(
        db.clone(),
        QueryLogConfig::default(),
        "node-a",
    ));
    let node_b = Arc::new(QueryLog::new(db, QueryLogConfig::default(), "node-b"));
    node_a
        .insert_batch(vec![
            Spec::new(at_secs(BASE_SECS - 20), "a1.example.com").event(),
            Spec::new(at_secs(BASE_SECS - 10), "a2.example.com").event(),
        ])
        .await
        .unwrap();
    node_b
        .insert_batch(vec![
            Spec::new(at_secs(BASE_SECS - 10), "b1.example.com").event(),
        ])
        .await
        .unwrap();

    // Query-log list filter.
    let page = node_a
        .list(&QueryLogFilter {
            node_id: Some("node-b".to_owned()),
            limit: 10,
            ..QueryLogFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0]["node_id"], "node-b");

    // Rollups keep the node dimension instead of merging the two nodes.
    node_a.run_rollup().await.unwrap();
    let hourly = node_a.rollup_rows(RollupWindow::Hourly).await.unwrap();
    assert!(
        hourly
            .iter()
            .any(|row| row.node_id == "node-a" && row.query_count == 2)
    );
    assert!(
        hourly
            .iter()
            .any(|row| row.node_id == "node-b" && row.query_count == 1)
    );

    // Both HTTP list endpoints accept the same filter.
    let (status, _, body) = request(&node_a, "/api/v1/stats/overview?node_id=node-b").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["data"]["total"], 1);

    let (status, _, body) = request(&node_a, "/api/v1/query-log?node_id=node-a").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["data"]["queries"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn stats_export_top_clients_and_domains_respect_cardinality_caps() {
    let (log, _clock) = harness(QueryLogConfig::default()).await;
    // More than both caps: 10_001 distinct clients and domains.
    let events: Vec<QueryEvent> = (0..10_001)
        .map(|i| {
            let mut spec = Spec::new(at_secs(BASE_SECS - 100), format!("d{i}.example.com"));
            spec.client = Some(format!("client-{i:05}"));
            spec.event()
        })
        .collect();
    log.insert_batch(events).await.unwrap();

    let (status, _, body) = request(&log, "/api/v1/stats/top_clients?limit=5000").await;
    assert_eq!(status, StatusCode::OK);
    let data = json(&body);
    let clients = data["data"]["clients"].as_array().unwrap();
    assert_eq!(clients.len(), 1000, "top_clients cap is 1000");
    assert_eq!(clients[0]["queries"], 1);

    let (status, _, body) = request(&log, "/api/v1/stats/top_domains?limit=50000").await;
    assert_eq!(status, StatusCode::OK);
    let data = json(&body);
    let domains = data["data"]["domains"].as_array().unwrap();
    assert_eq!(domains.len(), 10_000, "top_domains cap is 10 000");
}

#[tokio::test]
async fn stats_export_overview_cache_and_schema() {
    let (log, _clock) = harness(QueryLogConfig::default()).await;
    let mut events = Vec::new();
    for i in 0..10u64 {
        let mut spec = Spec::new(
            at_secs(BASE_SECS - 10 + i),
            format!("host{}.example.com", i % 3),
        );
        spec.protocol = if i % 2 == 0 {
            DnsProtocol::Udp53
        } else {
            DnsProtocol::Tcp53
        };
        spec.blocked = i % 5 == 0;
        spec.cache = i % 2 == 0 && !spec.blocked;
        events.push(spec.event());
    }
    log.insert_batch(events).await.unwrap();

    let (status, _, body) = request(&log, "/api/v1/stats/overview").await;
    assert_eq!(status, StatusCode::OK);
    let data = json(&body);
    let overview = &data["data"];
    assert_eq!(overview["total"], 10);
    assert_eq!(overview["blocked"], 2);
    assert_eq!(overview["allowed"], 8);
    assert_eq!(overview["by_protocol"]["udp53"], 5);
    assert_eq!(overview["by_protocol"]["tcp53"], 5);
    assert_eq!(overview["by_profile"]["default"], 10);
    assert_eq!(overview["by_view"]["lan"], 10);
    assert_eq!(overview["dnssec"]["secure"], 10);
    assert!(overview["from"].is_string() && overview["to"].is_string());

    // Four allowed even-index events resolved from cache; four allowed odd
    // events recursed.
    let (status, _, body) = request(&log, "/api/v1/stats/cache").await;
    assert_eq!(status, StatusCode::OK);
    let cache = &json(&body)["data"];
    assert_eq!(cache["hits"], 4);
    assert_eq!(cache["misses"], 4);
    assert_eq!(cache["hit_ratio"].as_f64().unwrap(), 0.5);

    // NDJSON exposes exactly the documented record schema, nothing else.
    let (status, _, body) = request(&log, "/api/v1/query-log/export.ndjson").await;
    assert_eq!(status, StatusCode::OK);
    let first = body_text(&body);
    let record: Value = serde_json::from_str(first.lines().next().unwrap()).unwrap();
    let documented = [
        "id",
        "node_id",
        "listener_id",
        "protocol",
        "source_ip",
        "source_ip_truncated",
        "client_id",
        "client",
        "query",
        "view_id",
        "profile_id",
        "filter_set",
        "selection",
        "steps",
        "answer_source",
        "filter",
        "dnssec",
        "forward_zone",
        "rcode",
        "answer_size",
        "timings",
        "time",
    ];
    for key in record.as_object().unwrap().keys() {
        assert!(
            documented.contains(&key.as_str()),
            "undocumented export field `{key}`"
        );
    }
    let text = record.to_string();
    for secret in ["authorization", "password", "secret", "token_hash"] {
        assert!(
            !text.contains(secret),
            "secret-like material leaked: {secret}"
        );
    }
}

#[tokio::test]
async fn stats_export_rejects_malformed_parameters() {
    let (log, _clock) = harness(QueryLogConfig::default()).await;

    let (status, _, body) = request(&log, "/api/v1/stats/overview?from=not-a-date").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        json(&body)["error"]["code"],
        "control_api.query_log.invalid"
    );

    let (status, _, body) = request(&log, "/api/v1/stats/top_clients?by=nope").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        json(&body)["error"]["code"],
        "control_api.query_log.invalid"
    );

    let (status, _, body) = request(&log, "/api/v1/stats/top_domains?limit=abc").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        json(&body)["error"]["code"],
        "control_api.pagination.invalid"
    );

    let (status, _, body) = request(
        &log,
        "/api/v1/stats/cache?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        json(&body)["error"]["code"],
        "control_api.query_log.invalid"
    );
}

#[tokio::test]
async fn stats_overview_reports_filter_hits_clients_and_sink_drops() {
    let clock = Arc::new(ManualClock::new(base_time()));
    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    let (sink, _rx) = QueryLog::channel(1);
    let log =
        Arc::new(QueryLog::new(db, QueryLogConfig::default(), "node-a").with_sink(sink.clone()));
    // Capacity 1 and no consumer: the second and third events are dropped.
    for i in 0..3u64 {
        let mut spec = Spec::new(at_secs(BASE_SECS - 10 + i), "ads.example.com");
        spec.blocked = i < 2;
        spec.client = Some("client-a".to_owned());
        let _ = sink.try_send(spec.event());
    }
    assert_eq!(sink.dropped(), 2);

    let mut events = Vec::new();
    for i in 0..4u64 {
        let mut spec = Spec::new(at_secs(BASE_SECS - 20 + i), "host.example.com");
        spec.blocked = i < 3;
        spec.client = Some(format!("client-{i}"));
        events.push(spec.event());
    }
    log.insert_batch(events).await.unwrap();

    let (status, _, body) = request(&log, "/api/v1/stats/overview").await;
    assert_eq!(status, StatusCode::OK);
    let overview = &json(&body)["data"];
    assert_eq!(overview["source"], "raw");
    assert_eq!(overview["query_log_dropped"], 2);
    assert_eq!(overview["active_clients"], 4);
    assert_eq!(overview["filter_hits"]["total"], 3);
    assert_eq!(overview["filter_hits"]["by_list"]["test-list"], 3);
    assert_eq!(overview["filter_hits"]["by_reason"]["list"], 3);
    assert_eq!(
        overview["filter_hits"]["top_rules"][0]["rule"],
        "||ads.example^"
    );
    assert_eq!(overview["filter_hits"]["top_rules"][0]["hits"], 3);
}

#[tokio::test]
async fn stats_overview_long_range_is_answered_from_rollups() {
    let (log, _clock) = harness(QueryLogConfig::default()).await;
    let events = vec![
        Spec::new(at_secs(BASE_SECS - 60), "a.example.com").event(),
        {
            let mut spec = Spec::new(at_secs(BASE_SECS - 120), "b.example.com");
            spec.blocked = true;
            spec.event()
        },
    ];
    log.insert_batch(events).await.unwrap();
    log.run_rollup().await.unwrap();

    // Starts 45 days before the clock, outside the 30-day raw retention.
    let (status, _, body) = request(&log, "/api/v1/stats/overview?from=2023-10-01T00:00:00Z").await;
    assert_eq!(status, StatusCode::OK);
    let overview = &json(&body)["data"];
    assert_eq!(overview["source"], "rollup");
    assert_eq!(overview["total"], 2);
    assert_eq!(overview["blocked"], 1);
    assert_eq!(overview["allowed"], 1);
    assert_eq!(overview["by_protocol"]["udp53"], 2);
    assert!(overview["active_clients"].is_null());
    assert!(overview["filter_hits"].is_null());
    assert_eq!(overview["by_view"].as_object().unwrap().len(), 0);
}

#[tokio::test]
async fn stats_profile_filter_scopes_every_dashboard_endpoint() {
    let (log, _clock) = harness(QueryLogConfig::default()).await;
    let mut events = Vec::new();
    for i in 0..4u64 {
        let mut spec = Spec::new(at_secs(BASE_SECS - 10 + i), "kid.example.com");
        spec.profile = if i < 3 { "kids" } else { "default" };
        spec.client = Some(format!("client-{i}"));
        spec.blocked = i == 0;
        spec.cache = i == 1;
        events.push(spec.event());
    }
    log.insert_batch(events).await.unwrap();

    let (status, _, body) = request(&log, "/api/v1/stats/overview?profile_id=kids").await;
    assert_eq!(status, StatusCode::OK);
    let overview = &json(&body)["data"];
    assert_eq!(overview["total"], 3);
    assert_eq!(overview["blocked"], 1);
    assert_eq!(overview["by_profile"]["default"], Value::Null);
    assert_eq!(overview["filter_hits"]["total"], 1);

    let (_, _, body) = request(&log, "/api/v1/stats/top_clients?profile_id=default").await;
    assert_eq!(json(&body)["data"]["clients"].as_array().unwrap().len(), 1);

    let (_, _, body) = request(&log, "/api/v1/stats/cache?profile_id=kids").await;
    assert_eq!(json(&body)["data"]["hits"], 1);
    assert_eq!(json(&body)["data"]["misses"], 1);

    let (_, _, body) = request(&log, "/api/v1/stats/top_domains?profile_id=nobody").await;
    assert_eq!(json(&body)["data"]["domains"].as_array().unwrap().len(), 0);
}
