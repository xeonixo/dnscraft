//! WX2: live query-log stream (`GET /api/v1/query-log/stream`).
//!
//! Rows come from the same in-memory fixture as the stats tests. Frames are read
//! with a short timeout; there are no sockets and no internet access.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use hyper::body::Body as HttpBody;
use dnscraft_api::{AppState, Db, ManualClock, QueryLog, QueryLogConfig};
use dnscraft_filtering::{BlockMode, ListId, Reason, RuleSource, SetId};
use dnscraft_listeners::QueryEvent;
use dnscraft_policy::{
    AnswerOrigin, ClientId, DecisionRecord, DecisionStep, DecisionTimings, DnsProtocol, FilterHit,
    ListenerId, ProfileId, SelectionCause, ViewId,
};
use dnscraft_proto::{Class, Name, Rcode, RecordType};
use dnscraft_resolver::{AnswerSource, DnssecStatus, Query};
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



/// Issues a GET through the real router and returns the status and the open body.
async fn open_stream(log: &Arc<QueryLog>, uri: &str) -> (StatusCode, axum::http::HeaderMap, Body) {
    let state = AppState::new().with_query_log(Arc::clone(log));
    let router = state
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let response = router
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    (response.status(), response.headers().clone(), response.into_body())
}

/// Reads frames for `window` and returns everything received as text.
async fn collect_for(body: &mut Body, window: Duration) -> String {
    let mut text = String::new();
    let deadline = tokio::time::Instant::now() + window;
    while let Ok(frame) = tokio::time::timeout_at(
        deadline,
        std::future::poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)),
    )
    .await
    {
        match frame {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    text.push_str(&String::from_utf8_lossy(data.as_ref()));
                }
            }
            _ => break,
        }
    }
    text
}

async fn new_log() -> Arc<QueryLog> {
    let clock = Arc::new(ManualClock::new(base_time()));
    let db = Db::open_in_memory(clock).await.unwrap();
    Arc::new(QueryLog::new(db, QueryLogConfig::default(), "node-a"))
}

#[tokio::test]
async fn stream_applies_the_same_filters_as_the_list() {
    let log = new_log().await;
    let mut blocked = Spec::new(at_secs(BASE_SECS - 1), "ads.example.com");
    blocked.blocked = true;
    let allowed = Spec::new(at_secs(BASE_SECS - 1), "ok.example.com");
    let (status, headers, mut body) = open_stream(&log, "/api/v1/query-log/stream?status=blocked").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], "text/event-stream");
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["x-accel-buffering"], "no");

    log.insert_batch(vec![blocked.event(), allowed.event()]).await.unwrap();
    let text = collect_for(&mut body, Duration::from_millis(400)).await;
    let rows: Vec<&str> = text.lines().filter(|line| line.starts_with("data: ")).collect();
    assert_eq!(rows.len(), 1, "{text}");
    let record: Value = serde_json::from_str(rows[0].trim_start_matches("data: ")).unwrap();
    assert_eq!(record["query"]["name"], "ads.example.com");
    assert!(text.contains("event: row"));
}

#[tokio::test]
async fn stream_limit_per_principal_returns_429() {
    let log = new_log().await;
    let mut open = Vec::new();
    for _ in 0..4 {
        let (status, _, body) = open_stream(&log, "/api/v1/query-log/stream").await;
        assert_eq!(status, StatusCode::OK);
        open.push(body);
    }
    let (status, _, body) = open_stream(&log, "/api/v1/query-log/stream").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"]["code"], "control_api.query_log.stream_limit");

    // Dropping one stream frees its slot.
    open.pop();
    tokio::task::yield_now().await;
    let (status, _, _) = open_stream(&log, "/api/v1/query-log/stream").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn invalid_filter_is_rejected_before_the_stream_opens() {
    let log = new_log().await;
    let (status, _, body) = open_stream(&log, "/api/v1/query-log/stream?protocol=carrier-pigeon").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"]["code"], "control_api.query_log.invalid");
}

#[tokio::test]
async fn a_subscriber_that_falls_behind_gets_a_lagged_event() {
    let log = new_log().await;
    let (_, _, mut body) = open_stream(&log, "/api/v1/query-log/stream").await;
    // One batch larger than the 512-event queue, sent before the reader runs.
    let events: Vec<QueryEvent> = (0..600u64)
        .map(|i| Spec::new(at_secs(BASE_SECS - 1 + i % 2), format!("h{i}.example.com")).event())
        .collect();
    log.insert_batch(events).await.unwrap();
    let text = collect_for(&mut body, Duration::from_millis(500)).await;
    assert!(text.contains("event: lagged"), "no lagged event: {}", &text[..text.len().min(200)]);
    let dropped: u64 = text
        .split("\"dropped\":")
        .nth(1)
        .and_then(|rest| rest.split('}').next())
        .and_then(|digits| digits.trim().parse().ok())
        .expect("dropped count");
    assert!(dropped >= 88, "dropped {dropped}");
}
