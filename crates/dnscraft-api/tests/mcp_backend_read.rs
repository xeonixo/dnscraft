//! MCP read tools over a real in-memory query log: `search_query_log` and
//! `get_stats`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dnscraft_api::{Db, ManualClock, QueryLog, QueryLogConfig, mcp_backend_for_test};
use dnscraft_filtering::{BlockMode, ListId, Reason, RuleSource, SetId};
use dnscraft_listeners::QueryEvent;
use dnscraft_mcp::backend::McpBackend;
use dnscraft_mcp::dto::{QType, QueryLogSearch, StatsParams, TopClient, TopDomain};
use dnscraft_policy::{
    AnswerOrigin, ClientId, DecisionRecord, DecisionStep, DecisionTimings, DnsProtocol, FilterHit,
    ListenerId, ProfileId, SelectionCause, ViewId,
};
use dnscraft_proto::{Class, Name, Rcode, RecordType};
use dnscraft_resolver::{AnswerSource, DnssecStatus, Query};

/// 2023-11-14T22:13:20Z.
const BASE_SECS: u64 = 1_700_000_000;

fn at_secs(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// One query event: blocked events carry a filter hit, allowed events carry a
/// resolve step (`cache` selects its source).
fn event(
    secs: u64,
    domain: &str,
    qtype: RecordType,
    blocked: bool,
    cache: bool,
    dnssec: DnssecStatus,
    client_id: Option<&str>,
) -> QueryEvent {
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
                    source: if cache {
                        AnswerSource::Cache
                    } else {
                        AnswerSource::Recursion
                    },
                    dnssec,
                },
            ],
            None,
            AnswerOrigin::Resolver,
            Rcode::NOERROR,
        )
    };
    QueryEvent {
        time: at_secs(secs),
        protocol: DnsProtocol::Udp53,
        listener_id: ListenerId::new("lan-udp").unwrap(),
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        client_id: client_id.and_then(|id| ClientId::new(id).ok()),
        query: Query {
            name: Name::from_ascii(&format!("{domain}.")).unwrap(),
            qtype,
            qclass: Class::IN,
        },
        rcode,
        answer_size: 128,
        duration: Duration::from_millis(1),
        decision: DecisionRecord {
            view_id: ViewId::new("lan").unwrap(),
            profile_id: ProfileId::new("default").unwrap(),
            selection,
            client_id: None,
            filter_set: SetId::new("default").unwrap(),
            steps,
            filter,
            forward_zone: None,
            dnssec: Some(dnssec),
            answer_source,
            timings: DecisionTimings {
                select_us: 2,
                filter_us: if blocked { 8 } else { 0 },
                resolve_us: if blocked { 0 } else { 940 },
                total_us: 950,
            },
            rcode,
        },
        loggable: true,
    }
}

/// Four records: two blocked `ads.example.com` (A, AAAA) and two allowed
/// (MX from cache, TXT via recursion) attributed to one client.
fn sample_events() -> Vec<QueryEvent> {
    vec![
        event(
            BASE_SECS - 3,
            "ads.example.com",
            RecordType::A,
            true,
            false,
            DnssecStatus::Bogus,
            None,
        ),
        event(
            BASE_SECS - 2,
            "ads.example.com",
            RecordType::AAAA,
            true,
            false,
            DnssecStatus::Bogus,
            None,
        ),
        event(
            BASE_SECS - 1,
            "ok.example.com",
            RecordType::MX,
            false,
            true,
            DnssecStatus::Secure,
            Some("iphone-k7q2x9"),
        ),
        event(
            BASE_SECS,
            "other.example.com",
            RecordType::TXT,
            false,
            false,
            DnssecStatus::Secure,
            Some("iphone-k7q2x9"),
        ),
    ]
}

async fn backend() -> Arc<dyn McpBackend> {
    let clock = Arc::new(ManualClock::new(at_secs(BASE_SECS)));
    let db = Db::open_in_memory(clock).await.unwrap();
    let log = Arc::new(QueryLog::new(db, QueryLogConfig::default(), "node-a"));
    log.insert_batch(sample_events()).await.unwrap();
    mcp_backend_for_test(Some(log))
}

#[tokio::test]
async fn search_query_log_maps_records_and_paginates() {
    let backend = backend().await;

    let first_page = backend
        .search_query_log(QueryLogSearch {
            limit: 2,
            offset: 0,
            ..QueryLogSearch::default()
        })
        .await
        .unwrap();
    assert_eq!(first_page.queries.len(), 2);
    assert!(first_page.has_more);
    assert_eq!(first_page.next_offset, Some(2));

    // Newest first.
    let newest = &first_page.queries[0];
    assert_eq!(newest.query.name, "other.example.com");
    assert_eq!(newest.query.qtype, QType::Txt);
    assert_eq!(newest.rcode, "NOERROR");
    assert_eq!(newest.profile_id, "default");
    assert_eq!(newest.answer_source, "resolver");
    assert_eq!(newest.timings.total_us, 950);
    assert!(!newest.id.is_empty());
    assert!(newest.time.starts_with("2023-11-14T22:13:20"));
    assert!(newest.filter.is_none());

    let second = &first_page.queries[1];
    assert_eq!(second.query.name, "ok.example.com");
    assert_eq!(second.query.qtype, QType::Mx);
    // No client directory is attached, so the client view stays empty.
    assert_eq!(second.client.id, "");
    assert_eq!(second.client.display_name, "");

    let second_page = backend
        .search_query_log(QueryLogSearch {
            limit: 2,
            offset: 2,
            ..QueryLogSearch::default()
        })
        .await
        .unwrap();
    assert_eq!(second_page.queries.len(), 2);
    assert!(!second_page.has_more);
    assert_eq!(second_page.next_offset, None);
    assert_eq!(second_page.queries[0].query.qtype, QType::Aaaa);
    assert_eq!(second_page.queries[1].query.qtype, QType::A);

    // Domain filter.
    let ads = backend
        .search_query_log(QueryLogSearch {
            limit: 50,
            domain: Some("ads.example.com".to_owned()),
            ..QueryLogSearch::default()
        })
        .await
        .unwrap();
    assert_eq!(ads.queries.len(), 2);
    assert!(
        ads.queries
            .iter()
            .all(|query| query.query.name == "ads.example.com")
    );

    // only_blocked also exercises the filter attribution mapping.
    let blocked = backend
        .search_query_log(QueryLogSearch {
            limit: 50,
            only_blocked: true,
            ..QueryLogSearch::default()
        })
        .await
        .unwrap();
    assert_eq!(blocked.queries.len(), 2);
    let filter = blocked.queries[0].filter.as_ref().unwrap();
    assert_eq!(filter.reason, "list");
    assert_eq!(filter.rule_text.as_deref(), Some("||ads.example^"));
    assert_eq!(filter.list_id.as_deref(), Some("adguard-dns"));
    assert_eq!(blocked.queries[0].rcode, "NXDOMAIN");

    // The exclusive upper bound excludes the newest record.
    let before = backend
        .search_query_log(QueryLogSearch {
            limit: 50,
            from: Some("2023-11-14T22:13:17Z".to_owned()),
            to: Some("2023-11-14T22:13:20Z".to_owned()),
            ..QueryLogSearch::default()
        })
        .await
        .unwrap();
    assert_eq!(before.queries.len(), 3);
    assert!(
        before
            .queries
            .iter()
            .all(|query| query.query.name != "other.example.com")
    );
}

#[tokio::test]
async fn get_stats_aggregates_the_window() {
    let backend = backend().await;
    let stats = backend
        .get_stats(StatsParams {
            from: Some("2023-11-14T22:13:17Z".to_owned()),
            to: Some("2023-11-14T22:13:21Z".to_owned()),
            profile_id: None,
        })
        .await
        .unwrap();

    assert_eq!(stats.total_queries, 4);
    assert_eq!(stats.blocked_queries, 2);
    assert_eq!(stats.allowed_queries, 2);
    assert!((stats.blocked_ratio - 0.5).abs() < f64::EPSILON);

    assert_eq!(
        stats.top_blocked_domains[0],
        TopDomain {
            domain: "ads.example.com".to_owned(),
            count: 2,
        }
    );
    assert_eq!(
        stats.top_clients,
        vec![TopClient {
            client_name: String::new(),
            queries: 2,
        }]
    );
    // One cache hit and one recursion among the allowed records.
    assert!((stats.cache_hit_ratio - 0.5).abs() < f64::EPSILON);
    assert_eq!(stats.dnssec.secure, 2);
    assert_eq!(stats.dnssec.bogus, 2);
    assert_eq!(stats.dnssec.insecure, 0);
    assert!(!stats.period.from.is_empty());
    assert!(!stats.period.to.is_empty());
}
