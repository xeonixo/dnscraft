//! Config validation: one test per rejection rule + happy path.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ManualClock as FilterClock,
    SetId, SnapshotBuilder,
};
use dnscraft_listeners::{
    DdrConfig, Exposure, FakeHandler, Limits, ListenerConfig, ListenersConfig, Protocol,
    PublicConfig, QueryHandler, TlsPolicy, TokenRate,
};
use dnscraft_policy::{
    AnswerOrigin, ClientFlags, DecisionRecord, DecisionTimings, DnsProtocol, ListenerId, NoClients,
    PolicyAnswer, PolicyConfig, PolicyEngine, ProfileConfig, ProfileId, RequestContext,
    SafeSearchConfig, SelectionCause, ViewConfig, ViewId, ViewRecordConfig,
};
use dnscraft_proto::{Class, Message, Name, RData, RecordType};
use dnscraft_resolver::{Query, Resolver, ResolverConfig, dnssec::TrustAnchors};

fn id(s: &str) -> ListenerId {
    ListenerId::new(s).unwrap()
}

fn addr_v4(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))
}

fn listener(id_s: &str, protocol: Protocol, address: SocketAddr) -> ListenerConfig {
    ListenerConfig {
        id: id(id_s),
        protocol,
        address,
        exposure: Exposure::Local,
        h3: false,
        tls_policy: None,
    }
}

fn valid_cfg(listeners: Vec<ListenerConfig>) -> ListenersConfig {
    ListenersConfig {
        listeners,
        limits: Limits::default(),
        public: PublicConfig {
            enabled: true,
            ..PublicConfig::default()
        },
        ddr: DdrConfig::default(),
    }
}

#[test]
fn config_spec_excerpt_validates() {
    let cfg = valid_cfg(vec![
        listener("lan-udp", Protocol::Udp53, addr_v4(53)),
        listener("lan-tcp", Protocol::Tcp53, addr_v4(53)),
        ListenerConfig {
            id: id("lan-dot"),
            protocol: Protocol::Dot,
            address: SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x53), 853)),
            exposure: Exposure::Local,
            h3: false,
            tls_policy: None,
        },
        ListenerConfig {
            id: id("public-doh"),
            protocol: Protocol::Doh,
            address: addr_v4(443),
            exposure: Exposure::Public,
            h3: true,
            tls_policy: None,
        },
    ]);
    assert!(cfg.validate().is_ok());
}

#[test]
fn config_rejects_duplicate_id() {
    let cfg = valid_cfg(vec![
        listener("same", Protocol::Udp53, addr_v4(53)),
        listener("same", Protocol::Tcp53, addr_v4(53)),
    ]);
    let err = cfg.validate().unwrap_err();
    assert_eq!(err.code(), "listeners.config.duplicate_id");
}

#[test]
fn config_rejects_public_plaintext() {
    let mut cfg = valid_cfg(vec![ListenerConfig {
        id: id("pub-udp"),
        protocol: Protocol::Udp53,
        address: addr_v4(53),
        exposure: Exposure::Public,
        h3: false,
        tls_policy: None,
    }]);
    cfg.public.enabled = true;
    let err = cfg.validate().unwrap_err();
    assert_eq!(err.code(), "listeners.config.public_plaintext");
}

#[test]
fn config_rejects_public_when_disabled() {
    let mut cfg = valid_cfg(vec![ListenerConfig {
        id: id("pub-dot"),
        protocol: Protocol::Dot,
        address: addr_v4(853),
        exposure: Exposure::Public,
        h3: false,
        tls_policy: None,
    }]);
    cfg.public.enabled = false;
    let err = cfg.validate().unwrap_err();
    assert_eq!(err.code(), "listeners.config.invalid");
}

#[test]
fn config_rejects_h3_on_non_doh() {
    let cfg = valid_cfg(vec![ListenerConfig {
        id: id("dot-h3"),
        protocol: Protocol::Dot,
        address: addr_v4(853),
        exposure: Exposure::Local,
        h3: true,
        tls_policy: None,
    }]);
    let err = cfg.validate().unwrap_err();
    assert_eq!(err.code(), "listeners.config.invalid");
}

#[test]
fn config_rejects_duplicate_udp_bind() {
    let cfg = valid_cfg(vec![
        listener("a", Protocol::Udp53, addr_v4(53)),
        listener("b", Protocol::Doq, addr_v4(53)),
    ]);
    let err = cfg.validate().unwrap_err();
    assert_eq!(err.code(), "listeners.config.invalid");
}

#[test]
fn config_rejects_doh_h3_conflicting_with_udp() {
    let cfg = valid_cfg(vec![
        listener("udp", Protocol::Udp53, addr_v4(443)),
        ListenerConfig {
            id: id("doh"),
            protocol: Protocol::Doh,
            address: addr_v4(443),
            exposure: Exposure::Local,
            h3: true,
            tls_policy: None,
        },
    ]);
    let err = cfg.validate().unwrap_err();
    assert_eq!(err.code(), "listeners.config.invalid");
}

#[test]
fn config_allows_udp_and_tcp_on_same_address() {
    let cfg = valid_cfg(vec![
        listener("u", Protocol::Udp53, addr_v4(53)),
        listener("t", Protocol::Tcp53, addr_v4(53)),
    ]);
    assert!(cfg.validate().is_ok());
}

#[test]
fn config_rejects_zero_limit() {
    let mut cfg = valid_cfg(vec![]);
    cfg.limits.max_inflight_per_listener = 0;
    let err = cfg.validate().unwrap_err();
    assert_eq!(err.code(), "listeners.config.invalid");

    let mut cfg = valid_cfg(vec![]);
    cfg.limits.max_queries_per_connection = 0;
    let err = cfg.validate().unwrap_err();
    assert_eq!(err.code(), "listeners.config.invalid");
}

#[test]
fn config_rejects_bad_rate_string() {
    let err = TokenRate::parse("fast").unwrap_err();
    assert_eq!(err.code(), "listeners.config.invalid");
    let err = TokenRate::parse("0/s").unwrap_err();
    assert_eq!(err.code(), "listeners.config.invalid");
}

#[test]
fn config_parses_rate_with_double_burst() {
    let rate = TokenRate::parse("200/s").unwrap();
    assert_eq!(rate.per_second, 200);
    assert_eq!(rate.burst, 400);
}

#[test]
fn config_rejects_empty_ddr_target() {
    let mut cfg = valid_cfg(vec![]);
    cfg.ddr.target.clear();
    let err = cfg.validate().unwrap_err();
    assert_eq!(err.code(), "listeners.config.invalid");
}

fn with_policy(mut l: ListenerConfig, policy: TlsPolicy) -> ListenerConfig {
    l.tls_policy = Some(policy);
    l
}

#[test]
fn config_accepts_tls_policy_on_encrypted_listeners() {
    let cfg = valid_cfg(vec![
        with_policy(
            listener("dot", Protocol::Dot, addr_v4(853)),
            TlsPolicy {
                min_version: "1.3".into(),
                ciphersuites: Some(vec!["TLS13_AES_256_GCM_SHA384".into()]),
                ..TlsPolicy::default()
            },
        ),
        with_policy(
            ListenerConfig {
                id: id("doh"),
                protocol: Protocol::Doh,
                address: addr_v4(443),
                exposure: Exposure::Local,
                h3: true,
                tls_policy: None,
            },
            TlsPolicy {
                alpn: vec!["h2".into()],
                ciphersuites: Some(vec![
                    "TLS13_AES_256_GCM_SHA384".into(),
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
                ]),
                ..TlsPolicy::default()
            },
        ),
        with_policy(
            listener("doq", Protocol::Doq, addr_v4(853)),
            TlsPolicy::default(),
        ),
    ]);
    assert!(cfg.validate().is_ok());
}

#[test]
fn config_rejects_tls_policy_on_plaintext() {
    for protocol in [Protocol::Udp53, Protocol::Tcp53] {
        let cfg = valid_cfg(vec![with_policy(
            listener("plain", protocol, addr_v4(53)),
            TlsPolicy::default(),
        )]);
        let err = cfg.validate().unwrap_err();
        assert_eq!(err.code(), "listeners.tls.policy");
    }
}

#[test]
fn config_rejects_bad_tls_policy_values() {
    let bad_policies = [
        TlsPolicy {
            min_version: "1.1".into(),
            ..TlsPolicy::default()
        },
        TlsPolicy {
            ciphersuites: Some(vec!["TLS_NOT_A_SUITE".into()]),
            ..TlsPolicy::default()
        },
        TlsPolicy {
            ciphersuites: Some(Vec::new()),
            ..TlsPolicy::default()
        },
        TlsPolicy {
            alpn: Vec::new(),
            ..TlsPolicy::default()
        },
    ];
    for policy in bad_policies {
        let cfg = valid_cfg(vec![with_policy(
            listener("dot", Protocol::Dot, addr_v4(853)),
            policy,
        )]);
        let err = cfg.validate().unwrap_err();
        assert_eq!(err.code(), "listeners.config.invalid");
    }
}

#[derive(Debug, Default)]
struct EmptyBodies;

impl ListBodies for EmptyBodies {
    fn body(&self, _id: &ListId) -> Option<Arc<str>> {
        None
    }
}

fn empty_filter() -> Arc<FilterEngine> {
    let mut sc = FilterSetConfig::new(SetId::new("default").unwrap(), "default");
    sc.lists = Vec::new();
    let cfg = FilterConfig {
        lists: Vec::new(),
        sets: vec![sc],
        ..FilterConfig::default()
    };
    let snap = SnapshotBuilder::new(Arc::new(EmptyBodies) as Arc<dyn ListBodies>)
        .build(&cfg)
        .unwrap();
    Arc::new(FilterEngine::from_snapshot(snap))
}

fn canned_answer() -> PolicyAnswer {
    let q = Message::query(0, Name::root(), RecordType::A);
    let message = Message::response_to(&q);
    PolicyAnswer {
        message,
        ede: None,
        record: DecisionRecord {
            view_id: ViewId::new("default").unwrap(),
            profile_id: ProfileId::new("default").unwrap(),
            selection: SelectionCause::Default,
            client_id: None,
            filter_set: SetId::new("default").unwrap(),
            steps: Vec::new(),
            filter: None,
            forward_zone: None,
            dnssec: None,
            answer_source: AnswerOrigin::LocalView,
            timings: DecisionTimings::default(),
            rcode: dnscraft_proto::Rcode::NOERROR,
        },
        loggable: true,
    }
}

#[tokio::test]
async fn fake_handler_records_and_returns_canned_answer() {
    let fake = FakeHandler::new(canned_answer());
    let ctx = RequestContext {
        source_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        protocol: DnsProtocol::Udp53,
        listener_id: id("lan-udp"),
        client_id: None,
        query: Query {
            name: Name::from_ascii("example.com.").unwrap(),
            qtype: RecordType::A,
            qclass: Class::IN,
        },
        flags: ClientFlags::default(),
        test_query: false,
    };
    let answer = QueryHandler::handle(&fake, ctx.clone()).await.unwrap();
    assert_eq!(answer.record.answer_source, AnswerOrigin::LocalView);
    assert_eq!(fake.recorded(), vec![ctx]);
}

#[tokio::test]
async fn policy_engine_query_handler_answers_local_record() {
    let resolver = Arc::new(
        Resolver::new(ResolverConfig {
            root_hints: vec!["127.0.0.1:9".parse().unwrap()],
            query_timeout: Duration::from_millis(50),
            trust_anchors: TrustAnchors::empty(),
            prefetch: false,
            ..ResolverConfig::default()
        })
        .await
        .unwrap(),
    );
    let clock = Arc::new(FilterClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
    ));
    let view = ViewConfig {
        id: ViewId::new("default").unwrap(),
        is_default: true,
        subnets: Vec::new(),
        client_ids: Vec::new(),
        records: vec![ViewRecordConfig {
            name: Name::from_ascii("app.example.").unwrap(),
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 55)),
        }],
        profile: ProfileId::new("default").unwrap(),
    };
    let engine = PolicyEngine::new(
        PolicyConfig {
            default_rebind: true,
            ptr_prefixes: Vec::new(),
            local_nxdomain_suffixes: Vec::new(),
            rebind_check_forward_zones: Vec::new(),
            views: vec![view],
            profiles: vec![ProfileConfig {
                id: ProfileId::new("default").unwrap(),
                filter_set: SetId::new("default").unwrap(),
                suppress_aaaa: false,
                firefox_canary: false,
                icloud_private_relay: false,
                rebind: None,
                rebind_exceptions: Vec::new(),
                forward_zones: None,
                safesearch: SafeSearchConfig::default(),
                schedules: Vec::new(),
            }],
        },
        empty_filter(),
        resolver,
        Arc::new(NoClients),
        clock,
    )
    .unwrap();

    let ctx = RequestContext {
        source_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        protocol: DnsProtocol::Udp53,
        listener_id: id("lan-udp"),
        client_id: None,
        query: Query {
            name: Name::from_ascii("app.example.").unwrap(),
            qtype: RecordType::A,
            qclass: Class::IN,
        },
        flags: ClientFlags::default(),
        test_query: false,
    };
    let answer = QueryHandler::handle(&engine, ctx).await.unwrap();
    assert_eq!(answer.record.answer_source, AnswerOrigin::LocalView);
    assert!(!answer.message.answers.is_empty());
}
