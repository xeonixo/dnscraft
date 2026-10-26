//! DNS listeners for DNScraft (Do53, DoT, DoH, DoQ).
//!
//! This crate binds configured addresses, admits each query under the
//! internet-exposure rules, turns wire messages into
//! [`dnscraft_policy::RequestContext`], calls [`dnscraft_policy::PolicyEngine`],
//! and writes answers back with the transport's framing.
//!
//! N1: configuration, errors, clock, handler, sockets.
//! N2: transport-independent [`handle_wire`] (validation, EDNS, padding).
//! N3: [`Admission`] (source class, rate limits, bans).
//! N4: Do53 [`serve_udp`].
//! N5: Do53 [`serve_tcp`] (length-prefix framing, pipelining).
//! N6: TLS server configs, SNI admission, hot reload.
//! N7: DoT ([`serve_dot`]) over the framed connection loop.
//! N8: DoH HTTP/2 + HTTP/1.1 ([`serve_doh`]).
//! N9: DoQ ([`serve_doq`]).
//! N10: DDR [`_dns.resolver.arpa`](DdrEndpoints) SVCB on local Do53.
//! N11: [`ListenerSet`] runtime, [`QueryEventSink`], status.

#![deny(missing_docs)]

mod admission;
mod bans;
mod clock;
mod config;
mod conn;
mod core;
mod ddr;
mod doh;
mod doh_request;
mod doq;
mod dot;
mod edns;
mod error;
mod events;
mod framing;
mod handler;
mod ratelimit;
mod set;
mod socket;
mod status;
mod tcp;
mod tls;
mod udp;

pub use admission::{
    Admission, AdmitDecision, ClientIdState, SourceClass, SourceClassifier, default_classifier,
    public_client_id_required,
};
pub use bans::StrikeReason;
pub use clock::{Clock, ManualClock, SystemClock, add_duration, wait_until};
pub use config::{
    DEFAULT_BAN_DURATION, DEFAULT_BAN_STRIKES, DEFAULT_BAN_WINDOW, DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_CONNECTIONS_PER_SOURCE, DEFAULT_MAX_INFLIGHT, DEFAULT_MAX_QUERIES_PER_CONNECTION,
    DEFAULT_MAX_QUIC_STREAMS, DEFAULT_MAX_TRACKED_SOURCES, DEFAULT_QUERY_TIMEOUT,
    DEFAULT_TCP_IDLE_TIMEOUT, DEFAULT_TLS_HANDSHAKE_TIMEOUT, DEFAULT_UDP_PAYLOAD_MAX, DdrConfig,
    Exposure, Limits, ListenerConfig, ListenersConfig, Protocol, PublicConfig, TokenRate,
};
pub use conn::FramedStats;
pub use core::{HandleWireResult, QueryEvent, QueryMeta, error_reply_from_wire, handle_wire};
pub use ddr::{
    DDR_QNAME, DDR_TTL, DOH_PATH, DdrEndpoint, DdrEndpoints, ddr_decision_record, is_ddr_qname,
    try_answer_ddr,
};
pub use doh::{DohServeParams, DohStats, cache_max_age, serve_doh};
pub use doh_request::{
    DNS_MESSAGE_TYPE, DohPath, DohWireError, MAX_DOH_PAYLOAD, extract_wire, parse_doh_path,
};
pub use doq::{
    DOQ_EXCESSIVE_LOAD, DOQ_NO_ERROR, DOQ_PROTOCOL_ERROR, DoqServeParams, DoqStats, serve_doq,
};
pub use dot::{DotServeParams, DotStats, serve_dot};
pub use edns::{PAD_BLOCK, build_response_edns, encode_padded, strip_ecs};
pub use error::ListenersError;
pub use events::{ChannelSink, NullSink, QueryEventSink, emit_event};
pub use framing::{FrameError, MAX_MESSAGE_LEN, read_frame, write_frame};
pub use handler::{FakeHandler, QueryHandler};
pub use set::{EmptyClientIds, ListenerSet, ListenerSetParams};
pub use socket::{bind_tcp, bind_udp};
pub use status::{ListenerStatus, ListenersStatus};
pub use tcp::{
    OPTION_TCP_KEEPALIVE, TcpServeParams, TcpStats, duration_to_keepalive_units, serve_tcp,
};
pub use tls::{
    ALPN_DOQ, ALPN_DOT, ALPN_H2, ALPN_H3, ALPN_HTTP_1_1, AcceptEncrypted, AcceptedTls,
    ListenerCertResolver, PolicyClientIds, PublicSniOutcome, SniGate, SniRejectKind, TlsStats,
    accept_encrypted, apply_sni_strike, apply_tls_handshake_strike, client_id_state_local,
    handshake_until, inspect_public_sni, is_handshake_timeout, quic_server_config,
    tcp_server_config, tls_acceptor, tls_handshake_timeout,
};
pub use udp::{CLASSIC_UDP_LIMIT, UdpServeParams, UdpStats, serve_udp, udp_size_limit};
