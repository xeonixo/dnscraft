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

#![deny(missing_docs)]

mod admission;
mod bans;
mod clock;
mod config;
mod core;
mod edns;
mod error;
mod framing;
mod handler;
mod ratelimit;
mod socket;
mod tcp;
mod tls;
mod udp;

pub use admission::{Admission, AdmitDecision, ClientIdState, SourceClass};
pub use bans::StrikeReason;
pub use clock::{Clock, ManualClock, SystemClock, wait_until};
pub use config::{
    DEFAULT_BAN_DURATION, DEFAULT_BAN_STRIKES, DEFAULT_BAN_WINDOW, DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_CONNECTIONS_PER_SOURCE, DEFAULT_MAX_INFLIGHT, DEFAULT_MAX_QUERIES_PER_CONNECTION,
    DEFAULT_MAX_QUIC_STREAMS, DEFAULT_MAX_TRACKED_SOURCES, DEFAULT_QUERY_TIMEOUT,
    DEFAULT_TCP_IDLE_TIMEOUT, DEFAULT_TLS_HANDSHAKE_TIMEOUT, DEFAULT_UDP_PAYLOAD_MAX, DdrConfig,
    Exposure, Limits, ListenerConfig, ListenersConfig, Protocol, PublicConfig, TokenRate,
};
pub use core::{HandleWireResult, QueryEvent, QueryMeta, error_reply_from_wire, handle_wire};
pub use edns::{PAD_BLOCK, build_response_edns, encode_padded, strip_ecs};
pub use error::ListenersError;
pub use framing::{FrameError, MAX_MESSAGE_LEN, read_frame, write_frame};
pub use handler::{FakeHandler, QueryHandler};
pub use socket::{bind_tcp, bind_udp};
pub use tcp::{
    OPTION_TCP_KEEPALIVE, TcpServeParams, TcpStats, duration_to_keepalive_units, serve_tcp,
};
pub use tls::{
    ALPN_DOQ, ALPN_DOT, ALPN_H2, ALPN_H3, ALPN_HTTP_1_1, AcceptEncrypted, AcceptedTls,
    ListenerCertResolver, PolicyClientIds, PublicSniOutcome, SniGate, SniRejectKind, TlsStats,
    accept_encrypted, apply_sni_strike, client_id_state_local, inspect_public_sni,
    quic_server_config, tcp_server_config, tls_acceptor, tls_handshake_timeout,
};
pub use udp::{CLASSIC_UDP_LIMIT, UdpServeParams, UdpStats, serve_udp, udp_size_limit};
