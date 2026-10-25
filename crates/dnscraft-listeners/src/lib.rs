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

#![deny(missing_docs)]

mod admission;
mod bans;
mod clock;
mod config;
mod core;
mod edns;
mod error;
mod handler;
mod ratelimit;
mod socket;

pub use admission::{Admission, AdmitDecision, ClientIdState, SourceClass};
pub use bans::StrikeReason;
pub use clock::{Clock, ManualClock, SystemClock, wait_until};
pub use config::{
    DEFAULT_BAN_DURATION, DEFAULT_BAN_STRIKES, DEFAULT_BAN_WINDOW, DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_CONNECTIONS_PER_SOURCE, DEFAULT_MAX_INFLIGHT, DEFAULT_MAX_QUIC_STREAMS,
    DEFAULT_MAX_TRACKED_SOURCES, DEFAULT_QUERY_TIMEOUT, DEFAULT_TCP_IDLE_TIMEOUT,
    DEFAULT_TLS_HANDSHAKE_TIMEOUT, DEFAULT_UDP_PAYLOAD_MAX, DdrConfig, Exposure, Limits,
    ListenerConfig, ListenersConfig, Protocol, PublicConfig, TokenRate,
};
pub use core::{HandleWireResult, QueryEvent, QueryMeta, handle_wire};
pub use edns::{PAD_BLOCK, build_response_edns, encode_padded, strip_ecs};
pub use error::ListenersError;
pub use handler::{FakeHandler, QueryHandler};
pub use socket::{bind_tcp, bind_udp};
