//! Request and response types of the resolver boundary.

use std::net::SocketAddr;
use std::sync::Arc;

use dnscraft_proto::{Class, Message, Name, RecordType};

use crate::config::ForwardZoneId;

/// A question to resolve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// Name asked for.
    pub name: Name,
    /// Record type asked for.
    pub qtype: RecordType,
    /// Class asked for (normally IN).
    pub qclass: Class,
}

/// Flags of the client request that influence resolution.
///
/// `Clone` is cheap: [`Self::forward_zones`] shares its id list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestFlags {
    /// The client's CD bit: skip DNSSEC validation (effective from Task 9).
    pub checking_disabled: bool,
    /// The client's DO bit: wants DNSSEC records in the answer.
    pub dnssec_ok: bool,
    /// Peer address of the client that asked this question, when known.
    ///
    /// Listeners should set this to the UDP/TCP peer. Forward-zone loop
    /// protection refuses to forward when the peer's IP is the IP of one of
    /// the zone's targets (the remote side forwarded back here). Only the IP
    /// is compared; the port is ignored, so port 0 is fine. It must be the
    /// real peer IP: behind NAT it no longer matches a target, the loop is
    /// not detected, and it only ends at `query_timeout`.
    pub client: Option<SocketAddr>,
    /// Forward zones this query may use.
    ///
    /// `None` applies every zone in the resolver configuration. `Some(ids)`
    /// forwards only through those ids. A name whose most specific covering
    /// zone is missing from the list is resolved from the root, and that zone
    /// does not suppress a local answer.
    pub forward_zones: Option<Arc<[ForwardZoneId]>>,
    /// Read the cache but never write to it (dry-run/test queries).
    ///
    /// No answer, negative, delegation, DNSKEY/DS or other cache entry is
    /// stored for this query, and no prefetch is scheduled. `false` by
    /// default; existing callers keep the normal caching behaviour.
    pub no_cache_write: bool,
}

/// How a question is routed.
///
/// Cache entries and in-flight coalescing include this so a forwarded answer
/// and a recursive answer for the same name stay separate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Route {
    /// Iterative resolution from the root. No forward zone applied.
    Recursive,
    /// Stub-forwarded through the zone with this id.
    Forward(ForwardZoneId),
}

impl Route {
    /// Zone id when this route forwards, otherwise `None`.
    pub fn forward_zone(&self) -> Option<ForwardZoneId> {
        match self {
            Self::Forward(id) => Some(id.clone()),
            Self::Recursive => None,
        }
    }
}

/// DNSSEC validation outcome of an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnssecStatus {
    /// Validated up to a trust anchor.
    Secure,
    /// Provably unsigned.
    Insecure,
    /// Validation failed.
    Bogus,
    /// Not determined: validation was off (CD bit, no trust anchors) or the
    /// response held nothing to validate. Never carries the AD bit.
    Indeterminate,
}

/// Where an answer came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnswerSource {
    /// Served from the cache (Task 11).
    Cache,
    /// Obtained by recursion.
    Recursion,
    /// Expired cache entry served because authoritative servers are
    /// unreachable (RFC 8767).
    Stale,
}

/// An Extended DNS Error (RFC 8914).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedError {
    /// INFO-CODE.
    pub code: u16,
    /// Optional human-readable EXTRA-TEXT.
    pub text: Option<String>,
}

/// The result of a resolution.
///
/// The message id is not meaningful (it is 0 for locally synthesized answers).
/// The caller (listeners) must set the id of the client's request before
/// sending.
#[derive(Clone, Debug)]
pub struct Answer {
    /// Final answer records and response code.
    pub message: Message,
    /// DNSSEC outcome.
    pub dnssec: DnssecStatus,
    /// Origin of the answer.
    pub source: AnswerSource,
    /// Extended error to attach for the client, if any.
    pub ede: Option<ExtendedError>,
    /// Forward zone that produced this answer, including a cache or stale hit
    /// of a forwarded answer. `None` for a recursive or local answer.
    pub forward_zone: Option<ForwardZoneId>,
}

/// What to remove from the cache (implemented in Task 11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlushScope {
    /// Everything.
    All,
    /// A domain and everything below it.
    Domain(Name),
}

/// Outcome of root priming (RFC 8109).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrimingStatus {
    /// The root NS set was refreshed from the answer of this server.
    Primed {
        /// The hint that answered the priming query.
        from: std::net::SocketAddr,
        /// Number of root server addresses now in use.
        servers: usize,
    },
    /// Priming failed; the built-in hints are used.
    FellBack,
}
