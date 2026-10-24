//! Request and response types of the resolver boundary.

use dnscraft_proto::{Class, Message, Name, RecordType};

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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestFlags {
    /// The client's CD bit: skip DNSSEC validation (effective from Task 9).
    pub checking_disabled: bool,
    /// The client's DO bit: wants DNSSEC records in the answer.
    pub dnssec_ok: bool,
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
    /// Not determined: validation was off (CD bit, no trust anchors), or the
    /// answer is a negative or wildcard-expanded one whose denial proof is not
    /// checked yet. Never carries the AD bit.
    Indeterminate,
}

/// Where an answer came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnswerSource {
    /// Served from the cache (Task 11).
    Cache,
    /// Obtained by recursion.
    Recursion,
    /// Expired cache entry served because servers are unreachable (Task 11).
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
}

/// What to remove from the cache (implemented in Task 11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlushScope {
    /// Everything.
    All,
    /// A domain and everything below it.
    Domain(Name),
}

/// Resolver counters (extended in Task 16).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolverStats {
    /// Questions passed to `resolve`.
    pub resolutions: u64,
    /// Queries sent to authoritative servers.
    pub outgoing_queries: u64,
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
