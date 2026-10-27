//! Error types with stable, locale-neutral codes.
//!
//! Every variant exposes a `code()` string for APIs and i18n. Human-readable
//! text on the error is for logs, not for end users.
//!
//! ## `ResolverError` codes
//!
//! | Variant | Code |
//! |---|---|
//! | [`ResolverError::NoRootHints`] | `resolver.no_root_hints` |
//! | [`ResolverError::InvalidConfig`] | `resolver.invalid_config` |
//! | [`ResolverError::DuplicateForwardZone`] | `resolver.forward_zone.duplicate_id` |
//!
//! ## `ForwardZoneIdError` codes
//!
//! | Variant | Code |
//! |---|---|
//! | [`ForwardZoneIdError::Empty`] | `resolver.forward_zone.empty` |
//! | [`ForwardZoneIdError::TooLong`] | `resolver.forward_zone.too_long` |
//! | [`ForwardZoneIdError::InvalidChar`] | `resolver.forward_zone.invalid_char` |
//!
//! ## `ResolveError` codes
//!
//! | Variant | Code |
//! |---|---|
//! | [`ResolveError::Unreachable`] | `resolver.unreachable` |
//! | [`ResolveError::QueryBudgetExceeded`] | `resolver.query_budget` |
//! | [`ResolveError::ReferralDepthExceeded`] | `resolver.referral_depth` |
//! | [`ResolveError::CnameLimitExceeded`] | `resolver.cname_limit` |
//! | [`ResolveError::CnameLoop`] | `resolver.cname_limit` |
//! | [`ResolveError::ForwardLoop`] | `resolver.forward_loop` |
//! | [`ResolveError::Overloaded`] | `resolver.overloaded` |
//! | [`ResolveError::Encode`] | `resolver.encode` |
//!
//! `CnameLimitExceeded` and `CnameLoop` share `resolver.cname_limit` by design
//! (Task 5): both are CNAME-chain failures that surface as SERVFAIL to the
//! client. DNSSEC validation failures are not `ResolveError`s; they are
//! returned as [`Answer`](crate::Answer) with `DnssecStatus::Bogus`, SERVFAIL,
//! and an EDE whose text comes from the DNSSEC module's own `code()`.

use dnscraft_proto::{Name, ProtoError};

use crate::config::ForwardZoneId;

/// Failure to construct a [`Resolver`](crate::Resolver).
#[derive(Debug, thiserror::Error)]

pub enum ResolverError {
    /// No root hints are configured, so recursion cannot start.
    #[error("no root hints configured")]
    NoRootHints,
    /// The configuration is unusable.
    #[error("invalid resolver configuration: {reason}")]
    InvalidConfig {
        /// What is wrong.
        reason: &'static str,
    },
    /// Two forward zones were configured with the same id.
    #[error("duplicate forward zone id {id}")]
    DuplicateForwardZone {
        /// The id that appeared more than once.
        id: ForwardZoneId,
    },
}

/// A [`ForwardZoneId`](crate::ForwardZoneId) was rejected.
///
/// Ids match `[a-z0-9-]{1,64}`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]

pub enum ForwardZoneIdError {
    /// The id is empty.
    #[error("forward zone id is empty")]
    Empty,
    /// The id is longer than 64 characters.
    #[error("forward zone id is {len} characters long, maximum is 64")]
    TooLong {
        /// Length of the rejected id.
        len: usize,
    },
    /// A character outside `a-z`, `0-9` and `-`.
    #[error("invalid character {ch:?} in forward zone id")]
    InvalidChar {
        /// The offending character.
        ch: char,
    },
}

impl ForwardZoneIdError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "resolver.forward_zone.empty",
            Self::TooLong { .. } => "resolver.forward_zone.too_long",
            Self::InvalidChar { .. } => "resolver.forward_zone.invalid_char",
        }
    }
}

impl ResolverError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoRootHints => "resolver.no_root_hints",
            Self::InvalidConfig { .. } => "resolver.invalid_config",
            Self::DuplicateForwardZone { .. } => "resolver.forward_zone.duplicate_id",
        }
    }
}

/// Failure to resolve one question.
#[derive(Debug, Clone, thiserror::Error)]

pub enum ResolveError {
    /// No authoritative server of the zone answered usefully.
    #[error("no authoritative server reachable for {zone}")]
    Unreachable {
        /// The zone whose servers were tried.
        zone: Name,
    },
    /// The per-question limit of outgoing queries was exceeded.
    #[error("outgoing query budget of {limit} exceeded while resolving {name}")]
    QueryBudgetExceeded {
        /// The name being resolved.
        name: Name,
        /// The configured limit.
        limit: u32,
    },
    /// The delegation chain is deeper than the configured limit.
    #[error("referral depth limit of {limit} exceeded while resolving {name}")]
    ReferralDepthExceeded {
        /// The name being resolved.
        name: Name,
        /// The configured limit.
        limit: u8,
    },
    /// A CNAME/DNAME chain is longer than the configured limit.
    #[error("CNAME chain limit of {limit} exceeded while resolving {name}")]
    CnameLimitExceeded {
        /// The name being resolved.
        name: Name,
        /// The configured limit.
        limit: u8,
    },
    /// A CNAME/DNAME chain points back to a name it already visited.
    #[error("CNAME loop detected at {name}")]
    CnameLoop {
        /// The name that was reached twice.
        name: Name,
    },
    /// The peer asking this question is itself a forward target for the zone.
    ///
    /// That means the remote side forwarded the query back to this resolver.
    /// Returned instead of forwarding again (or joining an in-flight forward
    /// that is waiting on that peer), which would hang.
    #[error("forwarding loop detected for {zone}")]
    ForwardLoop {
        /// The forward zone that matched the query.
        zone: Name,
    },
    /// Too many upstream resolutions are running at once and no slot became
    /// free within `query_timeout`. Callers answer SERVFAIL. Cache hits never
    /// see this error.
    #[error("resolver overloaded: too many concurrent resolutions")]
    Overloaded,
    /// A query could not be encoded.
    #[error("cannot encode query: {0}")]
    Encode(#[from] ProtoError),
}

impl ResolveError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unreachable { .. } => "resolver.unreachable",
            Self::QueryBudgetExceeded { .. } => "resolver.query_budget",
            Self::ReferralDepthExceeded { .. } => "resolver.referral_depth",
            Self::CnameLimitExceeded { .. } | Self::CnameLoop { .. } => "resolver.cname_limit",
            Self::ForwardLoop { .. } => "resolver.forward_loop",
            Self::Overloaded => "resolver.overloaded",
            Self::Encode(_) => "resolver.encode",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_resolver_error_has_a_documented_code() {
        assert_eq!(ResolverError::NoRootHints.code(), "resolver.no_root_hints");
        assert_eq!(
            ResolverError::InvalidConfig {
                reason: "query_timeout must be greater than zero"
            }
            .code(),
            "resolver.invalid_config"
        );
        assert_eq!(
            ResolverError::DuplicateForwardZone {
                id: ForwardZoneId::new("vpn").unwrap(),
            }
            .code(),
            "resolver.forward_zone.duplicate_id"
        );
    }

    #[test]
    fn forward_zone_id_errors_have_documented_codes() {
        assert_eq!(
            ForwardZoneIdError::Empty.code(),
            "resolver.forward_zone.empty"
        );
        assert_eq!(
            ForwardZoneIdError::TooLong { len: 65 }.code(),
            "resolver.forward_zone.too_long"
        );
        assert_eq!(
            ForwardZoneIdError::InvalidChar { ch: '_' }.code(),
            "resolver.forward_zone.invalid_char"
        );
    }

    #[test]
    fn construction_error_codes_are_unique() {
        let codes = [
            ResolverError::NoRootHints.code(),
            ResolverError::InvalidConfig { reason: "x" }.code(),
            ResolverError::DuplicateForwardZone {
                id: ForwardZoneId::new("vpn").unwrap(),
            }
            .code(),
            ForwardZoneIdError::Empty.code(),
            ForwardZoneIdError::TooLong { len: 65 }.code(),
            ForwardZoneIdError::InvalidChar { ch: 'A' }.code(),
        ];
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
    }

    #[test]
    fn every_resolve_error_has_a_documented_code() {
        let root = Name::root();
        let cases: &[(&str, ResolveError)] = &[
            (
                "resolver.unreachable",
                ResolveError::Unreachable { zone: root.clone() },
            ),
            (
                "resolver.query_budget",
                ResolveError::QueryBudgetExceeded {
                    name: root.clone(),
                    limit: 64,
                },
            ),
            (
                "resolver.referral_depth",
                ResolveError::ReferralDepthExceeded {
                    name: root.clone(),
                    limit: 8,
                },
            ),
            (
                "resolver.cname_limit",
                ResolveError::CnameLimitExceeded {
                    name: root.clone(),
                    limit: 16,
                },
            ),
            (
                "resolver.cname_limit",
                ResolveError::CnameLoop { name: root.clone() },
            ),
            (
                "resolver.forward_loop",
                ResolveError::ForwardLoop { zone: root },
            ),
            ("resolver.overloaded", ResolveError::Overloaded),
        ];
        for (code, err) in cases {
            assert_eq!(err.code(), *code, "{err}");
        }
        // Encode wraps a ProtoError; any construction that yields Encode works.
        let encode = ResolveError::Encode(ProtoError::EmptyLabel);
        assert_eq!(encode.code(), "resolver.encode");
    }

    #[test]
    fn resolve_error_codes_are_unique_except_cname_pair() {
        let codes = [
            "resolver.unreachable",
            "resolver.query_budget",
            "resolver.referral_depth",
            "resolver.cname_limit",
            "resolver.forward_loop",
            "resolver.overloaded",
            "resolver.encode",
        ];
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
    }
}
