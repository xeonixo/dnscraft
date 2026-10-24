//! Error types with stable, locale-neutral codes.

use dnscraft_proto::{Name, ProtoError};

/// Failure to construct a [`Resolver`](crate::Resolver).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
}

impl ResolverError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoRootHints => "resolver.no_root_hints",
            Self::InvalidConfig { .. } => "resolver.invalid_config",
        }
    }
}

/// Failure to resolve one question.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
            Self::Encode(_) => "resolver.encode",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable() {
        assert_eq!(ResolverError::NoRootHints.code(), "resolver.no_root_hints");
        let e = ResolveError::Unreachable { zone: Name::root() };
        assert_eq!(e.code(), "resolver.unreachable");
    }
}
