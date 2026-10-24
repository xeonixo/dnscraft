//! Loop and amplification guards for one incoming question.

use std::sync::atomic::{AtomicU32, Ordering};

use dnscraft_proto::Name;

use crate::config::ResolverConfig;
use crate::error::ResolveError;

/// Static limits applied to one resolution, copied from the configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Limits {
    /// Maximum referrals followed per iteration.
    pub max_referral_depth: u8,
    /// Maximum outgoing queries per incoming question (including nested lookups).
    pub max_queries: u32,
    /// Maximum nesting of name server address lookups.
    pub max_nested_depth: u8,
    /// Maximum number of CNAME/DNAME links in one answer chain.
    pub max_cname_chain: u8,
}

impl From<&ResolverConfig> for Limits {
    fn from(config: &ResolverConfig) -> Self {
        Self {
            max_referral_depth: config.max_referral_depth,
            max_queries: config.max_queries_per_resolve,
            max_nested_depth: config.max_nested_depth,
            max_cname_chain: config.max_cname_chain,
        }
    }
}

/// Counter of outgoing queries sent for one incoming question.
#[derive(Debug)]
pub(crate) struct Budget {
    limit: u32,
    sent: AtomicU32,
}

impl Budget {
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            sent: AtomicU32::new(0),
        }
    }

    /// Accounts for one outgoing query; fails once the limit is used up.
    pub fn charge(&self, name: &Name) -> Result<(), ResolveError> {
        if self.sent.fetch_add(1, Ordering::Relaxed) >= self.limit {
            return Err(ResolveError::QueryBudgetExceeded {
                name: name.clone(),
                limit: self.limit,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_is_enforced() {
        let b = Budget::new(2);
        let n = Name::root();
        assert!(b.charge(&n).is_ok());
        assert!(b.charge(&n).is_ok());
        assert!(matches!(
            b.charge(&n),
            Err(ResolveError::QueryBudgetExceeded { limit: 2, .. })
        ));
    }
}
