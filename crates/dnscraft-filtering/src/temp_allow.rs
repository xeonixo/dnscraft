//! Temporary allow rules that live outside the immutable index.
//!
//! A temporary allow ranks like an `$important` exception: it beats every
//! block (including `$important` blocks) for its domain until `until`. Expiry
//! is exact: the rule is active while `now < until` and gone at `until`.

use std::sync::Arc;
use std::time::SystemTime;

use crate::name::DomainName;
use crate::types::{Reason, RuleSource, Verdict};

/// A time-bounded allow for one domain (and optionally its subdomains).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TempAllow {
    /// Domain that is allowed.
    pub domain: DomainName,
    /// When true, every subdomain of [`Self::domain`] is allowed too.
    pub include_subdomains: bool,
    /// Instant at which the allow expires (not inclusive: active while
    /// `now < until`).
    pub until: SystemTime,
    /// Instant at which the allow was added. Stamped by
    /// [`FilterEngine::allow_temporarily`](crate::FilterEngine::allow_temporarily)
    /// from the engine clock; any value supplied by the caller is replaced.
    pub created_at: SystemTime,
}

impl TempAllow {
    /// Whether this allow still applies to `name` at `now`.
    pub fn matches(&self, name: &DomainName, now: SystemTime) -> bool {
        if now >= self.until {
            return false;
        }
        if name == &self.domain {
            return true;
        }
        if !self.include_subdomains {
            return false;
        }
        is_subdomain(name.as_str(), self.domain.as_str())
    }

    /// Synthesised rule text and [`Verdict::Allowed`] for a match.
    pub fn to_verdict(&self) -> Verdict {
        let rule = if self.include_subdomains {
            format!("@@||{}^", self.domain.as_str())
        } else {
            format!("@@|{}^", self.domain.as_str())
        };
        Verdict::Allowed(Reason {
            rule: Arc::from(rule),
            source: RuleSource::TemporaryAllow,
            important: true,
        })
    }
}

/// True when `name` is a strict subdomain of `parent` (ASCII, already canonical).
fn is_subdomain(name: &str, parent: &str) -> bool {
    name.len() > parent.len()
        && name.as_bytes().get(name.len() - parent.len() - 1) == Some(&b'.')
        && name.ends_with(parent)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn dn(s: &str) -> DomainName {
        s.parse().unwrap()
    }
    fn t(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn expires_exactly_at_until() {
        let a = TempAllow {
            domain: dn("a.example"),
            include_subdomains: false,
            until: t(100),
            created_at: t(0),
        };
        assert!(a.matches(&dn("a.example"), t(99)));
        assert!(!a.matches(&dn("a.example"), t(100)));
        assert!(!a.matches(&dn("a.example"), t(101)));
    }

    #[test]
    fn subdomains_optional() {
        let exact = TempAllow {
            domain: dn("a.example"),
            include_subdomains: false,
            until: t(100),
            created_at: t(0),
        };
        assert!(!exact.matches(&dn("x.a.example"), t(0)));
        let wide = TempAllow {
            include_subdomains: true,
            ..exact
        };
        assert!(wide.matches(&dn("x.a.example"), t(0)));
        assert!(!wide.matches(&dn("xa.example"), t(0)));
    }
}
