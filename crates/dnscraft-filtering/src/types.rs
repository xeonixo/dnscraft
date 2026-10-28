//! Ids, rule provenance and verdict types.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use crate::error::IdError;
use crate::name::DomainName;

const MAX_ID: usize = 64;

fn validate_id(s: &str) -> Result<(), IdError> {
    if s.is_empty() {
        return Err(IdError::Empty);
    }
    if s.len() > MAX_ID {
        return Err(IdError::TooLong { len: s.len() });
    }
    match s
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'))
    {
        Some(ch) => Err(IdError::InvalidChar { ch }),
        None => Ok(()),
    }
}

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Clone,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            Debug,
            serde::Serialize,
            serde::Deserialize,
        )]
        #[serde(try_from = "String")]
        pub struct $name(Arc<str>);

        impl $name {
            /// Validates `s` (`[a-z0-9-]{1,64}`) and wraps it.
            pub fn new(s: &str) -> Result<Self, IdError> {
                validate_id(s)?;
                Ok(Self(Arc::from(s)))
            }

            /// The id as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(&value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }
    };
}

id_type!(
    /// Identifier of a rule list (a downloaded or built-in filter list).
    /// Matches `[a-z0-9-]{1,64}`.
    ListId
);
id_type!(
    /// Identifier of a rule set (the unit a policy refers to).
    /// Matches `[a-z0-9-]{1,64}`.
    SetId
);
id_type!(
    /// Identifier of a block rule created through the MCP control API.
    ///
    /// Generated as canonical lowercase text by control-api (typically a
    /// UUID); the filtering crate needs no `uuid` dependency. Matches
    /// `[a-z0-9-]{1,64}`.
    McpRuleId
);

/// Where a rule came from.
#[derive(Clone, PartialEq, Eq, Debug)]

pub enum RuleSource {
    /// A line of a filter list.
    List {
        /// The list.
        list: ListId,
        /// 1-based line number in the list.
        line: u32,
    },
    /// A line of the custom rules of a rule set.
    Custom {
        /// The rule set.
        set: SetId,
        /// 1-based line number in the custom rules.
        line: u32,
    },
    /// A built-in blocked service.
    Service {
        /// Service id.
        id: Arc<str>,
    },
    /// A temporary allow (for example "allow for 10 minutes").
    TemporaryAllow,
    /// A block rule managed through the MCP control API.
    Mcp {
        /// The rule set the rule belongs to.
        set: SetId,
        /// The rule id.
        id: McpRuleId,
    },
}

/// Why a verdict was reached.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Reason {
    /// The rule text as written in its source.
    pub rule: Arc<str>,
    /// Where the rule came from.
    pub source: RuleSource,
    /// Whether the rule carried the `$important` modifier.
    pub important: bool,
}

/// A response modification chosen by a rule or by the block mode.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]

pub enum Rewrite {
    /// Answer with RCODE REFUSED.
    Refused,
    /// Answer with RCODE NXDOMAIN.
    NxDomain,
    /// Answer with RCODE SERVFAIL.
    ServFail,
    /// Answer NOERROR with an empty answer section.
    NoErrorEmpty,
    /// Answer with this A record.
    A(Ipv4Addr),
    /// Answer with this AAAA record.
    Aaaa(Ipv6Addr),
    /// Answer with a CNAME to this name.
    Cname(DomainName),
    /// Answer with this TXT record.
    Txt(Arc<str>),
}

/// Outcome of matching a name against a rule set.
#[derive(Clone, PartialEq, Eq, Debug)]

pub enum Verdict {
    /// No rule matched.
    Pass,
    /// An allow rule matched.
    Allowed(Reason),
    /// A block rule matched.
    Blocked(Reason),
    /// A rewrite rule matched.
    Rewrite(Rewrite, Reason),
}

/// How blocked queries are answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockMode {
    /// RCODE REFUSED.
    #[default]
    #[serde(alias = "Refused")]
    Refused,
    /// RCODE NXDOMAIN.
    #[serde(rename = "nxdomain", alias = "NxDomain")]
    NxDomain,
    /// `0.0.0.0` for A and `::` for AAAA.
    #[serde(alias = "NullIp")]
    NullIp,
    /// Configured addresses; a family set to `None` gets an empty answer.
    #[serde(alias = "CustomIp")]
    CustomIp {
        /// Address for A queries.
        v4: Option<Ipv4Addr>,
        /// Address for AAAA queries.
        v6: Option<Ipv6Addr>,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn valid_ids() {
        assert_eq!(
            ListId::new("adguard-dns-1").unwrap().as_str(),
            "adguard-dns-1"
        );
        assert_eq!("x".parse::<SetId>().unwrap().to_string(), "x");
        assert!(SetId::new(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn invalid_ids() {
        assert_eq!(ListId::new("").unwrap_err().code(), "filter_id.empty");
        assert_eq!(
            SetId::new(&"a".repeat(65)).unwrap_err().code(),
            "filter_id.too_long"
        );
        for bad in ["Upper", "under_score", "sp ace", "dot.ted", "ü"] {
            assert_eq!(
                ListId::new(bad).unwrap_err().code(),
                "filter_id.invalid_char",
                "{bad}"
            );
        }
    }

    #[test]
    fn block_mode_default_is_refused() {
        assert_eq!(BlockMode::default(), BlockMode::Refused);
    }

    #[test]
    fn verdict_carries_reason() {
        let reason = Reason {
            rule: Arc::from("||ads.example^"),
            source: RuleSource::List {
                list: ListId::new("ads").unwrap(),
                line: 3,
            },
            important: false,
        };
        let v = Verdict::Rewrite(Rewrite::NxDomain, reason.clone());
        assert_eq!(v, Verdict::Rewrite(Rewrite::NxDomain, reason));
        assert_ne!(v, Verdict::Pass);
    }
}
