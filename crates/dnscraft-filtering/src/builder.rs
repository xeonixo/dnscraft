//! Guided rule builder: turns a plain [`RuleSpec`] into canonical rule text so
//! the user never has to type `|`, `^`, `@@` or `$` (German Mac keyboard).
//!
//! ## Canonical form
//!
//! ```text
//! [@@] ("||" | "|") domain "^" ["$" modifier ("," modifier)*]
//! ```
//!
//! `||` is used for "include subdomains", `|` for the exact name. The domain
//! is lower-case ASCII (punycode for Unicode input) without a trailing dot.
//! Modifiers appear in a fixed order: `important`, `dnstype=...`,
//! `dnsrewrite=...`. Type names are upper-case (`TYPEnnn` for codes without a
//! well-known name), sorted by code; negated sets read `~A|~AAAA`. Record
//! rewrites always use the full form `NOERROR;A;1.2.3.4`; rcode rewrites are
//! the bare name (`NXDOMAIN`). A literal comma in TXT text is written `\,`.
//!
//! The builder is for plain domains only: wildcards and regular expressions
//! are rejected. As a last step the output is parsed again with
//! [`parse_rule`], so the builder never returns text the parser refuses.
//!
//! ## `BuildError` codes
//!
//! | Code | Meaning |
//! |---|---|
//! | `filter_build.invalid_domain` | the domain (or CNAME target) is not a valid name |
//! | `filter_build.pattern_not_allowed` | wildcard or regex in the domain field |
//! | `filter_build.rewrite_on_allow` | a rewrite on an allow rule |
//! | `filter_build.empty_negated_types` | "all types except none" |
//! | `filter_build.invalid_txt` | TXT text that cannot be expressed in a rule |
//! | `filter_build.unparsable` | internal: the parser refused the generated text |

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::NameError;
use crate::modifiers::DnsRewrite;
use crate::name::DomainName;
use crate::parser::parse_rule;
use crate::rule::{MatchKind, Rule, RuleAction};
use crate::types::Rewrite;

/// Longest TXT text accepted (one DNS character-string).
pub const MAX_TXT_LEN: usize = 255;

/// Answer rewrite of a custom block rule.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum RewriteSpec {
    /// RCODE REFUSED.
    Refused,
    /// RCODE NXDOMAIN.
    NxDomain,
    /// RCODE SERVFAIL.
    ServFail,
    /// NOERROR with an empty answer.
    NoError,
    /// Answer with this A record.
    A(Ipv4Addr),
    /// Answer with this AAAA record.
    Aaaa(Ipv6Addr),
    /// Answer with a CNAME to this name (Unicode allowed, normalised like the
    /// rule domain).
    Cname(String),
    /// Answer with this TXT text (no backslashes, `$`, `/`, `#` or control characters, 1 to
    /// [`MAX_TXT_LEN`] bytes, no leading or trailing blank).
    Txt(String),
}

/// A set of query types for `$dnstype`.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RecordTypeSel {
    /// RR type codes; empty means all types.
    pub types: Vec<u16>,
    /// Match every type except the listed ones.
    pub negated: bool,
}

/// Input of the guided builder.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RuleSpec {
    /// Block or allow.
    pub action: RuleAction,
    /// Domain as typed by the user: Unicode allowed, surrounding blanks and
    /// one trailing dot are ignored. No wildcards or regex.
    pub domain: String,
    /// Match the domain and its subdomains (`||`) rather than only the name.
    pub include_subdomains: bool,
    /// Query types the rule applies to.
    pub record_types: RecordTypeSel,
    /// `$important`.
    pub important: bool,
    /// Answer rewrite (block rules only).
    pub rewrite: Option<RewriteSpec>,
}

/// The builder rejected a spec.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// The domain or CNAME target is not a valid name.
    #[error("invalid domain: {reason}")]
    InvalidDomain {
        /// Code of the underlying name error (or `filter_rule.invalid_idna`).
        reason: &'static str,
    },
    /// Wildcard or regex in the domain field.
    #[error("wildcards and regular expressions are not allowed in the guided builder")]
    PatternNotAllowed,
    /// A rewrite on an allow rule.
    #[error("rewrites are only possible on block rules")]
    RewriteOnAllow,
    /// A negated type set without types.
    #[error("a negated type selection needs at least one type")]
    EmptyNegatedTypes,
    /// TXT text that cannot be written in a rule.
    #[error("invalid TXT text: {reason}")]
    InvalidTxt {
        /// `empty`, `too_long`, `control_char`, `backslash`, `dollar`, `slash`, `hash` or `edge_blank`.
        reason: &'static str,
    },
    /// The parser refused the generated text (a bug).
    #[error("generated rule rejected by the parser: {code}")]
    Unparsable {
        /// Code of the parser error.
        code: &'static str,
    },
}

impl BuildError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidDomain { .. } => "filter_build.invalid_domain",
            Self::PatternNotAllowed => "filter_build.pattern_not_allowed",
            Self::RewriteOnAllow => "filter_build.rewrite_on_allow",
            Self::EmptyNegatedTypes => "filter_build.empty_negated_types",
            Self::InvalidTxt { .. } => "filter_build.invalid_txt",
            Self::Unparsable { .. } => "filter_build.unparsable",
        }
    }

    /// Message parameters for i18n.
    pub fn params(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::InvalidDomain { reason } => vec![("reason", (*reason).to_string())],
            Self::InvalidTxt { reason } => vec![("reason", (*reason).to_string())],
            Self::Unparsable { code } => vec![("code", (*code).to_string())],
            _ => Vec::new(),
        }
    }
}

impl RuleSpec {
    /// The spec as [`describe_rule`] reports it after a round trip: canonical
    /// domain, sorted and de-duplicated types, canonical CNAME target.
    pub fn normalized(&self) -> Result<RuleSpec, BuildError> {
        let rewrite = match &self.rewrite {
            Some(RewriteSpec::Cname(t)) => Some(RewriteSpec::Cname(canonical_domain(t)?)),
            other => other.clone(),
        };
        let mut types = self.record_types.types.clone();
        types.sort_unstable();
        types.dedup();
        Ok(RuleSpec {
            action: self.action,
            domain: canonical_domain(&self.domain)?,
            include_subdomains: self.include_subdomains,
            record_types: RecordTypeSel {
                negated: self.record_types.negated && !types.is_empty(),
                types,
            },
            important: self.important,
            rewrite,
        })
    }
}

fn name_err(e: &NameError) -> BuildError {
    BuildError::InvalidDomain { reason: e.code() }
}

/// Canonical ASCII form of user input: trimmed, one trailing dot removed,
/// punycode, lower-case.
fn canonical_domain(input: &str) -> Result<String, BuildError> {
    let t = input.trim();
    if t.contains('*') || t.contains('/') {
        return Err(BuildError::PatternNotAllowed);
    }
    let ascii;
    let candidate = if t.is_ascii() {
        t
    } else {
        ascii = idna::domain_to_ascii(t.strip_suffix('.').unwrap_or(t)).map_err(|_| {
            BuildError::InvalidDomain {
                reason: "filter_rule.invalid_idna",
            }
        })?;
        &ascii
    };
    let domain = DomainName::parse(candidate).map_err(|e| name_err(&e))?;
    // Bare IP literals are answer-IP rules, not guided-builder domains.
    if domain.as_str().parse::<std::net::IpAddr>().is_ok() {
        return Err(BuildError::PatternNotAllowed);
    }
    Ok(domain.as_str().to_string())
}

fn type_token(code: u16) -> String {
    crate::modifiers::type_name_for(code).map_or_else(|| format!("TYPE{code}"), str::to_owned)
}

fn check_txt(text: &str) -> Result<(), BuildError> {
    let bad = |reason| Err(BuildError::InvalidTxt { reason });
    if text.is_empty() {
        return bad("empty");
    }
    if text.len() > MAX_TXT_LEN {
        return bad("too_long");
    }
    if text.contains('\\') {
        return bad("backslash");
    }
    if text.contains('$') {
        // The parser splits modifiers at the last `$`.
        return bad("dollar");
    }
    if text.contains('#') {
        // `##`, `#@#` and friends mark cosmetic rules.
        return bad("hash");
    }
    if text.contains('/') {
        // A `/` after the `$` makes the parser treat the line as a pattern.
        return bad("slash");
    }
    if text.chars().any(char::is_control) {
        return bad("control_char");
    }
    if text.starts_with(' ') || text.ends_with(' ') {
        return bad("edge_blank");
    }
    Ok(())
}

fn rewrite_token(rw: &RewriteSpec) -> Result<String, BuildError> {
    Ok(match rw {
        RewriteSpec::Refused => "REFUSED".to_string(),
        RewriteSpec::NxDomain => "NXDOMAIN".to_string(),
        RewriteSpec::ServFail => "SERVFAIL".to_string(),
        RewriteSpec::NoError => "NOERROR".to_string(),
        RewriteSpec::A(ip) => format!("NOERROR;A;{ip}"),
        RewriteSpec::Aaaa(ip) => format!("NOERROR;AAAA;{ip}"),
        RewriteSpec::Cname(t) => format!("NOERROR;CNAME;{}", canonical_domain(t)?),
        RewriteSpec::Txt(text) => {
            check_txt(text)?;
            format!("NOERROR;TXT;{}", text.replace(',', "\\,"))
        }
    })
}

/// Builds canonical rule text from a spec. See the module docs for the form.
pub fn build_rule(spec: &RuleSpec) -> Result<String, BuildError> {
    let domain = canonical_domain(&spec.domain)?;
    if spec.rewrite.is_some() && spec.action == RuleAction::Allow {
        return Err(BuildError::RewriteOnAllow);
    }
    let mut types = spec.record_types.types.clone();
    types.sort_unstable();
    types.dedup();
    if spec.record_types.negated && types.is_empty() {
        return Err(BuildError::EmptyNegatedTypes);
    }

    let mut mods: Vec<String> = Vec::new();
    if spec.important {
        mods.push("important".to_string());
    }
    if !types.is_empty() {
        let neg = if spec.record_types.negated { "~" } else { "" };
        let list: Vec<String> = types
            .iter()
            .map(|c| format!("{neg}{}", type_token(*c)))
            .collect();
        mods.push(format!("dnstype={}", list.join("|")));
    }
    if let Some(rw) = &spec.rewrite {
        mods.push(format!("dnsrewrite={}", rewrite_token(rw)?));
    }

    let mut out = String::new();
    if spec.action == RuleAction::Allow {
        out.push_str("@@");
    }
    out.push_str(if spec.include_subdomains { "||" } else { "|" });
    out.push_str(&domain);
    out.push('^');
    if !mods.is_empty() {
        out.push('$');
        out.push_str(&mods.join(","));
    }

    // Safety net: whatever we emit must parse back to the same rule.
    let rule = parse_rule(&out).map_err(|e| BuildError::Unparsable { code: e.code() })?;
    if rule.domain().map(|d| d.as_str()) != Some(domain.as_str()) {
        return Err(BuildError::Unparsable {
            code: "filter_build.domain_changed",
        });
    }
    Ok(out)
}

/// The inverse of [`build_rule`] for the editor: the spec of a parsed rule,
/// or `None` when the rule is not representable (patterns, regex, `$denyallow`,
/// `$badfilter`, `@@...$dnsrewrite` without value).
pub fn describe_rule(rule: &Rule) -> Option<RuleSpec> {
    let include_subdomains = match rule.kind() {
        MatchKind::Subdomains => true,
        MatchKind::Exact => false,
        _ => return None,
    };
    let m = rule.modifiers();
    if m.badfilter || m.denyallow.is_some() {
        return None;
    }
    let record_types = match &m.dnstype {
        Some(f) => RecordTypeSel {
            types: f.types().to_vec(),
            negated: f.is_negated(),
        },
        None => RecordTypeSel::default(),
    };
    let rewrite = match &m.dnsrewrite {
        None => None,
        Some(DnsRewrite::Set(rw)) => Some(match rw {
            Rewrite::Refused => RewriteSpec::Refused,
            Rewrite::NxDomain => RewriteSpec::NxDomain,
            Rewrite::ServFail => RewriteSpec::ServFail,
            Rewrite::NoErrorEmpty => RewriteSpec::NoError,
            Rewrite::A(ip) => RewriteSpec::A(*ip),
            Rewrite::Aaaa(ip) => RewriteSpec::Aaaa(*ip),
            Rewrite::Cname(d) => RewriteSpec::Cname(d.as_str().to_string()),
            Rewrite::Txt(t) => RewriteSpec::Txt(t.to_string()),
        }),
        Some(DnsRewrite::Disable) => return None,
    };
    Some(RuleSpec {
        action: rule.action(),
        domain: rule.domain()?.as_str().to_string(),
        include_subdomains,
        record_types,
        important: m.important,
        rewrite,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_and_well_formed() {
        let all = [
            BuildError::InvalidDomain { reason: "x" },
            BuildError::PatternNotAllowed,
            BuildError::RewriteOnAllow,
            BuildError::EmptyNegatedTypes,
            BuildError::InvalidTxt { reason: "x" },
            BuildError::Unparsable { code: "x" },
        ];
        let mut seen = std::collections::HashSet::new();
        for e in &all {
            let c = e.code();
            assert!(c.starts_with("filter_build."), "{c}");
            assert!(
                c.bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'.'),
                "{c}"
            );
            assert!(seen.insert(c), "duplicate {c}");
        }
    }
}
