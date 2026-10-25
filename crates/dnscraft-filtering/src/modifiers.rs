//! Rule modifiers (`$important`, `$badfilter`, `$dnstype`, `$denyallow`,
//! `$dnsrewrite`) and IDNA handling for domains in rules.
//!
//! ## Supported modifiers
//!
//! | Modifier | Meaning |
//! |---|---|
//! | `$important` | raises the rule's priority (matching, Task M1) |
//! | `$badfilter` | disables the otherwise identical rule, see [`Rule::badfilter_key`](crate::Rule::badfilter_key) |
//! | `$dnstype=A\|AAAA` | rule applies only to these query types |
//! | `$dnstype=~A\|~CNAME` | rule applies to all types except these (all entries negated, or none) |
//! | `$denyallow=a.com\|b.org` | block rule does not apply to these domains and their subdomains; invalid on `@@` rules |
//! | `$dnsrewrite=...` | answer rewrite, see [`DnsRewrite`] |
//!
//! Names are case-insensitive. A literal comma inside a value is written `\,`.
//!
//! ## `$dnsrewrite` forms
//!
//! `REFUSED`, `NXDOMAIN`, `SERVFAIL`, `NOERROR` (rcode only); shorthand
//! `1.2.3.4` (A), `::1` (AAAA), `target.example` (CNAME); full
//! `NOERROR;A;1.2.3.4`, `NOERROR;AAAA;::1`, `NOERROR;CNAME;t.example`,
//! `NOERROR;TXT;text`. `MX`, `HTTPS` and the other AdGuard record types are
//! rejected as `unsupported_rewrite_type`. On an `@@` rule the modifier takes
//! no value and means "disable rewrites for this name" (a value is rejected).
//!
//! Source policy (owner decision: a downloaded list must never redirect a
//! domain): in [`ListSource::List`] bodies, *record* rewrites (A, AAAA, CNAME,
//! TXT) are refused with [`RuleError::RewriteFromList`], while rcode forms and
//! the `@@` disable form are kept. [`ListSource::Custom`] and
//! [`parse_rule`](crate::parse_rule) accept everything.
//!
//! A block rule that carries `$dnsrewrite` is a *rewrite rule*: its
//! [`RuleAction`] stays `Block`, the index tells them apart by
//! `modifiers.dnsrewrite`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;
use std::sync::Arc;

use crate::error::{RuleError, UnsupportedKind};
use crate::name::DomainName;
use crate::parser::{ListSource, off, span_of};
use crate::rule::RuleAction;
use crate::types::Rewrite;

/// A set of DNS query types, allowed or excluded (`$dnstype`).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct DnsTypeFilter {
    types: Box<[u16]>,
    negated: bool,
}

impl DnsTypeFilter {
    /// Builds a filter; the types are sorted and de-duplicated.
    pub fn new(mut types: Vec<u16>, negated: bool) -> Self {
        types.sort_unstable();
        types.dedup();
        Self {
            types: types.into_boxed_slice(),
            negated,
        }
    }

    /// The listed RR type codes, sorted ascending.
    pub fn types(&self) -> &[u16] {
        &self.types
    }

    /// True for `$dnstype=~A|~AAAA`: every type except the listed ones.
    pub fn is_negated(&self) -> bool {
        self.negated
    }

    /// Whether a query of type `qtype` is in scope of the rule.
    pub fn matches(&self, qtype: u16) -> bool {
        self.types.binary_search(&qtype).is_ok() != self.negated
    }
}

/// The `$dnsrewrite` modifier.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum DnsRewrite {
    /// Rewrite the answer (block rules).
    Set(Rewrite),
    /// `@@...$dnsrewrite`: disable rewrites for the matched name.
    Disable,
}

/// Rule modifiers.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
#[non_exhaustive]
pub struct Modifiers {
    /// `$important`.
    pub important: bool,
    /// `$badfilter`.
    pub badfilter: bool,
    /// `$dnstype`.
    pub dnstype: Option<DnsTypeFilter>,
    /// `$denyallow`: sorted, de-duplicated domains.
    pub denyallow: Option<Box<[DomainName]>>,
    /// `$dnsrewrite`.
    pub dnsrewrite: Option<DnsRewrite>,
}

impl Modifiers {
    pub(crate) const NONE: Modifiers = Modifiers {
        important: false,
        badfilter: false,
        dnstype: None,
        denyallow: None,
        dnsrewrite: None,
    };

    /// True when no modifier is set.
    pub fn is_empty(&self) -> bool {
        *self == Self::NONE
    }
}

const KNOWN: &[&str] = &[
    "important",
    "badfilter",
    "dnstype",
    "denyallow",
    "dnsrewrite",
];

const BROWSER_MODIFIERS: &[&str] = &[
    "domain",
    "script",
    "third-party",
    "3p",
    "first-party",
    "1p",
    "image",
    "stylesheet",
    "css",
    "xmlhttprequest",
    "xhr",
    "popup",
    "document",
    "doc",
    "subdocument",
    "frame",
    "font",
    "media",
    "websocket",
    "ping",
    "other",
    "object",
    "match-case",
    "removeparam",
    "redirect",
    "redirect-rule",
    "csp",
    "cookie",
    "replace",
    "generichide",
    "elemhide",
    "specifichide",
    "urlblock",
    "content",
    "jsinject",
    "extension",
    "popunder",
    "to",
    "from",
    "method",
    "header",
    "permissions",
    "referrerpolicy",
];

const TYPE_NAMES: &[(&str, u16)] = &[
    ("A", 1),
    ("NS", 2),
    ("CNAME", 5),
    ("SOA", 6),
    ("PTR", 12),
    ("MX", 15),
    ("TXT", 16),
    ("AAAA", 28),
    ("SRV", 33),
    ("SVCB", 64),
    ("HTTPS", 65),
    ("ANY", 255),
    ("CAA", 257),
];

/// Parses a domain from rule text, converting non-ASCII input to punycode
/// with UTS 46 non-transitional processing (as browsers and AdGuard do).
pub(crate) fn parse_domain(s: &str, span: Range<usize>) -> Result<DomainName, RuleError> {
    if s.is_ascii() {
        return DomainName::parse(s).map_err(|source| RuleError::InvalidDomain { source, span });
    }
    let ascii =
        idna::domain_to_ascii(s).map_err(|_| RuleError::InvalidIdna { span: span.clone() })?;
    DomainName::parse(&ascii).map_err(|source| RuleError::InvalidDomain { source, span })
}

struct Tok<'a> {
    span: Range<usize>,
    name: String,
    neg: bool,
    value: Option<(&'a str, Range<usize>)>,
}

fn bad(modifier: &'static str, detail: &'static str, span: Range<usize>) -> RuleError {
    RuleError::InvalidModifier {
        modifier,
        detail,
        span,
    }
}

/// Splits at `sep` unless preceded by a backslash.
fn split_unescaped(s: &str, sep: u8) -> Vec<&str> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < b.len() {
        match b.get(i) {
            Some(b'\\') => i += 1,
            Some(&c) if c == sep => {
                out.push(s.get(start..i).unwrap_or(""));
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(s.get(start..).unwrap_or(""));
    out
}

fn unescape(s: &str) -> String {
    s.replace("\\,", ",")
}

fn tokenize<'a>(line: &'a str, mods: &'a str) -> Vec<Tok<'a>> {
    split_unescaped(mods, b',')
        .into_iter()
        .map(|raw| {
            let (name, value) = match raw.split_once('=') {
                Some((n, v)) => (n, Some((v, span_of(line, v)))),
                None => (raw, None),
            };
            let (neg, name) = match name.strip_prefix('~') {
                Some(n) => (true, n),
                None => (false, name),
            };
            Tok {
                span: span_of(line, raw),
                name: name.to_ascii_lowercase(),
                neg,
                value,
            }
        })
        .collect()
}

/// Parses the text after the `$` of a rule. `mods` must be a sub-slice of
/// `line`; spans refer to `line`.
pub(crate) fn parse_modifiers(
    line: &str,
    mods: &str,
    action: RuleAction,
    source: ListSource,
) -> Result<Modifiers, RuleError> {
    let toks = tokenize(line, mods);
    if toks
        .iter()
        .any(|t| BROWSER_MODIFIERS.contains(&t.name.as_str()))
    {
        let s = off(line, mods).saturating_sub(1);
        return Err(RuleError::Unsupported {
            kind: UnsupportedKind::BrowserOnly,
            span: s..off(line, mods) + mods.len(),
        });
    }
    if let Some(t) = toks.iter().find(|t| t.name == "client" || t.name == "ctag") {
        return Err(RuleError::ClientModifier {
            span: t.span.clone(),
        });
    }
    if let Some(t) = toks
        .iter()
        .find(|t| !t.name.is_empty() && !KNOWN.contains(&t.name.as_str()))
    {
        return Err(RuleError::UnknownModifier {
            span: t.span.clone(),
        });
    }
    let mut m = Modifiers::default();
    for t in &toks {
        let Some(name) = KNOWN.iter().find(|k| **k == t.name).copied() else {
            return Err(RuleError::InvalidSyntax {
                detail: "empty_modifier",
                span: t.span.clone(),
            });
        };
        if t.neg {
            return Err(bad(name, "negation_not_allowed", t.span.clone()));
        }
        let dup = match name {
            "important" => m.important,
            "badfilter" => m.badfilter,
            "dnstype" => m.dnstype.is_some(),
            "denyallow" => m.denyallow.is_some(),
            _ => m.dnsrewrite.is_some(),
        };
        if dup {
            return Err(RuleError::DuplicateModifier {
                span: t.span.clone(),
            });
        }
        match name {
            "important" | "badfilter" => {
                if let Some((_, sp)) = &t.value {
                    return Err(bad(name, "unexpected_value", sp.clone()));
                }
                if name == "important" {
                    m.important = true;
                } else {
                    m.badfilter = true;
                }
            }
            "dnstype" => m.dnstype = Some(parse_dnstype(line, t)?),
            "denyallow" => {
                if action == RuleAction::Allow {
                    return Err(bad(name, "not_allowed_on_exception", t.span.clone()));
                }
                m.denyallow = Some(parse_denyallow(line, t)?);
            }
            _ => m.dnsrewrite = Some(parse_dnsrewrite(line, t, action, source)?),
        }
    }
    Ok(m)
}

fn required<'a>(t: &Tok<'a>, name: &'static str) -> Result<(&'a str, Range<usize>), RuleError> {
    match &t.value {
        Some((v, sp)) if !v.is_empty() => Ok((v, sp.clone())),
        _ => Err(bad(name, "missing_value", t.span.clone())),
    }
}

fn parse_type(s: &str) -> Option<u16> {
    if let Some((_, code)) = TYPE_NAMES.iter().find(|(n, _)| s.eq_ignore_ascii_case(n)) {
        return Some(*code);
    }
    let n = s
        .get(..4)
        .filter(|p| p.eq_ignore_ascii_case("TYPE"))
        .and(s.get(4..))?;
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse::<u16>().ok()
}

fn parse_dnstype(line: &str, t: &Tok<'_>) -> Result<DnsTypeFilter, RuleError> {
    let (v, _) = required(t, "dnstype")?;
    let mut types = Vec::new();
    let mut negated: Option<bool> = None;
    for entry in v.split('|') {
        let espan = span_of(line, entry);
        if entry.is_empty() {
            return Err(bad("dnstype", "empty_entry", espan));
        }
        let (neg, name) = match entry.strip_prefix('~') {
            Some(n) => (true, n),
            None => (false, entry),
        };
        if *negated.get_or_insert(neg) != neg {
            return Err(bad("dnstype", "mixed_negation", espan));
        }
        match parse_type(name) {
            Some(code) => types.push(code),
            None => return Err(bad("dnstype", "unknown_type", espan)),
        }
    }
    Ok(DnsTypeFilter::new(types, negated.unwrap_or(false)))
}

fn parse_denyallow(line: &str, t: &Tok<'_>) -> Result<Box<[DomainName]>, RuleError> {
    let (v, _) = required(t, "denyallow")?;
    let mut out = Vec::new();
    for entry in split_unescaped(v, b'|') {
        let sp = span_of(line, entry);
        if entry.is_empty() {
            return Err(bad("denyallow", "empty_entry", sp));
        }
        out.push(parse_domain(entry, sp)?);
    }
    out.sort();
    out.dedup();
    Ok(out.into_boxed_slice())
}

fn rcode(s: &str) -> Option<Rewrite> {
    const RCODES: [(&str, Rewrite); 4] = [
        ("REFUSED", Rewrite::Refused),
        ("NXDOMAIN", Rewrite::NxDomain),
        ("SERVFAIL", Rewrite::ServFail),
        ("NOERROR", Rewrite::NoErrorEmpty),
    ];
    RCODES
        .into_iter()
        .find(|(n, _)| s.eq_ignore_ascii_case(n))
        .map(|(_, r)| r)
}

fn is_record(r: &Rewrite) -> bool {
    matches!(
        r,
        Rewrite::A(_) | Rewrite::Aaaa(_) | Rewrite::Cname(_) | Rewrite::Txt(_)
    )
}

fn parse_dnsrewrite(
    line: &str,
    t: &Tok<'_>,
    action: RuleAction,
    source: ListSource,
) -> Result<DnsRewrite, RuleError> {
    let has_value = t.value.as_ref().is_some_and(|(v, _)| !v.is_empty());
    if action == RuleAction::Allow {
        return match &t.value {
            Some((_, sp)) if has_value => Err(bad("dnsrewrite", "value_on_exception", sp.clone())),
            _ => Ok(DnsRewrite::Disable),
        };
    }
    let (v, sp) = required(t, "dnsrewrite")?;
    let parts: Vec<&str> = v.splitn(3, ';').collect();
    let rw = match parts.as_slice() {
        [one] => shorthand(line, one)?,
        [rc, ty, val] => full(line, rc, ty, val)?,
        _ => return Err(bad("dnsrewrite", "malformed_value", sp)),
    };
    if source == ListSource::List && is_record(&rw) {
        return Err(RuleError::RewriteFromList { span: sp });
    }
    Ok(DnsRewrite::Set(rw))
}

fn shorthand(line: &str, v: &str) -> Result<Rewrite, RuleError> {
    let sp = span_of(line, v);
    if let Some(r) = rcode(v) {
        return Ok(r);
    }
    if let Ok(ip) = v.parse::<Ipv4Addr>() {
        return Ok(Rewrite::A(ip));
    }
    if let Ok(ip) = v.parse::<Ipv6Addr>() {
        return Ok(Rewrite::Aaaa(ip));
    }
    if v.contains(':') || v.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return Err(bad("dnsrewrite", "invalid_ip", sp));
    }
    Ok(Rewrite::Cname(parse_domain(v, sp)?))
}

fn full(line: &str, rc: &str, ty: &str, val: &str) -> Result<Rewrite, RuleError> {
    if !rc.eq_ignore_ascii_case("NOERROR") {
        return Err(bad("dnsrewrite", "rcode_with_record", span_of(line, rc)));
    }
    let vsp = span_of(line, val);
    if val.is_empty() {
        return Err(bad("dnsrewrite", "missing_value", vsp));
    }
    if ty.eq_ignore_ascii_case("A") {
        let ip = val
            .parse::<Ipv4Addr>()
            .map_err(|_| bad("dnsrewrite", "invalid_ip", vsp))?;
        Ok(Rewrite::A(ip))
    } else if ty.eq_ignore_ascii_case("AAAA") {
        let ip = val
            .parse::<Ipv6Addr>()
            .map_err(|_| bad("dnsrewrite", "invalid_ip", vsp))?;
        Ok(Rewrite::Aaaa(ip))
    } else if ty.eq_ignore_ascii_case("CNAME") {
        Ok(Rewrite::Cname(parse_domain(val, vsp)?))
    } else if ty.eq_ignore_ascii_case("TXT") {
        Ok(Rewrite::Txt(Arc::from(unescape(val))))
    } else {
        Err(bad(
            "dnsrewrite",
            "unsupported_rewrite_type",
            span_of(line, ty),
        ))
    }
}
