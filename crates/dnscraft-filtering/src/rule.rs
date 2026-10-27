//! The parsed rule model.
//!
//! ## Memory layout
//!
//! A [`Rule`] is 48 bytes plus the heap allocation of its [`DomainName`] (or a
//! shared [`Glob`]/[`RegexRule`] for the rare pattern rules). It
//! does **not** own its source text. Instead it stores where the line lives in
//! the list body: 1-based line number (`u32`), byte offset of the trimmed line
//! (`u32`) and its length (`u16`, lines are capped at 4 KiB). The caller keeps
//! the list body once and recovers the text on demand with [`Rule::text`]. The
//! match index (Task M1) is expected to consume rules into an arena and keep
//! only line numbers. Modifiers are boxed and absent for the common plain
//! rule.

use std::net::IpAddr;
use std::ops::Range;
use std::sync::Arc;

pub use crate::modifiers::{DnsRewrite, DnsTypeFilter, Modifiers};
use crate::name::DomainName;
use crate::pattern::{Glob, RegexRule};

/// What a matching rule does.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]

pub enum RuleAction {
    /// Block the name (`||x^`, plain domains, hosts lines).
    Block,
    /// Allow the name (`@@||x^`).
    Allow,
}

/// How the rule's domain is matched against a query name.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]

pub enum MatchKind {
    /// The domain and all its subdomains (`||x^`, plain domain).
    Subdomains,
    /// Exactly the domain (`|x^`, `|x|`, hosts lines).
    Exact,
    /// Wildcard pattern, see [`Rule::glob`]. Rules of this kind have no domain.
    Pattern,
    /// Regular expression, see [`Rule::regex`]. Rules of this kind have no domain.
    Regex,
    /// An IPv4/IPv6 address matched against DNS **answers** (A/AAAA), see
    /// [`Rule::ip`]. Not used for query-name matching.
    Ip,
}

/// Identity of a rule for `$badfilter`, see [`Rule::badfilter_key`].
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct BadfilterKey {
    action: RuleAction,
    kind: MatchKind,
    /// Canonical domain, glob text, or regex source.
    text: Box<str>,
    modifiers: Modifiers,
}

/// What a rule matches against.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Target {
    Domain(DomainName),
    Glob(Arc<Glob>),
    Regex(Arc<RegexRule>),
    Ip(IpAddr),
}

/// A parsed filter rule.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Rule {
    target: Target,
    action: RuleAction,
    kind: MatchKind,
    modifiers: Option<Box<Modifiers>>,
    line: u32,
    offset: u32,
    len: u16,
}

impl Rule {
    /// Builds a rule that has no source text (for example for built-in
    /// services). [`Rule::text`] returns `None` for it.
    pub fn new(action: RuleAction, kind: MatchKind, domain: DomainName) -> Self {
        Self::with_target(action, kind, Target::Domain(domain))
    }

    /// Builds a wildcard rule ([`MatchKind::Pattern`]).
    pub fn new_glob(action: RuleAction, glob: Arc<Glob>) -> Self {
        Self::with_target(action, MatchKind::Pattern, Target::Glob(glob))
    }

    /// Builds a regex rule ([`MatchKind::Regex`]).
    pub fn new_regex(action: RuleAction, regex: Arc<RegexRule>) -> Self {
        Self::with_target(action, MatchKind::Regex, Target::Regex(regex))
    }

    /// Builds an answer-IP rule ([`MatchKind::Ip`]).
    pub fn new_ip(action: RuleAction, ip: IpAddr) -> Self {
        Self::with_target(action, MatchKind::Ip, Target::Ip(ip))
    }

    fn with_target(action: RuleAction, kind: MatchKind, target: Target) -> Self {
        Self {
            target,
            action,
            kind,
            modifiers: None,
            line: 0,
            offset: 0,
            len: 0,
        }
    }

    pub(crate) fn with_source(mut self, line: u32, offset: u32, len: u16) -> Self {
        self.line = line;
        self.offset = offset;
        self.len = len;
        self
    }

    pub(crate) fn with_modifiers(mut self, modifiers: Modifiers) -> Self {
        self.modifiers = (!modifiers.is_empty()).then(|| Box::new(modifiers));
        self
    }

    /// Block or allow.
    pub fn action(&self) -> RuleAction {
        self.action
    }

    /// How the domain is matched.
    pub fn kind(&self) -> MatchKind {
        self.kind
    }

    /// The canonical domain; `None` for pattern, regex and IP rules.
    pub fn domain(&self) -> Option<&DomainName> {
        match &self.target {
            Target::Domain(d) => Some(d),
            _ => None,
        }
    }

    /// The wildcard pattern of a [`MatchKind::Pattern`] rule.
    pub fn glob(&self) -> Option<&Arc<Glob>> {
        match &self.target {
            Target::Glob(g) => Some(g),
            _ => None,
        }
    }

    /// The regex of a [`MatchKind::Regex`] rule.
    pub fn regex(&self) -> Option<&Arc<RegexRule>> {
        match &self.target {
            Target::Regex(r) => Some(r),
            _ => None,
        }
    }

    /// The address of a [`MatchKind::Ip`] rule.
    pub fn ip(&self) -> Option<IpAddr> {
        match &self.target {
            Target::Ip(ip) => Some(*ip),
            _ => None,
        }
    }

    /// Literal that every name matched by this pattern or regex rule
    /// contains (lower-case); `None` for domain/IP rules and when unknown.
    pub fn prefilter(&self) -> Option<&str> {
        match &self.target {
            Target::Domain(_) | Target::Ip(_) => None,
            Target::Glob(g) => g.prefilter(),
            Target::Regex(r) => r.prefilter(),
        }
    }

    /// Evaluates a pattern or regex rule against a canonical name (prefilter
    /// first). Always `false` for domain and IP rules: those go through the
    /// index. Modifiers (`$dnstype`, `$denyallow`) are not considered here.
    pub fn pattern_matches(&self, name: &str) -> bool {
        if let Some(p) = self.prefilter()
            && !name.contains(p)
        {
            return false;
        }
        match &self.target {
            Target::Domain(_) | Target::Ip(_) => false,
            Target::Glob(g) => g.matches(name),
            Target::Regex(r) => r.is_match(name),
        }
    }

    /// The rule's modifiers.
    pub fn modifiers(&self) -> &Modifiers {
        self.modifiers.as_deref().unwrap_or(&Modifiers::NONE)
    }

    /// Identity used by `$badfilter`: a rule with `$badfilter` disables every
    /// rule whose key equals its own key.
    ///
    /// The key is the action, match kind, canonical domain (or canonical glob
    /// text, or regex source) and all modifiers except `badfilter`. It compares the *parsed* rule, so `||x^` and `||x`
    /// are identical (AdGuard
    /// compares the raw text minus `$badfilter`; this is a deliberate superset).
    /// The rule carrying `$badfilter` and the rule it disables have equal keys.
    pub fn badfilter_key(&self) -> BadfilterKey {
        let mut m = self.modifiers().clone();
        m.badfilter = false;
        BadfilterKey {
            action: self.action,
            kind: self.kind,
            text: match &self.target {
                Target::Domain(d) => d.as_str().into(),
                Target::Glob(g) => g.canonical().into(),
                Target::Regex(r) => r.as_str().into(),
                Target::Ip(ip) => ip.to_string().into(),
            },
            modifiers: m,
        }
    }

    /// 1-based line number in the source, 0 when the rule has no source.
    pub fn line(&self) -> u32 {
        self.line
    }

    /// Byte range of the (trimmed) source line within the list body.
    pub fn span(&self) -> Range<usize> {
        let start = self.offset as usize;
        start..start + usize::from(self.len)
    }

    /// Recovers the rule text from the body it was parsed from. Returns
    /// `None` if the rule has no source or `body` is not the parsed body.
    pub fn text<'a>(&self, body: &'a str) -> Option<&'a str> {
        if self.line == 0 {
            return None;
        }
        body.get(self.span())
    }
}
