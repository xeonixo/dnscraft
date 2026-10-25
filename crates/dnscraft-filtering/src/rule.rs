//! The parsed rule model.
//!
//! ## Memory layout
//!
//! A [`Rule`] is 40 bytes plus the heap allocation of its [`DomainName`]. It
//! does **not** own its source text. Instead it stores where the line lives in
//! the list body: 1-based line number (`u32`), byte offset of the trimmed line
//! (`u32`) and its length (`u16`, lines are capped at 4 KiB). The caller keeps
//! the list body once and recovers the text on demand with [`Rule::text`]. The
//! match index (Task M1) is expected to consume rules into an arena and keep
//! only line numbers. Modifiers are boxed and absent for the common plain
//! rule.

use std::ops::Range;

pub use crate::modifiers::{DnsRewrite, DnsTypeFilter, Modifiers};
use crate::name::DomainName;

/// What a matching rule does.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum RuleAction {
    /// Block the name (`||x^`, plain domains, hosts lines).
    Block,
    /// Allow the name (`@@||x^`).
    Allow,
}

/// How the rule's domain is matched against a query name.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum MatchKind {
    /// The domain and all its subdomains (`||x^`, plain domain).
    Subdomains,
    /// Exactly the domain (`|x^`, `|x|`, hosts lines).
    Exact,
    /// Wildcard pattern (Task F4; never produced yet).
    Pattern,
    /// Regular expression (Task F4; never produced yet).
    Regex,
}

/// Identity of a rule for `$badfilter`, see [`Rule::badfilter_key`].
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct BadfilterKey {
    action: RuleAction,
    kind: MatchKind,
    domain: DomainName,
    modifiers: Modifiers,
}

/// A parsed filter rule.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Rule {
    domain: DomainName,
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
        Self {
            domain,
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

    /// The canonical domain.
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// The rule's modifiers.
    pub fn modifiers(&self) -> &Modifiers {
        self.modifiers.as_deref().unwrap_or(&Modifiers::NONE)
    }

    /// Identity used by `$badfilter`: a rule with `$badfilter` disables every
    /// rule whose key equals its own key.
    ///
    /// The key is the action, match kind, canonical domain and all modifiers
    /// except `badfilter`. It compares the *parsed* rule, so `||x^` and `||x`
    /// are identical (AdGuard
    /// compares the raw text minus `$badfilter`; this is a deliberate superset).
    /// The rule carrying `$badfilter` and the rule it disables have equal keys.
    pub fn badfilter_key(&self) -> BadfilterKey {
        let mut m = self.modifiers().clone();
        m.badfilter = false;
        BadfilterKey {
            action: self.action,
            kind: self.kind,
            domain: self.domain.clone(),
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
