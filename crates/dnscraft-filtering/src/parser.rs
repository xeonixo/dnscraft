//! Rule and list parsing.
//!
//! Two entry points share one line parser:
//!
//! - [`parse_rule`] is strict: it returns exactly one [`Rule`] or a
//!   [`RuleError`] with code and byte span. Used for custom rules and the
//!   editor's live validation.
//! - [`parse_list`] is lenient: it never fails as a whole, counts every line
//!   it cannot turn into a rule by [`SkipReason`], and keeps a small sample of
//!   skipped lines for the UI.
//!
//! ## Accepted forms and their semantics
//!
//! | Line | Result |
//! |---|---|
//! | `\|\|x^`, `\|\|x^\|`, `\|\|x`, `\|\|x\|` | domain `x` and all subdomains |
//! | `\|x^`, `\|x\|`, `\|x` | exactly `x` |
//! | `://x^`, `://x\|`, `://x` | exactly `x` (hostname after a URL scheme) |
//! | `://*.x^` | subdomains of `x` only (glob `\|\|*.x^`) |
//! | `x`, `x^`, `x\|` (no start anchor) | domain `x` and all subdomains |
//! | `.x^`, `.x\|`, `.x` (leading dot, no anchor) | subdomains of `x` only (glob `\|\|*.x^`) |
//! | `\|\|1.2.3.4^`, `1.2.3.4`, `@@\|\|2001:db8::1^` | answer-IP rule ([`MatchKind::Ip`](crate::MatchKind::Ip)) |
//! | `@@` + any of the above | allow instead of block |
//! | `IP name [name...] [# comment]` | each name blocked, **exact** match |
//!
//! Decisions (see the task report for confidence):
//!
//! - A line that is a bare valid domain is treated as `\|\|x^`, as AdGuard Home
//!   does for domain lists. In full Adblock syntax an unanchored pattern is a
//!   substring match; the label-aware reading is a deliberate, safe
//!   approximation (it matches a subset of what a substring match would).
//!   The same applies to `x^` and `x\|` without a start anchor.
//! - Hosts names are **exact** matches (AdGuard Home does not add
//!   subdomains for hosts lines), whatever the IP is.
//! - Hosts names `localhost`, `localhost.localdomain`, `local`,
//!   `broadcasthost`, `0.0.0.0` and `ip6-*` are skipped as
//!   [`SkipReason::ReservedHost`]. On a hosts
//!   line every name is counted individually.
//! - `$` modifier lists are recognised syntactically (the text after the last
//!   unescaped `$` that starts with a letter or `~` and contains no `/`) and
//!   parsed by the `modifiers` module. Browser-only modifiers skip the rule as
//!   `Unsupported(BrowserOnly)`; `$client`/`$ctag` skip it as `ClientModifier`
//!   (applying a per-client rule globally would be wrong); unknown ones as
//!   `UnknownModifier`. `$dnsrewrite` records are refused in downloaded lists
//!   (`RewriteFromList`).
//! - Non-ASCII domains are converted to punycode (UTS 46); failures are
//!   `InvalidIdna`.
//! - Wildcard rules (any adblock pattern containing `*`) become
//!   [`MatchKind::Pattern`] rules and `/regex/` rules [`MatchKind::Regex`]
//!   rules; see the `pattern` module for their semantics. Invalid or
//!   oversized regexes are skipped as `InvalidRegex` / `RegexTooLarge`
//!   (errors `filter_rule.invalid_regex`, `filter_rule.regex_too_large`).
//!   Regexes containing `\/` are URL-path regexes and skipped as
//!   `Unsupported(BrowserOnly)`.
//! - Lines longer than 4 KiB are skipped as `TooLong`.

use std::net::IpAddr;
use std::ops::Range;
use std::sync::Arc;

use crate::error::{RuleError, UnsupportedKind};
use crate::modifiers::{Modifiers, parse_domain, parse_modifiers};
use crate::pattern::{Glob, GlobStart, RegexFailure, RegexRule};
use crate::rule::{MatchKind, Rule, RuleAction};

/// Maximum accepted line length in bytes.
pub const MAX_LINE_LEN: usize = 4096;
/// Maximum number of skipped lines kept in [`ParsedList::samples`].
pub const SKIP_SAMPLE_LIMIT: usize = 60;
/// Maximum number of samples kept per [`SkipReason`].
pub const SKIP_SAMPLES_PER_REASON: usize = 5;
const SAMPLE_TEXT_MAX: usize = 200;

/// Where a list body came from. `$dnsrewrite` uses this to decide whether record
/// rewrites are honoured (custom rules) or ignored (downloaded lists).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ListSource {
    /// A downloaded or local filter list (untrusted).
    List,
    /// The user's own custom rules (trusted).
    Custom,
}

/// Why a line (or a hosts name) produced no rule.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum SkipReason {
    /// Valid syntax this engine does not implement (cosmetic, browser-only).
    Unsupported(UnsupportedKind),
    /// Line longer than [`MAX_LINE_LEN`].
    TooLong,
    /// The domain part is not a valid name.
    InvalidDomain,
    /// Malformed rule.
    InvalidSyntax,
    /// Hosts name such as `localhost`.
    ReservedHost,
    /// A modifier this engine does not know.
    UnknownModifier,
    /// `$client` / `$ctag` (per-client scoping is done by profiles).
    ClientModifier,
    /// A `$dnsrewrite` record rewrite in a downloaded list (never honoured).
    RewriteFromList,
    /// A non-ASCII domain that cannot be converted to punycode.
    InvalidIdna,
    /// A `/regex/` rule that does not compile.
    InvalidRegex,
    /// A `/regex/` rule over the compiled size limit.
    RegexTooLarge,
    /// A glob or regex rule dropped because the per-index cap was reached
    /// (see [`crate::MAX_REGEX_RULES`]). Never produced by the parser itself.
    PatternBudget,
}

impl SkipReason {
    /// All reasons, in the order used by [`SkipCounts::iter`].
    pub const ALL: [SkipReason; 13] = [
        SkipReason::Unsupported(UnsupportedKind::Cosmetic),
        SkipReason::Unsupported(UnsupportedKind::BrowserOnly),
        SkipReason::TooLong,
        SkipReason::InvalidDomain,
        SkipReason::InvalidSyntax,
        SkipReason::ReservedHost,
        SkipReason::UnknownModifier,
        SkipReason::ClientModifier,
        SkipReason::RewriteFromList,
        SkipReason::InvalidIdna,
        SkipReason::InvalidRegex,
        SkipReason::RegexTooLarge,
        SkipReason::PatternBudget,
    ];

    fn index(self) -> usize {
        match self {
            Self::Unsupported(UnsupportedKind::Cosmetic) => 0,
            Self::Unsupported(UnsupportedKind::BrowserOnly) => 1,
            Self::TooLong => 2,
            Self::InvalidDomain => 3,
            Self::InvalidSyntax => 4,
            Self::ReservedHost => 5,
            Self::UnknownModifier => 6,
            Self::ClientModifier => 7,
            Self::RewriteFromList => 8,
            Self::InvalidIdna => 9,
            Self::InvalidRegex => 10,
            Self::RegexTooLarge => 11,
            Self::PatternBudget => 12,
            // `UnsupportedKind` is non-exhaustive for other crates only; new
            // kinds must be added to `ALL` and here.
            #[allow(unreachable_patterns)]
            Self::Unsupported(_) => 4,
        }
    }

    /// Stable identifier for APIs and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported(k) => k.as_str(),
            Self::TooLong => "too_long",
            Self::InvalidDomain => "invalid_domain",
            Self::InvalidSyntax => "invalid_syntax",
            Self::ReservedHost => "reserved_host",
            Self::UnknownModifier => "unknown_modifier",
            Self::ClientModifier => "client_modifier",
            Self::RewriteFromList => "rewrite_from_list",
            Self::InvalidIdna => "invalid_idna",
            Self::InvalidRegex => "invalid_regex",
            Self::RegexTooLarge => "regex_too_large",
            Self::PatternBudget => "pattern_budget",
        }
    }
}

impl From<&RuleError> for SkipReason {
    fn from(e: &RuleError) -> Self {
        match e {
            RuleError::TooLong { .. } => Self::TooLong,
            RuleError::InvalidDomain { .. } => Self::InvalidDomain,
            RuleError::Unsupported { kind, .. } => Self::Unsupported(*kind),
            RuleError::ReservedHost { .. } => Self::ReservedHost,
            RuleError::UnknownModifier { .. } => Self::UnknownModifier,
            RuleError::ClientModifier { .. } => Self::ClientModifier,
            RuleError::RewriteFromList { .. } => Self::RewriteFromList,
            RuleError::InvalidIdna { .. } => Self::InvalidIdna,
            RuleError::InvalidRegex { .. } => Self::InvalidRegex,
            RuleError::RegexTooLarge { .. } => Self::RegexTooLarge,
            _ => Self::InvalidSyntax,
        }
    }
}

/// Number of skipped items per [`SkipReason`].
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SkipCounts([usize; 13]);

impl SkipCounts {
    /// Count for one reason.
    pub fn get(&self, reason: SkipReason) -> usize {
        self.0.get(reason.index()).copied().unwrap_or(0)
    }

    /// Sum over all reasons.
    pub fn total(&self) -> usize {
        self.0.iter().sum()
    }

    /// `(reason, count)` for every reason, including zero counts.
    pub fn iter(&self) -> impl Iterator<Item = (SkipReason, usize)> + '_ {
        SkipReason::ALL.iter().map(|r| (*r, self.get(*r)))
    }

    /// Adds `n` skipped items of `reason`.
    pub(crate) fn add_n(&mut self, reason: SkipReason, n: usize) {
        if let Some(c) = self.0.get_mut(reason.index()) {
            *c = c.saturating_add(n);
        }
    }

    fn add(&mut self, reason: SkipReason) {
        if let Some(c) = self.0.get_mut(reason.index()) {
            *c += 1;
        }
    }
}

/// One skipped line kept as a sample for the UI.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SkippedLine {
    /// 1-based line number.
    pub line: u32,
    /// Why it was skipped.
    pub reason: SkipReason,
    /// The matching [`RuleError::code`].
    pub code: &'static str,
    /// The trimmed line, cut to 200 bytes.
    pub text: String,
}

/// Counts and samples from a lenient list parse (no rule vector).
///
/// Produced by [`parse_list_each`]; [`parse_list`] wraps the same stats with
/// the collected [`Rule`]s.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub struct ListParseStats {
    /// Number of lines in the body.
    pub total_lines: usize,
    /// Blank lines.
    pub blank_lines: usize,
    /// Comment lines (`!`, `#`, `[Adblock ...]` headers).
    pub comment_lines: usize,
    /// Rules handed to the callback (or collected by [`parse_list`]).
    pub rules_parsed: usize,
    /// Skipped items by reason. A hosts line can contribute several.
    pub skipped: SkipCounts,
    /// The first [`SKIP_SAMPLES_PER_REASON`] skipped items of each reason, at
    /// most [`SKIP_SAMPLE_LIMIT`] in total.
    pub samples: Vec<SkippedLine>,
}

/// Result of [`parse_list`].
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub struct ParsedList {
    /// All rules, in file order. Source text is recovered with
    /// [`Rule::text`] and the original body.
    pub rules: Vec<Rule>,
    /// Number of lines in the body.
    pub total_lines: usize,
    /// Blank lines.
    pub blank_lines: usize,
    /// Comment lines (`!`, `#`, `[Adblock ...]` headers).
    pub comment_lines: usize,
    /// Skipped items by reason. A hosts line can contribute several.
    pub skipped: SkipCounts,
    /// The first [`SKIP_SAMPLES_PER_REASON`] skipped items of each reason, at
    /// most [`SKIP_SAMPLE_LIMIT`] in total.
    pub samples: Vec<SkippedLine>,
}

enum Item {
    Blank,
    Comment,
    Rule {
        rule: Rule,
        modifiers: Modifiers,
        span: Range<usize>,
    },
    Skip(RuleError),
}

/// Whitespace the parser trims around rule lines.
pub(crate) fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n' | '\x0b' | '\x0c')
}

/// Trims ASCII whitespace and a leading UTF-8 BOM (U+FEFF).
///
/// A BOM on a single rule line (or after spaces) must not turn an IP literal
/// into a domain via IDNA; `parse_list` already skips a file-level BOM.
fn trim_rule_line(line: &str) -> &str {
    line.trim_matches(is_ws)
        .trim_start_matches('\u{feff}')
        .trim_matches(is_ws)
}

/// Byte offset of `sub` within `base`; `sub` must be a sub-slice of `base`.
pub(crate) fn off(base: &str, sub: &str) -> usize {
    (sub.as_ptr() as usize).saturating_sub(base.as_ptr() as usize)
}

pub(crate) fn span_of(base: &str, sub: &str) -> Range<usize> {
    let s = off(base, sub);
    s..s + sub.len()
}

/// Parses exactly one rule (strict).
///
/// Blank lines and comments are errors (`filter_rule.empty`,
/// `filter_rule.comment`), as is a hosts line with several names
/// (`filter_rule.multiple_names`) or any skipped name. The resulting
/// [`Rule`] refers to line 1 of `input`.
pub fn parse_rule(input: &str) -> Result<Rule, RuleError> {
    let t = trim_rule_line(input);
    let t_span = span_of(input, t);
    let mut err: Option<RuleError> = None;
    let mut rule: Option<Rule> = None;
    let mut multi: Option<Range<usize>> = None;
    parse_line(input, ListSource::Custom, &mut |item| match item {
        Item::Blank => {
            err.get_or_insert(RuleError::Empty {
                span: 0..input.len(),
            });
        }
        Item::Comment => {
            err.get_or_insert(RuleError::Comment {
                span: t_span.clone(),
            });
        }
        Item::Skip(e) => {
            err.get_or_insert(e);
        }
        Item::Rule {
            rule: base,
            modifiers,
            span,
        } => {
            if rule.is_some() {
                multi.get_or_insert(span);
            } else {
                let len = u16::try_from(t_span.len()).unwrap_or(u16::MAX);
                let start = u32::try_from(t_span.start).unwrap_or(0);
                rule = Some(base.with_modifiers(modifiers).with_source(1, start, len));
            }
        }
    });
    if let Some(e) = err {
        return Err(e);
    }
    if let Some(span) = multi {
        return Err(RuleError::MultipleNames { span });
    }
    rule.ok_or(RuleError::Empty {
        span: 0..input.len(),
    })
}

/// Parses a whole list body (lenient), calling `on_rule` for each rule.
///
/// Never fails and never builds a [`Vec`] of rules — use this when feeding an
/// [`IndexBuilder`](crate::IndexBuilder) so the peak stays at one rule at a
/// time. A leading UTF-8 BOM is ignored; `\n` and `\r\n` end lines. Rule
/// offsets refer to `body` as given (including the BOM).
pub fn parse_list_each<F>(body: &str, source: ListSource, mut on_rule: F) -> ListParseStats
where
    F: FnMut(Rule),
{
    let mut out = ListParseStats::default();
    let start = if body.starts_with('\u{feff}') { 3 } else { 0 };
    let mut offset = start;
    let mut line_no: u32 = 0;
    for raw in body.get(start..).unwrap_or("").split_inclusive('\n') {
        let line_start = offset;
        offset += raw.len();
        line_no = line_no.saturating_add(1);
        out.total_lines += 1;
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        let line = line.strip_suffix('\r').unwrap_or(line);

        if offset > u32::MAX as usize {
            // Offsets are u32: the list size cap (64 MiB) keeps this unreachable
            // in practice; refuse rather than wrap.
            let e = RuleError::TooLong {
                len: line.len(),
                span: 0..line.len(),
            };
            record_skip(&mut out, line_no, line, &e);
            continue;
        }
        let trimmed = trim_rule_line(line);
        let lead = off(line, trimmed);
        parse_line(line, source, &mut |item| match item {
            Item::Blank => out.blank_lines += 1,
            Item::Comment => out.comment_lines += 1,
            Item::Rule {
                rule, modifiers, ..
            } => {
                let trimmed_len = trimmed.len();
                on_rule(rule.with_modifiers(modifiers).with_source(
                    line_no,
                    u32::try_from(line_start + lead).unwrap_or(0),
                    u16::try_from(trimmed_len).unwrap_or(u16::MAX),
                ));
                out.rules_parsed = out.rules_parsed.saturating_add(1);
            }
            Item::Skip(e) => record_skip(&mut out, line_no, line, &e),
        });
    }
    out
}

/// Parses a whole list body (lenient). Never fails.
///
/// Collects every rule into a [`Vec`]. Prefer [`parse_list_each`] when the
/// rules are only fed into an index builder.
pub fn parse_list(body: &str, source: ListSource) -> ParsedList {
    let mut rules = Vec::new();
    let stats = parse_list_each(body, source, |r| rules.push(r));
    ParsedList {
        rules,
        total_lines: stats.total_lines,
        blank_lines: stats.blank_lines,
        comment_lines: stats.comment_lines,
        skipped: stats.skipped,
        samples: stats.samples,
    }
}

fn record_skip(out: &mut ListParseStats, line_no: u32, line: &str, e: &RuleError) {
    let reason = SkipReason::from(e);
    out.skipped.add(reason);
    if out.samples.len() < SKIP_SAMPLE_LIMIT && out.skipped.get(reason) <= SKIP_SAMPLES_PER_REASON {
        let t = trim_rule_line(line);
        let mut n = t.len().min(SAMPLE_TEXT_MAX);
        while !t.is_char_boundary(n) {
            n -= 1;
        }
        out.samples.push(SkippedLine {
            line: line_no,
            reason,
            code: e.code(),
            text: t.get(..n).unwrap_or("").to_string(),
        });
    }
}

fn parse_line<F: FnMut(Item)>(line: &str, source: ListSource, emit: &mut F) {
    if line.len() > MAX_LINE_LEN {
        emit(Item::Skip(RuleError::TooLong {
            len: line.len(),
            span: 0..line.len(),
        }));
        return;
    }
    let t = trim_rule_line(line);
    if t.is_empty() {
        emit(Item::Blank);
        return;
    }
    if is_comment(t) {
        emit(Item::Comment);
        return;
    }
    if parse_hosts(line, t, emit) {
        return;
    }
    if let Some(span) = find_cosmetic(line, t) {
        emit(Item::Skip(RuleError::Unsupported {
            kind: UnsupportedKind::Cosmetic,
            span,
        }));
        return;
    }
    match parse_adblock(line, t, source) {
        Ok(item) => emit(item),
        Err(e) => emit(Item::Skip(e)),
    }
}

/// True when `s` (starting with `#`) begins a cosmetic marker such as `##`,
/// `#@#`, `#$#`, `#?#`, `#%#`, `#@$#`.
fn cosmetic_marker_at(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 1;
    if b.get(i) == Some(&b'@') {
        i += 1;
    }
    if matches!(b.get(i), Some(b'$' | b'?' | b'%')) {
        i += 1;
    }
    b.get(i) == Some(&b'#')
}

fn is_comment(t: &str) -> bool {
    if t.starts_with('!') {
        return true;
    }
    if t.as_bytes()
        .get(..8)
        .is_some_and(|b| b.eq_ignore_ascii_case(b"[adblock"))
    {
        return true;
    }
    t.starts_with('#') && (t.bytes().all(|b| b == b'#') || !cosmetic_marker_at(t))
}

fn find_cosmetic(line: &str, t: &str) -> Option<Range<usize>> {
    for (i, _) in t.match_indices('#') {
        if let Some(rest) = t.get(i..) {
            if cosmetic_marker_at(rest) {
                let s = off(line, t) + i;
                return Some(s..off(line, t) + t.len());
            }
        }
    }
    // HTML filtering rules: `example.org$$script[...]`, `example.org$@$...`.
    for pat in ["$$", "$@$"] {
        if let Some(i) = t.find(pat) {
            let s = off(line, t) + i;
            return Some(s..off(line, t) + t.len());
        }
    }
    None
}

fn is_reserved_host(name: &str) -> bool {
    const RESERVED: [&str; 5] = [
        "localhost",
        "localhost.localdomain",
        "local",
        "broadcasthost",
        "0.0.0.0",
    ];
    RESERVED.iter().any(|r| name.eq_ignore_ascii_case(r))
        || name
            .as_bytes()
            .get(..4)
            .is_some_and(|b| b.eq_ignore_ascii_case(b"ip6-"))
}

/// Handles `IP name...` lines. Returns false if the first token is no IP.
fn parse_hosts<F: FnMut(Item)>(line: &str, t: &str, emit: &mut F) -> bool {
    let mut toks = t.split(is_ws).filter(|s| !s.is_empty());
    let Some(first) = toks.next() else {
        return false;
    };
    if first.parse::<IpAddr>().is_err() {
        return false;
    }
    let mut any = false;
    for tok in toks {
        let (name, last) = match tok.find('#') {
            Some(0) => break,
            Some(i) => (tok.get(..i).unwrap_or(tok), true),
            None => (tok, false),
        };
        any = true;
        let span = span_of(line, name);
        if is_reserved_host(name) {
            emit(Item::Skip(RuleError::ReservedHost { span }));
        } else if name.parse::<IpAddr>().is_ok() {
            // Same verdict as the adblock path: an IP literal is not a domain.
            emit(Item::Skip(RuleError::InvalidSyntax {
                detail: "ip_address",
                span,
            }));
        } else {
            match parse_domain(name, span.clone()) {
                Ok(domain) => emit(Item::Rule {
                    rule: Rule::new(RuleAction::Block, MatchKind::Exact, domain),
                    modifiers: Modifiers::default(),
                    span,
                }),
                Err(e) => emit(Item::Skip(e)),
            }
        }
        if last {
            break;
        }
    }
    if !any {
        // A bare IP (no hostname) is an AdGuard answer-IP rule, not a
        // broken hosts line.
        if let Ok(ip) = first.parse::<IpAddr>() {
            emit(Item::Rule {
                rule: Rule::new_ip(RuleAction::Block, ip),
                modifiers: Modifiers::default(),
                span: span_of(line, first),
            });
        } else {
            emit(Item::Skip(RuleError::InvalidSyntax {
                detail: "ip_without_name",
                span: span_of(line, first),
            }));
        }
    }
    true
}

/// Splits `rest` at the modifier separator. Returns `(pattern, modifiers)`
/// where `modifiers` excludes the `$`.
fn split_modifiers(rest: &str) -> (&str, Option<&str>) {
    if let Some(i) = rest.rfind('$') {
        let escaped = i > 0 && rest.as_bytes().get(i - 1) == Some(&b'\\');
        let mods = rest.get(i + 1..).unwrap_or("");
        let plausible = mods
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '~')
            && !mods.contains('/');
        if !escaped && plausible {
            return (rest.get(..i).unwrap_or(rest), Some(mods));
        }
    }
    (rest, None)
}

fn parse_adblock(line: &str, t: &str, source: ListSource) -> Result<Item, RuleError> {
    let (action, rest) = match t.strip_prefix("@@") {
        Some(r) => (RuleAction::Allow, r),
        None => (RuleAction::Block, t),
    };
    let (pat, mods) = split_modifiers(rest);
    let (rule, span) = parse_pattern(line, pat, action)?;
    let modifiers = match mods {
        Some(m) => parse_modifiers(line, m, action, source)?,
        None => Modifiers::default(),
    };
    Ok(Item::Rule {
        rule,
        modifiers,
        span,
    })
}

fn parse_pattern(
    line: &str,
    pat: &str,
    action: RuleAction,
) -> Result<(Rule, Range<usize>), RuleError> {
    if pat.len() >= 2 && pat.starts_with('/') && pat.ends_with('/') {
        return parse_regex(line, pat, action);
    }
    // `://host` is a hostname-start anchor in URL syntax (AdGuard DNS filter
    // ships rules like `://jhf.ru^`). A path after the host stays browser-only.
    let (start, body) = if let Some(r) = pat.strip_prefix("://") {
        if r.contains('/') {
            return Err(RuleError::Unsupported {
                kind: UnsupportedKind::BrowserOnly,
                span: span_of(line, pat),
            });
        }
        // `://*.x^` → same as `||*.x^`; plain `://x^` → same as `|x^`.
        if r.starts_with('*') {
            (GlobStart::Boundary, r)
        } else {
            (GlobStart::Exact, r)
        }
    } else if pat.contains('/') {
        return Err(RuleError::Unsupported {
            kind: UnsupportedKind::BrowserOnly,
            span: span_of(line, pat),
        });
    } else if let Some(r) = pat.strip_prefix("||") {
        (GlobStart::Boundary, r)
    } else if let Some(r) = pat.strip_prefix('|') {
        (GlobStart::Exact, r)
    } else {
        (GlobStart::Anywhere, pat)
    };
    let (body, end_anchored) = match body.strip_suffix('|') {
        Some(b) => (b.strip_suffix('^').unwrap_or(b), true),
        None => match body.strip_suffix('^') {
            Some(b) => (b, true),
            None => (body, false),
        },
    };
    let span = span_of(line, body);
    if pat.contains('*') {
        let glob = Glob::from_body(body, start, end_anchored, span.clone())?;
        return Ok((Rule::new_glob(action, Arc::new(glob)), span));
    }
    if start == GlobStart::Anywhere && body.starts_with('.') {
        return parse_leading_dot(action, body, span);
    }
    let kind = match start {
        GlobStart::Exact => MatchKind::Exact,
        _ => MatchKind::Subdomains,
    };
    if body.is_empty() {
        return Err(RuleError::InvalidSyntax {
            detail: "empty_pattern",
            span: if pat.is_empty() {
                span
            } else {
                span_of(line, pat)
            },
        });
    }
    if body.contains(['|', '^']) {
        return Err(RuleError::InvalidSyntax {
            detail: "misplaced_anchor",
            span,
        });
    }
    if let Ok(ip) = body.parse::<IpAddr>() {
        // AdGuard DNS filter IP rules match answers, not query names.
        // Anchor kind (`||` / `|` / bare) is ignored; hosts *names* that are
        // IPs stay invalid (see [`parse_hosts`]).
        let _ = kind;
        return Ok((Rule::new_ip(action, ip), span));
    }
    parse_domain(body, span.clone()).map(|domain| (Rule::new(action, kind, domain), span))
}

/// `.x^`, `.x|`, `.x` (no start anchor): in adblock semantics the name must
/// contain `.x` followed by the end, i.e. subdomains of `x` but not `x`
/// itself. Compiled as the glob `||*.x^`.
fn parse_leading_dot(
    action: RuleAction,
    body: &str,
    span: Range<usize>,
) -> Result<(Rule, Range<usize>), RuleError> {
    let rest = body.get(1..).unwrap_or("");
    if rest.is_empty() {
        return Err(RuleError::InvalidSyntax {
            detail: "empty_pattern",
            span,
        });
    }
    if rest.contains(['|', '^']) {
        return Err(RuleError::InvalidSyntax {
            detail: "misplaced_anchor",
            span,
        });
    }
    if rest.parse::<IpAddr>().is_ok() {
        return Err(RuleError::InvalidSyntax {
            detail: "ip_address",
            span,
        });
    }
    if rest.ends_with('.') {
        return Err(RuleError::InvalidDomain {
            source: crate::error::NameError::EmptyLabel,
            span,
        });
    }
    // Validates the domain (including IDNA).
    parse_domain(rest, span.clone())?;
    let glob = Glob::from_body(&format!("*{body}"), GlobStart::Boundary, true, span.clone())?;
    Ok((Rule::new_glob(action, Arc::new(glob)), span))
}

fn parse_regex(
    line: &str,
    pat: &str,
    action: RuleAction,
) -> Result<(Rule, Range<usize>), RuleError> {
    let span = span_of(line, pat);
    let body = pat.get(1..pat.len() - 1).unwrap_or("");
    if body.is_empty() {
        return Err(RuleError::InvalidSyntax {
            detail: "empty_regex",
            span,
        });
    }
    if body.contains("\\/") {
        // URL-path regex from a browser list.
        return Err(RuleError::Unsupported {
            kind: UnsupportedKind::BrowserOnly,
            span,
        });
    }
    match RegexRule::compile(body) {
        Ok(r) => Ok((Rule::new_regex(action, Arc::new(r)), span)),
        Err(RegexFailure::TooLarge) => Err(RuleError::RegexTooLarge { span }),
        Err(RegexFailure::Invalid(message)) => Err(RuleError::InvalidRegex { message, span }),
    }
}
