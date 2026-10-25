//! Wildcard (glob) and regular-expression rules.
//!
//! ## Glob semantics (AdGuard adblock syntax applied to host names)
//!
//! A glob rule is an adblock pattern that contains at least one `*`:
//!
//! | Token | Meaning |
//! |---|---|
//! | `*` | any sequence of characters, **including dots and the empty sequence** |
//! | `\|\|` (start) | the match starts at the beginning of the name or right after a dot |
//! | `\|` (start) | the match starts at the beginning of the name |
//! | no start anchor | the match may start anywhere (substring semantics) |
//! | `^` | end of the name (a host name has no other separator characters) |
//! | `\|` (end) | end of the name, same as `^` |
//! | no end anchor | the match may end anywhere |
//!
//! Examples (`yes` = matches, `no` = does not):
//!
//! | Rule | `ads.example.com` | `ad1.example` | `a.ad1.example` | `example` | `x.example` |
//! |---|---|---|---|---|---|
//! | `\|\|ad*.example^` | no | yes | yes | no | no |
//! | `\|\|*.example^` | no | no | yes | **no** (apex) | yes |
//! | `ads*.example.com` | yes | no | no | no | no |
//! | `*ads*` | yes | no | no | no | no |
//! | `\|ad*^` | no | yes | no | no | no |
//!
//! `||*.example^` therefore matches subdomains only, never the apex, exactly as
//! in AdGuard. `*` crossing dots follows AdGuard's adblock semantics:
//! `||ad*.example^` also matches `ad1.sub.example`.
//!
//! A pattern needs at least one ASCII letter or digit literal, so a rule such
//! as `*` or `*.*` can never block everything by accident (use `/./` for that).
//! Literals are lower-cased; non-ASCII literals are converted with IDNA.
//!
//! Matching works on the canonical name ([`DomainName`](crate::DomainName):
//! lower-case, no trailing dot). It uses the classic two-pointer glob
//! algorithm with single-star backtracking: O(n·m) worst case, no allocation,
//! no exponential blow-up. `||` is evaluated as the union of "anchored at the
//! start" and "`*.` then anchored at the start".
//!
//! ## Regex semantics
//!
//! `/…/` rules use the `regex` crate (linear time, no backreferences or
//! look-around), case-insensitive, matched against the canonical name
//! (lower-case, **no trailing dot**) with unanchored search semantics like
//! AdGuard: `/^ads?[0-9]*\.example$/` anchors explicitly.
//! Each regex is limited to [`REGEX_SIZE_LIMIT`] bytes of compiled program and
//! [`REGEX_DFA_SIZE_LIMIT`] bytes of lazy-DFA cache. Regexes whose body contains
//! `\/` are URL-path regexes from browser lists and are skipped as
//! browser-only. Per index, the number of regex and glob rules and the summed
//! estimated regex size are capped (see [`crate::MAX_REGEX_RULES`]).
//!
//! ## Prefilter
//!
//! Every glob and regex may expose a lower-case literal that any matching name
//! must contain. The index checks `name.contains(prefilter)` before running
//! the matcher. The extraction is conservative: it can return `None`, but a
//! returned literal is always required (no false negatives).

use std::fmt::Write as _;
use std::ops::Range;

use regex::bytes::{Regex, RegexBuilder};

use crate::error::{NameError, RuleError};

/// Compiled-program size limit per regex rule (bytes).
pub const REGEX_SIZE_LIMIT: usize = 8 * 1024;
/// Lazy-DFA cache limit per regex rule (bytes).
pub const REGEX_DFA_SIZE_LIMIT: usize = 64 * 1024;
/// Maximum length of the regex error message kept in [`RuleError::InvalidRegex`].
pub const REGEX_MESSAGE_MAX: usize = 200;

/// Wildcard marker in the token string. Never a valid name byte.
const STAR: u8 = 0xFF;
/// Zero-width "end of name" marker. Never a valid name byte.
const END: u8 = 0;

/// Where a glob match may begin.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum GlobStart {
    /// No anchor: anywhere in the name.
    Anywhere,
    /// `||`: start of the name or after a dot.
    Boundary,
    /// `|`: start of the name.
    Exact,
}

/// A compiled wildcard pattern. See the [module documentation](self).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Glob {
    start: GlobStart,
    end_anchored: bool,
    /// Literal bytes (lower-case), [`STAR`] and [`END`]. For `Anywhere` there
    /// is no leading star and for an unanchored end no trailing star: those
    /// are implicit.
    core: Box<[u8]>,
    prefilter: Option<Box<str>>,
}

impl Glob {
    /// Builds a glob from the text between the anchors.
    ///
    /// `body` may contain `*`, `^` (end of name, only last or followed by `*`)
    /// and literal host-name characters.
    pub(crate) fn from_body(
        body: &str,
        start: GlobStart,
        end_anchored: bool,
        span: Range<usize>,
    ) -> Result<Self, RuleError> {
        let mut core: Vec<u8> = Vec::with_capacity(body.len() + 1);
        let mut lit = String::new();
        for c in body.chars() {
            match c {
                '*' | '^' => {
                    flush_literal(&mut lit, &mut core, &span)?;
                    if c == '*' {
                        if core.last() != Some(&STAR) {
                            core.push(STAR);
                        }
                    } else {
                        core.push(END);
                    }
                }
                '|' => {
                    return Err(RuleError::InvalidSyntax {
                        detail: "misplaced_anchor",
                        span,
                    });
                }
                _ => lit.push(c),
            }
        }
        flush_literal(&mut lit, &mut core, &span)?;
        if end_anchored && core.last() != Some(&END) {
            core.push(END);
        }
        if start == GlobStart::Anywhere {
            while core.first() == Some(&STAR) {
                core.remove(0);
            }
        }
        if !end_anchored {
            while core.last() == Some(&STAR) {
                core.pop();
            }
        }
        // `^` may only be followed by `*`: anything else can never match.
        if let Some(i) = core.iter().position(|b| *b == END)
            && core
                .get(i + 1..)
                .is_some_and(|t| t.iter().any(|b| *b != STAR))
        {
            return Err(RuleError::InvalidSyntax {
                detail: "misplaced_anchor",
                span,
            });
        }
        if !core.iter().any(u8::is_ascii_alphanumeric) {
            return Err(RuleError::InvalidSyntax {
                detail: "pattern_without_literal",
                span,
            });
        }
        let prefilter = longest_run(&core);
        Ok(Self {
            start,
            end_anchored,
            core: core.into_boxed_slice(),
            prefilter,
        })
    }

    /// The start anchor.
    pub fn start(&self) -> GlobStart {
        self.start
    }

    /// Whether the pattern must end at the end of the name (`^` or `|`).
    pub fn is_end_anchored(&self) -> bool {
        self.end_anchored
    }

    /// A literal that every matching name contains, if there is one.
    pub fn prefilter(&self) -> Option<&str> {
        self.prefilter.as_deref()
    }

    /// Canonical pattern text, used as the `$badfilter` identity. Re-parsing
    /// it (as a rule) yields an equal glob.
    pub fn canonical(&self) -> String {
        let mut s = String::with_capacity(self.core.len() + 4);
        match self.start {
            GlobStart::Anywhere => s.push('*'),
            GlobStart::Boundary => s.push_str("||"),
            GlobStart::Exact => s.push('|'),
        }
        for &b in self.core.iter() {
            match b {
                STAR => s.push('*'),
                END => s.push('^'),
                _ => s.push(char::from(b)),
            }
        }
        if !self.end_anchored {
            s.push('*');
        }
        s
    }

    /// Matches a canonical (lower-case, no trailing dot) name.
    ///
    /// ASCII upper case in `name` is tolerated, but callers should pass a
    /// [`DomainName`](crate::DomainName) string.
    pub fn matches(&self, name: &str) -> bool {
        let pre_any: &[u8] = &[STAR];
        let post: &[u8] = if self.end_anchored { &[] } else { &[STAR] };
        match self.start {
            GlobStart::Exact => self.run(&[], post, name),
            GlobStart::Anywhere => self.run(pre_any, post, name),
            GlobStart::Boundary => self.run(&[], post, name) || self.run(&[STAR, b'.'], post, name),
        }
    }

    /// Two-pointer glob match of `pre ++ core ++ post` against
    /// `name ++ [END]`.
    fn run(&self, pre: &[u8], post: &[u8], name: &str) -> bool {
        let text = name.as_bytes();
        let n = text.len() + 1; // virtual end-of-name byte
        let m = pre.len() + self.core.len() + post.len();
        let tok = |j: usize| -> u8 {
            if j < pre.len() {
                pre.get(j).copied().unwrap_or(0)
            } else if j < pre.len() + self.core.len() {
                self.core.get(j - pre.len()).copied().unwrap_or(0)
            } else {
                post.get(j - pre.len() - self.core.len())
                    .copied()
                    .unwrap_or(0)
            }
        };
        let ch = |i: usize| -> u8 {
            match text.get(i) {
                Some(b) => b.to_ascii_lowercase(),
                None => END,
            }
        };
        let (mut i, mut j) = (0usize, 0usize);
        let mut star: Option<usize> = None;
        let mut mark = 0usize;
        while i < n {
            if j < m && tok(j) == STAR {
                star = Some(j);
                mark = i;
                j += 1;
            } else if j < m && tok(j) == ch(i) {
                i += 1;
                j += 1;
            } else if let Some(sj) = star {
                mark += 1;
                i = mark;
                j = sj + 1;
            } else {
                return false;
            }
        }
        while j < m && tok(j) == STAR {
            j += 1;
        }
        j == m
    }
}

fn flush_literal(
    lit: &mut String,
    core: &mut Vec<u8>,
    span: &Range<usize>,
) -> Result<(), RuleError> {
    if lit.is_empty() {
        return Ok(());
    }
    let ascii;
    let text: &str = if lit.is_ascii() {
        lit
    } else {
        ascii = idna::domain_to_ascii(lit)
            .map_err(|_| RuleError::InvalidIdna { span: span.clone() })?;
        &ascii
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
            core.push(c.to_ascii_lowercase() as u8);
        } else if c.is_ascii() {
            return Err(RuleError::InvalidDomain {
                source: NameError::InvalidChar { ch: c },
                span: span.clone(),
            });
        } else {
            return Err(RuleError::InvalidDomain {
                source: NameError::NonAscii { ch: c },
                span: span.clone(),
            });
        }
    }
    lit.clear();
    Ok(())
}

/// Longest contiguous literal run (between stars and end markers).
fn longest_run(core: &[u8]) -> Option<Box<str>> {
    core.split(|b| *b == STAR || *b == END)
        .max_by_key(|r| r.len())
        .filter(|r| !r.is_empty())
        .and_then(|r| std::str::from_utf8(r).ok())
        .map(Box::from)
}

/// Why a regex was rejected.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum RegexFailure {
    /// Syntax error; the message is truncated to [`REGEX_MESSAGE_MAX`].
    Invalid(String),
    /// Exceeds [`REGEX_SIZE_LIMIT`].
    TooLarge,
}

/// A compiled `/regex/` rule. Cheap to clone through `Arc` in [`Rule`](crate::Rule).
#[derive(Clone, Debug)]
pub struct RegexRule {
    regex: Regex,
    prefilter: Option<Box<str>>,
}

impl PartialEq for RegexRule {
    fn eq(&self, other: &Self) -> bool {
        self.regex.as_str() == other.regex.as_str()
    }
}

impl Eq for RegexRule {}

impl RegexRule {
    /// Compiles `source` case-insensitively within the size limits.
    ///
    /// Hostnames are ASCII, so Unicode character classes are disabled
    /// (`unicode(false)`). That keeps patterns such as `\w{2}` small enough to
    /// compile. Matching uses [`regex::bytes::Regex`] so that `.` / `\d` / `\w`
    /// with Unicode disabled are still accepted (they may match invalid UTF-8
    /// as bytes; our names are always valid ASCII). A pattern that only works
    /// with Unicode classes is rejected as [`RegexFailure::Invalid`].
    pub(crate) fn compile(source: &str) -> Result<Self, RegexFailure> {
        let regex = RegexBuilder::new(source)
            .case_insensitive(true)
            .unicode(false)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
            .build()
            .map_err(|e| match e {
                regex::Error::CompiledTooBig(_) => RegexFailure::TooLarge,
                other => RegexFailure::Invalid(truncate(&other.to_string(), REGEX_MESSAGE_MAX)),
            })?;
        let prefilter = regex_prefilter(source).map(Box::from);
        Ok(Self { regex, prefilter })
    }

    /// Heuristic estimate of the memory the compiled regex holds (the `regex`
    /// crate does not report it): `512 + 32 * source length`, capped at
    /// [`REGEX_SIZE_LIMIT`]. Used for the per-index regex budget.
    pub fn estimated_bytes(&self) -> usize {
        self.regex
            .as_str()
            .len()
            .saturating_mul(32)
            .saturating_add(512)
            .min(REGEX_SIZE_LIMIT)
    }

    /// The regex source without the surrounding slashes.
    pub fn as_str(&self) -> &str {
        self.regex.as_str()
    }

    /// A lower-case literal that every matching name contains, if known.
    pub fn prefilter(&self) -> Option<&str> {
        self.prefilter.as_deref()
    }

    /// Matches a canonical (lower-case, no trailing dot) name.
    pub fn is_match(&self, name: &str) -> bool {
        self.regex.is_match(name.as_bytes())
    }
}

fn truncate(s: &str, max: usize) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut n = flat.len().min(max);
    while !flat.is_char_boundary(n) {
        n -= 1;
    }
    let mut out = flat.get(..n).unwrap_or("").to_string();
    if n < flat.len() {
        let _ = write!(out, "...");
    }
    out
}

/// Conservative required-literal extraction from regex source text.
///
/// Returns the longest lower-case ASCII run that every match must contain, or
/// `None` when unsure. Bails out (returns `None`) on alternation anywhere,
/// non-ASCII text and the verbose flag `x`. Group contents and character
/// classes are ignored; a quantifier removes the character it applies to.
fn regex_prefilter(src: &str) -> Option<String> {
    if !src.is_ascii() || src.contains('|') {
        return None;
    }
    let b = src.as_bytes();
    let mut runs: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut depth = 0usize;
    let mut i = 0usize;
    let flush = |cur: &mut String, runs: &mut Vec<String>| {
        if !cur.is_empty() {
            runs.push(std::mem::take(cur));
        }
    };
    while i < b.len() {
        let c = *b.get(i)?;
        match c {
            b'\\' => {
                let next = *b.get(i + 1)?;
                i += 2;
                if depth > 0 {
                    continue;
                }
                if next.is_ascii_alphanumeric() || matches!(next, b'<' | b'>') {
                    // Class or special escape (`\d`, `\b`, `\x41`, `\p{..}`):
                    // not a plain literal.
                    flush(&mut cur, &mut runs);
                } else {
                    cur.push(char::from(next));
                }
                continue;
            }
            b'[' => {
                // Skip the class, honouring escapes and a leading `]`/`^]`.
                flush(&mut cur, &mut runs);
                i += 1;
                if b.get(i) == Some(&b'^') {
                    i += 1;
                }
                if b.get(i) == Some(&b']') {
                    i += 1;
                }
                let mut nested = 0usize;
                loop {
                    match *b.get(i)? {
                        b'\\' => i += 1,
                        b'[' => nested += 1,
                        b']' => {
                            if nested == 0 {
                                break;
                            }
                            nested -= 1;
                        }
                        _ => {}
                    }
                    i += 1;
                }
                i += 1;
                continue;
            }
            b'(' => {
                if b.get(i + 1) == Some(&b'?') {
                    let end = src.get(i..)?.find([')', ':']).map(|k| i + k)?;
                    if src.get(i..end)?.contains('x') {
                        return None;
                    }
                }
                flush(&mut cur, &mut runs);
                depth += 1;
            }
            b')' => {
                flush(&mut cur, &mut runs);
                depth = depth.saturating_sub(1);
            }
            b'{' => {
                // Counted repetition or `\p{..}` body: skip it, drop the
                // repeated character.
                if depth == 0 {
                    cur.pop();
                    flush(&mut cur, &mut runs);
                }
                while *b.get(i)? != b'}' {
                    i += 1;
                }
            }
            b'*' | b'?' => {
                if depth == 0 {
                    cur.pop();
                    flush(&mut cur, &mut runs);
                }
            }
            b'+' | b'.' | b'^' | b'$' | b']' | b'}' => {
                if depth == 0 {
                    flush(&mut cur, &mut runs);
                }
            }
            _ => {
                if depth == 0 {
                    cur.push(char::from(c.to_ascii_lowercase()));
                }
            }
        }
        i += 1;
    }
    flush(&mut cur, &mut runs);
    runs.into_iter().max_by_key(String::len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_prefilter_cases() {
        let cases: &[(&str, Option<&str>)] = &[
            ("^ads?[0-9]*\\.example$", Some(".example")),
            ("ads|track", None),
            ("(ads)?tracker", Some("tracker")),
            ("^foo+bar$", Some("bar")),
            ("a{3}bcd", Some("bcd")),
            ("(?x)abc", None),
            ("\\d+", None),
            ("\\p{Greek}abc", Some("abc")),
            ("ünï", None),
            ("[a-z]+", None),
        ];
        for (src, want) in cases {
            assert_eq!(regex_prefilter(src).as_deref(), *want, "{src}");
        }
    }
}
