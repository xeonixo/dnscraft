//! Immutable match index and AdGuard-style verdict evaluation (Task M1).
//!
//! ## Data layout
//!
//! Plain domain rules (`||x^`, `|x^`, hosts lines; the vast majority of a
//! list) are stored as **parallel arrays** sorted by their *reversed* name
//! (`www.example.com` is stored as `com.example.www`, see
//! [`DomainName::reversed`]), so every suffix of a query name is a prefix of
//! its reversed form and can be found by binary search:
//!
//! | Array | Per entry | Content |
//! |---|---|---|
//! | `arena` | name length | all reversed names, back to back, no separators |
//! | `offsets` | 4 B | start of the name in `arena` (plus one end sentinel) |
//! | `flags` | 1 B | allow, exact, important, has-modifiers |
//! | `sources` | 2 B | [`SourceId`] of the first list that contributed the rule |
//! | `text_offs` | 4 B | byte offset of the trimmed line in the source body |
//!
//! That is 11 bytes of overhead per entry beyond the name bytes. The line
//! number and the trimmed length are **not** stored: [`RuleTextSource`]
//! derives the line by counting newlines before the offset and reads text up
//! to the next newline (then trims trailing whitespace). The rare rules with
//! `$dnstype`, `$denyallow` or `$dnsrewrite` keep their [`Modifiers`] in a
//! small side table keyed by entry index.
//!
//! Rule text and list bodies are never held by the index: [`Reason`]s are
//! built lazily, only for the winning rule, by asking a [`RuleTextSource`]
//! for `(source, offset)` (store-backed snapshots use one small positional
//! read from the list file they were built from; custom rules keep their
//! small text in memory). [`MemoryTexts`] is the in-memory
//! implementation. Wildcard and regex rules live in a separate small vector
//! and are tested with [`Rule::pattern_matches`] (literal prefilter first).
//!
//! ## Build
//!
//! [`IndexBuilder::add_rule`] appends the reversed name to the arena and one
//! 16-byte pending record (no per-rule heap allocation; feed rules via
//! [`crate::parse_list_each`] so list bodies never become a `Vec<Rule>`).
//! [`IndexBuilder::build`] sorts a `u32` index into the pending records
//! (O(n log n)), applies `$badfilter`, de-duplicates and compacts into the
//! final arrays. Output depends only on the order of `add_source`/`add_rule`
//! calls.
//!
//! ## Semantics
//!
//! * Candidates: every domain entry whose name is a suffix of the query name
//!   (`Subdomains`) or equals it (`Exact`), plus every matching pattern rule.
//! * A candidate is dropped when its `$dnstype` excludes the query type, or
//!   when the query name equals or is below a `$denyallow` domain.
//! * Priority, highest first: `$important` allow, `$important` block,
//!   allow, block. A block rule with `$dnsrewrite` ranks as a block rule
//!   (so a plain `@@||x^` allow beats it, as in AdGuard) and yields
//!   [`Verdict::Rewrite`] when it wins.
//! * `@@||x^$dnsrewrite` (the *disable* form) cancels **all** rewrite
//!   rules that match the name and query type. It is not an allow rule: it
//!   never produces a verdict and does not unblock plain blocks (our reading
//!   of AdGuard; confidence medium, the AdGuard docs are terse on this).
//! * Ties between equal-priority candidates are broken deterministically:
//!   the longest matching name wins (`||a.example.com^` beats
//!   `||example.com^`; pattern and regex rules count as length 0), then the
//!   lowest [`SourceId`] (source order), then the lowest text offset in the
//!   source body (earlier lines win), then the position in the index. The
//!   [`Reason`] points at that rule.
//! * Only one rewrite is returned (the winner); multi-record answers are not
//!   assembled from several rules.
//! * `$badfilter` rules are applied at build time. They remove every rule
//!   with the same [`Rule::badfilter_key`] from the sources of this index
//!   they may affect and are not matching rules themselves. A `$badfilter`
//!   (and a `@@…$dnsrewrite` disable) from a list or service never affects a
//!   [`SourceKind::Custom`] rule; a custom one affects every source.
//! * Regex and glob rules are capped per index ([`MAX_REGEX_RULES`],
//!   [`MAX_GLOB_RULES`], [`REGEX_BUDGET_BYTES`]); excess rules are skipped and
//!   counted ([`Index::pattern_budget_skipped`]).
//! * Duplicates (same reversed name, kind, action, `$important` and
//!   modifiers) from different sources collapse into one entry that remembers
//!   the first source; the dropped ones are counted per source.

use std::collections::HashSet;
use std::mem::size_of;
use std::net::IpAddr;
use std::sync::Arc;

use crate::modifiers::{DnsRewrite, Modifiers};
use crate::name::DomainName;
use crate::rule::{BadfilterKey, MatchKind, Rule, RuleAction};
use crate::types::{ListId, Reason, Rewrite, RuleSource, SetId, Verdict};

/// Maximum number of regex rules in one index; further ones are skipped.
pub const MAX_REGEX_RULES: usize = 5_000;
/// Maximum number of glob (wildcard) rules in one index.
pub const MAX_GLOB_RULES: usize = 20_000;
/// Budget for the summed estimated compiled size of all regex rules in one
/// index (see [`crate::RegexRule::estimated_bytes`]).
pub const REGEX_BUDGET_BYTES: usize = 32 * 1024 * 1024;

const F_ALLOW: u8 = 1;
const F_EXACT: u8 = 2;
const F_IMPORTANT: u8 = 4;
const F_MODS: u8 = 8;

/// Per-entry bytes beyond the name: offset 4 + flags 1 + source 2 + text
/// offset 4.
pub const ENTRY_OVERHEAD_BYTES: usize = 11;

/// Sentinel [`Index::text_offs`] value: the rule has no source text (for
/// example a built-in service rule). Line 0 and a synthesised text are used.
const NO_TEXT: u32 = u32::MAX;

/// Errors from [`IndexBuilder`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IndexError {
    /// The [`SourceId`] was not created by this builder.
    #[error("unknown rule source")]
    UnknownSource,
    /// The name arena would exceed 4 GiB.
    #[error("index too large")]
    TooLarge,
    /// More than 65 535 sources were registered (source ids are `u16`).
    #[error("too many rule sources")]
    TooManySources,
}

impl IndexError {
    /// Stable error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownSource => "filter_index.unknown_source",
            Self::TooLarge => "filter_index.too_large",
            Self::TooManySources => "filter_index.too_many_sources",
        }
    }
}

/// Position of a source in an [`IndexSources`]; lower ids win ties.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct SourceId(u32);

impl SourceId {
    /// The raw index.
    pub fn get(self) -> u32 {
        self.0
    }
}

/// Where the rules of a source come from, without the line number.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum SourceKind {
    /// A filter list.
    List(ListId),
    /// The custom rules of a set.
    Custom(SetId),
    /// A built-in service.
    Service(Arc<str>),
}

impl SourceKind {
    fn rule_source(&self, line: u32) -> RuleSource {
        match self {
            Self::List(list) => RuleSource::List {
                list: list.clone(),
                line,
            },
            Self::Custom(set) => RuleSource::Custom {
                set: set.clone(),
                line,
            },
            Self::Service(id) => RuleSource::Service { id: id.clone() },
        }
    }
}

/// Resolves the text of a rule line on demand (only when a match happens).
///
/// The index stores only `(source, offset)`. Implementations read from
/// `offset` up to the next newline (trimming trailing whitespace) and derive
/// the 1-based line number by counting `\n` bytes before `offset`. Suitable
/// for an on-disk cache (pread/seek at `offset`) as well as in-memory bodies.
pub trait RuleTextSource: Send + Sync + std::fmt::Debug {
    /// `(1-based line, trimmed rule text)`, or `None` if it cannot be read.
    fn rule_at(&self, source: u32, offset: u32) -> Option<(u32, Arc<str>)>;
}

/// In-memory [`RuleTextSource`]: one body per source id.
#[derive(Clone, Default, Debug)]
pub struct MemoryTexts {
    bodies: Vec<Arc<str>>,
}

impl MemoryTexts {
    /// Bodies indexed by [`SourceId`].
    pub fn new(bodies: Vec<Arc<str>>) -> Self {
        Self { bodies }
    }
}

impl RuleTextSource for MemoryTexts {
    fn rule_at(&self, source: u32, offset: u32) -> Option<(u32, Arc<str>)> {
        let body = self.bodies.get(source as usize)?;
        rule_at_body(body, offset).map(|(line, text)| (line, Arc::from(text)))
    }
}

/// Reads the trimmed rule line at `offset` in `body` and its 1-based line no.
pub(crate) fn rule_at_body(body: &str, offset: u32) -> Option<(u32, &str)> {
    let s = offset as usize;
    if s > body.len() {
        return None;
    }
    let line = body
        .get(..s)?
        .bytes()
        .filter(|&b| b == b'\n')
        .count()
        .saturating_add(1) as u32;
    let rest = body.get(s..)?;
    let end = rest.find('\n').unwrap_or(rest.len());
    let text = rest.get(..end)?.trim_end_matches(crate::parser::is_ws);
    Some((line, text))
}

const F_REMOVED: u8 = 0x80;

#[derive(Clone, Copy, Debug)]
struct Pending {
    off: u32,
    len: u8,
    flags: u8,
    source: u16,
    text_off: u32,
    mod_idx: u32,
}

const NO_MOD: u32 = u32::MAX;

#[derive(Debug)]
struct PatternEntry {
    rule: Rule,
    source: u32,
}

/// Per-index caps on regex and glob rules (hostile lists must not exhaust
/// memory or make the linear pattern scan unbounded).
#[derive(Default, Debug)]
struct PatternBudget {
    regex: usize,
    glob: usize,
    regex_bytes: usize,
    /// Rules refused by the caps, per source.
    skipped: Vec<u32>,
}

impl PatternBudget {
    /// True if `rule` fits the caps (and is then charged); otherwise counts
    /// it as skipped for `source`.
    fn admit(&mut self, rule: &Rule, source: u32) -> bool {
        let fits = if let Some(rx) = rule.regex() {
            let cost = rx.estimated_bytes();
            let ok = self.regex < MAX_REGEX_RULES
                && self.regex_bytes.saturating_add(cost) <= REGEX_BUDGET_BYTES;
            if ok {
                self.regex += 1;
                self.regex_bytes += cost;
            }
            ok
        } else {
            let ok = self.glob < MAX_GLOB_RULES;
            if ok {
                self.glob += 1;
            }
            ok
        };
        if !fits {
            let i = source as usize;
            if self.skipped.len() <= i {
                self.skipped.resize(i + 1, 0);
            }
            if let Some(c) = self.skipped.get_mut(i) {
                *c = c.saturating_add(1);
            }
        }
        fits
    }
}

#[derive(Clone, Copy, Debug)]
struct PendingIp {
    /// IPv4 as `u32` or IPv6 as the low... we store key separately.
    key_v4: Option<u32>,
    key_v6: Option<u128>,
    flags: u8,
    source: u16,
    text_off: u32,
}

/// Collects rules from one or more sources and builds an [`Index`].
#[derive(Default, Debug)]
pub struct IndexBuilder {
    kinds: Vec<SourceKind>,
    bodies: Vec<Arc<str>>,
    arena: Vec<u8>,
    pending: Vec<Pending>,
    pending_ip: Vec<PendingIp>,
    mods: Vec<Modifiers>,
    patterns: Vec<PatternEntry>,
    /// `$badfilter` rules with the source that contributed them.
    badfilters: Vec<(Rule, u16)>,
    pattern_budget: PatternBudget,
}

impl IndexBuilder {
    /// An empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a source. Sources added first win ties.
    ///
    /// Fails with [`IndexError::TooManySources`] after 65 535 sources (ids are
    /// stored as `u16` in the index).
    pub fn add_source(&mut self, kind: SourceKind) -> Result<SourceId, IndexError> {
        let id = u16::try_from(self.kinds.len()).map_err(|_| IndexError::TooManySources)?;
        self.kinds.push(kind);
        self.bodies.push(Arc::from(""));
        Ok(SourceId(u32::from(id)))
    }

    /// Registers a source together with its body, for
    /// [`IndexBuilder::build_in_memory`].
    pub fn add_source_with_body(
        &mut self,
        kind: SourceKind,
        body: Arc<str>,
    ) -> Result<SourceId, IndexError> {
        let id = self.add_source(kind)?;
        if let Some(b) = self.bodies.get_mut(id.0 as usize) {
            *b = body;
        }
        Ok(id)
    }

    /// Regex and glob rules of `source` refused by the per-index caps
    /// ([`MAX_REGEX_RULES`], [`MAX_GLOB_RULES`], [`REGEX_BUDGET_BYTES`]).
    /// Feed this into the skip counts as `pattern_budget`.
    pub fn pattern_budget_skipped(&self, source: SourceId) -> usize {
        self.pattern_budget
            .skipped
            .get(source.0 as usize)
            .map_or(0, |&c| c as usize)
    }

    /// Adds many rules of one source.
    pub fn add_rules<I: IntoIterator<Item = Rule>>(
        &mut self,
        source: SourceId,
        rules: I,
    ) -> Result<(), IndexError> {
        for r in rules {
            self.add_rule(r, source)?;
        }
        Ok(())
    }

    /// Adds one rule of `source`.
    pub fn add_rule(&mut self, rule: Rule, source: SourceId) -> Result<(), IndexError> {
        if source.0 as usize >= self.kinds.len() {
            return Err(IndexError::UnknownSource);
        }
        if rule.modifiers().badfilter {
            let src = u16::try_from(source.0).map_err(|_| IndexError::TooManySources)?;
            self.badfilters.push((rule, src));
            return Ok(());
        }
        match rule.kind() {
            MatchKind::Subdomains | MatchKind::Exact => self.add_domain(&rule, source),
            MatchKind::Ip => self.add_ip(&rule, source),
            MatchKind::Pattern | MatchKind::Regex => {
                if (rule.glob().is_some() || rule.regex().is_some())
                    && self.pattern_budget.admit(&rule, source.0)
                {
                    self.patterns.push(PatternEntry {
                        rule,
                        source: source.0,
                    });
                }
                Ok(())
            }
        }
    }

    fn add_ip(&mut self, rule: &Rule, source: SourceId) -> Result<(), IndexError> {
        let Some(ip) = rule.ip() else {
            return Ok(());
        };
        let source = u16::try_from(source.0).map_err(|_| IndexError::TooManySources)?;
        let text_off = if rule.line() == 0 {
            NO_TEXT
        } else {
            u32::try_from(rule.span().start).unwrap_or(0)
        };
        let mut flags = 0u8;
        if rule.action() == RuleAction::Allow {
            flags |= F_ALLOW;
        }
        if rule.modifiers().important {
            flags |= F_IMPORTANT;
        }
        let (key_v4, key_v6) = match ip {
            IpAddr::V4(v) => (Some(u32::from(v)), None),
            IpAddr::V6(v) => (None, Some(u128::from(v))),
        };
        self.pending_ip.push(PendingIp {
            key_v4,
            key_v6,
            flags,
            source,
            text_off,
        });
        Ok(())
    }

    fn add_domain(&mut self, rule: &Rule, source: SourceId) -> Result<(), IndexError> {
        let Some(d) = rule.domain() else {
            return Ok(());
        };
        let name = d.as_str();
        let off = u32::try_from(self.arena.len()).map_err(|_| IndexError::TooLarge)?;
        if self.arena.len().saturating_add(name.len()) >= u32::MAX as usize {
            return Err(IndexError::TooLarge);
        }
        let len = u8::try_from(name.len()).map_err(|_| IndexError::TooLarge)?;
        for (i, label) in name.rsplit('.').enumerate() {
            if i > 0 {
                self.arena.push(b'.');
            }
            self.arena.extend_from_slice(label.as_bytes());
        }
        let mut flags = domain_flags(rule);
        let mut mod_idx = NO_MOD;
        if has_side_mods(rule.modifiers()) {
            flags |= F_MODS;
            mod_idx = u32::try_from(self.mods.len()).map_err(|_| IndexError::TooLarge)?;
            self.mods.push(rule.modifiers().clone());
        }
        let text_off = if rule.line() == 0 {
            NO_TEXT
        } else {
            u32::try_from(rule.span().start).unwrap_or(0)
        };
        let source = u16::try_from(source.0).map_err(|_| IndexError::TooManySources)?;
        self.pending.push(Pending {
            off,
            len,
            flags,
            source,
            text_off,
            mod_idx,
        });
        Ok(())
    }

    /// Builds the index with the bodies given to
    /// [`add_source_with_body`](Self::add_source_with_body) as text source.
    pub fn build_in_memory(self) -> Index {
        let texts = Arc::new(MemoryTexts::new(self.bodies.clone()));
        self.build(texts)
    }

    /// Sorts, applies `$badfilter`, de-duplicates and freezes the index.
    pub fn build(self, texts: Arc<dyn RuleTextSource>) -> Index {
        let Self {
            kinds,
            bodies: _,
            mut arena,
            mut pending,
            mut pending_ip,
            mods,
            patterns,
            badfilters,
            pattern_budget,
        } = self;
        let nsrc = kinds.len();
        // Sort pending in place (no parallel u32 index array) to cut the peak.
        pending.sort_unstable_by(|a, b| {
            pname(&arena, a)
                .cmp(pname(&arena, b))
                .then(a.flags.cmp(&b.flags))
                .then(a.source.cmp(&b.source))
                .then(a.text_off.cmp(&b.text_off))
        });
        pending_ip.sort_unstable_by(|a, b| {
            a.key_v4
                .cmp(&b.key_v4)
                .then(a.key_v6.cmp(&b.key_v6))
                .then(a.flags.cmp(&b.flags))
                .then(a.source.cmp(&b.source))
                .then(a.text_off.cmp(&b.text_off))
        });

        // `$badfilter` scope: a rule from a list or service never removes a
        // custom rule; a custom `$badfilter` may remove any rule.
        let is_custom: Vec<bool> = kinds
            .iter()
            .map(|k| matches!(k, SourceKind::Custom(_)))
            .collect();
        let custom_src = |src: u16| is_custom.get(usize::from(src)).copied().unwrap_or(false);
        let mut badfiltered = 0usize;
        let mut keys_from_custom: HashSet<BadfilterKey> = HashSet::new();
        let mut keys_from_other: HashSet<BadfilterKey> = HashSet::new();
        for (bf, bf_src) in &badfilters {
            let bf_custom = custom_src(*bf_src);
            if let Some(d) = bf.domain() {
                badfiltered += remove_matching(&arena, &mut pending, &mods, bf, d, |target| {
                    bf_custom || !custom_src(target)
                });
            } else if let Some(ip) = bf.ip() {
                badfiltered += remove_matching_ip(&mut pending_ip, bf, ip, |target| {
                    bf_custom || !custom_src(target)
                });
            } else if bf_custom {
                keys_from_custom.insert(bf.badfilter_key());
            } else {
                keys_from_other.insert(bf.badfilter_key());
            }
        }
        let patterns: Vec<PatternEntry> =
            if keys_from_custom.is_empty() && keys_from_other.is_empty() {
                patterns
            } else {
                patterns
                    .into_iter()
                    .filter(|p| {
                        let key = p.rule.badfilter_key();
                        let target_custom = custom_src(u16::try_from(p.source).unwrap_or(u16::MAX));
                        let hit = keys_from_custom.contains(&key)
                            || (!target_custom && keys_from_other.contains(&key));
                        badfiltered += usize::from(hit);
                        !hit
                    })
                    .collect()
            };

        // Mark duplicates while pending is name-sorted. Entries removed by
        // `$badfilter` stay inside their name group (they are skipped, they
        // do not end it), so later duplicates in the group are still found.
        let mut dup_by_source = vec![0u32; nsrc];
        let mut duplicates = 0usize;
        {
            let mut start = 0usize;
            while start < pending.len() {
                let name = pname(&arena, &pending[start]);
                let mut end = start + 1;
                while end < pending.len() && pname(&arena, &pending[end]) == name {
                    end += 1;
                }
                for i in start..end {
                    if pending[i].flags & F_REMOVED != 0 {
                        continue;
                    }
                    if is_dup_of_group(&pending, start, i, &mods) {
                        let src = pending[i].source;
                        if let Some(c) = dup_by_source.get_mut(usize::from(src)) {
                            *c += 1;
                        }
                        duplicates += 1;
                        pending[i].flags |= F_REMOVED;
                    }
                }
                start = end;
            }
        }

        pending.retain(|p| p.flags & F_REMOVED == 0);
        pending.shrink_to_fit();

        // Compact name bytes in ascending `off` order (write ≤ read), then
        // re-sort by name for the final layout. No parallel index array.
        pending.sort_unstable_by_key(|p| p.off);
        {
            let mut write = 0usize;
            for p in &mut pending {
                let len = usize::from(p.len);
                let old = p.off as usize;
                if old != write {
                    arena.copy_within(old..old + len, write);
                }
                p.off = write as u32;
                write += len;
            }
            arena.truncate(write);
            arena.shrink_to_fit();
        }
        pending.sort_unstable_by(|a, b| {
            pname(&arena, a)
                .cmp(pname(&arena, b))
                .then(a.flags.cmp(&b.flags))
                .then(a.source.cmp(&b.source))
                .then(a.text_off.cmp(&b.text_off))
        });

        // Repack names in name-sorted entry order so `offsets[i+1] - offsets[i]`
        // is the length (binary search layout). Source arena is already free of
        // removed-name bytes, so the copy is ~steady-state size.
        let n = pending.len();
        let mut packed = Vec::with_capacity(arena.len());
        let mut offsets = Vec::with_capacity(n + 1);
        for p in &pending {
            offsets.push(u32::try_from(packed.len()).unwrap_or(u32::MAX));
            packed.extend_from_slice(pname(&arena, p));
        }
        offsets.push(u32::try_from(packed.len()).unwrap_or(u32::MAX));
        drop(arena);

        // Dedup IP rules (same address + flags → keep first source).
        {
            let mut i = 0usize;
            while i < pending_ip.len() {
                if pending_ip[i].flags & F_REMOVED != 0 {
                    i += 1;
                    continue;
                }
                let key4 = pending_ip[i].key_v4;
                let key6 = pending_ip[i].key_v6;
                let group_start = i;
                i += 1;
                while i < pending_ip.len()
                    && pending_ip[i].flags & F_REMOVED == 0
                    && pending_ip[i].key_v4 == key4
                    && pending_ip[i].key_v6 == key6
                {
                    let same = (group_start..i).any(|j| {
                        pending_ip[j].flags & F_REMOVED == 0
                            && pending_ip[j].flags == pending_ip[i].flags
                    });
                    if same {
                        let src = pending_ip[i].source;
                        if let Some(c) = dup_by_source.get_mut(usize::from(src)) {
                            *c += 1;
                        }
                        duplicates += 1;
                        pending_ip[i].flags |= F_REMOVED;
                    }
                    i += 1;
                }
            }
        }
        pending_ip.retain(|p| p.flags & F_REMOVED == 0);

        let mut out = Index {
            kinds,
            texts,
            arena: packed,
            offsets,
            flags: Vec::with_capacity(n),
            src: Vec::with_capacity(n),
            text_offs: Vec::with_capacity(n),
            mod_ids: Vec::new(),
            mods: Vec::new(),
            patterns: patterns.into_boxed_slice(),
            v4: Vec::new(),
            v4_flags: Vec::new(),
            v4_src: Vec::new(),
            v4_text_offs: Vec::new(),
            v6: Vec::new(),
            v6_flags: Vec::new(),
            v6_src: Vec::new(),
            v6_text_offs: Vec::new(),
            dup_by_source,
            duplicates,
            badfiltered,
            pattern_budget_skipped: pattern_budget.skipped.iter().map(|&c| c as usize).sum(),
        };
        let mut mods = mods;
        for p in &pending {
            let idx = u32::try_from(out.flags.len()).unwrap_or(u32::MAX);
            out.flags.push(p.flags & !F_REMOVED);
            out.src.push(p.source);
            out.text_offs.push(p.text_off);
            if p.flags & F_MODS != 0 {
                if let Some(m) = mods.get_mut(p.mod_idx as usize) {
                    out.mod_ids.push(idx);
                    out.mods.push(std::mem::take(m));
                }
            }
        }
        for p in &pending_ip {
            if let Some(k) = p.key_v4 {
                out.v4.push(k);
                out.v4_flags.push(p.flags & !F_REMOVED);
                out.v4_src.push(p.source);
                out.v4_text_offs.push(p.text_off);
            } else if let Some(k) = p.key_v6 {
                out.v6.push(k);
                out.v6_flags.push(p.flags & !F_REMOVED);
                out.v6_src.push(p.source);
                out.v6_text_offs.push(p.text_off);
            }
        }
        out.arena.shrink_to_fit();
        out.offsets.shrink_to_fit();
        out.flags.shrink_to_fit();
        out.src.shrink_to_fit();
        out.text_offs.shrink_to_fit();
        out.v4.shrink_to_fit();
        out.v4_flags.shrink_to_fit();
        out.v4_src.shrink_to_fit();
        out.v4_text_offs.shrink_to_fit();
        out.v6.shrink_to_fit();
        out.v6_flags.shrink_to_fit();
        out.v6_src.shrink_to_fit();
        out.v6_text_offs.shrink_to_fit();
        out
    }
}

/// True when `pending[i]` matches an earlier kept entry in `[group_start, i)`.
fn is_dup_of_group(pending: &[Pending], group_start: usize, i: usize, mods: &[Modifiers]) -> bool {
    let p = &pending[i];
    (group_start..i).any(|j| {
        if pending[j].flags & F_REMOVED != 0 || pending[j].flags != p.flags {
            return false;
        }
        if p.flags & F_MODS == 0 {
            return true;
        }
        match (
            mods.get(pending[j].mod_idx as usize),
            mods.get(p.mod_idx as usize),
        ) {
            (Some(a), Some(b)) => same_side_mods(a, b),
            _ => false,
        }
    })
}

fn pname<'a>(arena: &'a [u8], p: &Pending) -> &'a [u8] {
    let s = p.off as usize;
    arena.get(s..s + usize::from(p.len)).unwrap_or(&[])
}

fn domain_flags(rule: &Rule) -> u8 {
    let mut f = 0;
    if rule.action() == RuleAction::Allow {
        f |= F_ALLOW;
    }
    if rule.kind() == MatchKind::Exact {
        f |= F_EXACT;
    }
    if rule.modifiers().important {
        f |= F_IMPORTANT;
    }
    f
}

fn has_side_mods(m: &Modifiers) -> bool {
    m.dnstype.is_some() || m.denyallow.is_some() || m.dnsrewrite.is_some()
}

fn same_side_mods(a: &Modifiers, b: &Modifiers) -> bool {
    a.dnstype == b.dnstype && a.denyallow == b.denyallow && a.dnsrewrite == b.dnsrewrite
}

fn remove_matching_ip(
    pending_ip: &mut [PendingIp],
    bf: &Rule,
    ip: IpAddr,
    may_remove: impl Fn(u16) -> bool,
) -> usize {
    let mut flags = 0u8;
    if bf.action() == RuleAction::Allow {
        flags |= F_ALLOW;
    }
    if bf.modifiers().important {
        flags |= F_IMPORTANT;
    }
    let (want4, want6) = match ip {
        IpAddr::V4(v) => (Some(u32::from(v)), None),
        IpAddr::V6(v) => (None, Some(u128::from(v))),
    };
    let mut n = 0;
    for p in pending_ip.iter_mut() {
        if p.key_v4 != want4 || p.key_v6 != want6 {
            continue;
        }
        if p.flags & !F_REMOVED != flags || !may_remove(p.source) {
            continue;
        }
        p.flags |= F_REMOVED;
        n += 1;
    }
    n
}

/// Marks entries equal to the `$badfilter` rule `bf` as removed.
fn remove_matching(
    arena: &[u8],
    pending: &mut [Pending],
    mods: &[Modifiers],
    bf: &Rule,
    d: &DomainName,
    may_remove: impl Fn(u16) -> bool,
) -> usize {
    let mut flags = domain_flags(bf);
    let side = has_side_mods(bf.modifiers());
    if side {
        flags |= F_MODS;
    }
    let want = d.reversed();
    let want = want.as_bytes();
    let start = pending.partition_point(|p| pname(arena, p) < want);
    let mut n = 0;
    for p in pending.iter_mut().skip(start) {
        if pname(arena, p) != want {
            break;
        }
        if p.flags & !F_REMOVED != flags || !may_remove(p.source) {
            continue;
        }
        if side
            && !mods
                .get(p.mod_idx as usize)
                .is_some_and(|m| same_side_mods(m, bf.modifiers()))
        {
            continue;
        }
        p.flags |= F_REMOVED;
        n += 1;
    }
    n
}

/// Approximate memory use of the domain part of an [`Index`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IndexMemory {
    /// Number of domain entries.
    pub entries: usize,
    /// Bytes of reversed names.
    pub name_bytes: usize,
    /// Bytes of offsets, flags, sources and text offsets.
    pub overhead_bytes: usize,
    /// Bytes of the modifier side table (shallow: `size_of`, no heap).
    pub side_bytes: usize,
}

impl IndexMemory {
    /// Overhead bytes per entry beyond the name bytes.
    pub fn overhead_per_entry(&self) -> f64 {
        if self.entries == 0 {
            0.0
        } else {
            self.overhead_bytes as f64 / self.entries as f64
        }
    }
}

/// An immutable, shareable rule index. Build with [`IndexBuilder`].
#[derive(Debug)]
pub struct Index {
    kinds: Vec<SourceKind>,
    texts: Arc<dyn RuleTextSource>,
    arena: Vec<u8>,
    offsets: Vec<u32>,
    flags: Vec<u8>,
    src: Vec<u16>,
    text_offs: Vec<u32>,
    mod_ids: Vec<u32>,
    mods: Vec<Modifiers>,
    patterns: Box<[PatternEntry]>,
    v4: Vec<u32>,
    v4_flags: Vec<u8>,
    v4_src: Vec<u16>,
    v4_text_offs: Vec<u32>,
    v6: Vec<u128>,
    v6_flags: Vec<u8>,
    v6_src: Vec<u16>,
    v6_text_offs: Vec<u32>,
    dup_by_source: Vec<u32>,
    duplicates: usize,
    badfiltered: usize,
    pattern_budget_skipped: usize,
}

type Key = (u8, u32, u32, u32, u8, u32);

#[derive(Clone, Copy)]
struct Best<'a> {
    key: Key,
    rewrite: Option<&'a Rewrite>,
}

/// Rewrite candidates, kept apart by origin so that a `@@…$dnsrewrite` from a
/// list or service cannot cancel a custom rewrite (a custom one cancels all).
#[derive(Default)]
struct Rewrites<'a> {
    custom: Option<Best<'a>>,
    other: Option<Best<'a>>,
    custom_disabled: bool,
    other_disabled: bool,
}

impl<'a> Rewrites<'a> {
    fn disable(&mut self, from_custom: bool) {
        if from_custom {
            self.custom_disabled = true;
        } else {
            self.other_disabled = true;
        }
    }

    fn offer(&mut self, from_custom: bool, cand: Best<'a>) {
        let slot = if from_custom {
            &mut self.custom
        } else {
            &mut self.other
        };
        if slot.as_ref().is_none_or(|b| cand.key < b.key) {
            *slot = Some(cand);
        }
    }

    /// The best rewrite that no disable rule cancels.
    fn winner(&self) -> Option<Best<'a>> {
        let custom = self.custom.filter(|_| !self.custom_disabled);
        let other = self
            .other
            .filter(|_| !self.custom_disabled && !self.other_disabled);
        match (custom, other) {
            (Some(a), Some(b)) => Some(if a.key <= b.key { a } else { b }),
            (a, b) => a.or(b),
        }
    }
}

impl Index {
    /// Number of domain entries (after dedup and `$badfilter`).
    pub fn len(&self) -> usize {
        self.flags.len()
    }

    /// True when the index has no domain, pattern or IP rules.
    pub fn is_empty(&self) -> bool {
        self.flags.is_empty()
            && self.patterns.is_empty()
            && self.v4.is_empty()
            && self.v6.is_empty()
    }

    /// Number of wildcard and regex rules.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Number of answer-IP rules (IPv4 + IPv6).
    pub fn ip_count(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Entries dropped because an identical rule came from an earlier source.
    pub fn duplicates(&self) -> usize {
        self.duplicates
    }

    /// Duplicates dropped that were contributed by `source` (it adds nothing
    /// unique for them).
    pub fn duplicates_of(&self, source: SourceId) -> usize {
        self.dup_by_source
            .get(source.0 as usize)
            .map_or(0, |&c| c as usize)
    }

    /// Regex and glob rules dropped by the per-index caps.
    pub fn pattern_budget_skipped(&self) -> usize {
        self.pattern_budget_skipped
    }

    /// Rules removed by `$badfilter`.
    pub fn badfiltered(&self) -> usize {
        self.badfiltered
    }

    /// The kind of source `id`.
    pub fn source_kind(&self, id: SourceId) -> Option<&SourceKind> {
        self.kinds.get(id.0 as usize)
    }

    /// Memory of the domain arrays, from `size_of` and lengths.
    pub fn memory(&self) -> IndexMemory {
        let n = self.flags.len();
        IndexMemory {
            entries: n,
            name_bytes: self.arena.len(),
            overhead_bytes: self.offsets.len() * size_of::<u32>()
                + n * (size_of::<u8>() + size_of::<u16>() + size_of::<u32>()),
            side_bytes: self.mod_ids.len() * size_of::<u32>()
                + self.mods.len() * size_of::<Modifiers>(),
        }
    }

    fn name_at(&self, i: usize) -> &[u8] {
        let s = self.offsets.get(i).copied().unwrap_or(0) as usize;
        let e = self.offsets.get(i + 1).copied().unwrap_or(0) as usize;
        self.arena.get(s..e).unwrap_or(&[])
    }

    fn mods_at(&self, i: usize) -> Option<&Modifiers> {
        let pos = self.mod_ids.binary_search(&u32::try_from(i).ok()?).ok()?;
        self.mods.get(pos)
    }

    /// Matches an address from a DNS answer (A/AAAA) against IP rules.
    ///
    /// Priority is the same as for names (`$important` allow > `$important`
    /// block > allow > block). Ties break by lowest source id, then lowest
    /// text offset. There is no longest-match step.
    pub fn match_answer_ip(&self, ip: IpAddr) -> Verdict {
        match ip {
            IpAddr::V4(v) => self.match_ip4(u32::from(v)),
            IpAddr::V6(v) => self.match_ip6(u128::from(v)),
        }
    }

    fn match_ip4(&self, key: u32) -> Verdict {
        let start = self.v4.partition_point(|&k| k < key);
        let mut best: Option<(u8, u32, u32, usize)> = None;
        let mut i = start;
        while i < self.v4.len() && self.v4[i] == key {
            let f = self.v4_flags.get(i).copied().unwrap_or(0);
            let action = if f & F_ALLOW != 0 {
                RuleAction::Allow
            } else {
                RuleAction::Block
            };
            let r = rank(action, f & F_IMPORTANT != 0);
            let src = u32::from(self.v4_src.get(i).copied().unwrap_or(0));
            let off = self.v4_text_offs.get(i).copied().unwrap_or(NO_TEXT);
            let cand = (r, src, off, i);
            if best.as_ref().is_none_or(|b| cand < *b) {
                best = Some(cand);
            }
            i += 1;
        }
        let Some((r, src, off, _)) = best else {
            return Verdict::Pass;
        };
        self.ip_verdict(r, src, off)
    }

    fn match_ip6(&self, key: u128) -> Verdict {
        let start = self.v6.partition_point(|&k| k < key);
        let mut best: Option<(u8, u32, u32, usize)> = None;
        let mut i = start;
        while i < self.v6.len() && self.v6[i] == key {
            let f = self.v6_flags.get(i).copied().unwrap_or(0);
            let action = if f & F_ALLOW != 0 {
                RuleAction::Allow
            } else {
                RuleAction::Block
            };
            let r = rank(action, f & F_IMPORTANT != 0);
            let src = u32::from(self.v6_src.get(i).copied().unwrap_or(0));
            let off = self.v6_text_offs.get(i).copied().unwrap_or(NO_TEXT);
            let cand = (r, src, off, i);
            if best.as_ref().is_none_or(|b| cand < *b) {
                best = Some(cand);
            }
            i += 1;
        }
        let Some((r, src, off, _)) = best else {
            return Verdict::Pass;
        };
        self.ip_verdict(r, src, off)
    }

    fn ip_verdict(&self, rank: u8, source: u32, text_off: u32) -> Verdict {
        let important = rank == 0 || rank == 1;
        let allow = rank == 0 || rank == 2;
        let (line, text) = if text_off == NO_TEXT {
            (0, Arc::from(""))
        } else {
            self.fetch(source, text_off)
                .unwrap_or_else(|| (0, Arc::from("")))
        };
        let rule_source = self
            .kinds
            .get(source as usize)
            .map_or(RuleSource::TemporaryAllow, |k| k.rule_source(line));
        let reason = Reason {
            rule: text,
            source: rule_source,
            important,
        };
        if allow {
            Verdict::Allowed(reason)
        } else {
            Verdict::Blocked(reason)
        }
    }

    /// Matches a query name and returns the verdict.
    pub fn match_name(&self, name: &DomainName, qtype: u16) -> Verdict {
        let text = name.as_str();
        let mut rev = [0u8; 256];
        let mut n = 0;
        for (i, label) in text.rsplit('.').enumerate() {
            if i > 0 {
                if let Some(b) = rev.get_mut(n) {
                    *b = b'.';
                }
                n += 1;
            }
            let Some(dst) = rev.get_mut(n..n + label.len()) else {
                return Verdict::Pass;
            };
            dst.copy_from_slice(label.as_bytes());
            n += label.len();
        }
        let rev = rev.get(..n).unwrap_or(&[]);

        let mut best: Option<Best<'_>> = None;
        let mut rewrites = Rewrites::default();

        let mut hi = self.flags.len();
        let mut end = n;
        loop {
            let p = rev.get(..end).unwrap_or(&[]);
            let lo = self.lower_bound(p, hi);
            let mut i = lo;
            while i < self.flags.len() && self.name_at(i) == p {
                self.consider_domain(i, end == n, end, text, qtype, &mut best, &mut rewrites);
                i += 1;
            }
            hi = lo;
            match p.iter().rposition(|&b| b == b'.') {
                Some(pos) => end = pos,
                None => break,
            }
        }

        for (idx, pe) in self.patterns.iter().enumerate() {
            if !pe.rule.pattern_matches(text) {
                continue;
            }
            let m = pe.rule.modifiers();
            let action = pe.rule.action();
            let key = (
                rank(action, m.important),
                u32::MAX,
                pe.source,
                u32::try_from(pe.rule.span().start).unwrap_or(0),
                1,
                u32::try_from(idx).unwrap_or(u32::MAX),
            );
            self.offer(m, action, text, qtype, key, &mut best, &mut rewrites);
        }

        let winner = match (best, rewrites.winner()) {
            (Some(a), Some(b)) => Some(if a.key <= b.key { a } else { b }),
            (a, b) => a.or(b),
        };
        let Some(w) = winner else {
            return Verdict::Pass;
        };
        let reason = self.reason(w.key);
        match (w.key.0, w.rewrite) {
            (_, Some(rw)) => Verdict::Rewrite(rw.clone(), reason),
            (0 | 2, None) => Verdict::Allowed(reason),
            _ => Verdict::Blocked(reason),
        }
    }

    /// First index in `0..hi` whose name is not smaller than `p`.
    fn lower_bound(&self, p: &[u8], hi: usize) -> usize {
        let (mut lo, mut hi) = (0usize, hi);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.name_at(mid) < p {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    #[allow(clippy::too_many_arguments)]
    fn consider_domain<'a>(
        &'a self,
        i: usize,
        full: bool,
        matched_len: usize,
        text: &str,
        qtype: u16,
        best: &mut Option<Best<'a>>,
        rewrites: &mut Rewrites<'a>,
    ) {
        let f = self.flags.get(i).copied().unwrap_or(0);
        if f & F_EXACT != 0 && !full {
            return;
        }
        let action = if f & F_ALLOW != 0 {
            RuleAction::Allow
        } else {
            RuleAction::Block
        };
        let key = (
            rank(action, f & F_IMPORTANT != 0),
            u32::MAX - u32::try_from(matched_len).unwrap_or(0),
            u32::from(self.src.get(i).copied().unwrap_or(0)),
            self.text_offs.get(i).copied().unwrap_or(NO_TEXT),
            0,
            u32::try_from(i).unwrap_or(u32::MAX),
        );
        let m = if f & F_MODS != 0 {
            self.mods_at(i)
        } else {
            None
        };
        self.offer(
            m.unwrap_or(&Modifiers::NONE),
            action,
            text,
            qtype,
            key,
            best,
            rewrites,
        );
    }

    /// Applies the modifier filters to a matching candidate and records it.
    #[allow(clippy::too_many_arguments)]
    fn offer<'a>(
        &'a self,
        m: &'a Modifiers,
        action: RuleAction,
        text: &str,
        qtype: u16,
        key: Key,
        best: &mut Option<Best<'a>>,
        rewrites: &mut Rewrites<'a>,
    ) {
        if m.dnstype.as_ref().is_some_and(|t| !t.matches(qtype)) {
            return;
        }
        if let Some(deny) = &m.denyallow {
            if denied(text, deny) {
                return;
            }
        }
        let custom = self.is_custom_source(key.2);
        match &m.dnsrewrite {
            Some(DnsRewrite::Disable) => rewrites.disable(custom),
            Some(DnsRewrite::Set(rw)) => rewrites.offer(
                custom,
                Best {
                    key,
                    rewrite: Some(rw),
                },
            ),
            _ => {
                let _ = action;
                if best.as_ref().is_none_or(|b| key < b.key) {
                    *best = Some(Best { key, rewrite: None });
                }
            }
        }
    }

    fn is_custom_source(&self, source: u32) -> bool {
        matches!(self.kinds.get(source as usize), Some(SourceKind::Custom(_)))
    }

    fn reason(&self, key: Key) -> Reason {
        let (rank, _, source, text_off, tag, idx) = key;
        let idx = idx as usize;
        let important = rank == 0 || rank == 1;
        let allow = rank == 0 || rank == 2;
        let (line, text): (u32, Arc<str>) = if tag == 1 {
            self.patterns.get(idx).map_or_else(
                || (0, Arc::from("")),
                |pe| {
                    let off = u32::try_from(pe.rule.span().start).unwrap_or(0);
                    match self.fetch(source, off) {
                        Some((line, text)) => (line, text),
                        None => (pe.rule.line(), Arc::from(pattern_text(&pe.rule))),
                    }
                },
            )
        } else {
            let f = self.flags.get(idx).copied().unwrap_or(0);
            let synth = || {
                Arc::from(synth_text(
                    allow,
                    f & F_EXACT != 0,
                    self.name_at(idx),
                    important,
                ))
            };
            if text_off == NO_TEXT {
                (0, synth())
            } else {
                self.fetch(source, text_off).unwrap_or_else(|| (0, synth()))
            }
        };
        let rule_source = self
            .kinds
            .get(source as usize)
            .map_or(RuleSource::TemporaryAllow, |k| k.rule_source(line));
        Reason {
            rule: text,
            source: rule_source,
            important,
        }
    }

    fn fetch(&self, source: u32, off: u32) -> Option<(u32, Arc<str>)> {
        if off == NO_TEXT {
            return None;
        }
        self.texts.rule_at(source, off)
    }
}

/// Priority rank: lower wins.
fn rank(action: RuleAction, important: bool) -> u8 {
    match (action, important) {
        (RuleAction::Allow, true) => 0,
        (_, true) => 1,
        (RuleAction::Allow, false) => 2,
        _ => 3,
    }
}

/// True when `text` or one of its parent suffixes is in the sorted `deny` list.
fn denied(text: &str, deny: &[DomainName]) -> bool {
    let mut cur = Some(text);
    while let Some(s) = cur {
        if deny.binary_search_by(|d| d.as_str().cmp(s)).is_ok() {
            return true;
        }
        cur = s.split_once('.').map(|(_, rest)| rest);
    }
    false
}

fn pattern_text(rule: &Rule) -> String {
    let body = rule
        .glob()
        .map(|g| g.canonical())
        .or_else(|| rule.regex().map(|r| format!("/{}/", r.as_str())))
        .unwrap_or_default();
    format!(
        "{}{}{}",
        if rule.action() == RuleAction::Allow {
            "@@"
        } else {
            ""
        },
        body,
        if rule.modifiers().important {
            "$important"
        } else {
            ""
        }
    )
}

/// Rule text for rules that have no source line (reconstructed, modifiers
/// other than `$important` are not shown).
fn synth_text(allow: bool, exact: bool, reversed: &[u8], important: bool) -> String {
    let rev = String::from_utf8_lossy(reversed);
    let name: Vec<&str> = rev.rsplit('.').collect();
    format!(
        "{}{}{}^{}",
        if allow { "@@" } else { "" },
        if exact { "|" } else { "||" },
        name.join("."),
        if important { "$important" } else { "" }
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// 100k synthetic entries: report and bound the per-entry overhead.
    #[test]
    fn index_memory_per_entry() {
        let mut b = IndexBuilder::new();
        let s = b
            .add_source(SourceKind::List(ListId::new("synthetic").unwrap()))
            .unwrap();
        let mut name_total = 0usize;
        for i in 0..100_000u32 {
            let n = format!("host{i}.zone{}.example.com", i % 997);
            name_total += n.len();
            let d = DomainName::parse(&n).unwrap();
            b.add_rule(Rule::new(RuleAction::Block, MatchKind::Subdomains, d), s)
                .unwrap();
        }
        let idx = b.build_in_memory();
        let m = idx.memory();
        assert_eq!(m.entries, 100_000);
        assert_eq!(m.name_bytes, name_total);
        let per = m.overhead_per_entry();
        println!(
            "index memory: {} entries, names {} B ({:.1} B/entry), overhead {} B ({per:.2} B/entry), side {} B",
            m.entries,
            m.name_bytes,
            m.name_bytes as f64 / m.entries as f64,
            m.overhead_bytes,
            m.side_bytes
        );
        assert!(per <= 24.0, "overhead {per} B/entry");
        assert!(per <= ENTRY_OVERHEAD_BYTES as f64 + 0.1);
    }
}
