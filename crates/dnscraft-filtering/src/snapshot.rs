//! Immutable snapshot of all filter sets, and its builder.
//!
//! # Sharing
//!
//! Sets whose *effective* list combination (enabled lists, in set order, without
//! repeats) is identical share one [`SharedIndex`] through an `Arc`. Lists are
//! parsed and fed into the [`IndexBuilder`] one at a time and each
//! `ParsedList` rule vector is dropped right after it is consumed, so peak
//! memory is the index plus the rules of the single largest list. A list that
//! belongs to several different combinations is parsed once per combination
//! (parsing is fast, about 0.7 s for 2.2 M rules; holding every parsed rule
//! would cost far more memory).
//!
//! # Custom rules and priority
//!
//! Custom rules are per set. Normally they go into a small separate index and
//! a query is evaluated against the custom index and the shared list index;
//! the better verdict wins by the AdGuard priority (important allow >
//! important block > allow > block); on equal rank the custom rule wins.
//! Longest-match tie-breaking only applies inside one index.
//!
//! Two kinds of custom rule must act on list rules and cannot be evaluated
//! separately: `$badfilter` (removes list rules with the same key) and
//! `@@...$dnsrewrite` (disables list rewrites). A set with such a rule gets a
//! private merged index containing its lists and its custom rules, built with
//! the custom rules as first source. Trade-off: that set does not share, so it
//! costs a full extra index (about the size of the combination index) and one
//! more parse of its lists. In a merged index a list-side `$badfilter` can
//! also remove an identical custom rule.
//!
//! # Rule text
//!
//! List bodies are not kept. The index asks [`ListBodies`] lazily when a
//! `Reason` needs the rule text; custom rules keep their (small) text inline.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use crate::error::FilterError;
use crate::index::{Index, IndexBuilder, IndexMemory, RuleTextSource, SourceId, SourceKind};
use crate::modifiers::DnsRewrite;
use crate::name::DomainName;
use crate::parser::{ListSource, ParsedList, SkipCounts, parse_list, parse_list_each};
use crate::rule::Rule;
use crate::set::{FilterConfig, ListBodies, SnapshotError};
use crate::types::{BlockMode, ListId, SetId, Verdict};

/// Facts about one list inside one list combination.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ListFacts {
    /// The list.
    pub list: ListId,
    /// False if [`ListBodies`] had no body (the list contributed nothing).
    pub body_available: bool,
    /// Lines in the body.
    pub total_lines: usize,
    /// Rules parsed (all rules handed to the index, including `$badfilter` rules).
    pub rules_parsed: usize,
    /// Skipped items by reason.
    pub skipped: SkipCounts,
    /// Unique contribution: `rules_parsed` minus the domain rules that were
    /// dropped because an identical rule came from an **earlier** list of the
    /// same combination (`Index::duplicates_of`). Order-dependent and computed
    /// per combination; the first list of a combination always has the
    /// highest value. Wildcard/regex rules and rules removed by `$badfilter`
    /// are not subtracted.
    pub unique_contribution: usize,
}

/// A list index shared by all sets with the same list combination.
#[derive(Debug)]
pub struct SharedIndex {
    /// The merged index.
    pub index: Index,
    /// Per-list facts, in combination order.
    pub lists: Vec<ListFacts>,
}

/// Facts about the custom rules of one set.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct CustomFacts {
    /// Rules parsed.
    pub rules_parsed: usize,
    /// Skipped items by reason.
    pub skipped: SkipCounts,
    /// True if the custom rules live in the set's private merged index.
    pub merged_into_list_index: bool,
}

#[derive(Debug)]
struct SetEntry {
    lists: Arc<SharedIndex>,
    custom: Option<Index>,
    custom_facts: CustomFacts,
    block_mode: BlockMode,
    paused_until: Option<SystemTime>,
}

/// Immutable view of all filter sets.
#[derive(Debug)]
pub struct Snapshot {
    sets: HashMap<SetId, SetEntry>,
}

impl Snapshot {
    /// Ids of all sets.
    pub fn set_ids(&self) -> impl Iterator<Item = &SetId> {
        self.sets.keys()
    }

    /// The shared list index of a set (compare with `Arc::ptr_eq`).
    pub fn shared_index(&self, set: &SetId) -> Option<&Arc<SharedIndex>> {
        self.sets.get(set).map(|e| &e.lists)
    }

    /// Per-list facts of a set (see [`ListFacts::unique_contribution`]).
    pub fn list_facts(&self, set: &SetId) -> Option<&[ListFacts]> {
        self.sets.get(set).map(|e| e.lists.lists.as_slice())
    }

    /// Facts about a set's custom rules.
    pub fn custom_facts(&self, set: &SetId) -> Option<&CustomFacts> {
        self.sets.get(set).map(|e| &e.custom_facts)
    }

    /// The block mode of a set.
    pub fn block_mode(&self, set: &SetId) -> Option<BlockMode> {
        self.sets.get(set).map(|e| e.block_mode)
    }

    /// The pause deadline of a set.
    pub fn paused_until(&self, set: &SetId) -> Option<SystemTime> {
        self.sets.get(set).and_then(|e| e.paused_until)
    }

    /// Domain-array memory of the distinct indexes in this snapshot (shared
    /// indexes are counted once).
    pub fn memory(&self) -> IndexMemory {
        let mut seen: Vec<*const SharedIndex> = Vec::new();
        let mut total = IndexMemory {
            entries: 0,
            name_bytes: 0,
            overhead_bytes: 0,
            side_bytes: 0,
        };
        let mut add = |m: IndexMemory| {
            total.entries += m.entries;
            total.name_bytes += m.name_bytes;
            total.overhead_bytes += m.overhead_bytes;
            total.side_bytes += m.side_bytes;
        };
        for e in self.sets.values() {
            let p = Arc::as_ptr(&e.lists);
            if !seen.contains(&p) {
                seen.push(p);
                add(e.lists.index.memory());
            }
            if let Some(c) = &e.custom {
                add(c.memory());
            }
        }
        total
    }

    /// Matches `name` against a set at time `now`.
    ///
    /// A paused set (`now < paused_until`) returns `Pass`. Otherwise custom
    /// and list rules compete by AdGuard priority; on equal rank the custom
    /// rule wins.
    pub fn match_name(
        &self,
        set: &SetId,
        name: &DomainName,
        qtype: u16,
        now: SystemTime,
    ) -> Result<Verdict, FilterError> {
        let e = self
            .sets
            .get(set)
            .ok_or_else(|| FilterError::UnknownSet(set.to_string()))?;
        if e.paused_until.is_some_and(|until| now < until) {
            return Ok(Verdict::Pass);
        }
        let list_v = e.lists.index.match_name(name, qtype);
        let Some(custom) = &e.custom else {
            return Ok(list_v);
        };
        let custom_v = custom.match_name(name, qtype);
        Ok(match (verdict_rank(&custom_v), verdict_rank(&list_v)) {
            (None, _) => list_v,
            (Some(_), None) => custom_v,
            (Some(c), Some(l)) if c <= l => custom_v,
            _ => list_v,
        })
    }

    /// Matches an answer address against IP rules of `set` at time `now`.
    ///
    /// A paused set returns `Pass`. Custom and list IP rules compete by AdGuard
    /// priority; on equal rank the custom rule wins. Callers (policy) should
    /// invoke this for every A/AAAA record of a resolved answer.
    pub fn match_answer_ip(
        &self,
        set: &SetId,
        ip: IpAddr,
        now: SystemTime,
    ) -> Result<Verdict, FilterError> {
        let e = self
            .sets
            .get(set)
            .ok_or_else(|| FilterError::UnknownSet(set.to_string()))?;
        if e.paused_until.is_some_and(|until| now < until) {
            return Ok(Verdict::Pass);
        }
        let list_v = e.lists.index.match_answer_ip(ip);
        let Some(custom) = &e.custom else {
            return Ok(list_v);
        };
        let custom_v = custom.match_answer_ip(ip);
        Ok(match (verdict_rank(&custom_v), verdict_rank(&list_v)) {
            (None, _) => list_v,
            (Some(_), None) => custom_v,
            (Some(c), Some(l)) if c <= l => custom_v,
            _ => list_v,
        })
    }
}

/// AdGuard priority rank of a verdict (lower wins), `None` for `Pass`.
fn verdict_rank(v: &Verdict) -> Option<u8> {
    match v {
        Verdict::Allowed(r) => Some(if r.important { 0 } else { 2 }),
        Verdict::Blocked(r) | Verdict::Rewrite(_, r) => Some(if r.important { 1 } else { 3 }),
        Verdict::Pass => None,
    }
}

#[derive(Debug)]
enum TextEntry {
    List(ListId),
    Inline(Arc<str>),
}

/// Resolves rule text lazily from [`ListBodies`] (lists) or memory (custom).
#[derive(Debug)]
struct SnapshotTexts {
    bodies: Arc<dyn ListBodies>,
    entries: Vec<TextEntry>,
}

impl RuleTextSource for SnapshotTexts {
    fn rule_at(&self, source: u32, offset: u32) -> Option<(u32, Arc<str>)> {
        let body = match self.entries.get(source as usize)? {
            TextEntry::Inline(body) => Arc::clone(body),
            TextEntry::List(id) => self.bodies.body(id)?,
        };
        crate::index::rule_at_body(&body, offset).map(|(line, text)| (line, Arc::from(text)))
    }
}

struct CustomParsed {
    body: Arc<str>,
    rules: Vec<Rule>,
    facts: CustomFacts,
}

/// Builds a [`Snapshot`] from a [`FilterConfig`].
#[derive(Debug)]
pub struct SnapshotBuilder {
    bodies: Arc<dyn ListBodies>,
}

impl SnapshotBuilder {
    /// A builder reading list bodies from `bodies`.
    pub fn new(bodies: Arc<dyn ListBodies>) -> Self {
        Self { bodies }
    }

    /// Builds the snapshot. Disabled lists are excluded from all sets; lists
    /// without a body contribute nothing (see [`ListFacts::body_available`]).
    pub fn build(&self, config: &FilterConfig) -> Result<Snapshot, SnapshotError> {
        let mut enabled: HashMap<&ListId, bool> = HashMap::new();
        for l in &config.lists {
            if enabled.insert(&l.id, l.enabled).is_some() {
                return Err(SnapshotError::DuplicateList(l.id.clone()));
            }
        }
        let mut shared: HashMap<Vec<ListId>, Arc<SharedIndex>> = HashMap::new();
        let mut sets: HashMap<SetId, SetEntry> = HashMap::new();
        for s in &config.sets {
            if sets.contains_key(&s.id) {
                return Err(SnapshotError::DuplicateSet(s.id.clone()));
            }
            let mut combo: Vec<ListId> = Vec::new();
            for l in &s.lists {
                match enabled.get(l) {
                    None => {
                        return Err(SnapshotError::UnknownList {
                            set: s.id.clone(),
                            list: l.clone(),
                        });
                    }
                    Some(true) if !combo.contains(l) => combo.push(l.clone()),
                    Some(_) => {}
                }
            }
            let mut custom = parse_custom(&s.custom_rules);
            let (lists, custom_index) = if needs_merge(&custom.rules) {
                custom.facts.merged_into_list_index = true;
                let idx = self.build_list_index(&combo, Some((&s.id, &mut custom)))?;
                (Arc::new(idx), None)
            } else {
                let lists = match shared.get(&combo) {
                    Some(a) => Arc::clone(a),
                    None => {
                        let a = Arc::new(self.build_list_index(&combo, None)?);
                        shared.insert(combo, Arc::clone(&a));
                        a
                    }
                };
                let ci = if custom.rules.is_empty() {
                    None
                } else {
                    let mut b = IndexBuilder::new();
                    let src = b.add_source_with_body(
                        SourceKind::Custom(s.id.clone()),
                        Arc::clone(&custom.body),
                    )?;
                    b.add_rules(src, std::mem::take(&mut custom.rules))?;
                    Some(b.build_in_memory())
                };
                (lists, ci)
            };
            sets.insert(
                s.id.clone(),
                SetEntry {
                    lists,
                    custom: custom_index,
                    custom_facts: custom.facts,
                    block_mode: s.block_mode,
                    paused_until: s.paused_until,
                },
            );
        }
        Ok(Snapshot { sets })
    }

    /// Builds one index from `combo`, optionally with a set's custom rules as
    /// the first source (they then win ties and own duplicates).
    fn build_list_index(
        &self,
        combo: &[ListId],
        custom: Option<(&SetId, &mut CustomParsed)>,
    ) -> Result<SharedIndex, SnapshotError> {
        let mut texts = Vec::with_capacity(combo.len() + 1);
        let mut b = IndexBuilder::new();
        if let Some((set, c)) = custom {
            let src = b.add_source(SourceKind::Custom(set.clone()))?;
            texts.push(TextEntry::Inline(Arc::clone(&c.body)));
            b.add_rules(src, std::mem::take(&mut c.rules))?;
        }
        let mut sources: Vec<(SourceId, ListFacts)> = Vec::with_capacity(combo.len());
        for id in combo {
            let src = b.add_source(SourceKind::List(id.clone()))?;
            texts.push(TextEntry::List(id.clone()));
            let mut facts = ListFacts {
                list: id.clone(),
                body_available: false,
                total_lines: 0,
                rules_parsed: 0,
                skipped: SkipCounts::default(),
                unique_contribution: 0,
            };
            if let Some(body) = self.bodies.body(id) {
                // Stream rules into the builder; drop each Rule immediately and
                // drop the body Arc when this block ends (ListBodies may keep
                // another copy — on-disk stores should not).
                let mut add_err = None;
                let stats = parse_list_each(&body, ListSource::List, |rule| {
                    if add_err.is_none() {
                        if let Err(e) = b.add_rule(rule, src) {
                            add_err = Some(e);
                        }
                    }
                });
                if let Some(e) = add_err {
                    return Err(e.into());
                }
                facts.body_available = true;
                facts.total_lines = stats.total_lines;
                facts.rules_parsed = stats.rules_parsed;
                facts.skipped = stats.skipped;
                drop(body);
            }
            sources.push((src, facts));
        }
        let index = b.build(Arc::new(SnapshotTexts {
            bodies: Arc::clone(&self.bodies),
            entries: texts,
        }));
        let lists = sources
            .into_iter()
            .map(|(src, mut f)| {
                f.unique_contribution = f.rules_parsed.saturating_sub(index.duplicates_of(src));
                f
            })
            .collect();
        Ok(SharedIndex { index, lists })
    }
}

fn parse_custom(text: &str) -> CustomParsed {
    let body: Arc<str> = Arc::from(text);
    let ParsedList { rules, skipped, .. } = parse_list(&body, ListSource::Custom);
    CustomParsed {
        facts: CustomFacts {
            rules_parsed: rules.len(),
            skipped,
            merged_into_list_index: false,
        },
        body,
        rules,
    }
}

/// Custom rules that must act on list rules.
fn needs_merge(rules: &[Rule]) -> bool {
    rules.iter().any(|r| {
        r.modifiers().badfilter || matches!(r.modifiers().dnsrewrite, Some(DnsRewrite::Disable))
    })
}
