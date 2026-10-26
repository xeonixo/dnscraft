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
//! more parse of its lists. Custom rules stay protected there: a `$badfilter`
//! or `@@...$dnsrewrite` from a list or service never affects a custom rule.
//!
//! # Rule text
//!
//! List bodies are not kept. The index asks the snapshot's text source lazily
//! when a `Reason` needs the rule text; custom rules keep their (small) text
//! inline. For each list the builder takes a [`ListText`] from
//! [`ListBodies::open`], pinned to the exact bytes that were parsed, so a
//! snapshot never reads text from a newer body (hot reload).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use crate::builder::{RecordTypeSel, RuleSpec, build_rule};
use crate::clock::{Clock, SystemClock};
use crate::error::FilterError;
use crate::index::{Index, IndexBuilder, IndexMemory, RuleTextSource, SourceId, SourceKind};
use crate::modifiers::DnsRewrite;
use crate::name::DomainName;
use crate::parser::{ListSource, ParsedList, SkipCounts, SkipReason, parse_list, parse_list_each};
use crate::rule::{Rule, RuleAction};
use crate::services::ServiceCatalog;
use crate::set::{FilterConfig, ListBodies, ListText, McpRule, SnapshotError};
use crate::types::{BlockMode, ListId, McpRuleId, Reason, RuleSource, SetId, Verdict};

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
    /// Service ids listed in the set config but missing from the catalog.
    unknown_services: Vec<String>,
    block_mode: BlockMode,
    paused_until: Option<SystemTime>,
    mcp: McpIndex,
}

/// Block rules created through the MCP control API.
///
/// Kept apart from the custom index so expiry can be checked exactly at match
/// time: the snapshot outlives the build, and an expired rule must stop
/// blocking without a config change or rebuild.
#[derive(Debug, Default)]
struct McpIndex {
    /// Exact-name rules, keyed by canonical domain text.
    exact: HashMap<Box<str>, McpEntry>,
    /// Domain-and-subdomain rules, keyed by canonical domain text.
    subdomains: HashMap<Box<str>, McpEntry>,
}

#[derive(Debug)]
struct McpEntry {
    id: McpRuleId,
    expires_at: SystemTime,
    /// Canonical block-rule text from [`build_rule`].
    rule: Arc<str>,
}

impl McpIndex {
    /// The rule that blocks `name` at `now`, or `Verdict::Pass`.
    ///
    /// The longest applicable domain wins: an active exact rule first, then
    /// the nearest active subdomain rule.
    fn match_name(&self, set: &SetId, name: &DomainName, now: SystemTime) -> Verdict {
        let exact = self.exact.get(name.as_str()).filter(|e| now < e.expires_at);
        let entry = exact.or_else(|| {
            name.suffixes()
                .find_map(|suffix| self.subdomains.get(suffix).filter(|e| now < e.expires_at))
        });
        let Some(entry) = entry else {
            return Verdict::Pass;
        };
        Verdict::Blocked(Reason {
            rule: Arc::clone(&entry.rule),
            source: RuleSource::Mcp {
                set: set.clone(),
                id: entry.id.clone(),
            },
            important: false,
        })
    }
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

    /// Service ids enabled on the set but not present in the catalog.
    ///
    /// Unknown ids are ignored when building (not fatal).
    pub fn unknown_services(&self, set: &SetId) -> Option<&[String]> {
        self.sets.get(set).map(|e| e.unknown_services.as_slice())
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
        Ok(self.match_name_active(set, e, name, qtype, now))
    }

    /// CNAME-uncloaking match over a resolution chain.
    ///
    /// `names` is the queried name followed by each CNAME target in order
    /// (`[qname, cname1, cname2, …]`). An empty slice yields [`Verdict::Pass`].
    /// A paused set yields `Pass`. Unknown set → [`FilterError::UnknownSet`].
    ///
    /// # Rules
    ///
    /// 1. **Important allow on the queried name wins the whole chain.**  
    ///    If `names[0]` matches an `$important` allow (or a temporary allow),
    ///    that allow is returned and later names are not considered. A
    ///    blocked CNAME target therefore does **not** block the request.
    /// 2. **First blocking verdict along the chain wins.**  
    ///    Walking the names in order, the first `Blocked` or `Rewrite` is
    ///    returned. Non-blocking verdicts (`Pass`, plain `Allowed`) do not
    ///    stop the walk.
    /// 3. **A non-important allow on the queried name does not unblock a
    ///    blocked CNAME target.**  
    ///    Example: rules `@@||safe.example^` and `||tracker.example^`, chain
    ///    `[safe.example, tracker.example]` → `Blocked` by the tracker rule.
    /// 4. **An important allow on the (blocked) target does unblock it.**  
    ///    Example: `||tracker.example^` and `@@||tracker.example^$important`,
    ///    chain `[page.example, tracker.example]` → `Allowed` (important) for
    ///    the target, so the chain does not return a block; the overall
    ///    result is the queried name's verdict (`Pass` here).
    /// 5. **If nothing in the chain blocks**, the queried name's verdict is
    ///    returned (`Pass`, plain `Allowed`, or an `$important` allow already
    ///    handled in rule 1).
    ///
    /// Temporary allows are applied by [`crate::FilterEngine`], which uses
    /// the same chain rules with temps ranked as `$important` allows.
    pub fn match_chain(
        &self,
        set: &SetId,
        names: &[DomainName],
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
        Ok(resolve_chain(names, |name| {
            self.match_name_active(set, e, name, qtype, now)
        }))
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

    fn match_name_active(
        &self,
        set: &SetId,
        e: &SetEntry,
        name: &DomainName,
        qtype: u16,
        now: SystemTime,
    ) -> Verdict {
        let list_v = e.lists.index.match_name(name, qtype);
        let custom_v = e
            .custom
            .as_ref()
            .map_or(Verdict::Pass, |c| c.match_name(name, qtype));
        let mcp_v = e.mcp.match_name(set, name, now);
        // MCP rules rank exactly like appended custom block rules: they
        // compete with the custom side by AdGuard priority and custom rules
        // win ties; the resulting custom side then competes with the lists.
        let custom_side = better_verdict(custom_v, mcp_v);
        better_verdict(custom_side, list_v)
    }
}

/// The better of two verdicts; on equal rank `a` wins.
fn better_verdict(a: Verdict, b: Verdict) -> Verdict {
    match (verdict_rank(&a), verdict_rank(&b)) {
        (None, _) => b,
        (Some(_), None) => a,
        (Some(x), Some(y)) if x <= y => a,
        _ => b,
    }
}

/// CNAME-chain evaluation given a per-name matcher (see [`Snapshot::match_chain`]).
pub(crate) fn resolve_chain(
    names: &[DomainName],
    mut match_one: impl FnMut(&DomainName) -> Verdict,
) -> Verdict {
    let Some(first_name) = names.first() else {
        return Verdict::Pass;
    };
    let first = match_one(first_name);
    if is_important_allow(&first) {
        return first;
    }
    if is_blocking(&first) {
        return first;
    }
    for name in &names[1..] {
        let v = match_one(name);
        if is_blocking(&v) {
            return v;
        }
    }
    first
}

fn is_important_allow(v: &Verdict) -> bool {
    matches!(v, Verdict::Allowed(r) if r.important)
}

fn is_blocking(v: &Verdict) -> bool {
    matches!(v, Verdict::Blocked(_) | Verdict::Rewrite(_, _))
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
    /// A list; the reader is pinned to the bytes the snapshot was built from.
    List(ListId, Option<Arc<dyn ListText>>),
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
        match self.entries.get(source as usize)? {
            TextEntry::Inline(body) => {
                crate::index::rule_at_body(body, offset).map(|(line, text)| (line, Arc::from(text)))
            }
            TextEntry::List(_, Some(text)) => text.rule_at(offset),
            TextEntry::List(id, None) => self.bodies.rule_at(id, offset),
        }
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
    catalog: Option<Arc<ServiceCatalog>>,
    clock: Arc<dyn Clock>,
}

impl SnapshotBuilder {
    /// A builder reading list bodies from `bodies`.
    pub fn new(bodies: Arc<dyn ListBodies>) -> Self {
        Self {
            bodies,
            catalog: None,
            clock: Arc::new(SystemClock),
        }
    }

    /// Uses `clock` to decide which MCP rules are already expired at build
    /// time (default: [`SystemClock`]).
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Injects blocked-service rules from `catalog` into sets that enable them.
    #[must_use]
    pub fn with_catalog(mut self, catalog: Option<Arc<ServiceCatalog>>) -> Self {
        self.catalog = catalog;
        self
    }

    /// Builds the snapshot. Disabled lists are excluded from all sets; lists
    /// without a body contribute nothing (see [`ListFacts::body_available`]).
    ///
    /// Enabled [`FilterSetConfig::services`](crate::FilterSetConfig::services)
    /// whose ids exist in the catalog join each set with
    /// [`RuleSource::Service`](crate::RuleSource::Service); unknown ids are
    /// recorded on the snapshot and are not fatal.
    pub fn build(&self, config: &FilterConfig) -> Result<Snapshot, SnapshotError> {
        let mut enabled: HashMap<&ListId, bool> = HashMap::new();
        for l in &config.lists {
            if enabled.insert(&l.id, l.enabled).is_some() {
                return Err(SnapshotError::DuplicateList(l.id.clone()));
            }
        }
        let mut shared: HashMap<Vec<ListId>, Arc<SharedIndex>> = HashMap::new();
        let mut sets: HashMap<SetId, SetEntry> = HashMap::new();
        let now = self.clock.now();
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
            let mcp = build_mcp_index(&s.id, &s.mcp_rules, now)?;
            let mut custom = parse_custom(&s.custom_rules);
            let (service_srcs, unknown_services) =
                resolve_services(self.catalog.as_deref(), &s.services);
            let has_services = !service_srcs.is_empty();
            let (lists, custom_index) = if needs_merge(&custom.rules) {
                custom.facts.merged_into_list_index = true;
                let idx =
                    self.build_list_index(&combo, Some((&s.id, &mut custom)), &service_srcs)?;
                (Arc::new(idx), None)
            } else {
                let lists = match shared.get(&combo) {
                    Some(a) => Arc::clone(a),
                    None => {
                        let a = Arc::new(self.build_list_index(&combo, None, &[])?);
                        shared.insert(combo, Arc::clone(&a));
                        a
                    }
                };
                let ci = if custom.rules.is_empty() && !has_services {
                    None
                } else {
                    Some(build_side_index(&s.id, &mut custom, &service_srcs)?)
                };
                (lists, ci)
            };
            sets.insert(
                s.id.clone(),
                SetEntry {
                    lists,
                    custom: custom_index,
                    custom_facts: custom.facts,
                    unknown_services,
                    block_mode: s.block_mode,
                    paused_until: s.paused_until,
                    mcp,
                },
            );
        }
        Ok(Snapshot { sets })
    }

    /// Builds one index from `combo`, optionally with a set's custom rules and
    /// blocked services as leading sources (they then win ties and own duplicates).
    fn build_list_index(
        &self,
        combo: &[ListId],
        custom: Option<(&SetId, &mut CustomParsed)>,
        services: &[(Arc<str>, Arc<str>)],
    ) -> Result<SharedIndex, SnapshotError> {
        let mut texts = Vec::with_capacity(combo.len() + 1 + services.len());
        let mut b = IndexBuilder::new();
        for (id, body) in services {
            let src = b.add_source(SourceKind::Service(Arc::clone(id)))?;
            texts.push(TextEntry::Inline(Arc::clone(body)));
            let mut add_err = None;
            parse_list_each(body, ListSource::List, |rule| {
                if add_err.is_none()
                    && let Err(e) = b.add_rule(rule, src)
                {
                    add_err = Some(e);
                }
            });
            if let Some(e) = add_err {
                return Err(e.into());
            }
        }
        if let Some((set, c)) = custom {
            let src = b.add_source(SourceKind::Custom(set.clone()))?;
            texts.push(TextEntry::Inline(Arc::clone(&c.body)));
            b.add_rules(src, std::mem::take(&mut c.rules))?;
        }
        let mut sources: Vec<(SourceId, ListFacts)> = Vec::with_capacity(combo.len());
        for id in combo {
            let src = b.add_source(SourceKind::List(id.clone()))?;
            let opened = self.bodies.open(id);
            texts.push(TextEntry::List(
                id.clone(),
                opened.as_ref().and_then(|o| o.text.clone()),
            ));
            let mut facts = ListFacts {
                list: id.clone(),
                body_available: false,
                total_lines: 0,
                rules_parsed: 0,
                skipped: SkipCounts::default(),
                unique_contribution: 0,
            };
            if let Some(body) = opened.map(|o| o.body) {
                // Stream rules into the builder; drop each Rule immediately and
                // drop the body Arc when this block ends (ListBodies may keep
                // another copy — on-disk stores should not).
                let mut add_err = None;
                let stats = parse_list_each(&body, ListSource::List, |rule| {
                    if add_err.is_none()
                        && let Err(e) = b.add_rule(rule, src)
                    {
                        add_err = Some(e);
                    }
                });
                if let Some(e) = add_err {
                    return Err(e.into());
                }
                facts.body_available = true;
                facts.total_lines = stats.total_lines;
                facts.rules_parsed = stats.rules_parsed;
                facts.skipped = stats.skipped;
                facts
                    .skipped
                    .add_n(SkipReason::PatternBudget, b.pattern_budget_skipped(src));
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
                f.unique_contribution = f
                    .rules_parsed
                    .saturating_sub(index.duplicates_of(src))
                    .saturating_sub(f.skipped.get(SkipReason::PatternBudget));
                f
            })
            .collect();
        Ok(SharedIndex { index, lists })
    }
}

/// Validates a set's MCP rules and builds the match-time index.
///
/// Every rule is validated and converted with [`build_rule`] (block action,
/// no modifiers); rules already expired at `now` are then dropped silently.
fn build_mcp_index(
    set: &SetId,
    rules: &[McpRule],
    now: SystemTime,
) -> Result<McpIndex, SnapshotError> {
    let mut ids: HashSet<&str> = HashSet::new();
    let mut pairs: HashSet<(&DomainName, bool)> = HashSet::new();
    let mut index = McpIndex::default();
    for rule in rules {
        if !ids.insert(rule.id.as_str()) {
            return Err(SnapshotError::DuplicateMcpRuleId {
                set: set.clone(),
                id: rule.id.clone(),
            });
        }
        if !pairs.insert((&rule.domain, rule.include_subdomains)) {
            return Err(SnapshotError::DuplicateMcpRule {
                set: set.clone(),
                domain: rule.domain.clone(),
            });
        }
        if rule.expires_at <= rule.created_at {
            return Err(SnapshotError::InvalidMcpRuleExpiry {
                set: set.clone(),
                id: rule.id.clone(),
            });
        }
        let text = build_rule(&RuleSpec {
            action: RuleAction::Block,
            domain: rule.domain.as_str().to_owned(),
            include_subdomains: rule.include_subdomains,
            record_types: RecordTypeSel::default(),
            important: false,
            rewrite: None,
        })
        .map_err(|e| SnapshotError::InvalidMcpRule {
            set: set.clone(),
            id: rule.id.clone(),
            code: e.code(),
        })?;
        if rule.expires_at <= now {
            continue;
        }
        let entry = McpEntry {
            id: rule.id.clone(),
            expires_at: rule.expires_at,
            rule: Arc::from(text),
        };
        if rule.include_subdomains {
            index.subdomains.insert(rule.domain.as_str().into(), entry);
        } else {
            index.exact.insert(rule.domain.as_str().into(), entry);
        }
    }
    Ok(index)
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

/// One enabled service ready to feed into an [`IndexBuilder`].
type ServiceSource = (Arc<str>, Arc<str>);

/// Resolves enabled service ids against the catalog.
///
/// Returns `(id, rules_body)` pairs and the list of unknown ids (not fatal).
fn resolve_services(
    catalog: Option<&ServiceCatalog>,
    ids: &[String],
) -> (Vec<ServiceSource>, Vec<String>) {
    let mut found = Vec::new();
    let mut unknown = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for id in ids {
        let id = id.trim();
        if id.is_empty() || !seen.insert(id.to_owned()) {
            continue;
        }
        match catalog.and_then(|c| c.get(id)) {
            Some(svc) => found.push((Arc::clone(&svc.id), Arc::clone(&svc.rules_body))),
            None => unknown.push(id.to_owned()),
        }
    }
    (found, unknown)
}

/// Custom + service rules in a small per-set index (competes with the shared
/// list index by AdGuard priority; on equal rank this side wins).
fn build_side_index(
    set: &SetId,
    custom: &mut CustomParsed,
    services: &[(Arc<str>, Arc<str>)],
) -> Result<Index, SnapshotError> {
    let mut b = IndexBuilder::new();
    for (id, body) in services {
        let src = b.add_source_with_body(SourceKind::Service(Arc::clone(id)), Arc::clone(body))?;
        let mut add_err = None;
        parse_list_each(body, ListSource::List, |rule| {
            if add_err.is_none()
                && let Err(e) = b.add_rule(rule, src)
            {
                add_err = Some(e);
            }
        });
        if let Some(e) = add_err {
            return Err(e.into());
        }
    }
    if !custom.rules.is_empty() {
        let src =
            b.add_source_with_body(SourceKind::Custom(set.clone()), Arc::clone(&custom.body))?;
        b.add_rules(src, std::mem::take(&mut custom.rules))?;
    }
    Ok(b.build_in_memory())
}

/// Custom rules that must act on list rules.
fn needs_merge(rules: &[Rule]) -> bool {
    rules.iter().any(|r| {
        r.modifiers().badfilter || matches!(r.modifiers().dnsrewrite, Some(DnsRewrite::Disable))
    })
}
