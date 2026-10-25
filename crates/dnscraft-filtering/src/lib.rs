//! Domain filtering engine for DNScraft.
//!
//! This crate decides what should happen to a query name: pass it, allow it
//! explicitly, block it, or rewrite the answer. Every non-pass verdict carries
//! a [`Reason`] naming the rule and where it came from.
//!
//! What it is not: it speaks no DNS on the wire, opens no sockets, and has no
//! notion of clients. Callers hand in a name and get a [`Verdict`] back.
//!
//! Currently provided: the canonical matching name [`DomainName`], validated
//! ids ([`ListId`], [`SetId`]), verdict types, [`BlockMode`], an injectable
//! [`Clock`], filter sets ([`Snapshot`]), temporary allows, match counters,
//! and error types with stable codes.

mod builder;
mod clock;
mod engine;
mod error;
mod fetch;
mod index;
mod modifiers;
mod name;
mod parser;
mod pattern;
mod rule;
mod set;
mod snapshot;
mod stats;
mod store;
mod temp_allow;
mod types;

pub use builder::{
    BuildError, MAX_TXT_LEN, RecordTypeSel, RewriteSpec, RuleSpec, build_rule, describe_rule,
};
pub use clock::{Clock, ManualClock, SystemClock};
pub use engine::FilterEngine;
pub use error::{FilterError, IdError, NameError, RuleError, UnsupportedKind};
pub use fetch::{FetchError, FetchOutcome, Fetcher, FetcherConfig, MAX_REDIRECTS};
pub use index::{
    ENTRY_OVERHEAD_BYTES, Index, IndexBuilder, IndexError, IndexMemory, MemoryTexts,
    RuleTextSource, SourceId, SourceKind,
};
pub use name::{DomainName, Labels, Suffixes};
pub use parser::{
    ListParseStats, ListSource, MAX_LINE_LEN, ParsedList, SKIP_SAMPLE_LIMIT, SkipCounts,
    SkipReason, SkippedLine, parse_list, parse_list_each, parse_rule,
};
pub use pattern::{
    Glob, GlobStart, REGEX_DFA_SIZE_LIMIT, REGEX_MESSAGE_MAX, REGEX_SIZE_LIMIT, RegexRule,
};
pub use rule::{BadfilterKey, DnsRewrite, DnsTypeFilter, MatchKind, Modifiers, Rule, RuleAction};
pub use set::{
    DEFAULT_UPDATE_INTERVAL, FilterConfig, FilterSetConfig, ListBodies, ListConfig, SnapshotError,
};
pub use snapshot::{CustomFacts, ListFacts, SharedIndex, Snapshot, SnapshotBuilder};
pub use stats::{FilterStats, ListStats, SetStats};
pub use store::{
    DEFAULT_MAX_BODY_BYTES, ListMeta, ListSourceSpec, ListStore, META_VERSION, MetaError,
    StoreConfig, StoreError,
};
pub use temp_allow::TempAllow;
pub use types::{BlockMode, ListId, Reason, Rewrite, RuleSource, SetId, Verdict};
