//! Domain filtering engine for DNScraft.
//!
//! This crate decides what should happen to a query name: pass it, allow it
//! explicitly, block it, or rewrite the answer. Every non-pass verdict carries
//! a [`Reason`] naming the rule and where it came from.
//!
//! What it is not: it speaks no DNS on the wire, opens no sockets, and has no
//! notion of clients. Callers hand in a name and get a [`Verdict`] back.
//!
//! Primary entry point: [`FilterEngine::new`] (config + [`ListStore`] +
//! [`Clock`]). Matching-only tests may use [`FilterEngine::from_snapshot`].
//! Also provided: [`DomainName`], [`parse_rule`] / [`build_rule`],
//! [`ServiceCatalog`], and error types with stable `code()`.

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
mod scheduler;
mod services;
mod set;
mod snapshot;
mod stats;
mod store;
mod temp_allow;
mod types;

/// Deterministic reference-shaped rule generator for criterion benches.
/// Enabled only with `--features testgen`; not part of the stable public API.
#[cfg(feature = "testgen")]
#[doc(hidden)]
pub mod testgen;

pub use builder::{
    BuildError, MAX_TXT_LEN, RecordTypeSel, RewriteSpec, RuleSpec, build_rule, describe_rule,
};
pub use clock::{Clock, ManualClock, SystemClock, wait_until};
pub use engine::{FilterEngine, ListSelection, ListStatus, ReloadReport};
pub use error::{FilterError, IdError, NameError, RuleError, UnsupportedKind};
pub use fetch::{FetchError, FetchOutcome, Fetcher, FetcherConfig, MAX_REDIRECTS};
pub use index::{
    ENTRY_OVERHEAD_BYTES, Index, IndexBuilder, IndexError, IndexMemory, MAX_GLOB_RULES,
    MAX_REGEX_RULES, MemoryTexts, REGEX_BUDGET_BYTES, RuleTextSource, SourceId, SourceKind,
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
pub use scheduler::UpdateScheduler;
pub use services::{
    FetchOutcomeKind as ServicesFetchKind, SERVICES_I18N_STEM, SERVICES_I18N_URL,
    SERVICES_JSON_URL, SERVICES_STEM, ServiceCatalog, ServiceError, ServiceInfo, ServiceParseStats,
    ServicesUpdateReport, ServicesUrls, seed_services_cache, update_services_catalog,
};
pub use set::{
    DEFAULT_UPDATE_INTERVAL, FilterConfig, FilterSetConfig, ListBodies, ListConfig, ListText,
    OpenedList, SnapshotError,
};
pub use snapshot::{CustomFacts, ListFacts, SharedIndex, Snapshot, SnapshotBuilder};
pub use stats::{FilterStats, ListStats, SetStats};
pub use store::{
    DEFAULT_MAX_BODY_BYTES, ListMeta, ListSourceSpec, ListStore, META_VERSION, MetaError,
    StoreConfig, StoreError, StoreListBodies,
};
pub use temp_allow::TempAllow;
pub use types::{BlockMode, ListId, Reason, Rewrite, RuleSource, SetId, Verdict};
