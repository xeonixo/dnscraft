//! Filter set configuration and the list-body provider.
//!
//! These are plain Rust values (no serde here): `control-api` owns persistence
//! and hands a [`FilterConfig`] to the [`SnapshotBuilder`](crate::SnapshotBuilder).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::index::IndexError;
use crate::store::ListSourceSpec;
use crate::types::{BlockMode, ListId, SetId};

/// Default list update interval (24 h).
pub const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// One configured filter list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListConfig {
    /// List id.
    pub id: ListId,
    /// Display name.
    pub name: String,
    /// Where the list comes from.
    pub source: ListSourceSpec,
    /// Disabled lists are excluded from every set.
    pub enabled: bool,
}

/// One configured filter set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterSetConfig {
    /// Set id.
    pub id: SetId,
    /// Display name.
    pub name: String,
    /// Lists in priority order (earlier lists win ties and own duplicates).
    pub lists: Vec<ListId>,
    /// Custom rules, one rule per line.
    pub custom_rules: String,
    /// Blocked service ids (placeholder until the service catalog exists).
    pub services: Vec<String>,
    /// How blocked queries are answered.
    pub block_mode: BlockMode,
    /// The set passes every name before this time.
    pub paused_until: Option<SystemTime>,
}

impl FilterSetConfig {
    /// A set with no lists, no custom rules and default block mode.
    pub fn new(id: SetId, name: &str) -> Self {
        Self {
            id,
            name: name.to_owned(),
            lists: Vec::new(),
            custom_rules: String::new(),
            services: Vec::new(),
            block_mode: BlockMode::default(),
            paused_until: None,
        }
    }
}

/// The whole filtering configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterConfig {
    /// All known lists.
    pub lists: Vec<ListConfig>,
    /// All filter sets.
    pub sets: Vec<FilterSetConfig>,
    /// How often lists are refreshed.
    pub update_interval: Duration,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            lists: Vec::new(),
            sets: Vec::new(),
            update_interval: DEFAULT_UPDATE_INTERVAL,
        }
    }
}

/// Provides list bodies. The snapshot never keeps bodies; it asks again when
/// the text of a matched rule is needed.
///
/// Implemented from the on-disk [`crate::ListStore`] by the engine; tests use
/// an in-memory map. Builders call [`Self::body`] once per list and drop the
/// result so bodies are never all held at once.
pub trait ListBodies: Send + Sync + std::fmt::Debug {
    /// The body of list `id`, or `None` if it has not been downloaded yet.
    fn body(&self, id: &ListId) -> Option<Arc<str>>;

    /// Trimmed rule line at byte `offset` in list `id`, plus its 1-based line
    /// number. The default loads [`Self::body`] and slices; store-backed
    /// implementations seek without keeping the whole file.
    fn rule_at(&self, id: &ListId, offset: u32) -> Option<(u32, Arc<str>)> {
        let body = self.body(id)?;
        crate::index::rule_at_body(&body, offset).map(|(line, text)| (line, Arc::from(text)))
    }
}

/// Why a snapshot could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SnapshotError {
    /// A set refers to a list that is not configured.
    #[error("set {set} refers to unknown list {list}")]
    UnknownList {
        /// The set.
        set: SetId,
        /// The missing list.
        list: ListId,
    },
    /// Two sets share an id.
    #[error("duplicate set id {0}")]
    DuplicateSet(SetId),
    /// Two lists share an id.
    #[error("duplicate list id {0}")]
    DuplicateList(ListId),
    /// The index builder failed.
    #[error(transparent)]
    Index(#[from] IndexError),
}

impl SnapshotError {
    /// Stable, locale-neutral code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownList { .. } => "filter_set.unknown_list",
            Self::DuplicateSet(_) => "filter_set.duplicate_set",
            Self::DuplicateList(_) => "filter_set.duplicate_list",
            Self::Index(e) => e.code(),
        }
    }
}
