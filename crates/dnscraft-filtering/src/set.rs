//! Filter set configuration and the list-body provider.
//!
//! These are plain Rust values that serialize to JSON for the config snapshot.
//! `control-api` owns persistence and hands a [`FilterConfig`] to the
//! [`SnapshotBuilder`](crate::SnapshotBuilder).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::index::IndexError;
use crate::name::DomainName;
use crate::store::ListSourceSpec;
use crate::types::{BlockMode, ListId, McpRuleId, SetId};

/// serde adapter for [`SystemTime`], which has no serde implementation.
///
/// Encoded as `{ "secs": <u64>, "nanos": <u32> }` seconds and nanoseconds
/// since the Unix epoch, preserving full precision. Times before the epoch
/// cannot be represented and fail to serialize.
pub(crate) mod system_time_serde {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use serde::ser::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Timestamp {
        secs: u64,
        nanos: u32,
    }

    pub fn serialize<S: Serializer>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error> {
        let since_epoch = time.duration_since(UNIX_EPOCH).map_err(S::Error::custom)?;
        Timestamp {
            secs: since_epoch.as_secs(),
            nanos: since_epoch.subsec_nanos(),
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SystemTime, D::Error> {
        from_timestamp(Timestamp::deserialize(deserializer)?)
    }

    fn from_timestamp<E: serde::de::Error>(ts: Timestamp) -> Result<SystemTime, E> {
        if ts.nanos >= 1_000_000_000 {
            return Err(E::custom("nanoseconds out of range"));
        }
        UNIX_EPOCH
            .checked_add(Duration::new(ts.secs, ts.nanos))
            .ok_or_else(|| E::custom("timestamp out of range"))
    }

    pub mod option {
        use std::time::SystemTime;

        use serde::{Deserialize, Deserializer, Serializer};

        use super::Timestamp;

        pub fn serialize<S: Serializer>(
            time: &Option<SystemTime>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match time {
                Some(time) => super::serialize(time, serializer),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<SystemTime>, D::Error> {
            Option::<Timestamp>::deserialize(deserializer)?
                .map(super::from_timestamp)
                .transpose()
        }
    }
}

/// Default list update interval (24 h).
pub const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Default maximum size of one list body in MiB (64 MiB).
pub const DEFAULT_MAX_LIST_SIZE_MB: u64 = crate::store::DEFAULT_MAX_BODY_BYTES / (1024 * 1024);

/// One configured filter list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// A block rule created through the MCP control API.
///
/// Unlike [`FilterSetConfig::custom_rules`], every rule carries its own
/// metadata and expires. At snapshot build time non-expired rules are turned
/// into canonical block-rule text with
/// [`build_rule`](crate::build_rule); expired rules are dropped silently.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRule {
    /// Unique per set.
    pub id: McpRuleId,
    /// Domain to block.
    pub domain: DomainName,
    /// Block the domain and every subdomain (`||`) rather than the name only
    /// (`|`).
    pub include_subdomains: bool,
    /// When the rule was created.
    #[serde(with = "system_time_serde")]
    pub created_at: SystemTime,
    /// When the rule stops blocking (mandatory; must be after `created_at`).
    #[serde(with = "system_time_serde")]
    pub expires_at: SystemTime,
    /// Which MCP token created the rule.
    pub token_id: String,
}

/// One configured filter set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterSetConfig {
    /// Set id.
    pub id: SetId,
    /// Display name.
    pub name: String,
    /// Lists in priority order (earlier lists win ties and own duplicates).
    pub lists: Vec<ListId>,
    /// Custom rules, one rule per line.
    pub custom_rules: String,
    /// Blocked service ids from the runtime catalog (`services.json`).
    pub services: Vec<String>,
    /// How blocked queries are answered.
    pub block_mode: BlockMode,
    /// The set passes every name before this time.
    #[serde(default, with = "system_time_serde::option")]
    pub paused_until: Option<SystemTime>,
    /// Block rules created through the MCP control API. Empty by default.
    pub mcp_rules: Vec<McpRule>,
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
            mcp_rules: Vec::new(),
        }
    }
}

/// The whole filtering configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterConfig {
    /// All known lists.
    pub lists: Vec<ListConfig>,
    /// All filter sets.
    pub sets: Vec<FilterSetConfig>,
    /// How often lists are refreshed.
    #[serde(with = "dnscraft_common::duration::serde")]
    pub update_interval: Duration,
    /// Maximum accepted size of one list body, in MiB (spec
    /// `filtering.max_list_size_mb`, default 64 MiB). This is the counterpart
    /// of [`StoreConfig::max_body_bytes`](crate::StoreConfig::max_body_bytes)
    /// and is applied to every store body read, fetch and write.
    pub max_list_size_mb: u64,
}

impl FilterConfig {
    /// [`Self::max_list_size_mb`] in bytes, saturating on absurd values.
    pub fn max_list_size_bytes(&self) -> u64 {
        self.max_list_size_mb.saturating_mul(1024 * 1024)
    }
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            lists: Vec::new(),
            sets: Vec::new(),
            update_interval: DEFAULT_UPDATE_INTERVAL,
            max_list_size_mb: DEFAULT_MAX_LIST_SIZE_MB,
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

    /// The body of list `id` plus a rule-text reader pinned to those bytes.
    /// Snapshot builders call this instead of [`Self::body`]. The default has
    /// no pinned reader, so rule text then comes from [`Self::rule_at`].
    fn open(&self, id: &ListId) -> Option<OpenedList> {
        self.body(id).map(|body| OpenedList { body, text: None })
    }

    /// Trimmed rule line at byte `offset` in list `id`, plus its 1-based line
    /// number. The default loads [`Self::body`] and slices; store-backed
    /// implementations seek without keeping the whole file.
    fn rule_at(&self, id: &ListId, offset: u32) -> Option<(u32, Arc<str>)> {
        let body = self.body(id)?;
        crate::index::rule_at_body(&body, offset).map(|(line, text)| (line, Arc::from(text)))
    }
}

/// Reads rule text from exactly the bytes a snapshot was built from.
///
/// Obtained from [`ListBodies::open`]. The snapshot owns it, so a list body
/// that is replaced later (hot reload) never changes the text that an older
/// snapshot reports. Offsets are byte offsets into the body that
/// [`ListBodies::open`] returned.
pub trait ListText: Send + Sync + std::fmt::Debug {
    /// Trimmed rule line at byte `offset` plus its 1-based line number, or
    /// `None` if it cannot be read.
    fn rule_at(&self, offset: u32) -> Option<(u32, Arc<str>)>;
}

/// A list body together with the reader for its rule text.
#[derive(Debug)]
pub struct OpenedList {
    /// The body to parse.
    pub body: Arc<str>,
    /// Rule-text reader pinned to the same bytes as `body`. `None` falls back
    /// to [`ListBodies::rule_at`] (which may see a newer body).
    pub text: Option<Arc<dyn ListText>>,
}

/// Why a snapshot could not be built.
#[derive(Debug, thiserror::Error)]

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
    /// Two MCP rules of a set share an id.
    #[error("set {set} has duplicate MCP rule id {id}")]
    DuplicateMcpRuleId {
        /// The set.
        set: SetId,
        /// The duplicated id.
        id: McpRuleId,
    },
    /// Two MCP rules of a set block the same `(domain, include_subdomains)`.
    #[error("set {set} has duplicate MCP rule for {domain}")]
    DuplicateMcpRule {
        /// The set.
        set: SetId,
        /// The duplicated domain.
        domain: DomainName,
    },
    /// An MCP rule expires at or before it was created.
    #[error("MCP rule {id} of set {set} must expire after it was created")]
    InvalidMcpRuleExpiry {
        /// The set.
        set: SetId,
        /// The rule.
        id: McpRuleId,
    },
    /// An MCP rule could not be turned into canonical rule text.
    #[error("MCP rule {id} of set {set} is invalid: {code}")]
    InvalidMcpRule {
        /// The set.
        set: SetId,
        /// The rule.
        id: McpRuleId,
        /// Underlying error code (for example `filter_build.pattern_not_allowed`).
        code: &'static str,
    },
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
            Self::DuplicateMcpRuleId { .. } => "filtering.config.mcp_rule_id_duplicate",
            Self::DuplicateMcpRule { .. } => "filtering.config.mcp_rule_duplicate",
            Self::InvalidMcpRuleExpiry { .. } => "filtering.config.mcp_rule_expiry",
            Self::InvalidMcpRule { .. } => "filtering.config.mcp_rule_invalid",
            Self::Index(e) => e.code(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    #[test]
    fn config_round_trips_through_json() {
        let list = ListConfig {
            id: ListId::new("ads").unwrap(),
            name: "Ads".into(),
            source: ListSourceSpec::Url("https://example.com/hosts.txt".into()),
            enabled: true,
        };
        let rule = McpRule {
            id: McpRuleId::new("mcp-1").unwrap(),
            domain: DomainName::parse("ads.example.net").unwrap(),
            include_subdomains: true,
            created_at: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            expires_at: UNIX_EPOCH + Duration::from_secs(1_700_003_600),
            token_id: "token-1".into(),
        };
        let set = FilterSetConfig {
            id: SetId::new("default").unwrap(),
            name: "Default".into(),
            lists: vec![list.id.clone()],
            custom_rules: "||tracker.example.com^".into(),
            services: vec!["video".into()],
            block_mode: BlockMode::NxDomain,
            paused_until: Some(UNIX_EPOCH + Duration::from_secs(1_700_007_200)),
            mcp_rules: vec![rule],
        };
        let config = FilterConfig {
            lists: vec![list],
            sets: vec![set],
            update_interval: Duration::from_secs(43_200),
            max_list_size_mb: 32,
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"update_interval\":\"12h\""), "{json}");
        let back: FilterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn duration_field_parses_human_strings() {
        let mut value = serde_json::to_value(FilterConfig::default()).unwrap();
        value["update_interval"] = "1d".into();
        let config: FilterConfig = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(config.update_interval, Duration::from_secs(86_400));

        value["update_interval"] = "90s".into();
        let config: FilterConfig = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(config.update_interval, Duration::from_secs(90));

        value["update_interval"] = "1x".into();
        assert!(serde_json::from_value::<FilterConfig>(value).is_err());
    }

    #[test]
    fn system_time_rejects_out_of_range_nanos() {
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct Paused {
            #[serde(with = "system_time_serde::option")]
            paused_until: Option<SystemTime>,
        }

        let json = r#"{"paused_until":{"secs":1,"nanos":1000000000}}"#;
        assert!(serde_json::from_str::<Paused>(json).is_err());
    }
}
