//! Policy configuration values and the per-query request context.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use dnscraft_filtering::SetId;
use dnscraft_proto::{Name, RData, RecordType};
use dnscraft_resolver::{ForwardZoneId, Query};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::ids::{ClientId, ListenerId, NodeId, ProfileId, ViewId};
use crate::rdata_text::{format_rdata, parse_rdata, record_type_text};

/// Default TTL for view local records when the config omits one.
pub const DEFAULT_RECORD_TTL: u32 = 60;

/// Default special-use suffixes answered with NXDOMAIN when unknown and not forwarded.
pub const DEFAULT_LOCAL_NXDOMAIN_SUFFIXES: &[&str] = &["local", "lan", "internal"];

/// Transport that delivered the DNS query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]

pub enum DnsProtocol {
    /// Plain DNS over UDP on port 53.
    Udp53,
    /// Plain DNS over TCP on port 53.
    Tcp53,
    /// DNS over TLS.
    DoT,
    /// DNS over HTTPS.
    DoH,
    /// DNS over QUIC.
    DoQ,
}

impl DnsProtocol {
    /// Wire / config name (`udp53`, `tcp53`, `dot`, `doh`, `doq`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp53 => "udp53",
            Self::Tcp53 => "tcp53",
            Self::DoT => "dot",
            Self::DoH => "doh",
            Self::DoQ => "doq",
        }
    }
}

/// Client message flags that influence policy and the resolver.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClientFlags {
    /// Checking Disabled (CD): skip DNSSEC validation downstream.
    pub checking_disabled: bool,
    /// DNSSEC OK (DO): the client wants DNSSEC records in the answer.
    pub dnssec_ok: bool,
    /// Recursion Desired (RD): mirrored into synthetic answers. Default true.
    pub recursion_desired: bool,
}

impl Default for ClientFlags {
    fn default() -> Self {
        Self {
            checking_disabled: false,
            dnssec_ok: false,
            recursion_desired: true,
        }
    }
}

/// Everything the listener knows about one incoming query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestContext {
    /// Source address of the client.
    pub source_ip: IpAddr,
    /// Transport used by the client.
    pub protocol: DnsProtocol,
    /// Listener that accepted the query.
    pub listener_id: ListenerId,
    /// Cluster node that accepted the query (`None` on a standalone node
    /// without a configured id). Views with `nodes` set must list it.
    pub node_id: Option<NodeId>,
    /// DoH/DoT Client ID when present (after TLS/listener admission).
    pub client_id: Option<ClientId>,
    /// The DNS question.
    pub query: Query,
    /// CD / DO / RD from the client message.
    pub flags: ClientFlags,
    /// When true, return a full decision record and never write the query log.
    pub test_query: bool,
}

/// One local resource record in the global name space.
///
/// Serialized as presentation text (`name`, `type`, `ttl`, `rdata`,
/// `overrides`), e.g. `rdata = "192.0.2.10"` with `type = "A"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RecordWire", into = "RecordWire")]
pub struct ViewRecordConfig {
    /// Owner name. Exact names, or a single leading `*` label
    /// (`*.example.com`); embedded `*` labels are rejected.
    pub name: Name,
    /// TTL in seconds. [`DEFAULT_RECORD_TTL`] when omitted.
    pub ttl: u32,
    /// Default record data for every view. Only A, AAAA, CNAME, TXT, SRV, MX
    /// and PTR are accepted.
    pub rdata: RData,
    /// Per-view replacement data, keyed by view id. A view without an entry
    /// uses [`Self::rdata`].
    pub overrides: BTreeMap<ViewId, RData>,
}

/// Presentation-text wire form of [`ViewRecordConfig`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordWire {
    name: String,
    #[serde(rename = "type")]
    rtype: String,
    #[serde(default = "default_record_ttl")]
    ttl: u32,
    rdata: String,
    #[serde(default)]
    overrides: BTreeMap<String, String>,
}

fn default_record_ttl() -> u32 {
    DEFAULT_RECORD_TTL
}

impl TryFrom<RecordWire> for ViewRecordConfig {
    type Error = String;

    fn try_from(wire: RecordWire) -> Result<Self, Self::Error> {
        let name = Name::from_ascii(&wire.name)
            .map_err(|err| format!("record `{}`: invalid owner name: {err}", wire.name))?;
        let rtype = crate::rdata_text::parse_record_type(&wire.rtype)
            .ok_or_else(|| format!("record `{}`: unsupported type `{}`", wire.name, wire.rtype))?;
        let rdata = parse_rdata(rtype, &wire.rdata)
            .map_err(|err| format!("record `{}` ({}): {err}", wire.name, wire.rtype))?;
        let mut overrides = BTreeMap::new();
        for (view, text) in wire.overrides {
            let id = ViewId::new(&view)
                .map_err(|err| format!("record `{}`: override view `{view}`: {err}", wire.name))?;
            let value = parse_rdata(rtype, &text)
                .map_err(|err| format!("record `{}` override `{view}`: {err}", wire.name))?;
            overrides.insert(id, value);
        }
        Ok(Self {
            name,
            ttl: wire.ttl,
            rdata,
            overrides,
        })
    }
}

impl From<ViewRecordConfig> for RecordWire {
    fn from(record: ViewRecordConfig) -> Self {
        Self {
            name: record.name.to_string(),
            rtype: record_type_text(record.rtype()).to_owned(),
            ttl: record.ttl,
            rdata: format_rdata(&record.rdata),
            overrides: record
                .overrides
                .iter()
                .map(|(view, rdata)| (view.to_string(), format_rdata(rdata)))
                .collect(),
        }
    }
}

impl ViewRecordConfig {
    /// Record data this record has in `view` (the override, else the default).
    pub fn rdata_for(&self, view: &ViewId) -> &RData {
        self.overrides.get(view).unwrap_or(&self.rdata)
    }
}

impl ViewRecordConfig {
    /// Wire type of this record.
    pub fn rtype(&self) -> RecordType {
        self.rdata.record_type()
    }
}

/// Whether a view-record type is allowed in v1.
pub(crate) fn is_allowed_view_rtype(rtype: RecordType) -> bool {
    matches!(
        rtype,
        RecordType::A
            | RecordType::AAAA
            | RecordType::CNAME
            | RecordType::TXT
            | RecordType::SRV
            | RecordType::MX
            | RecordType::PTR
    )
}

/// Returns true when any label of `name` is a single `*` octet.
pub(crate) fn name_has_wildcard_label(name: &Name) -> bool {
    name.labels().any(|label| label == b"*")
}

/// RFC 4592-style view wildcard: leftmost label is `*`, at least one more
/// label follows, and no other label is `*`.
pub(crate) fn is_allowed_wildcard_owner(name: &Name) -> bool {
    let mut labels = name.labels();
    match labels.next() {
        Some(b"*") => {
            let mut rest = 0usize;
            for label in labels {
                if label == b"*" {
                    return false;
                }
                rest += 1;
            }
            rest >= 1
        }
        _ => false,
    }
}

/// True when `name` has a `*` label that is not a valid leading wildcard.
pub(crate) fn name_has_invalid_wildcard(name: &Name) -> bool {
    name_has_wildcard_label(name) && !is_allowed_wildcard_owner(name)
}

/// Known SafeSearch provider ids (SPEC-policy.md). Matched case-insensitively
/// and stored lower-cased at snapshot build.
pub const SAFESEARCH_PROVIDERS: &[&str] = &["google", "bing", "youtube", "duckduckgo"];

/// Length of one week from Monday 00:00 UTC — upper bound for schedule `end`.
pub const SCHEDULE_WEEK: Duration = Duration::from_secs(7 * 24 * 3600);

/// YouTube Restricted Mode level used when the `youtube` SafeSearch provider is on.
///
/// Maps to Google's DNS CNAME targets (`restrict.youtube.com` vs
/// `restrictmoderate.youtube.com`). Default is [`Strict`](Self::Strict).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]

pub enum YoutubeMode {
    /// Maximum restriction (`restrict.youtube.com`).
    #[default]
    Strict,
    /// Moderate restriction (`restrictmoderate.youtube.com`).
    Moderate,
}

/// SafeSearch settings on a profile.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeSearchConfig {
    /// When true, rewrite known search/video hosts to their safe endpoints.
    pub enabled: bool,
    /// Provider ids the profile enables (`google`, `bing`, `youtube`, `duckduckgo`).
    pub providers: Vec<Arc<str>>,
    /// YouTube Restricted Mode when the `youtube` provider is enabled.
    pub youtube_mode: YoutubeMode,
}

/// One schedule window that may switch the active filter set.
///
/// Windows are offsets within one week from Monday 00:00 UTC
/// (`start` inclusive, `end` exclusive). See [`crate::active_schedule`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleConfig {
    /// Human-readable id for status / UI.
    pub id: Arc<str>,
    /// Filter set to use while this window is active.
    #[serde(with = "serde_ids")]
    pub filter_set: SetId,
    /// Inclusive start of the window within a week, from Monday 00:00 UTC.
    #[serde(with = "dnscraft_common::duration::serde")]
    pub start: Duration,
    /// Exclusive end of the window within a week, from Monday 00:00 UTC.
    #[serde(with = "dnscraft_common::duration::serde")]
    pub end: Duration,
}

/// A split-horizon view ("zone"): selection keys, node validity, and a profile pointer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewConfig {
    /// Stable view id.
    pub id: ViewId,
    /// When true, this view is the catch-all used when nothing else matches.
    /// Exactly one view in the config must set this.
    pub is_default: bool,
    /// Client source subnets that select this view (longest prefix wins).
    pub subnets: Vec<IpNet>,
    /// Nodes on which this view exists; empty means every node. The default
    /// view must be empty.
    #[serde(default)]
    pub nodes: Vec<NodeId>,
    /// Profile applied after selection.
    pub profile: ProfileId,
}

/// A policy profile: filter set, canaries, rebind, forward-zone allow-list, …
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileConfig {
    /// Stable profile id.
    pub id: ProfileId,
    /// Active filter set (schedules may override later).
    #[serde(with = "serde_ids")]
    pub filter_set: SetId,
    /// When true and the qtype is AAAA, answer NODATA.
    pub suppress_aaaa: bool,
    /// Answer `use-application-dns.net` with NXDOMAIN.
    pub firefox_canary: bool,
    /// Answer Apple Private Relay canary names with the blocking answer.
    pub icloud_private_relay: bool,
    /// Rebind protection for this profile. `None` uses [`PolicyConfig::default_rebind`].
    pub rebind: Option<bool>,
    /// Domains / `*.suffix` patterns exempt from rebind stripping.
    pub rebind_exceptions: Vec<Arc<str>>,
    /// Forward zones this profile may use.
    ///
    /// `None` applies every configured zone; `Some(ids)` restricts to those ids.
    #[serde(with = "serde_ids::opt_seq")]
    pub forward_zones: Option<Vec<ForwardZoneId>>,
    /// SafeSearch rewrite (steps 5–6).
    pub safesearch: SafeSearchConfig,
    /// Schedule windows that may swap the active filter set.
    pub schedules: Vec<ScheduleConfig>,
}

impl ProfileConfig {
    /// Effective rebind flag given the policy-wide default.
    pub fn rebind_enabled(&self, default_rebind: bool) -> bool {
        self.rebind.unwrap_or(default_rebind)
    }
}

/// Top-level policy configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Default for profiles that omit [`ProfileConfig::rebind`].
    pub default_rebind: bool,
    /// Extra prefixes for ClientDirectory PTR answers (RFC 1918 / ULA / loopback always on).
    pub ptr_prefixes: Vec<IpNet>,
    /// Non-public suffixes synthesised as NXDOMAIN when unknown and not forwarded.
    pub local_nxdomain_suffixes: Vec<Arc<str>>,
    /// Forward zones whose answers still get rebind protection (default: none).
    #[serde(with = "serde_ids::seq")]
    pub rebind_check_forward_zones: Vec<ForwardZoneId>,
    /// Split-horizon views.
    pub views: Vec<ViewConfig>,
    /// Profiles referenced by views.
    pub profiles: Vec<ProfileConfig>,
    /// Client-ID registry: IDs that public listeners admit. A registry, not a
    /// selection key; selection is source-IP only.
    #[serde(default)]
    pub client_ids: Vec<ClientIdEntry>,
    /// Local records: one global name space, with per-view overrides.
    #[serde(default)]
    pub records: Vec<ViewRecordConfig>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default_rebind: true,
            ptr_prefixes: Vec::new(),
            local_nxdomain_suffixes: DEFAULT_LOCAL_NXDOMAIN_SUFFIXES
                .iter()
                .map(|s| Arc::<str>::from(*s))
                .collect(),
            rebind_check_forward_zones: Vec::new(),
            views: Vec::new(),
            profiles: Vec::new(),
            client_ids: Vec::new(),
            records: Vec::new(),
        }
    }
}

/// Maximum length of a Client-ID label, in characters (after trimming).
pub const MAX_CLIENT_LABEL_CHARS: usize = 64;
/// Maximum length of a Client-ID device reference, in characters (after trimming).
pub const MAX_CLIENT_DEVICE_CHARS: usize = 128;

/// One Client-ID registry entry: a bare id (the original form, still valid) or
/// the object form with an optional label and device reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClientIdEntry {
    /// `"iphone-k7q2x9"`.
    Plain(ClientId),
    /// `{ "id": "iphone-k7q2x9", "label": "iPhone von Anna", "device": "..." }`.
    Detailed(ClientIdMeta),
}

/// Object form of a [`ClientIdEntry`]. Unknown keys are rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientIdMeta {
    /// The registered Client ID.
    pub id: ClientId,
    /// Display name shown in the UI and the query log (trimmed, 1..=64 characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Free-text reference to a client-directory entry (trimmed, at most 128 characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Pinned view: selected for this Client ID when no subnet matches the source IP
    /// (and the view is valid on the request's node). Must name an existing view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<ViewId>,
}

impl ClientIdEntry {
    /// The registered Client ID.
    pub fn id(&self) -> &ClientId {
        match self {
            Self::Plain(id) => id,
            Self::Detailed(meta) => &meta.id,
        }
    }

    /// The label, if the entry has one.
    pub fn label(&self) -> Option<&str> {
        match self {
            Self::Plain(_) => None,
            Self::Detailed(meta) => meta.label.as_deref(),
        }
    }

    /// The device reference, if the entry has one.
    pub fn device(&self) -> Option<&str> {
        match self {
            Self::Plain(_) => None,
            Self::Detailed(meta) => meta.device.as_deref(),
        }
    }

    /// The pinned view, if the entry has one.
    pub fn view(&self) -> Option<&ViewId> {
        match self {
            Self::Plain(_) => None,
            Self::Detailed(meta) => meta.view.as_ref(),
        }
    }
}

impl From<ClientId> for ClientIdEntry {
    fn from(id: ClientId) -> Self {
        Self::Plain(id)
    }
}

/// Checks a trimmed, non-empty Client-ID label. Returns the reason on failure.
pub fn check_client_label(label: &str) -> Result<(), &'static str> {
    if label.chars().count() > MAX_CLIENT_LABEL_CHARS {
        return Err("is longer than 64 characters");
    }
    if label.chars().any(char::is_control) {
        return Err("contains control characters");
    }
    Ok(())
}

/// Checks a trimmed, non-empty device reference. Returns the reason on failure.
pub fn check_client_device(device: &str) -> Result<(), &'static str> {
    if device.chars().count() > MAX_CLIENT_DEVICE_CHARS {
        return Err("is longer than 128 characters");
    }
    if device.chars().any(char::is_control) {
        return Err("contains control characters");
    }
    Ok(())
}

/// Serde adapter for `SetId` / `ForwardZoneId`: text on the wire, parsed back
/// through `FromStr` so the id charset/length rules still apply on deserialize.
/// Keeps this crate independent of serde support in the crates that define them.
mod serde_ids {
    use std::fmt::Display;
    use std::str::FromStr;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Display,
        S: Serializer,
    {
        value.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr,
        T::Err: Display,
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }

    pub mod seq {
        use super::*;

        pub fn serialize<T, S>(values: &[T], serializer: S) -> Result<S::Ok, S::Error>
        where
            T: Display,
            S: Serializer,
        {
            let text: Vec<String> = values.iter().map(ToString::to_string).collect();
            text.serialize(serializer)
        }

        pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
        where
            T: FromStr,
            T::Err: Display,
            D: Deserializer<'de>,
        {
            Vec::<String>::deserialize(deserializer)?
                .into_iter()
                .map(|text| text.parse().map_err(serde::de::Error::custom))
                .collect()
        }
    }

    pub mod opt_seq {
        use super::*;

        pub fn serialize<T, S>(values: &Option<Vec<T>>, serializer: S) -> Result<S::Ok, S::Error>
        where
            T: Display,
            S: Serializer,
        {
            let text: Option<Vec<String>> = values
                .as_ref()
                .map(|values| values.iter().map(ToString::to_string).collect());
            text.serialize(serializer)
        }

        pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<Vec<T>>, D::Error>
        where
            T: FromStr,
            T::Err: Display,
            D: Deserializer<'de>,
        {
            Option::<Vec<String>>::deserialize(deserializer)?
                .map(|texts| {
                    texts
                        .into_iter()
                        .map(|text| text.parse().map_err(serde::de::Error::custom))
                        .collect()
                })
                .transpose()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use dnscraft_proto::RData;
    use std::net::Ipv4Addr;

    #[test]
    fn config_allowed_view_rtypes() {
        assert!(is_allowed_view_rtype(RecordType::A));
        assert!(is_allowed_view_rtype(RecordType::PTR));
        assert!(!is_allowed_view_rtype(RecordType::NS));
        assert!(!is_allowed_view_rtype(RecordType::SOA));
    }

    #[test]
    fn config_wildcard_label_detection() {
        let leading = Name::from_ascii("*.example.com").unwrap();
        assert!(name_has_wildcard_label(&leading));
        assert!(is_allowed_wildcard_owner(&leading));
        assert!(!name_has_invalid_wildcard(&leading));
        assert!(!name_has_wildcard_label(
            &Name::from_ascii("nas.lan.example.com").unwrap()
        ));
        let star_middle = Name::from_ascii("a.*.example.com").unwrap();
        assert!(name_has_wildcard_label(&star_middle));
        assert!(!is_allowed_wildcard_owner(&star_middle));
        assert!(name_has_invalid_wildcard(&star_middle));
    }

    #[test]
    fn config_view_record_rtype_from_rdata() {
        let rec = ViewRecordConfig {
            name: Name::from_ascii("nas.lan.example.com").unwrap(),
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 10)),
            overrides: BTreeMap::new(),
        };
        assert_eq!(rec.rtype(), RecordType::A);
    }

    #[test]
    fn config_round_trips_through_json() {
        let cfg = PolicyConfig {
            default_rebind: false,
            ptr_prefixes: vec![
                "192.0.2.0/24".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
            ],
            local_nxdomain_suffixes: vec![Arc::from("lan"), Arc::from("example.com")],
            rebind_check_forward_zones: vec![ForwardZoneId::new("example-zone").unwrap()],
            views: vec![ViewConfig {
                id: ViewId::new("lan").unwrap(),
                is_default: true,
                subnets: vec!["192.0.2.0/24".parse().unwrap()],
                nodes: vec![NodeId::new("node-1").unwrap()],
                profile: ProfileId::new("default").unwrap(),
            }],
            client_ids: vec![ClientId::new("iphone-k7q2x9").unwrap().into()],
            records: vec![
                ViewRecordConfig {
                    name: Name::from_ascii("nas.lan.example.com").unwrap(),
                    ttl: DEFAULT_RECORD_TTL,
                    rdata: RData::A(Ipv4Addr::new(192, 0, 2, 10)),
                    overrides: BTreeMap::from([(
                        ViewId::new("lan").unwrap(),
                        RData::A(Ipv4Addr::new(192, 0, 2, 50)),
                    )]),
                },
                ViewRecordConfig {
                    name: Name::from_ascii("alias.lan.example.com").unwrap(),
                    ttl: 300,
                    rdata: RData::CNAME(Name::from_ascii("nas.lan.example.com").unwrap()),
                    overrides: BTreeMap::new(),
                },
                ViewRecordConfig {
                    name: Name::from_ascii("txt.lan.example.com").unwrap(),
                    ttl: 60,
                    rdata: RData::TXT(vec![b"hello world".to_vec().into_boxed_slice()]),
                    overrides: BTreeMap::new(),
                },
            ],
            profiles: vec![ProfileConfig {
                id: ProfileId::new("default").unwrap(),
                filter_set: SetId::new("family").unwrap(),
                suppress_aaaa: true,
                firefox_canary: true,
                icloud_private_relay: false,
                rebind: Some(true),
                rebind_exceptions: vec![Arc::from("nas.example.com")],
                forward_zones: Some(vec![ForwardZoneId::new("example-zone").unwrap()]),
                safesearch: SafeSearchConfig {
                    enabled: true,
                    providers: vec![Arc::from("google"), Arc::from("youtube")],
                    youtube_mode: YoutubeMode::Moderate,
                },
                schedules: vec![ScheduleConfig {
                    id: Arc::from("school"),
                    filter_set: SetId::new("strict").unwrap(),
                    start: Duration::from_secs(8 * 3600),
                    end: Duration::from_secs(15 * 3600),
                }],
            }],
        };

        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"start\":\"8h\""), "{json}");
        assert!(json.contains("\"end\":\"15h\""), "{json}");
        let decoded: PolicyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, cfg);
    }

    #[test]
    fn record_config_reads_presentation_text() {
        let value = serde_json::json!({
            "name": "nas.lan.example.com",
            "type": "A",
            "rdata": "192.0.2.10",
            "overrides": { "guests": "192.0.2.50" },
        });
        let rec: ViewRecordConfig = serde_json::from_value(value).unwrap();
        assert_eq!(rec.ttl, DEFAULT_RECORD_TTL);
        assert_eq!(rec.rdata, RData::A(Ipv4Addr::new(192, 0, 2, 10)));
        let guests = ViewId::new("guests").unwrap();
        assert_eq!(
            rec.overrides[&guests],
            RData::A(Ipv4Addr::new(192, 0, 2, 50))
        );

        let bad =
            serde_json::json!({ "name": "nas.lan.example.com", "type": "A", "rdata": "nope" });
        let err = serde_json::from_value::<ViewRecordConfig>(bad).unwrap_err();
        assert!(err.to_string().contains("invalid IPv4"), "{err}");

        let unknown = serde_json::json!({ "name": "a.example.com", "type": "NS", "rdata": "x" });
        assert!(serde_json::from_value::<ViewRecordConfig>(unknown).is_err());
    }

    #[test]
    fn duration_fields_parse_human_strings() {
        let schedule = ScheduleConfig {
            id: Arc::from("school"),
            filter_set: SetId::new("strict").unwrap(),
            start: Duration::from_secs(8 * 3600),
            end: Duration::from_secs(15 * 3600),
        };
        let mut value = serde_json::to_value(&schedule).unwrap();
        value["start"] = "1d".into();
        value["end"] = "90s".into();
        let back: ScheduleConfig = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(back.start, Duration::from_secs(86_400));
        assert_eq!(back.end, Duration::from_secs(90));

        value["start"] = "1x".into();
        assert!(serde_json::from_value::<ScheduleConfig>(value).is_err());
    }
}
