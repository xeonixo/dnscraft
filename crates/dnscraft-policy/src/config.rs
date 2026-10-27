//! Policy configuration values and the per-query request context.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use dnscraft_filtering::SetId;
use dnscraft_proto::{Name, RData, RecordType};
use dnscraft_resolver::{ForwardZoneId, Query};
use ipnet::IpNet;

use crate::ids::{ClientId, ListenerId, ProfileId, ViewId};

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
    /// DoH/DoT Client ID when present (after TLS/listener admission).
    pub client_id: Option<ClientId>,
    /// The DNS question.
    pub query: Query,
    /// CD / DO / RD from the client message.
    pub flags: ClientFlags,
    /// When true, return a full decision record and never write the query log.
    pub test_query: bool,
}

/// One resource record authored under a view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewRecordConfig {
    /// Owner name (exact; wildcards are rejected at build time).
    pub name: Name,
    /// TTL in seconds. [`DEFAULT_RECORD_TTL`] when unset by the UI.
    pub ttl: u32,
    /// Record data; the wire type is derived from the variant.
    ///
    /// Only A, AAAA, CNAME, TXT, SRV, MX and PTR are accepted.
    pub rdata: RData,
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

/// Known SafeSearch provider ids (SPEC-policy.md). Matched case-insensitively
/// and stored lower-cased at snapshot build.
pub const SAFESEARCH_PROVIDERS: &[&str] = &["google", "bing", "youtube", "duckduckgo"];

/// Length of one week from Monday 00:00 UTC — upper bound for schedule `end`.
pub const SCHEDULE_WEEK: Duration = Duration::from_secs(7 * 24 * 3600);

/// YouTube Restricted Mode level used when the `youtube` SafeSearch provider is on.
///
/// Maps to Google's DNS CNAME targets (`restrict.youtube.com` vs
/// `restrictmoderate.youtube.com`). Default is [`Strict`](Self::Strict).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]

pub enum YoutubeMode {
    /// Maximum restriction (`restrict.youtube.com`).
    #[default]
    Strict,
    /// Moderate restriction (`restrictmoderate.youtube.com`).
    Moderate,
}

/// SafeSearch settings on a profile.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleConfig {
    /// Human-readable id for status / UI.
    pub id: Arc<str>,
    /// Filter set to use while this window is active.
    pub filter_set: SetId,
    /// Inclusive start of the window within a week, from Monday 00:00 UTC.
    pub start: Duration,
    /// Exclusive end of the window within a week, from Monday 00:00 UTC.
    pub end: Duration,
}

/// A split-horizon view: selection keys, local records, and a profile pointer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewConfig {
    /// Stable view id.
    pub id: ViewId,
    /// When true, this view is the catch-all used when nothing else matches.
    /// Exactly one view in the config must set this.
    pub is_default: bool,
    /// Client source subnets that select this view (longest prefix wins).
    pub subnets: Vec<IpNet>,
    /// DoH/DoT Client IDs that select this view (beats any subnet).
    pub client_ids: Vec<ClientId>,
    /// Exact-name local records for this view.
    pub records: Vec<ViewRecordConfig>,
    /// Profile applied after selection.
    pub profile: ProfileId,
}

/// A policy profile: filter set, canaries, rebind, forward-zone allow-list, …
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileConfig {
    /// Stable profile id.
    pub id: ProfileId,
    /// Active filter set (schedules may override later).
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyConfig {
    /// Default for profiles that omit [`ProfileConfig::rebind`].
    pub default_rebind: bool,
    /// Extra prefixes for ClientDirectory PTR answers (RFC 1918 / ULA / loopback always on).
    pub ptr_prefixes: Vec<IpNet>,
    /// Non-public suffixes synthesised as NXDOMAIN when unknown and not forwarded.
    pub local_nxdomain_suffixes: Vec<Arc<str>>,
    /// Forward zones whose answers still get rebind protection (default: none).
    pub rebind_check_forward_zones: Vec<ForwardZoneId>,
    /// Split-horizon views.
    pub views: Vec<ViewConfig>,
    /// Profiles referenced by views.
    pub profiles: Vec<ProfileConfig>,
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
        assert!(name_has_wildcard_label(
            &Name::from_ascii("*.example.com").unwrap()
        ));
        assert!(!name_has_wildcard_label(
            &Name::from_ascii("nas.lan.example.com").unwrap()
        ));
        let star_middle = Name::from_ascii("a.*.example.com").unwrap();
        assert!(name_has_wildcard_label(&star_middle));
    }

    #[test]
    fn config_view_record_rtype_from_rdata() {
        let rec = ViewRecordConfig {
            name: Name::from_ascii("nas.lan.example.com").unwrap(),
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 10)),
        };
        assert_eq!(rec.rtype(), RecordType::A);
    }
}
