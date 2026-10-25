//! Immutable, validated policy snapshot swapped on hot reload.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dnscraft_filtering::SetId;
use dnscraft_proto::{Class, Name, Record, RecordType};
use dnscraft_resolver::ForwardZoneId;
use ipnet::IpNet;

use crate::config::{
    PolicyConfig, ProfileConfig, SAFESEARCH_PROVIDERS, SCHEDULE_WEEK, SafeSearchConfig,
    ScheduleConfig, ViewConfig, ViewRecordConfig, is_allowed_view_rtype, name_has_wildcard_label,
};
use crate::error::{ConfigReason, PolicyError};
use crate::ids::{ClientId, ProfileId, ViewId};

/// Index of a view inside [`PolicySnapshot::views`].
pub type ViewIdx = u16;

/// Index of a profile inside [`PolicySnapshot::profiles`].
pub type ProfileIdx = u16;

/// Local records for one owner name inside a view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewRrSets {
    /// Records at this name (never mixes a CNAME with other types).
    pub(crate) records: Arc<[Record]>,
}

/// One validated view ready for selection and local answers.
#[derive(Clone, Debug)]
pub struct SnapshotView {
    /// View id.
    pub(crate) id: ViewId,
    /// Whether this is the catch-all default.
    #[allow(dead_code)] // read by later pipeline steps
    pub(crate) is_default: bool,
    /// Profile applied for this view.
    pub(crate) profile_idx: ProfileIdx,
    /// Exact-name local records.
    pub(crate) records: HashMap<Name, ViewRrSets>,
}

/// A pre-parsed `rebind_exceptions` entry (built once at snapshot load).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RebindException {
    /// Exact owner match.
    Exact(Name),
    /// Suffix match (`*.zone`): `zone.zone_of(qname)`.
    Suffix(Name),
}

/// One validated profile.
#[derive(Clone, Debug)]
pub struct SnapshotProfile {
    /// Profile id.
    pub(crate) id: ProfileId,
    /// Source config (filter set, canaries, rebind, …).
    pub(crate) config: ProfileConfig,
    /// Parsed [`ProfileConfig::rebind_exceptions`] for the hot path.
    pub(crate) rebind_exceptions: Arc<[RebindException]>,
}

/// Per-prefix-length table: masked address → view index.
#[derive(Clone, Debug, Default)]
pub struct PrefixTable<A: Eq + std::hash::Hash> {
    /// Prefix length → map of masked network address to view.
    pub(crate) by_len: HashMap<u8, HashMap<A, ViewIdx>>,
    /// Present lengths, sorted descending (longest first).
    pub(crate) lengths_desc: Vec<u8>,
}

impl<A: Eq + std::hash::Hash + Copy> PrefixTable<A> {
    fn insert(&mut self, len: u8, addr: A, view: ViewIdx) {
        self.by_len.entry(len).or_default().insert(addr, view);
    }

    fn finish(&mut self) {
        let mut lens: Vec<u8> = self.by_len.keys().copied().collect();
        lens.sort_unstable_by(|a, b| b.cmp(a));
        self.lengths_desc = lens;
    }
}

/// Validated policy configuration and selection indexes.
#[derive(Clone, Debug)]
pub struct PolicySnapshot {
    /// Top-level settings retained for the pipeline.
    #[allow(dead_code)] // read by later pipeline steps
    pub(crate) default_rebind: bool,
    /// Extra PTR prefixes (step 2).
    pub(crate) ptr_prefixes: Arc<[IpNet]>,
    /// Special-use NXDOMAIN suffixes (step 2).
    pub(crate) local_nxdomain_suffixes: Arc<[Arc<str>]>,
    /// Forward zones that still receive rebind checks.
    #[allow(dead_code)] // read by later pipeline steps
    pub(crate) rebind_check_forward_zones: Arc<[ForwardZoneId]>,
    /// Views in config order.
    pub(crate) views: Arc<[SnapshotView]>,
    /// Profiles in config order.
    pub(crate) profiles: Arc<[SnapshotProfile]>,
    /// Index of the default view.
    pub(crate) default_view: ViewIdx,
    /// Client ID → view (exact match).
    pub(crate) client_ids: HashMap<ClientId, ViewIdx>,
    /// IPv4 subnet tables keyed by prefix length.
    pub(crate) v4: PrefixTable<[u8; 4]>,
    /// IPv6 subnet tables keyed by prefix length.
    pub(crate) v6: PrefixTable<[u8; 16]>,
}

impl PolicySnapshot {
    /// Builds and validates a snapshot.
    ///
    /// `known_sets` are filter-set ids that exist in the filter engine.
    /// `known_zones` are forward-zone ids that exist in the resolver.
    pub fn build(
        config: PolicyConfig,
        known_sets: &[SetId],
        known_zones: &[ForwardZoneId],
    ) -> Result<Self, PolicyError> {
        let known_set: HashSet<&str> = known_sets.iter().map(|s| s.as_str()).collect();
        let known_zone: HashSet<&str> = known_zones.iter().map(|z| z.as_str()).collect();

        for zone in &config.rebind_check_forward_zones {
            if !known_zone.contains(zone.as_str()) {
                return Err(PolicyError::UnknownForwardZone { id: zone.clone() });
            }
        }

        let mut profile_by_id: HashMap<ProfileId, ProfileIdx> = HashMap::new();
        let mut profiles: Vec<SnapshotProfile> = Vec::with_capacity(config.profiles.len());
        for profile in config.profiles {
            if profile_by_id.contains_key(&profile.id) {
                return Err(PolicyError::InvalidConfig {
                    reason: ConfigReason::DuplicateProfileId {
                        id: Arc::from(profile.id.as_str()),
                    },
                });
            }
            if !known_set.contains(profile.filter_set.as_str()) {
                return Err(PolicyError::UnknownFilterSet {
                    id: profile.filter_set.clone(),
                });
            }
            if let Some(zones) = &profile.forward_zones {
                for zone in zones {
                    if !known_zone.contains(zone.as_str()) {
                        return Err(PolicyError::UnknownForwardZone { id: zone.clone() });
                    }
                }
            }
            let rebind_exceptions = parse_rebind_exceptions(&profile.rebind_exceptions)?;
            validate_schedules(&profile.schedules, &known_set)?;
            let mut profile = profile;
            let safesearch = std::mem::take(&mut profile.safesearch);
            profile.safesearch = validate_safesearch(safesearch)?;
            let idx = ProfileIdx::try_from(profiles.len()).map_err(|_| PolicyError::Internal {
                message: Arc::from("too many profiles"),
            })?;
            profile_by_id.insert(profile.id.clone(), idx);
            profiles.push(SnapshotProfile {
                id: profile.id.clone(),
                config: profile,
                rebind_exceptions,
            });
        }

        let mut view_by_id: HashMap<ViewId, ViewIdx> = HashMap::new();
        let mut client_ids: HashMap<ClientId, ViewIdx> = HashMap::new();
        let mut v4 = PrefixTable::default();
        let mut v6 = PrefixTable::default();
        let mut subnet_owner: HashMap<IpNet, ViewIdx> = HashMap::new();
        let mut views: Vec<SnapshotView> = Vec::with_capacity(config.views.len());
        let mut default_view: Option<ViewIdx> = None;

        for view in config.views {
            if view_by_id.contains_key(&view.id) {
                return Err(PolicyError::InvalidConfig {
                    reason: ConfigReason::DuplicateViewId {
                        id: Arc::from(view.id.as_str()),
                    },
                });
            }
            let Some(&profile_idx) = profile_by_id.get(&view.profile) else {
                return Err(PolicyError::InvalidConfig {
                    reason: ConfigReason::UnknownProfile {
                        id: Arc::from(view.profile.as_str()),
                    },
                });
            };

            let view_idx = ViewIdx::try_from(views.len()).map_err(|_| PolicyError::Internal {
                message: Arc::from("too many views"),
            })?;

            if view.is_default {
                if default_view.is_some() {
                    return Err(PolicyError::InvalidConfig {
                        reason: ConfigReason::MultipleDefaultViews,
                    });
                }
                default_view = Some(view_idx);
            }

            for client_id in &view.client_ids {
                if client_ids.contains_key(client_id) {
                    return Err(PolicyError::InvalidConfig {
                        reason: ConfigReason::DuplicateClientId {
                            id: Arc::from(client_id.as_str()),
                        },
                    });
                }
                client_ids.insert(client_id.clone(), view_idx);
            }

            for net in &view.subnets {
                let masked = net.trunc();
                match subnet_owner.get(&masked) {
                    Some(&owner) if owner != view_idx => {
                        return Err(PolicyError::InvalidConfig {
                            reason: ConfigReason::DuplicateSubnet { net: masked },
                        });
                    }
                    _ => {
                        subnet_owner.insert(masked, view_idx);
                    }
                }
                match net {
                    IpNet::V4(n) => {
                        v4.insert(n.prefix_len(), n.network().octets(), view_idx);
                    }
                    IpNet::V6(n) => {
                        v6.insert(n.prefix_len(), n.network().octets(), view_idx);
                    }
                }
            }

            let records = build_view_records(&view)?;
            view_by_id.insert(view.id.clone(), view_idx);
            views.push(SnapshotView {
                id: view.id,
                is_default: view.is_default,
                profile_idx,
                records,
            });
        }

        let Some(default_view) = default_view else {
            return Err(PolicyError::InvalidConfig {
                reason: ConfigReason::NoDefaultView,
            });
        };

        v4.finish();
        v6.finish();

        Ok(Self {
            default_rebind: config.default_rebind,
            ptr_prefixes: Arc::from(config.ptr_prefixes),
            local_nxdomain_suffixes: Arc::from(config.local_nxdomain_suffixes),
            rebind_check_forward_zones: Arc::from(config.rebind_check_forward_zones),
            views: Arc::from(views),
            profiles: Arc::from(profiles),
            default_view,
            client_ids,
            v4,
            v6,
        })
    }

    /// Profile for a view index.
    pub fn profile_for_view(&self, view: ViewIdx) -> &SnapshotProfile {
        let idx = self.views[usize::from(view)].profile_idx;
        &self.profiles[usize::from(idx)]
    }
}

/// Parses `domain` / `*.domain` exceptions; rejects anything else with a
/// stable [`ConfigReason::InvalidRebindException`] code via [`PolicyError`].
fn parse_rebind_exceptions(patterns: &[Arc<str>]) -> Result<Arc<[RebindException]>, PolicyError> {
    let mut out = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        let parsed = if let Some(suffix) = pattern.strip_prefix("*.") {
            if suffix.is_empty() || suffix.contains('*') {
                None
            } else {
                Name::from_ascii(suffix).ok().map(RebindException::Suffix)
            }
        } else if pattern.is_empty() || pattern.contains('*') {
            None
        } else {
            Name::from_ascii(pattern.as_ref())
                .ok()
                .map(RebindException::Exact)
        };
        let Some(ex) = parsed else {
            return Err(PolicyError::InvalidConfig {
                reason: ConfigReason::InvalidRebindException {
                    pattern: pattern.clone(),
                },
            });
        };
        out.push(ex);
    }
    Ok(Arc::from(out))
}

fn validate_schedules(
    schedules: &[ScheduleConfig],
    known_set: &HashSet<&str>,
) -> Result<(), PolicyError> {
    let mut seen: HashSet<&str> = HashSet::new();
    for schedule in schedules {
        // Same charset as profile/view ids: `[a-z0-9-]{1,64}`.
        if ProfileId::new(schedule.id.as_ref()).is_err() {
            return Err(PolicyError::InvalidConfig {
                reason: ConfigReason::InvalidScheduleId {
                    id: schedule.id.clone(),
                },
            });
        }
        if !seen.insert(schedule.id.as_ref()) {
            return Err(PolicyError::InvalidConfig {
                reason: ConfigReason::DuplicateScheduleId {
                    id: schedule.id.clone(),
                },
            });
        }
        if !known_set.contains(schedule.filter_set.as_str()) {
            return Err(PolicyError::UnknownFilterSet {
                id: schedule.filter_set.clone(),
            });
        }
        if schedule.start >= schedule.end {
            return Err(PolicyError::InvalidConfig {
                reason: ConfigReason::ScheduleWindowOrder {
                    id: schedule.id.clone(),
                },
            });
        }
        if schedule.end > SCHEDULE_WEEK {
            return Err(PolicyError::InvalidConfig {
                reason: ConfigReason::ScheduleWindowTooLong {
                    id: schedule.id.clone(),
                },
            });
        }
    }
    Ok(())
}

fn validate_safesearch(mut cfg: SafeSearchConfig) -> Result<SafeSearchConfig, PolicyError> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut normalised = Vec::with_capacity(cfg.providers.len());
    for raw in cfg.providers.drain(..) {
        let lower = raw.to_ascii_lowercase();
        if !SAFESEARCH_PROVIDERS.contains(&lower.as_str()) {
            return Err(PolicyError::InvalidConfig {
                reason: ConfigReason::UnknownSafeSearchProvider { name: raw },
            });
        }
        if !seen.insert(lower.clone()) {
            return Err(PolicyError::InvalidConfig {
                reason: ConfigReason::DuplicateSafeSearchProvider {
                    name: Arc::from(lower),
                },
            });
        }
        normalised.push(Arc::<str>::from(lower));
    }
    cfg.providers = normalised;
    Ok(cfg)
}

fn build_view_records(view: &ViewConfig) -> Result<HashMap<Name, ViewRrSets>, PolicyError> {
    let mut by_name: HashMap<Name, Vec<ViewRecordConfig>> = HashMap::new();
    for rec in &view.records {
        if name_has_wildcard_label(&rec.name) {
            return Err(PolicyError::InvalidConfig {
                reason: ConfigReason::WildcardOwner,
            });
        }
        if !is_allowed_view_rtype(rec.rtype()) {
            return Err(PolicyError::InvalidConfig {
                reason: ConfigReason::UnsupportedRecordType,
            });
        }
        by_name
            .entry(rec.name.clone())
            .or_default()
            .push(rec.clone());
    }

    let mut out = HashMap::with_capacity(by_name.len());
    for (name, recs) in by_name {
        let has_cname = recs.iter().any(|r| r.rtype() == RecordType::CNAME);
        if has_cname && recs.len() > 1 {
            return Err(PolicyError::CnameConflict { name });
        }
        let mut deduped: Vec<ViewRecordConfig> = Vec::with_capacity(recs.len());
        for r in recs {
            if deduped
                .iter()
                .any(|d| d.rtype() == r.rtype() && d.ttl != r.ttl)
            {
                return Err(PolicyError::InvalidConfig {
                    reason: ConfigReason::RrsetTtlMismatch { name },
                });
            }
            if !deduped.iter().any(|d| d.rdata == r.rdata) {
                deduped.push(r);
            }
        }
        let records: Arc<[Record]> = deduped
            .into_iter()
            .map(|r| Record::new(r.name, Class::IN, r.ttl, r.rdata))
            .collect::<Vec<_>>()
            .into();
        out.insert(name, ViewRrSets { records });
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::{
        DEFAULT_LOCAL_NXDOMAIN_SUFFIXES, ProfileConfig, SCHEDULE_WEEK, SafeSearchConfig,
        ViewConfig, ViewRecordConfig,
    };
    use crate::ids::{ClientId, ProfileId, ViewId};
    use dnscraft_proto::{Name, RData};
    use ipnet::IpNet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    fn doc_v4() -> IpNet {
        IpNet::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).unwrap()
    }

    fn doc_v6() -> IpNet {
        IpNet::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0)),
            64,
        )
        .unwrap()
    }

    fn set(id: &str) -> SetId {
        SetId::new(id).unwrap()
    }

    fn zone(id: &str) -> ForwardZoneId {
        ForwardZoneId::new(id).unwrap()
    }

    fn profile(id: &str, filter_set: &str) -> ProfileConfig {
        ProfileConfig {
            id: ProfileId::new(id).unwrap(),
            filter_set: set(filter_set),
            suppress_aaaa: false,
            firefox_canary: true,
            icloud_private_relay: true,
            rebind: Some(true),
            rebind_exceptions: vec![Arc::from("*.example.com")],
            forward_zones: None,
            safesearch: SafeSearchConfig::default(),
            schedules: Vec::new(),
        }
    }

    fn default_view(profile: &str) -> ViewConfig {
        ViewConfig {
            id: ViewId::new("default").unwrap(),
            is_default: true,
            subnets: Vec::new(),
            client_ids: Vec::new(),
            records: Vec::new(),
            profile: ProfileId::new(profile).unwrap(),
        }
    }

    fn lan_view(profile: &str) -> ViewConfig {
        ViewConfig {
            id: ViewId::new("lan").unwrap(),
            is_default: false,
            subnets: vec![doc_v4(), doc_v6()],
            client_ids: Vec::new(),
            records: vec![ViewRecordConfig {
                name: Name::from_ascii("nas.lan.example.com").unwrap(),
                ttl: 60,
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, 10)),
            }],
            profile: ProfileId::new(profile).unwrap(),
        }
    }

    /// Spec TOML excerpt as Rust values — must validate.
    fn spec_excerpt_config() -> PolicyConfig {
        PolicyConfig {
            default_rebind: true,
            ptr_prefixes: Vec::new(),
            local_nxdomain_suffixes: DEFAULT_LOCAL_NXDOMAIN_SUFFIXES
                .iter()
                .map(|s| Arc::<str>::from(*s))
                .collect(),
            rebind_check_forward_zones: Vec::new(),
            views: vec![lan_view("default"), default_view("default")],
            profiles: vec![profile("default", "default")],
        }
    }

    #[test]
    fn config_accepts_spec_toml_excerpt() {
        let snap = PolicySnapshot::build(spec_excerpt_config(), &[set("default")], &[]).unwrap();
        assert_eq!(snap.views.len(), 2);
        assert_eq!(snap.default_view, 1);
        assert_eq!(snap.views[0].id.as_str(), "lan");
        assert!(
            snap.views[0]
                .records
                .contains_key(&Name::from_ascii("nas.lan.example.com").unwrap())
        );
        assert_eq!(snap.v4.lengths_desc, vec![24]);
        assert_eq!(snap.v6.lengths_desc, vec![64]);
        assert_eq!(
            snap.local_nxdomain_suffixes.as_ref(),
            &[
                Arc::<str>::from("local"),
                Arc::from("lan"),
                Arc::from("internal")
            ]
        );
    }

    #[test]
    fn config_rejects_no_default_view() {
        let mut cfg = spec_excerpt_config();
        cfg.views.retain(|v| !v.is_default);
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.invalid");
        assert!(matches!(
            err,
            PolicyError::InvalidConfig {
                reason: ConfigReason::NoDefaultView
            }
        ));
    }

    #[test]
    fn config_rejects_multiple_default_views() {
        let mut cfg = spec_excerpt_config();
        cfg.views[0].is_default = true;
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.invalid");
    }

    #[test]
    fn config_rejects_client_id_on_two_views() {
        let mut cfg = spec_excerpt_config();
        let id = ClientId::new("iphone-k7q2x9").unwrap();
        cfg.views[0].client_ids.push(id.clone());
        cfg.views[1].client_ids.push(id);
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.invalid");
        assert!(matches!(
            err,
            PolicyError::InvalidConfig {
                reason: ConfigReason::DuplicateClientId { .. }
            }
        ));
    }

    #[test]
    fn config_rejects_unknown_filter_set() {
        let cfg = spec_excerpt_config();
        let err = PolicySnapshot::build(cfg, &[], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.unknown_filter_set");
    }

    #[test]
    fn config_rejects_unknown_forward_zone_on_profile() {
        let mut cfg = spec_excerpt_config();
        cfg.profiles[0].forward_zones = Some(vec![zone("vpn-site-a")]);
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.unknown_forward_zone");
    }

    #[test]
    fn config_rejects_unknown_rebind_check_forward_zone() {
        let mut cfg = spec_excerpt_config();
        cfg.rebind_check_forward_zones = vec![zone("vpn-site-a")];
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.unknown_forward_zone");
    }

    #[test]
    fn config_accepts_known_forward_zone_allow_list() {
        let mut cfg = spec_excerpt_config();
        cfg.profiles[0].forward_zones = Some(vec![zone("vpn-site-a")]);
        cfg.rebind_check_forward_zones = vec![zone("vpn-site-a")];
        PolicySnapshot::build(cfg, &[set("default")], &[zone("vpn-site-a")]).unwrap();
    }

    #[test]
    fn config_rejects_cname_beside_other_types() {
        let mut cfg = spec_excerpt_config();
        let name = Name::from_ascii("alias.example.com").unwrap();
        cfg.views[0].records.push(ViewRecordConfig {
            name: name.clone(),
            ttl: 60,
            rdata: RData::CNAME(Name::from_ascii("nas.lan.example.com").unwrap()),
        });
        cfg.views[0].records.push(ViewRecordConfig {
            name,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 11)),
        });
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.record.cname_conflict");
    }

    #[test]
    fn config_rejects_unsupported_record_type() {
        let mut cfg = spec_excerpt_config();
        cfg.views[0].records.push(ViewRecordConfig {
            name: Name::from_ascii("ns.example.com").unwrap(),
            ttl: 60,
            rdata: RData::NS(Name::from_ascii("a.example.com").unwrap()),
        });
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.invalid");
        assert!(matches!(
            err,
            PolicyError::InvalidConfig {
                reason: ConfigReason::UnsupportedRecordType
            }
        ));
    }

    #[test]
    fn config_rejects_wildcard_owner() {
        let mut cfg = spec_excerpt_config();
        cfg.views[0].records.push(ViewRecordConfig {
            name: Name::from_ascii("*.example.com").unwrap(),
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 99)),
        });
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.invalid");
        assert!(matches!(
            err,
            PolicyError::InvalidConfig {
                reason: ConfigReason::WildcardOwner
            }
        ));
    }

    #[test]
    fn config_rejects_unknown_profile() {
        let mut cfg = spec_excerpt_config();
        cfg.views[0].profile = ProfileId::new("missing").unwrap();
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.invalid");
    }

    #[test]
    fn config_rejects_same_subnet_on_two_views_v4() {
        let mut cfg = spec_excerpt_config();
        // lan already has 192.0.2.0/24; the unmasked host form must conflict.
        cfg.views[1].subnets =
            vec![IpNet::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77)), 24).unwrap()];
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.invalid");
        assert!(matches!(
            err,
            PolicyError::InvalidConfig {
                reason: ConfigReason::DuplicateSubnet { net }
            } if net == doc_v4()
        ));
    }

    #[test]
    fn config_rejects_same_subnet_on_two_views_v6() {
        let mut cfg = spec_excerpt_config();
        cfg.views[1].subnets = vec![
            IpNet::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 5)),
                64,
            )
            .unwrap(),
        ];
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert!(matches!(
            err,
            PolicyError::InvalidConfig {
                reason: ConfigReason::DuplicateSubnet { net }
            } if net == doc_v6()
        ));
    }

    #[test]
    fn config_accepts_same_subnet_repeated_in_one_view() {
        let mut cfg = spec_excerpt_config();
        cfg.views[0].subnets = vec![doc_v4(), doc_v4(), doc_v6(), doc_v6()];
        PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap();
    }

    #[test]
    fn config_rejects_duplicate_view_id() {
        let mut cfg = spec_excerpt_config();
        cfg.views[1].id = ViewId::new("lan").unwrap();
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert!(matches!(
            err,
            PolicyError::InvalidConfig {
                reason: ConfigReason::DuplicateViewId { .. }
            }
        ));
    }

    #[test]
    fn config_rejects_duplicate_profile_id() {
        let mut cfg = spec_excerpt_config();
        cfg.profiles.push(profile("default", "default"));
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert!(matches!(
            err,
            PolicyError::InvalidConfig {
                reason: ConfigReason::DuplicateProfileId { .. }
            }
        ));
    }

    #[test]
    fn config_rejects_unknown_schedule_filter_set() {
        let mut cfg = spec_excerpt_config();
        cfg.profiles[0].schedules = vec![crate::config::ScheduleConfig {
            id: Arc::from("night"),
            filter_set: set("night"),
            start: std::time::Duration::from_secs(0),
            end: std::time::Duration::from_secs(3600),
        }];
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.unknown_filter_set");
    }

    #[test]
    fn config_accepts_valid_schedule_and_safesearch() {
        let mut cfg = spec_excerpt_config();
        cfg.profiles[0].schedules = vec![crate::config::ScheduleConfig {
            id: Arc::from("evening"),
            filter_set: set("default"),
            start: std::time::Duration::from_secs(18 * 3600),
            end: std::time::Duration::from_secs(22 * 3600),
        }];
        cfg.profiles[0].safesearch = SafeSearchConfig {
            enabled: true,
            providers: vec![Arc::from("Google"), Arc::from("BING")],
        };
        let snap = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap();
        assert_eq!(
            snap.profiles[0].config.safesearch.providers.as_slice(),
            &[Arc::from("google"), Arc::from("bing")]
        );
    }

    #[test]
    fn config_rejects_schedule_window_order() {
        let mut cfg = spec_excerpt_config();
        cfg.profiles[0].schedules = vec![crate::config::ScheduleConfig {
            id: Arc::from("bad"),
            filter_set: set("default"),
            start: std::time::Duration::from_secs(10),
            end: std::time::Duration::from_secs(10),
        }];
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.schedule_window");
    }

    #[test]
    fn config_rejects_schedule_window_too_long() {
        let mut cfg = spec_excerpt_config();
        cfg.profiles[0].schedules = vec![crate::config::ScheduleConfig {
            id: Arc::from("week"),
            filter_set: set("default"),
            start: std::time::Duration::ZERO,
            end: SCHEDULE_WEEK + std::time::Duration::from_secs(1),
        }];
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.schedule_window");
    }

    #[test]
    fn config_rejects_duplicate_schedule_id() {
        let mut cfg = spec_excerpt_config();
        let s = |id: &str| crate::config::ScheduleConfig {
            id: Arc::from(id),
            filter_set: set("default"),
            start: std::time::Duration::ZERO,
            end: std::time::Duration::from_secs(60),
        };
        cfg.profiles[0].schedules = vec![s("dup"), s("dup")];
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.duplicate_schedule_id");
    }

    #[test]
    fn config_rejects_invalid_schedule_id() {
        let mut cfg = spec_excerpt_config();
        cfg.profiles[0].schedules = vec![crate::config::ScheduleConfig {
            id: Arc::from("Bad_Id"),
            filter_set: set("default"),
            start: std::time::Duration::ZERO,
            end: std::time::Duration::from_secs(60),
        }];
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.invalid_schedule_id");
    }

    #[test]
    fn config_rejects_unknown_safesearch_provider() {
        let mut cfg = spec_excerpt_config();
        cfg.profiles[0].safesearch = SafeSearchConfig {
            enabled: true,
            providers: vec![Arc::from("yahoo")],
        };
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.unknown_safesearch_provider");
    }

    #[test]
    fn config_rejects_duplicate_safesearch_provider() {
        let mut cfg = spec_excerpt_config();
        cfg.profiles[0].safesearch = SafeSearchConfig {
            enabled: true,
            providers: vec![Arc::from("google"), Arc::from("GOOGLE")],
        };
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.duplicate_safesearch_provider");
    }

    #[test]
    fn config_accepts_single_cname() {
        let mut cfg = spec_excerpt_config();
        let name = Name::from_ascii("alias.example.com").unwrap();
        cfg.views[0].records.push(ViewRecordConfig {
            name: name.clone(),
            ttl: 60,
            rdata: RData::CNAME(Name::from_ascii("nas.lan.example.com").unwrap()),
        });
        let snap = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap();
        let sets = snap.views[0].records.get(&name).unwrap();
        assert_eq!(sets.records.len(), 1);
    }

    #[test]
    fn config_collapses_exact_duplicate_records() {
        let mut cfg = spec_excerpt_config();
        for owner in ["x.example", "X.example"] {
            cfg.views[0].records.push(ViewRecordConfig {
                name: Name::from_ascii(owner).unwrap(),
                ttl: 60,
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, 50)),
            });
        }
        let snap = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap();
        let sets = snap.views[0]
            .records
            .get(&Name::from_ascii("x.example").unwrap())
            .unwrap();
        assert_eq!(sets.records.len(), 1);
    }

    #[test]
    fn config_rejects_rrset_ttl_mismatch() {
        let mut cfg = spec_excerpt_config();
        for (ttl, last) in [(60, 50), (120, 51)] {
            cfg.views[0].records.push(ViewRecordConfig {
                name: Name::from_ascii("x.example").unwrap(),
                ttl,
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, last)),
            });
        }
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert_eq!(err.code(), "policy.config.invalid");
        assert!(matches!(
            err,
            PolicyError::InvalidConfig {
                reason: ConfigReason::RrsetTtlMismatch { .. }
            }
        ));
    }

    #[test]
    fn config_rejects_ttl_mismatch_on_identical_records() {
        let mut cfg = spec_excerpt_config();
        for ttl in [60, 3600] {
            cfg.views[0].records.push(ViewRecordConfig {
                name: Name::from_ascii("x.example").unwrap(),
                ttl,
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, 50)),
            });
        }
        let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
        assert!(matches!(
            err,
            PolicyError::InvalidConfig {
                reason: ConfigReason::RrsetTtlMismatch { .. }
            }
        ));
    }

    #[test]
    fn config_accepts_valid_rebind_exceptions() {
        let mut cfg = spec_excerpt_config();
        cfg.profiles[0].rebind_exceptions =
            vec![Arc::from("*.example.com"), Arc::from("nas.example.com")];
        PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap();
    }

    #[test]
    fn config_rejects_invalid_rebind_exceptions() {
        for bad in ["**bad", "*.", "a.*.b", "", "*example.com"] {
            let mut cfg = spec_excerpt_config();
            cfg.profiles[0].rebind_exceptions = vec![Arc::from(bad)];
            let err = PolicySnapshot::build(cfg, &[set("default")], &[]).unwrap_err();
            assert_eq!(err.code(), "policy.config.invalid", "{bad:?}");
            assert!(
                matches!(
                    err,
                    PolicyError::InvalidConfig {
                        reason: ConfigReason::InvalidRebindException { .. }
                    }
                ),
                "{bad:?}"
            );
        }
    }
}
