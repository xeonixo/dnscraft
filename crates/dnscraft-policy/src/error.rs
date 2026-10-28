//! Error types with stable, locale-neutral codes.
//!
//! Every error exposes a `code()` of the form `area.reason` for APIs and i18n.
//! Human-readable text is for logs, not for end users.
//!
//! ## `IdError` codes
//!
//! | Variant | Code |
//! |---|---|
//! | [`IdError::Empty`] | `policy.id.empty` |
//! | [`IdError::TooLong`] | `policy.id.too_long` |
//! | [`IdError::InvalidChar`] | `policy.id.invalid_char` |
//!
//! ## `PolicyError` codes
//!
//! | Variant | Code |
//! |---|---|
//! | [`PolicyError::InvalidConfig`] | `policy.config.invalid` |
//! | [`PolicyError::UnknownFilterSet`] | `policy.config.unknown_filter_set` |
//! | [`PolicyError::UnknownForwardZone`] | `policy.config.unknown_forward_zone` |
//! | [`PolicyError::CnameConflict`] | `policy.record.cname_conflict` |
//! | [`PolicyError::NoView`] | `policy.selection.no_view` |
//! | [`PolicyError::Resolve`] | `policy.resolve` |
//! | [`PolicyError::Internal`] | `policy.internal` |

use std::sync::Arc;

use dnscraft_filtering::SetId;
use dnscraft_proto::Name;
use dnscraft_resolver::ForwardZoneId;

/// A view, profile, listener or client id was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]

pub enum IdError {
    /// The id is empty.
    #[error("id is empty")]
    Empty,
    /// The id is longer than the allowed maximum.
    #[error("id is {len} characters long, maximum is {max}")]
    TooLong {
        /// Length of the id.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// A character outside the allowed charset.
    #[error("invalid character {ch:?} in id")]
    InvalidChar {
        /// The offending character.
        ch: char,
    },
}

impl IdError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "policy.id.empty",
            Self::TooLong { .. } => "policy.id.too_long",
            Self::InvalidChar { .. } => "policy.id.invalid_char",
        }
    }
}

/// Why a policy configuration was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]

pub enum ConfigReason {
    /// No view is marked as the default catch-all.
    #[error("exactly one default view is required")]
    NoDefaultView,
    /// More than one view is marked as default.
    #[error("more than one default view")]
    MultipleDefaultViews,
    /// The Client-ID registry lists the same Client ID twice.
    #[error("client id {id} is listed more than once")]
    DuplicateClientId {
        /// The duplicated Client ID.
        id: Arc<str>,
    },
    /// A Client-ID label or device reference is malformed.
    #[error("client id {id}: {field} {reason}")]
    InvalidClientMeta {
        /// The Client ID the field belongs to.
        id: Arc<str>,
        /// `label` or `device`.
        field: &'static str,
        /// Why the value was rejected.
        reason: &'static str,
    },
    /// Two Client IDs share a label (compared case-insensitively).
    #[error("client label {label} is used more than once")]
    DuplicateClientLabel {
        /// The duplicated label (trimmed).
        label: Arc<str>,
    },
    /// The default view is restricted to some nodes; it must exist on every node.
    #[error("the default view must not restrict nodes")]
    DefaultViewNodes,
    /// A record override names a view that is not defined.
    #[error("record override references unknown view {id}")]
    UnknownOverrideView {
        /// The missing view id.
        id: Arc<str>,
    },
    /// Two views share an id.
    #[error("duplicate view id {id}")]
    DuplicateViewId {
        /// The duplicated view id.
        id: Arc<str>,
    },
    /// Two profiles share an id.
    #[error("duplicate profile id {id}")]
    DuplicateProfileId {
        /// The duplicated profile id.
        id: Arc<str>,
    },
    /// A view points at a profile that is not defined.
    #[error("view references unknown profile {id}")]
    UnknownProfile {
        /// The missing profile id.
        id: Arc<str>,
    },
    /// A view record uses a type outside A/AAAA/CNAME/TXT/SRV/MX/PTR.
    #[error("unsupported record type for view local records")]
    UnsupportedRecordType,
    /// A view record owner has an invalid wildcard (embedded `*`, or bare `*`).
    #[error(
        "wildcard owner must be a single leading * label (e.g. *.example.com)"
    )]
    WildcardOwner,
    /// The same subnet (same network address and prefix length) is listed on two views.
    #[error("subnet {net} is listed on more than one view")]
    DuplicateSubnet {
        /// The duplicated subnet, masked to its network address.
        net: ipnet::IpNet,
    },
    /// Records at one owner name and type carry different TTLs (RFC 2181 section 5.2).
    #[error("records at {name} with the same type have different TTLs")]
    RrsetTtlMismatch {
        /// Owner name of the inconsistent RRset.
        name: Name,
    },
    /// A rebind exception is neither a domain name nor `*.` plus a domain name.
    #[error("invalid rebind exception {pattern:?}")]
    InvalidRebindException {
        /// The rejected pattern.
        pattern: Arc<str>,
    },
    /// [`PauseUntil::For`](crate::PauseUntil::For) was called with a zero duration.
    #[error("pause duration must be greater than zero")]
    ZeroPauseDuration,
    /// A schedule window has `start >= end`.
    #[error("schedule {id} has start >= end")]
    ScheduleWindowOrder {
        /// Schedule id.
        id: Arc<str>,
    },
    /// A schedule window ends after seven days from Monday 00:00 UTC.
    #[error("schedule {id} ends after 7 days")]
    ScheduleWindowTooLong {
        /// Schedule id.
        id: Arc<str>,
    },
    /// Two schedules on one profile share an id.
    #[error("duplicate schedule id {id}")]
    DuplicateScheduleId {
        /// The duplicated schedule id.
        id: Arc<str>,
    },
    /// A schedule id failed the `[a-z0-9-]{1,64}` charset check.
    #[error("invalid schedule id {id}")]
    InvalidScheduleId {
        /// The rejected schedule id.
        id: Arc<str>,
    },
    /// A SafeSearch provider is not in the known list.
    #[error("unknown SafeSearch provider {name}")]
    UnknownSafeSearchProvider {
        /// The rejected provider name.
        name: Arc<str>,
    },
    /// The same SafeSearch provider appears twice on one profile.
    #[error("duplicate SafeSearch provider {name}")]
    DuplicateSafeSearchProvider {
        /// The duplicated provider.
        name: Arc<str>,
    },
    /// Two schedule windows on one profile overlap in time.
    #[error("schedule windows {id_a} and {id_b} overlap")]
    OverlappingScheduleWindows {
        /// First overlapping schedule id.
        id_a: Arc<str>,
        /// Second overlapping schedule id.
        id_b: Arc<str>,
    },
}

impl ConfigReason {
    /// Stable, locale-neutral code for APIs / i18n.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ZeroPauseDuration => "policy.config.invalid",
            Self::ScheduleWindowOrder { .. } => "policy.config.schedule_window",
            Self::ScheduleWindowTooLong { .. } => "policy.config.schedule_window",
            Self::DuplicateScheduleId { .. } => "policy.config.duplicate_schedule_id",
            Self::InvalidScheduleId { .. } => "policy.config.invalid_schedule_id",
            Self::OverlappingScheduleWindows { .. } => "policy.config.overlapping_schedules",
            Self::UnknownSafeSearchProvider { .. } => "policy.config.unknown_safesearch_provider",
            Self::DuplicateSafeSearchProvider { .. } => {
                "policy.config.duplicate_safesearch_provider"
            }
            _ => "policy.config.invalid",
        }
    }
}

/// Errors from building or running the policy engine.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]

pub enum PolicyError {
    /// The configuration failed validation.
    #[error("invalid policy config: {reason}")]
    InvalidConfig {
        /// Detailed reason.
        reason: ConfigReason,
    },
    /// A profile (or schedule) references a filter set that does not exist.
    #[error("unknown filter set {id}")]
    UnknownFilterSet {
        /// The missing set id.
        id: SetId,
    },
    /// A forward-zone id is not present in the resolver configuration.
    #[error("unknown forward zone {id}")]
    UnknownForwardZone {
        /// The missing zone id.
        id: ForwardZoneId,
    },
    /// A CNAME coexists with other types at the same owner name.
    #[error("CNAME conflict at {name}")]
    CnameConflict {
        /// Owner name that carries both a CNAME and another type.
        name: Name,
    },
    /// Selection found no view (defensive; unreachable when a default exists).
    #[error("no view matched the request")]
    NoView,
    /// The resolver failed in a way that could not be turned into an answer.
    #[error("resolver error: {message}")]
    Resolve {
        /// Human-readable cause for logs.
        message: Arc<str>,
    },
    /// An internal invariant was violated.
    #[error("internal policy error: {message}")]
    Internal {
        /// Human-readable cause for logs.
        message: Arc<str>,
    },
}

impl PolicyError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { reason } => reason.code(),
            Self::UnknownFilterSet { .. } => "policy.config.unknown_filter_set",
            Self::UnknownForwardZone { .. } => "policy.config.unknown_forward_zone",
            Self::CnameConflict { .. } => "policy.record.cname_conflict",
            Self::NoView => "policy.selection.no_view",
            Self::Resolve { .. } => "policy.resolve",
            Self::Internal { .. } => "policy.internal",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use dnscraft_filtering::SetId;
    use dnscraft_proto::Name;
    use dnscraft_resolver::ForwardZoneId;

    #[test]
    fn policy_error_codes_are_unique_and_documented() {
        let samples: Vec<(&str, PolicyError)> = vec![
            (
                "policy.config.invalid",
                PolicyError::InvalidConfig {
                    reason: ConfigReason::NoDefaultView,
                },
            ),
            (
                "policy.config.unknown_filter_set",
                PolicyError::UnknownFilterSet {
                    id: SetId::new("default").unwrap(),
                },
            ),
            (
                "policy.config.unknown_forward_zone",
                PolicyError::UnknownForwardZone {
                    id: ForwardZoneId::new("vpn").unwrap(),
                },
            ),
            (
                "policy.record.cname_conflict",
                PolicyError::CnameConflict {
                    name: Name::from_ascii("nas.lan.example.com").unwrap(),
                },
            ),
            ("policy.selection.no_view", PolicyError::NoView),
            (
                "policy.resolve",
                PolicyError::Resolve {
                    message: Arc::from("timeout"),
                },
            ),
            (
                "policy.internal",
                PolicyError::Internal {
                    message: Arc::from("bug"),
                },
            ),
        ];
        let mut codes: Vec<&str> = samples.iter().map(|(c, _)| *c).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), samples.len());
        for (want, err) in &samples {
            assert_eq!(err.code(), *want);
        }
    }

    #[test]
    fn config_reason_stable_codes_are_unique() {
        let samples: Vec<(&str, ConfigReason)> = vec![
            ("policy.config.invalid", ConfigReason::NoDefaultView),
            (
                "policy.config.schedule_window",
                ConfigReason::ScheduleWindowOrder {
                    id: Arc::from("evening"),
                },
            ),
            (
                "policy.config.duplicate_schedule_id",
                ConfigReason::DuplicateScheduleId {
                    id: Arc::from("evening"),
                },
            ),
            (
                "policy.config.invalid_schedule_id",
                ConfigReason::InvalidScheduleId {
                    id: Arc::from("Bad"),
                },
            ),
            (
                "policy.config.overlapping_schedules",
                ConfigReason::OverlappingScheduleWindows {
                    id_a: Arc::from("a"),
                    id_b: Arc::from("b"),
                },
            ),
            (
                "policy.config.unknown_safesearch_provider",
                ConfigReason::UnknownSafeSearchProvider {
                    name: Arc::from("yahoo"),
                },
            ),
            (
                "policy.config.duplicate_safesearch_provider",
                ConfigReason::DuplicateSafeSearchProvider {
                    name: Arc::from("google"),
                },
            ),
        ];
        let mut codes: Vec<&str> = samples.iter().map(|(c, _)| *c).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), samples.len());
        for (want, reason) in &samples {
            assert_eq!(reason.code(), *want);
        }
        // Shared code for order vs too-long is intentional (same validation family).
        assert_eq!(
            ConfigReason::ScheduleWindowTooLong {
                id: Arc::from("evening"),
            }
            .code(),
            "policy.config.schedule_window"
        );
    }

    #[test]
    fn id_error_codes_are_unique() {
        let codes = [
            IdError::Empty.code(),
            IdError::TooLong { len: 64, max: 63 }.code(),
            IdError::InvalidChar { ch: '_' }.code(),
        ];
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
        assert_eq!(IdError::Empty.code(), "policy.id.empty");
        assert_eq!(
            IdError::TooLong { len: 64, max: 63 }.code(),
            "policy.id.too_long"
        );
        assert_eq!(
            IdError::InvalidChar { ch: 'A' }.code(),
            "policy.id.invalid_char"
        );
    }
}
