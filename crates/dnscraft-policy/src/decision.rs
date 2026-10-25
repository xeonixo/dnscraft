//! Decision record returned with every policy answer.

use dnscraft_filtering::{BlockMode, Reason};
use dnscraft_proto::Rcode;
use dnscraft_resolver::{AnswerSource, DnssecStatus, ForwardZoneId};

use crate::ids::{ClientId, ProfileId, ViewId};
use crate::select::SelectionCause;

/// Which pause protection scope suppressed filtering for this query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProtectionPauseScope {
    /// [`PauseScope::Global`](crate::PauseScope::Global) was active.
    Global,
    /// A per-profile pause was active (and global was not).
    Profile,
}

/// Why step 10 (rebind) did not strip addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RebindSkipReason {
    /// Profile rebind flag is off (or default is off).
    Disabled,
    /// Qname matched a `rebind_exceptions` pattern.
    Exception,
    /// Answer came via a forward zone not listed in `rebind_check_forward_zones`.
    ForwardZoneExempt,
}

/// Where the final answer came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AnswerOrigin {
    /// Iterative or forwarded recursion.
    Resolver,
    /// Minimal RFC 8482 answer for qtype ANY.
    SynthAny,
    /// SERVFAIL synthesised after a resolver failure.
    ResolveError,
    /// View local records.
    LocalView,
    /// ClientDirectory name, PTR, or special-use NXDOMAIN.
    LocalClient,
    /// Bypass / canary (Firefox DoH, iCloud Private Relay).
    Bypass,
    /// Filter block or rewrite synthesis.
    Filter,
}

/// One breadcrumb from the pipeline, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecisionStep {
    /// View/profile selection finished.
    Selected {
        /// Which selection rule matched.
        cause: SelectionCause,
    },
    /// RFC 8482 ANY answer; resolver was not called.
    AnySynth,
    /// Answered from the selected view's local records.
    LocalView,
    /// Answered from the ClientDirectory (forward name or PTR).
    LocalClient,
    /// Special-use suffix NXDOMAIN (unknown name, no covering forward zone).
    SpecialUseNxdomain,
    /// Bypass / canary answer (profile flag on).
    Bypass,
    /// User-facing pause suppressed filter steps 4 / 6 / 8 / 9 for this query.
    ///
    /// Recorded at most once per query (not once per skipped step).
    ProtectionPaused {
        /// Global vs per-profile pause that was active.
        scope: ProtectionPauseScope,
    },
    /// Filter blocked the qname (or a CNAME-rewrite target).
    FilterBlocked,
    /// Filter rewrote the answer (records or rcode).
    FilterRewrite,
    /// Name could not be converted for filtering; treated as Pass.
    FilterSkipped {
        /// Why filtering was skipped.
        reason: &'static str,
    },
    /// CNAME-chain uncloaking blocked a name in the resolver answer (step 8).
    AnswerChainBlocked,
    /// An answer A/AAAA matched an IP block rule (step 9).
    AnswerIpBlocked,
    /// Rebind protection was skipped (step 10).
    RebindSkipped {
        /// Why the check did not run.
        reason: RebindSkipReason,
    },
    /// Private A/AAAA were stripped from a resolver answer (step 10).
    RebindStripped {
        /// Number of address records removed.
        count: u32,
    },
    /// Profile `suppress_aaaa` replaced an AAAA answer with NODATA (step 11).
    AaaaSuppressed,
    /// Resolver returned an answer.
    Resolve {
        /// Cache / recursion / stale.
        source: AnswerSource,
        /// DNSSEC outcome.
        dnssec: DnssecStatus,
    },
    /// Resolver returned an error; SERVFAIL was synthesised.
    ///
    /// The policy-layer code for this outcome is always `policy.resolve`.
    ResolveFailed {
        /// Nested resolver `code()` when available.
        cause_code: Option<&'static str>,
    },
    /// SafeSearch rewrote the qname to a provider safe host (step 5).
    SafeSearchRewrite {
        /// Provider id (`google`, `bing`, `youtube`, `duckduckgo`).
        provider: std::sync::Arc<str>,
        /// Safe endpoint hostname (no trailing dot).
        target: std::sync::Arc<str>,
    },
    /// A later step is configured but not applied yet (schedules until P14).
    NotApplied {
        /// Which stubbed pipeline step.
        step: NotAppliedStep,
    },
}

/// Identifies a pipeline step that is configured but not evaluated yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NotAppliedStep {
    /// Schedule windows that would swap the filter set (until P14).
    Schedules,
}

/// Filter hit attached to the decision record when a list/custom rule matched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterHit {
    /// Reason from the filtering engine.
    pub reason: Reason,
    /// Block mode when the verdict was a block.
    pub block_mode: Option<BlockMode>,
}

/// Pipeline timings in microseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DecisionTimings {
    /// Selection.
    pub select_us: u64,
    /// Filter match (0 until filter steps land).
    pub filter_us: u64,
    /// Resolver call (0 for synthetic answers that skip resolve).
    pub resolve_us: u64,
    /// End-to-end `handle`.
    pub total_us: u64,
}

/// Structured decision for the query log and test-query UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionRecord {
    /// Selected view.
    pub view_id: ViewId,
    /// Selected profile.
    pub profile_id: ProfileId,
    /// Selection cause.
    pub selection: SelectionCause,
    /// Client ID from the request, if any.
    pub client_id: Option<ClientId>,
    /// Ordered pipeline breadcrumbs.
    pub steps: Vec<DecisionStep>,
    /// Filter hit when a list/custom rule decided the answer.
    pub filter: Option<FilterHit>,
    /// Forward zone that produced a resolver answer, if any.
    pub forward_zone: Option<ForwardZoneId>,
    /// DNSSEC status of a resolver answer.
    pub dnssec: Option<DnssecStatus>,
    /// Origin of the final answer.
    pub answer_source: AnswerOrigin,
    /// Step timings.
    pub timings: DecisionTimings,
    /// Response code of the answer message.
    pub rcode: Rcode,
}
