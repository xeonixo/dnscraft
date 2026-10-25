//! Decision record returned with every policy answer.

use dnscraft_filtering::{BlockMode, Reason};
use dnscraft_proto::Rcode;
use dnscraft_resolver::{AnswerSource, DnssecStatus, ForwardZoneId};

use crate::ids::{ClientId, ProfileId, ViewId};
use crate::select::SelectionCause;

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
    /// View local records (later tasks).
    LocalView,
    /// ClientDirectory name or PTR (later tasks).
    LocalClient,
    /// Bypass / canary (later tasks).
    Bypass,
    /// Filter block or rewrite (later tasks).
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
    /// A later step is configured but not applied yet (SafeSearch / schedules).
    NotApplied {
        /// Short step name for the UI.
        step: &'static str,
    },
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
