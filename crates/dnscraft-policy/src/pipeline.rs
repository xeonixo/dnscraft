//! Pipeline step framework: draft answer and control flow.

use dnscraft_filtering::SetId;
use dnscraft_proto::Message;
use dnscraft_resolver::{DnssecStatus, ExtendedError};

use crate::decision::{AnswerOrigin, DecisionRecord, DecisionStep, DecisionTimings, FilterHit};
use crate::select::Selection;
use crate::snapshot::PolicySnapshot;

/// Outcome of one pipeline step.
#[derive(Debug)]
pub enum Flow {
    /// Keep running later steps.
    Continue,
    /// Stop and emit this synthesised answer.
    Answer(Synth),
}

/// A synthesised answer produced by a pipeline step.
#[derive(Clone, Debug)]
pub struct Synth {
    /// Response message (AD must already be clear unless the step documents otherwise).
    pub message: Message,
    /// Optional EDE for the listener to attach.
    pub ede: Option<ExtendedError>,
    /// Origin recorded on the decision.
    pub origin: AnswerOrigin,
}

/// Clears the AD bit. Every synthesis and modification goes through this.
#[inline]
pub fn clear_ad(message: &mut Message) {
    message.header.ad = false;
}

/// AD only for unmodified Secure answers; every other status clears it.
pub(crate) fn apply_ad_policy(message: &mut Message, status: DnssecStatus) {
    if status != DnssecStatus::Secure {
        clear_ad(message);
    }
}

/// Mutable state accumulated while handling one query.
#[derive(Debug)]
pub struct Draft {
    /// Selection result.
    pub selection: Selection,
    /// Effective filter set (profile default or active schedule).
    pub filter_set: SetId,
    /// Pipeline breadcrumbs.
    pub steps: Vec<DecisionStep>,
    /// Filter hit, if any.
    pub filter: Option<FilterHit>,
    /// Timings filled as steps run.
    pub timings: DecisionTimings,
    /// When true, later answer-side steps (rebind, …) skip this answer.
    pub synthetic: bool,
}

impl Draft {
    /// Starts a draft after selection with the profile's default filter set.
    ///
    /// The engine may overwrite [`Self::filter_set`] when a schedule is active.
    pub fn new(selection: Selection, filter_set: SetId) -> Self {
        let cause = selection.matched_by;
        Self {
            selection,
            filter_set,
            steps: vec![DecisionStep::Selected { cause }],
            filter: None,
            timings: DecisionTimings::default(),
            synthetic: false,
        }
    }

    /// Builds the decision record for an emitted answer.
    pub fn into_record(
        self,
        answer_source: AnswerOrigin,
        rcode: dnscraft_proto::Rcode,
        forward_zone: Option<dnscraft_resolver::ForwardZoneId>,
        dnssec: Option<dnscraft_resolver::DnssecStatus>,
        client_id: Option<crate::ids::ClientId>,
    ) -> DecisionRecord {
        DecisionRecord {
            view_id: self.selection.view_id,
            profile_id: self.selection.profile_id,
            selection: self.selection.matched_by,
            client_id,
            filter_set: self.filter_set,
            steps: self.steps,
            filter: self.filter,
            forward_zone,
            dnssec,
            answer_source,
            timings: self.timings,
            rcode,
        }
    }
}

/// Shared inputs for pipeline steps.
#[derive(Clone, Copy)]
pub struct StepCtx<'a> {
    /// Validated snapshot for this query.
    pub snapshot: &'a PolicySnapshot,
    /// Client directory for step 2.
    pub clients: &'a dyn crate::directory::ClientDirectory,
    /// Resolver (forward-zone lookups and CNAME rewrite follow).
    pub resolver: &'a dnscraft_resolver::Resolver,
    /// Profile forward-zone allow-list (`None` = all configured zones).
    pub forward_zones_allow: Option<&'a [dnscraft_resolver::ForwardZoneId]>,
    /// Filter engine for step 4+.
    pub filter: &'a dnscraft_filtering::FilterEngine,
    /// Effective filter set for steps 4 / 6 / 8 / 9.
    pub filter_set: &'a SetId,
    /// Shared clock (pause / temporary allows / match_name `now`).
    pub clock: &'a dyn dnscraft_filtering::Clock,
    /// When true, filter steps 4 / 6 / 8 / 9 return Pass (user-facing pause).
    pub paused: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnscraft_proto::Header;

    fn message_with_ad() -> Message {
        Message {
            header: Header {
                ad: true,
                ..Header::default()
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        }
    }

    #[test]
    fn ad_policy_keeps_ad_only_for_secure() {
        let mut secure = message_with_ad();
        apply_ad_policy(&mut secure, DnssecStatus::Secure);
        assert!(secure.header.ad);

        for status in [
            DnssecStatus::Insecure,
            DnssecStatus::Bogus,
            DnssecStatus::Indeterminate,
        ] {
            let mut message = message_with_ad();
            apply_ad_policy(&mut message, status);
            assert!(!message.header.ad, "{status:?}");
        }
    }
}
