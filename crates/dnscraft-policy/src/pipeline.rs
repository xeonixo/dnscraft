//! Pipeline step framework: draft answer and control flow.

use dnscraft_proto::Message;
use dnscraft_resolver::ExtendedError;

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

/// Mutable state accumulated while handling one query.
#[derive(Debug)]
pub struct Draft {
    /// Selection result.
    pub selection: Selection,
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
    /// Starts a draft after selection.
    pub fn new(selection: Selection) -> Self {
        let cause = selection.matched_by;
        Self {
            selection,
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

/// Shared inputs for pipeline steps (later tasks).
#[derive(Clone, Copy)]
pub struct StepCtx<'a> {
    /// Validated snapshot for this query.
    pub snapshot: &'a PolicySnapshot,
}
