//! Policy engine: select a view, run the pipeline, emit an answer.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use dnscraft_filtering::{Clock, FilterEngine};
use dnscraft_proto::RecordType;
use dnscraft_resolver::{DnssecStatus, RequestFlags, Resolver};

use crate::config::{PolicyConfig, RequestContext};
use crate::decision::{AnswerOrigin, DecisionStep};
use crate::directory::ClientDirectory;
use crate::error::PolicyError;
use crate::pipeline::{Draft, Flow, StepCtx, apply_ad_policy};
use crate::snapshot::PolicySnapshot;
use crate::steps::answer_side::AnswerSide;
use crate::steps::{answer_side, canary, directory, filter, local_records};
use crate::synth::{any_rfc8482, resolve_servfail};

/// Final answer from [`PolicyEngine::handle`].
#[derive(Clone, Debug)]
pub struct PolicyAnswer {
    /// Response message. Id is 0; the listener sets the client's id.
    pub message: dnscraft_proto::Message,
    /// Extended error for the listener to attach, if any.
    pub ede: Option<dnscraft_resolver::ExtendedError>,
    /// Structured decision for logs / test query.
    pub record: crate::decision::DecisionRecord,
    /// When false, `control-api` must not write the query log (`test_query`).
    pub loggable: bool,
}

/// Pipeline between listeners and the resolver / filter engine.
pub struct PolicyEngine {
    snapshot: Arc<PolicySnapshot>,
    filter: Arc<FilterEngine>,
    resolver: Arc<Resolver>,
    clients: Arc<dyn ClientDirectory>,
    clock: Arc<dyn Clock>,
}

impl PolicyEngine {
    /// Builds a validated snapshot and returns the engine.
    ///
    /// Known filter sets come from `filter`; known forward zones from
    /// [`Resolver::forward_zone_ids`].
    pub fn new(
        config: PolicyConfig,
        filter: Arc<FilterEngine>,
        resolver: Arc<Resolver>,
        clients: Arc<dyn ClientDirectory>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PolicyError> {
        let known_sets: Vec<_> = filter.snapshot().set_ids().cloned().collect();
        let known_zones = resolver.forward_zone_ids();
        let snapshot = PolicySnapshot::build(config, &known_sets, &known_zones)?;
        Ok(Self {
            snapshot: Arc::new(snapshot),
            filter,
            resolver,
            clients,
            clock,
        })
    }

    /// Current snapshot (for tests and status).
    pub fn snapshot(&self) -> Arc<PolicySnapshot> {
        Arc::clone(&self.snapshot)
    }

    /// Handles one query: select, run steps, emit.
    ///
    /// Selection, RFC 8482 ANY, view local records (step 1), ClientDirectory
    /// (step 2), bypass canaries (step 3), filter qname (step 4), resolve
    /// (step 7), then CNAME uncloaking + answer-IP rules (steps 8–9). Steps
    /// 5–6 and 10–11 follow later.
    ///
    /// ECS is never forwarded: policy calls the resolver with
    /// [`RequestFlags`] only (no client EDNS options).
    pub async fn handle(&self, ctx: RequestContext) -> Result<PolicyAnswer, PolicyError> {
        let total_start = Instant::now();
        let snapshot = Arc::clone(&self.snapshot);
        let loggable = !ctx.test_query;

        let select_start = Instant::now();
        let selection = snapshot.select(&ctx);
        let select_us = elapsed_us(select_start);

        let mut draft = Draft::new(selection);
        draft.timings.select_us = select_us;

        // ANY → RFC 8482, never resolve (and never view records).
        if ctx.query.qtype == RecordType::ANY {
            let synth = any_rfc8482(&ctx.query, ctx.flags.recursion_desired);
            draft.steps.push(DecisionStep::AnySynth);
            draft.synthetic = true;
            draft.timings.total_us = elapsed_us(total_start);
            return Ok(emit(
                draft,
                synth,
                ctx.client_id.clone(),
                loggable,
                None,
                None,
            ));
        }

        let profile = snapshot.profile_for_view(draft.selection.view_idx);
        let forward_zones = profile
            .config
            .forward_zones
            .as_ref()
            .map(|ids| Arc::<[_]>::from(ids.as_slice()));

        let step_ctx = StepCtx {
            snapshot: snapshot.as_ref(),
            clients: self.clients.as_ref(),
            resolver: self.resolver.as_ref(),
            forward_zones_allow: forward_zones.as_deref(),
            filter: self.filter.as_ref(),
            clock: self.clock.as_ref(),
        };

        // Step 1: view local records.
        if let Flow::Answer(synth) = local_records::run(&ctx, step_ctx, &mut draft) {
            draft.timings.total_us = elapsed_us(total_start);
            return Ok(emit(
                draft,
                synth,
                ctx.client_id.clone(),
                loggable,
                None,
                None,
            ));
        }

        // Step 2: ClientDirectory names / PTR / special-use NXDOMAIN.
        if let Flow::Answer(synth) = directory::run(&ctx, step_ctx, &mut draft) {
            draft.timings.total_us = elapsed_us(total_start);
            return Ok(emit(
                draft,
                synth,
                ctx.client_id.clone(),
                loggable,
                None,
                None,
            ));
        }

        // Step 3: bypass canaries (Firefox DoH / iCloud Private Relay).
        if let Flow::Answer(synth) = canary::run(&ctx, step_ctx, &mut draft) {
            draft.timings.total_us = elapsed_us(total_start);
            return Ok(emit(
                draft,
                synth,
                ctx.client_id.clone(),
                loggable,
                None,
                None,
            ));
        }

        // Step 4: filter original qname (block / rewrite).
        if let Flow::Answer(synth) = filter::run(&ctx, step_ctx, &mut draft).await {
            draft.timings.total_us = elapsed_us(total_start);
            return Ok(emit(
                draft,
                synth,
                ctx.client_id.clone(),
                loggable,
                None,
                None,
            ));
        }

        // Steps 5–6 / 10–11: later tasks. Then resolve (step 7).

        let flags = RequestFlags {
            checking_disabled: ctx.flags.checking_disabled,
            dnssec_ok: ctx.flags.dnssec_ok,
            client: Some(SocketAddr::new(ctx.source_ip, 0)),
            forward_zones: forward_zones.clone(),
        };

        let resolve_start = Instant::now();
        let resolved = self.resolver.resolve(&ctx.query, flags).await;
        draft.timings.resolve_us = elapsed_us(resolve_start);

        let answer = match resolved {
            Ok(answer) => answer,
            Err(err) => {
                draft.steps.push(DecisionStep::ResolveFailed {
                    cause_code: Some(err.code()),
                });
                let synth = resolve_servfail(&ctx.query, ctx.flags.recursion_desired);
                draft.synthetic = true;
                draft.timings.total_us = elapsed_us(total_start);
                return Ok(emit(
                    draft,
                    synth,
                    ctx.client_id.clone(),
                    loggable,
                    None,
                    None,
                ));
            }
        };

        draft.steps.push(DecisionStep::Resolve {
            source: answer.source,
            dnssec: answer.dnssec,
        });

        let mut message = answer.message;
        apply_ad_policy(&mut message, answer.dnssec);
        // Listener owns the message id.
        message.header.id = 0;

        // Steps 8–9: CNAME uncloaking + answer-IP rules (resolver answers only).
        match answer_side::run(&ctx, step_ctx, &mut draft, &message) {
            AnswerSide::Replace(synth) => {
                draft.timings.total_us = elapsed_us(total_start);
                return Ok(emit(
                    draft,
                    synth,
                    ctx.client_id.clone(),
                    loggable,
                    None,
                    None,
                ));
            }
            AnswerSide::Keep => {}
        }

        draft.timings.total_us = elapsed_us(total_start);
        let rcode = message.rcode();
        let record = draft.into_record(
            AnswerOrigin::Resolver,
            rcode,
            answer.forward_zone.clone(),
            Some(answer.dnssec),
            ctx.client_id,
        );

        Ok(PolicyAnswer {
            message,
            ede: answer.ede,
            record,
            loggable,
        })
    }
}

fn emit(
    draft: Draft,
    synth: crate::pipeline::Synth,
    client_id: Option<crate::ids::ClientId>,
    loggable: bool,
    forward_zone: Option<dnscraft_resolver::ForwardZoneId>,
    dnssec: Option<DnssecStatus>,
) -> PolicyAnswer {
    let rcode = synth.message.rcode();
    let origin = synth.origin;
    let record = draft.into_record(origin, rcode, forward_zone, dnssec, client_id);
    PolicyAnswer {
        message: synth.message,
        ede: synth.ede,
        record,
        loggable,
    }
}

fn elapsed_us(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

impl PolicyEngine {
    /// Client directory (for later steps and tests).
    pub fn clients(&self) -> &Arc<dyn ClientDirectory> {
        &self.clients
    }

    /// Filter engine (for later steps and tests).
    pub fn filter(&self) -> &Arc<FilterEngine> {
        &self.filter
    }
}
