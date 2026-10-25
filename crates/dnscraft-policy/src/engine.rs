//! Policy engine: select a view, run the pipeline, emit an answer.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use dnscraft_filtering::{Clock, FilterEngine};
use dnscraft_proto::RecordType;
use dnscraft_resolver::{DnssecStatus, RequestFlags, Resolver};

use crate::config::{PolicyConfig, RequestContext};
use crate::decision::{AnswerOrigin, DecisionStep, ProtectionPauseScope};
use crate::directory::ClientDirectory;
use crate::error::PolicyError;
use crate::ids::ProfileId;
use crate::pause::{PauseScope, PauseTable, PauseUntil};
use crate::pipeline::{Draft, Flow, StepCtx, Synth, apply_ad_policy};
use crate::snapshot::PolicySnapshot;
use crate::stats::{PolicyStats, StatsTable};
use crate::status::PolicyStatus;
use crate::steps::answer_side::AnswerSide;
use crate::steps::{
    aaaa, answer_side, canary, directory, filter, local_records, rebind, safesearch,
};
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
    snapshot: RwLock<Arc<PolicySnapshot>>,
    filter: Arc<FilterEngine>,
    resolver: Arc<Resolver>,
    clients: Arc<dyn ClientDirectory>,
    clock: Arc<dyn Clock>,
    pauses: Mutex<PauseTable>,
    stats: RwLock<StatsTable>,
    /// Serialises [`Self::apply_config`] so concurrent reloads cannot let an
    /// older build overwrite a newer one.
    config_lock: Mutex<()>,
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
        let (view_ids, profile_ids) = snapshot_ids(&snapshot);
        Ok(Self {
            snapshot: RwLock::new(Arc::new(snapshot)),
            filter,
            resolver,
            clients,
            clock,
            pauses: Mutex::new(PauseTable::default()),
            stats: RwLock::new(StatsTable::new(view_ids, profile_ids)),
            config_lock: Mutex::new(()),
        })
    }

    /// Current snapshot (for tests and status). Cloned under a short lock.
    pub fn snapshot(&self) -> Arc<PolicySnapshot> {
        Arc::clone(
            &self
                .snapshot
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Per-view / per-profile counters.
    pub fn stats(&self) -> PolicyStats {
        self.stats
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot()
    }

    /// Coarse status for the UI (`safesearch_applied` / `schedules_applied` are
    /// false until evaluation lands).
    pub fn status(&self) -> PolicyStatus {
        PolicyStatus::stubs()
    }

    /// Rebuilds and swaps the snapshot. On validation failure the previous
    /// snapshot stays in place. Pause state and counters survive by id;
    /// pauses and counters for removed profiles/views are dropped.
    ///
    /// Concurrent calls are serialised so an older build cannot overwrite a
    /// newer one.
    pub async fn apply_config(&self, config: PolicyConfig) -> Result<(), PolicyError> {
        let _serial = self
            .config_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let known_sets: Vec<_> = self.filter.snapshot().set_ids().cloned().collect();
        let known_zones = self.resolver.forward_zone_ids();
        let snapshot = PolicySnapshot::build(config, &known_sets, &known_zones)?;
        let (view_ids, profile_ids) = snapshot_ids(&snapshot);

        {
            let mut guard = self
                .snapshot
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard = Arc::new(snapshot);
        }
        self.pauses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain_profiles(&profile_ids);
        self.stats
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sync_ids(&view_ids, &profile_ids);
        Ok(())
    }

    /// Pauses filtering (steps 4 / 6 / 8 / 9) for `scope`.
    pub fn pause(&self, scope: PauseScope, until: PauseUntil) -> Result<(), PolicyError> {
        let snapshot = self.snapshot();
        let known: Vec<ProfileId> = snapshot.profiles.iter().map(|p| p.id.clone()).collect();
        self.pauses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pause(scope, until, self.clock.now(), &known)
    }

    /// Clears a previously set pause for `scope`.
    pub fn resume(&self, scope: PauseScope) {
        self.pauses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .resume(scope);
    }

    /// Handles one query: select, run steps, emit.
    ///
    /// Selection, RFC 8482 ANY, view local records (step 1), ClientDirectory
    /// (step 2), bypass canaries (step 3), filter qname (step 4), resolve
    /// (step 7), CNAME uncloaking + answer-IP rules (steps 8–9), rebind
    /// (step 10), and AAAA suppression (step 11). Steps 5–6 follow later.
    ///
    /// ECS is never forwarded: policy calls the resolver with
    /// [`RequestFlags`] only (no client EDNS options).
    pub async fn handle(&self, ctx: RequestContext) -> Result<PolicyAnswer, PolicyError> {
        let total_start = Instant::now();
        let snapshot = self.snapshot();
        let loggable = !ctx.test_query;

        let select_start = Instant::now();
        let selection = snapshot.select(&ctx);
        let select_us = elapsed_us(select_start);

        let mut draft = Draft::new(selection);
        draft.timings.select_us = select_us;

        let pause_scope = self.active_pause(&draft.selection.profile_id);
        let paused = pause_scope.is_some();
        if let Some(scope) = pause_scope {
            draft.steps.push(DecisionStep::ProtectionPaused { scope });
        }

        // ANY → RFC 8482, never resolve (and never view records).
        if ctx.query.qtype == RecordType::ANY {
            let synth = any_rfc8482(&ctx.query, ctx.flags.recursion_desired);
            draft.steps.push(DecisionStep::AnySynth);
            draft.synthetic = true;
            return Ok(self.finish_synth(draft, synth, total_start, ctx.client_id, loggable));
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
            paused,
        };

        // Step 1: view local records.
        if let Flow::Answer(synth) = local_records::run(&ctx, step_ctx, &mut draft) {
            return Ok(self.finish_synth(
                draft,
                synth,
                total_start,
                ctx.client_id.clone(),
                loggable,
            ));
        }

        // Step 2: ClientDirectory names / PTR / special-use NXDOMAIN.
        if let Flow::Answer(synth) = directory::run(&ctx, step_ctx, &mut draft) {
            return Ok(self.finish_synth(
                draft,
                synth,
                total_start,
                ctx.client_id.clone(),
                loggable,
            ));
        }

        // Step 3: bypass canaries (Firefox DoH / iCloud Private Relay).
        if let Flow::Answer(synth) = canary::run(&ctx, step_ctx, &mut draft) {
            return Ok(self.finish_synth(
                draft,
                synth,
                total_start,
                ctx.client_id.clone(),
                loggable,
            ));
        }

        // Step 4: filter original qname (block / rewrite). Skipped while paused.
        if let Flow::Answer(synth) = filter::run(&ctx, step_ctx, &mut draft).await {
            return Ok(self.finish_synth(
                draft,
                synth,
                total_start,
                ctx.client_id.clone(),
                loggable,
            ));
        }

        // Steps 5–6: SafeSearch + re-filter (config surface / NotApplied stubs).
        safesearch::run(step_ctx, &mut draft);

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
                return Ok(self.finish_synth(
                    draft,
                    synth,
                    total_start,
                    ctx.client_id.clone(),
                    loggable,
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
                return Ok(self.finish_synth(
                    draft,
                    synth,
                    total_start,
                    ctx.client_id.clone(),
                    loggable,
                ));
            }
            AnswerSide::Keep => {}
        }

        // Step 10: rebind protection (resolver answers only; synthetics skip).
        let steps_before_rebind = draft.steps.len();
        rebind::run(
            &ctx,
            step_ctx,
            &mut draft,
            &mut message,
            answer.forward_zone.as_ref(),
        );
        let rebind_changed = draft.steps.len() > steps_before_rebind
            && matches!(
                draft.steps.last(),
                Some(DecisionStep::RebindStripped { .. })
            );

        // Step 11: AAAA suppression.
        let aaaa_suppressed = aaaa::run(&ctx, step_ctx, &mut draft, &mut message);
        let mut ede = answer.ede;
        if rebind_changed || aaaa_suppressed {
            ede = None;
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
        if loggable {
            self.record_stats(&record);
        }

        Ok(PolicyAnswer {
            message,
            ede,
            record,
            loggable,
        })
    }

    fn active_pause(&self, profile: &ProfileId) -> Option<ProtectionPauseScope> {
        self.pauses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active_scope(profile, self.clock.now())
    }

    fn finish_synth(
        &self,
        mut draft: Draft,
        synth: Synth,
        total_start: Instant,
        client_id: Option<crate::ids::ClientId>,
        loggable: bool,
    ) -> PolicyAnswer {
        draft.timings.total_us = elapsed_us(total_start);
        let answer = emit(draft, synth, client_id, loggable, None, None);
        if loggable {
            self.record_stats(&answer.record);
        }
        answer
    }

    fn record_stats(&self, decision: &crate::decision::DecisionRecord) {
        self.stats
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(decision);
    }

    /// Client directory (internal / integration tests).
    #[doc(hidden)]
    pub fn clients(&self) -> &Arc<dyn ClientDirectory> {
        &self.clients
    }

    /// Filter engine (internal / integration tests).
    #[doc(hidden)]
    pub fn filter(&self) -> &Arc<FilterEngine> {
        &self.filter
    }
}

fn snapshot_ids(snapshot: &PolicySnapshot) -> (Vec<crate::ids::ViewId>, Vec<ProfileId>) {
    let views = snapshot.views.iter().map(|v| v.id.clone()).collect();
    let profiles = snapshot.profiles.iter().map(|p| p.id.clone()).collect();
    (views, profiles)
}

fn emit(
    draft: Draft,
    synth: Synth,
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
