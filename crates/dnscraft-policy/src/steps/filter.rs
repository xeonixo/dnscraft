//! Step 4: filter the original qname (block / rewrite / pass).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use dnscraft_filtering::{BlockMode, DomainName, FilterError, Rewrite, SetId, Verdict};
use dnscraft_proto::{Class, Name, RecordType};
use dnscraft_resolver::{Query, RequestFlags};
use tracing::warn;

use crate::config::RequestContext;
use crate::decision::{DecisionStep, FilterHit};
use crate::pipeline::{Draft, Flow, StepCtx};
use crate::synth::{
    DEFAULT_BLOCK_TTL, block_answer, filter_internal_servfail, rewrite_answer, rewrite_cname_follow,
};
use crate::util::{ede_text, name_to_domain};

/// Logs at most once per process when a set vanishes mid-flight (reload race).
static UNKNOWN_SET_LOGGED: AtomicBool = AtomicBool::new(false);

/// Runs step 4. May call the resolver for a CNAME rewrite follow.
pub(crate) async fn run(ctx: &RequestContext, step: StepCtx<'_>, draft: &mut Draft) -> Flow {
    if ctx.query.qclass != Class::IN {
        return Flow::Continue;
    }
    if step.paused {
        return Flow::Continue;
    }

    let profile = step.snapshot.profile_for_view(draft.selection.view_idx);
    let set_id = &profile.config.filter_set;
    let Some(domain) = name_to_domain(&ctx.query.name) else {
        draft.steps.push(DecisionStep::FilterSkipped {
            reason: "unrepresentable_name",
        });
        return Flow::Continue;
    };

    let now = step.clock.now();
    let verdict = match step
        .filter
        .match_name(set_id, &domain, u16::from(ctx.query.qtype), now)
    {
        Ok(v) => v,
        Err(FilterError::UnknownSet(_)) => {
            if !UNKNOWN_SET_LOGGED.swap(true, Ordering::Relaxed) {
                warn!(
                    set = %set_id,
                    "filter set missing at runtime; answering SERVFAIL (policy.internal)"
                );
            }
            draft.synthetic = true;
            draft.steps.push(DecisionStep::FilterBlocked);
            return Flow::Answer(filter_internal_servfail(
                &ctx.query,
                ctx.flags.recursion_desired,
            ));
        }
        Err(err) => {
            warn!(error = %err, code = err.code(), "filter match_name failed");
            draft.synthetic = true;
            draft.steps.push(DecisionStep::FilterBlocked);
            return Flow::Answer(filter_internal_servfail(
                &ctx.query,
                ctx.flags.recursion_desired,
            ));
        }
    };

    let ttl = DEFAULT_BLOCK_TTL;
    let rd = ctx.flags.recursion_desired;
    let mode = step
        .filter
        .snapshot()
        .block_mode(set_id)
        .unwrap_or_default();

    match verdict {
        Verdict::Pass | Verdict::Allowed(_) => Flow::Continue,
        Verdict::Blocked(reason) => {
            draft.filter = Some(FilterHit {
                reason: reason.clone(),
                block_mode: Some(mode),
            });
            draft.steps.push(DecisionStep::FilterBlocked);
            draft.synthetic = true;
            Flow::Answer(block_answer(
                &ctx.query,
                rd,
                mode,
                ttl,
                Some(ede_text(&reason)),
            ))
        }
        Verdict::Rewrite(rewrite, reason) => {
            draft.filter = Some(FilterHit {
                reason: reason.clone(),
                block_mode: None,
            });
            draft.steps.push(DecisionStep::FilterRewrite);
            draft.synthetic = true;
            match &rewrite {
                Rewrite::Cname(target) => {
                    follow_cname_rewrite(ctx, step, draft, set_id, mode, ttl, target).await
                }
                _ => Flow::Answer(rewrite_answer(&ctx.query, rd, &rewrite, ttl)),
            }
        }
        _ => Flow::Continue,
    }
}

async fn follow_cname_rewrite(
    ctx: &RequestContext,
    step: StepCtx<'_>,
    draft: &mut Draft,
    set_id: &SetId,
    mode: BlockMode,
    ttl: u32,
    target: &DomainName,
) -> Flow {
    let rd = ctx.flags.recursion_desired;
    let Ok(target_name) = Name::from_ascii(target.as_str()) else {
        return Flow::Answer(rewrite_answer(&ctx.query, rd, &Rewrite::NoErrorEmpty, ttl));
    };

    // Filter the rewrite target once more; a block wins.
    if let Ok(domain) = DomainName::parse(target.as_str()) {
        let now = step.clock.now();
        match step
            .filter
            .match_name(set_id, &domain, u16::from(ctx.query.qtype), now)
        {
            Ok(Verdict::Blocked(reason)) => {
                draft.filter = Some(FilterHit {
                    reason: reason.clone(),
                    block_mode: Some(mode),
                });
                draft.steps.push(DecisionStep::FilterBlocked);
                return Flow::Answer(block_answer(
                    &ctx.query,
                    rd,
                    mode,
                    ttl,
                    Some(ede_text(&reason)),
                ));
            }
            Ok(_) => {}
            Err(_) => {
                // Missing set / error while following: keep parent rewrite path
                // conservative — SERVFAIL.
                draft.steps.push(DecisionStep::FilterBlocked);
                return Flow::Answer(filter_internal_servfail(&ctx.query, rd));
            }
        }
    }

    // qtype CNAME: return the CNAME only (no follow).
    if ctx.query.qtype == RecordType::CNAME {
        return Flow::Answer(rewrite_answer(
            &ctx.query,
            rd,
            &Rewrite::Cname(target.clone()),
            ttl,
        ));
    }

    let flags = RequestFlags {
        checking_disabled: ctx.flags.checking_disabled,
        dnssec_ok: ctx.flags.dnssec_ok,
        client: Some(SocketAddr::new(ctx.source_ip, 0)),
        forward_zones: step.forward_zones_allow.map(std::sync::Arc::from),
    };
    let target_query = Query {
        name: target_name.clone(),
        qtype: ctx.query.qtype,
        qclass: ctx.query.qclass,
    };
    match step.resolver.resolve(&target_query, flags).await {
        Ok(answer) => {
            let rcode = answer.message.rcode();
            Flow::Answer(rewrite_cname_follow(
                &ctx.query,
                rd,
                ttl,
                &target_name,
                answer.message.answers,
                rcode,
            ))
        }
        Err(_) => {
            // Resolution failed: still return the CNAME so the client can follow.
            Flow::Answer(rewrite_answer(
                &ctx.query,
                rd,
                &Rewrite::Cname(target.clone()),
                ttl,
            ))
        }
    }
}
