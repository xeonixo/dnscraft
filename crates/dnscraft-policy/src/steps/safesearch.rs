//! Steps 5–6: SafeSearch rewrite + re-filter of the safe host.
//!
//! Step 5 rewrites A / AAAA / HTTPS queries for known provider hosts to the
//! provider's safe endpoint (CNAME + follow). Other qtypes pass through
//! unchanged. Step 6 runs `match_name` on the safe host before resolving;
//! Blocked / Rewrite are handled like steps 4a / 4b.
//!
//! Pause protection (SPEC): filtering Passes while paused, but SafeSearch
//! rewrite still runs — step 6 is skipped when paused so a blocked safe host
//! does not fire during pause.

use std::net::SocketAddr;
use std::sync::Arc;

use dnscraft_filtering::{DomainName, FilterError, Rewrite, Verdict};
use dnscraft_proto::{Class, Name, RecordType};
use dnscraft_resolver::{Query, RequestFlags};
use tracing::warn;

use crate::config::RequestContext;
use crate::decision::{DecisionStep, FilterHit};
use crate::pipeline::{Draft, Flow, StepCtx};
use crate::safesearch_table::{self, SafeSearchProvider};
use crate::steps::filter::follow_cname_rewrite;
use crate::synth::{
    DEFAULT_BLOCK_TTL, block_answer, filter_internal_servfail, rewrite_answer, rewrite_cname_follow,
};
use crate::util::ede_text;

/// Runs steps 5–6. May call the resolver to follow the safe-host CNAME.
pub(crate) async fn run(ctx: &RequestContext, step: StepCtx<'_>, draft: &mut Draft) -> Flow {
    let profile = step.snapshot.profile_for_view(draft.selection.view_idx);

    if !profile.config.safesearch.enabled {
        return Flow::Continue;
    }
    if ctx.query.qclass != Class::IN {
        return Flow::Continue;
    }
    // ANY is answered before this step. Other qtypes (MX, TXT, …) pass through.
    if !matches!(
        ctx.query.qtype,
        RecordType::A | RecordType::AAAA | RecordType::HTTPS
    ) {
        return Flow::Continue;
    }

    let Some(hit) =
        safesearch_table::lookup(&ctx.query.name, profile.config.safesearch.youtube_mode)
    else {
        return Flow::Continue;
    };
    if !provider_enabled(&profile.config.safesearch.providers, hit.provider) {
        return Flow::Continue;
    }

    draft.steps.push(DecisionStep::SafeSearchRewrite {
        provider: Arc::from(hit.provider.as_str()),
        target: Arc::from(hit.target),
    });

    let set_id = step.filter_set;
    let rd = ctx.flags.recursion_desired;
    let ttl = DEFAULT_BLOCK_TTL;
    let mode = step
        .filter
        .snapshot()
        .block_mode(set_id)
        .unwrap_or_default();

    // Step 6: filter the safe host (skipped while protection is paused).
    if !step.paused {
        let Ok(domain) = DomainName::parse(hit.target) else {
            return Flow::Continue;
        };
        let now = step.clock.now();
        match step
            .filter
            .match_name(set_id, &domain, u16::from(ctx.query.qtype), now)
        {
            Ok(Verdict::Pass) | Ok(Verdict::Allowed(_)) => {}
            Ok(Verdict::Blocked(reason)) => {
                draft.filter = Some(FilterHit {
                    reason: reason.clone(),
                    block_mode: Some(mode),
                });
                draft.steps.push(DecisionStep::FilterBlocked);
                draft.synthetic = true;
                return Flow::Answer(block_answer(
                    &ctx.query,
                    rd,
                    mode,
                    ttl,
                    Some(ede_text(&reason)),
                ));
            }
            Ok(Verdict::Rewrite(rewrite, reason)) => {
                draft.filter = Some(FilterHit {
                    reason: reason.clone(),
                    block_mode: None,
                });
                draft.steps.push(DecisionStep::FilterRewrite);
                draft.synthetic = true;
                return match &rewrite {
                    Rewrite::Cname(target) => {
                        follow_cname_rewrite(ctx, step, draft, set_id, mode, ttl, target).await
                    }
                    _ => Flow::Answer(rewrite_answer(&ctx.query, rd, &rewrite, ttl)),
                };
            }
            Err(FilterError::UnknownSet(_)) => {
                draft.synthetic = true;
                draft.steps.push(DecisionStep::FilterBlocked);
                return Flow::Answer(filter_internal_servfail(&ctx.query, rd));
            }
            Err(err) => {
                warn!(error = %err, code = err.code(), "SafeSearch step 6 match_name failed");
                draft.synthetic = true;
                draft.steps.push(DecisionStep::FilterBlocked);
                return Flow::Answer(filter_internal_servfail(&ctx.query, rd));
            }
        }
    }

    let Ok(target_name) = Name::from_ascii(hit.target) else {
        return Flow::Continue;
    };

    // qtype CNAME never reaches here (gated above). Resolve the safe host and
    // return CNAME(qname → safe) + target answers (reuse step 4b helper).
    let flags = RequestFlags {
        checking_disabled: ctx.flags.checking_disabled,
        dnssec_ok: ctx.flags.dnssec_ok,
        client: Some(SocketAddr::new(ctx.source_ip, 0)),
        forward_zones: step.forward_zones_allow.map(Arc::from),
        no_cache_write: ctx.test_query,
    };
    let target_query = Query {
        name: target_name.clone(),
        qtype: ctx.query.qtype,
        qclass: ctx.query.qclass,
    };
    match step.resolver.resolve(&target_query, flags).await {
        Ok(answer) => {
            let rcode = answer.message.rcode();
            // Carry resolve metadata so rebind exemption / DecisionRecord are correct.
            draft.follow_forward_zone = answer.forward_zone;
            draft.follow_dnssec = Some(answer.dnssec);
            // Not marked synthetic: answer-side / rebind / AAAA still apply
            // to the resolved target (SPEC / P13).
            Flow::Answer(rewrite_cname_follow(
                &ctx.query,
                rd,
                ttl,
                &target_name,
                answer.message.answers,
                rcode,
            ))
        }
        Err(err) => {
            // Resolution failed: still return the CNAME so the client can follow,
            // but record why the follow did not complete.
            draft.steps.push(DecisionStep::ResolveFailed {
                cause_code: Some(err.code()),
            });
            let Ok(domain) = DomainName::parse(hit.target) else {
                return Flow::Continue;
            };
            Flow::Answer(rewrite_answer(&ctx.query, rd, &Rewrite::Cname(domain), ttl))
        }
    }
}

fn provider_enabled(providers: &[Arc<str>], provider: SafeSearchProvider) -> bool {
    let id = provider.as_str();
    providers.iter().any(|p| p.as_ref() == id)
}
