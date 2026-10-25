//! Steps 8–9: CNAME uncloaking and answer-IP filtering on resolver answers.

use std::net::IpAddr;

use dnscraft_filtering::{DomainName, FilterError, Reason, Verdict};
use dnscraft_proto::{Message, Name, RData, Record, RecordType};
use tracing::warn;

use crate::config::RequestContext;
use crate::decision::{DecisionStep, FilterHit};
use crate::pipeline::{Draft, StepCtx};
use crate::synth::{DEFAULT_BLOCK_TTL, block_answer, filter_internal_servfail};
use crate::util::{ede_text, name_to_domain};

/// Outcome of answer-side filtering.
pub(crate) enum AnswerSide {
    /// Keep the resolver message (possibly still Secure/AD).
    Keep,
    /// Replace the entire answer with this synthesis.
    Replace(crate::pipeline::Synth),
}

/// Runs steps 8 (CNAME chain) and 9 (answer IPs). Skipped when `draft.synthetic`.
pub(crate) fn run(
    ctx: &RequestContext,
    step: StepCtx<'_>,
    draft: &mut Draft,
    message: &Message,
) -> AnswerSide {
    if draft.synthetic {
        return AnswerSide::Keep;
    }

    let profile = step.snapshot.profile_for_view(draft.selection.view_idx);
    let set_id = &profile.config.filter_set;
    let now = step.clock.now();
    let qtype = u16::from(ctx.query.qtype);
    let rd = ctx.flags.recursion_desired;
    let mode = step
        .filter
        .snapshot()
        .block_mode(set_id)
        .unwrap_or_default();
    let ttl = DEFAULT_BLOCK_TTL;

    // Step 8: CNAME uncloaking.
    let chain = collect_chain_names(&ctx.query.name, &message.answers);
    if !chain.is_empty() {
        match step.filter.match_chain(set_id, &chain, qtype, now) {
            Ok(Verdict::Blocked(reason)) => {
                return replace_blocked(
                    draft,
                    ctx,
                    rd,
                    mode,
                    ttl,
                    reason,
                    DecisionStep::AnswerChainBlocked,
                );
            }
            Ok(_) => {}
            Err(FilterError::UnknownSet(_)) | Err(_) => {
                warn!(set = %set_id, "answer-side match_chain failed");
                draft.synthetic = true;
                draft.steps.push(DecisionStep::AnswerChainBlocked);
                return AnswerSide::Replace(filter_internal_servfail(&ctx.query, rd));
            }
        }
    }

    // Step 9: answer-IP rules.
    for ip in answer_ips(&message.answers) {
        match step.filter.match_answer_ip(set_id, ip, now) {
            Ok(Verdict::Blocked(reason)) => {
                return replace_blocked(
                    draft,
                    ctx,
                    rd,
                    mode,
                    ttl,
                    reason,
                    DecisionStep::AnswerIpBlocked,
                );
            }
            Ok(_) => {}
            Err(FilterError::UnknownSet(_)) | Err(_) => {
                warn!(set = %set_id, "answer-side match_answer_ip failed");
                draft.synthetic = true;
                draft.steps.push(DecisionStep::AnswerIpBlocked);
                return AnswerSide::Replace(filter_internal_servfail(&ctx.query, rd));
            }
        }
    }

    AnswerSide::Keep
}

fn replace_blocked(
    draft: &mut Draft,
    ctx: &RequestContext,
    rd: bool,
    mode: dnscraft_filtering::BlockMode,
    ttl: u32,
    reason: Reason,
    step: DecisionStep,
) -> AnswerSide {
    draft.filter = Some(FilterHit {
        reason: reason.clone(),
        block_mode: Some(mode),
    });
    draft.steps.push(step);
    draft.synthetic = true;
    AnswerSide::Replace(block_answer(
        &ctx.query,
        rd,
        mode,
        ttl,
        Some(ede_text(&reason)),
    ))
}

/// Qname plus each CNAME target in answer order (owners followed within the section).
fn collect_chain_names(qname: &Name, answers: &[Record]) -> Vec<DomainName> {
    let mut out = Vec::new();
    if let Some(d) = name_to_domain(qname) {
        out.push(d);
    }
    let mut current = qname.clone();
    for rec in answers {
        if rec.rtype() != RecordType::CNAME || rec.name != current {
            continue;
        }
        let RData::CNAME(target) = &rec.rdata else {
            continue;
        };
        if let Some(d) = name_to_domain(target) {
            out.push(d);
        }
        current = target.clone();
    }
    out
}

fn answer_ips(answers: &[Record]) -> Vec<IpAddr> {
    answers
        .iter()
        .filter_map(|r| match &r.rdata {
            RData::A(v4) => Some(IpAddr::V4(*v4)),
            RData::AAAA(v6) => Some(IpAddr::V6(*v6)),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unit {
    use super::*;
    use dnscraft_proto::{Class, Record};

    #[test]
    fn collect_chain_follows_cname_owners() {
        let q = Name::from_ascii("alias.example.test.").unwrap();
        let mid = Name::from_ascii("mid.example.test.").unwrap();
        let end = Name::from_ascii("www.example.test.").unwrap();
        let answers = vec![
            Record::new(q.clone(), Class::IN, 60, RData::CNAME(mid.clone())),
            Record::new(mid.clone(), Class::IN, 60, RData::CNAME(end.clone())),
            Record::new(
                end,
                Class::IN,
                60,
                RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            ),
        ];
        let names = collect_chain_names(&q, &answers);
        assert_eq!(
            names.iter().map(DomainName::as_str).collect::<Vec<_>>(),
            vec!["alias.example.test", "mid.example.test", "www.example.test"]
        );
    }
}
