//! Step 10: DNS rebind protection (strip private A/AAAA from resolver answers).
//!
//! When every address record is private and removed, **CNAME chain records are
//! kept**: the response is NOERROR with only the CNAMEs (NODATA-for-alias
//! shape). Only A/AAAA are stripped; the answer section is not cleared.

use dnscraft_proto::{Message, Name, RData, Rcode};
use dnscraft_resolver::ForwardZoneId;

use crate::config::RequestContext;
use crate::decision::{DecisionStep, RebindSkipReason};
use crate::pipeline::{Draft, StepCtx, clear_ad};
use crate::private::is_private_for_rebind;
use crate::snapshot::RebindException;
use crate::synth::{DEFAULT_BLOCK_TTL, ensure_nodata_soa};

/// Runs rebind stripping on a resolver answer. Skipped when `draft.synthetic`
/// (defence in depth; synthetic paths return before step 10).
///
/// Mutates `message` in place: private A/AAAA removed; if every address was
/// stripped → NOERROR with remaining non-address records (e.g. CNAMEs), no EDE.
/// Clears AD on any change.
pub(crate) fn run(
    ctx: &RequestContext,
    step: StepCtx<'_>,
    draft: &mut Draft,
    message: &mut Message,
    forward_zone: Option<&ForwardZoneId>,
) {
    if draft.synthetic {
        return;
    }

    let profile = step.snapshot.profile_for_view(draft.selection.view_idx);
    let default_rebind = step.snapshot.default_rebind;

    if !profile.config.rebind_enabled(default_rebind) {
        draft.steps.push(DecisionStep::RebindSkipped {
            reason: RebindSkipReason::Disabled,
        });
        return;
    }

    if exception_matches(&ctx.query.name, &profile.rebind_exceptions) {
        draft.steps.push(DecisionStep::RebindSkipped {
            reason: RebindSkipReason::Exception,
        });
        return;
    }

    if let Some(z) = forward_zone {
        let checked = step
            .snapshot
            .rebind_check_forward_zones
            .iter()
            .any(|id| id == z);
        if !checked {
            draft.steps.push(DecisionStep::RebindSkipped {
                reason: RebindSkipReason::ForwardZoneExempt,
            });
            return;
        }
    }

    let before = message.answers.len();
    message.answers.retain(|rec| match &rec.rdata {
        RData::A(v4) => !is_private_for_rebind((*v4).into()),
        RData::AAAA(v6) => !is_private_for_rebind((*v6).into()),
        _ => true,
    });
    let stripped = before.saturating_sub(message.answers.len());
    if stripped == 0 {
        return;
    }

    clear_ad(message);
    draft.steps.push(DecisionStep::RebindStripped {
        count: u32::try_from(stripped).unwrap_or(u32::MAX),
    });

    // All addresses gone: keep any CNAME (or other non-address) records and
    // ensure NOERROR — NODATA-for-alias when CNAMEs remain; empty answer gets
    // a synthetic SOA so clients can negatively cache.
    let any_address_left = message
        .answers
        .iter()
        .any(|r| matches!(&r.rdata, RData::A(_) | RData::AAAA(_)));
    if !any_address_left {
        let _ = message.set_rcode(Rcode::NOERROR);
        if message.answers.is_empty() {
            ensure_nodata_soa(message, &ctx.query.name, DEFAULT_BLOCK_TTL);
        }
    }
}

/// Pre-parsed `exact` or `*.suffix` against the qname (suffix includes the apex).
fn exception_matches(qname: &Name, exceptions: &[RebindException]) -> bool {
    for ex in exceptions {
        match ex {
            RebindException::Exact(name) => {
                if name == qname {
                    return true;
                }
            }
            RebindException::Suffix(zone) => {
                if zone.zone_of(qname) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unit {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn exception_exact_and_suffix() {
        let suffix = RebindException::Suffix(Name::from_ascii("example.com").unwrap());
        let exact = RebindException::Exact(Name::from_ascii("nas.lan").unwrap());
        let list = Arc::from(vec![suffix, exact]);

        let q = Name::from_ascii("cdn.internal.example.com.").unwrap();
        assert!(exception_matches(&q, &list));
        assert!(exception_matches(
            &Name::from_ascii("example.com.").unwrap(),
            &list
        ));
        assert!(!exception_matches(
            &Name::from_ascii("example.org.").unwrap(),
            &list
        ));
        assert!(exception_matches(
            &Name::from_ascii("nas.lan.").unwrap(),
            &list
        ));
        assert!(!exception_matches(
            &Name::from_ascii("other.lan.").unwrap(),
            &list
        ));
    }
}
