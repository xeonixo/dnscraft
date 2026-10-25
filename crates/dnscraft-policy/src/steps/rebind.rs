//! Step 10: DNS rebind protection (strip private A/AAAA from resolver answers).

use dnscraft_proto::{Message, Name, RData, Rcode};
use dnscraft_resolver::ForwardZoneId;

use crate::config::RequestContext;
use crate::decision::{DecisionStep, RebindSkipReason};
use crate::pipeline::{Draft, StepCtx, clear_ad};
use crate::private::is_private_for_rebind;

/// Runs rebind stripping on a resolver answer. Skipped when `draft.synthetic`.
///
/// Mutates `message` in place: private A/AAAA removed; if every address was
/// stripped → NOERROR/NODATA (empty answers, no EDE). Clears AD on any change.
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

    if exception_matches(&ctx.query.name, &profile.config.rebind_exceptions) {
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

    let any_address_left = message
        .answers
        .iter()
        .any(|r| matches!(&r.rdata, RData::A(_) | RData::AAAA(_)));
    if !any_address_left {
        // All addresses were private: NOERROR/NODATA, no EDE.
        message.answers.clear();
        let _ = message.set_rcode(Rcode::NOERROR);
    }
}

/// `exact` or `*.suffix` against the qname (suffix includes the apex).
fn exception_matches(qname: &Name, exceptions: &[std::sync::Arc<str>]) -> bool {
    for pattern in exceptions {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            let Ok(zone) = Name::from_ascii(suffix) else {
                continue;
            };
            if zone.zone_of(qname) {
                return true;
            }
        } else {
            let Ok(exact) = Name::from_ascii(pattern.as_ref()) else {
                continue;
            };
            if &exact == qname {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unit {
    use super::*;

    #[test]
    fn exception_exact_and_suffix() {
        let q = Name::from_ascii("cdn.internal.example.com.").unwrap();
        assert!(exception_matches(
            &q,
            &[std::sync::Arc::from("*.example.com")]
        ));
        assert!(exception_matches(
            &Name::from_ascii("example.com.").unwrap(),
            &[std::sync::Arc::from("*.example.com")]
        ));
        assert!(!exception_matches(
            &Name::from_ascii("example.org.").unwrap(),
            &[std::sync::Arc::from("*.example.com")]
        ));
        assert!(exception_matches(
            &Name::from_ascii("nas.lan.").unwrap(),
            &[std::sync::Arc::from("nas.lan")]
        ));
        assert!(!exception_matches(
            &Name::from_ascii("other.lan.").unwrap(),
            &[std::sync::Arc::from("nas.lan")]
        ));
    }
}
