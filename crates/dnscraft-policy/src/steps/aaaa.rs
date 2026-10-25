//! Step 11: AAAA suppression (IPv4-only profiles).

use dnscraft_proto::{Message, Rcode, RecordType};

use crate::config::RequestContext;
use crate::decision::DecisionStep;
use crate::pipeline::{Draft, StepCtx, clear_ad};

/// When the profile has `suppress_aaaa` and the qtype is AAAA, replace with
/// NOERROR/NODATA. Other qtypes (including HTTPS/SVCB) are left unchanged.
///
/// Returns `true` when the answer was replaced (caller should drop EDE).
pub(crate) fn run(
    ctx: &RequestContext,
    step: StepCtx<'_>,
    draft: &mut Draft,
    message: &mut Message,
) -> bool {
    if ctx.query.qtype != RecordType::AAAA {
        return false;
    }
    let profile = step.snapshot.profile_for_view(draft.selection.view_idx);
    if !profile.config.suppress_aaaa {
        return false;
    }

    message.answers.clear();
    message.authorities.clear();
    let _ = message.set_rcode(Rcode::NOERROR);
    clear_ad(message);
    draft.steps.push(DecisionStep::AaaaSuppressed);
    true
}
