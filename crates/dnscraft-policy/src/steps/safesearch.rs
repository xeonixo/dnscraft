//! Steps 5–6: SafeSearch rewrite + re-filter (config surface only in v1).

use crate::config::RequestContext;
use crate::decision::DecisionStep;
use crate::pipeline::{Draft, Flow, StepCtx};

/// Records that SafeSearch / post-rewrite filter are configured but not applied.
///
/// When the profile has SafeSearch enabled, pushes two [`DecisionStep::NotApplied`]
/// breadcrumbs (step 5 then step 6). Schedules that would swap the filter set get
/// a separate `NotApplied` when the profile lists any windows. Always continues.
pub(crate) fn run(ctx: &RequestContext, step: StepCtx<'_>, draft: &mut Draft) -> Flow {
    let _ = ctx;
    let profile = step.snapshot.profile_for_view(draft.selection.view_idx);

    if profile.config.safesearch.enabled {
        draft
            .steps
            .push(DecisionStep::NotApplied { step: "safesearch" });
        draft.steps.push(DecisionStep::NotApplied {
            step: "safesearch-filter",
        });
    }

    if !profile.config.schedules.is_empty() {
        draft
            .steps
            .push(DecisionStep::NotApplied { step: "schedules" });
    }

    Flow::Continue
}
