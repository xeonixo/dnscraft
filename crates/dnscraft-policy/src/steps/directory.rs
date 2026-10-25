//! Step 2: ClientDirectory names / PTR and special-use NXDOMAIN.

use std::net::IpAddr;

use dnscraft_proto::{Class, Name, RData, Record, RecordType};

use crate::config::{DEFAULT_RECORD_TTL, RequestContext};
use crate::decision::DecisionStep;
use crate::pipeline::{Draft, Flow, StepCtx};
use crate::reverse::{ip_from_reverse, ptr_eligible};
use crate::synth::{directory_answer, directory_nodata, special_use_nxdomain};

/// Runs step 2. Continues when the directory does not know the name and the
/// query is not a special-use NXDOMAIN case.
pub(crate) fn run(ctx: &RequestContext, step: StepCtx<'_>, draft: &mut Draft) -> Flow {
    if ctx.query.qclass != Class::IN {
        return Flow::Continue;
    }
    let rd = ctx.flags.recursion_desired;

    if let Some(flow) = try_addresses(ctx, step, draft, rd) {
        return flow;
    }
    if let Some(flow) = try_ptr(ctx, step, draft, rd) {
        return flow;
    }
    if let Some(flow) = try_special_use(ctx, step, draft, rd) {
        return flow;
    }
    Flow::Continue
}

fn try_addresses(
    ctx: &RequestContext,
    step: StepCtx<'_>,
    draft: &mut Draft,
    rd: bool,
) -> Option<Flow> {
    let addrs = step.clients.addresses(&ctx.query.name)?;
    draft.steps.push(DecisionStep::LocalClient);
    draft.synthetic = true;

    match ctx.query.qtype {
        RecordType::A => {
            let records: Vec<Record> = addrs
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(Record::new(
                        ctx.query.name.clone(),
                        Class::IN,
                        DEFAULT_RECORD_TTL,
                        RData::A(*v4),
                    )),
                    IpAddr::V6(_) => None,
                })
                .collect();
            Some(if records.is_empty() {
                Flow::Answer(directory_nodata(&ctx.query, rd))
            } else {
                Flow::Answer(directory_answer(&ctx.query, rd, records))
            })
        }
        RecordType::AAAA => {
            let records: Vec<Record> = addrs
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(v6) => Some(Record::new(
                        ctx.query.name.clone(),
                        Class::IN,
                        DEFAULT_RECORD_TTL,
                        RData::AAAA(*v6),
                    )),
                    IpAddr::V4(_) => None,
                })
                .collect();
            Some(if records.is_empty() {
                Flow::Answer(directory_nodata(&ctx.query, rd))
            } else {
                Flow::Answer(directory_answer(&ctx.query, rd, records))
            })
        }
        // Known name, other type → NODATA (do not fall through).
        _ => Some(Flow::Answer(directory_nodata(&ctx.query, rd))),
    }
}

fn try_ptr(ctx: &RequestContext, step: StepCtx<'_>, draft: &mut Draft, rd: bool) -> Option<Flow> {
    if ctx.query.qtype != RecordType::PTR {
        return None;
    }
    let ip = ip_from_reverse(&ctx.query.name)?;
    if !ptr_eligible(ip, &step.snapshot.ptr_prefixes) {
        return None;
    }
    let target = step.clients.reverse(ip)?;
    let target_name = Name::from_ascii(target.as_ref()).ok()?;
    draft.steps.push(DecisionStep::LocalClient);
    draft.synthetic = true;
    let rec = Record::new(
        ctx.query.name.clone(),
        Class::IN,
        DEFAULT_RECORD_TTL,
        RData::PTR(target_name),
    );
    Some(Flow::Answer(directory_answer(&ctx.query, rd, vec![rec])))
}

fn try_special_use(
    ctx: &RequestContext,
    step: StepCtx<'_>,
    draft: &mut Draft,
    rd: bool,
) -> Option<Flow> {
    // Known names already returned above. Here the directory said unknown.
    let zone = matching_nxdomain_suffix(&ctx.query.name, &step.snapshot.local_nxdomain_suffixes)?;
    if step
        .resolver
        .forward_zone_for(&ctx.query.name, step.forward_zones_allow)
        .is_some()
    {
        // A covering forward zone wins; fall through to resolve.
        return None;
    }
    draft.steps.push(DecisionStep::SpecialUseNxdomain);
    draft.synthetic = true;
    Some(Flow::Answer(special_use_nxdomain(&ctx.query, rd, &zone)))
}

/// Most specific configured special-use suffix that contains `name`.
fn matching_nxdomain_suffix(name: &Name, suffixes: &[std::sync::Arc<str>]) -> Option<Name> {
    let mut best: Option<Name> = None;
    for suffix in suffixes {
        let Ok(zone) = Name::from_ascii(suffix.as_ref()) else {
            continue;
        };
        if !zone.zone_of(name) {
            continue;
        }
        let better = best
            .as_ref()
            .is_none_or(|b| zone.label_count() > b.label_count());
        if better {
            best = Some(zone);
        }
    }
    best
}
