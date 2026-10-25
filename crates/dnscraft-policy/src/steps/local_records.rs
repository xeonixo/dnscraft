//! Step 1: answer from the selected view's local records.

use dnscraft_proto::{Class, Name, RData, Record, RecordType};
use dnscraft_resolver::Query;

use crate::config::RequestContext;
use crate::decision::DecisionStep;
use crate::pipeline::{Draft, Flow, StepCtx};
use crate::snapshot::SnapshotView;
use crate::synth::{local_nodata, local_records_answer};

/// Maximum CNAME hops followed within one view (spec loop guard).
pub const MAX_CNAME_HOPS: u8 = 8;

/// Runs step 1. Continues when the qname is unknown in this view.
pub(crate) fn run(ctx: &RequestContext, step: StepCtx<'_>, draft: &mut Draft) -> Flow {
    // View records are class IN; other classes (CH, …) are not ours to answer.
    if ctx.query.qclass != Class::IN {
        return Flow::Continue;
    }
    let rd = ctx.flags.recursion_desired;
    let view = &step.snapshot.views[usize::from(draft.selection.view_idx)];
    match answer_from_view(view, &ctx.query) {
        None => Flow::Continue,
        Some(Outcome::Records(records)) => {
            draft.steps.push(DecisionStep::LocalView);
            draft.synthetic = true;
            Flow::Answer(local_records_answer(&ctx.query, rd, records))
        }
        Some(Outcome::Nodata) => {
            draft.steps.push(DecisionStep::LocalView);
            draft.synthetic = true;
            Flow::Answer(local_nodata(&ctx.query, rd))
        }
    }
}

enum Outcome {
    Records(Vec<Record>),
    Nodata,
}

fn answer_from_view(view: &SnapshotView, query: &Query) -> Option<Outcome> {
    let rrsets = view.records.get(&query.name)?;
    let cname = rrsets
        .records
        .iter()
        .find(|r| r.rtype() == RecordType::CNAME);

    if let Some(cname_rec) = cname {
        if query.qtype == RecordType::CNAME {
            return Some(Outcome::Records(vec![cname_rec.clone()]));
        }
        return Some(follow_cname(view, query, cname_rec));
    }

    let matching: Vec<Record> = rrsets
        .records
        .iter()
        .filter(|r| r.rtype() == query.qtype)
        .cloned()
        .collect();
    if matching.is_empty() {
        Some(Outcome::Nodata)
    } else {
        Some(Outcome::Records(matching))
    }
}

/// Returns CNAME chain (+ final qtype records when the target is local).
///
/// At most [`MAX_CNAME_HOPS`] CNAME records are included (loop guard).
fn follow_cname(view: &SnapshotView, query: &Query, first: &Record) -> Outcome {
    let mut answers = vec![first.clone()];
    let mut current = match cname_target(first) {
        Some(n) => n,
        None => return Outcome::Records(answers),
    };

    while answers.len() < usize::from(MAX_CNAME_HOPS) {
        let Some(rrsets) = view.records.get(&current) else {
            // External target: return the CNAME(s) only; client/resolver follows.
            return Outcome::Records(answers);
        };

        if let Some(next_cname) = rrsets
            .records
            .iter()
            .find(|r| r.rtype() == RecordType::CNAME)
        {
            answers.push(next_cname.clone());
            match cname_target(next_cname) {
                Some(n) => current = n,
                None => return Outcome::Records(answers),
            }
            continue;
        }

        let matching: Vec<Record> = rrsets
            .records
            .iter()
            .filter(|r| r.rtype() == query.qtype)
            .cloned()
            .collect();
        if matching.is_empty() {
            // Local name exists but not of the queried type → CNAME(s) only (NOERROR).
            return Outcome::Records(answers);
        }
        answers.extend(matching);
        return Outcome::Records(answers);
    }

    Outcome::Records(answers)
}

fn cname_target(rec: &Record) -> Option<Name> {
    match &rec.rdata {
        RData::CNAME(name) => Some(name.clone()),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unit {
    use super::*;
    use crate::ids::ViewId;
    use crate::snapshot::{SnapshotView, ViewRrSets};
    use dnscraft_proto::{Class, Name, RData};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    fn view_with(records: Vec<(Name, Vec<Record>)>) -> SnapshotView {
        let mut map = HashMap::new();
        for (name, recs) in records {
            map.insert(
                name,
                ViewRrSets {
                    records: Arc::from(recs),
                },
            );
        }
        SnapshotView {
            id: ViewId::new("v").unwrap(),
            is_default: false,
            profile_idx: 0,
            records: map,
        }
    }

    fn rec(name: &str, rdata: RData) -> Record {
        Record::new(Name::from_ascii(name).unwrap(), Class::IN, 60, rdata)
    }

    #[test]
    fn local_records_cname_loop_stops_at_eight() {
        let a = Name::from_ascii("a.example.com").unwrap();
        let b = Name::from_ascii("b.example.com").unwrap();
        // a → b → a …
        let view = view_with(vec![
            (
                a.clone(),
                vec![rec("a.example.com", RData::CNAME(b.clone()))],
            ),
            (
                b.clone(),
                vec![rec("b.example.com", RData::CNAME(a.clone()))],
            ),
        ]);
        let q = Query {
            name: a,
            qtype: RecordType::A,
            qclass: Class::IN,
        };
        let out = answer_from_view(&view, &q).unwrap();
        match out {
            Outcome::Records(recs) => {
                assert_eq!(recs.len(), usize::from(MAX_CNAME_HOPS));
                assert!(recs.iter().all(|r| r.rtype() == RecordType::CNAME));
            }
            Outcome::Nodata => panic!("expected cname chain"),
        }
    }

    #[test]
    fn local_records_cname_to_local_a() {
        let alias = Name::from_ascii("alias.example.com").unwrap();
        let target = Name::from_ascii("nas.example.com").unwrap();
        let view = view_with(vec![
            (
                alias.clone(),
                vec![rec("alias.example.com", RData::CNAME(target.clone()))],
            ),
            (
                target,
                vec![rec(
                    "nas.example.com",
                    RData::A(Ipv4Addr::new(192, 0, 2, 10)),
                )],
            ),
        ]);
        let q = Query {
            name: alias,
            qtype: RecordType::A,
            qclass: Class::IN,
        };
        let Outcome::Records(recs) = answer_from_view(&view, &q).unwrap() else {
            panic!("expected records");
        };
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].rtype(), RecordType::CNAME);
        assert_eq!(recs[1].rtype(), RecordType::A);
    }

    #[test]
    fn local_records_cname_to_external_stops() {
        let alias = Name::from_ascii("alias.example.com").unwrap();
        let view = view_with(vec![(
            alias.clone(),
            vec![rec(
                "alias.example.com",
                RData::CNAME(Name::from_ascii("cdn.example.net").unwrap()),
            )],
        )]);
        let q = Query {
            name: alias,
            qtype: RecordType::A,
            qclass: Class::IN,
        };
        let Outcome::Records(recs) = answer_from_view(&view, &q).unwrap() else {
            panic!("expected records");
        };
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].rtype(), RecordType::CNAME);
    }
}
