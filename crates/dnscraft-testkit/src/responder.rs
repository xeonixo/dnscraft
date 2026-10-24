//! Authoritative response construction. Pure functions over [`Zone`], kept
//! separate from the sockets so fault injection can wrap them later.

use hickory_proto::op::{Edns, Message, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use crate::zone::{DenialChain, Zone};

/// EDNS UDP payload size advertised in responses.
const ADVERTISED_PAYLOAD: u16 = 1232;

/// Builds the authoritative response of `zone` for the request `req`.
pub(crate) fn respond(zone: &Zone, req: &Message) -> Message {
    let mut resp = Message::response(req.metadata.id, req.metadata.op_code);
    resp.metadata.recursion_desired = req.metadata.recursion_desired;
    resp.metadata.checking_disabled = req.metadata.checking_disabled;
    resp.queries = req.queries.clone();
    let do_bit = req.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);
    if req.edns.is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(ADVERTISED_PAYLOAD);
        edns.set_dnssec_ok(do_bit);
        resp.edns = Some(edns);
    }

    if req.metadata.op_code != OpCode::Query {
        resp.metadata.response_code = ResponseCode::NotImp;
        return resp;
    }
    let [query] = req.queries.as_slice() else {
        resp.metadata.response_code = ResponseCode::FormErr;
        return resp;
    };
    let qname = query.name();
    if query.query_class() != DNSClass::IN || !zone.origin().zone_of(qname) {
        resp.metadata.response_code = ResponseCode::Refused;
        return resp;
    }
    let qtype = query.query_type();
    let dnssec = do_bit && zone.is_signed();

    if let Some(cut) = zone.delegation_for(qname) {
        // DS lives on the parent side of the cut: answer it authoritatively.
        if !(cut == *qname && qtype == RecordType::DS) {
            let ns: Vec<Record> = zone.rrset(&cut, RecordType::NS).cloned().collect();
            resp.additionals.extend(glue(zone, &ns));
            resp.authorities = ns;
            if dnssec {
                let ds: Vec<Record> = zone.rrset(&cut, RecordType::DS).cloned().collect();
                if ds.is_empty() {
                    resp.authorities.extend(no_ds_proof(zone, &cut));
                } else {
                    resp.authorities.extend(ds);
                    resp.authorities.extend(zone.sigs(&cut, RecordType::DS));
                }
            }
            return resp;
        }
    }

    resp.metadata.authoritative = true;
    let matching: Vec<Record> = zone
        .records()
        .iter()
        .filter(|r| r.name == *qname && wanted(r, qtype, dnssec))
        .cloned()
        .collect();
    if !matching.is_empty() {
        if qtype == RecordType::NS {
            resp.additionals.extend(glue(zone, &matching));
        }
        resp.answers = matching;
        if dnssec && qtype != RecordType::ANY && qtype != RecordType::RRSIG {
            resp.answers.extend(zone.sigs(qname, qtype));
        }
        return resp;
    }
    if qtype != RecordType::CNAME {
        let cname: Vec<Record> = zone.rrset(qname, RecordType::CNAME).cloned().collect();
        if !cname.is_empty() {
            resp.answers = cname;
            if dnssec {
                resp.answers.extend(zone.sigs(qname, RecordType::CNAME));
            }
            return resp;
        }
    }
    if zone.name_exists(qname) {
        add_soa(zone, &mut resp, dnssec);
        if dnssec {
            let proof = nodata_proof(zone, qname);
            push_unique(&mut resp.authorities, proof);
        }
        return resp;
    }

    // The name does not exist: try wildcard synthesis (RFC 4592).
    let encloser = zone.closest_encloser(qname);
    let wildcard = encloser.prepend_label("*").ok();
    if let Some(wildcard) = wildcard.filter(|w| zone.has_records(w)) {
        let synthesized: Vec<Record> = zone
            .records()
            .iter()
            .filter(|r| r.name == wildcard && wanted(r, qtype, dnssec))
            .cloned()
            .map(|mut r| {
                r.name = qname.clone();
                r
            })
            .collect();
        if !synthesized.is_empty() {
            resp.answers = synthesized;
            if dnssec && qtype != RecordType::ANY && qtype != RecordType::RRSIG {
                // RRSIGs keep their original labels field so validators see the expansion.
                resp.answers
                    .extend(zone.sigs(&wildcard, qtype).into_iter().map(|mut r| {
                        r.name = qname.clone();
                        r
                    }));
            }
            if dnssec {
                let proof = match zone.chain() {
                    Some(DenialChain::Nsec3 { .. }) => {
                        nsec3_cover(zone, &next_closer(qname, &encloser))
                    }
                    _ => name_absent_proof(zone, qname, &encloser, false),
                };
                push_unique(&mut resp.authorities, proof);
            }
            return resp;
        }
        add_soa(zone, &mut resp, dnssec);
        if dnssec {
            let mut proof = name_absent_proof(zone, qname, &encloser, false);
            proof.extend(match zone.chain() {
                Some(DenialChain::Nsec3 { .. }) => nsec3_match(zone, &wildcard),
                _ => nsec_at(zone, &wildcard),
            });
            push_unique(&mut resp.authorities, proof);
        }
        return resp;
    }

    resp.metadata.response_code = ResponseCode::NXDomain;
    add_soa(zone, &mut resp, dnssec);
    if dnssec {
        let proof = name_absent_proof(zone, qname, &encloser, true);
        push_unique(&mut resp.authorities, proof);
    }
    resp
}

/// Whether record `r` (already known to have the right owner) answers `qtype`.
fn wanted(r: &Record, qtype: RecordType, dnssec: bool) -> bool {
    if qtype == RecordType::ANY {
        dnssec
            || !matches!(
                r.record_type(),
                RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
            )
    } else {
        r.record_type() == qtype
    }
}

fn add_soa(zone: &Zone, resp: &mut Message, dnssec: bool) {
    if let Some(soa) = zone.soa() {
        resp.authorities.push(soa.clone());
        if dnssec {
            resp.authorities
                .extend(zone.sigs(&zone.origin().clone(), RecordType::SOA));
        }
    }
}

fn push_unique(into: &mut Vec<Record>, records: Vec<Record>) {
    for record in records {
        if !into.contains(&record) {
            into.push(record);
        }
    }
}

/// NSEC record(s) owned by `owner`, with RRSIGs.
fn nsec_at(zone: &Zone, owner: &Name) -> Vec<Record> {
    let mut out: Vec<Record> = zone.rrset(owner, RecordType::NSEC).cloned().collect();
    out.extend(zone.sigs(owner, RecordType::NSEC));
    out
}

/// NSEC3 record(s) owned by `owner`, with RRSIGs.
fn nsec3_at(zone: &Zone, owner: &Name) -> Vec<Record> {
    let mut out: Vec<Record> = zone.rrset(owner, RecordType::NSEC3).cloned().collect();
    out.extend(zone.sigs(owner, RecordType::NSEC3));
    out
}

/// NSEC3 whose hash matches `name`, if any.
fn nsec3_match(zone: &Zone, name: &Name) -> Vec<Record> {
    zone.chain()
        .and_then(|chain| {
            let hash = chain.hash(name)?;
            Some(nsec3_at(zone, chain.nsec3_match(&hash)?))
        })
        .unwrap_or_default()
}

/// NSEC3 whose interval covers the hash of `name`, if any.
fn nsec3_cover(zone: &Zone, name: &Name) -> Vec<Record> {
    zone.chain()
        .and_then(|chain| {
            let hash = chain.hash(name)?;
            Some(nsec3_at(zone, chain.nsec3_cover(&hash)?))
        })
        .unwrap_or_default()
}

/// The name one label below `encloser` on the way to `qname` (the "next closer").
fn next_closer(qname: &Name, encloser: &Name) -> Name {
    qname.trim_to(usize::from(encloser.num_labels()) + 1)
}

/// Proof that `qname` does not exist (NSEC: covering NSEC for the name and the
/// wildcard; NSEC3: closest-encloser proof). `with_wildcard` adds the proof
/// that `*.<encloser>` does not exist either.
fn name_absent_proof(
    zone: &Zone,
    qname: &Name,
    encloser: &Name,
    with_wildcard: bool,
) -> Vec<Record> {
    let wildcard = encloser.prepend_label("*").ok();
    let mut out = Vec::new();
    match zone.chain() {
        Some(DenialChain::Nsec) => {
            if let Some(owner) = zone.nsec_covering(qname) {
                out.extend(nsec_at(zone, &owner));
            }
            if with_wildcard && let Some(owner) = wildcard.and_then(|w| zone.nsec_covering(&w)) {
                push_unique(&mut out, nsec_at(zone, &owner));
            }
        }
        Some(DenialChain::Nsec3 { .. }) => {
            out.extend(nsec3_match(zone, encloser));
            push_unique(&mut out, nsec3_cover(zone, &next_closer(qname, encloser)));
            if with_wildcard && let Some(w) = wildcard {
                push_unique(&mut out, nsec3_cover(zone, &w));
            }
        }
        None => {}
    }
    out
}

/// Proof that `name` exists but has no RRset of the queried type.
fn nodata_proof(zone: &Zone, name: &Name) -> Vec<Record> {
    match zone.chain() {
        Some(DenialChain::Nsec) => nsec_at(zone, name),
        Some(DenialChain::Nsec3 { .. }) => {
            let matched = nsec3_match(zone, name);
            if matched.is_empty() {
                // Opt-out: no NSEC3 for the name; closest provable encloser proof.
                let encloser = nsec3_encloser(zone, name);
                name_absent_proof(zone, name, &encloser, false)
            } else {
                matched
            }
        }
        None => Vec::new(),
    }
}

/// Proof that the delegation at `cut` has no DS RRset (insecure delegation).
fn no_ds_proof(zone: &Zone, cut: &Name) -> Vec<Record> {
    nodata_proof(zone, cut)
}

/// Longest proper ancestor of `name` that owns a matching NSEC3 record.
fn nsec3_encloser(zone: &Zone, name: &Name) -> Name {
    let mut candidate = name.base_name();
    while candidate != *zone.origin() && nsec3_match(zone, &candidate).is_empty() {
        candidate = candidate.base_name();
    }
    candidate
}

/// Address records for the targets of the given NS records.
fn glue(zone: &Zone, ns_records: &[Record]) -> Vec<Record> {
    let targets: Vec<&Name> = ns_records
        .iter()
        .filter_map(|r| match &r.data {
            RData::NS(ns) => Some(&ns.0),
            _ => None,
        })
        .collect();
    zone.records()
        .iter()
        .filter(|r| matches!(r.record_type(), RecordType::A | RecordType::AAAA))
        .filter(|r| targets.contains(&&r.name))
        .cloned()
        .collect()
}
