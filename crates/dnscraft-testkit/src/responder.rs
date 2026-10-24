//! Authoritative response construction. Pure functions over [`Zone`], kept
//! separate from the sockets so fault injection can wrap them later.

use hickory_proto::op::{Edns, Message, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use crate::zone::Zone;

/// EDNS UDP payload size advertised in responses.
const ADVERTISED_PAYLOAD: u16 = 1232;

/// Builds the authoritative response of `zone` for the request `req`.
pub(crate) fn respond(zone: &Zone, req: &Message) -> Message {
    let mut resp = Message::response(req.metadata.id, req.metadata.op_code);
    resp.metadata.recursion_desired = req.metadata.recursion_desired;
    resp.metadata.checking_disabled = req.metadata.checking_disabled;
    resp.queries = req.queries.clone();
    if req.edns.is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(ADVERTISED_PAYLOAD);
        edns.set_dnssec_ok(req.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok));
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

    if let Some(cut) = zone.delegation_for(qname) {
        let ns: Vec<Record> = zone.rrset(&cut, RecordType::NS).cloned().collect();
        resp.additionals.extend(glue(zone, &ns));
        resp.authorities = ns;
        return resp;
    }

    resp.metadata.authoritative = true;
    let matching: Vec<Record> = zone
        .records()
        .iter()
        .filter(|r| r.name == *qname && (qtype == RecordType::ANY || r.record_type() == qtype))
        .cloned()
        .collect();
    if !matching.is_empty() {
        if qtype == RecordType::NS {
            resp.additionals.extend(glue(zone, &matching));
        }
        resp.answers = matching;
        return resp;
    }
    if qtype != RecordType::CNAME {
        let cname: Vec<Record> = zone.rrset(qname, RecordType::CNAME).cloned().collect();
        if !cname.is_empty() {
            resp.answers = cname;
            return resp;
        }
    }
    if !zone.name_exists(qname) {
        resp.metadata.response_code = ResponseCode::NXDomain;
    }
    resp.authorities.extend(zone.soa().cloned());
    resp
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
