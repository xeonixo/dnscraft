//! Synthesised DNS answers (ANY, SERVFAIL, block/rewrite, local answers).

use std::net::{Ipv4Addr, Ipv6Addr};

use dnscraft_filtering::BlockMode;
use dnscraft_proto::{Class, Header, Message, Name, Question, RData, Rcode, Record, RecordType};
use dnscraft_resolver::{ExtendedError, Query};

use crate::decision::AnswerOrigin;
use crate::pipeline::{Synth, clear_ad};

/// Default TTL for filter block / rewrite answers when the set has no
/// dedicated blocked-response TTL field yet (plan: 10 s).
pub const DEFAULT_BLOCK_TTL: u32 = 10;

/// RFC 8914 INFO-CODE 15 Blocked (operator policy).
pub const EDE_BLOCKED: u16 = 15;
/// RFC 8914 INFO-CODE 4 Forged Answer (null/custom IP).
pub const EDE_FORGED_ANSWER: u16 = 4;

/// HINFO type number (RFC 1035); not a first-class [`RData`] variant.
const HINFO: RecordType = RecordType(13);

/// Minimal RFC 8482 answer: NOERROR with one HINFO (`CPU=RFC8482`, empty OS).
///
/// Does not recurse and clears AD.
pub fn any_rfc8482(query: &Query, rd: bool) -> Synth {
    let mut message = response_skeleton(query, rd);
    message.header.ra = true;
    let _ = message.set_rcode(Rcode::NOERROR);
    message.answers.push(Record::new(
        query.name.clone(),
        Class::IN,
        3600,
        hinfo_rfc8482(),
    ));
    clear_ad(&mut message);
    Synth {
        message,
        ede: None,
        origin: AnswerOrigin::SynthAny,
    }
}

/// SERVFAIL for a resolver failure. Clears AD; no EDE (not a filter block).
pub fn resolve_servfail(query: &Query, rd: bool) -> Synth {
    let mut message = response_skeleton(query, rd);
    message.header.ra = true;
    let _ = message.set_rcode(Rcode::SERVFAIL);
    clear_ad(&mut message);
    Synth {
        message,
        ede: None,
        origin: AnswerOrigin::ResolveError,
    }
}

/// Authoritative answer from a view's local records. Sets AA, clears AD.
pub fn local_records_answer(query: &Query, rd: bool, answers: Vec<Record>) -> Synth {
    let mut message = response_skeleton(query, rd);
    message.header.aa = true;
    message.header.ra = true;
    let _ = message.set_rcode(Rcode::NOERROR);
    message.answers = answers;
    clear_ad(&mut message);
    Synth {
        message,
        ede: None,
        origin: AnswerOrigin::LocalView,
    }
}

/// NODATA for a view name that exists but has no records of the queried type.
///
/// Sets AA, clears AD, empty answer section.
pub fn local_nodata(query: &Query, rd: bool) -> Synth {
    let mut message = response_skeleton(query, rd);
    message.header.aa = true;
    message.header.ra = true;
    let _ = message.set_rcode(Rcode::NOERROR);
    clear_ad(&mut message);
    Synth {
        message,
        ede: None,
        origin: AnswerOrigin::LocalView,
    }
}

/// Authoritative answer from the ClientDirectory (A/AAAA/PTR). Sets AA, clears AD.
pub fn directory_answer(query: &Query, rd: bool, answers: Vec<Record>) -> Synth {
    let mut message = response_skeleton(query, rd);
    message.header.aa = true;
    message.header.ra = true;
    let _ = message.set_rcode(Rcode::NOERROR);
    message.answers = answers;
    clear_ad(&mut message);
    Synth {
        message,
        ede: None,
        origin: AnswerOrigin::LocalClient,
    }
}

/// NODATA for a ClientDirectory name known without the queried type.
pub fn directory_nodata(query: &Query, rd: bool) -> Synth {
    let mut message = response_skeleton(query, rd);
    message.header.aa = true;
    message.header.ra = true;
    let _ = message.set_rcode(Rcode::NOERROR);
    clear_ad(&mut message);
    Synth {
        message,
        ede: None,
        origin: AnswerOrigin::LocalClient,
    }
}

/// Bypass / canary NXDOMAIN (Firefox DoH, iCloud Private Relay). Clears AD; no EDE.
pub fn bypass_nxdomain(query: &Query, rd: bool) -> Synth {
    let mut message = response_skeleton(query, rd);
    message.header.aa = true;
    message.header.ra = true;
    let _ = message.set_rcode(Rcode::NXDOMAIN);
    clear_ad(&mut message);
    Synth {
        message,
        ede: None,
        origin: AnswerOrigin::Bypass,
    }
}

/// SERVFAIL when the profile's filter set is missing at runtime (`policy.internal`).
pub fn filter_internal_servfail(query: &Query, rd: bool) -> Synth {
    let mut message = response_skeleton(query, rd);
    message.header.ra = true;
    let _ = message.set_rcode(Rcode::SERVFAIL);
    clear_ad(&mut message);
    Synth {
        message,
        ede: None,
        origin: AnswerOrigin::Filter,
    }
}

/// Block synthesis for a [`BlockMode`], with the matching EDE.
pub fn block_answer(
    query: &Query,
    rd: bool,
    mode: BlockMode,
    ttl: u32,
    ede_text: Option<String>,
) -> Synth {
    match mode {
        BlockMode::Refused => {
            let mut message = response_skeleton(query, rd);
            message.header.ra = true;
            let _ = message.set_rcode(Rcode::REFUSED);
            clear_ad(&mut message);
            Synth {
                message,
                ede: Some(ede(EDE_BLOCKED, ede_text)),
                origin: AnswerOrigin::Filter,
            }
        }
        BlockMode::NxDomain => {
            let mut message = response_skeleton(query, rd);
            message.header.aa = true;
            message.header.ra = true;
            let _ = message.set_rcode(Rcode::NXDOMAIN);
            message.authorities.push(synthetic_soa(&query.name, ttl));
            clear_ad(&mut message);
            Synth {
                message,
                ede: Some(ede(EDE_BLOCKED, ede_text)),
                origin: AnswerOrigin::Filter,
            }
        }
        BlockMode::NullIp => match query.qtype {
            RecordType::A => filter_address_answer(
                query,
                rd,
                ttl,
                vec![RData::A(Ipv4Addr::UNSPECIFIED)],
                ede_text,
            ),
            RecordType::AAAA => filter_address_answer(
                query,
                rd,
                ttl,
                vec![RData::AAAA(Ipv6Addr::UNSPECIFIED)],
                ede_text,
            ),
            _ => filter_nodata(query, rd, ttl, Some(ede(EDE_FORGED_ANSWER, ede_text))),
        },
        BlockMode::CustomIp { v4, v6 } => match query.qtype {
            RecordType::A => match v4 {
                Some(ip) => filter_address_answer(query, rd, ttl, vec![RData::A(ip)], ede_text),
                None => filter_nodata(query, rd, ttl, Some(ede(EDE_FORGED_ANSWER, ede_text))),
            },
            RecordType::AAAA => match v6 {
                Some(ip) => filter_address_answer(query, rd, ttl, vec![RData::AAAA(ip)], ede_text),
                None => filter_nodata(query, rd, ttl, Some(ede(EDE_FORGED_ANSWER, ede_text))),
            },
            _ => filter_nodata(query, rd, ttl, Some(ede(EDE_FORGED_ANSWER, ede_text))),
        },
        }
}

/// Rewrite synthesis (no EDE). Type-mismatched address/TXT rewrites → NODATA.
pub fn rewrite_answer(
    query: &Query,
    rd: bool,
    rewrite: &dnscraft_filtering::Rewrite,
    ttl: u32,
) -> Synth {
    use dnscraft_filtering::Rewrite;
    match rewrite {
        Rewrite::Refused => {
            let mut message = response_skeleton(query, rd);
            message.header.ra = true;
            let _ = message.set_rcode(Rcode::REFUSED);
            clear_ad(&mut message);
            Synth {
                message,
                ede: None,
                origin: AnswerOrigin::Filter,
            }
        }
        Rewrite::NxDomain => {
            let mut message = response_skeleton(query, rd);
            message.header.aa = true;
            message.header.ra = true;
            let _ = message.set_rcode(Rcode::NXDOMAIN);
            message.authorities.push(synthetic_soa(&query.name, ttl));
            clear_ad(&mut message);
            Synth {
                message,
                ede: None,
                origin: AnswerOrigin::Filter,
            }
        }
        Rewrite::ServFail => {
            let mut message = response_skeleton(query, rd);
            message.header.ra = true;
            let _ = message.set_rcode(Rcode::SERVFAIL);
            clear_ad(&mut message);
            Synth {
                message,
                ede: None,
                origin: AnswerOrigin::Filter,
            }
        }
        Rewrite::NoErrorEmpty => filter_nodata(query, rd, ttl, None),
        Rewrite::A(ip) => {
            if query.qtype == RecordType::A {
                filter_records_answer(query, rd, ttl, vec![RData::A(*ip)])
            } else {
                filter_nodata(query, rd, ttl, None)
            }
        }
        Rewrite::Aaaa(ip) => {
            if query.qtype == RecordType::AAAA {
                filter_records_answer(query, rd, ttl, vec![RData::AAAA(*ip)])
            } else {
                filter_nodata(query, rd, ttl, None)
            }
        }
        Rewrite::Txt(text) => {
            if query.qtype == RecordType::TXT {
                let bytes: Box<[u8]> = text.as_bytes().into();
                filter_records_answer(query, rd, ttl, vec![RData::TXT(vec![bytes])])
            } else {
                filter_nodata(query, rd, ttl, None)
            }
        }
        Rewrite::Cname(target) => match Name::from_ascii(target.as_str()) {
            Ok(n) => filter_records_answer(query, rd, ttl, vec![RData::CNAME(n)]),
            Err(_) => filter_nodata(query, rd, ttl, None),
        },
        }
}

/// CNAME rewrite answer: synthesised CNAME plus the target's resolved records.
pub fn rewrite_cname_follow(
    query: &Query,
    rd: bool,
    ttl: u32,
    target: &Name,
    target_answers: Vec<Record>,
    target_rcode: Rcode,
) -> Synth {
    let mut message = response_skeleton(query, rd);
    message.header.aa = false;
    message.header.ra = true;
    let _ = message.set_rcode(target_rcode);
    message.answers.push(Record::new(
        query.name.clone(),
        Class::IN,
        ttl,
        RData::CNAME(target.clone()),
    ));
    message.answers.extend(target_answers);
    clear_ad(&mut message);
    Synth {
        message,
        ede: None,
        origin: AnswerOrigin::Filter,
    }
}

fn filter_address_answer(
    query: &Query,
    rd: bool,
    ttl: u32,
    rdata: Vec<RData>,
    ede_text: Option<String>,
) -> Synth {
    let mut s = filter_records_answer(query, rd, ttl, rdata);
    s.ede = Some(ede(EDE_FORGED_ANSWER, ede_text));
    s
}

fn filter_records_answer(query: &Query, rd: bool, ttl: u32, rdata: Vec<RData>) -> Synth {
    let mut message = response_skeleton(query, rd);
    message.header.aa = true;
    message.header.ra = true;
    let _ = message.set_rcode(Rcode::NOERROR);
    message.answers = rdata
        .into_iter()
        .map(|r| Record::new(query.name.clone(), Class::IN, ttl, r))
        .collect();
    clear_ad(&mut message);
    Synth {
        message,
        ede: None,
        origin: AnswerOrigin::Filter,
    }
}

fn filter_nodata(query: &Query, rd: bool, ttl: u32, ede: Option<ExtendedError>) -> Synth {
    let mut message = response_skeleton(query, rd);
    message.header.aa = true;
    message.header.ra = true;
    let _ = message.set_rcode(Rcode::NOERROR);
    message.authorities.push(synthetic_soa(&query.name, ttl));
    clear_ad(&mut message);
    Synth {
        message,
        ede,
        origin: AnswerOrigin::Filter,
    }
}

/// Synthetic SOA for NODATA / NXDOMAIN authority (negative caching).
pub(crate) fn synthetic_soa(zone: &Name, ttl: u32) -> Record {
    let rname = match Name::from_ascii("nobody.invalid.") {
        Ok(n) => n,
        Err(_) => Name::root(),
    };
    Record::new(
        zone.clone(),
        Class::IN,
        ttl,
        RData::SOA {
            mname: zone.clone(),
            rname,
            serial: 1,
            refresh: 604_800,
            retry: 86_400,
            expire: 2_419_200,
            minimum: ttl,
        },
    )
}

/// Ensures a NODATA answer has a single synthetic SOA in authority.
pub(crate) fn ensure_nodata_soa(message: &mut Message, owner: &Name, ttl: u32) {
    message.authorities.clear();
    message.authorities.push(synthetic_soa(owner, ttl));
}

fn ede(code: u16, text: Option<String>) -> ExtendedError {
    ExtendedError { code, text }
}

/// Special-use suffix NXDOMAIN with a synthetic SOA in authority. No EDE.
///
/// `zone` is the matching `local_nxdomain_suffixes` apex. TTL follows the
/// RFC 6303 local-zone convention (3 hours).
pub fn special_use_nxdomain(query: &Query, rd: bool, zone: &Name) -> Synth {
    const SOA_TTL: u32 = 10_800;
    let mut message = response_skeleton(query, rd);
    message.header.aa = true;
    message.header.ra = true;
    let _ = message.set_rcode(Rcode::NXDOMAIN);
    let rname = match Name::from_ascii("nobody.invalid.") {
        Ok(n) => n,
        Err(_) => Name::root(),
    };
    message.authorities.push(Record::new(
        zone.clone(),
        Class::IN,
        SOA_TTL,
        RData::SOA {
            mname: zone.clone(),
            rname,
            serial: 1,
            refresh: 604_800,
            retry: 86_400,
            expire: 2_419_200,
            minimum: SOA_TTL,
        },
    ));
    clear_ad(&mut message);
    Synth {
        message,
        ede: None,
        origin: AnswerOrigin::LocalClient,
    }
}

/// Response header and question; `rd` mirrors the client's RD bit.
fn response_skeleton(query: &Query, rd: bool) -> Message {
    Message {
        header: Header {
            id: 0,
            qr: true,
            rd,
            ..Header::default()
        },
        questions: vec![Question {
            name: query.name.clone(),
            qtype: query.qtype,
            qclass: query.qclass,
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
        edns: None,
    }
}

/// Wire HINFO RDATA: length-prefixed CPU `RFC8482` and empty OS.
fn hinfo_rfc8482() -> RData {
    let cpu = b"RFC8482";
    let mut data = Vec::with_capacity(2 + cpu.len());
    data.push(u8::try_from(cpu.len()).unwrap_or(0));
    data.extend_from_slice(cpu);
    data.push(0);
    RData::Unknown {
        rtype: HINFO,
        data: data.into(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use dnscraft_proto::Name;

    #[test]
    fn engine_any_synth_is_hinfo_noerror() {
        let q = Query {
            name: Name::from_ascii("example.com").unwrap(),
            qtype: RecordType::ANY,
            qclass: Class::IN,
        };
        let s = any_rfc8482(&q, true);
        assert_eq!(s.message.rcode(), Rcode::NOERROR);
        assert!(!s.message.header.ad);
        assert_eq!(s.message.header.id, 0);
        assert_eq!(s.message.answers.len(), 1);
        assert_eq!(s.message.answers[0].rtype(), HINFO);
        assert_eq!(s.origin, AnswerOrigin::SynthAny);
    }

    #[test]
    fn synth_mirrors_client_rd() {
        let q = Query {
            name: Name::from_ascii("example.com").unwrap(),
            qtype: RecordType::A,
            qclass: Class::IN,
        };
        for rd in [true, false] {
            assert_eq!(any_rfc8482(&q, rd).message.header.rd, rd);
            assert_eq!(resolve_servfail(&q, rd).message.header.rd, rd);
            assert_eq!(
                local_records_answer(&q, rd, Vec::new()).message.header.rd,
                rd
            );
            assert_eq!(local_nodata(&q, rd).message.header.rd, rd);
            assert_eq!(directory_nodata(&q, rd).message.header.rd, rd);
            assert_eq!(
                special_use_nxdomain(&q, rd, &Name::from_ascii("lan").unwrap())
                    .message
                    .header
                    .rd,
                rd
            );
            assert_eq!(bypass_nxdomain(&q, rd).message.header.rd, rd);
            assert_eq!(filter_internal_servfail(&q, rd).message.header.rd, rd);
        }
    }

    #[test]
    fn bypass_nxdomain_clears_ad_no_ede() {
        let q = Query {
            name: Name::from_ascii("use-application-dns.net").unwrap(),
            qtype: RecordType::A,
            qclass: Class::IN,
        };
        let s = bypass_nxdomain(&q, true);
        assert_eq!(s.message.rcode(), Rcode::NXDOMAIN);
        assert!(s.message.header.aa);
        assert!(!s.message.header.ad);
        assert!(s.ede.is_none());
        assert!(s.message.answers.is_empty());
        assert_eq!(s.origin, AnswerOrigin::Bypass);
    }

    #[test]
    fn special_use_nxdomain_has_soa_no_ede() {
        let q = Query {
            name: Name::from_ascii("printer.lan").unwrap(),
            qtype: RecordType::A,
            qclass: Class::IN,
        };
        let zone = Name::from_ascii("lan").unwrap();
        let s = special_use_nxdomain(&q, true, &zone);
        assert_eq!(s.message.rcode(), Rcode::NXDOMAIN);
        assert!(s.message.header.aa);
        assert!(!s.message.header.ad);
        assert!(s.ede.is_none());
        assert_eq!(s.message.authorities.len(), 1);
        assert_eq!(s.message.authorities[0].rtype(), RecordType::SOA);
        assert_eq!(s.origin, AnswerOrigin::LocalClient);
    }
}
