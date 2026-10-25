//! Synthesised DNS answers (ANY, SERVFAIL, and later block/local answers).

use dnscraft_proto::{Class, Header, Message, Question, RData, Rcode, Record, RecordType};
use dnscraft_resolver::Query;

use crate::decision::AnswerOrigin;
use crate::pipeline::{Synth, clear_ad};

/// HINFO type number (RFC 1035); not a first-class [`RData`] variant.
const HINFO: RecordType = RecordType(13);

/// Minimal RFC 8482 answer: NOERROR with one HINFO (`CPU=RFC8482`, empty OS).
///
/// Does not recurse and clears AD.
pub fn any_rfc8482(query: &Query) -> Synth {
    let mut message = response_skeleton(query);
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
pub fn resolve_servfail(query: &Query) -> Synth {
    let mut message = response_skeleton(query);
    message.header.ra = true;
    let _ = message.set_rcode(Rcode::SERVFAIL);
    clear_ad(&mut message);
    Synth {
        message,
        ede: None,
        origin: AnswerOrigin::ResolveError,
    }
}

fn response_skeleton(query: &Query) -> Message {
    Message {
        header: Header {
            id: 0,
            qr: true,
            rd: true,
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
        let s = any_rfc8482(&q);
        assert_eq!(s.message.rcode(), Rcode::NOERROR);
        assert!(!s.message.header.ad);
        assert_eq!(s.message.header.id, 0);
        assert_eq!(s.message.answers.len(), 1);
        assert_eq!(s.message.answers[0].rtype(), HINFO);
        assert_eq!(s.origin, AnswerOrigin::SynthAny);
    }
}
