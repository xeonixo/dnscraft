//! Complete DNS messages: questions, record sections and EDNS.

use crate::edns::Edns;
use crate::error::ProtoError;
use crate::header::{Counts, HEADER_LEN, Header, Opcode, Rcode};
use crate::name::{CompressionMap, Name};
use crate::rdata::Reader;
use crate::record::Record;
use crate::rtype::{Class, RecordType};

/// Smallest possible question: root name plus QTYPE and QCLASS.
const MIN_QUESTION: usize = 5;
/// Smallest possible record: root name plus TYPE, CLASS, TTL and RDLENGTH.
const MIN_RECORD: usize = 11;
/// EDNS payload size used when `set_rcode` has to create the OPT record.
const DEFAULT_EDNS_PAYLOAD: u16 = 1232;

/// An entry of the question section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    /// Name being asked about.
    pub name: Name,
    /// Requested record type.
    pub qtype: RecordType,
    /// Requested class.
    pub qclass: Class,
}

impl Question {
    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let name = r.name()?;
        let qtype = RecordType(r.u16()?);
        let qclass = Class(r.u16()?);
        Ok(Self {
            name,
            qtype,
            qclass,
        })
    }

    fn encode(&self, buf: &mut Vec<u8>, map: &mut CompressionMap) {
        self.name.encode(buf, Some(map));
        buf.extend_from_slice(&self.qtype.value().to_be_bytes());
        buf.extend_from_slice(&self.qclass.value().to_be_bytes());
    }
}

/// A DNS message.
///
/// The OPT pseudo-record is not part of `additionals`; it is exposed as
/// `edns`. The header carries only the low 4 bits of the response code, use
/// [`Message::rcode`] and [`Message::set_rcode`] for the combined value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Header flags and the low response code bits.
    pub header: Header,
    /// Question section.
    pub questions: Vec<Question>,
    /// Answer section.
    pub answers: Vec<Record>,
    /// Authority section.
    pub authorities: Vec<Record>,
    /// Additional section, without the OPT record.
    pub additionals: Vec<Record>,
    /// EDNS data, if the message carries an OPT record.
    pub edns: Option<Edns>,
}

impl Message {
    /// A recursive query (RD set) for `name` and `qtype` in class IN, without
    /// EDNS; set [`Message::edns`] to add it.
    pub fn query(id: u16, name: Name, qtype: RecordType) -> Self {
        Self {
            header: Header {
                id,
                rd: true,
                ..Header::default()
            },
            questions: vec![Question {
                name,
                qtype,
                qclass: Class::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        }
    }

    /// An empty response to `query`: copies id, opcode, questions, RD and CD,
    /// and sets QR. No EDNS, records or other flags are copied.
    pub fn response_to(query: &Self) -> Self {
        Self {
            header: Header {
                id: query.header.id,
                qr: true,
                opcode: query.header.opcode,
                rd: query.header.rd,
                cd: query.header.cd,
                ..Header::default()
            },
            questions: query.questions.clone(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        }
    }

    /// The opcode.
    pub fn opcode(&self) -> Opcode {
        self.header.opcode
    }

    /// The full response code: header bits plus the extended bits of the OPT
    /// record (zero without EDNS).
    pub fn rcode(&self) -> Rcode {
        let high = self.edns.as_ref().map_or(0, |e| e.extended_rcode_high);
        Rcode::from_parts(self.header.rcode_low, high)
    }

    /// Sets the response code, splitting it between the header and the OPT
    /// record.
    ///
    /// Codes above 15 do not fit the header, so if the message has no EDNS
    /// data a default one (payload size 1232) is created automatically.
    /// Values above [`Rcode::MAX`] are rejected.
    pub fn set_rcode(&mut self, rcode: Rcode) -> Result<(), ProtoError> {
        if rcode.value() > Rcode::MAX {
            return Err(ProtoError::InvalidMessage {
                reason: "rcode exceeds 12 bits",
            });
        }
        if rcode.high() != 0 && self.edns.is_none() {
            self.edns = Some(Edns::new(DEFAULT_EDNS_PAYLOAD));
        }
        self.header.rcode_low = rcode.low();
        if let Some(edns) = self.edns.as_mut() {
            edns.extended_rcode_high = rcode.high();
        }
        Ok(())
    }

    /// Decodes a complete message.
    ///
    /// Section counts are checked against the remaining data before anything
    /// is allocated ([`ProtoError::CountsExceedData`]). A question count above
    /// one is accepted. The OPT record is taken out of the additional section
    /// (a second one is [`ProtoError::DuplicateOpt`]; one in the answer or
    /// authority section is [`ProtoError::MisplacedOpt`]). Octets after the
    /// last record are [`ProtoError::TrailingData`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let (header, counts) = Header::decode(bytes)?;
        let available = bytes.len().saturating_sub(HEADER_LEN);
        let needed = usize::from(counts.qd) * MIN_QUESTION
            + (usize::from(counts.an) + usize::from(counts.ns) + usize::from(counts.ar))
                * MIN_RECORD;
        if needed > available {
            return Err(ProtoError::CountsExceedData { needed, available });
        }
        let mut pos = HEADER_LEN;
        let mut questions = Vec::with_capacity(usize::from(counts.qd));
        for _ in 0..counts.qd {
            let mut r = Reader::new(bytes, pos);
            questions.push(Question::decode(&mut r)?);
            pos = r.pos();
        }
        let mut read_section =
            |count: u16, section: &'static str| -> Result<Vec<Record>, ProtoError> {
                let mut out = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    let (rec, next) = Record::decode(bytes, pos)?;
                    pos = next;
                    if rec.rtype == RecordType::OPT {
                        return Err(ProtoError::MisplacedOpt { section });
                    }
                    out.push(rec);
                }
                Ok(out)
            };
        let answers = read_section(counts.an, "answer")?;
        let authorities = read_section(counts.ns, "authority")?;
        let mut additionals = Vec::with_capacity(usize::from(counts.ar));
        let mut edns = None;
        for _ in 0..counts.ar {
            let (rec, next) = Record::decode(bytes, pos)?;
            pos = next;
            if rec.rtype == RecordType::OPT {
                if edns.is_some() {
                    return Err(ProtoError::DuplicateOpt);
                }
                edns = Some(Edns::from_record(&rec)?);
            } else {
                additionals.push(rec);
            }
        }
        if pos != bytes.len() {
            return Err(ProtoError::TrailingData {
                offset: pos,
                len: bytes.len().saturating_sub(pos),
            });
        }
        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
            edns,
        })
    }

    /// Encodes the message with name compression across all sections.
    ///
    /// The OPT record, if any, is written last in the additional section.
    /// Section counts are derived from the section lengths; more than 65535
    /// entries, or an OPT record inside a record section, is an error.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let opt = self.edns.as_ref().map(Edns::to_record).transpose()?;
        encode_parts(
            &self.header,
            &self.questions,
            [
                &self.answers.iter().collect::<Vec<_>>(),
                &self.authorities.iter().collect::<Vec<_>>(),
                &self.additionals.iter().collect::<Vec<_>>(),
            ],
            opt.as_ref(),
        )
    }

    /// Encodes the message into at most `max` octets, truncating cleanly.
    ///
    /// If the full encoding fits it is returned unchanged. Otherwise whole
    /// RRsets (all records of one name, type and class within a section) are
    /// dropped from the end: additional records first, then authority, then
    /// answer, one RRset at a time until the message fits. TC is set when any
    /// answer or authority RRset was dropped. Dropping only additional
    /// records does not set TC, since additional data is optional
    /// (RFC 2181 section 9). Header, questions and OPT are always kept; if
    /// they alone exceed `max`, [`ProtoError::LimitTooSmall`] is returned.
    pub fn encode_with_limit(&self, max: usize) -> Result<Vec<u8>, ProtoError> {
        let opt = self.edns.as_ref().map(Edns::to_record).transpose()?;
        let mut header = self.header;
        let mut sections: [Vec<&Record>; 3] = [
            self.answers.iter().collect(),
            self.authorities.iter().collect(),
            self.additionals.iter().collect(),
        ];
        loop {
            let out = encode_parts(
                &header,
                &self.questions,
                [&sections[0], &sections[1], &sections[2]],
                opt.as_ref(),
            )?;
            if out.len() <= max {
                return Ok(out);
            }
            let Some(idx) = [2usize, 1, 0]
                .into_iter()
                .find(|&i| sections.get(i).is_some_and(|s| !s.is_empty()))
            else {
                return Err(ProtoError::LimitTooSmall {
                    limit: max,
                    needed: out.len(),
                });
            };
            if let Some(section) = sections.get_mut(idx) {
                if let Some(last) = section.last().copied() {
                    section.retain(|r| {
                        !(r.name == last.name && r.rtype == last.rtype && r.class == last.class)
                    });
                }
            }
            if idx < 2 {
                header.tc = true;
            }
        }
    }
}

fn count(len: usize) -> Result<u16, ProtoError> {
    u16::try_from(len).map_err(|_| ProtoError::InvalidMessage {
        reason: "section has more than 65535 entries",
    })
}

fn encode_parts(
    header: &Header,
    questions: &[Question],
    sections: [&[&Record]; 3],
    opt: Option<&Record>,
) -> Result<Vec<u8>, ProtoError> {
    let [answers, authorities, additionals] = sections;
    let counts = Counts {
        qd: count(questions.len())?,
        an: count(answers.len())?,
        ns: count(authorities.len())?,
        ar: count(additionals.len() + usize::from(opt.is_some()))?,
    };
    let mut buf = Vec::with_capacity(512);
    header.encode(&mut buf, counts);
    let mut map = CompressionMap::new();
    for q in questions {
        q.encode(&mut buf, &mut map);
    }
    for rec in answers.iter().chain(authorities).chain(additionals) {
        if rec.rtype == RecordType::OPT {
            return Err(ProtoError::InvalidMessage {
                reason: "OPT record in a record section; use Message::edns",
            });
        }
        rec.encode(&mut buf, Some(&mut map))?;
    }
    if let Some(opt) = opt {
        opt.encode(&mut buf, Some(&mut map))?;
    }
    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::edns::EdnsOption;
    use crate::rdata::RData;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).expect("name")
    }

    fn a(name: &str, last: u8) -> Record {
        Record {
            name: n(name),
            rtype: RecordType::A,
            class: Class::IN,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, last)),
        }
    }

    fn txt(name: &str) -> Record {
        Record {
            name: n(name),
            rtype: RecordType::TXT,
            class: Class::IN,
            ttl: 60,
            rdata: RData::TXT(vec![b"hello".to_vec().into()]),
        }
    }

    fn full() -> Message {
        let q = Message::query(0x1234, n("www.example.com."), RecordType::A);
        let mut m = Message::response_to(&q);
        m.header.aa = true;
        m.header.ra = true;
        m.answers.push(a("www.example.com.", 1));
        m.answers.push(a("www.example.com.", 2));
        m.authorities.push(Record {
            name: n("example.com."),
            rtype: RecordType::NS,
            class: Class::IN,
            ttl: 300,
            rdata: RData::NS(n("ns1.example.com.")),
        });
        m.additionals.push(a("ns1.example.com.", 53));
        let mut e = Edns::new(1232);
        e.dnssec_ok = true;
        e.options.push(EdnsOption::Padding(8));
        m.edns = Some(e);
        m
    }

    #[test]
    fn full_message_round_trips_and_compresses() {
        let m = full();
        let bytes = m.encode().unwrap();
        assert_eq!(Message::decode(&bytes).unwrap(), m);
        let mut plain = Vec::new();
        for r in m.answers.iter().chain(&m.authorities).chain(&m.additionals) {
            r.encode(&mut plain, None).unwrap();
        }
        assert!(bytes.len() < 12 + 21 + plain.len() + 11 + 12);
    }

    #[test]
    fn builders() {
        let q = Message::query(7, n("a."), RecordType::AAAA);
        assert!(q.header.rd && !q.header.qr);
        assert_eq!(q.questions[0].qclass, Class::IN);
        let mut q2 = q.clone();
        q2.header.cd = true;
        q2.header.opcode = Opcode::NOTIFY;
        q2.header.ad = true;
        let r = Message::response_to(&q2);
        assert!(r.header.qr && r.header.rd && r.header.cd && !r.header.ad);
        assert_eq!(r.header.id, 7);
        assert_eq!(r.opcode(), Opcode::NOTIFY);
        assert_eq!(r.questions, q2.questions);
    }

    #[test]
    fn rcode_split_merge_and_badvers() {
        let mut m = Message::query(1, n("a."), RecordType::A);
        m.set_rcode(Rcode::NXDOMAIN).unwrap();
        assert_eq!(m.rcode(), Rcode::NXDOMAIN);
        assert!(m.edns.is_none());
        m.set_rcode(Rcode::BADVERS).unwrap();
        assert_eq!(m.header.rcode_low, 0);
        assert_eq!(m.edns.as_ref().unwrap().extended_rcode_high, 1);
        assert_eq!(m.rcode(), Rcode::BADVERS);
        let back = Message::decode(&m.encode().unwrap()).unwrap();
        assert_eq!(back.rcode(), Rcode::BADVERS);
        m.set_rcode(Rcode::BADCOOKIE).unwrap();
        assert_eq!(m.rcode(), Rcode::BADCOOKIE);
        m.set_rcode(Rcode::REFUSED).unwrap();
        assert_eq!(m.rcode(), Rcode::REFUSED);
        assert!(m.set_rcode(Rcode(0x1000)).is_err());
    }

    fn with_counts(mut bytes: Vec<u8>, counts: [u16; 4]) -> Vec<u8> {
        for (i, c) in counts.iter().enumerate() {
            bytes[4 + i * 2..6 + i * 2].copy_from_slice(&c.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn counts_exceeding_data_are_rejected_early() {
        let mut bytes = vec![0u8; 12];
        bytes.extend_from_slice(&[0; 8]);
        let bytes = with_counts(bytes, [0, 65535, 0, 0]);
        assert!(matches!(
            Message::decode(&bytes),
            Err(ProtoError::CountsExceedData { .. })
        ));
        let bytes = with_counts(vec![0u8; 20], [65535, 0, 0, 0]);
        let err = Message::decode(&bytes).unwrap_err();
        assert_eq!(err.code(), "proto.counts_exceed_data");
    }

    #[test]
    fn trailing_garbage_is_rejected() {
        let mut bytes = full().encode().unwrap();
        bytes.push(0);
        assert!(matches!(
            Message::decode(&bytes),
            Err(ProtoError::TrailingData { len: 1, .. })
        ));
    }

    #[test]
    fn duplicate_opt_and_misplaced_opt() {
        let m = full();
        let mut bytes = m.encode().unwrap();
        let opt = m.edns.as_ref().unwrap().to_record().unwrap();
        opt.encode(&mut bytes, None).unwrap();
        let ar = u16::from_be_bytes([bytes[10], bytes[11]]) + 1;
        bytes[10..12].copy_from_slice(&ar.to_be_bytes());
        assert_eq!(Message::decode(&bytes), Err(ProtoError::DuplicateOpt));

        let mut head = Vec::new();
        Header::default().encode(
            &mut head,
            Counts {
                an: 1,
                ..Counts::default()
            },
        );
        opt.encode(&mut head, None).unwrap();
        assert_eq!(
            Message::decode(&head),
            Err(ProtoError::MisplacedOpt { section: "answer" })
        );
        let mut head = Vec::new();
        Header::default().encode(
            &mut head,
            Counts {
                ns: 1,
                ..Counts::default()
            },
        );
        opt.encode(&mut head, None).unwrap();
        assert_eq!(
            Message::decode(&head),
            Err(ProtoError::MisplacedOpt {
                section: "authority"
            })
        );
    }

    #[test]
    fn opt_with_non_root_owner_is_rejected() {
        let mut bytes = Vec::new();
        Header::default().encode(
            &mut bytes,
            Counts {
                ar: 1,
                ..Counts::default()
            },
        );
        let mut opt = Edns::new(512).to_record().unwrap();
        opt.name = n("x.");
        opt.encode(&mut bytes, None).unwrap();
        assert_eq!(Message::decode(&bytes), Err(ProtoError::OptOwnerNotRoot));
    }

    #[test]
    fn every_prefix_is_an_error() {
        let bytes = full().encode().unwrap();
        for cut in 0..bytes.len() {
            assert!(Message::decode(&bytes[..cut]).is_err(), "cut {cut}");
        }
        assert!(Message::decode(&bytes).is_ok());
    }

    #[test]
    fn multiple_questions_are_accepted() {
        let mut m = Message::query(1, n("a."), RecordType::A);
        m.questions.push(Question {
            name: n("b."),
            qtype: RecordType::MX,
            qclass: Class::IN,
        });
        let back = Message::decode(&m.encode().unwrap()).unwrap();
        assert_eq!(back.questions.len(), 2);
    }

    #[test]
    fn opt_in_record_section_fails_encode() {
        let mut m = full();
        m.additionals
            .push(m.edns.as_ref().unwrap().to_record().unwrap());
        assert!(m.encode().is_err());
    }

    fn big_response() -> Message {
        let q = Message::query(9, n("big.example.com."), RecordType::A);
        let mut m = Message::response_to(&q);
        m.answers.push(txt("big.example.com."));
        for i in 0..=255u8 {
            m.answers.push(a("big.example.com.", i));
        }
        m.authorities.push(Record {
            name: n("example.com."),
            rtype: RecordType::NS,
            class: Class::IN,
            ttl: 1,
            rdata: RData::NS(n("ns1.example.com.")),
        });
        m.additionals.push(a("ns1.example.com.", 1));
        m.edns = Some(Edns::new(1232));
        m
    }

    #[test]
    fn limit_drops_whole_rrsets_and_sets_tc() {
        let m = big_response();
        assert!(m.encode().unwrap().len() > 512);
        let bytes = m.encode_with_limit(512).unwrap();
        assert!(bytes.len() <= 512);
        let got = Message::decode(&bytes).unwrap();
        assert!(got.header.tc);
        assert!(got.edns.is_some());
        assert_eq!(got.questions, m.questions);
        assert!(got.additionals.is_empty() && got.authorities.is_empty());
        // The 256-record A RRset (last) is dropped whole; the earlier TXT
        // RRset survives.
        assert!(got.answers.iter().all(|r| r.rtype != RecordType::A));
        assert_eq!(got.answers.len(), 1);
        // Never splits: for every limit the A records are all or nothing.
        for max in (60..m.encode().unwrap().len()).step_by(37) {
            if let Ok(b) = m.encode_with_limit(max) {
                assert!(b.len() <= max);
                let g = Message::decode(&b).unwrap();
                let na = g
                    .answers
                    .iter()
                    .filter(|r| r.rtype == RecordType::A)
                    .count();
                assert!(na == 0 || na == 256, "split at {max}: {na}");
                assert!(g.edns.is_some());
            }
        }
    }

    #[test]
    fn limit_that_fits_changes_nothing() {
        let m = big_response();
        let full = m.encode().unwrap();
        assert_eq!(m.encode_with_limit(full.len()).unwrap(), full);
        assert!(!Message::decode(&full).unwrap().header.tc);
    }

    #[test]
    fn dropping_only_additionals_keeps_tc_clear() {
        let mut m = full();
        for i in 0..40u8 {
            m.additionals.push(a(&format!("glue{i}.example.com."), i));
        }
        let full_len = m.encode().unwrap().len();
        let bytes = m.encode_with_limit(full_len - 20).unwrap();
        let got = Message::decode(&bytes).unwrap();
        assert!(!got.header.tc);
        assert_eq!(got.answers, m.answers);
        assert_eq!(got.authorities, m.authorities);
        assert!(got.additionals.len() < m.additionals.len());
        assert!(got.edns.is_some());
    }

    #[test]
    fn limit_below_minimum_is_an_error() {
        let m = full();
        assert!(matches!(
            m.encode_with_limit(20),
            Err(ProtoError::LimitTooSmall { limit: 20, .. })
        ));
        // Header + question + OPT exactly fits.
        let mut bare = m.clone();
        bare.answers.clear();
        bare.authorities.clear();
        bare.additionals.clear();
        let min = bare.encode().unwrap().len();
        let got = Message::decode(&m.encode_with_limit(min).unwrap()).unwrap();
        assert!(got.header.tc);
        assert_eq!(got.questions, m.questions);
        assert_eq!(got.edns, m.edns);
    }
}
