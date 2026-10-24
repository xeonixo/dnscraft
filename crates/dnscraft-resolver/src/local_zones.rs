//! Locally served private zones (RFC 6303 section 4, RFC 8375 `home.arpa.`).
//!
//! Queries below these zones never leave the host. They are answered locally
//! with NXDOMAIN (NODATA at the apex) and a synthesized SOA (RFC 6303
//! section 3), unless a forward zone is equal to, inside, or covers the local
//! zone, in which case the query takes the normal resolution path.

use dnscraft_proto::{
    Class, EdnsOption, Header, Message, Name, Question, RData, Rcode, Record, RecordType,
};

use crate::types::{Answer, AnswerSource, DnssecStatus, Query};

/// TTL of the synthesized SOA and NS records (RFC 6303 section 3: negative
/// caching TTL of 3 hours).
const LOCAL_TTL: u32 = 10800;

/// Fixed built-in zones in presentation format. The 16.172 … 31.172 reverse
/// zones and the two full-length IPv6 zones are generated in `rfc6303`.
const FIXED_ZONES: &[&str] = &[
    "10.in-addr.arpa.",
    "168.192.in-addr.arpa.",
    "0.in-addr.arpa.",
    "127.in-addr.arpa.",
    "254.169.in-addr.arpa.",
    "2.0.192.in-addr.arpa.",
    "100.51.198.in-addr.arpa.",
    "113.0.203.in-addr.arpa.",
    "255.255.255.255.in-addr.arpa.",
    "d.f.ip6.arpa.",
    "8.e.f.ip6.arpa.",
    "9.e.f.ip6.arpa.",
    "a.e.f.ip6.arpa.",
    "b.e.f.ip6.arpa.",
    "8.b.d.0.1.0.0.2.ip6.arpa.",
    "home.arpa.",
];

/// Set of locally served zones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalZones {
    zones: Vec<Name>,
}

impl LocalZones {
    /// The zones listed in RFC 6303 section 4, plus `home.arpa.` (RFC 8375).
    pub fn rfc6303() -> Self {
        let mut text: Vec<String> = FIXED_ZONES.iter().map(|z| (*z).to_owned()).collect();
        text.extend((16..=31).map(|second| format!("{second}.172.in-addr.arpa.")));
        // `::` and `::1` reverse names: 32 nibbles each.
        text.push(format!("{}ip6.arpa.", "0.".repeat(32)));
        text.push(format!("1.{}ip6.arpa.", "0.".repeat(31)));
        let zones = text
            .iter()
            .filter_map(|t| Name::from_ascii(t).ok())
            .collect();
        Self { zones }
    }

    /// The local zones currently in the set.
    pub fn zones(&self) -> &[Name] {
        &self.zones
    }

    /// Removes every built-in zone that is equal to, below, or above `zone`.
    pub fn without(&mut self, zone: &Name) {
        self.zones.retain(|z| !(z.zone_of(zone) || zone.zone_of(z)));
    }

    /// True if a forward zone is equal to or inside `local`, or covers it.
    pub fn is_overridden_by<'a>(
        &self,
        local: &Name,
        forward_zones: impl IntoIterator<Item = &'a Name>,
    ) -> bool {
        forward_zones
            .into_iter()
            .any(|f| local.zone_of(f) || f.zone_of(local))
    }

    /// The most specific local zone containing `name`, if any.
    fn zone_for(&self, name: &Name) -> Option<&Name> {
        self.zones
            .iter()
            .filter(|z| z.zone_of(name))
            .max_by_key(|z| z.label_count())
    }

    /// Answers `query` locally, or returns `None` if the query is not in a
    /// local zone, the zone is overridden by a forward zone, or the class is
    /// not IN.
    ///
    /// Local answers carry the AA bit, use `DnssecStatus::Insecure` and
    /// `AnswerSource::Recursion` (there is no dedicated local source). The
    /// message id is 0; the caller must copy the id of the client request.
    pub fn answer<'a>(
        &self,
        query: &Query,
        forward_zones: impl IntoIterator<Item = &'a Name>,
    ) -> Option<Answer> {
        if query.qclass != Class::IN {
            return None;
        }
        let zone = self.zone_for(&query.name)?;
        if self.is_overridden_by(zone, forward_zones) {
            return None;
        }
        let rname = Name::from_ascii("nobody.invalid.").ok()?;
        let soa = soa_record(zone, &rname);

        let mut message = Message {
            header: Header {
                qr: true,
                aa: true,
                rcode_low: Rcode::NOERROR.low(),
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
        };

        if query.name != *zone {
            message.header.rcode_low = Rcode::NXDOMAIN.low();
            message.authorities.push(soa);
        } else {
            let ns = Record {
                name: zone.clone(),
                rtype: RecordType::NS,
                class: Class::IN,
                ttl: LOCAL_TTL,
                rdata: RData::NS(Name::from_ascii("localhost.").ok()?),
            };
            match query.qtype {
                RecordType::SOA => message.answers.push(soa),
                RecordType::NS => message.answers.push(ns),
                RecordType::ANY => {
                    message.answers.push(soa);
                    message.answers.push(ns);
                }
                // The name exists (it is the apex) but has no such type.
                _ => message.authorities.push(soa),
            }
        }

        Some(Answer {
            message,
            dnssec: DnssecStatus::Insecure,
            source: AnswerSource::Recursion,
            ede: None,
        })
    }
}

/// Removes every EDNS Client Subnet option from `msg`; other options are kept.
pub fn strip_client_subnet(msg: &mut Message) {
    if let Some(edns) = msg.edns.as_mut() {
        edns.options
            .retain(|opt| !matches!(opt, EdnsOption::ClientSubnet { .. }));
    }
}

/// The synthesized SOA of RFC 6303 section 3.
fn soa_record(zone: &Name, rname: &Name) -> Record {
    Record {
        name: zone.clone(),
        rtype: RecordType::SOA,
        class: Class::IN,
        ttl: LOCAL_TTL,
        rdata: RData::SOA {
            mname: zone.clone(),
            rname: rname.clone(),
            serial: 1,
            refresh: 604_800,
            retry: 86_400,
            expire: 2_419_200,
            minimum: LOCAL_TTL,
        },
    }
}
