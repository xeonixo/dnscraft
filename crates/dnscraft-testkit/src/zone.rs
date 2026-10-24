use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::rr::rdata::{A, AAAA, NS, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::TestkitError;

/// Default TTL of records created through the [`Zone`] builder.
const DEFAULT_TTL: u32 = 300;

/// Parses an absolute domain name.
pub fn parse_name(text: &str) -> Result<Name, TestkitError> {
    Name::from_ascii(text).map_err(|source| TestkitError::InvalidName {
        name: text.to_owned(),
        source,
    })
}

/// A zone: an origin plus a flat list of structured resource records.
///
/// Records are stored as `hickory_proto` [`Record`] values (not text), so
/// later work can add DNSSEC records and signatures. Delegations are NS
/// records owned by a name below the origin; glue is any address record owned
/// by an NS target below that cut.
///
/// All owner names passed to the builder methods must be fully qualified.
#[derive(Clone, Debug)]
pub struct Zone {
    origin: Name,
    records: Vec<Record>,
}

impl Zone {
    /// Creates an empty zone for `origin` (for example `"example.test."`).
    pub fn new(origin: &str) -> Result<Self, TestkitError> {
        Ok(Self {
            origin: parse_name(origin)?,
            records: Vec::new(),
        })
    }

    /// The zone origin.
    pub fn origin(&self) -> &Name {
        &self.origin
    }

    /// All records of the zone.
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Adds an arbitrary record.
    pub fn with_record(mut self, record: Record) -> Self {
        self.records.push(record);
        self
    }

    /// Adds a SOA record at the origin with fixed, test-friendly timers.
    pub fn with_soa(self, mname: &str, rname: &str) -> Result<Self, TestkitError> {
        let soa = SOA::new(
            parse_name(mname)?,
            parse_name(rname)?,
            1,
            3600,
            600,
            86400,
            60,
        );
        let origin = self.origin.clone();
        Ok(self.with_record(Record::from_rdata(origin, DEFAULT_TTL, RData::SOA(soa))))
    }

    /// Adds an NS record: `owner NS target`. Use it at the origin for the
    /// zone's own name servers, or below the origin to create a delegation.
    pub fn with_ns(self, owner: &str, target: &str) -> Result<Self, TestkitError> {
        let rdata = RData::NS(NS(parse_name(target)?));
        Ok(self.with_record(Record::from_rdata(parse_name(owner)?, DEFAULT_TTL, rdata)))
    }

    /// Adds an A record.
    pub fn with_a(self, owner: &str, addr: Ipv4Addr) -> Result<Self, TestkitError> {
        let rdata = RData::A(A(addr));
        Ok(self.with_record(Record::from_rdata(parse_name(owner)?, DEFAULT_TTL, rdata)))
    }

    /// Adds an AAAA record.
    pub fn with_aaaa(self, owner: &str, addr: Ipv6Addr) -> Result<Self, TestkitError> {
        let rdata = RData::AAAA(AAAA(addr));
        Ok(self.with_record(Record::from_rdata(parse_name(owner)?, DEFAULT_TTL, rdata)))
    }

    /// The SOA record at the origin, if present.
    pub(crate) fn soa(&self) -> Option<&Record> {
        self.records
            .iter()
            .find(|r| r.record_type() == RecordType::SOA && r.name == self.origin)
    }

    /// Finds the delegation point covering `qname`, if any: the shallowest NS
    /// owner strictly below the origin that is an ancestor of (or equal to)
    /// `qname`.
    pub(crate) fn delegation_for(&self, qname: &Name) -> Option<Name> {
        self.records
            .iter()
            .filter(|r| r.record_type() == RecordType::NS)
            .filter(|r| r.name != self.origin && r.name.zone_of(qname))
            .map(|r| r.name.clone())
            .min_by_key(Name::num_labels)
    }

    /// Records owned by `name` with the given type.
    pub(crate) fn rrset<'a>(
        &'a self,
        name: &'a Name,
        rtype: RecordType,
    ) -> impl Iterator<Item = &'a Record> + 'a {
        self.records
            .iter()
            .filter(move |r| r.name == *name && r.record_type() == rtype)
    }

    /// Whether `name` owns records or has descendants that do (empty non-terminal).
    pub(crate) fn name_exists(&self, name: &Name) -> bool {
        self.records.iter().any(|r| name.zone_of(&r.name))
    }
}
