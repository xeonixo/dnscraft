use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::dnssec::Nsec3HashAlgorithm;
use hickory_proto::dnssec::rdata::DNSSECRData;
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
    chain: Option<DenialChain>,
}

/// Denial-of-existence data of a signed zone, used by the responder to pick
/// the NSEC or NSEC3 records that prove a negative answer.
#[derive(Clone, Debug)]
pub(crate) enum DenialChain {
    /// NSEC chain; the records live in the zone's record list.
    Nsec,
    /// NSEC3 chain with its parameters and the sorted hash to owner mapping.
    Nsec3 {
        salt: Vec<u8>,
        iterations: u16,
        /// `(hash, owner)` sorted by hash.
        hashes: Vec<(Vec<u8>, Name)>,
    },
}

impl DenialChain {
    /// NSEC3 hash of `name` under this chain's parameters (`None` for NSEC).
    pub(crate) fn hash(&self, name: &Name) -> Option<Vec<u8>> {
        match self {
            Self::Nsec => None,
            Self::Nsec3 {
                salt, iterations, ..
            } => Nsec3HashAlgorithm::SHA1
                .hash(salt, name, *iterations)
                .ok()
                .map(|d| d.as_ref().to_vec()),
        }
    }

    /// Owner of the NSEC3 record whose hash equals `hash`.
    pub(crate) fn nsec3_match(&self, hash: &[u8]) -> Option<&Name> {
        match self {
            Self::Nsec3 { hashes, .. } => hashes
                .iter()
                .find(|(h, _)| h.as_slice() == hash)
                .map(|(_, n)| n),
            Self::Nsec => None,
        }
    }

    /// Owner of the NSEC3 record whose interval covers `hash`.
    pub(crate) fn nsec3_cover(&self, hash: &[u8]) -> Option<&Name> {
        match self {
            Self::Nsec3 { hashes, .. } => {
                let idx = hashes.partition_point(|(h, _)| h.as_slice() < hash);
                let pick = if idx == 0 {
                    hashes.last()
                } else {
                    hashes.get(idx - 1)
                };
                pick.map(|(_, n)| n)
            }
            Self::Nsec => None,
        }
    }
}

impl Zone {
    /// Creates an empty zone for `origin` (for example `"example.test."`).
    pub fn new(origin: &str) -> Result<Self, TestkitError> {
        Ok(Self {
            origin: parse_name(origin)?,
            records: Vec::new(),
            chain: None,
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

    /// Whether the zone has been signed (see [`sign_zone`](crate::sign_zone)).
    pub fn is_signed(&self) -> bool {
        self.chain.is_some()
    }

    pub(crate) fn chain(&self) -> Option<&DenialChain> {
        self.chain.as_ref()
    }

    pub(crate) fn with_chain(mut self, chain: DenialChain) -> Self {
        self.chain = Some(chain);
        self
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

impl Zone {
    /// RRSIG records at `name` covering `rtype`.
    pub(crate) fn sigs(&self, name: &Name, rtype: RecordType) -> Vec<Record> {
        self.records
            .iter()
            .filter(|r| r.name == *name && rrsig_covered(r) == Some(rtype))
            .cloned()
            .collect()
    }

    /// Whether `name` itself owns at least one record.
    pub(crate) fn has_records(&self, name: &Name) -> bool {
        self.records.iter().any(|r| r.name == *name)
    }

    /// The longest existing proper ancestor of `qname` (at worst the origin).
    pub(crate) fn closest_encloser(&self, qname: &Name) -> Name {
        let mut candidate = qname.base_name();
        while candidate != self.origin && !self.name_exists(&candidate) {
            candidate = candidate.base_name();
        }
        candidate
    }

    /// Owner of the NSEC record that matches or covers `name`.
    pub(crate) fn nsec_covering(&self, name: &Name) -> Option<Name> {
        let mut owners: Vec<&Name> = self
            .records
            .iter()
            .filter(|r| r.record_type() == RecordType::NSEC)
            .map(|r| &r.name)
            .collect();
        owners.sort();
        owners.dedup();
        owners
            .iter()
            .rev()
            .find(|owner| ***owner <= *name)
            .or(owners.last())
            .map(|owner| (*owner).clone())
    }
}

/// The type an RRSIG record covers (`None` for other record types).
pub(crate) fn rrsig_covered(record: &Record) -> Option<RecordType> {
    match &record.data {
        RData::DNSSEC(DNSSECRData::RRSIG(sig)) => Some(sig.input().type_covered),
        _ => None,
    }
}
