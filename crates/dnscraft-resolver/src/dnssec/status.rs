//! Validation state carried through an iteration and its mapping to the
//! public [`DnssecStatus`] (Task 9b).
//!
//! Everything here is pure; the DNSKEY fetches live in `walk.rs`.
//!
//! Status lattice for one answer (weakest wins): `Bogus` > `Insecure` >
//! `Indeterminate` > `Secure`. Only `Secure` sets the AD bit.

use std::time::SystemTime;

use dnscraft_proto::dnssec::{MAX_ITERATIONS_DEFAULT, base32hex_decode, nsec3_hash};
use dnscraft_proto::{Name, RData, Record, RecordType};

use super::{ChainFailure, DsStatus, ValidatedKeys, VerifyFailure, ds_status, validate_rrset};
use crate::types::DnssecStatus;

/// NSEC3 opt-out flag (RFC 5155 section 3.1.2).
const NSEC3_OPT_OUT: u8 = 0x01;

/// Why an answer is bogus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BogusReason {
    /// Establishing the DNSKEY RRset of a zone failed.
    Chain(ChainFailure),
    /// An RRset did not validate.
    Verify(VerifyFailure),
    /// No server delivered the DNSKEY RRset of a zone that has a DS.
    DnskeyUnavailable,
    /// A referral without DS came with no valid proof that there is none.
    NoDsProof,
}

impl BogusReason {
    /// Stable, locale-neutral code (used as EXTRA-TEXT of the EDE).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Chain(c) => c.code(),
            Self::Verify(v) => v.code(),
            Self::DnskeyUnavailable => "dnssec.dnskey_unavailable",
            Self::NoDsProof => "dnssec.no_ds_proof",
        }
    }

    /// RFC 8914 INFO-CODE.
    pub fn ede_code(&self) -> u16 {
        match self {
            Self::Chain(c) => c.ede_code(),
            Self::Verify(v) => v.ede_code(),
            // 9 DNSKEY Missing
            Self::DnskeyUnavailable => 9,
            // 12 NSEC Missing
            Self::NoDsProof => 12,
        }
    }
}

/// How far a zone is trusted while following referrals.
#[derive(Clone, Debug)]
pub(crate) enum Trust {
    /// Validation is off (CD bit, no trust anchors, nested address lookups).
    Off,
    /// A signed zone whose DNSKEY RRset is authenticated by the trust anchors.
    Anchor,
    /// A signed zone whose DNSKEY RRset is authenticated by this (validated) DS RRset.
    Ds(Vec<Record>),
    /// DNSKEY RRset authenticated.
    Secure(std::sync::Arc<ValidatedKeys>),
    /// Provably unsigned (or only unsupported algorithms/digests).
    Insecure,
    /// The chain of trust is broken.
    Bogus(BogusReason),
}

impl Trust {
    /// Whether the DNSKEY RRset still has to be fetched.
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Anchor | Self::Ds(_))
    }
}

/// Validation result of one answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    Secure,
    Insecure,
    Indeterminate,
    Bogus(BogusReason),
}

impl Status {
    /// The weaker of two statuses (the first Bogus wins).
    pub fn combine(self, other: Self) -> Self {
        fn rank(s: &Status) -> u8 {
            match s {
                Status::Secure => 0,
                Status::Indeterminate => 1,
                Status::Insecure => 2,
                Status::Bogus(_) => 3,
            }
        }
        if rank(&other) > rank(&self) {
            other
        } else {
            self
        }
    }

    /// The public status.
    pub fn public(&self) -> DnssecStatus {
        match self {
            Self::Secure => DnssecStatus::Secure,
            Self::Insecure => DnssecStatus::Insecure,
            Self::Indeterminate => DnssecStatus::Indeterminate,
            Self::Bogus(_) => DnssecStatus::Bogus,
        }
    }
}

/// Trust in the child zone `cut`, given the referral's authority section and
/// the validated keys of the parent.
///
/// A DS RRset must validate against the parent keys; without a DS the child
/// is insecure only if the referral proves that there is none.
pub(crate) fn child_trust(
    cut: &Name,
    authorities: &[Record],
    parent: &ValidatedKeys,
    now: SystemTime,
) -> Trust {
    let ds: Vec<Record> = authorities
        .iter()
        .filter(|r| r.rtype == RecordType::DS && r.name == *cut)
        .cloned()
        .collect();
    if ds.is_empty() {
        return match check_no_ds(cut, authorities, parent, now) {
            Ok(()) => Trust::Insecure,
            Err(e) => Trust::Bogus(e),
        };
    }
    if let Err(e) = validate_rrset(&ds, authorities, parent, now) {
        return Trust::Bogus(BogusReason::Verify(e));
    }
    match ds_status(&ds) {
        DsStatus::Usable => Trust::Ds(ds),
        DsStatus::Unsupported(_) => Trust::Insecure,
        DsStatus::Absent => Trust::Bogus(BogusReason::NoDsProof),
    }
}

/// Checks the NSEC/NSEC3 records of a referral for a signed proof that `cut`
/// has no DS record (RFC 4035 section 5.2, RFC 5155 section 8.9).
///
/// TODO(Task 10): the full denial logic (closest encloser, opt-out span
/// rules) belongs to the authenticated denial module; this interim check
/// accepts a validated matching NSEC/NSEC3 whose bitmap has NS but neither DS
/// nor SOA, or a validated opt-out NSEC3 covering the hash of `cut`.
pub(crate) fn check_no_ds(
    cut: &Name,
    authorities: &[Record],
    parent: &ValidatedKeys,
    now: SystemTime,
) -> Result<(), BogusReason> {
    let mut failure: Option<VerifyFailure> = None;
    for r in authorities {
        let proves = match &r.rdata {
            RData::NSEC { types, .. } if r.name == *cut => no_ds_bitmap(types),
            RData::NSEC3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner,
                types,
            } if parent.zone().zone_of(&r.name) => {
                let Ok(hash) = nsec3_hash(
                    *hash_algorithm,
                    cut,
                    salt,
                    *iterations,
                    MAX_ITERATIONS_DEFAULT,
                ) else {
                    continue;
                };
                let Some(owner_hash) = nsec3_owner_hash(&r.name) else {
                    continue;
                };
                if owner_hash == hash {
                    no_ds_bitmap(types)
                } else {
                    // TODO(Task 10): verify covering/opt-out proof (closest encloser).
                    flags & NSEC3_OPT_OUT != 0 && covers(&owner_hash, next_hashed_owner, &hash)
                }
            }
            _ => false,
        };
        if !proves {
            continue;
        }
        let rrset: Vec<Record> = authorities
            .iter()
            .filter(|x| x.rtype == r.rtype && x.name == r.name && x.class == r.class)
            .cloned()
            .collect();
        match validate_rrset(&rrset, authorities, parent, now) {
            Ok(_) => return Ok(()),
            Err(e) => {
                failure = Some(failure.map_or(e, |f| {
                    if e.specificity() > f.specificity() {
                        e
                    } else {
                        f
                    }
                }))
            }
        }
    }
    Err(failure.map_or(BogusReason::NoDsProof, BogusReason::Verify))
}

fn no_ds_bitmap(types: &dnscraft_proto::TypeBitmap) -> bool {
    types.contains(RecordType::NS)
        && !types.contains(RecordType::DS)
        && !types.contains(RecordType::SOA)
}

/// The hash in the first label of an NSEC3 owner name.
fn nsec3_owner_hash(owner: &Name) -> Option<Vec<u8>> {
    let label = owner.labels().next()?;
    base32hex_decode(std::str::from_utf8(label).ok()?).ok()
}

/// Whether `hash` lies strictly between `owner` and `next` (the last NSEC3
/// of the chain wraps around).
fn covers(owner: &[u8], next: &[u8], hash: &[u8]) -> bool {
    if owner < next {
        owner < hash && hash < next
    } else {
        hash > owner || hash < next
    }
}

/// Groups the in-bailiwick records of `records` into RRsets (RRSIGs excluded).
pub(crate) fn rrsets<'a>(
    records: &'a [Record],
    zone: &Name,
    wanted: impl Fn(&Record) -> bool,
) -> Vec<Vec<&'a Record>> {
    let mut sets: Vec<Vec<&Record>> = Vec::new();
    for r in records
        .iter()
        .filter(|r| r.rtype != RecordType::RRSIG && zone.zone_of(&r.name) && wanted(r))
    {
        match sets
            .iter_mut()
            .find(|s| s[0].name == r.name && s[0].rtype == r.rtype && s[0].class == r.class)
        {
            Some(set) => set.push(r),
            None => sets.push(vec![r]),
        }
    }
    sets
}
