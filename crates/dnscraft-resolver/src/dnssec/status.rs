//! Validation state carried through an iteration and its mapping to the
//! public [`DnssecStatus`] (Task 9b).
//!
//! Everything here is pure; the DNSKEY fetches live in `walk.rs`.
//!
//! Status lattice for one answer (weakest wins): `Bogus` > `Insecure` >
//! `Indeterminate` > `Secure`. Only `Secure` sets the AD bit.

use std::time::SystemTime;

use dnscraft_proto::{Name, Record, RecordType};

use super::denial::{Denial, InsecureWhy, prove_no_ds};
use super::{ChainFailure, DsStatus, ValidatedKeys, VerifyFailure, ds_status, validate_rrset};
use crate::types::DnssecStatus;

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
    /// A negative answer or wildcard expansion came without NSEC/NSEC3 proof.
    NoDenialProof,
    /// The NSEC/NSEC3 records do not prove what they must.
    BadDenialProof,
}

impl BogusReason {
    /// Stable, locale-neutral code (used as EXTRA-TEXT of the EDE).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Chain(c) => c.code(),
            Self::Verify(v) => v.code(),
            Self::DnskeyUnavailable => "dnssec.dnskey_unavailable",
            Self::NoDsProof => "dnssec.no_ds_proof",
            Self::NoDenialProof => "dnssec.no_denial_proof",
            Self::BadDenialProof => "dnssec.bad_denial_proof",
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
            Self::NoDsProof | Self::NoDenialProof => 12,
            // 6 DNSSEC Bogus
            Self::BadDenialProof => 6,
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
    /// Insecure because the NSEC3 iteration count exceeds the limit
    /// (carries EDE 27).
    InsecureNsec3Iterations,
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
                Status::Insecure | Status::InsecureNsec3Iterations => 2,
                Status::Bogus(_) => 3,
            }
        }
        if rank(&other) > rank(&self) {
            other
        } else {
            self
        }
    }

    /// The status for a proof that is only insecure.
    pub fn from_insecure(why: InsecureWhy) -> Self {
        match why {
            InsecureWhy::Nsec3Iterations => Self::InsecureNsec3Iterations,
            InsecureWhy::OptOut | InsecureWhy::Nsec3Algorithm => Self::Insecure,
        }
    }

    /// The Extended DNS Error (INFO-CODE, EXTRA-TEXT) that goes with the status.
    pub fn ede(&self) -> Option<(u16, &'static str)> {
        match self {
            Self::Bogus(r) => Some((r.ede_code(), r.code())),
            // 27 Unsupported NSEC3 Iterations Value
            Self::InsecureNsec3Iterations => Some((27, "dnssec.nsec3_iterations")),
            _ => None,
        }
    }

    /// The public status.
    pub fn public(&self) -> DnssecStatus {
        match self {
            Self::Secure => DnssecStatus::Secure,
            Self::Insecure | Self::InsecureNsec3Iterations => DnssecStatus::Insecure,
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
/// Only records that validate against `parent` count; the logic is in
/// [`prove_no_ds`]. An opt-out span or an unsupported NSEC3 parameter set
/// yields `Ok` as well: the child is then insecure, not bogus.
pub(crate) fn check_no_ds(
    cut: &Name,
    authorities: &[Record],
    parent: &ValidatedKeys,
    now: SystemTime,
) -> Result<(), BogusReason> {
    let mut failure: Option<VerifyFailure> = None;
    let mut valid: Vec<Record> = Vec::new();
    for set in rrsets(authorities, parent.zone(), |r| {
        matches!(r.rtype, RecordType::NSEC | RecordType::NSEC3)
    }) {
        let owned: Vec<Record> = set.into_iter().cloned().collect();
        match validate_rrset(&owned, authorities, parent, now) {
            // An expanded NSEC/NSEC3 is a replay, not a proof.
            Ok(v) if v.wildcard.is_none() => valid.extend(owned),
            Ok(_) => {}
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
    match prove_no_ds(parent.zone(), cut, &valid) {
        Denial::Secure | Denial::Insecure(_) => Ok(()),
        Denial::Bogus(_) => Err(failure.map_or(BogusReason::NoDsProof, BogusReason::Verify)),
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
