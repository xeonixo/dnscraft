//! Chain of trust: DS/anchor to DNSKEY RRset, then RRset validation
//! (RFC 4035 sections 5.2 and 5.3, RFC 4509, RFC 6840 section 5.2).

use std::time::SystemTime;

use dnscraft_proto::dnssec::{
    DIGEST_SHA1, DIGEST_SHA256, DIGEST_SHA384, dnskey_key_tag, ds_digest,
};
use dnscraft_proto::{Name, RData, Record, RecordType};

use super::anchors::{Anchor, TrustAnchors};
use super::verify::{
    RrsetValidation, VerifyFailure, is_supported_algorithm, verify_rrsig, wildcard_source,
};

const ZONE_FLAG: u16 = 0x0100;

/// DNSKEYs of a zone whose RRset has been authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedKeys {
    zone: Name,
    keys: Vec<Record>,
}

impl ValidatedKeys {
    /// The zone.
    pub fn zone(&self) -> &Name {
        &self.zone
    }

    /// All DNSKEY records of the validated RRset.
    pub fn keys(&self) -> &[Record] {
        &self.keys
    }
}

/// Where trust in a zone's DNSKEY RRset comes from.
#[derive(Clone, Copy, Debug)]
pub enum DelegationTrust<'a> {
    /// The (already validated) DS RRset from the parent.
    Ds(&'a [Record]),
    /// Configured trust anchors (the zone must be an anchor zone).
    Anchors(&'a TrustAnchors),
}

/// Why a zone is insecure rather than validatable (RFC 4035 section 5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsecureReason {
    /// Every DS names an unsupported key algorithm.
    UnsupportedAlgorithm(u8),
    /// Every DS uses an unsupported digest type.
    UnsupportedDigest(u8),
}

impl InsecureReason {
    /// Stable, locale-neutral code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedAlgorithm(_) => "dnssec.insecure_unsupported_algorithm",
            Self::UnsupportedDigest(_) => "dnssec.insecure_unsupported_digest",
        }
    }

    /// RFC 8914 code to attach (1 Unsupported DNSKEY Algorithm, 2 Unsupported DS Digest Type);
    /// informational, the answer is still returned.
    pub fn ede_code(&self) -> u16 {
        match self {
            Self::UnsupportedAlgorithm(_) => 1,
            Self::UnsupportedDigest(_) => 2,
        }
    }
}

/// Result of [`validate_dnskey_rrset`] when nothing is wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeysOutcome {
    /// The DNSKEY RRset is authenticated.
    Secure(ValidatedKeys),
    /// The zone must be treated as insecure.
    Insecure(InsecureReason),
}

/// Why the chain of trust is broken (the zone is bogus).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainFailure {
    /// `DelegationTrust::Anchors` was given but has no anchor for the zone.
    NoTrustAnchor,
    /// The DNSKEY RRset is empty.
    NoDnskeys,
    /// No DNSKEY matches any usable DS/anchor.
    DsNoMatch,
    /// DNSKEY RRset signature check failed.
    Verify(VerifyFailure),
}

impl ChainFailure {
    /// Stable, locale-neutral code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoTrustAnchor => "dnssec.no_trust_anchor",
            Self::NoDnskeys => "dnssec.no_dnskeys",
            Self::DsNoMatch => "dnssec.ds_no_match",
            Self::Verify(v) => v.code(),
        }
    }

    /// RFC 8914 Extended DNS Error info code.
    pub fn ede_code(&self) -> u16 {
        match self {
            Self::NoTrustAnchor => 6,
            Self::NoDnskeys | Self::DsNoMatch => 9,
            Self::Verify(v) => v.ede_code(),
        }
    }
}

impl std::fmt::Display for ChainFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verify(v) => write!(f, "{v}"),
            _ => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for ChainFailure {}

/// What the parent's DS RRset says about a delegation (before any NSEC proof).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DsStatus {
    /// No DS records present. Task 10 must prove their absence (NSEC/NSEC3)
    /// before treating the child as insecure.
    Absent,
    /// At least one DS is usable.
    Usable,
    /// DS records exist but none is usable: the child is insecure.
    Unsupported(InsecureReason),
}

/// A DS entry reduced to what matching needs.
struct DsEntry<'a> {
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: &'a [u8],
}

fn ds_entries(records: &[Record]) -> Vec<DsEntry<'_>> {
    records
        .iter()
        .filter_map(|r| match &r.rdata {
            RData::DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => Some(DsEntry {
                key_tag: *key_tag,
                algorithm: *algorithm,
                digest_type: *digest_type,
                digest,
            }),
            _ => None,
        })
        .collect()
}

fn digest_supported(t: u8) -> bool {
    matches!(t, DIGEST_SHA1 | DIGEST_SHA256 | DIGEST_SHA384)
}

fn classify(entries: &[(u16, u8, u8)]) -> DsStatus {
    if entries.is_empty() {
        return DsStatus::Absent;
    }
    if entries
        .iter()
        .any(|&(_, a, d)| is_supported_algorithm(a) && digest_supported(d))
    {
        return DsStatus::Usable;
    }
    if let Some(&(_, a, _)) = entries
        .iter()
        .find(|&&(_, a, _)| !is_supported_algorithm(a))
    {
        return DsStatus::Unsupported(InsecureReason::UnsupportedAlgorithm(a));
    }
    let d = entries.first().map_or(0, |e| e.2);
    DsStatus::Unsupported(InsecureReason::UnsupportedDigest(d))
}

/// Classifies a DS RRset: absent, usable or unsupported-only.
pub fn ds_status(ds_set: &[Record]) -> DsStatus {
    let e: Vec<_> = ds_entries(ds_set)
        .iter()
        .map(|d| (d.key_tag, d.algorithm, d.digest_type))
        .collect();
    classify(&e)
}

/// Validates the DNSKEY RRset of `zone` against its DS RRset or trust anchors.
///
/// `dnskey_rrset` may contain records of other names/types; only DNSKEYs
/// owned by `zone` are used. `rrsigs` may contain unrelated RRSIGs too.
/// A DNSKEY RRset is trusted when a DS (or DNSKEY anchor) matches a
/// zone-flagged DNSKEY and that key has a valid RRSIG over the whole RRset.
/// SHA-1 DS records are ignored when a SHA-2 DS exists for the same key.
pub fn validate_dnskey_rrset(
    zone: &Name,
    dnskey_rrset: &[Record],
    rrsigs: &[Record],
    trust: DelegationTrust<'_>,
    now: SystemTime,
) -> Result<KeysOutcome, ChainFailure> {
    // Collect the trust material as (key_tag, algorithm, digest_type, digest) or direct keys.
    let mut ds: Vec<(u16, u8, u8, Vec<u8>)> = Vec::new();
    let mut direct: Vec<(u16, u8, Vec<u8>)> = Vec::new(); // (flags, alg, key)
    match trust {
        DelegationTrust::Ds(records) => {
            for e in ds_entries(records) {
                ds.push((e.key_tag, e.algorithm, e.digest_type, e.digest.to_vec()));
            }
        }
        DelegationTrust::Anchors(anchors) => {
            if !anchors.has_zone(zone) {
                return Err(ChainFailure::NoTrustAnchor);
            }
            for a in anchors.for_zone(zone) {
                match a {
                    Anchor::Ds {
                        key_tag,
                        algorithm,
                        digest_type,
                        digest,
                        ..
                    } => ds.push((*key_tag, *algorithm, *digest_type, digest.clone())),
                    Anchor::Dnskey {
                        flags,
                        algorithm,
                        public_key,
                        ..
                    } => direct.push((*flags, *algorithm, public_key.clone())),
                }
            }
        }
    }

    let summary: Vec<_> = ds.iter().map(|d| (d.0, d.1, d.2)).collect();
    if direct.is_empty() {
        match classify(&summary) {
            DsStatus::Absent => return Err(ChainFailure::DsNoMatch),
            DsStatus::Unsupported(reason) => return Ok(KeysOutcome::Insecure(reason)),
            DsStatus::Usable => {}
        }
    }

    let keys: Vec<&Record> = dnskey_rrset
        .iter()
        .filter(|r| r.name == *zone && r.rtype == RecordType::DNSKEY)
        .collect();
    if keys.is_empty() {
        return Err(ChainFailure::NoDnskeys);
    }

    // RFC 4509: drop SHA-1 DS where a SHA-2 DS exists for the same key.
    let strong: Vec<(u16, u8)> = ds
        .iter()
        .filter(|d| d.2 == DIGEST_SHA256 || d.2 == DIGEST_SHA384)
        .map(|d| (d.0, d.1))
        .collect();
    let usable_ds: Vec<&(u16, u8, u8, Vec<u8>)> = ds
        .iter()
        .filter(|d| is_supported_algorithm(d.1) && digest_supported(d.2))
        .filter(|d| d.2 != DIGEST_SHA1 || !strong.contains(&(d.0, d.1)))
        .collect();

    let mut entry_keys: Vec<&Record> = Vec::new();
    for key in &keys {
        let RData::DNSKEY {
            flags,
            algorithm,
            public_key,
            ..
        } = &key.rdata
        else {
            continue;
        };
        if flags & ZONE_FLAG == 0 {
            continue;
        }
        let Some(tag) = dnskey_key_tag(&key.rdata) else {
            continue;
        };
        let by_ds = usable_ds.iter().any(|d| {
            d.0 == tag
                && d.1 == *algorithm
                && ds_digest(zone, &key.rdata, d.2).is_ok_and(|calc| calc == d.3)
        });
        let by_anchor = direct
            .iter()
            .any(|(f, a, k)| f == flags && a == algorithm && k.as_slice() == &**public_key);
        if by_ds || by_anchor {
            entry_keys.push(key);
        }
    }
    if entry_keys.is_empty() {
        return Err(ChainFailure::DsNoMatch);
    }

    let mut best: Option<VerifyFailure> = None;
    let mut seen_sig = false;
    for sig in rrsigs.iter().filter(|r| {
        r.name == *zone
            && matches!(&r.rdata, RData::RRSIG { type_covered, .. } if *type_covered == RecordType::DNSKEY)
    }) {
        seen_sig = true;
        let RData::RRSIG {
            key_tag, algorithm, ..
        } = &sig.rdata
        else {
            continue;
        };
        for key in &entry_keys {
            let RData::DNSKEY {
                algorithm: ka,
                ..
            } = &key.rdata
            else {
                continue;
            };
            if ka != algorithm || dnskey_key_tag(&key.rdata) != Some(*key_tag) {
                continue;
            }
            let rrset: Vec<Record> = keys.iter().map(|r| (*r).clone()).collect();
            match verify_rrsig(&rrset, sig, key, now) {
                Ok(()) => {
                    return Ok(KeysOutcome::Secure(ValidatedKeys {
                        zone: zone.clone(),
                        keys: rrset,
                    }));
                }
                Err(e) => note(&mut best, e),
            }
        }
        if best.is_none() {
            best = Some(VerifyFailure::NoMatchingKey);
        }
    }
    if !seen_sig {
        return Err(ChainFailure::Verify(VerifyFailure::NoSignatures));
    }
    Err(ChainFailure::Verify(
        best.unwrap_or(VerifyFailure::NoMatchingKey),
    ))
}

fn note(best: &mut Option<VerifyFailure>, e: VerifyFailure) {
    if best.is_none_or(|b| e.specificity() > b.specificity()) {
        *best = Some(e);
    }
}

/// Validates `rrset` with RRSIGs from `rrsigs` (which may hold unrelated
/// records) using keys from `keys`. Any one valid RRSIG suffices; otherwise
/// the most specific failure is returned.
pub fn validate_rrset(
    rrset: &[Record],
    rrsigs: &[Record],
    keys: &ValidatedKeys,
    now: SystemTime,
) -> Result<RrsetValidation, VerifyFailure> {
    let first = rrset.first().ok_or(VerifyFailure::RrsetMismatch)?;
    let mut best: Option<VerifyFailure> = None;
    let mut seen = false;
    for sig in rrsigs.iter().filter(|s| {
        s.name == first.name
            && s.class == first.class
            && matches!(&s.rdata, RData::RRSIG { type_covered, .. } if *type_covered == first.rtype)
    }) {
        seen = true;
        let RData::RRSIG {
            key_tag,
            algorithm,
            labels,
            signer_name,
            ..
        } = &sig.rdata
        else {
            continue;
        };
        let mut matched = false;
        for key in keys.keys() {
            let RData::DNSKEY { algorithm: ka, .. } = &key.rdata else {
                continue;
            };
            if ka != algorithm || dnskey_key_tag(&key.rdata) != Some(*key_tag) {
                continue;
            }
            matched = true;
            match verify_rrsig(rrset, sig, key, now) {
                Ok(()) => {
                    return Ok(RrsetValidation {
                        key_tag: *key_tag,
                        signer: signer_name.clone(),
                        wildcard: wildcard_source(&first.name, *labels),
                    });
                }
                Err(e) => note(&mut best, e),
            }
        }
        if !matched {
            note(&mut best, VerifyFailure::NoMatchingKey);
        }
    }
    if !seen {
        return Err(VerifyFailure::NoSignatures);
    }
    Err(best.unwrap_or(VerifyFailure::NoMatchingKey))
}
