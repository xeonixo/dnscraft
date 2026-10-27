//! RRSIG verification (RFC 4034 section 3, RFC 4035 section 5.3).

use std::time::{SystemTime, UNIX_EPOCH};

use dnscraft_proto::dnssec::rrsig_signing_input;
use dnscraft_proto::{Name, RData, Record};

use super::budget::ValidationBudget;
use ring::signature::{
    self, ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED, ED25519, RsaParameters,
    RsaPublicKeyComponents, UnparsedPublicKey,
};

const ZONE_FLAG: u16 = 0x0100;
const REVOKE_FLAG: u16 = 0x0080;

/// Seconds an RRSIG's inception may lie in the future and still be accepted
/// (clock skew between the signer and this resolver). Applies only to the
/// inception; expiration is checked strictly.
pub const SIG_INCEPTION_SKEW: u32 = 300;

/// Why one RRSIG did not validate an RRset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]

pub enum VerifyFailure {
    /// The cryptographic check failed.
    BadSignature,
    /// Expiration is in the past.
    Expired,
    /// Inception is in the future.
    NotYetValid,
    /// RRSIG key tag differs from the DNSKEY's.
    KeyTagMismatch,
    /// RRSIG and DNSKEY algorithms differ.
    AlgorithmMismatch,
    /// No DNSKEY matches the RRSIG's key tag and algorithm.
    NoMatchingKey,
    /// The algorithm is not supported (RFC 8624 policy or missing in ring).
    UnsupportedAlgorithm(u8),
    /// The RRSIG labels field exceeds the owner's label count.
    LabelsMismatch,
    /// The signer is not the DNSKEY owner, or not an ancestor of the RRset owner.
    SignerNotZone,
    /// DNSKEY lacks the zone flag, has protocol != 3, or is revoked.
    KeyNotZoneKey,
    /// RRSIG type covered differs from the RRset type.
    TypeCoveredMismatch,
    /// The RRset is empty or its records disagree on owner, class or type
    /// (or the RRSIG owner/class differs).
    RrsetMismatch,
    /// No RRSIG covers the RRset.
    NoSignatures,
    /// Key material or record contents cannot be interpreted.
    MalformedKey,
    /// The per-resolution signature verification budget is spent
    /// (KeyTrap protection); fail closed.
    BudgetExhausted,
}

impl VerifyFailure {
    /// Stable, locale-neutral code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadSignature => "dnssec.bad_signature",
            Self::Expired => "dnssec.signature_expired",
            Self::NotYetValid => "dnssec.signature_not_yet_valid",
            Self::KeyTagMismatch => "dnssec.key_tag_mismatch",
            Self::AlgorithmMismatch => "dnssec.algorithm_mismatch",
            Self::NoMatchingKey => "dnssec.no_matching_key",
            Self::UnsupportedAlgorithm(_) => "dnssec.unsupported_algorithm",
            Self::LabelsMismatch => "dnssec.labels_mismatch",
            Self::SignerNotZone => "dnssec.signer_not_zone",
            Self::KeyNotZoneKey => "dnssec.key_not_zone_key",
            Self::TypeCoveredMismatch => "dnssec.type_covered_mismatch",
            Self::RrsetMismatch => "dnssec.rrset_mismatch",
            Self::NoSignatures => "dnssec.no_signatures",
            Self::MalformedKey => "dnssec.malformed_key",
            Self::BudgetExhausted => "dnssec.validation_budget",
        }
    }

    /// RFC 8914 Extended DNS Error info code.
    pub fn ede_code(&self) -> u16 {
        match self {
            Self::UnsupportedAlgorithm(_) => 1,
            Self::Expired => 7,
            Self::NotYetValid => 8,
            Self::NoMatchingKey => 9,
            Self::NoSignatures => 10,
            _ => 6,
        }
    }

    /// Which failure is the most informative when several RRSIGs failed
    /// (higher is more specific).
    pub(crate) fn specificity(&self) -> u8 {
        match self {
            Self::BudgetExhausted => 10,
            Self::Expired | Self::NotYetValid => 9,
            Self::BadSignature => 8,
            Self::UnsupportedAlgorithm(_) => 7,
            Self::SignerNotZone | Self::KeyNotZoneKey | Self::LabelsMismatch => 6,
            Self::AlgorithmMismatch | Self::KeyTagMismatch | Self::TypeCoveredMismatch => 5,
            Self::RrsetMismatch | Self::MalformedKey => 4,
            Self::NoMatchingKey => 3,
            Self::NoSignatures => 2,
        }
    }
}

impl std::fmt::Display for VerifyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedAlgorithm(a) => write!(f, "{} ({a})", self.code()),
            _ => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for VerifyFailure {}

/// A successfully validated RRset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RrsetValidation {
    /// Key tag of the DNSKEY that verified the RRset.
    pub key_tag: u16,
    /// The signer zone.
    pub signer: Name,
    /// For a wildcard-expanded RRset (RRSIG labels < owner labels), the
    /// wildcard owner it was synthesised from, e.g. `*.example.com.`.
    /// Task 10 must then prove that no closer name exists.
    pub wildcard: Option<Name>,
    /// Longest lifetime in seconds the validated RRset may be given
    /// (RFC 4035 section 5.3.3): the smaller of the validating RRSIG's
    /// original TTL and the time left until its expiration.
    pub max_ttl: u32,
}

/// Whether algorithm `alg` can be validated here.
pub fn is_supported_algorithm(alg: u8) -> bool {
    matches!(alg, 8 | 10 | 13 | 14 | 15)
}

/// RFC 1982 serial arithmetic: `a < b` for 32-bit serials.
pub fn serial_lt(a: u32, b: u32) -> bool {
    a != b && b.wrapping_sub(a) < 0x8000_0000
}

/// Checks `inception - SIG_INCEPTION_SKEW <= now <= expiration` using serial
/// arithmetic (RFC 4034 section 3.1.5); `now` is reduced modulo 2^32.
pub fn validity_window(
    inception: u32,
    expiration: u32,
    now: SystemTime,
) -> Result<(), VerifyFailure> {
    let secs = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    // Truncation to 32 bits is the point: serial numbers wrap.
    let now32 = (secs & 0xFFFF_FFFF) as u32;
    if serial_lt(now32.wrapping_add(SIG_INCEPTION_SKEW), inception) {
        Err(VerifyFailure::NotYetValid)
    } else if serial_lt(expiration, now32) {
        Err(VerifyFailure::Expired)
    } else {
        Ok(())
    }
}

/// Longest TTL an RRset may keep when it was validated by an RRSIG with
/// `original_ttl` and `expiration` at `now` (RFC 4035 section 5.3.3): the
/// smaller of the original TTL and the seconds left until expiration.
pub fn signature_max_ttl(original_ttl: u32, expiration: u32, now: SystemTime) -> u32 {
    let secs = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    // Truncation to 32 bits is the point: serial numbers wrap.
    let now32 = (secs & 0xFFFF_FFFF) as u32;
    let left = if serial_lt(expiration, now32) {
        0
    } else {
        expiration.wrapping_sub(now32)
    };
    original_ttl.min(left)
}

/// The wildcard owner (`*.` + the last `labels` labels of `owner`) if an RRSIG
/// with `labels` labels over `owner` indicates wildcard expansion.
pub fn wildcard_source(owner: &Name, labels: u8) -> Option<Name> {
    let have = owner.label_count();
    let want = usize::from(labels);
    if want >= have {
        return None;
    }
    let mut base = owner.clone();
    for _ in 0..have - want {
        base = base.parent()?;
    }
    let mut wire = vec![1, b'*'];
    wire.extend_from_slice(base.as_wire());
    let source = Name::decode(&wire, 0).ok().map(|(n, _)| n)?;
    // The labels field does not count a leading `*` (RFC 4034 section 3.1.3):
    // a record owned by the wildcard itself is no expansion.
    (source != *owner).then_some(source)
}

/// Verifies `rrsig` over `rrset` with `dnskey` at time `now`.
///
/// On success returns nothing; use [`wildcard_source`] or
/// [`validate_rrset`](crate::dnssec::validate_rrset) for wildcard information.
pub fn verify_rrsig(
    rrset: &[Record],
    rrsig: &Record,
    dnskey: &Record,
    now: SystemTime,
) -> Result<(), VerifyFailure> {
    verify_rrsig_budgeted(
        rrset,
        rrsig,
        dnskey,
        now,
        &ValidationBudget::unlimited(),
        &mut None,
    )
}

/// [`verify_rrsig`] that charges one verification to `budget` right before
/// the cryptographic check (cheap structural rejections are free), and reuses
/// the RRSIG signing input cached in `input` across keys.
pub(crate) fn verify_rrsig_budgeted(
    rrset: &[Record],
    rrsig: &Record,
    dnskey: &Record,
    now: SystemTime,
    budget: &ValidationBudget,
    input: &mut Option<Vec<u8>>,
) -> Result<(), VerifyFailure> {
    verify_rrsig_inner(rrset, rrsig, dnskey, now, budget, input, false)
}

/// Like [`verify_rrsig_budgeted`], but accepts the DNSKEY's REVOKE bit.
///
/// RFC 5011 section 2.3 revocation is proved by the revoked key signing the
/// DNSKEY RRset itself; every other check still applies.
pub(crate) fn verify_revocation_budgeted(
    rrset: &[Record],
    rrsig: &Record,
    dnskey: &Record,
    now: SystemTime,
    budget: &ValidationBudget,
    input: &mut Option<Vec<u8>>,
) -> Result<(), VerifyFailure> {
    verify_rrsig_inner(rrset, rrsig, dnskey, now, budget, input, true)
}

fn verify_rrsig_inner(
    rrset: &[Record],
    rrsig: &Record,
    dnskey: &Record,
    now: SystemTime,
    budget: &ValidationBudget,
    input: &mut Option<Vec<u8>>,
    allow_revoked: bool,
) -> Result<(), VerifyFailure> {
    let RData::RRSIG {
        type_covered,
        algorithm,
        labels,
        expiration,
        inception,
        key_tag,
        signer_name,
        signature: sig,
        ..
    } = &rrsig.rdata
    else {
        return Err(VerifyFailure::MalformedKey);
    };
    let RData::DNSKEY {
        flags,
        protocol,
        algorithm: key_alg,
        public_key,
    } = &dnskey.rdata
    else {
        return Err(VerifyFailure::MalformedKey);
    };

    let first = rrset.first().ok_or(VerifyFailure::RrsetMismatch)?;
    if rrset
        .iter()
        .any(|r| r.name != first.name || r.class != first.class || r.rtype() != first.rtype())
        || rrsig.name != first.name
        || rrsig.class != first.class
    {
        return Err(VerifyFailure::RrsetMismatch);
    }
    if *type_covered != first.rtype() {
        return Err(VerifyFailure::TypeCoveredMismatch);
    }
    if dnskey.name != *signer_name || !signer_name.zone_of(&first.name) {
        return Err(VerifyFailure::SignerNotZone);
    }
    if flags & ZONE_FLAG == 0 || *protocol != 3 || (flags & REVOKE_FLAG != 0 && !allow_revoked) {
        return Err(VerifyFailure::KeyNotZoneKey);
    }
    if algorithm != key_alg {
        return Err(VerifyFailure::AlgorithmMismatch);
    }
    if dnscraft_proto::dnssec::key_tag(*flags, *protocol, *key_alg, public_key) != *key_tag {
        return Err(VerifyFailure::KeyTagMismatch);
    }
    if usize::from(*labels) > first.name.label_count() {
        return Err(VerifyFailure::LabelsMismatch);
    }
    if !is_supported_algorithm(*algorithm) {
        return Err(VerifyFailure::UnsupportedAlgorithm(*algorithm));
    }
    validity_window(*inception, *expiration, now)?;

    let msg = match input {
        Some(m) => m,
        None => input.insert(
            rrsig_signing_input(&rrsig.rdata, rrset).map_err(|_| VerifyFailure::MalformedKey)?,
        ),
    };
    if !budget.charge_verification() {
        return Err(VerifyFailure::BudgetExhausted);
    }
    verify_signature(*algorithm, public_key, msg, sig)
}

fn verify_signature(alg: u8, key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), VerifyFailure> {
    let ok = match alg {
        8 | 10 => {
            let (e, n) = parse_rsa(key)?;
            let bits = modulus_bits(n);
            let params: &RsaParameters = match (alg, bits >= 2048) {
                (8, true) => &signature::RSA_PKCS1_2048_8192_SHA256,
                (8, false) => &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                (_, true) => &signature::RSA_PKCS1_2048_8192_SHA512,
                (_, false) => &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
            };
            if bits < 1024 {
                return Err(VerifyFailure::UnsupportedAlgorithm(alg));
            }
            RsaPublicKeyComponents { n, e }
                .verify(params, msg, sig)
                .is_ok()
        }
        13 | 14 => {
            let (len, params) = if alg == 13 {
                (64, &ECDSA_P256_SHA256_FIXED)
            } else {
                (96, &ECDSA_P384_SHA384_FIXED)
            };
            if key.len() != len {
                return Err(VerifyFailure::MalformedKey);
            }
            let mut point = Vec::with_capacity(len + 1);
            point.push(0x04);
            point.extend_from_slice(key);
            UnparsedPublicKey::new(params, point)
                .verify(msg, sig)
                .is_ok()
        }
        15 => {
            if key.len() != 32 {
                return Err(VerifyFailure::MalformedKey);
            }
            UnparsedPublicKey::new(&ED25519, key)
                .verify(msg, sig)
                .is_ok()
        }
        other => return Err(VerifyFailure::UnsupportedAlgorithm(other)),
    };
    if ok {
        Ok(())
    } else {
        Err(VerifyFailure::BadSignature)
    }
}

/// RFC 3110 section 2: returns (exponent, modulus).
fn parse_rsa(key: &[u8]) -> Result<(&[u8], &[u8]), VerifyFailure> {
    let bad = VerifyFailure::MalformedKey;
    let (&first, rest) = key.split_first().ok_or(bad)?;
    let (elen, rest) = if first == 0 {
        let (len, rest) = rest.split_at_checked(2).ok_or(bad)?;
        (usize::from(u16::from_be_bytes([len[0], len[1]])), rest)
    } else {
        (usize::from(first), rest)
    };
    let (e, n) = rest.split_at_checked(elen).ok_or(bad)?;
    if e.is_empty() || n.is_empty() {
        return Err(bad);
    }
    Ok((e, n))
}

fn modulus_bits(n: &[u8]) -> usize {
    let skip = n.iter().take_while(|&&b| b == 0).count();
    match n.get(skip) {
        Some(&b) => (n.len() - skip) * 8 - b.leading_zeros() as usize,
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::time::Duration;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn serial_arithmetic() {
        assert!(serial_lt(1, 2));
        assert!(!serial_lt(2, 1));
        assert!(!serial_lt(5, 5));
        // Wrap: 0xFFFF_FFF0 < 0x10 because 0x10 is 0x20 ahead.
        assert!(serial_lt(0xFFFF_FFF0, 0x10));
        assert!(!serial_lt(0x10, 0xFFFF_FFF0));
        // Exactly half the space apart is undefined: neither is less.
        assert!(!serial_lt(0, 0x8000_0000));
        assert!(!serial_lt(0x8000_0000, 0));
        assert!(serial_lt(0, 0x7FFF_FFFF));
    }

    #[test]
    fn window_plain() {
        assert_eq!(validity_window(1000, 2000, at(1000)), Ok(()));
        assert_eq!(validity_window(1000, 2000, at(1500)), Ok(()));
        assert_eq!(validity_window(1000, 2000, at(2000)), Ok(()));
        // Inception skew: up to SIG_INCEPTION_SKEW seconds early is fine.
        assert_eq!(validity_window(1000, 2000, at(1000 - 300)), Ok(()));
        assert_eq!(
            validity_window(1000, 2000, at(1000 - 301)),
            Err(VerifyFailure::NotYetValid)
        );
        // Expiration gets no skew.
        assert_eq!(
            validity_window(1000, 2000, at(2001)),
            Err(VerifyFailure::Expired)
        );
    }

    #[test]
    fn window_wraps_around_2_32() {
        // Window straddles the 32-bit wrap: inception just below 2^32,
        // expiration just after.
        let (inc, exp) = (0xFFFF_FF00_u32, 0x0000_0100_u32);
        let wrap = 1u64 << 32;
        assert_eq!(validity_window(inc, exp, at(0xFFFF_FF00)), Ok(()));
        assert_eq!(validity_window(inc, exp, at(0xFFFF_FFFF)), Ok(()));
        assert_eq!(validity_window(inc, exp, at(wrap)), Ok(()));
        assert_eq!(validity_window(inc, exp, at(wrap + 0x100)), Ok(()));
        assert_eq!(validity_window(inc, exp, at(0xFFFF_FDD4)), Ok(()));
        assert_eq!(
            validity_window(inc, exp, at(0xFFFF_FDD3)),
            Err(VerifyFailure::NotYetValid)
        );
        assert_eq!(
            validity_window(inc, exp, at(wrap + 0x101)),
            Err(VerifyFailure::Expired)
        );
        // Clock past 2^32 (year 2106) with a window set before the wrap.
        assert_eq!(
            validity_window(0xFFFF_0000, 0xFFFF_FFF0, at(wrap + 5)),
            Err(VerifyFailure::Expired)
        );
    }

    #[test]
    fn wildcard_names() {
        let n = |s: &str| Name::from_ascii(s).unwrap();
        assert_eq!(
            wildcard_source(&n("a.b.example.test."), 2),
            Some(n("*.example.test."))
        );
        assert_eq!(
            wildcard_source(&n("x.wild.secure.test."), 3),
            Some(n("*.wild.secure.test."))
        );
        assert_eq!(wildcard_source(&n("www.secure.test."), 3), None);
        // The wildcard itself (labels excludes the "*"): not an expansion.
        assert_eq!(wildcard_source(&n("*.wild.secure.test."), 3), None);
        assert_eq!(wildcard_source(&n("a.test."), 0), Some(n("*.")));
    }

    #[test]
    fn rsa_parsing_and_bits() {
        assert_eq!(
            parse_rsa(&[1, 3, 0xAA, 0xBB]).unwrap(),
            (&[3u8][..], &[0xAA, 0xBB][..])
        );
        assert_eq!(
            parse_rsa(&[0, 0, 1, 3, 0xAA]).unwrap(),
            (&[3u8][..], &[0xAA][..])
        );
        assert!(parse_rsa(&[]).is_err());
        assert!(parse_rsa(&[5, 1]).is_err());
        assert!(parse_rsa(&[1, 3]).is_err());
        assert_eq!(modulus_bits(&[0x00, 0x80]), 8);
        assert_eq!(modulus_bits(&[0x01, 0x00]), 9);
    }

    #[test]
    fn failure_codes_and_ede() {
        assert_eq!(VerifyFailure::Expired.ede_code(), 7);
        assert_eq!(VerifyFailure::NotYetValid.ede_code(), 8);
        assert_eq!(VerifyFailure::BadSignature.ede_code(), 6);
        assert_eq!(VerifyFailure::NoMatchingKey.ede_code(), 9);
        assert_eq!(VerifyFailure::NoSignatures.ede_code(), 10);
        assert_eq!(VerifyFailure::UnsupportedAlgorithm(5).ede_code(), 1);
        assert_eq!(VerifyFailure::BadSignature.code(), "dnssec.bad_signature");
    }
}
