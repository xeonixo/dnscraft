//! Work limits against CPU-exhaustion attacks on the validator (KeyTrap,
//! CVE-2023-50387, and the NSEC3 iteration/closest-encloser class,
//! CVE-2023-50868).
//!
//! An attacker who controls a zone can publish many DNSKEYs with one key tag
//! and many RRSIGs, or NSEC3 proofs for names with many labels, so that an
//! unbounded validator spends seconds of CPU per query. Three nested caps
//! apply, all fail closed (the answer becomes bogus, never insecure):
//!
//! 1. per RRset: [`MAX_SIGS_PER_RRSET`] RRSIGs, each tried against at most
//!    [`MAX_KEYS_PER_TAG`] keys of the same (key tag, algorithm);
//! 2. per resolution: [`MAX_VERIFICATIONS_PER_RESOLVE`] cryptographic
//!    signature verifications over DNSKEY, DS, answer and denial RRsets;
//! 3. per resolution: [`MAX_NSEC3_HASHES_PER_RESOLVE`] NSEC3 owner-name
//!    hashes (each costs up to `NSEC3_MAX_ITERATIONS + 1` SHA-1 rounds).

use std::sync::atomic::{AtomicU32, Ordering};

/// RRSIGs tried per RRset. Legitimate zones sign an RRset with one or two
/// keys (ZSK, plus an algorithm rollover or a multi-signer setup), so 8 leaves
/// ample room.
pub const MAX_SIGS_PER_RRSET: usize = 8;

/// Keys tried per RRSIG among those sharing its key tag and algorithm. Tag
/// collisions are rare (16-bit tags, a handful of keys per zone); 4 tolerates
/// them while capping the KeyTrap multiplier.
pub const MAX_KEYS_PER_TAG: usize = 4;

/// Signature verifications per resolution, successful or not.
///
/// A cold-cache lookup 4 zones deep needs roughly one DNSKEY verification and
/// one DS verification per zone, the answer RRset and up to about five NSEC3
/// RRsets for a negative answer: around 20. 64 leaves 3x headroom for CNAME
/// chains and hidden-cut probes. For comparison, BIND 9.18/9.20 post-KeyTrap
/// defaults allow 16 validations and 16 failures per fetch
/// (`max-validations-per-fetch`, `max-validation-failures-per-fetch`); a
/// resolution here spans several such fetches, hence the larger total.
pub const MAX_VERIFICATIONS_PER_RESOLVE: u32 = 64;

/// NSEC3 owner-name hashes per resolution, counted per hash computation
/// regardless of the iteration count (which is itself capped by
/// `NSEC3_MAX_ITERATIONS`, so the worst case is 128 * 101 SHA-1 rounds, well
/// under a millisecond). A normal negative answer needs 3 to 8 hashes; a
/// 127-label query name can force one per label in the closest-encloser walk,
/// which this cap cuts off.
pub const MAX_NSEC3_HASHES_PER_RESOLVE: u32 = 128;

/// Shared counters of validation work for one resolution.
#[derive(Debug)]
pub struct ValidationBudget {
    verifications: AtomicU32,
    verification_limit: u32,
    hashes: AtomicU32,
    hash_limit: u32,
}

impl Default for ValidationBudget {
    fn default() -> Self {
        Self::with_limits(MAX_VERIFICATIONS_PER_RESOLVE, MAX_NSEC3_HASHES_PER_RESOLVE)
    }
}

impl ValidationBudget {
    /// A budget with explicit limits.
    pub fn with_limits(verifications: u32, nsec3_hashes: u32) -> Self {
        Self {
            verifications: AtomicU32::new(0),
            verification_limit: verifications,
            hashes: AtomicU32::new(0),
            hash_limit: nsec3_hashes,
        }
    }

    /// A budget that never runs out (unit tests of pure logic).
    pub fn unlimited() -> Self {
        Self::with_limits(u32::MAX, u32::MAX)
    }

    /// Reserves one signature verification; `false` once the budget is spent.
    pub(crate) fn charge_verification(&self) -> bool {
        take(&self.verifications, self.verification_limit)
    }

    /// Reserves one NSEC3 hash computation; `false` once the budget is spent.
    pub(crate) fn charge_nsec3_hash(&self) -> bool {
        take(&self.hashes, self.hash_limit)
    }

    /// Signature verifications performed so far.
    pub fn verifications_used(&self) -> u32 {
        self.verifications.load(Ordering::Relaxed)
    }

    /// NSEC3 hashes computed so far.
    pub fn nsec3_hashes_used(&self) -> u32 {
        self.hashes.load(Ordering::Relaxed)
    }
}

fn take(counter: &AtomicU32, limit: u32) -> bool {
    let mut n = counter.load(Ordering::Relaxed);
    loop {
        if n >= limit {
            return false;
        }
        match counter.compare_exchange_weak(n, n + 1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(cur) => n = cur,
        }
    }
}
