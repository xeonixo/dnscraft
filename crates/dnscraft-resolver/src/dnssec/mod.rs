//! DNSSEC validation building blocks (Task 9a): trust anchors, RRSIG
//! verification and chain-of-trust establishment.
//!
//! Everything here is pure: no I/O, the current time is passed in. Task 9b
//! drives these functions from the resolver; Task 10 adds authenticated
//! denial on top (see [`RrsetValidation::wildcard`]).
//!
//! # Algorithm policy (RFC 8624, RFC 4035 section 5.2)
//!
//! Supported for validation: 8 (RSASHA256), 10 (RSASHA512), 13 (ECDSAP256SHA256),
//! 14 (ECDSAP384SHA384) and 15 (ED25519). Algorithms 1, 3, 5, 6, 7, 12, 16 and
//! unknown ones are unsupported: a zone whose DS set offers nothing else is
//! treated as insecure, never bogus. RSA keys of 1024 to 2047 bits are accepted
//! through ring's `*_FOR_LEGACY_USE_ONLY` verifiers; shorter keys are rejected.
//!
//! # DS digest policy
//!
//! Digest types 1 (SHA-1), 2 (SHA-256) and 4 (SHA-384) are understood. When a
//! DS set holds a SHA-2 DS for a key, the SHA-1 DS of the same key is ignored
//! (RFC 4509 section 3).

mod anchors;
mod budget;
mod chain;
pub(crate) mod denial;
pub(crate) mod nta;
pub(crate) mod status;
mod verify;
pub(crate) mod walk;

pub use anchors::{Anchor, AnchorError, TrustAnchors};
pub use budget::{
    MAX_KEYS_PER_TAG, MAX_NSEC3_HASHES_PER_RESOLVE, MAX_SIGS_PER_RRSET,
    MAX_VERIFICATIONS_PER_RESOLVE, ValidationBudget,
};
pub use chain::{
    ChainFailure, DelegationTrust, DsStatus, InsecureReason, KeysOutcome, ValidatedKeys, ds_status,
    validate_dnskey_rrset, validate_dnskey_rrset_budgeted, validate_rrset, validate_rrset_budgeted,
};
pub use verify::{
    RrsetValidation, SIG_INCEPTION_SKEW, VerifyFailure, is_supported_algorithm, serial_lt,
    validity_window, verify_rrsig, wildcard_source,
};
