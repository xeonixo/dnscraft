//! DNSSEC helpers that need no I/O: key tags, DS digests, NSEC3 hashing and
//! the canonical signing input of an RRset.
//!
//! Signature verification is not part of this module; [`canonical`] only
//! produces the exact octets that a signature covers.

pub mod canonical;
pub mod digest;
pub mod keytag;
pub mod nsec3hash;

pub use canonical::{canonical_owner, canonical_rdata, rrsig_signing_input};
pub use digest::{DIGEST_SHA1, DIGEST_SHA256, DIGEST_SHA384, ds_digest, ds_digest_from_wire};
pub use keytag::{dnskey_key_tag, key_tag, key_tag_from_rdata};
pub use nsec3hash::{
    MAX_ITERATIONS_DEFAULT, NSEC3_HASH_SHA1, base32hex_decode, base32hex_encode, nsec3_hash,
};
