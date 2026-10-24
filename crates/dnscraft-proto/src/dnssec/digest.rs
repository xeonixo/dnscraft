//! DS digest computation (RFC 4034 section 5.1.4, RFC 4509, RFC 6605).

use ring::digest;

use crate::error::ProtoError;
use crate::name::Name;
use crate::rdata::RData;

/// DS digest type 1, SHA-1 (legacy; do not trust for new delegations).
pub const DIGEST_SHA1: u8 = 1;
/// DS digest type 2, SHA-256.
pub const DIGEST_SHA256: u8 = 2;
/// DS digest type 4, SHA-384.
pub const DIGEST_SHA384: u8 = 4;

/// Computes the DS digest of a DNSKEY given its RDATA wire octets:
/// `digest(canonical owner name | DNSKEY RDATA)`.
///
/// Unsupported digest types (including GOST, 3) yield
/// [`ProtoError::UnsupportedDigestType`].
pub fn ds_digest_from_wire(
    owner: &Name,
    dnskey_rdata: &[u8],
    digest_type: u8,
) -> Result<Vec<u8>, ProtoError> {
    let algorithm = match digest_type {
        DIGEST_SHA1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        DIGEST_SHA256 => &digest::SHA256,
        DIGEST_SHA384 => &digest::SHA384,
        _ => return Err(ProtoError::UnsupportedDigestType { digest_type }),
    };
    let mut input = Vec::with_capacity(owner.wire_len() + dnskey_rdata.len());
    owner.encode_canonical(&mut input);
    input.extend_from_slice(dnskey_rdata);
    Ok(digest::digest(algorithm, &input).as_ref().to_vec())
}

/// Computes the DS digest of an [`RData::DNSKEY`] owned by `owner`.
///
/// Any other variant is [`ProtoError::InvalidRrset`].
pub fn ds_digest(owner: &Name, dnskey: &RData, digest_type: u8) -> Result<Vec<u8>, ProtoError> {
    if !matches!(dnskey, RData::DNSKEY { .. }) {
        return Err(ProtoError::InvalidRrset {
            reason: "DS digest input is not a DNSKEY",
        });
    }
    let mut wire = Vec::new();
    dnskey.encode(&mut wire, None)?;
    ds_digest_from_wire(owner, &wire, digest_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_types() {
        let owner = Name::root();
        for t in [0, 3, 5, 255] {
            assert_eq!(
                ds_digest_from_wire(&owner, &[1], t),
                Err(ProtoError::UnsupportedDigestType { digest_type: t })
            );
        }
    }

    #[test]
    fn digest_lengths() {
        let owner = Name::root();
        assert_eq!(
            ds_digest_from_wire(&owner, &[1], 1).map(|d| d.len()),
            Ok(20)
        );
        assert_eq!(
            ds_digest_from_wire(&owner, &[1], 2).map(|d| d.len()),
            Ok(32)
        );
        assert_eq!(
            ds_digest_from_wire(&owner, &[1], 4).map(|d| d.len()),
            Ok(48)
        );
    }

    #[test]
    fn rejects_non_dnskey() {
        assert!(ds_digest(&Name::root(), &RData::A([1, 2, 3, 4].into()), 2).is_err());
    }
}
