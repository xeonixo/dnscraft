//! Key tag computation (RFC 4034 Appendix B).

use crate::rdata::RData;

/// Computes the key tag of a DNSKEY given its RDATA wire octets.
///
/// `algorithm` must be the DNSKEY algorithm field (needed for the RSA/MD5
/// special case, algorithm 1, where the tag is bits of the public key).
pub fn key_tag_from_rdata(rdata: &[u8], algorithm: u8) -> u16 {
    if algorithm == 1 {
        // The most significant 16 bits of the least significant 24 bits of
        // the public key modulus: the two octets before the last one.
        let len = rdata.len();
        return match len.checked_sub(3).and_then(|i| rdata.get(i..i + 2)) {
            Some(&[hi, lo]) => u16::from_be_bytes([hi, lo]),
            _ => 0,
        };
    }
    let mut acc: u32 = 0;
    for (i, &b) in rdata.iter().enumerate() {
        let b = u32::from(b);
        acc = acc.wrapping_add(if i % 2 == 0 { b << 8 } else { b });
    }
    acc = acc.wrapping_add((acc >> 16) & 0xFFFF);
    (acc & 0xFFFF) as u16
}

/// Computes the key tag from the DNSKEY fields.
pub fn key_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 {
    let mut wire = Vec::with_capacity(4 + public_key.len());
    wire.extend_from_slice(&flags.to_be_bytes());
    wire.push(protocol);
    wire.push(algorithm);
    wire.extend_from_slice(public_key);
    key_tag_from_rdata(&wire, algorithm)
}

/// Computes the key tag of an [`RData::DNSKEY`]; `None` for other variants.
pub fn dnskey_key_tag(rdata: &RData) -> Option<u16> {
    match rdata {
        RData::DNSKEY {
            flags,
            protocol,
            algorithm,
            public_key,
        } => Some(key_tag(*flags, *protocol, *algorithm, public_key)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_short_inputs_do_not_panic() {
        assert_eq!(key_tag_from_rdata(&[], 8), 0);
        assert_eq!(key_tag_from_rdata(&[], 1), 0);
        assert_eq!(key_tag_from_rdata(&[1, 2], 1), 0);
        assert_eq!(key_tag_from_rdata(&[1, 2, 3], 1), 0x0102);
        assert_eq!(key_tag_from_rdata(&[1, 2, 3, 4], 1), 0x0203);
    }

    #[test]
    fn simple_sum() {
        // 0x0100 + 0x0002 + 0x0300, no carry.
        assert_eq!(key_tag_from_rdata(&[1, 2, 3], 8), 0x0100 + 0x0002 + 0x0300);
    }

    #[test]
    fn non_dnskey_is_none() {
        assert_eq!(dnskey_key_tag(&RData::A([1, 2, 3, 4].into())), None);
    }
}
