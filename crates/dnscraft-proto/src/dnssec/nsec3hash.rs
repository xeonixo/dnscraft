//! NSEC3 owner name hashing (RFC 5155 section 5) and base32hex (RFC 4648).

use ring::digest;

use crate::error::ProtoError;
use crate::name::Name;

/// The only defined NSEC3 hash algorithm: SHA-1.
pub const NSEC3_HASH_SHA1: u8 = 1;

/// Default cap on NSEC3 iterations (RFC 9276 recommends 0; resolvers
/// commonly treat anything above 150 as insecure). Callers pass their own cap
/// to [`nsec3_hash`].
pub const MAX_ITERATIONS_DEFAULT: u16 = 150;

/// Computes the iterated NSEC3 hash of `name`:
/// `IH(salt, x, 0) = H(x | salt)`, `IH(salt, x, k) = H(IH(salt, x, k-1) | salt)`
/// where `x` is the canonical (lowercase, uncompressed) wire form of `name`.
///
/// `iterations` is the number of *additional* iterations from the NSEC3
/// record. Fails with [`ProtoError::Nsec3IterationsTooHigh`] when it exceeds
/// `max_iterations` and with [`ProtoError::UnsupportedNsec3Algorithm`] for an
/// algorithm other than 1.
pub fn nsec3_hash(
    algorithm: u8,
    name: &Name,
    salt: &[u8],
    iterations: u16,
    max_iterations: u16,
) -> Result<[u8; 20], ProtoError> {
    if algorithm != NSEC3_HASH_SHA1 {
        return Err(ProtoError::UnsupportedNsec3Algorithm { algorithm });
    }
    if iterations > max_iterations {
        return Err(ProtoError::Nsec3IterationsTooHigh {
            iterations,
            max: max_iterations,
        });
    }
    let mut input = Vec::with_capacity(name.wire_len() + salt.len());
    name.encode_canonical(&mut input);
    input.extend_from_slice(salt);
    let mut out = [0u8; 20];
    let mut hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
    for _ in 0..iterations {
        let mut next = Vec::with_capacity(20 + salt.len());
        next.extend_from_slice(hash.as_ref());
        next.extend_from_slice(salt);
        hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &next);
    }
    out.copy_from_slice(hash.as_ref());
    Ok(out)
}

const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

/// Encodes `data` as base32hex (RFC 4648 section 7) in lowercase, without
/// padding, as used in NSEC3 owner labels.
pub fn base32hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in data {
        acc = acc << 8 | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = usize::try_from((acc >> bits) & 31).unwrap_or(0);
            out.push(char::from(ALPHABET.get(idx).copied().unwrap_or(b'0')));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        let idx = usize::try_from((acc << (5 - bits)) & 31).unwrap_or(0);
        out.push(char::from(ALPHABET.get(idx).copied().unwrap_or(b'0')));
    }
    out
}

/// Decodes unpadded base32hex, accepting upper and lower case.
///
/// Rejects padding, characters outside the alphabet, impossible lengths and
/// non-zero trailing bits (so the encoding is canonical).
pub fn base32hex_decode(text: &str) -> Result<Vec<u8>, ProtoError> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in text.bytes() {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'v' => c - b'a' + 10,
            b'A'..=b'V' => c - b'A' + 10,
            _ => return Err(ProtoError::InvalidBase32),
        };
        acc = acc << 5 | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).unwrap_or(0));
            acc &= (1 << bits) - 1;
        }
    }
    // Leftover bits must be fewer than 5 (a whole character of padding would
    // mean a non-canonical length) and zero.
    if bits >= 5 || acc != 0 {
        return Err(ProtoError::InvalidBase32);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).expect("name")
    }

    const SALT: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];

    fn h(name: &str) -> String {
        base32hex_encode(&nsec3_hash(1, &n(name), &SALT, 12, 150).expect("hash"))
    }

    #[test]
    fn rfc5155_appendix_a_vectors() {
        // RFC 5155 Appendix A: salt aabbccdd, 12 iterations.
        assert_eq!(h("example"), "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom");
        assert_eq!(h("a.example"), "35mthgpgcu1qg68fab165klnsnk3dpvl");
        assert_eq!(h("ai.example"), "gjeqe526plbf1g8mklp59enfd789njgi");
        assert_eq!(h("ns1.example"), "2t7b4g4vsa5smi47k61mv5bv1a22bojr");
        assert_eq!(h("ns2.example"), "q04jkcevqvmu85r014c7dkba38o0ji5r");
        assert_eq!(h("w.example"), "k8udemvp1j2f7eg6jebps17vp3n8i58h");
        assert_eq!(h("*.w.example"), "r53bq7cc2uvmubfu5ocmm6pers9tk9en");
        assert_eq!(h("x.w.example"), "b4um86eghhds6nea196smvmlo4ors995");
        assert_eq!(h("y.w.example"), "ji6neoaepv8b5o6k4ev33abha8ht9fgc");
        assert_eq!(h("x.y.w.example"), "2vptu5timamqttgl4luu9kg21e0aor3s");
        assert_eq!(h("xx.example"), "t644ebqk9bibcna874givr6joj62mlhv");
    }

    #[test]
    fn hash_is_case_insensitive() {
        assert_eq!(h("EXAMPLE"), h("example"));
    }

    #[test]
    fn iteration_cap_and_algorithm() {
        assert_eq!(
            nsec3_hash(1, &n("a."), &[], 151, MAX_ITERATIONS_DEFAULT),
            Err(ProtoError::Nsec3IterationsTooHigh {
                iterations: 151,
                max: 150
            })
        );
        assert!(nsec3_hash(1, &n("a."), &[], 150, MAX_ITERATIONS_DEFAULT).is_ok());
        assert!(nsec3_hash(1, &n("a."), &[], 0, 0).is_ok());
        assert_eq!(
            nsec3_hash(2, &n("a."), &[], 0, 150),
            Err(ProtoError::UnsupportedNsec3Algorithm { algorithm: 2 })
        );
    }

    #[test]
    fn base32hex_rfc4648_vectors() {
        for (raw, enc) in [
            ("", ""),
            ("f", "co"),
            ("fo", "cpng"),
            ("foo", "cpnmu"),
            ("foob", "cpnmuog"),
            ("fooba", "cpnmuoj1"),
            ("foobar", "cpnmuoj1e8"),
        ] {
            assert_eq!(base32hex_encode(raw.as_bytes()), enc);
            assert_eq!(base32hex_decode(enc).expect("decode"), raw.as_bytes());
            assert_eq!(
                base32hex_decode(&enc.to_ascii_uppercase()).expect("decode"),
                raw.as_bytes()
            );
        }
    }

    #[test]
    fn base32hex_round_trip_all_lengths() {
        let data: Vec<u8> = (0..=255u8).collect();
        for len in 0..40 {
            let slice = data.get(..len).expect("slice");
            assert_eq!(base32hex_decode(&base32hex_encode(slice)).unwrap(), slice);
        }
    }

    #[test]
    fn base32hex_rejections() {
        for bad in [
            "c",
            "co=",
            "w",
            "co o",
            "cpngx",
            "cp",
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tow",
        ] {
            assert_eq!(
                base32hex_decode(bad),
                Err(ProtoError::InvalidBase32),
                "{bad}"
            );
        }
    }
}
