//! DNSSEC RDATA (RFC 4034, RFC 5155): DNSKEY, DS, RRSIG, NSEC, NSEC3 and
//! NSEC3PARAM, plus the NSEC/NSEC3 type bitmap.

use super::{RData, Reader, invalid};
use crate::error::ProtoError;
use crate::rtype::RecordType;

/// The set of record types of an NSEC or NSEC3 record (RFC 4034 section 4.1.2).
///
/// Stored as a sorted, duplicate-free list. The wire form is a sequence of
/// window blocks (window number, bitmap length 1 to 32, bitmap); the encoder
/// never emits trailing zero octets or empty blocks. The decoder is strict:
/// windows must strictly increase, bitmap lengths must be 1 to 32, and a
/// bitmap may not end in a zero octet (that would be a non-minimal
/// encoding, which would not re-encode to the signed octets).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TypeBitmap {
    types: Vec<RecordType>,
}

impl TypeBitmap {
    /// Builds a bitmap from any collection of types; order and duplicates
    /// do not matter.
    pub fn new(types: impl IntoIterator<Item = RecordType>) -> Self {
        let mut types: Vec<RecordType> = types.into_iter().collect();
        types.sort_unstable();
        types.dedup();
        Self { types }
    }

    /// Whether `rtype` is in the set.
    pub fn contains(&self, rtype: RecordType) -> bool {
        self.types.binary_search(&rtype).is_ok()
    }

    /// Iterates over the types in ascending numeric order.
    pub fn iter(&self) -> impl Iterator<Item = RecordType> + '_ {
        self.types.iter().copied()
    }

    /// Number of types in the set.
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Decodes the window blocks occupying exactly `data`.
    pub fn decode(data: &[u8]) -> Result<Self, ProtoError> {
        let bad = |reason| ProtoError::InvalidTypeBitmap { reason };
        let mut types = Vec::new();
        let mut rest = data;
        let mut previous: Option<u8> = None;
        while !rest.is_empty() {
            let (&window, tail) = rest.split_first().ok_or(bad("truncated"))?;
            let (&len, tail) = tail.split_first().ok_or(bad("missing bitmap length"))?;
            if previous.is_some_and(|p| window <= p) {
                return Err(bad("windows not strictly increasing"));
            }
            previous = Some(window);
            if !(1..=32).contains(&len) {
                return Err(bad("bitmap length not in 1..=32"));
            }
            let (bitmap, tail) = tail
                .split_at_checked(usize::from(len))
                .ok_or(bad("bitmap runs past the end"))?;
            if bitmap.last() == Some(&0) {
                return Err(bad("bitmap has a trailing zero octet"));
            }
            for (i, &octet) in bitmap.iter().enumerate() {
                for bit in 0..8u16 {
                    if octet & (0x80 >> bit) != 0 {
                        // i < 32, so this cannot overflow.
                        let low = u16::try_from(i).unwrap_or(0) * 8 + bit;
                        types.push(RecordType(u16::from(window) << 8 | low));
                    }
                }
            }
            rest = tail;
        }
        Ok(Self { types })
    }

    /// Appends the window blocks to `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        let mut iter = self.types.iter().map(|t| t.value()).peekable();
        while let Some(&first) = iter.peek() {
            let window = first >> 8;
            let mut bitmap = [0u8; 32];
            let mut used = 0usize;
            while let Some(&v) = iter.peek() {
                if v >> 8 != window {
                    break;
                }
                iter.next();
                let low = usize::from(v & 0xFF);
                if let Some(octet) = bitmap.get_mut(low / 8) {
                    *octet |= 0x80 >> (low % 8);
                }
                used = low / 8 + 1;
            }
            buf.push(u8::try_from(window).unwrap_or(0));
            buf.push(u8::try_from(used).unwrap_or(0));
            buf.extend_from_slice(bitmap.get(..used).unwrap_or(&[]));
        }
    }
}

fn read_len_prefixed<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], ProtoError> {
    let len = usize::from(r.u8()?);
    r.bytes(len)
}

fn push_len_prefixed(
    rtype: RecordType,
    data: &[u8],
    buf: &mut Vec<u8>,
    reason: &'static str,
) -> Result<(), ProtoError> {
    let len = u8::try_from(data.len()).map_err(|_| invalid(rtype, reason))?;
    buf.push(len);
    buf.extend_from_slice(data);
    Ok(())
}

pub(super) fn decode_dnskey(r: &mut Reader<'_>) -> Result<RData, ProtoError> {
    Ok(RData::DNSKEY {
        flags: r.u16()?,
        protocol: r.u8()?,
        algorithm: r.u8()?,
        public_key: r.rest().into(),
    })
}

pub(super) fn decode_ds(r: &mut Reader<'_>) -> Result<RData, ProtoError> {
    Ok(RData::DS {
        key_tag: r.u16()?,
        algorithm: r.u8()?,
        digest_type: r.u8()?,
        digest: r.rest().into(),
    })
}

pub(super) fn decode_rrsig(r: &mut Reader<'_>) -> Result<RData, ProtoError> {
    Ok(RData::RRSIG {
        type_covered: RecordType(r.u16()?),
        algorithm: r.u8()?,
        labels: r.u8()?,
        original_ttl: r.u32()?,
        expiration: r.u32()?,
        inception: r.u32()?,
        key_tag: r.u16()?,
        signer_name: r.name()?,
        signature: r.rest().into(),
    })
}

pub(super) fn decode_nsec(r: &mut Reader<'_>) -> Result<RData, ProtoError> {
    let next_domain = r.name()?;
    let types = TypeBitmap::decode(r.rest())?;
    Ok(RData::NSEC { next_domain, types })
}

pub(super) fn decode_nsec3(r: &mut Reader<'_>) -> Result<RData, ProtoError> {
    let hash_algorithm = r.u8()?;
    let flags = r.u8()?;
    let iterations = r.u16()?;
    let salt = read_len_prefixed(r)?.into();
    let next_hashed_owner = read_len_prefixed(r)?;
    if next_hashed_owner.is_empty() {
        return Err(invalid(
            RecordType::NSEC3,
            "next hashed owner name is empty",
        ));
    }
    let next_hashed_owner = next_hashed_owner.into();
    let types = TypeBitmap::decode(r.rest())?;
    Ok(RData::NSEC3 {
        hash_algorithm,
        flags,
        iterations,
        salt,
        next_hashed_owner,
        types,
    })
}

pub(super) fn decode_nsec3param(r: &mut Reader<'_>) -> Result<RData, ProtoError> {
    Ok(RData::NSEC3PARAM {
        hash_algorithm: r.u8()?,
        flags: r.u8()?,
        iterations: r.u16()?,
        salt: read_len_prefixed(r)?.into(),
    })
}

pub(super) fn encode_nsec3(
    parts: (u8, u8, u16, &[u8], &[u8], &TypeBitmap),
    buf: &mut Vec<u8>,
) -> Result<(), ProtoError> {
    let (hash_algorithm, flags, iterations, salt, next, types) = parts;
    if next.is_empty() {
        return Err(invalid(
            RecordType::NSEC3,
            "next hashed owner name is empty",
        ));
    }
    buf.push(hash_algorithm);
    buf.push(flags);
    buf.extend_from_slice(&iterations.to_be_bytes());
    push_len_prefixed(RecordType::NSEC3, salt, buf, "salt longer than 255 octets")?;
    push_len_prefixed(
        RecordType::NSEC3,
        next,
        buf,
        "next hashed owner name longer than 255 octets",
    )?;
    types.encode(buf);
    Ok(())
}

pub(super) fn encode_nsec3param(
    parts: (u8, u8, u16, &[u8]),
    buf: &mut Vec<u8>,
) -> Result<(), ProtoError> {
    let (hash_algorithm, flags, iterations, salt) = parts;
    buf.push(hash_algorithm);
    buf.push(flags);
    buf.extend_from_slice(&iterations.to_be_bytes());
    push_len_prefixed(
        RecordType::NSEC3PARAM,
        salt,
        buf,
        "salt longer than 255 octets",
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::name::Name;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).expect("valid name")
    }

    fn bitmap(types: &[u16]) -> TypeBitmap {
        TypeBitmap::new(types.iter().map(|&t| RecordType(t)))
    }

    fn wire(b: &TypeBitmap) -> Vec<u8> {
        let mut v = Vec::new();
        b.encode(&mut v);
        v
    }

    #[test]
    fn bitmap_rfc4034_example() {
        // A, MX, RRSIG, NSEC, TYPE1234 (RFC 4034 section 4.3).
        let b = bitmap(&[1, 15, 46, 47, 1234]);
        let expected: Vec<u8> = [
            &[0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03][..],
            &[0x04, 0x1b],
            &[0; 26],
            &[0x20],
        ]
        .concat();
        assert_eq!(wire(&b), expected);
        assert_eq!(TypeBitmap::decode(&expected).expect("decode"), b);
        assert!(b.contains(RecordType::MX));
        assert!(!b.contains(RecordType::NS));
        assert_eq!(b.len(), 5);
        assert_eq!(
            b.iter().map(RecordType::value).collect::<Vec<_>>(),
            [1, 15, 46, 47, 1234]
        );
    }

    #[test]
    fn bitmap_empty() {
        let b = bitmap(&[]);
        assert!(b.is_empty());
        assert!(wire(&b).is_empty());
        assert_eq!(TypeBitmap::decode(&[]).expect("decode"), b);
    }

    #[test]
    fn bitmap_max_window_and_dedup() {
        let b = bitmap(&[65535, 65535, 0, 255, 256]);
        assert_eq!(b.len(), 4);
        let w = wire(&b);
        assert_eq!(TypeBitmap::decode(&w).expect("decode"), b);
        // Last block: window 255, full 32 octet bitmap ending in 0x01.
        let tail = w.get(w.len() - 34..).expect("tail");
        assert_eq!(tail.first(), Some(&255));
        assert_eq!(tail.get(1), Some(&32));
        assert_eq!(tail.last(), Some(&0x01));
    }

    #[test]
    fn bitmap_rejections() {
        let cases: [&[u8]; 7] = [
            &[0, 1, 0x40, 0, 1, 0x40], // window repeated
            &[1, 1, 0x40, 0, 1, 0x40], // window decreasing
            &[0, 0],                   // zero-length bitmap
            &[0, 33, 0],               // too long
            &[0, 2, 0x40],             // runs past the end
            &[0],                      // missing length
            &[0, 2, 0x40, 0x00],       // trailing zero octet
        ];
        for c in cases {
            assert!(
                matches!(
                    TypeBitmap::decode(c),
                    Err(ProtoError::InvalidTypeBitmap { .. })
                ),
                "{c:?}"
            );
        }
    }

    fn round_trip(rtype: RecordType, rdata: &RData) -> Vec<u8> {
        assert_eq!(rdata.record_type(), rtype);
        let mut buf = Vec::new();
        rdata.encode(&mut buf, None).expect("encode");
        assert_eq!(
            &RData::decode(&buf, rtype, 0, buf.len()).expect("decode"),
            rdata
        );
        buf
    }

    #[test]
    fn round_trip_all_six() {
        round_trip(
            RecordType::DNSKEY,
            &RData::DNSKEY {
                flags: 257,
                protocol: 3,
                algorithm: 8,
                public_key: vec![1, 2, 3, 4].into(),
            },
        );
        round_trip(
            RecordType::DS,
            &RData::DS {
                key_tag: 20326,
                algorithm: 8,
                digest_type: 2,
                digest: vec![9; 32].into(),
            },
        );
        round_trip(
            RecordType::RRSIG,
            &RData::RRSIG {
                type_covered: RecordType::A,
                algorithm: 13,
                labels: 2,
                original_ttl: 300,
                expiration: 2,
                inception: 1,
                key_tag: 5,
                signer_name: n("Example.COM."),
                signature: vec![7; 64].into(),
            },
        );
        round_trip(
            RecordType::NSEC,
            &RData::NSEC {
                next_domain: n("b.example."),
                types: bitmap(&[1, 46, 47]),
            },
        );
        round_trip(
            RecordType::NSEC3,
            &RData::NSEC3 {
                hash_algorithm: 1,
                flags: 1,
                iterations: 12,
                salt: vec![0xAA, 0xBB].into(),
                next_hashed_owner: vec![3; 20].into(),
                types: bitmap(&[2, 43, 46]),
            },
        );
        round_trip(
            RecordType::NSEC3PARAM,
            &RData::NSEC3PARAM {
                hash_algorithm: 1,
                flags: 0,
                iterations: 0,
                salt: Box::new([]),
            },
        );
    }

    #[test]
    fn signer_and_next_names_never_compressed() {
        let rdata = RData::RRSIG {
            type_covered: RecordType::A,
            algorithm: 8,
            labels: 2,
            original_ttl: 0,
            expiration: 0,
            inception: 0,
            key_tag: 0,
            signer_name: n("example.com."),
            signature: Box::new([]),
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0; 12]);
        buf.extend_from_slice(n("example.com.").as_wire());
        let mut map = crate::name::CompressionMap::new();
        let before = buf.len();
        rdata.encode(&mut buf, Some(&mut map)).expect("encode");
        assert_eq!(buf.len() - before, 18 + 13);
    }

    #[test]
    fn lenient_pointer_in_signer_on_decode() {
        // Name at 0 ("a."), then an RRSIG whose signer is a pointer to 0.
        let mut msg = vec![1, b'a', 0];
        let start = msg.len();
        msg.extend_from_slice(&[
            0, 1, 8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 0,
        ]);
        let rd = RData::decode(&msg, RecordType::RRSIG, start, msg.len()).expect("decode");
        let RData::RRSIG { signer_name, .. } = rd else {
            panic!("not RRSIG");
        };
        assert_eq!(signer_name, n("a."));
    }

    #[test]
    fn malformed_rdata() {
        let nsec3_empty_next = [1, 0, 0, 0, 0, 0];
        assert!(matches!(
            RData::decode(&nsec3_empty_next, RecordType::NSEC3, 0, 6),
            Err(ProtoError::InvalidRdata { .. })
        ));
        for rtype in [
            RecordType::DNSKEY,
            RecordType::DS,
            RecordType::RRSIG,
            RecordType::NSEC,
            RecordType::NSEC3,
            RecordType::NSEC3PARAM,
        ] {
            assert!(
                matches!(
                    RData::decode(&[1], rtype, 0, 1),
                    Err(ProtoError::RdataLengthMismatch { .. })
                ),
                "{rtype}"
            );
        }
        // Salt length runs past RDLENGTH.
        assert!(RData::decode(&[1, 0, 0, 0, 9, 1], RecordType::NSEC3PARAM, 0, 6).is_err());
    }

    #[test]
    fn encode_validation_rolls_back() {
        let bad = RData::NSEC3PARAM {
            hash_algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: vec![0; 256].into(),
        };
        let mut buf = vec![0xEE];
        assert!(bad.encode(&mut buf, None).is_err());
        assert_eq!(buf, [0xEE]);
        let bad = RData::NSEC3 {
            hash_algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: Box::new([]),
            next_hashed_owner: Box::new([]),
            types: bitmap(&[]),
        };
        assert!(bad.encode(&mut buf, None).is_err());
        assert_eq!(buf, [0xEE]);
    }
}
