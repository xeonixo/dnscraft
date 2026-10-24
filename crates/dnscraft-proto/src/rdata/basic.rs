//! Decoding and encoding of the fixed-layout and simple RDATA types.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::{RData, Reader, invalid};
use crate::error::ProtoError;
use crate::rtype::RecordType;

pub(super) fn decode_a(r: &mut Reader<'_>) -> Result<RData, ProtoError> {
    let b = r.bytes(4)?;
    let mut o = [0u8; 4];
    o.copy_from_slice(b);
    Ok(RData::A(Ipv4Addr::from(o)))
}

pub(super) fn decode_aaaa(r: &mut Reader<'_>) -> Result<RData, ProtoError> {
    let b = r.bytes(16)?;
    let mut o = [0u8; 16];
    o.copy_from_slice(b);
    Ok(RData::AAAA(Ipv6Addr::from(o)))
}

pub(super) fn decode_soa(r: &mut Reader<'_>) -> Result<RData, ProtoError> {
    Ok(RData::SOA {
        mname: r.name()?,
        rname: r.name()?,
        serial: r.u32()?,
        refresh: r.u32()?,
        retry: r.u32()?,
        expire: r.u32()?,
        minimum: r.u32()?,
    })
}

pub(super) fn decode_mx(r: &mut Reader<'_>) -> Result<RData, ProtoError> {
    Ok(RData::MX {
        preference: r.u16()?,
        exchange: r.name()?,
    })
}

pub(super) fn decode_srv(r: &mut Reader<'_>) -> Result<RData, ProtoError> {
    Ok(RData::SRV {
        priority: r.u16()?,
        weight: r.u16()?,
        port: r.u16()?,
        target: r.name()?,
    })
}

pub(super) fn decode_txt(r: &mut Reader<'_>) -> Result<RData, ProtoError> {
    if r.remaining() == 0 {
        return Err(invalid(
            RecordType::TXT,
            "TXT needs at least one character-string",
        ));
    }
    let mut strings: Vec<Box<[u8]>> = Vec::new();
    while r.remaining() > 0 {
        let len = usize::from(r.u8()?);
        strings.push(r.bytes(len)?.into());
    }
    Ok(RData::TXT(strings))
}

pub(super) fn encode_txt(strings: &[Box<[u8]>], buf: &mut Vec<u8>) -> Result<(), ProtoError> {
    if strings.is_empty() {
        return Err(invalid(
            RecordType::TXT,
            "TXT needs at least one character-string",
        ));
    }
    for s in strings {
        let len = u8::try_from(s.len())
            .map_err(|_| invalid(RecordType::TXT, "character-string longer than 255 octets"))?;
        buf.push(len);
        buf.extend_from_slice(s);
    }
    Ok(())
}

fn valid_caa_tag(tag: &[u8]) -> bool {
    (1..=15).contains(&tag.len()) && tag.iter().all(u8::is_ascii_alphanumeric)
}

pub(super) fn decode_caa(r: &mut Reader<'_>) -> Result<RData, ProtoError> {
    let flags = r.u8()?;
    let tag_len = usize::from(r.u8()?);
    let tag = r.bytes(tag_len)?;
    if !valid_caa_tag(tag) {
        return Err(invalid(
            RecordType::CAA,
            "tag must be 1 to 15 ASCII letters or digits",
        ));
    }
    let tag = std::str::from_utf8(tag)
        .map_err(|_| invalid(RecordType::CAA, "tag is not ASCII"))?
        .into();
    Ok(RData::CAA {
        flags,
        tag,
        value: r.rest().into(),
    })
}

pub(super) fn encode_caa(
    flags: u8,
    tag: &str,
    value: &[u8],
    buf: &mut Vec<u8>,
) -> Result<(), ProtoError> {
    if !valid_caa_tag(tag.as_bytes()) {
        return Err(invalid(
            RecordType::CAA,
            "tag must be 1 to 15 ASCII letters or digits",
        ));
    }
    buf.push(flags);
    buf.push(u8::try_from(tag.len()).map_err(|_| invalid(RecordType::CAA, "tag too long"))?);
    buf.extend_from_slice(tag.as_bytes());
    buf.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn dec(rtype: RecordType, bytes: &[u8]) -> Result<RData, ProtoError> {
        RData::decode(bytes, rtype, 0, bytes.len())
    }

    #[test]
    fn txt_empty_rdata_is_an_error() {
        assert_eq!(
            dec(RecordType::TXT, &[]),
            Err(ProtoError::InvalidRdata {
                rtype: 16,
                reason: "TXT needs at least one character-string"
            })
        );
        let mut buf = vec![9];
        assert!(RData::TXT(Vec::new()).encode(&mut buf, None).is_err());
        assert_eq!(buf, [9], "buffer restored on error");
    }

    #[test]
    fn txt_strings() {
        let r = dec(RecordType::TXT, b"\x02ab\x00\x01c").expect("txt");
        assert_eq!(
            r,
            RData::TXT(vec![
                b"ab".to_vec().into(),
                Vec::new().into(),
                b"c".to_vec().into()
            ])
        );
        // String runs past RDLENGTH.
        assert!(matches!(
            dec(RecordType::TXT, b"\x05ab"),
            Err(ProtoError::RdataLengthMismatch { .. })
        ));
        // Overlong string on encode.
        let long = RData::TXT(vec![vec![0u8; 256].into()]);
        assert!(long.encode(&mut Vec::new(), None).is_err());
        let max = RData::TXT(vec![vec![0u8; 255].into()]);
        let mut buf = Vec::new();
        max.encode(&mut buf, None).expect("max string");
        assert_eq!(buf.len(), 256);
    }

    #[test]
    fn caa_tag_rules() {
        let ok = dec(RecordType::CAA, b"\x00\x05issueca.example").expect("caa");
        assert_eq!(
            ok,
            RData::CAA {
                flags: 0,
                tag: "issue".into(),
                value: b"ca.example".to_vec().into()
            }
        );
        for bad in [
            &b"\x00\x00value"[..],
            b"\x00\x03a-bvalue",
            b"\x00\x10aaaaaaaaaaaaaaaax",
            b"\x00\x03a\xC3\xA9",
        ] {
            assert!(
                matches!(
                    dec(RecordType::CAA, bad),
                    Err(ProtoError::InvalidRdata { rtype: 257, .. })
                ),
                "{bad:?}"
            );
        }
        // Tag longer than RDLENGTH.
        assert!(matches!(
            dec(RecordType::CAA, b"\x00\x09abc"),
            Err(ProtoError::RdataLengthMismatch { .. })
        ));
        let bad = RData::CAA {
            flags: 0,
            tag: "bad tag".into(),
            value: Box::new([]),
        };
        assert!(bad.encode(&mut Vec::new(), None).is_err());
    }

    #[test]
    fn caa_empty_value_round_trips() {
        let r = RData::CAA {
            flags: 0,
            tag: "iodef".into(),
            value: Box::new([]),
        };
        let mut buf = Vec::new();
        r.encode(&mut buf, None).expect("encode");
        assert_eq!(dec(RecordType::CAA, &buf), Ok(r));
    }

    #[test]
    fn fixed_sizes() {
        assert_eq!(
            dec(RecordType::A, &[10, 0, 0, 1]),
            Ok(RData::A(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert!(dec(RecordType::A, &[]).is_err());
        assert!(dec(RecordType::AAAA, &[0; 16]).is_ok());
    }
}
