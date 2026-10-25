//! Canonical RR form and RRset signing input (RFC 4034 sections 6.2 and 6.3,
//! RFC 4035 section 5.3.2, RFC 6840 section 5.1).
//!
//! # Embedded names (RFC 6840 section 5.1)
//!
//! RFC 4034 section 6.2 item 3 lists the types whose RDATA names are
//! lowercased. RFC 6840 section 5.1 keeps the next domain name of `NSEC`
//! as written (it is not lowercased), while the signer name of `RRSIG`
//! RDATA is lowercased. Unknown types are left alone. This module therefore
//! lowercases the names of NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR, MINFO, MX,
//! RP, AFSDB, RT, PX, KX, NAPTR, SRV and DNAME, plus the RRSIG signer name
//! (also required by RFC 4034 section 3.1.8.1 for the signing input).
//!
//! The obsolete types SIG, NXT and A6 are rejected with
//! [`ProtoError::UnsupportedCanonicalType`] instead of being guessed at.
//! Types without a typed variant (anything in [`RData::Unknown`]) are
//! handled when they appear in the list above; all others are copied
//! verbatim.

use crate::error::ProtoError;
use crate::name::Name;
use crate::rdata::{RData, Reader};
use crate::record::Record;
use crate::rtype::RecordType;

#[derive(Clone, Copy)]
enum Field {
    U16,
    Name,
    CharStr,
}

const MD: RecordType = RecordType(3);
const MF: RecordType = RecordType(4);
const MB: RecordType = RecordType(7);
const MG: RecordType = RecordType(8);
const MR: RecordType = RecordType(9);
const MINFO: RecordType = RecordType(14);
const RP: RecordType = RecordType(17);
const AFSDB: RecordType = RecordType(18);
const SIG: RecordType = RecordType(24);
const RT: RecordType = RecordType(21);
const PX: RecordType = RecordType(26);
const NXT: RecordType = RecordType(30);
const NAPTR: RecordType = RecordType(35);
const KX: RecordType = RecordType(36);
const A6: RecordType = RecordType(38);

/// Layout of opaque RDATA whose names must be lowercased, if any.
fn opaque_layout(rtype: RecordType) -> Result<Option<&'static [Field]>, ProtoError> {
    use Field::{CharStr, Name, U16};
    Ok(match rtype {
        MD
        | MF
        | MB
        | MG
        | MR
        | RecordType::NS
        | RecordType::CNAME
        | RecordType::PTR
        | RecordType::DNAME => Some(&[Name]),
        MINFO | RP => Some(&[Name, Name]),
        AFSDB | RT | KX => Some(&[U16, Name]),
        PX => Some(&[U16, Name, Name]),
        NAPTR => Some(&[U16, U16, CharStr, CharStr, CharStr, Name]),
        SIG | NXT | A6 => {
            return Err(ProtoError::UnsupportedCanonicalType {
                rtype: rtype.value(),
            });
        }
        _ => None,
    })
}

fn lowercase_opaque(
    rtype: RecordType,
    data: &[u8],
    layout: &[Field],
    out: &mut Vec<u8>,
) -> Result<(), ProtoError> {
    let mut r = Reader::new(data, 0);
    for field in layout {
        match field {
            Field::U16 => out.extend_from_slice(&r.u16()?.to_be_bytes()),
            Field::Name => r.name()?.encode_canonical(out),
            Field::CharStr => {
                let len = r.u8()?;
                out.push(len);
                out.extend_from_slice(r.bytes(usize::from(len))?);
            }
        }
    }
    if r.remaining() != 0 {
        return Err(ProtoError::RdataLengthMismatch {
            rtype: rtype.value(),
            rdlength: data.len(),
        });
    }
    Ok(())
}

/// The canonical RDATA octets of `rdata` (RFC 4034 section 6.2 items 1 and 3,
/// as updated by RFC 6840 section 5.1), without RDLENGTH.
pub fn canonical_rdata(rdata: &RData) -> Result<Vec<u8>, ProtoError> {
    let mut out = Vec::new();
    match rdata {
        RData::NS(n) | RData::CNAME(n) | RData::PTR(n) | RData::DNAME(n) => {
            n.encode_canonical(&mut out);
        }
        RData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            mname.encode_canonical(&mut out);
            rname.encode_canonical(&mut out);
            for v in [serial, refresh, retry, expire, minimum] {
                out.extend_from_slice(&v.to_be_bytes());
            }
        }
        RData::MX {
            preference,
            exchange,
        } => {
            out.extend_from_slice(&preference.to_be_bytes());
            exchange.encode_canonical(&mut out);
        }
        RData::SRV {
            priority,
            weight,
            port,
            target,
        } => {
            for v in [priority, weight, port] {
                out.extend_from_slice(&v.to_be_bytes());
            }
            target.encode_canonical(&mut out);
        }
        RData::Unknown { rtype, data } => match opaque_layout(*rtype)? {
            Some(layout) => lowercase_opaque(*rtype, data, layout, &mut out)?,
            None => out.extend_from_slice(data),
        },
        RData::RRSIG {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name,
            signature,
        } => {
            out.extend_from_slice(&type_covered.value().to_be_bytes());
            out.push(*algorithm);
            out.push(*labels);
            for v in [original_ttl, expiration, inception] {
                out.extend_from_slice(&v.to_be_bytes());
            }
            out.extend_from_slice(&key_tag.to_be_bytes());
            signer_name.encode_canonical(&mut out);
            out.extend_from_slice(signature);
        }
        // Everything else has no lowercased names: NSEC per RFC 6840 section
        // 5.1, and all newer types per RFC 3597 section 7.
        other => other.encode(&mut out, None)?,
    }
    Ok(out)
}

/// The owner name used in the signing input (RFC 4035 section 5.3.2):
/// lowercase, and for a wildcard expansion (`labels` below the owner's label
/// count) `*.` followed by the rightmost `labels` labels.
///
/// `labels` greater than the owner's label count is
/// [`ProtoError::RrsigLabelsTooMany`].
pub fn canonical_owner(owner: &Name, labels: u8) -> Result<Name, ProtoError> {
    let count = owner.label_count();
    let want = usize::from(labels);
    if want > count {
        return Err(ProtoError::RrsigLabelsTooMany {
            labels,
            owner_labels: count,
        });
    }
    let mut suffix = owner.to_lowercase();
    if want == count {
        return Ok(suffix);
    }
    for _ in 0..count - want {
        suffix = suffix.parent().ok_or(ProtoError::InvalidRrset {
            reason: "owner name has fewer labels than counted",
        })?;
    }
    let mut wire = vec![1, b'*'];
    wire.extend_from_slice(suffix.as_wire());
    Name::decode(&wire, 0).map(|(name, _)| name)
}

/// Builds the data covered by an RRSIG signature:
/// `RRSIG_RDATA (without the signature) | RR(1) | RR(2) | ...`.
///
/// `rrsig` must be [`RData::RRSIG`]. `rrset` must be non-empty and all its
/// records must share owner (case-insensitively), class, and a type equal to
/// the RRSIG's `type_covered`. Each RR is written with the canonical owner,
/// the original TTL from the RRSIG and canonical RDATA, the RRs are sorted by
/// canonical RDATA octets and exact duplicates are removed (RFC 4034
/// sections 6.2 and 6.3). Checking validity periods, algorithms or the
/// signature itself is the caller's job.
pub fn rrsig_signing_input(rrsig: &RData, rrset: &[Record]) -> Result<Vec<u8>, ProtoError> {
    let RData::RRSIG {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        expiration,
        inception,
        key_tag,
        signer_name,
        ..
    } = rrsig
    else {
        return Err(ProtoError::InvalidRrset {
            reason: "not an RRSIG",
        });
    };
    let first = rrset.first().ok_or(ProtoError::InvalidRrset {
        reason: "empty RRset",
    })?;
    let mut rdatas: Vec<Vec<u8>> = Vec::with_capacity(rrset.len());
    for rec in rrset {
        if rec.name != first.name || rec.class != first.class {
            return Err(ProtoError::InvalidRrset {
                reason: "records differ in owner or class",
            });
        }
        if rec.rtype() != *type_covered || rec.rdata.record_type() != *type_covered {
            return Err(ProtoError::InvalidRrset {
                reason: "record type differs from the RRSIG type covered",
            });
        }
        rdatas.push(canonical_rdata(&rec.rdata)?);
    }
    rdatas.sort_unstable();
    rdatas.dedup();

    let owner = canonical_owner(&first.name, *labels)?;

    let mut out = Vec::new();
    out.extend_from_slice(&type_covered.value().to_be_bytes());
    out.push(*algorithm);
    out.push(*labels);
    for v in [original_ttl, expiration, inception] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(&key_tag.to_be_bytes());
    signer_name.encode_canonical(&mut out);
    for rdata in &rdatas {
        let len = u16::try_from(rdata.len()).map_err(|_| ProtoError::InvalidRrset {
            reason: "RDATA longer than 65535 octets",
        })?;
        owner.encode_canonical(&mut out);
        out.extend_from_slice(&type_covered.value().to_be_bytes());
        out.extend_from_slice(&first.class.value().to_be_bytes());
        out.extend_from_slice(&original_ttl.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(rdata);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::rtype::Class;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).expect("name")
    }

    fn rec(owner: &str, rdata: RData) -> Record {
        Record {
            name: n(owner),
            class: Class::IN,
            ttl: 999,
            rdata,
        }
    }

    fn sig(rtype: RecordType, labels: u8) -> RData {
        RData::RRSIG {
            type_covered: rtype,
            algorithm: 8,
            labels,
            original_ttl: 3600,
            expiration: 200,
            inception: 100,
            key_tag: 7,
            signer_name: n("Example.COM."),
            signature: vec![1, 2, 3].into(),
        }
    }

    #[test]
    fn owner_forms() {
        assert_eq!(
            canonical_owner(&n("WWW.Example.com."), 3)
                .unwrap()
                .as_wire(),
            b"\x03www\x07example\x03com\x00"
        );
        assert_eq!(
            canonical_owner(&n("a.b.Example.com."), 2)
                .unwrap()
                .as_wire(),
            b"\x01*\x07example\x03com\x00"
        );
        assert_eq!(
            canonical_owner(&n("a.b.com."), 0).unwrap().as_wire(),
            b"\x01*\x00"
        );
        assert_eq!(
            canonical_owner(&n("a.com."), 3),
            Err(ProtoError::RrsigLabelsTooMany {
                labels: 3,
                owner_labels: 2
            })
        );
    }

    #[test]
    fn sorted_deduped_and_ttl_replaced() {
        let set = [
            rec("a.example.com.", RData::A([192, 0, 2, 2].into())),
            rec("A.example.com.", RData::A([192, 0, 2, 1].into())),
            rec("a.example.com.", RData::A([192, 0, 2, 2].into())),
        ];
        let out = rrsig_signing_input(&sig(RecordType::A, 3), &set).unwrap();
        let mut want = vec![
            0, 1, 8, 3, 0, 0, 0x0e, 0x10, 0, 0, 0, 200, 0, 0, 0, 100, 0, 7,
        ];
        want.extend_from_slice(b"\x07example\x03com\x00");
        for last in [1u8, 2] {
            want.extend_from_slice(b"\x01a\x07example\x03com\x00");
            want.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 192, 0, 2, last]);
        }
        assert_eq!(out, want);
    }

    #[test]
    fn rdata_names_lowercased_except_nsec() {
        assert_eq!(
            canonical_rdata(&RData::MX {
                preference: 10,
                exchange: n("MX.Example.")
            })
            .unwrap(),
            b"\x00\x0a\x02mx\x07example\x00"
        );
        let nsec = RData::NSEC {
            next_domain: n("NEXT.Example."),
            types: crate::TypeBitmap::new([RecordType::A]),
        };
        let got = canonical_rdata(&nsec).unwrap();
        assert!(got.starts_with(b"\x04NEXT\x07Example\x00"));
    }

    #[test]
    fn rrsig_signer_lowercased_nsec_next_kept() {
        // RRSIG: fixed header, then the lowercased signer name, then signature.
        let mut want = vec![
            0, 1, 8, 2, 0, 0, 0x0e, 0x10, 0, 0, 0, 200, 0, 0, 0, 100, 0, 7,
        ];
        want.extend_from_slice(b"\x07example\x03com\x00");
        want.extend_from_slice(&[1, 2, 3]);
        assert_eq!(canonical_rdata(&sig(RecordType::A, 2)).unwrap(), want);
        // NSEC: next domain name keeps its case.
        let nsec = RData::NSEC {
            next_domain: n("NEXT.Example."),
            types: crate::TypeBitmap::new([RecordType::A]),
        };
        assert!(
            canonical_rdata(&nsec)
                .unwrap()
                .starts_with(b"\x04NEXT\x07Example\x00")
        );
    }

    #[test]
    fn opaque_name_types() {
        // RP: two names.
        let rp = RData::Unknown {
            rtype: RP,
            data: b"\x01A\x00\x01B\x00".to_vec().into(),
        };
        assert_eq!(canonical_rdata(&rp).unwrap(), b"\x01a\x00\x01b\x00");
        // AFSDB: u16 + name.
        let afsdb = RData::Unknown {
            rtype: AFSDB,
            data: b"\x00\x01\x01X\x00".to_vec().into(),
        };
        assert_eq!(canonical_rdata(&afsdb).unwrap(), b"\x00\x01\x01x\x00");
        // NAPTR.
        let naptr = RData::Unknown {
            rtype: NAPTR,
            data: b"\x00\x01\x00\x02\x01U\x01S\x00\x01Z\x00".to_vec().into(),
        };
        assert_eq!(
            canonical_rdata(&naptr).unwrap(),
            b"\x00\x01\x00\x02\x01U\x01S\x00\x01z\x00"
        );
        // Unknown type kept verbatim; obsolete types refused.
        let other = RData::Unknown {
            rtype: RecordType(65280),
            data: b"\x01A".to_vec().into(),
        };
        assert_eq!(canonical_rdata(&other).unwrap(), b"\x01A");
        for t in [SIG, NXT, A6] {
            let d = RData::Unknown {
                rtype: t,
                data: Box::new([]),
            };
            assert!(matches!(
                canonical_rdata(&d),
                Err(ProtoError::UnsupportedCanonicalType { .. })
            ));
        }
        // Malformed opaque data errors instead of panicking.
        let bad = RData::Unknown {
            rtype: RP,
            data: b"\x05A".to_vec().into(),
        };
        assert!(canonical_rdata(&bad).is_err());
    }

    #[test]
    fn rejects_bad_rrsets() {
        let a = rec("a.example.", RData::A([1, 1, 1, 1].into()));
        let b = rec("b.example.", RData::A([1, 1, 1, 1].into()));
        let s = sig(RecordType::A, 2);
        assert!(rrsig_signing_input(&s, &[]).is_err());
        assert!(rrsig_signing_input(&s, &[a.clone(), b]).is_err());
        assert!(rrsig_signing_input(&sig(RecordType::MX, 2), std::slice::from_ref(&a)).is_err());
        assert!(rrsig_signing_input(&RData::A([1, 1, 1, 1].into()), &[a]).is_err());
    }
}
