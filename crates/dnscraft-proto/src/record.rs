//! Resource records: owner name, type, class, TTL and RDATA.

use crate::error::ProtoError;
use crate::name::{CompressionMap, Name};
use crate::rdata::{RData, Reader};
use crate::rtype::{Class, RecordType};

/// A resource record.
///
/// `rtype` and `rdata` are kept separately so that opaque types round-trip;
/// [`Record::encode`] writes both as given and does not check that they
/// agree (use [`RData::record_type`] to build consistent records).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Owner name.
    pub name: Name,
    /// Record type.
    pub rtype: RecordType,
    /// Record class.
    pub class: Class,
    /// Time to live in seconds.
    pub ttl: u32,
    /// Record data.
    pub rdata: RData,
}

impl Record {
    /// Decodes one record from `msg` at `offset`.
    ///
    /// Returns the record and the offset just after it (after RDLENGTH
    /// octets of RDATA). The RDATA parser may not read past RDLENGTH and must
    /// consume it exactly ([`ProtoError::RdataLengthMismatch`] otherwise).
    /// An RDLENGTH that runs past the end of `msg` is [`ProtoError::Truncated`].
    pub fn decode(msg: &[u8], offset: usize) -> Result<(Self, usize), ProtoError> {
        let (name, pos) = Name::decode(msg, offset)?;
        let mut r = Reader::new(msg, pos);
        let rtype = RecordType(r.u16()?);
        let class = Class(r.u16()?);
        let ttl = r.u32()?;
        let rdlength = usize::from(r.u16()?);
        let start = r.pos();
        let end = start + rdlength;
        let rdata = RData::decode(msg, rtype, start, end)?;
        Ok((
            Self {
                name,
                rtype,
                class,
                ttl,
                rdata,
            },
            end,
        ))
    }

    /// Appends the record to `buf`, patching RDLENGTH after the RDATA.
    ///
    /// `buf` must start at the beginning of the message when `compression`
    /// is given. The owner name and the names allowed by RFC 3597 section 4
    /// (see [`RData`]) use the map. On error `buf` is restored to its
    /// previous length.
    pub fn encode(
        &self,
        buf: &mut Vec<u8>,
        compression: Option<&mut CompressionMap>,
    ) -> Result<(), ProtoError> {
        let before = buf.len();
        let result = self.encode_inner(buf, compression);
        if result.is_err() {
            buf.truncate(before);
        }
        result
    }

    fn encode_inner(
        &self,
        buf: &mut Vec<u8>,
        mut compression: Option<&mut CompressionMap>,
    ) -> Result<(), ProtoError> {
        self.name.encode(buf, compression.as_deref_mut());
        buf.extend_from_slice(&self.rtype.value().to_be_bytes());
        buf.extend_from_slice(&self.class.value().to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        let len_at = buf.len();
        buf.extend_from_slice(&[0, 0]);
        self.rdata.encode(buf, compression)?;
        let rdlength = buf.len() - len_at - 2;
        let rdlength = u16::try_from(rdlength).map_err(|_| ProtoError::InvalidRdata {
            rtype: self.rtype.value(),
            reason: "rdata longer than 65535 octets",
        })?;
        if let Some(slot) = buf.get_mut(len_at..len_at + 2) {
            slot.copy_from_slice(&rdlength.to_be_bytes());
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).expect("valid name")
    }

    fn a_record(name: &str) -> Record {
        Record {
            name: n(name),
            rtype: RecordType::A,
            class: Class::IN,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        }
    }

    #[test]
    fn round_trip_and_rdlength_patch() {
        let rec = a_record("www.example.com.");
        let mut buf = Vec::new();
        rec.encode(&mut buf, None).expect("encode");
        assert_eq!(buf.len(), 17 + 10 + 4);
        assert_eq!(&buf[25..27], &[0, 4]);
        assert_eq!(Record::decode(&buf, 0), Ok((rec, buf.len())));
    }

    #[test]
    fn several_records_with_compression() {
        let recs = [
            a_record("www.example.com."),
            Record {
                name: n("example.com."),
                rtype: RecordType::MX,
                class: Class::IN,
                ttl: 60,
                rdata: RData::MX {
                    preference: 5,
                    exchange: n("mail.example.com."),
                },
            },
            a_record("mail.example.com."),
        ];
        let mut buf = vec![0u8; 12];
        let mut map = CompressionMap::new();
        for r in &recs {
            r.encode(&mut buf, Some(&mut map)).expect("encode");
        }
        let mut pos = 12;
        for r in &recs {
            let (got, next) = Record::decode(&buf, pos).expect("decode");
            assert_eq!(&got, r);
            pos = next;
        }
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn rdlength_mismatch_both_directions() {
        let rec = a_record("a.");
        let mut buf = Vec::new();
        rec.encode(&mut buf, None).expect("encode");
        let len_at = buf.len() - 6;
        // Larger than consumed: pad with a trailing byte so it fits the message.
        let mut big = buf.clone();
        big[len_at + 1] = 5;
        big.push(0);
        assert!(matches!(
            Record::decode(&big, 0),
            Err(ProtoError::RdataLengthMismatch {
                rtype: 1,
                rdlength: 5
            })
        ));
        // Smaller than consumed.
        let mut small = buf.clone();
        small[len_at + 1] = 3;
        assert!(matches!(
            Record::decode(&small, 0),
            Err(ProtoError::RdataLengthMismatch {
                rtype: 1,
                rdlength: 3
            })
        ));
        // RDLENGTH beyond the message.
        let mut long = buf.clone();
        long[len_at + 1] = 9;
        assert!(matches!(
            Record::decode(&long, 0),
            Err(ProtoError::Truncated { .. })
        ));
    }

    #[test]
    fn truncated_header_never_panics() {
        let rec = a_record("www.example.com.");
        let mut buf = Vec::new();
        rec.encode(&mut buf, None).expect("encode");
        for cut in 0..buf.len() {
            assert!(Record::decode(&buf[..cut], 0).is_err(), "cut {cut}");
        }
        assert!(Record::decode(&buf, buf.len() + 1).is_err());
    }

    #[test]
    fn unknown_type_round_trips_bytes() {
        let rec = Record {
            name: n("x."),
            rtype: RecordType(65280),
            class: Class(7),
            ttl: u32::MAX,
            rdata: RData::Unknown {
                rtype: RecordType(65280),
                data: vec![1, 2, 3].into(),
            },
        };
        let mut buf = Vec::new();
        rec.encode(&mut buf, None).expect("encode");
        assert_eq!(Record::decode(&buf, 0), Ok((rec, buf.len())));
    }

    #[test]
    fn encode_failure_restores_buffer() {
        let mut rec = a_record("a.");
        rec.rtype = RecordType::TXT;
        rec.rdata = RData::TXT(Vec::new());
        let mut buf = vec![1, 2, 3];
        assert!(rec.encode(&mut buf, None).is_err());
        assert_eq!(buf, [1, 2, 3]);
    }

    #[test]
    fn oversize_rdata_is_rejected() {
        let rec = Record {
            name: Name::root(),
            rtype: RecordType(65280),
            class: Class::IN,
            ttl: 0,
            rdata: RData::Unknown {
                rtype: RecordType(65280),
                data: vec![0u8; 65536].into(),
            },
        };
        assert!(rec.encode(&mut Vec::new(), None).is_err());
    }
}
