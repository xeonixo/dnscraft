//! Typed RDATA for the core record types.

mod basic;
mod dnssec;
mod svcb;

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::ProtoError;
use crate::name::{CompressionMap, Name};
use crate::rtype::RecordType;

pub use dnssec::TypeBitmap;
pub use svcb::SvcbData;

/// The data of a resource record.
///
/// Types without a dedicated variant (including OPT, which the message layer
/// intercepts) are kept as opaque bytes in
/// [`RData::Unknown`] per RFC 3597; their bytes are re-encoded verbatim.
///
/// Name compression: when encoding, only the names of `NS`, `CNAME`, `SOA`,
/// `PTR` and `MX` use the compression map (RFC 3597 section 4). `DNAME`,
/// `SRV`, `SVCB`/`HTTPS`, the RRSIG signer name, the NSEC next domain name and
/// everything else are written uncompressed (RFC 4034 sections 3.1.7 and
/// 4.1.1, RFC 6840 section 5.1). When
/// decoding, compression pointers are accepted in every name field of the
/// known types, including `DNAME`, `SRV`, the `SVCB`/`HTTPS` target and the
/// RRSIG signer / NSEC next names (which RFC 4034 forbids compressing), as
/// real servers sometimes emit them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RData {
    /// IPv4 address.
    A(Ipv4Addr),
    /// IPv6 address.
    AAAA(Ipv6Addr),
    /// Authoritative name server.
    NS(Name),
    /// Canonical name.
    CNAME(Name),
    /// Delegation name.
    DNAME(Name),
    /// Domain name pointer.
    PTR(Name),
    /// Start of authority.
    SOA {
        /// Primary name server.
        mname: Name,
        /// Responsible mailbox.
        rname: Name,
        /// Zone serial number.
        serial: u32,
        /// Refresh interval in seconds.
        refresh: u32,
        /// Retry interval in seconds.
        retry: u32,
        /// Expiry in seconds.
        expire: u32,
        /// Negative caching TTL (RFC 2308).
        minimum: u32,
    },
    /// Mail exchange.
    MX {
        /// Preference; lower is preferred.
        preference: u16,
        /// Mail server name.
        exchange: Name,
    },
    /// Text: one or more character-strings of at most 255 octets each.
    TXT(Vec<Box<[u8]>>),
    /// Service locator (RFC 2782).
    SRV {
        /// Priority; lower is preferred.
        priority: u16,
        /// Weight among equal priorities.
        weight: u16,
        /// Service port.
        port: u16,
        /// Target host.
        target: Name,
    },
    /// Certification authority authorization (RFC 8659).
    CAA {
        /// Flags octet (bit 0 is the issuer-critical flag).
        flags: u8,
        /// Property tag: 1 to 15 ASCII letters or digits.
        tag: Box<str>,
        /// Property value, opaque octets.
        value: Box<[u8]>,
    },
    /// General service binding (RFC 9460).
    SVCB(SvcbData),
    /// HTTPS service binding (RFC 9460).
    HTTPS(SvcbData),
    /// DNSSEC public key (RFC 4034 section 2).
    DNSKEY {
        /// Flags (bit 7 zone key, bit 15 secure entry point, bit 8 revoke).
        flags: u16,
        /// Protocol; always 3.
        protocol: u8,
        /// Signature algorithm number.
        algorithm: u8,
        /// Public key, algorithm-specific octets.
        public_key: Box<[u8]>,
    },
    /// Delegation signer (RFC 4034 section 5).
    DS {
        /// Key tag of the referenced DNSKEY.
        key_tag: u16,
        /// Signature algorithm of the referenced DNSKEY.
        algorithm: u8,
        /// Digest type (1 SHA-1, 2 SHA-256, 4 SHA-384).
        digest_type: u8,
        /// Digest of the DNSKEY.
        digest: Box<[u8]>,
    },
    /// RRset signature (RFC 4034 section 3).
    RRSIG {
        /// Type of the covered RRset.
        type_covered: RecordType,
        /// Signature algorithm number.
        algorithm: u8,
        /// Number of labels in the original owner name (without a leading
        /// wildcard label and the root).
        labels: u8,
        /// TTL of the RRset as signed.
        original_ttl: u32,
        /// Expiration as seconds since the epoch, modulo 2^32.
        expiration: u32,
        /// Inception as seconds since the epoch, modulo 2^32.
        inception: u32,
        /// Key tag of the signing DNSKEY.
        key_tag: u16,
        /// Name of the zone that owns the signing key.
        signer_name: Name,
        /// The signature octets.
        signature: Box<[u8]>,
    },
    /// Next secure record (RFC 4034 section 4).
    NSEC {
        /// Next owner name in canonical zone order.
        next_domain: Name,
        /// Types present at the owner name.
        types: TypeBitmap,
    },
    /// Hashed next secure record (RFC 5155 section 3).
    NSEC3 {
        /// Hash algorithm (1 is SHA-1).
        hash_algorithm: u8,
        /// Flags (bit 0 is opt-out).
        flags: u8,
        /// Additional hash iterations.
        iterations: u16,
        /// Salt, 0 to 255 octets.
        salt: Box<[u8]>,
        /// Next hashed owner name, 1 to 255 octets.
        next_hashed_owner: Box<[u8]>,
        /// Types present at the original owner name.
        types: TypeBitmap,
    },
    /// NSEC3 parameters (RFC 5155 section 4).
    NSEC3PARAM {
        /// Hash algorithm (1 is SHA-1).
        hash_algorithm: u8,
        /// Flags; must be 0 in NSEC3PARAM.
        flags: u8,
        /// Additional hash iterations.
        iterations: u16,
        /// Salt, 0 to 255 octets.
        salt: Box<[u8]>,
    },
    /// Any other type, as opaque bytes (RFC 3597).
    Unknown {
        /// The record type the bytes belong to.
        rtype: RecordType,
        /// The raw RDATA.
        data: Box<[u8]>,
    },
}

/// Bounded cursor over a message.
///
/// `msg` is cut off at the end of the region being parsed, so no read can go
/// past it, while compression pointers (which only point backwards) still
/// see the whole message prefix.
pub(crate) struct Reader<'a> {
    msg: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(msg: &'a [u8], pos: usize) -> Self {
        Self { msg, pos }
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn remaining(&self) -> usize {
        self.msg.len().saturating_sub(self.pos)
    }

    fn truncated(&self) -> ProtoError {
        ProtoError::Truncated {
            offset: self.msg.len(),
        }
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Result<&'a [u8], ProtoError> {
        let end = self.pos.checked_add(len).ok_or_else(|| self.truncated())?;
        let out = self
            .msg
            .get(self.pos..end)
            .ok_or_else(|| self.truncated())?;
        self.pos = end;
        Ok(out)
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let out = self.msg.get(self.pos..).unwrap_or(&[]);
        self.pos = self.msg.len();
        out
    }

    pub(crate) fn u8(&mut self) -> Result<u8, ProtoError> {
        Ok(self.bytes(1)?.first().copied().unwrap_or(0))
    }

    pub(crate) fn u16(&mut self) -> Result<u16, ProtoError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([
            b.first().copied().unwrap_or(0),
            b.get(1).copied().unwrap_or(0),
        ]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, ProtoError> {
        let b = self.bytes(4)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(b);
        Ok(u32::from_be_bytes(a))
    }

    pub(crate) fn name(&mut self) -> Result<Name, ProtoError> {
        let (name, next) = Name::decode(self.msg, self.pos)?;
        self.pos = next;
        Ok(name)
    }
}

pub(crate) fn invalid(rtype: RecordType, reason: &'static str) -> ProtoError {
    ProtoError::InvalidRdata {
        rtype: rtype.value(),
        reason,
    }
}

impl RData {
    /// The record type this data naturally belongs to.
    pub fn record_type(&self) -> RecordType {
        match self {
            Self::A(_) => RecordType::A,
            Self::AAAA(_) => RecordType::AAAA,
            Self::NS(_) => RecordType::NS,
            Self::CNAME(_) => RecordType::CNAME,
            Self::DNAME(_) => RecordType::DNAME,
            Self::PTR(_) => RecordType::PTR,
            Self::SOA { .. } => RecordType::SOA,
            Self::MX { .. } => RecordType::MX,
            Self::TXT(_) => RecordType::TXT,
            Self::SRV { .. } => RecordType::SRV,
            Self::CAA { .. } => RecordType::CAA,
            Self::SVCB(_) => RecordType::SVCB,
            Self::HTTPS(_) => RecordType::HTTPS,
            Self::DNSKEY { .. } => RecordType::DNSKEY,
            Self::DS { .. } => RecordType::DS,
            Self::RRSIG { .. } => RecordType::RRSIG,
            Self::NSEC { .. } => RecordType::NSEC,
            Self::NSEC3 { .. } => RecordType::NSEC3,
            Self::NSEC3PARAM { .. } => RecordType::NSEC3PARAM,
            Self::Unknown { rtype, .. } => *rtype,
        }
    }

    /// Decodes the RDATA of type `rtype` occupying `msg[start..end]`.
    ///
    /// The whole message is needed so that compression pointers can be
    /// resolved, but nothing at or beyond `end` is ever read. The parser
    /// must consume exactly `end - start` octets, otherwise
    /// [`ProtoError::RdataLengthMismatch`] is returned.
    pub fn decode(
        msg: &[u8],
        rtype: RecordType,
        start: usize,
        end: usize,
    ) -> Result<Self, ProtoError> {
        if end > msg.len() {
            return Err(ProtoError::Truncated { offset: msg.len() });
        }
        let mismatch = ProtoError::RdataLengthMismatch {
            rtype: rtype.value(),
            rdlength: end.saturating_sub(start),
        };
        let bounded = msg
            .get(..end)
            .ok_or(ProtoError::Truncated { offset: end })?;
        if start > end {
            return Err(mismatch);
        }
        let mut r = Reader::new(bounded, start);
        let rdata = match Self::decode_body(&mut r, rtype) {
            Ok(rdata) => rdata,
            // Running into the RDLENGTH bound means RDLENGTH is too small.
            Err(ProtoError::Truncated { .. }) => return Err(mismatch),
            Err(e) => return Err(e),
        };
        if r.remaining() != 0 {
            return Err(mismatch);
        }
        Ok(rdata)
    }

    fn decode_body(r: &mut Reader<'_>, rtype: RecordType) -> Result<Self, ProtoError> {
        match rtype {
            RecordType::A => basic::decode_a(r),
            RecordType::AAAA => basic::decode_aaaa(r),
            RecordType::NS => Ok(Self::NS(r.name()?)),
            RecordType::CNAME => Ok(Self::CNAME(r.name()?)),
            RecordType::DNAME => Ok(Self::DNAME(r.name()?)),
            RecordType::PTR => Ok(Self::PTR(r.name()?)),
            RecordType::SOA => basic::decode_soa(r),
            RecordType::MX => basic::decode_mx(r),
            RecordType::TXT => basic::decode_txt(r),
            RecordType::SRV => basic::decode_srv(r),
            RecordType::CAA => basic::decode_caa(r),
            RecordType::SVCB => Ok(Self::SVCB(svcb::decode(r, rtype)?)),
            RecordType::HTTPS => Ok(Self::HTTPS(svcb::decode(r, rtype)?)),
            RecordType::DNSKEY => dnssec::decode_dnskey(r),
            RecordType::DS => dnssec::decode_ds(r),
            RecordType::RRSIG => dnssec::decode_rrsig(r),
            RecordType::NSEC => dnssec::decode_nsec(r),
            RecordType::NSEC3 => dnssec::decode_nsec3(r),
            RecordType::NSEC3PARAM => dnssec::decode_nsec3param(r),
            // OPT is intercepted by the message layer; everything else stays
            // opaque (RFC 3597).
            other => Ok(Self::Unknown {
                rtype: other,
                data: r.rest().into(),
            }),
        }
    }

    /// Appends the RDATA (without RDLENGTH) to `buf`.
    ///
    /// `buf` must start at the beginning of the message when a compression
    /// map is given. See the type documentation for which names are
    /// compressed. On error `buf` is restored to its previous length.
    pub fn encode(
        &self,
        buf: &mut Vec<u8>,
        compression: Option<&mut CompressionMap>,
    ) -> Result<(), ProtoError> {
        let before = buf.len();
        let result = self.encode_body(buf, compression);
        if result.is_err() {
            buf.truncate(before);
        }
        result
    }

    fn encode_body(
        &self,
        buf: &mut Vec<u8>,
        mut compression: Option<&mut CompressionMap>,
    ) -> Result<(), ProtoError> {
        match self {
            Self::A(ip) => buf.extend_from_slice(&ip.octets()),
            Self::AAAA(ip) => buf.extend_from_slice(&ip.octets()),
            Self::NS(n) | Self::CNAME(n) | Self::PTR(n) => {
                n.encode(buf, compression.as_deref_mut());
            }
            Self::DNAME(n) => n.encode(buf, None),
            Self::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                mname.encode(buf, compression.as_deref_mut());
                rname.encode(buf, compression.as_deref_mut());
                for v in [serial, refresh, retry, expire, minimum] {
                    buf.extend_from_slice(&v.to_be_bytes());
                }
            }
            Self::MX {
                preference,
                exchange,
            } => {
                buf.extend_from_slice(&preference.to_be_bytes());
                exchange.encode(buf, compression);
            }
            Self::TXT(strings) => basic::encode_txt(strings, buf)?,
            Self::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                for v in [priority, weight, port] {
                    buf.extend_from_slice(&v.to_be_bytes());
                }
                target.encode(buf, None);
            }
            Self::CAA { flags, tag, value } => basic::encode_caa(*flags, tag, value, buf)?,
            Self::SVCB(d) => svcb::encode(d, RecordType::SVCB, buf)?,
            Self::HTTPS(d) => svcb::encode(d, RecordType::HTTPS, buf)?,
            Self::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            } => {
                buf.extend_from_slice(&flags.to_be_bytes());
                buf.push(*protocol);
                buf.push(*algorithm);
                buf.extend_from_slice(public_key);
            }
            Self::DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                buf.extend_from_slice(&key_tag.to_be_bytes());
                buf.push(*algorithm);
                buf.push(*digest_type);
                buf.extend_from_slice(digest);
            }
            Self::RRSIG {
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
                buf.extend_from_slice(&type_covered.value().to_be_bytes());
                buf.push(*algorithm);
                buf.push(*labels);
                for v in [original_ttl, expiration, inception] {
                    buf.extend_from_slice(&v.to_be_bytes());
                }
                buf.extend_from_slice(&key_tag.to_be_bytes());
                signer_name.encode(buf, None);
                buf.extend_from_slice(signature);
            }
            Self::NSEC { next_domain, types } => {
                next_domain.encode(buf, None);
                types.encode(buf);
            }
            Self::NSEC3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner,
                types,
            } => dnssec::encode_nsec3(
                (
                    *hash_algorithm,
                    *flags,
                    *iterations,
                    salt,
                    next_hashed_owner,
                    types,
                ),
                buf,
            )?,
            Self::NSEC3PARAM {
                hash_algorithm,
                flags,
                iterations,
                salt,
            } => dnssec::encode_nsec3param((*hash_algorithm, *flags, *iterations, salt), buf)?,
            Self::Unknown { data, .. } => buf.extend_from_slice(data),
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).expect("valid name")
    }

    fn round_trip(rtype: RecordType, rdata: &RData) -> Vec<u8> {
        let mut buf = Vec::new();
        rdata.encode(&mut buf, None).expect("encode");
        let back = RData::decode(&buf, rtype, 0, buf.len()).expect("decode");
        assert_eq!(&back, rdata);
        buf
    }

    #[test]
    fn round_trip_every_type() {
        let svcb = SvcbData {
            priority: 1,
            target: n("svc.example."),
            params: vec![(1, b"\x02h2".to_vec().into()), (3, vec![1, 187].into())],
        };
        let cases = [
            (RecordType::A, RData::A(Ipv4Addr::new(192, 0, 2, 1))),
            (RecordType::AAAA, RData::AAAA(Ipv6Addr::LOCALHOST)),
            (RecordType::NS, RData::NS(n("ns.example."))),
            (RecordType::CNAME, RData::CNAME(n("c.example."))),
            (RecordType::DNAME, RData::DNAME(n("d.example."))),
            (RecordType::PTR, RData::PTR(n("p.example."))),
            (
                RecordType::SOA,
                RData::SOA {
                    mname: n("ns.example."),
                    rname: n("host.example."),
                    serial: 1,
                    refresh: 2,
                    retry: 3,
                    expire: 4,
                    minimum: 5,
                },
            ),
            (
                RecordType::MX,
                RData::MX {
                    preference: 10,
                    exchange: n("mx.example."),
                },
            ),
            (
                RecordType::TXT,
                RData::TXT(vec![b"v=spf1".to_vec().into(), Vec::new().into()]),
            ),
            (
                RecordType::SRV,
                RData::SRV {
                    priority: 1,
                    weight: 2,
                    port: 443,
                    target: n("srv.example."),
                },
            ),
            (
                RecordType::CAA,
                RData::CAA {
                    flags: 128,
                    tag: "issue".into(),
                    value: b"ca.example".to_vec().into(),
                },
            ),
            (RecordType::SVCB, RData::SVCB(svcb.clone())),
            (RecordType::HTTPS, RData::HTTPS(svcb)),
            (
                RecordType(65280),
                RData::Unknown {
                    rtype: RecordType(65280),
                    data: vec![1, 2, 3].into(),
                },
            ),
            (
                RecordType::DS,
                RData::DS {
                    key_tag: 1,
                    algorithm: 8,
                    digest_type: 2,
                    digest: vec![9, 9].into(),
                },
            ),
        ];
        for (rtype, rdata) in cases {
            assert_eq!(rdata.record_type(), rtype);
            round_trip(rtype, &rdata);
        }
    }

    #[test]
    fn rdlength_larger_than_consumed() {
        for (rtype, bytes) in [
            (RecordType::A, vec![1, 2, 3, 4, 5]),
            (RecordType::AAAA, vec![0; 17]),
            (RecordType::NS, b"\x01a\x00\x00".to_vec()),
            (RecordType::MX, b"\x00\x01\x01a\x00\x00".to_vec()),
            (RecordType::SRV, b"\0\0\0\0\0\0\x00\x00".to_vec()),
        ] {
            assert_eq!(
                RData::decode(&bytes, rtype, 0, bytes.len()),
                Err(ProtoError::RdataLengthMismatch {
                    rtype: rtype.value(),
                    rdlength: bytes.len()
                }),
                "{rtype}"
            );
        }
    }

    #[test]
    fn rdlength_smaller_than_consumed() {
        let cases: [(RecordType, &[u8]); 5] = [
            (RecordType::A, &[1, 2, 3]),
            (RecordType::AAAA, &[0; 15]),
            (RecordType::NS, b"\x01a"),
            (RecordType::SOA, b"\x00\x00\x00\x00\x00\x00"),
            (RecordType::MX, b"\x00"),
        ];
        for (rtype, bytes) in cases {
            assert!(
                matches!(
                    RData::decode(bytes, rtype, 0, bytes.len()),
                    Err(ProtoError::RdataLengthMismatch { .. })
                ),
                "{rtype}"
            );
        }
    }

    #[test]
    fn bound_is_respected_for_names() {
        // The name would be complete if read past `end`; it must not be.
        let msg = b"\x01a\x00";
        assert!(matches!(
            RData::decode(msg, RecordType::NS, 0, 2),
            Err(ProtoError::RdataLengthMismatch { .. })
        ));
        // End beyond the message is a truncation, not a panic.
        assert_eq!(
            RData::decode(msg, RecordType::NS, 0, 9),
            Err(ProtoError::Truncated { offset: 3 })
        );
        assert!(RData::decode(msg, RecordType::A, 5, 4).is_err());
    }

    #[test]
    fn compression_pointers_decode_in_all_name_types() {
        // Offset 0 holds "example."; each RDATA points back at it.
        let mut msg = b"\x07example\x00".to_vec();
        let start = msg.len();
        msg.extend_from_slice(b"\x03www\xC0\x00");
        let end = msg.len();
        for rtype in [
            RecordType::NS,
            RecordType::CNAME,
            RecordType::PTR,
            RecordType::DNAME,
        ] {
            let r = RData::decode(&msg, rtype, start, end).expect("decode");
            assert!(
                matches!(&r, RData::NS(x) | RData::CNAME(x) | RData::PTR(x) | RData::DNAME(x) if *x == n("www.example."))
            );
        }
        let mut srv = msg[..start].to_vec();
        srv.extend_from_slice(b"\0\0\0\0\0\x50\x03www\xC0\x00");
        let r = RData::decode(&srv, RecordType::SRV, start, srv.len()).expect("srv");
        assert!(matches!(r, RData::SRV { port: 80, .. }));
    }

    #[test]
    fn compression_only_for_legacy_types() {
        let target = n("host.example.");
        let compressed_types = [
            (RecordType::NS, RData::NS(target.clone())),
            (RecordType::CNAME, RData::CNAME(target.clone())),
            (RecordType::PTR, RData::PTR(target.clone())),
            (
                RecordType::MX,
                RData::MX {
                    preference: 1,
                    exchange: target.clone(),
                },
            ),
        ];
        for (_, rdata) in compressed_types {
            let mut buf = Vec::new();
            let mut map = CompressionMap::new();
            target.encode(&mut buf, Some(&mut map));
            let before = buf.len();
            rdata.encode(&mut buf, Some(&mut map)).expect("encode");
            assert!(buf.len() - before < target.wire_len(), "{rdata:?}");
        }
        let uncompressed = [
            RData::DNAME(target.clone()),
            RData::SRV {
                priority: 0,
                weight: 0,
                port: 0,
                target: target.clone(),
            },
            RData::SVCB(SvcbData {
                priority: 1,
                target: target.clone(),
                params: Vec::new(),
            }),
            RData::HTTPS(SvcbData {
                priority: 1,
                target: target.clone(),
                params: Vec::new(),
            }),
        ];
        for rdata in uncompressed {
            let mut buf = Vec::new();
            let mut map = CompressionMap::new();
            target.encode(&mut buf, Some(&mut map));
            let before = buf.len();
            rdata.encode(&mut buf, Some(&mut map)).expect("encode");
            let tail = buf.get(before..).expect("tail");
            assert!(
                tail.windows(target.wire_len())
                    .any(|w| w == target.as_wire()),
                "{rdata:?}"
            );
        }
    }

    #[test]
    fn soa_compresses_both_names() {
        let rdata = RData::SOA {
            mname: n("ns.example."),
            rname: n("host.example."),
            serial: 0,
            refresh: 0,
            retry: 0,
            expire: 0,
            minimum: 0,
        };
        let mut buf = Vec::new();
        let mut map = CompressionMap::new();
        n("example.").encode(&mut buf, Some(&mut map));
        let before = buf.len();
        rdata.encode(&mut buf, Some(&mut map)).expect("encode");
        // "\x02ns" + ptr, "\x04host" + ptr, 20 bytes of numbers.
        assert_eq!(buf.len() - before, 5 + 7 + 20);
        let back = RData::decode(&buf, RecordType::SOA, before, buf.len()).expect("decode");
        assert_eq!(back, rdata);
    }

    #[test]
    fn opt_is_kept_as_unknown() {
        let r = RData::decode(&[0, 10, 0, 0], RecordType::OPT, 0, 4).expect("opt");
        assert_eq!(r.record_type(), RecordType::OPT);
        assert!(matches!(r, RData::Unknown { .. }));
    }
}
