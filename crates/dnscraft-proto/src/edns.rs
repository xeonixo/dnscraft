//! EDNS(0): the OPT pseudo-record and its options (RFC 6891).

use crate::error::ProtoError;
use crate::name::Name;
use crate::rdata::{RData, Reader};
use crate::record::Record;
use crate::rtype::{Class, RecordType};

/// Option code of EDNS Client Subnet (RFC 7871).
pub const OPTION_ECS: u16 = 8;
/// Option code of DNS cookies (RFC 7873).
pub const OPTION_COOKIE: u16 = 10;
/// Option code of padding (RFC 7830).
pub const OPTION_PADDING: u16 = 12;
/// Option code of extended DNS errors (RFC 8914).
pub const OPTION_EDE: u16 = 15;

/// One EDNS option.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EdnsOption {
    /// EDNS Client Subnet (RFC 7871).
    ///
    /// `address` holds exactly `ceil(source_prefix / 8)` octets. Family 1
    /// (IPv4) allows prefixes up to 32, family 2 (IPv6) up to 128; other
    /// families are only checked for the address length. Non-zero bits
    /// beyond the source prefix are accepted on decode and kept verbatim.
    ClientSubnet {
        /// Address family number (1 = IPv4, 2 = IPv6).
        family: u16,
        /// Number of significant address bits in the query.
        source_prefix: u8,
        /// Number of address bits the answer covers.
        scope_prefix: u8,
        /// Truncated address octets.
        address: Box<[u8]>,
    },
    /// Extended DNS error (RFC 8914).
    ///
    /// The extra text should be UTF-8; on decode, invalid sequences are
    /// replaced with U+FFFD (lossy), so such a message does not re-encode to
    /// identical bytes.
    ExtendedError {
        /// Info code.
        info_code: u16,
        /// Human readable extra text, possibly empty.
        extra_text: Box<str>,
    },
    /// Padding of the given number of zero octets (RFC 7830). The content of
    /// received padding is ignored.
    Padding(u16),
    /// DNS cookie (RFC 7873).
    Cookie {
        /// Client cookie.
        client: [u8; 8],
        /// Server cookie, 8 to 32 octets, absent in the first query.
        server: Option<Box<[u8]>>,
    },
    /// Any other option, as opaque bytes.
    Unknown {
        /// Option code.
        code: u16,
        /// Option data.
        data: Box<[u8]>,
    },
}

fn bad(reason: &'static str) -> ProtoError {
    ProtoError::InvalidEdns { reason }
}

fn check_ecs(
    family: u16,
    source_prefix: u8,
    scope_prefix: u8,
    address_len: usize,
) -> Result<(), ProtoError> {
    let max = match family {
        1 => 32,
        2 => 128,
        _ => 255,
    };
    if source_prefix > max || scope_prefix > max {
        return Err(bad("client subnet prefix exceeds the address family size"));
    }
    if address_len != usize::from(source_prefix).div_ceil(8) {
        return Err(bad("client subnet address length does not match prefix"));
    }
    Ok(())
}

impl EdnsOption {
    /// The option code.
    pub fn code(&self) -> u16 {
        match self {
            Self::ClientSubnet { .. } => OPTION_ECS,
            Self::ExtendedError { .. } => OPTION_EDE,
            Self::Padding(_) => OPTION_PADDING,
            Self::Cookie { .. } => OPTION_COOKIE,
            Self::Unknown { code, .. } => *code,
        }
    }

    fn decode(code: u16, data: &[u8]) -> Result<Self, ProtoError> {
        let mut r = Reader::new(data, 0);
        match code {
            OPTION_ECS => {
                let family = r.u16()?;
                let source_prefix = r.u8()?;
                let scope_prefix = r.u8()?;
                let address: Box<[u8]> = r.rest().into();
                check_ecs(family, source_prefix, scope_prefix, address.len())?;
                Ok(Self::ClientSubnet {
                    family,
                    source_prefix,
                    scope_prefix,
                    address,
                })
            }
            OPTION_EDE => {
                let info_code = r.u16()?;
                let extra_text = String::from_utf8_lossy(r.rest()).into_owned().into();
                Ok(Self::ExtendedError {
                    info_code,
                    extra_text,
                })
            }
            OPTION_PADDING => {
                let len = u16::try_from(data.len()).map_err(|_| bad("padding too long"))?;
                Ok(Self::Padding(len))
            }
            OPTION_COOKIE => {
                let mut client = [0u8; 8];
                client.copy_from_slice(r.bytes(8)?);
                let rest = r.rest();
                let server = if rest.is_empty() {
                    None
                } else if (8..=32).contains(&rest.len()) {
                    Some(rest.into())
                } else {
                    return Err(bad("server cookie must be 8 to 32 octets"));
                };
                Ok(Self::Cookie { client, server })
            }
            _ => Ok(Self::Unknown {
                code,
                data: data.into(),
            }),
        }
    }

    /// Appends code, length and data to `buf`; restores `buf` on error.
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), ProtoError> {
        let before = buf.len();
        let result = self.encode_inner(buf);
        if result.is_err() {
            buf.truncate(before);
        }
        result
    }

    fn encode_inner(&self, buf: &mut Vec<u8>) -> Result<(), ProtoError> {
        buf.extend_from_slice(&self.code().to_be_bytes());
        let len_at = buf.len();
        buf.extend_from_slice(&[0, 0]);
        match self {
            Self::ClientSubnet {
                family,
                source_prefix,
                scope_prefix,
                address,
            } => {
                check_ecs(*family, *source_prefix, *scope_prefix, address.len())?;
                buf.extend_from_slice(&family.to_be_bytes());
                buf.extend_from_slice(&[*source_prefix, *scope_prefix]);
                buf.extend_from_slice(address);
            }
            Self::ExtendedError {
                info_code,
                extra_text,
            } => {
                buf.extend_from_slice(&info_code.to_be_bytes());
                buf.extend_from_slice(extra_text.as_bytes());
            }
            Self::Padding(len) => buf.resize(buf.len() + usize::from(*len), 0),
            Self::Cookie { client, server } => {
                buf.extend_from_slice(client);
                if let Some(server) = server {
                    if !(8..=32).contains(&server.len()) {
                        return Err(bad("server cookie must be 8 to 32 octets"));
                    }
                    buf.extend_from_slice(server);
                }
            }
            Self::Unknown { data, .. } => buf.extend_from_slice(data),
        }
        let len = u16::try_from(buf.len() - len_at - 2).map_err(|_| bad("option too long"))?;
        if let Some(slot) = buf.get_mut(len_at..len_at + 2) {
            slot.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }
}

/// The EDNS(0) data of a message, carried in an OPT pseudo-record.
///
/// On the wire the OPT record has the root as owner, the UDP payload size in
/// the CLASS field, and in the TTL: extended RCODE high bits, version, the DO
/// flag and 15 zero bits (ignored on decode). The extended RCODE bits are
/// managed through `Message::rcode`/`Message::set_rcode`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edns {
    /// Requestor's or responder's UDP payload size.
    pub udp_payload: u16,
    /// High 8 bits of the response code; see `Message::set_rcode`.
    pub(crate) extended_rcode_high: u8,
    /// EDNS version (0).
    pub version: u8,
    /// DNSSEC OK flag.
    pub dnssec_ok: bool,
    /// Options in wire order.
    pub options: Vec<EdnsOption>,
}

impl Edns {
    /// EDNS version 0 with the given payload size, no flags and no options.
    pub fn new(udp_payload: u16) -> Self {
        Self {
            udp_payload,
            extended_rcode_high: 0,
            version: 0,
            dnssec_ok: false,
            options: Vec::new(),
        }
    }

    /// Builds the EDNS data from a decoded OPT record.
    ///
    /// The owner must be the root ([`ProtoError::OptOwnerNotRoot`]) and the
    /// type must be OPT.
    pub fn from_record(record: &Record) -> Result<Self, ProtoError> {
        if record.rtype() != RecordType::OPT {
            return Err(bad("record is not an OPT record"));
        }
        if !record.name.is_root() {
            return Err(ProtoError::OptOwnerNotRoot);
        }
        let RData::Unknown { data, .. } = &record.rdata else {
            return Err(bad("OPT record has typed rdata"));
        };
        let mut r = Reader::new(data, 0);
        let mut options = Vec::new();
        while r.remaining() > 0 {
            let code = r.u16()?;
            let len = usize::from(r.u16()?);
            options.push(EdnsOption::decode(code, r.bytes(len)?)?);
        }
        let ttl = record.ttl;
        Ok(Self {
            udp_payload: record.class.value(),
            extended_rcode_high: (ttl >> 24) as u8,
            version: (ttl >> 16) as u8,
            dnssec_ok: ttl & 0x8000 != 0,
            options,
        })
    }

    /// Builds the OPT pseudo-record for this EDNS data.
    pub fn to_record(&self) -> Result<Record, ProtoError> {
        let mut data = Vec::new();
        for opt in &self.options {
            opt.encode(&mut data)?;
        }
        let ttl = (u32::from(self.extended_rcode_high) << 24)
            | (u32::from(self.version) << 16)
            | (u32::from(self.dnssec_ok) << 15);
        Ok(Record {
            name: Name::root(),
            class: Class(self.udp_payload),
            ttl,
            rdata: RData::Unknown {
                rtype: RecordType::OPT,
                data: data.into(),
            },
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn round_trip(edns: &Edns) -> Edns {
        let rec = edns.to_record().expect("to_record");
        let mut buf = Vec::new();
        rec.encode(&mut buf, None).expect("encode");
        let (back, end) = Record::decode(&buf, 0).expect("decode");
        assert_eq!(end, buf.len());
        Edns::from_record(&back).expect("from_record")
    }

    fn with(opt: EdnsOption) -> Edns {
        let mut e = Edns::new(1232);
        e.options.push(opt);
        e
    }

    #[test]
    fn plain_edns_round_trips() {
        let mut e = Edns::new(4096);
        e.dnssec_ok = true;
        e.version = 3;
        e.extended_rcode_high = 1;
        assert_eq!(round_trip(&e), e);
        let rec = e.to_record().unwrap();
        assert_eq!(rec.ttl, 0x0103_8000);
        assert_eq!(rec.class, Class(4096));
    }

    #[test]
    fn every_option_round_trips() {
        let opts = [
            EdnsOption::ClientSubnet {
                family: 1,
                source_prefix: 24,
                scope_prefix: 0,
                address: vec![192, 0, 2].into(),
            },
            EdnsOption::ClientSubnet {
                family: 2,
                source_prefix: 0,
                scope_prefix: 0,
                address: Box::new([]),
            },
            EdnsOption::ClientSubnet {
                family: 2,
                source_prefix: 57,
                scope_prefix: 56,
                address: vec![0x20, 1, 0xd, 0xb8, 0, 0, 0, 0x80].into(),
            },
            EdnsOption::ExtendedError {
                info_code: 22,
                extra_text: "no reachable authority".into(),
            },
            EdnsOption::ExtendedError {
                info_code: 0,
                extra_text: "".into(),
            },
            EdnsOption::Padding(0),
            EdnsOption::Padding(100),
            EdnsOption::Cookie {
                client: [1, 2, 3, 4, 5, 6, 7, 8],
                server: None,
            },
            EdnsOption::Cookie {
                client: [1; 8],
                server: Some(vec![9; 8].into()),
            },
            EdnsOption::Cookie {
                client: [1; 8],
                server: Some(vec![9; 32].into()),
            },
            EdnsOption::Unknown {
                code: 65001,
                data: vec![1, 2, 3].into(),
            },
        ];
        for o in opts {
            let e = with(o);
            assert_eq!(round_trip(&e), e);
        }
        let mut all = Edns::new(512);
        all.options = vec![
            EdnsOption::Padding(3),
            EdnsOption::Unknown {
                code: 1,
                data: Box::new([]),
            },
        ];
        assert_eq!(round_trip(&all), all);
    }

    #[test]
    fn padding_encodes_zeros() {
        let rec = with(EdnsOption::Padding(4)).to_record().unwrap();
        let RData::Unknown { data, .. } = rec.rdata else {
            panic!("expected opaque rdata");
        };
        assert_eq!(&*data, &[0, 12, 0, 4, 0, 0, 0, 0]);
    }

    #[test]
    fn invalid_ecs_is_rejected_both_ways() {
        let bad_opts = [
            (1u16, 24u8, 0u8, vec![1, 2]),
            (1, 24, 0, vec![1, 2, 3, 4]),
            (1, 33, 0, vec![1, 2, 3, 4, 5]),
            (1, 8, 33, vec![1]),
            (2, 129, 0, vec![0; 17]),
            (2, 0, 0, vec![0]),
        ];
        for (family, source_prefix, scope_prefix, address) in bad_opts {
            let o = EdnsOption::ClientSubnet {
                family,
                source_prefix,
                scope_prefix,
                address: address.clone().into(),
            };
            assert!(with(o).to_record().is_err(), "{family}/{source_prefix}");
            let mut data = family.to_be_bytes().to_vec();
            data.extend_from_slice(&[source_prefix, scope_prefix]);
            data.extend_from_slice(&address);
            assert!(EdnsOption::decode(OPTION_ECS, &data).is_err());
        }
        assert!(EdnsOption::decode(OPTION_ECS, &[0, 1, 8]).is_err());
    }

    #[test]
    fn cookie_size_limits() {
        for server_len in [1usize, 7, 33, 40] {
            let o = EdnsOption::Cookie {
                client: [0; 8],
                server: Some(vec![0; server_len].into()),
            };
            assert!(with(o).to_record().is_err(), "{server_len}");
            let data = vec![0u8; 8 + server_len];
            assert!(EdnsOption::decode(OPTION_COOKIE, &data).is_err());
        }
        assert!(EdnsOption::decode(OPTION_COOKIE, &[0; 7]).is_err());
        assert!(EdnsOption::decode(OPTION_COOKIE, &[]).is_err());
    }

    #[test]
    fn invalid_utf8_in_ede_is_lossy() {
        let got = EdnsOption::decode(OPTION_EDE, &[0, 1, b'a', 0xFF, b'b']).unwrap();
        assert_eq!(
            got,
            EdnsOption::ExtendedError {
                info_code: 1,
                extra_text: "a\u{FFFD}b".into()
            }
        );
        assert!(EdnsOption::decode(OPTION_EDE, &[0]).is_err());
    }

    #[test]
    fn opt_owner_must_be_root() {
        let mut rec = Edns::new(512).to_record().unwrap();
        rec.name = Name::from_ascii("example.").unwrap();
        assert_eq!(Edns::from_record(&rec), Err(ProtoError::OptOwnerNotRoot));
    }

    #[test]
    fn option_length_overrun_is_an_error() {
        let mut rec = Edns::new(512).to_record().unwrap();
        rec.rdata = RData::Unknown {
            rtype: RecordType::OPT,
            data: vec![0, 99, 0, 5, 1].into(),
        };
        assert!(Edns::from_record(&rec).is_err());
        rec.rdata = RData::Unknown {
            rtype: RecordType::OPT,
            data: vec![0, 99, 0].into(),
        };
        assert!(Edns::from_record(&rec).is_err());
    }

    #[test]
    fn failed_option_encode_restores_buffer() {
        let mut buf = vec![7, 7];
        let o = EdnsOption::Cookie {
            client: [0; 8],
            server: Some(vec![0; 3].into()),
        };
        assert!(o.encode(&mut buf).is_err());
        assert_eq!(buf, [7, 7]);
    }
}
