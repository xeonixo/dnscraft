//! The 12-octet message header, opcodes and response codes.

use std::fmt;

use crate::error::ProtoError;
use crate::rdata::Reader;

/// A DNS opcode (4 bits), an open newtype.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
pub struct Opcode(pub u8);

impl Opcode {
    /// Standard query.
    pub const QUERY: Self = Self(0);
    /// Zone change notification (RFC 1996).
    pub const NOTIFY: Self = Self(4);
    /// Dynamic update (RFC 2136).
    pub const UPDATE: Self = Self(5);

    /// The numeric value.
    pub fn value(self) -> u8 {
        self.0
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::QUERY => f.write_str("QUERY"),
            Self::NOTIFY => f.write_str("NOTIFY"),
            Self::UPDATE => f.write_str("UPDATE"),
            Self(n) => write!(f, "OPCODE{n}"),
        }
    }
}

/// A 12-bit response code: the 4 header bits combined with the 8 extended
/// bits carried in the OPT record (RFC 6891), an open newtype.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
pub struct Rcode(pub u16);

impl Rcode {
    /// No error.
    pub const NOERROR: Self = Self(0);
    /// Format error.
    pub const FORMERR: Self = Self(1);
    /// Server failure.
    pub const SERVFAIL: Self = Self(2);
    /// Non-existent domain.
    pub const NXDOMAIN: Self = Self(3);
    /// Not implemented.
    pub const NOTIMP: Self = Self(4);
    /// Query refused.
    pub const REFUSED: Self = Self(5);
    /// Name exists when it should not (RFC 2136).
    pub const YXDOMAIN: Self = Self(6);
    /// RRset exists when it should not (RFC 2136).
    pub const YXRRSET: Self = Self(7);
    /// RRset that should exist does not (RFC 2136).
    pub const NXRRSET: Self = Self(8);
    /// Not authoritative / not authorized (RFC 2136, RFC 8945).
    pub const NOTAUTH: Self = Self(9);
    /// Name not in zone (RFC 2136).
    pub const NOTZONE: Self = Self(10);
    /// Bad OPT version (RFC 6891) or bad TSIG signature.
    pub const BADVERS: Self = Self(16);
    /// Bad or missing server cookie (RFC 7873).
    pub const BADCOOKIE: Self = Self(23);

    /// Largest representable value (12 bits).
    pub const MAX: u16 = 0x0FFF;

    /// The numeric value.
    pub fn value(self) -> u16 {
        self.0
    }

    /// The low 4 bits, as stored in the header.
    pub fn low(self) -> u8 {
        (self.0 & 0x0F) as u8
    }

    /// The high 8 bits, as stored in the OPT TTL.
    pub fn high(self) -> u8 {
        ((self.0 >> 4) & 0xFF) as u8
    }

    /// Combines the header bits (low 4) and the extended bits.
    pub fn from_parts(low: u8, high: u8) -> Self {
        Self((u16::from(high) << 4) | u16::from(low & 0x0F))
    }
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::NOERROR => "NOERROR",
            Self::FORMERR => "FORMERR",
            Self::SERVFAIL => "SERVFAIL",
            Self::NXDOMAIN => "NXDOMAIN",
            Self::NOTIMP => "NOTIMP",
            Self::REFUSED => "REFUSED",
            Self::YXDOMAIN => "YXDOMAIN",
            Self::YXRRSET => "YXRRSET",
            Self::NXRRSET => "NXRRSET",
            Self::NOTAUTH => "NOTAUTH",
            Self::NOTZONE => "NOTZONE",
            Self::BADVERS => "BADVERS",
            Self::BADCOOKIE => "BADCOOKIE",
            Self(n) => return write!(f, "RCODE{n}"),
        };
        f.write_str(name)
    }
}

/// The four section counts of a message header.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Counts {
    /// Number of questions.
    pub qd: u16,
    /// Number of answer records.
    pub an: u16,
    /// Number of authority records.
    pub ns: u16,
    /// Number of additional records (including OPT).
    pub ar: u16,
}

/// The message header without the section counts.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Header {
    /// Message identifier.
    pub id: u16,
    /// Response flag (QR).
    pub qr: bool,
    /// Opcode (4 bits; higher bits are masked on encode).
    pub opcode: Opcode,
    /// Authoritative answer.
    pub aa: bool,
    /// Truncated.
    pub tc: bool,
    /// Recursion desired.
    pub rd: bool,
    /// Recursion available.
    pub ra: bool,
    /// The single reserved bit (Z), preserved as received.
    pub z: bool,
    /// Authentic data (RFC 4035).
    pub ad: bool,
    /// Checking disabled (RFC 4035).
    pub cd: bool,
    /// The low 4 bits of the response code (higher bits masked on encode).
    pub rcode_low: u8,
}

/// Length of the wire header.
pub(crate) const HEADER_LEN: usize = 12;

impl Header {
    /// Decodes the first 12 octets of `msg`: the header and the counts.
    pub fn decode(msg: &[u8]) -> Result<(Self, Counts), ProtoError> {
        let mut r = Reader::new(msg, 0);
        let id = r.u16()?;
        let f1 = r.u8()?;
        let f2 = r.u8()?;
        let counts = Counts {
            qd: r.u16()?,
            an: r.u16()?,
            ns: r.u16()?,
            ar: r.u16()?,
        };
        let header = Self {
            id,
            qr: f1 & 0x80 != 0,
            opcode: Opcode((f1 >> 3) & 0x0F),
            aa: f1 & 0x04 != 0,
            tc: f1 & 0x02 != 0,
            rd: f1 & 0x01 != 0,
            ra: f2 & 0x80 != 0,
            z: f2 & 0x40 != 0,
            ad: f2 & 0x20 != 0,
            cd: f2 & 0x10 != 0,
            rcode_low: f2 & 0x0F,
        };
        Ok((header, counts))
    }

    /// Appends the 12-octet header with the given counts to `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>, counts: Counts) {
        let f1 = (u8::from(self.qr) << 7)
            | ((self.opcode.0 & 0x0F) << 3)
            | (u8::from(self.aa) << 2)
            | (u8::from(self.tc) << 1)
            | u8::from(self.rd);
        let f2 = (u8::from(self.ra) << 7)
            | (u8::from(self.z) << 6)
            | (u8::from(self.ad) << 5)
            | (u8::from(self.cd) << 4)
            | (self.rcode_low & 0x0F);
        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.extend_from_slice(&[f1, f2]);
        for c in [counts.qd, counts.an, counts.ns, counts.ar] {
            buf.extend_from_slice(&c.to_be_bytes());
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn round_trip(h: Header) {
        let counts = Counts {
            qd: 1,
            an: 2,
            ns: 3,
            ar: 4,
        };
        let mut buf = Vec::new();
        h.encode(&mut buf, counts);
        assert_eq!(buf.len(), HEADER_LEN);
        assert_eq!(Header::decode(&buf), Ok((h, counts)));
    }

    #[test]
    fn every_flag_round_trips_alone() {
        let base = Header::default();
        round_trip(base);
        round_trip(Header { id: 0xBEEF, ..base });
        round_trip(Header { qr: true, ..base });
        round_trip(Header { aa: true, ..base });
        round_trip(Header { tc: true, ..base });
        round_trip(Header { rd: true, ..base });
        round_trip(Header { ra: true, ..base });
        round_trip(Header { z: true, ..base });
        round_trip(Header { ad: true, ..base });
        round_trip(Header { cd: true, ..base });
        for op in 0..16 {
            round_trip(Header {
                opcode: Opcode(op),
                ..base
            });
        }
        for rc in 0..16 {
            round_trip(Header {
                rcode_low: rc,
                ..base
            });
        }
        round_trip(Header {
            id: 0xFFFF,
            qr: true,
            opcode: Opcode(15),
            aa: true,
            tc: true,
            rd: true,
            ra: true,
            z: true,
            ad: true,
            cd: true,
            rcode_low: 15,
        });
    }

    #[test]
    fn flags_land_on_the_documented_bits() {
        let h = Header {
            qr: true,
            opcode: Opcode::UPDATE,
            rd: true,
            ad: true,
            ..Header::default()
        };
        let mut buf = Vec::new();
        h.encode(&mut buf, Counts::default());
        assert_eq!(&buf[2..4], &[0x80 | (5 << 3) | 1, 0x20]);
    }

    #[test]
    fn short_header_is_an_error() {
        let mut buf = Vec::new();
        Header::default().encode(&mut buf, Counts::default());
        for cut in 0..HEADER_LEN {
            assert!(Header::decode(&buf[..cut]).is_err());
        }
    }

    #[test]
    fn rcode_split_and_merge() {
        assert_eq!(Rcode::BADVERS.low(), 0);
        assert_eq!(Rcode::BADVERS.high(), 1);
        assert_eq!(Rcode::BADCOOKIE.low(), 7);
        assert_eq!(Rcode::BADCOOKIE.high(), 1);
        assert_eq!(Rcode::from_parts(0, 1), Rcode::BADVERS);
        assert_eq!(Rcode::from_parts(7, 1), Rcode::BADCOOKIE);
        assert_eq!(Rcode::from_parts(3, 0), Rcode::NXDOMAIN);
        assert_eq!(Rcode(0xFFF).high(), 0xFF);
        assert_eq!(Rcode::BADVERS.to_string(), "BADVERS");
        assert_eq!(Rcode(99).to_string(), "RCODE99");
        assert_eq!(Opcode::NOTIFY.to_string(), "NOTIFY");
        assert_eq!(Opcode(9).to_string(), "OPCODE9");
    }
}
