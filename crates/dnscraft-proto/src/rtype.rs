//! Record types and classes as open newtypes over `u16`.

use std::fmt;

/// A DNS record type (RR TYPE), an open newtype over its numeric value.
///
/// Unassigned or unsupported values are representable and displayed as
/// `TYPE<n>` (RFC 3597).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct RecordType(pub u16);

impl RecordType {
    /// IPv4 host address.
    pub const A: Self = Self(1);
    /// Authoritative name server.
    pub const NS: Self = Self(2);
    /// Canonical name.
    pub const CNAME: Self = Self(5);
    /// Start of authority.
    pub const SOA: Self = Self(6);
    /// Domain name pointer.
    pub const PTR: Self = Self(12);
    /// Mail exchange.
    pub const MX: Self = Self(15);
    /// Text strings.
    pub const TXT: Self = Self(16);
    /// IPv6 host address.
    pub const AAAA: Self = Self(28);
    /// Service locator.
    pub const SRV: Self = Self(33);
    /// Delegation name.
    pub const DNAME: Self = Self(39);
    /// EDNS(0) pseudo-record.
    pub const OPT: Self = Self(41);
    /// Delegation signer.
    pub const DS: Self = Self(43);
    /// DNSSEC signature.
    pub const RRSIG: Self = Self(46);
    /// Next secure record.
    pub const NSEC: Self = Self(47);
    /// DNSSEC public key.
    pub const DNSKEY: Self = Self(48);
    /// Hashed next secure record.
    pub const NSEC3: Self = Self(50);
    /// NSEC3 parameters.
    pub const NSEC3PARAM: Self = Self(51);
    /// General service binding.
    pub const SVCB: Self = Self(64);
    /// HTTPS service binding.
    pub const HTTPS: Self = Self(65);
    /// Query for any type.
    pub const ANY: Self = Self(255);
    /// Certification authority authorization.
    pub const CAA: Self = Self(257);

    /// The numeric value.
    pub fn value(self) -> u16 {
        self.0
    }
}

impl From<u16> for RecordType {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<RecordType> for u16 {
    fn from(value: RecordType) -> Self {
        value.0
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::A => "A",
            Self::NS => "NS",
            Self::CNAME => "CNAME",
            Self::SOA => "SOA",
            Self::PTR => "PTR",
            Self::MX => "MX",
            Self::TXT => "TXT",
            Self::AAAA => "AAAA",
            Self::SRV => "SRV",
            Self::DNAME => "DNAME",
            Self::OPT => "OPT",
            Self::DS => "DS",
            Self::RRSIG => "RRSIG",
            Self::NSEC => "NSEC",
            Self::DNSKEY => "DNSKEY",
            Self::NSEC3 => "NSEC3",
            Self::NSEC3PARAM => "NSEC3PARAM",
            Self::SVCB => "SVCB",
            Self::HTTPS => "HTTPS",
            Self::ANY => "ANY",
            Self::CAA => "CAA",
            Self(n) => return write!(f, "TYPE{n}"),
        };
        f.write_str(name)
    }
}

/// A DNS class (RR CLASS), an open newtype over its numeric value.
///
/// Unassigned values are displayed as `CLASS<n>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Class(pub u16);

impl Class {
    /// Internet.
    pub const IN: Self = Self(1);
    /// Chaos.
    pub const CH: Self = Self(3);
    /// None (RFC 2136 prerequisites and updates).
    pub const NONE: Self = Self(254);
    /// Any class (queries).
    pub const ANY: Self = Self(255);

    /// The numeric value.
    pub fn value(self) -> u16 {
        self.0
    }
}

impl From<u16> for Class {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<Class> for u16 {
    fn from(value: Class) -> Self {
        value.0
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::IN => f.write_str("IN"),
            Self::CH => f.write_str("CH"),
            Self::NONE => f.write_str("NONE"),
            Self::ANY => f.write_str("ANY"),
            Self(n) => write!(f, "CLASS{n}"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn display_mnemonics_and_generic() {
        assert_eq!(RecordType::A.to_string(), "A");
        assert_eq!(RecordType::NSEC3PARAM.to_string(), "NSEC3PARAM");
        assert_eq!(RecordType::CAA.to_string(), "CAA");
        assert_eq!(RecordType(65280).to_string(), "TYPE65280");
        assert_eq!(RecordType(0).to_string(), "TYPE0");
        assert_eq!(Class::IN.to_string(), "IN");
        assert_eq!(Class(42).to_string(), "CLASS42");
    }

    #[test]
    fn numeric_conversions() {
        assert_eq!(u16::from(RecordType::HTTPS), 65);
        assert_eq!(RecordType::from(28), RecordType::AAAA);
        assert_eq!(RecordType::SVCB.value(), 64);
        assert_eq!(Class::from(254), Class::NONE);
        assert_eq!(u16::from(Class::CH), 3);
    }
}
