//! Trust anchors (RFC 4033 section 2, RFC 7958).

use dnscraft_proto::{Name, RData, Record, RecordType};

/// One trust anchor: a DS-style digest or a full DNSKEY.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Anchor {
    /// DS-style anchor.
    Ds {
        /// Zone the anchor belongs to.
        owner: Name,
        /// Key tag.
        key_tag: u16,
        /// DNSSEC algorithm.
        algorithm: u8,
        /// Digest type.
        digest_type: u8,
        /// Digest octets.
        digest: Vec<u8>,
    },
    /// DNSKEY-style anchor.
    Dnskey {
        /// Zone the anchor belongs to.
        owner: Name,
        /// DNSKEY flags.
        flags: u16,
        /// DNSKEY protocol.
        protocol: u8,
        /// DNSSEC algorithm.
        algorithm: u8,
        /// Public key octets.
        public_key: Vec<u8>,
    },
}

impl Anchor {
    /// The zone this anchor covers.
    pub fn owner(&self) -> &Name {
        match self {
            Self::Ds { owner, .. } | Self::Dnskey { owner, .. } => owner,
        }
    }
}

/// A record handed to [`TrustAnchors::from_records`] is neither DS nor DNSKEY.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("record of type {0} cannot be a trust anchor")]
pub struct AnchorError(pub RecordType);

impl AnchorError {
    /// Stable, locale-neutral code.
    pub fn code(&self) -> &'static str {
        "dnssec.bad_anchor"
    }
}

/// A set of trust anchors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustAnchors {
    anchors: Vec<Anchor>,
}

/// IANA root KSK-2017 (key tag 20326) and KSK-2024 (key tag 38696): SHA-256 DS
/// digests, from <https://data.iana.org/root-anchors/root-anchors.xml>.
const ROOT_DS: [(u16, &str); 2] = [
    (
        20326,
        "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    ),
    (
        38696,
        "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
    ),
];

impl TrustAnchors {
    /// No anchors: nothing validates.
    pub fn empty() -> Self {
        Self::default()
    }

    /// The built-in IANA root anchors (key tags 20326 and 38696; algorithm 8,
    /// digest type 2).
    pub fn iana_root() -> Self {
        let anchors = ROOT_DS
            .iter()
            .map(|&(key_tag, hex)| Anchor::Ds {
                owner: Name::root(),
                key_tag,
                algorithm: 8,
                digest_type: 2,
                digest: unhex(hex),
            })
            .collect();
        Self { anchors }
    }

    /// Builds anchors from DS and/or DNSKEY records (the testkit override).
    pub fn from_records(records: &[Record]) -> Result<Self, AnchorError> {
        let mut anchors = Vec::with_capacity(records.len());
        for r in records {
            anchors.push(match &r.rdata {
                RData::DS {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                } => Anchor::Ds {
                    owner: r.name.clone(),
                    key_tag: *key_tag,
                    algorithm: *algorithm,
                    digest_type: *digest_type,
                    digest: digest.to_vec(),
                },
                RData::DNSKEY {
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                } => Anchor::Dnskey {
                    owner: r.name.clone(),
                    flags: *flags,
                    protocol: *protocol,
                    algorithm: *algorithm,
                    public_key: public_key.to_vec(),
                },
                _ => return Err(AnchorError(r.rtype)),
            });
        }
        Ok(Self { anchors })
    }

    /// Adds one anchor.
    pub fn push(&mut self, anchor: Anchor) {
        self.anchors.push(anchor);
    }

    /// All anchors.
    pub fn anchors(&self) -> &[Anchor] {
        &self.anchors
    }

    /// The anchors for exactly `zone`.
    pub fn for_zone<'a>(&'a self, zone: &'a Name) -> impl Iterator<Item = &'a Anchor> + 'a {
        self.anchors.iter().filter(move |a| a.owner() == zone)
    }

    /// Whether `zone` has an anchor.
    pub fn has_zone(&self, zone: &Name) -> bool {
        self.for_zone(zone).next().is_some()
    }
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .filter_map(|p| {
            let hi = char::from(p[0]).to_digit(16)?;
            let lo = char::from(*p.get(1)?).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn builtin_root_anchors() {
        let a = TrustAnchors::iana_root();
        assert_eq!(a.anchors().len(), 2);
        assert!(a.has_zone(&Name::root()));
        let Anchor::Ds {
            digest, key_tag, ..
        } = &a.anchors()[0]
        else {
            panic!("ds")
        };
        assert_eq!(*key_tag, 20326);
        assert_eq!(digest.len(), 32);
        assert_eq!(digest[0], 0xE0);
    }

    #[test]
    fn rejects_other_types() {
        let r = Record {
            name: Name::root(),
            rtype: RecordType::A,
            class: dnscraft_proto::Class::IN,
            ttl: 0,
            rdata: RData::A(std::net::Ipv4Addr::LOCALHOST),
        };
        assert!(TrustAnchors::from_records(&[r]).is_err());
    }
}
