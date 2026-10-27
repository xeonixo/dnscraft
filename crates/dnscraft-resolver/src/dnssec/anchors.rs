//! Trust anchors (RFC 4033 section 2, RFC 7958) and RFC 5011 rollover.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use dnscraft_proto::dnssec::{dnskey_key_tag, ds_digest};
use dnscraft_proto::{Name, RData, Record, RecordType};

use super::verify::verify_revocation_budgeted;
use super::{ValidationBudget, is_supported_algorithm};

/// One trust anchor: a DS-style digest or a full DNSKEY.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Anchor {
    /// DS-style anchor.
    Ds {
        /// Zone the anchor belongs to.
        #[serde(with = "crate::config::name_serde")]
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
        #[serde(with = "crate::config::name_serde")]
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
///
/// The configured anchors are serialized; the RFC 5011 rollover state is
/// runtime-only and starts from them on the first observation.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct TrustAnchors {
    anchors: Vec<Anchor>,
    /// RFC 5011 state, seeded lazily from `anchors` by the first observation.
    #[serde(skip)]
    rollover: Arc<Mutex<Rollover>>,
}

impl PartialEq for TrustAnchors {
    fn eq(&self, other: &Self) -> bool {
        self.anchors == other.anchors
    }
}

impl Eq for TrustAnchors {}

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

/// RFC 5011 sections 2.2 and 2.3: a new root key is not used, and a key that
/// stopped appearing is not dropped, until it has been observed in that state
/// for this long. The RFC recommends 30 days.
const ADD_HOLD_DOWN: Duration = Duration::from_secs(30 * 24 * 3600);
const REMOVE_HOLD_DOWN: Duration = Duration::from_secs(30 * 24 * 3600);

const ZONE_FLAG: u16 = 0x0100;
const SEP_FLAG: u16 = 0x0001;
const REVOKE_FLAG: u16 = 0x0080;
const DNSKEY_PROTOCOL: u8 = 3;

/// RFC 5011 state of one anchor (sections 2.2 and 2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnchorState {
    /// Trusted.
    Valid,
    /// Seen in a validated DNSKEY RRset, not trusted until the add hold-down
    /// has passed.
    AddPending,
    /// Was trusted, has not been seen for a while; dropped after the remove
    /// hold-down.
    Missing,
}

#[derive(Clone, Debug)]
struct RolloverEntry {
    anchor: Anchor,
    state: AnchorState,
    /// When the current state was entered.
    since: SystemTime,
}

/// RFC 5011 state of the anchor set.
#[derive(Debug, Default)]
struct Rollover {
    /// One entry per anchor, seeded from [`TrustAnchors::anchors`] on the
    /// first observation. `None` means no observation has happened yet.
    entries: Option<Vec<RolloverEntry>>,
}

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
        Self {
            anchors,
            ..Self::default()
        }
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
                _ => return Err(AnchorError(r.rtype())),
            });
        }
        Ok(Self {
            anchors,
            ..Self::default()
        })
    }

    /// Adds one anchor.
    pub fn push(&mut self, anchor: Anchor) {
        let mut rollover = lock(&self.rollover);
        if let Some(entries) = &mut rollover.entries {
            entries.push(RolloverEntry {
                anchor: anchor.clone(),
                state: AnchorState::Valid,
                since: SystemTime::UNIX_EPOCH,
            });
        }
        self.anchors.push(anchor);
    }

    /// All anchors currently trusted.
    pub fn anchors(&self) -> Vec<Anchor> {
        let rollover = lock(&self.rollover);
        match &rollover.entries {
            Some(entries) => entries
                .iter()
                .filter(|e| e.state != AnchorState::AddPending)
                .map(|e| e.anchor.clone())
                .collect(),
            None => self.anchors.clone(),
        }
    }

    /// The anchors for exactly `zone`.
    pub fn for_zone<'a>(&'a self, zone: &'a Name) -> impl Iterator<Item = Anchor> + 'a {
        let zone = zone.clone();
        self.anchors()
            .into_iter()
            .filter(move |a| *a.owner() == zone)
    }

    /// Whether `zone` has an anchor.
    pub fn has_zone(&self, zone: &Name) -> bool {
        self.for_zone(zone).next().is_some()
    }

    /// Applies one validated root DNSKEY RRset to the RFC 5011 rollover
    /// state (sections 2.2 and 2.3).
    ///
    /// `rrset` and `rrsigs` are the DNSKEY RRset and its RRSIGs as received;
    /// the caller must already have validated the RRset against the current
    /// anchors. A key that is new and has the SEP bit is trusted after the
    /// add hold-down, a trusted key that stays absent is dropped after the
    /// remove hold-down, and a key whose REVOKE bit is set and that signs the
    /// RRset itself is dropped at once. Keys below other zones are ignored;
    /// only the root anchor set is tracked.
    pub fn observe_dnskeys(
        &self,
        zone: &Name,
        rrset: &[Record],
        rrsigs: &[Record],
        now: SystemTime,
        budget: &ValidationBudget,
    ) {
        if !zone.is_root() {
            return;
        }
        let keys: Vec<Record> = rrset
            .iter()
            .filter(|r| r.name == *zone && r.rtype() == RecordType::DNSKEY)
            .cloned()
            .collect();
        if keys.is_empty() {
            return;
        }
        let mut rollover = lock(&self.rollover);
        if rollover.entries.is_none() {
            if !self.anchors.iter().any(|a| a.owner() == zone) {
                return;
            }
            rollover.entries = Some(
                self.anchors
                    .iter()
                    .map(|a| RolloverEntry {
                        anchor: a.clone(),
                        state: AnchorState::Valid,
                        since: SystemTime::UNIX_EPOCH,
                    })
                    .collect(),
            );
        }
        let Some(entries) = rollover.entries.as_mut() else {
            return;
        };

        // RFC 5011 section 2.3: revocation needs the REVOKE bit and a
        // signature by that same key over the DNSKEY RRset.
        let revoked: Vec<&Record> = keys
            .iter()
            .filter(|k| is_revoked(k) && self_signed(&keys, k, rrsigs, now, budget))
            .collect();

        let mut kept: Vec<RolloverEntry> = Vec::with_capacity(entries.len());
        for mut entry in entries.drain(..) {
            if entry.anchor.owner() != zone {
                kept.push(entry);
                continue;
            }
            if revoked
                .iter()
                .any(|k| anchor_matches_revoked_key(&entry.anchor, k))
            {
                continue;
            }
            let present = keys.iter().any(|k| anchor_matches_key(&entry.anchor, k));
            if present {
                if entry.state == AnchorState::AddPending
                    && !held_down(now, entry.since, ADD_HOLD_DOWN)
                {
                    // Still inside the add hold-down.
                    kept.push(entry);
                    continue;
                }
                entry.state = AnchorState::Valid;
                kept.push(entry);
                continue;
            }
            match entry.state {
                AnchorState::Valid => {
                    entry.state = AnchorState::Missing;
                    entry.since = now;
                    kept.push(entry);
                }
                AnchorState::Missing => {
                    if !held_down(now, entry.since, REMOVE_HOLD_DOWN) {
                        kept.push(entry);
                    }
                }
                // A candidate that vanished restarts from scratch if it
                // appears again.
                AnchorState::AddPending => {}
            }
        }

        for key in &keys {
            if !is_candidate(key) || revoked.contains(&key) {
                continue;
            }
            if kept.iter().any(|e| anchor_matches_key(&e.anchor, key)) {
                continue;
            }
            let Some(anchor) = anchor_of_key(zone, key) else {
                continue;
            };
            kept.push(RolloverEntry {
                anchor,
                state: AnchorState::AddPending,
                since: now,
            });
        }
        *entries = kept;
    }
}

/// RFC 5011 section 2.2: a new key must be seen for the whole add hold-down.
/// A gap is not detectable from a single observation; the key simply is not
/// promoted until one observation is at least the hold-down after the first.
fn held_down(now: SystemTime, since: SystemTime, hold_down: Duration) -> bool {
    now.duration_since(since).is_ok_and(|d| d >= hold_down)
}

/// Whether `key` is a zone/SEP key that may become a trust anchor.
fn is_candidate(key: &Record) -> bool {
    match &key.rdata {
        RData::DNSKEY {
            flags,
            protocol,
            algorithm,
            ..
        } => {
            flags & (ZONE_FLAG | SEP_FLAG) == ZONE_FLAG | SEP_FLAG
                && flags & REVOKE_FLAG == 0
                && *protocol == DNSKEY_PROTOCOL
                && is_supported_algorithm(*algorithm)
        }
        _ => false,
    }
}

fn is_revoked(key: &Record) -> bool {
    matches!(&key.rdata, RData::DNSKEY { flags, .. } if flags & REVOKE_FLAG != 0)
}

/// The anchor equivalent of a (validated) candidate DNSKEY.
fn anchor_of_key(zone: &Name, key: &Record) -> Option<Anchor> {
    let RData::DNSKEY {
        flags,
        protocol,
        algorithm,
        public_key,
    } = &key.rdata
    else {
        return None;
    };
    Some(Anchor::Dnskey {
        owner: zone.clone(),
        flags: *flags,
        protocol: *protocol,
        algorithm: *algorithm,
        public_key: public_key.to_vec(),
    })
}

/// Whether `anchor` names this DNSKEY.
fn anchor_matches_key(anchor: &Anchor, key: &Record) -> bool {
    let RData::DNSKEY {
        flags,
        protocol,
        algorithm,
        public_key,
    } = &key.rdata
    else {
        return false;
    };
    match anchor {
        Anchor::Ds {
            owner,
            key_tag,
            algorithm: a,
            digest_type,
            digest,
        } => {
            owner == &key.name
                && a == algorithm
                && dnskey_key_tag(&key.rdata) == Some(*key_tag)
                && ds_digest(owner, &key.rdata, *digest_type).is_ok_and(|d| d == *digest)
        }
        Anchor::Dnskey {
            owner,
            flags: f,
            protocol: p,
            algorithm: a,
            public_key: k,
        } => {
            owner == &key.name
                && f == flags
                && p == protocol
                && a == algorithm
                && k.as_slice() == &**public_key
        }
    }
}

/// Whether `anchor` is this key with its REVOKE bit set (RFC 5011 section
/// 2.3). The DS digest includes the flags, so it is computed over the
/// un-revoked form to recognise a DS anchor of the same key.
fn anchor_matches_revoked_key(anchor: &Anchor, key: &Record) -> bool {
    if !matches!(&key.rdata, RData::DNSKEY { .. }) {
        return false;
    }
    let mut unrevoked = key.clone();
    if let RData::DNSKEY { flags, .. } = &mut unrevoked.rdata {
        *flags &= !REVOKE_FLAG;
    }
    anchor_matches_key(anchor, &unrevoked)
}

/// Whether `key` signs the DNSKEY RRset `rrset` itself.
fn self_signed(
    rrset: &[Record],
    key: &Record,
    rrsigs: &[Record],
    now: SystemTime,
    budget: &ValidationBudget,
) -> bool {
    let RData::DNSKEY { algorithm, .. } = &key.rdata else {
        return false;
    };
    let Some(tag) = dnskey_key_tag(&key.rdata) else {
        return false;
    };
    rrsigs.iter().any(|sig| {
        matches!(
            &sig.rdata,
            RData::RRSIG { type_covered, key_tag, algorithm: a, .. }
                if *type_covered == RecordType::DNSKEY && *key_tag == tag && a == algorithm
        ) && verify_revocation_budgeted(rrset, sig, key, now, budget, &mut None).is_ok()
    })
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
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
    use std::time::UNIX_EPOCH;

    use dnscraft_common::clock::{Clock, ManualClock};
    use hickory_proto::dnssec::crypto::EcdsaSigningKey;
    use hickory_proto::dnssec::rdata::{DNSKEY as HDnskey, DNSSECRData, SigInput};
    use hickory_proto::dnssec::{Algorithm, SigningKey, TBS};
    use hickory_proto::rr::{
        DNSClass, Name as HName, RData as HRData, Record as HRecord, RecordType as HRType,
        SerialNumber,
    };
    use hickory_proto::serialize::binary::BinEncodable;

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
            class: dnscraft_proto::Class::IN,
            ttl: 0,
            rdata: RData::A(std::net::Ipv4Addr::LOCALHOST),
        };
        assert!(TrustAnchors::from_records(&[r]).is_err());
    }

    /// A generated root KSK (flags 257) that can sign test DNSKEY RRsets.
    struct TestKey {
        signing: EcdsaSigningKey,
        dnskey: HDnskey,
    }

    impl TestKey {
        fn new() -> Self {
            let der = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).unwrap();
            let signing = EcdsaSigningKey::from_pkcs8(&der, Algorithm::ECDSAP256SHA256).unwrap();
            let public = signing.to_public_key().unwrap();
            Self {
                signing,
                dnskey: HDnskey::from_key(&public),
            }
        }

        fn revoked_dnskey(&self) -> HDnskey {
            HDnskey::with_flags(
                self.dnskey.flags() | REVOKE_FLAG,
                self.dnskey.public_key().clone(),
            )
        }

        fn record(&self) -> Record {
            dnskey_record(&self.dnskey)
        }

        fn revoked_record(&self) -> Record {
            dnskey_record(&self.revoked_dnskey())
        }

        /// An RRSIG by the key over `dnskeys` (a DNSKEY RRset).
        fn sign_dnskeys(&self, dnskeys: &[HDnskey], key_tag: u16, now: SystemTime) -> Record {
            let records: Vec<HRecord> = dnskeys
                .iter()
                .map(|d| {
                    HRecord::from_rdata(
                        HName::root(),
                        3600,
                        HRData::DNSSEC(DNSSECRData::DNSKEY(d.clone())),
                    )
                })
                .collect();
            let secs = u32::try_from(
                now.duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs(),
            )
            .unwrap_or(u32::MAX);
            let input = SigInput {
                type_covered: HRType::DNSKEY,
                algorithm: Algorithm::ECDSAP256SHA256,
                num_labels: 0,
                original_ttl: 3600,
                sig_expiration: SerialNumber::new(secs.saturating_add(30 * 24 * 3600)),
                sig_inception: SerialNumber::new(secs.saturating_sub(3600)),
                key_tag,
                signer_name: HName::root(),
            };
            let tbs =
                TBS::from_input(&HName::root(), DNSClass::IN, &input, records.iter()).unwrap();
            let signature = self.signing.sign(&tbs).unwrap();
            let rrsig = hickory_proto::dnssec::rdata::RRSIG::from_sig(input, signature);
            let bytes = rrsig.to_bytes().unwrap();
            Record {
                name: Name::root(),
                class: dnscraft_proto::Class::IN,
                ttl: 3600,
                rdata: RData::decode(&bytes, RecordType::RRSIG, 0, bytes.len()).unwrap(),
            }
        }
    }

    fn dnskey_record(dnskey: &HDnskey) -> Record {
        let bytes = dnskey.to_bytes().unwrap();
        Record {
            name: Name::root(),
            class: dnscraft_proto::Class::IN,
            ttl: 3600,
            rdata: RData::decode(&bytes, RecordType::DNSKEY, 0, bytes.len()).unwrap(),
        }
    }

    fn budget() -> ValidationBudget {
        ValidationBudget::default()
    }

    fn start() -> ManualClock {
        ManualClock::new(UNIX_EPOCH + Duration::from_secs(1_700_000_000))
    }

    #[test]
    fn new_key_is_trusted_after_the_add_hold_down() {
        let clock = start();
        let a = TestKey::new();
        let b = TestKey::new();
        let anchors = TrustAnchors::from_records(&[a.record()]).unwrap();
        let rrset = vec![a.record(), b.record()];

        anchors.observe_dnskeys(&Name::root(), &rrset, &[], clock.now(), &budget());
        assert_eq!(anchors.anchors().len(), 1, "trusted at once");

        clock.advance(Duration::from_secs(29 * 24 * 3600));
        anchors.observe_dnskeys(&Name::root(), &rrset, &[], clock.now(), &budget());
        assert_eq!(anchors.anchors().len(), 1, "trusted before the hold-down");

        clock.advance(Duration::from_secs(24 * 3600));
        anchors.observe_dnskeys(&Name::root(), &rrset, &[], clock.now(), &budget());
        let current = anchors.anchors();
        assert_eq!(current.len(), 2, "new key still not trusted");
        assert!(
            current
                .iter()
                .any(|x| matches!(x, Anchor::Dnskey { flags, .. } if *flags == 257)),
            "the added anchor is the new DNSKEY"
        );
    }

    #[test]
    fn missing_key_is_dropped_after_the_remove_hold_down() {
        let clock = start();
        let a = TestKey::new();
        let b = TestKey::new();
        let anchors = TrustAnchors::from_records(&[a.record(), b.record()]).unwrap();
        anchors.observe_dnskeys(
            &Name::root(),
            &[a.record(), b.record()],
            &[],
            clock.now(),
            &budget(),
        );
        assert_eq!(anchors.anchors().len(), 2);

        let only_a = vec![a.record()];
        anchors.observe_dnskeys(&Name::root(), &only_a, &[], clock.now(), &budget());
        assert_eq!(anchors.anchors().len(), 2, "removed at once");

        clock.advance(Duration::from_secs(29 * 24 * 3600));
        anchors.observe_dnskeys(&Name::root(), &only_a, &[], clock.now(), &budget());
        assert_eq!(anchors.anchors().len(), 2, "removed before the hold-down");

        clock.advance(Duration::from_secs(24 * 3600));
        anchors.observe_dnskeys(&Name::root(), &only_a, &[], clock.now(), &budget());
        assert_eq!(anchors.anchors().len(), 1);
        assert!(anchors.has_zone(&Name::root()));
    }

    #[test]
    fn revoked_key_is_dropped_at_once() {
        let clock = start();
        let a = TestKey::new();
        let b = TestKey::new();
        let anchors = TrustAnchors::from_records(&[a.record(), b.record()]).unwrap();
        anchors.observe_dnskeys(
            &Name::root(),
            &[a.record(), b.record()],
            &[],
            clock.now(),
            &budget(),
        );
        assert_eq!(anchors.anchors().len(), 2);

        let revoked = b.revoked_dnskey();
        let tag = revoked.calculate_key_tag().unwrap();
        let rrset = vec![a.record(), b.revoked_record()];
        let rrsigs = vec![b.sign_dnskeys(&[a.dnskey.clone(), revoked], tag, clock.now())];
        anchors.observe_dnskeys(&Name::root(), &rrset, &rrsigs, clock.now(), &budget());
        assert_eq!(anchors.anchors().len(), 1, "revoked key kept");
    }

    #[test]
    fn revoked_key_without_a_self_signature_stays() {
        let clock = start();
        let a = TestKey::new();
        let b = TestKey::new();
        let anchors = TrustAnchors::from_records(&[a.record(), b.record()]).unwrap();
        anchors.observe_dnskeys(
            &Name::root(),
            &[a.record(), b.record()],
            &[],
            clock.now(),
            &budget(),
        );

        // The REVOKE bit without a signature by that key is not a revocation.
        let rrset = vec![a.record(), b.revoked_record()];
        anchors.observe_dnskeys(&Name::root(), &rrset, &[], clock.now(), &budget());
        assert_eq!(anchors.anchors().len(), 2);
    }
}
