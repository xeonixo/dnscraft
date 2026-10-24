//! Zone signing with `hickory-proto` (an implementation independent of
//! `dnscraft-proto`). Signing happens at test time with explicit inception and
//! expiration timestamps, so tests can create expired signatures deterministically.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use hickory_proto::dnssec::crypto::{EcdsaSigningKey, Ed25519SigningKey, RsaSigningKey};
use hickory_proto::dnssec::rdata::{
    DNSKEY, DNSSECRData, DS, NSEC, NSEC3, NSEC3PARAM, RRSIG, SigInput,
};
use hickory_proto::dnssec::{Algorithm, DigestType, Nsec3HashAlgorithm, SigningKey, TBS};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, SerialNumber};
use rustls_pki_types::PrivatePkcs8KeyDer;

use crate::TestkitError;
use crate::zone::{DenialChain, Zone};

/// TTL of generated DNSSEC records (the SOA minimum of the testkit zones).
const DNSSEC_TTL: u32 = 60;

/// First embedded RSA-2048 test key (PKCS#8, test-only, not secret).
const RSA_KEY_A: &[u8] = include_bytes!("keys/rsa2048.pk8.der");

/// Second embedded RSA-2048 test key, used as the decoy for "DS without key".
const RSA_KEY_B: &[u8] = include_bytes!("keys/rsa2048b.pk8.der");

fn signing_error(error: impl std::fmt::Display) -> TestkitError {
    TestkitError::Signing(error.to_string())
}

/// Current Unix time in seconds (saturating at `u32::MAX`).
pub fn unix_now() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    u32::try_from(secs).unwrap_or(u32::MAX)
}

/// Signature algorithm of a [`ZoneKey`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SigAlgorithm {
    /// ECDSA P-256 with SHA-256 (algorithm 13), the default.
    #[default]
    EcdsaP256Sha256,
    /// RSA with SHA-256 (algorithm 8), 2048-bit embedded test key.
    RsaSha256,
    /// Ed25519 (algorithm 15).
    Ed25519,
}

impl SigAlgorithm {
    /// The DNSSEC algorithm number.
    pub fn number(self) -> u8 {
        match self {
            Self::EcdsaP256Sha256 => 13,
            Self::RsaSha256 => 8,
            Self::Ed25519 => 15,
        }
    }

    fn hickory(self) -> Algorithm {
        match self {
            Self::EcdsaP256Sha256 => Algorithm::ECDSAP256SHA256,
            Self::RsaSha256 => Algorithm::RSASHA256,
            Self::Ed25519 => Algorithm::ED25519,
        }
    }
}

/// A combined signing key (CSK): one key with the zone and SEP flags (DNSKEY
/// flags 257) that signs every RRset of a zone including the DNSKEY RRset.
pub struct ZoneKey {
    key: Box<dyn SigningKey>,
    dnskey: DNSKEY,
    algorithm: SigAlgorithm,
}

impl std::fmt::Debug for ZoneKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneKey")
            .field("algorithm", &self.algorithm)
            .field("key_tag", &self.key_tag())
            .finish()
    }
}

impl ZoneKey {
    /// Generates a fresh key (ECDSA, Ed25519) or loads the embedded RSA test
    /// key (ring cannot generate RSA keys, so all RSA keys of one run are equal).
    pub fn generate(algorithm: SigAlgorithm) -> Result<Self, TestkitError> {
        Self::build(algorithm, RSA_KEY_A)
    }

    /// Like [`generate`](Self::generate) but guaranteed to differ from the
    /// RSA key of `generate` (used for DS records that match no published key).
    pub fn generate_decoy(algorithm: SigAlgorithm) -> Result<Self, TestkitError> {
        Self::build(algorithm, RSA_KEY_B)
    }

    fn build(algorithm: SigAlgorithm, rsa_der: &'static [u8]) -> Result<Self, TestkitError> {
        let key: Box<dyn SigningKey> = match algorithm {
            SigAlgorithm::EcdsaP256Sha256 => {
                let der = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256)
                    .map_err(signing_error)?;
                Box::new(
                    EcdsaSigningKey::from_pkcs8(&der, Algorithm::ECDSAP256SHA256)
                        .map_err(signing_error)?,
                )
            }
            SigAlgorithm::Ed25519 => {
                let der = Ed25519SigningKey::generate_pkcs8().map_err(signing_error)?;
                Box::new(Ed25519SigningKey::from_pkcs8(&der).map_err(signing_error)?)
            }
            SigAlgorithm::RsaSha256 => Box::new(
                RsaSigningKey::from_pkcs8(&PrivatePkcs8KeyDer::from(rsa_der), Algorithm::RSASHA256)
                    .map_err(signing_error)?,
            ),
        };
        let public = key.to_public_key().map_err(signing_error)?;
        let dnskey = DNSKEY::from_key(&public);
        Ok(Self {
            key,
            dnskey,
            algorithm,
        })
    }

    /// The algorithm of the key.
    pub fn algorithm(&self) -> SigAlgorithm {
        self.algorithm
    }

    /// The public DNSKEY data (flags 257).
    pub fn dnskey(&self) -> &DNSKEY {
        &self.dnskey
    }

    /// The key tag of the DNSKEY.
    pub fn key_tag(&self) -> u16 {
        self.dnskey.calculate_key_tag().unwrap_or(0)
    }

    /// The DNSKEY as a record owned by `owner`.
    pub fn dnskey_record(&self, owner: &Name) -> Record {
        Record::from_rdata(
            owner.clone(),
            DNSSEC_TTL,
            RData::DNSSEC(DNSSECRData::DNSKEY(self.dnskey.clone())),
        )
    }

    /// The SHA-256 DS data for this key at zone `owner`.
    pub fn ds(&self, owner: &Name) -> Result<DS, TestkitError> {
        let digest = self
            .dnskey
            .to_digest(owner, DigestType::SHA256)
            .map_err(signing_error)?;
        Ok(DS::new(
            self.key_tag(),
            self.algorithm.hickory(),
            DigestType::SHA256,
            digest.as_ref().to_vec(),
        ))
    }

    /// The SHA-256 DS as a record owned by `owner` (the zone apex).
    pub fn ds_record(&self, owner: &Name) -> Result<Record, TestkitError> {
        Ok(Record::from_rdata(
            owner.clone(),
            DNSSEC_TTL,
            RData::DNSSEC(DNSSECRData::DS(self.ds(owner)?)),
        ))
    }
}

/// Which denial-of-existence mechanism a signed zone uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DenialMode {
    /// NSEC chain (RFC 4034).
    Nsec,
    /// NSEC3 chain (RFC 5155) with SHA-1.
    Nsec3 {
        /// Salt (RFC 9276 recommends empty; tests often use `aabbccdd`).
        salt: Vec<u8>,
        /// Additional hash iterations (RFC 9276 recommends 0).
        iterations: u16,
        /// Opt-out flag: insecure delegations are left out of the chain.
        opt_out: bool,
    },
}

/// Options of [`sign_zone`].
#[derive(Clone, Debug)]
pub struct SigningOptions {
    /// RRSIG inception (Unix seconds).
    pub inception: u32,
    /// RRSIG expiration (Unix seconds).
    pub expiration: u32,
    /// NSEC or NSEC3.
    pub denial: DenialMode,
    /// If set, the signature of this `(owner, type)` RRset is corrupted.
    pub corrupt_signature_of: Option<(Name, RecordType)>,
}

impl SigningOptions {
    /// Options with the default validity window `now - 1h ..= now + 30d`, NSEC denial.
    pub fn at(now: u32) -> Self {
        Self {
            inception: now.saturating_sub(3600),
            expiration: now.saturating_add(30 * 86400),
            denial: DenialMode::Nsec,
            corrupt_signature_of: None,
        }
    }

    /// Options with the default window relative to the current time.
    pub fn now() -> Self {
        Self::at(unix_now())
    }
}

/// Lowercase base32hex (RFC 4648 extended hex, no padding) as used for NSEC3 owners.
fn base32hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for byte in bytes {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((acc << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Signs `zone` with `key`: adds the apex DNSKEY, the NSEC or NSEC3 chain (and
/// NSEC3PARAM) and an RRSIG for every authoritative RRset (and DS and NSEC at
/// delegations). NS RRsets at cuts and glue stay unsigned, as RFC 4035 demands.
///
/// DS records for delegated children must be added to `zone` before signing.
/// Wildcard owners are signed with the labels field excluding the `*` label.
pub fn sign_zone(
    zone: Zone,
    key: &ZoneKey,
    options: &SigningOptions,
) -> Result<Zone, TestkitError> {
    let origin = zone.origin().clone();
    let mut records: Vec<Record> = zone.records().to_vec();
    records.push(key.dnskey_record(&origin));

    let cuts: BTreeSet<Name> = records
        .iter()
        .filter(|r| r.record_type() == RecordType::NS && r.name != origin)
        .map(|r| r.name.clone())
        .collect();
    let below_cut = |name: &Name| cuts.iter().any(|c| c != name && c.zone_of(name));

    if let DenialMode::Nsec3 {
        salt,
        iterations,
        opt_out,
    } = &options.denial
    {
        let param = NSEC3PARAM::new(
            Nsec3HashAlgorithm::SHA1,
            *opt_out,
            *iterations,
            salt.clone(),
        );
        records.push(Record::from_rdata(
            origin.clone(),
            DNSSEC_TTL,
            RData::DNSSEC(DNSSECRData::NSEC3PARAM(param)),
        ));
    }

    // Types per authoritative owner name.
    let mut types: BTreeMap<Name, BTreeSet<RecordType>> = BTreeMap::new();
    for r in &records {
        if !below_cut(&r.name) {
            types
                .entry(r.name.clone())
                .or_default()
                .insert(r.record_type());
        }
    }

    let chain = match &options.denial {
        DenialMode::Nsec => {
            let names: Vec<Name> = types.keys().cloned().collect();
            for (i, name) in names.iter().enumerate() {
                let next = names.get(i + 1).unwrap_or(&names[0]).clone();
                let bitmap = types[name]
                    .iter()
                    .copied()
                    .chain([RecordType::NSEC, RecordType::RRSIG]);
                records.push(Record::from_rdata(
                    name.clone(),
                    DNSSEC_TTL,
                    RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(next, bitmap))),
                ));
            }
            DenialChain::Nsec
        }
        DenialMode::Nsec3 {
            salt,
            iterations,
            opt_out,
        } => {
            // Names in the chain: authoritative names plus empty non-terminals;
            // with opt-out, delegations without DS are skipped.
            let mut chain_types: BTreeMap<Name, BTreeSet<RecordType>> = BTreeMap::new();
            for (name, set) in &types {
                let insecure_cut = cuts.contains(name) && !set.contains(&RecordType::DS);
                if !(*opt_out && insecure_cut) {
                    chain_types.insert(name.clone(), set.clone());
                }
                let mut ancestor = name.base_name();
                while ancestor != origin && origin.zone_of(&ancestor) {
                    chain_types.entry(ancestor.clone()).or_default();
                    ancestor = ancestor.base_name();
                }
            }
            let mut hashed: Vec<(Vec<u8>, Name, BTreeSet<RecordType>)> = Vec::new();
            for (name, set) in chain_types {
                let hash = Nsec3HashAlgorithm::SHA1
                    .hash(salt, &name, *iterations)
                    .map_err(signing_error)?
                    .as_ref()
                    .to_vec();
                hashed.push((hash, name, set));
            }
            hashed.sort_by(|a, b| a.0.cmp(&b.0));
            let mut mapping = Vec::new();
            for (i, (hash, _, set)) in hashed.iter().enumerate() {
                let next = hashed.get(i + 1).unwrap_or(&hashed[0]).0.clone();
                let owner = origin
                    .prepend_label(base32hex(hash))
                    .map_err(signing_error)?;
                let mut bitmap: BTreeSet<RecordType> = set.clone();
                if !bitmap.is_empty() {
                    bitmap.insert(RecordType::RRSIG);
                }
                records.push(Record::from_rdata(
                    owner.clone(),
                    DNSSEC_TTL,
                    RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                        Nsec3HashAlgorithm::SHA1,
                        *opt_out,
                        *iterations,
                        salt.clone(),
                        next,
                        bitmap,
                    ))),
                ));
                mapping.push((hash.clone(), owner));
            }
            DenialChain::Nsec3 {
                salt: salt.clone(),
                iterations: *iterations,
                hashes: mapping,
            }
        }
    };

    // Sign every authoritative RRset.
    let mut rrsets: BTreeMap<(Name, RecordType), Vec<usize>> = BTreeMap::new();
    for (i, r) in records.iter().enumerate() {
        let rtype = r.record_type();
        if rtype == RecordType::RRSIG || below_cut(&r.name) {
            continue;
        }
        if rtype == RecordType::NS && cuts.contains(&r.name) {
            continue;
        }
        rrsets.entry((r.name.clone(), rtype)).or_default().push(i);
    }
    let mut sigs = Vec::new();
    for ((name, rtype), indices) in &rrsets {
        let members: Vec<&Record> = indices.iter().map(|i| &records[*i]).collect();
        let ttl = members.first().map_or(DNSSEC_TTL, |r| r.ttl);
        // `Name::num_labels` already excludes a leading `*` label, as RFC 4034 requires.
        let labels = name.num_labels();
        let input = SigInput {
            type_covered: *rtype,
            algorithm: key.algorithm().hickory(),
            num_labels: labels,
            original_ttl: ttl,
            sig_expiration: SerialNumber::new(options.expiration),
            sig_inception: SerialNumber::new(options.inception),
            key_tag: key.key_tag(),
            signer_name: origin.clone(),
        };
        let tbs = TBS::from_input(name, DNSClass::IN, &input, members.iter().copied())
            .map_err(signing_error)?;
        let mut signature = key.key.sign(&tbs).map_err(signing_error)?;
        if options
            .corrupt_signature_of
            .as_ref()
            .is_some_and(|(n, t)| n == name && t == rtype)
            && let Some(byte) = signature.get_mut(0)
        {
            *byte ^= 0xff;
        }
        sigs.push(Record::from_rdata(
            name.clone(),
            ttl,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, signature))),
        ));
    }
    records.extend(sigs);

    let mut signed = records
        .into_iter()
        .fold(Zone::new(&origin.to_ascii())?, Zone::with_record);
    signed = signed.with_chain(chain);
    Ok(signed)
}
