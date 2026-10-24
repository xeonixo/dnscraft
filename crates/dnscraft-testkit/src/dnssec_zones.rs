//! A signed fake hierarchy: root `.` and `test.` are signed and linked by DS
//! records, and selectable child zones exercise the DNSSEC cases a validating
//! resolver must handle (secure, insecure, bogus variants, NSEC3, wildcards).

use std::net::Ipv4Addr;

use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, DS};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::TestkitError;
use crate::hierarchy::ServerSpec;
use crate::signer::{DenialMode, SigAlgorithm, SigningOptions, ZoneKey, sign_zone, unix_now};
use crate::zone::{Zone, parse_name};

/// NSEC3 salt used by the NSEC3 child variants.
pub const NSEC3_SALT: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];

/// A child zone of `test.` that can be selected by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChildVariant {
    /// `secure.test.`: signed, DS in parent, NSEC denial, wildcard at `*.wild.secure.test.`.
    Secure,
    /// `nsec3.test.`: signed with NSEC3 (salt `aabbccdd`, 0 iterations), wildcard at `*.wild.nsec3.test.`.
    Nsec3,
    /// `nsec3-optout.test.`: NSEC3 with the opt-out flag; its insecure
    /// delegation `unsigned.nsec3-optout.test.` is left out of the chain.
    Nsec3OptOut,
    /// `insecure.test.`: unsigned, the parent proves there is no DS.
    Insecure,
    /// `bogus-sig.test.`: signed, but the RRSIG over `www A` is corrupted.
    BogusSig,
    /// `bogus-expired.test.`: all RRSIGs expired.
    BogusExpired,
    /// `bogus-nokey.test.`: the parent's DS matches a key the child does not publish.
    BogusNoKey,
}

impl ChildVariant {
    /// Every variant.
    pub const ALL: [ChildVariant; 7] = [
        Self::Secure,
        Self::Nsec3,
        Self::Nsec3OptOut,
        Self::Insecure,
        Self::BogusSig,
        Self::BogusExpired,
        Self::BogusNoKey,
    ];

    /// The zone origin, for example `secure.test.`.
    pub fn zone_name(self) -> &'static str {
        match self {
            Self::Secure => "secure.test.",
            Self::Nsec3 => "nsec3.test.",
            Self::Nsec3OptOut => "nsec3-optout.test.",
            Self::Insecure => "insecure.test.",
            Self::BogusSig => "bogus-sig.test.",
            Self::BogusExpired => "bogus-expired.test.",
            Self::BogusNoKey => "bogus-nokey.test.",
        }
    }

    /// Looks a variant up by its zone name (`secure.test.`, trailing dot optional).
    pub fn from_zone_name(name: &str) -> Option<Self> {
        let wanted = name.trim_end_matches('.').to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|v| v.zone_name().trim_end_matches('.') == wanted)
    }

    fn www_addr(self) -> Ipv4Addr {
        let octet = Self::ALL
            .iter()
            .position(|v| *v == self)
            .and_then(|i| u8::try_from(i).ok())
            .unwrap_or(0);
        Ipv4Addr::new(192, 0, 2, 10 + octet)
    }

    fn is_signed(self) -> bool {
        self != Self::Insecure
    }
}

/// The trust anchor for the fake root: its DNSKEY and the matching DS.
#[derive(Clone, Debug)]
pub struct TrustAnchor {
    /// Owner name (the root).
    pub owner: Name,
    /// The root DNSKEY (flags 257).
    pub dnskey: DNSKEY,
    /// SHA-256 DS of the root DNSKEY.
    pub ds: DS,
}

impl TrustAnchor {
    /// The DNSKEY as a resource record.
    pub fn dnskey_record(&self) -> Record {
        Record::from_rdata(
            self.owner.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::DNSKEY(self.dnskey.clone())),
        )
    }

    /// The DS as a resource record.
    pub fn ds_record(&self) -> Record {
        Record::from_rdata(
            self.owner.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::DS(self.ds.clone())),
        )
    }
}

/// Configuration of a signed hierarchy.
#[derive(Clone, Debug)]
pub struct DnssecScenario {
    variants: Vec<ChildVariant>,
    algorithm: SigAlgorithm,
    now: u32,
    validity: Option<(u32, u32)>,
}

impl DnssecScenario {
    /// A scenario with the given child zones, ECDSA P-256 and the current time.
    pub fn new(variants: &[ChildVariant]) -> Self {
        Self {
            variants: variants.to_vec(),
            algorithm: SigAlgorithm::default(),
            now: unix_now(),
            validity: None,
        }
    }

    /// A scenario with every child zone.
    pub fn all() -> Self {
        Self::new(&ChildVariant::ALL)
    }

    /// Uses `algorithm` for every key.
    pub fn with_algorithm(mut self, algorithm: SigAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Fixes the reference time (Unix seconds). Default windows are
    /// `now - 1h ..= now + 30d`; `bogus-expired.test.` gets `now - 30d ..= now - 1d`.
    pub fn with_now(mut self, now: u32) -> Self {
        self.now = now;
        self
    }

    /// Overrides inception and expiration of every zone except `bogus-expired.test.`.
    pub fn with_validity(mut self, inception: u32, expiration: u32) -> Self {
        self.validity = Some((inception, expiration));
        self
    }

    fn options(&self, denial: DenialMode) -> SigningOptions {
        let mut options = SigningOptions::at(self.now);
        if let Some((inception, expiration)) = self.validity {
            options.inception = inception;
            options.expiration = expiration;
        }
        options.denial = denial;
        options
    }
}

/// Builds the server specs of a signed hierarchy and its trust anchor.
///
/// The returned specs are ready for [`Hierarchy::start_with`](crate::Hierarchy::start_with);
/// [`Hierarchy::start_signed`](crate::Hierarchy::start_signed) does that and keeps the anchor.
pub fn signed_servers(
    scenario: &DnssecScenario,
) -> Result<(Vec<ServerSpec>, TrustAnchor), TestkitError> {
    let lo = Ipv4Addr::LOCALHOST;
    let alg = scenario.algorithm;
    let root_key = ZoneKey::generate(alg)?;
    let test_key = ZoneKey::generate(alg)?;
    let test_name = parse_name("test.")?;

    let mut test = Zone::new("test.")?
        .with_soa("ns1.test.", "hostmaster.test.")?
        .with_ns("test.", "ns1.test.")?
        .with_a("ns1.test.", lo)?;
    let mut specs = Vec::new();
    for variant in &scenario.variants {
        let origin = variant.zone_name();
        let ns = format!("ns1.{origin}");
        test = test.with_ns(origin, &ns)?.with_a(&ns, lo)?;

        let key = ZoneKey::generate(alg)?;
        let mut zone = Zone::new(origin)?
            .with_soa(&ns, &format!("hostmaster.{origin}"))?
            .with_ns(origin, &ns)?
            .with_a(&ns, lo)?
            .with_a(&format!("www.{origin}"), variant.www_addr())?;
        if matches!(variant, ChildVariant::Secure | ChildVariant::Nsec3) {
            zone = zone.with_a(&format!("*.wild.{origin}"), Ipv4Addr::new(192, 0, 2, 99))?;
        }
        if *variant == ChildVariant::Nsec3OptOut {
            let cut = format!("unsigned.{origin}");
            let cut_ns = format!("ns1.{cut}");
            zone = zone.with_ns(&cut, &cut_ns)?.with_a(&cut_ns, lo)?;
        }

        let origin_name = parse_name(origin)?;
        if variant.is_signed() {
            // The DS in the parent: for bogus-nokey it describes a key the child never publishes.
            let ds_record = if *variant == ChildVariant::BogusNoKey {
                decoy_key(alg)?.ds_record(&origin_name)?
            } else {
                key.ds_record(&origin_name)?
            };
            test = test.with_record(ds_record);

            let mut options = match variant {
                ChildVariant::BogusExpired => {
                    let mut o = SigningOptions::at(scenario.now);
                    o.inception = scenario.now.saturating_sub(30 * 86400);
                    o.expiration = scenario.now.saturating_sub(86400);
                    o
                }
                _ => scenario.options(DenialMode::Nsec),
            };
            options.denial = match variant {
                ChildVariant::Nsec3 => nsec3(false),
                ChildVariant::Nsec3OptOut => nsec3(true),
                _ => DenialMode::Nsec,
            };
            if *variant == ChildVariant::BogusSig {
                options.corrupt_signature_of =
                    Some((parse_name(&format!("www.{origin}"))?, RecordType::A));
            }
            zone = sign_zone(zone, &key, &options)?;
        }
        specs.push(ServerSpec::new(&format!("ns1.{origin}"), zone)?);
    }

    let test = sign_zone(test, &test_key, &scenario.options(DenialMode::Nsec))?;
    let root = Zone::new(".")?
        .with_soa("a.root-servers.net.", "hostmaster.root-servers.net.")?
        .with_ns(".", "a.root-servers.net.")?
        .with_a("a.root-servers.net.", lo)?
        .with_ns("test.", "ns1.test.")?
        .with_a("ns1.test.", lo)?
        .with_record(test_key.ds_record(&test_name)?);
    let root = sign_zone(root, &root_key, &scenario.options(DenialMode::Nsec))?;

    let anchor = TrustAnchor {
        owner: Name::root(),
        dnskey: root_key.dnskey().clone(),
        ds: root_key.ds(&Name::root())?,
    };
    let mut all = vec![
        ServerSpec::new("a.root-servers.net.", root)?,
        ServerSpec::new("ns1.test.", test)?,
    ];
    all.append(&mut specs);
    Ok((all, anchor))
}

fn nsec3(opt_out: bool) -> DenialMode {
    DenialMode::Nsec3 {
        salt: NSEC3_SALT.to_vec(),
        iterations: 0,
        opt_out,
    }
}

/// A key different from the one used for the zone itself (RSA has two embedded keys).
fn decoy_key(alg: SigAlgorithm) -> Result<ZoneKey, TestkitError> {
    ZoneKey::generate_decoy(alg)
}
