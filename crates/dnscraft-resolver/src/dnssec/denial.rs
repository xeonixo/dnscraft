//! Authenticated denial of existence (Task 10): NSEC (RFC 4035 section 5.4,
//! RFC 6840 section 4) and NSEC3 (RFC 5155 sections 8.3 to 8.9) proofs.
//!
//! Everything here is pure and works on records whose RRSIGs have already
//! been validated; the caller guarantees that every record passed in was
//! signed by `zone` (the apex whose denial is proven). These functions only
//! check the logic of the proof.
//!
//! Judgment calls (Unbound and BIND behave the same where the RFCs leave
//! room):
//! - An NSEC3 chain whose iteration count exceeds [`NSEC3_MAX_ITERATIONS`] or
//!   whose hash algorithm is unknown proves nothing and yields `Insecure`
//!   (RFC 9276 section 3.2), never `Bogus`, and is never hashed.
//! - An opt-out span covering the next closer name makes DS NODATA (RFC 5155
//!   section 8.6), wildcard expansions (section 8.8) and NXDOMAIN without a
//!   wildcard proof `Insecure`. A complete NXDOMAIN proof (closest encloser,
//!   next closer and wildcard) stays `Secure` even with the opt-out flag set,
//!   as in Unbound and BIND: TLDs such as .de and .com are opt-out zones and
//!   their NXDOMAIN answers validate.
//! - NSEC/NSEC3 records at a delegation point (NS without SOA) or below a
//!   DNAME never prove anything about names below them.

use std::cell::{Cell, RefCell};
use std::cmp::Ordering;
use std::collections::HashMap;

use dnscraft_proto::dnssec::{NSEC3_HASH_SHA1, base32hex_decode, nsec3_hash};
use dnscraft_proto::{Name, RData, Record, RecordType, TypeBitmap};

use super::ValidationBudget;
use super::status::BogusReason;

/// NSEC3 opt-out flag (RFC 5155 section 3.1.2).
const NSEC3_OPT_OUT: u8 = 0x01;

/// Above this many additional NSEC3 iterations a zone is treated as insecure
/// (RFC 9276 section 3.2: validators MAY, above their limit SHOULD). RFC 9276
/// asks zones for 0 iterations; BIND treats more than 50 as insecure, Unbound's
/// default cap is 150. 100 sits between them: it bounds one hash at 101 SHA-1
/// rounds while tolerating the few legacy zones that still use dozens. It is
/// also passed to the hash function as its own safety net, together with the
/// per-resolution hash count budget (`MAX_NSEC3_HASHES_PER_RESOLVE`).
pub(crate) const NSEC3_MAX_ITERATIONS: u16 = 100;

/// Why a proof leads to `Insecure` instead of `Secure`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InsecureWhy {
    /// The next closer name lies in an opt-out span: unsigned delegations
    /// may exist there.
    OptOut,
    /// More NSEC3 iterations than [`NSEC3_MAX_ITERATIONS`] (EDE 27).
    Nsec3Iterations,
    /// Unknown NSEC3 hash algorithm.
    Nsec3Algorithm,
}

/// Result of a denial proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Denial {
    /// The proof is complete.
    Secure,
    /// The proof is complete but only proves insecurity.
    Insecure(InsecureWhy),
    /// The proof is missing or does not prove what it must.
    Bogus(BogusReason),
}

impl Denial {
    fn bad() -> Self {
        Self::Bogus(BogusReason::BadDenialProof)
    }

    /// The better of two results for the same claim (Secure, then Insecure,
    /// then the first Bogus).
    pub fn better(self, other: Self) -> Self {
        fn rank(d: &Denial) -> u8 {
            match d {
                Denial::Secure => 0,
                Denial::Insecure(_) => 1,
                Denial::Bogus(_) => 2,
            }
        }
        if rank(&other) < rank(&self) {
            other
        } else {
            self
        }
    }
}

// ---------------------------------------------------------------------------
// Public proofs
// ---------------------------------------------------------------------------

/// Proof that `qname` does not exist in `zone` (NXDOMAIN).
pub(crate) fn prove_nxdomain(
    zone: &Name,
    qname: &Name,
    records: &[Record],
    budget: &ValidationBudget,
) -> Denial {
    both(
        zone,
        records,
        |z, r| nsec_nxdomain(z, qname, r),
        |z, r| nsec3_nxdomain(z, qname, r, budget),
    )
}

/// Proof that `qname` exists in `zone` but has no `qtype` RRset (NODATA),
/// including wildcard NODATA, empty non-terminals and DS at an opt-out span.
pub(crate) fn prove_nodata(
    zone: &Name,
    qname: &Name,
    qtype: RecordType,
    records: &[Record],
    budget: &ValidationBudget,
) -> Denial {
    both(
        zone,
        records,
        |z, r| nsec_nodata(z, qname, qtype, r),
        |z, r| nsec3_nodata(z, qname, qtype, r, budget),
    )
}

/// Proof that `qname`, answered from the wildcard `source`, does not exist
/// itself (RFC 4035 section 5.3.4, RFC 5155 section 8.8).
pub(crate) fn prove_wildcard_answer(
    zone: &Name,
    qname: &Name,
    source: &Name,
    records: &[Record],
    budget: &ValidationBudget,
) -> Denial {
    both(
        zone,
        records,
        |z, r| nsec_wildcard_answer(z, qname, source, r),
        |z, r| nsec3_wildcard_answer(z, qname, source, r, budget),
    )
}

/// Proof that the delegation `cut` has no DS record (RFC 4035 section 5.2,
/// RFC 5155 section 8.9): a matching NSEC/NSEC3 with NS but neither DS nor
/// SOA, or (NSEC3 only) an opt-out span covering the cut with a proven
/// closest encloser, which is `Insecure`.
pub(crate) fn prove_no_ds(
    zone: &Name,
    cut: &Name,
    records: &[Record],
    budget: &ValidationBudget,
) -> Denial {
    both(
        zone,
        records,
        |_, r| nsec_no_ds(cut, r),
        |z, r| nsec3_no_ds(z, cut, r, budget),
    )
}

/// Runs the NSEC and NSEC3 variants over the records of that kind.
fn both(
    zone: &Name,
    records: &[Record],
    nsec: impl Fn(&Name, &[&Record]) -> Denial,
    nsec3: impl Fn(&Name, &[&Record]) -> Denial,
) -> Denial {
    let owned = |t: RecordType| -> Vec<&Record> {
        records
            .iter()
            .filter(|r| r.rtype == t && zone.zone_of(&r.name))
            .collect()
    };
    let (n1, n3) = (owned(RecordType::NSEC), owned(RecordType::NSEC3));
    let mut result: Option<Denial> = None;
    let mut add = |d: Denial| result = Some(result.map_or(d, |p| p.better(d)));
    if !n1.is_empty() {
        add(nsec(zone, &n1));
    }
    if !n3.is_empty() {
        add(nsec3(zone, &n3));
    }
    result.unwrap_or(Denial::Bogus(BogusReason::NoDenialProof))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The ancestor of `name` with exactly `labels` labels.
fn ancestor_with(name: &Name, labels: usize) -> Option<Name> {
    let mut cur = name.clone();
    while cur.label_count() > labels {
        cur = cur.parent()?;
    }
    (cur.label_count() == labels).then_some(cur)
}

/// `*.parent`.
fn wildcard_of(parent: &Name) -> Option<Name> {
    let mut wire = vec![1u8, b'*'];
    wire.extend_from_slice(parent.as_wire());
    Name::decode(&wire, 0).ok().map(|(n, _)| n)
}

/// A delegation point: NS without SOA (RFC 6840 section 4.1).
fn is_delegation(types: &TypeBitmap) -> bool {
    types.contains(RecordType::NS) && !types.contains(RecordType::SOA)
}

/// Whether a matching NSEC/NSEC3 bitmap proves that `qtype` does not exist:
/// neither `qtype` nor CNAME is present and the record is not from the wrong
/// side of a zone cut (RFC 6840 section 4.1 and 4.3).
fn bitmap_denies(types: &TypeBitmap, qtype: RecordType) -> bool {
    let has_qtype = if qtype == RecordType::ANY {
        types
            .iter()
            .any(|t| !matches!(t, RecordType::NSEC | RecordType::NSEC3 | RecordType::RRSIG))
    } else {
        types.contains(qtype)
    };
    if has_qtype || (qtype != RecordType::CNAME && types.contains(RecordType::CNAME)) {
        return false;
    }
    if qtype == RecordType::DS {
        // A bitmap with SOA comes from the child apex.
        !types.contains(RecordType::SOA)
    } else {
        !is_delegation(types)
    }
}

/// Whether `owner` with `types` is on the wrong side of a cut for `name`
/// (below a delegation point or a DNAME).
fn blocks(owner: &Name, types: &TypeBitmap, name: &Name) -> bool {
    owner != name
        && owner.zone_of(name)
        && (is_delegation(types) || types.contains(RecordType::DNAME))
}

// ---------------------------------------------------------------------------
// NSEC
// ---------------------------------------------------------------------------

struct Nsec<'a> {
    owner: &'a Name,
    next: &'a Name,
    types: &'a TypeBitmap,
}

fn nsecs<'a>(records: &[&'a Record]) -> Vec<Nsec<'a>> {
    records
        .iter()
        .filter_map(|r| match &r.rdata {
            RData::NSEC { next_domain, types } => Some(Nsec {
                owner: &r.name,
                next: next_domain,
                types,
            }),
            _ => None,
        })
        .collect()
}

impl Nsec<'_> {
    /// Whether `name` lies strictly between owner and next in canonical
    /// order; the last NSEC of the chain wraps around to the apex
    /// (RFC 4034 section 4.1.1), as does a single-name chain.
    fn covers(&self, name: &Name) -> bool {
        match self.owner.cmp(self.next) {
            Ordering::Less => self.owner < name && name < self.next,
            _ => name > self.owner || name < self.next,
        }
    }

    /// Covers `name` and may be used as proof that it is absent: not from
    /// the wrong side of a cut, and `name` is not an empty non-terminal.
    fn proves_absent(&self, name: &Name) -> bool {
        self.covers(name)
            && !blocks(self.owner, self.types, name)
            && !(self.next != name && name.zone_of(self.next))
    }
}

/// The deepest ancestor of `qname` that is also an ancestor of (or equal to)
/// the owner or the next name of `nsec`: the closest encloser implied by the
/// covering NSEC (RFC 4035 section 5.4).
fn nsec_encloser(zone: &Name, qname: &Name, nsec: &Nsec<'_>) -> Option<Name> {
    let deepest = |other: &Name| {
        let mut c = qname.clone();
        while !c.zone_of(other) {
            c = c.parent()?;
        }
        Some(c)
    };
    let (a, b) = (deepest(nsec.owner)?, deepest(nsec.next)?);
    let ce = if a.label_count() >= b.label_count() {
        a
    } else {
        b
    };
    (zone.zone_of(&ce) && ce != *qname).then_some(ce)
}

fn nsec_nxdomain(zone: &Name, qname: &Name, records: &[&Record]) -> Denial {
    let all = nsecs(records);
    if all.iter().any(|n| n.owner == qname) {
        // The name exists.
        return Denial::bad();
    }
    let Some(cover) = all.iter().find(|n| n.proves_absent(qname)) else {
        return Denial::bad();
    };
    let Some(wildcard) = nsec_encloser(zone, qname, cover).and_then(|ce| wildcard_of(&ce)) else {
        return Denial::bad();
    };
    if all.iter().any(|n| n.owner == &wildcard) {
        return Denial::bad();
    }
    if all.iter().any(|n| n.proves_absent(&wildcard)) {
        Denial::Secure
    } else {
        Denial::bad()
    }
}

fn nsec_nodata(zone: &Name, qname: &Name, qtype: RecordType, records: &[&Record]) -> Denial {
    let all = nsecs(records);
    if let Some(m) = all.iter().find(|n| n.owner == qname) {
        return if bitmap_denies(m.types, qtype) {
            Denial::Secure
        } else {
            Denial::bad()
        };
    }
    let Some(cover) = all.iter().find(|n| n.covers(qname)) else {
        return Denial::bad();
    };
    if blocks(cover.owner, cover.types, qname) {
        return Denial::bad();
    }
    // Empty non-terminal: the next name is below `qname`.
    if cover.next != qname && qname.zone_of(cover.next) {
        return Denial::Secure;
    }
    // Wildcard NODATA: `qname` does not exist, but the wildcard does and
    // lacks the type.
    let Some(wildcard) = nsec_encloser(zone, qname, cover).and_then(|ce| wildcard_of(&ce)) else {
        return Denial::bad();
    };
    match all.iter().find(|n| n.owner == &wildcard) {
        Some(w) if bitmap_denies(w.types, qtype) => Denial::Secure,
        _ => Denial::bad(),
    }
}

fn nsec_wildcard_answer(zone: &Name, qname: &Name, source: &Name, records: &[&Record]) -> Denial {
    let all = nsecs(records);
    // The covering NSEC must imply the same closest encloser as the
    // synthesizing wildcard (RFC 4035 section 5.3.4 / RFC 4592): otherwise
    // a higher signed wildcard can be replayed under a closer existing name.
    let Some(expected_ce) = source
        .parent()
        .filter(|ce| ce.zone_of(qname) && *ce != *qname)
    else {
        return Denial::bad();
    };
    let ok = all.iter().any(|n| {
        n.proves_absent(qname) && nsec_encloser(zone, qname, n).as_ref() == Some(&expected_ce)
    });
    if ok {
        Denial::Secure
    } else if all.is_empty() {
        Denial::Bogus(BogusReason::NoDenialProof)
    } else {
        Denial::bad()
    }
}

fn nsec_no_ds(cut: &Name, records: &[&Record]) -> Denial {
    match nsecs(records).iter().find(|n| n.owner == cut) {
        Some(m)
            if m.types.contains(RecordType::NS)
                && !m.types.contains(RecordType::DS)
                && !m.types.contains(RecordType::SOA) =>
        {
            Denial::Secure
        }
        _ => Denial::bad(),
    }
}

// ---------------------------------------------------------------------------
// NSEC3
// ---------------------------------------------------------------------------

struct Nsec3<'a> {
    owner_hash: Vec<u8>,
    next: &'a [u8],
    opt_out: bool,
    types: &'a TypeBitmap,
}

impl Nsec3<'_> {
    fn covers(&self, hash: &[u8]) -> bool {
        if self.owner_hash.as_slice() < self.next {
            self.owner_hash.as_slice() < hash && hash < self.next
        } else {
            hash > self.owner_hash.as_slice() || hash < self.next
        }
    }
}

struct Chain<'a> {
    algorithm: u8,
    iterations: u16,
    salt: &'a [u8],
    items: Vec<Nsec3<'a>>,
    /// Hashes computed during this proof evaluation, so that each name is
    /// hashed at most once however often it is matched or covered.
    memo: RefCell<HashMap<Name, [u8; 20]>>,
    budget: &'a ValidationBudget,
    /// A hash was refused because the budget is spent.
    exhausted: Cell<bool>,
}

/// The NSEC3 records directly below `zone` sharing the parameters of the
/// first usable one; records with other parameters are ignored.
fn nsec3_chain<'a>(
    zone: &Name,
    records: &[&'a Record],
    budget: &'a ValidationBudget,
) -> Option<Chain<'a>> {
    let mut chain: Option<Chain<'a>> = None;
    for r in records {
        let RData::NSEC3 {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner,
            types,
        } = &r.rdata
        else {
            continue;
        };
        if r.name.parent().as_ref() != Some(zone) {
            continue;
        }
        let Some(owner_hash) = r
            .name
            .labels()
            .next()
            .and_then(|l| std::str::from_utf8(l).ok())
            .and_then(|l| base32hex_decode(l).ok())
        else {
            continue;
        };
        let item = Nsec3 {
            owner_hash,
            next: next_hashed_owner,
            opt_out: flags & NSEC3_OPT_OUT != 0,
            types,
        };
        match &mut chain {
            None => {
                chain = Some(Chain {
                    algorithm: *hash_algorithm,
                    iterations: *iterations,
                    salt,
                    items: vec![item],
                    memo: RefCell::new(HashMap::new()),
                    budget,
                    exhausted: Cell::new(false),
                });
            }
            Some(c) => {
                if c.algorithm == *hash_algorithm
                    && c.iterations == *iterations
                    && c.salt == &**salt
                {
                    c.items.push(item);
                }
            }
        }
    }
    chain
}

impl Chain<'_> {
    /// Why this chain cannot be used, if so.
    fn unsupported(&self) -> Option<InsecureWhy> {
        if self.algorithm != NSEC3_HASH_SHA1 {
            Some(InsecureWhy::Nsec3Algorithm)
        } else if self.iterations > NSEC3_MAX_ITERATIONS {
            Some(InsecureWhy::Nsec3Iterations)
        } else {
            None
        }
    }

    /// The NSEC3 hash of `name`, memoised; `None` when the hash cannot be
    /// computed or the budget is spent (then `exhausted` is set and the proof
    /// result is replaced by a budget failure in [`with_chain`]).
    fn hash(&self, name: &Name) -> Option<[u8; 20]> {
        if let Some(h) = self.memo.borrow().get(name) {
            return Some(*h);
        }
        if !self.budget.charge_nsec3_hash() {
            self.exhausted.set(true);
            return None;
        }
        let h = nsec3_hash(
            self.algorithm,
            name,
            self.salt,
            self.iterations,
            NSEC3_MAX_ITERATIONS,
        )
        .ok()?;
        self.memo.borrow_mut().insert(name.clone(), h);
        Some(h)
    }

    fn matching(&self, name: &Name) -> Option<&Nsec3<'_>> {
        let h = self.hash(name)?;
        self.items.iter().find(|n| n.owner_hash == h)
    }

    fn covering(&self, name: &Name) -> Option<&Nsec3<'_>> {
        let h = self.hash(name)?;
        self.items.iter().find(|n| n.covers(&h))
    }
}

/// Closest encloser proof (RFC 5155 section 8.3): the longest proper
/// ancestor of `qname` inside `zone` with a matching NSEC3, plus the NSEC3
/// covering the next closer name.
struct EncloserProof {
    encloser: Name,
    /// The covering NSEC3 of the next closer name has the opt-out flag.
    opt_out: bool,
}

fn encloser_proof(zone: &Name, qname: &Name, chain: &Chain<'_>) -> Result<EncloserProof, Denial> {
    let mut cur = qname.parent();
    while let Some(c) = cur {
        if !zone.zone_of(&c) {
            break;
        }
        if let Some(m) = chain.matching(&c) {
            // The encloser must be a name of this zone (RFC 5155 section 8.3).
            if m.types.contains(RecordType::DNAME) || is_delegation(m.types) {
                return Err(Denial::bad());
            }
            let nc = ancestor_with(qname, c.label_count() + 1).ok_or_else(Denial::bad)?;
            let next_closer = chain.covering(&nc).ok_or_else(Denial::bad)?;
            return Ok(EncloserProof {
                encloser: c,
                opt_out: next_closer.opt_out,
            });
        }
        cur = c.parent();
    }
    Err(Denial::bad())
}

/// Builds the NSEC3 chain of `records`, runs `prove` on it and turns an
/// exhausted hash budget into a fail-closed `Bogus` (a refused hash would
/// otherwise look like "no matching record").
fn with_chain(
    zone: &Name,
    records: &[&Record],
    budget: &ValidationBudget,
    prove: impl FnOnce(&Chain<'_>) -> Denial,
) -> Denial {
    let Some(chain) = nsec3_chain(zone, records, budget) else {
        return Denial::Bogus(BogusReason::NoDenialProof);
    };
    if let Some(why) = chain.unsupported() {
        return Denial::Insecure(why);
    }
    let result = prove(&chain);
    if chain.exhausted.get() {
        Denial::Bogus(BogusReason::Nsec3Budget)
    } else {
        result
    }
}

fn nsec3_nxdomain(
    zone: &Name,
    qname: &Name,
    records: &[&Record],
    budget: &ValidationBudget,
) -> Denial {
    with_chain(zone, records, budget, |chain| {
        nxdomain_in_chain(zone, qname, chain)
    })
}

fn nxdomain_in_chain(zone: &Name, qname: &Name, chain: &Chain<'_>) -> Denial {
    if chain.matching(qname).is_some() {
        return Denial::bad();
    }
    let proof = match encloser_proof(zone, qname, chain) {
        Ok(p) => p,
        Err(d) => return d,
    };
    let wildcard_covered = wildcard_of(&proof.encloser)
        .and_then(|w| {
            // A matching NSEC3 would mean that the wildcard exists.
            chain.matching(&w).is_none().then(|| chain.covering(&w))
        })
        .flatten()
        .is_some();
    if wildcard_covered {
        // The complete proof of RFC 5155 section 8.4. An opt-out flag on the
        // next closer's covering record is accepted as Secure here, like
        // Unbound and BIND do (delv validates NXDOMAIN under .de and .com):
        // the server shows that neither the name nor its wildcard is in the
        // signed chain, and a delegation in the span would have got a referral.
        //
        // AD-bit trade-off (deliberate): inside an opt-out span, unsigned
        // delegations may exist without any NSEC3 record, so the proof cannot
        // distinguish "name does not exist" from "name is an unsigned
        // delegation". An attacker who replays a genuine, still-valid
        // opt-out NXDOMAIN proof for a span can therefore make a resolver
        // deny an existing unsigned delegation inside that span with AD=1.
        // Impact is limited: such a zone is unauthenticated anyway (an
        // on-path attacker could equally strip its DS-less referral, and its
        // data would never be Secure), the replay only works within the proof's
        // RRSIG validity and the span, and rejecting opt-out NXDOMAIN would
        // make most of .com/.de/.net names fail validation.
        Denial::Secure
    } else if proof.opt_out {
        // Without the wildcard proof an opt-out span only shows that the name
        // is not in the signed part of the zone (RFC 5155 section 6).
        Denial::Insecure(InsecureWhy::OptOut)
    } else {
        Denial::bad()
    }
}

fn nsec3_nodata(
    zone: &Name,
    qname: &Name,
    qtype: RecordType,
    records: &[&Record],
    budget: &ValidationBudget,
) -> Denial {
    with_chain(zone, records, budget, |chain| {
        nodata_in_chain(zone, qname, qtype, chain)
    })
}

fn nodata_in_chain(zone: &Name, qname: &Name, qtype: RecordType, chain: &Chain<'_>) -> Denial {
    if let Some(m) = chain.matching(qname) {
        return if bitmap_denies(m.types, qtype) {
            Denial::Secure
        } else {
            Denial::bad()
        };
    }
    let proof = match encloser_proof(zone, qname, chain) {
        Ok(p) => p,
        Err(d) => return d,
    };
    if qtype == RecordType::DS {
        // RFC 5155 section 8.6: only an opt-out span may hide a DS-less name.
        return if proof.opt_out {
            Denial::Insecure(InsecureWhy::OptOut)
        } else {
            Denial::bad()
        };
    }
    // Wildcard NODATA (RFC 5155 section 8.7).
    match wildcard_of(&proof.encloser).and_then(|w| chain.matching(&w)) {
        Some(w) if bitmap_denies(w.types, qtype) => Denial::Secure,
        _ => Denial::bad(),
    }
}

fn nsec3_wildcard_answer(
    zone: &Name,
    qname: &Name,
    source: &Name,
    records: &[&Record],
    budget: &ValidationBudget,
) -> Denial {
    with_chain(zone, records, budget, |chain| {
        wildcard_answer_in_chain(qname, source, chain)
    })
}

fn wildcard_answer_in_chain(qname: &Name, source: &Name, chain: &Chain<'_>) -> Denial {
    let Some(encloser) = source
        .parent()
        .filter(|ce| ce.zone_of(qname) && ce != qname)
    else {
        return Denial::bad();
    };
    let Some(nc) = ancestor_with(qname, encloser.label_count() + 1) else {
        return Denial::bad();
    };
    if chain.matching(&nc).is_some() {
        return Denial::bad();
    }
    match chain.covering(&nc) {
        Some(c) if c.opt_out => Denial::Insecure(InsecureWhy::OptOut),
        Some(_) => Denial::Secure,
        None => Denial::bad(),
    }
}

fn nsec3_no_ds(zone: &Name, cut: &Name, records: &[&Record], budget: &ValidationBudget) -> Denial {
    with_chain(zone, records, budget, |chain| {
        no_ds_in_chain(zone, cut, chain)
    })
}

fn no_ds_in_chain(zone: &Name, cut: &Name, chain: &Chain<'_>) -> Denial {
    if let Some(m) = chain.matching(cut) {
        return if m.types.contains(RecordType::NS)
            && !m.types.contains(RecordType::DS)
            && !m.types.contains(RecordType::SOA)
        {
            Denial::Secure
        } else {
            Denial::bad()
        };
    }
    // RFC 5155 section 8.9: an opt-out span covering the next closer name
    // (the cut itself, as a delegation is a name) with a proven closest
    // encloser.
    match encloser_proof(zone, cut, chain) {
        Ok(p) if p.opt_out => Denial::Insecure(InsecureWhy::OptOut),
        Ok(_) => Denial::bad(),
        Err(d) => d,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use dnscraft_proto::Class;
    use dnscraft_proto::dnssec::base32hex_encode;

    // Test shims: the pure proof logic runs with an unlimited budget.
    fn prove_nxdomain_t(zone: &Name, qname: &Name, records: &[Record]) -> Denial {
        prove_nxdomain(zone, qname, records, &ValidationBudget::unlimited())
    }
    fn prove_nodata_t(zone: &Name, qname: &Name, qtype: RecordType, records: &[Record]) -> Denial {
        prove_nodata(zone, qname, qtype, records, &ValidationBudget::unlimited())
    }
    fn prove_wildcard_answer_t(
        zone: &Name,
        qname: &Name,
        source: &Name,
        records: &[Record],
    ) -> Denial {
        prove_wildcard_answer(zone, qname, source, records, &ValidationBudget::unlimited())
    }
    fn prove_no_ds_t(zone: &Name, cut: &Name, records: &[Record]) -> Denial {
        prove_no_ds(zone, cut, records, &ValidationBudget::unlimited())
    }

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn nsec(owner: &str, next: &str, types: &[RecordType]) -> Record {
        Record {
            name: n(owner),
            rtype: RecordType::NSEC,
            class: Class::IN,
            ttl: 300,
            rdata: RData::NSEC {
                next_domain: n(next),
                types: TypeBitmap::new(types.iter().copied()),
            },
        }
    }

    fn h(name: &str, iterations: u16) -> Vec<u8> {
        nsec3_hash(1, &n(name), b"\xaa", iterations, u16::MAX)
            .unwrap()
            .to_vec()
    }

    /// An NSEC3 record covering exactly the hash interval (`owner`, `next`).
    fn nsec3(
        zone: &str,
        owner: &[u8],
        next: &[u8],
        flags: u8,
        iter: u16,
        t: &[RecordType],
    ) -> Record {
        Record {
            name: n(&format!("{}.{zone}", base32hex_encode(owner))),
            rtype: RecordType::NSEC3,
            class: Class::IN,
            ttl: 300,
            rdata: RData::NSEC3 {
                hash_algorithm: 1,
                flags,
                iterations: iter,
                salt: vec![0xaa].into(),
                next_hashed_owner: next.to_vec().into(),
                types: TypeBitmap::new(t.iter().copied()),
            },
        }
    }

    fn minus_one(mut v: Vec<u8>) -> Vec<u8> {
        for b in v.iter_mut().rev() {
            if *b == 0 {
                *b = 0xff;
            } else {
                *b -= 1;
                break;
            }
        }
        v
    }

    fn plus_one(mut v: Vec<u8>) -> Vec<u8> {
        for b in v.iter_mut().rev() {
            if *b == 0xff {
                *b = 0;
            } else {
                *b += 1;
                break;
            }
        }
        v
    }

    #[test]
    fn canonical_order_rfc4034_section_6_1() {
        let ordered = [
            "example.",
            "a.example.",
            "yljkjljk.a.example.",
            "Z.a.example.",
            "zABC.a.EXAMPLE.",
            "z.example.",
            "\\001.z.example.",
            "*.z.example.",
            "\\200.z.example.",
        ];
        let names: Vec<Name> = ordered.iter().map(|s| n(s)).collect();
        for w in names.windows(2) {
            assert_eq!(w[0].cmp(&w[1]), Ordering::Less, "{} < {}", w[0], w[1]);
        }
        let mut shuffled = names.clone();
        shuffled.reverse();
        shuffled.sort();
        assert_eq!(shuffled, names);
        assert_eq!(n("A.B.").cmp(&n("a.b.")), Ordering::Equal);
    }

    #[test]
    fn nsec_wraparound_covers() {
        let last = nsec("z.example.", "example.", &[RecordType::A]);
        let rs = [&last];
        let all = nsecs(&rs);
        assert!(all[0].covers(&n("zz.example.")));
        assert!(all[0].covers(&n("a.other.")));
        assert!(!all[0].covers(&n("m.example.")));
        assert!(!all[0].covers(&n("z.example.")));
    }

    #[test]
    fn nsec_nxdomain_needs_name_and_wildcard_cover() {
        let zone = n("example.");
        // example. -> m.example. covers b.example. and *.example.
        let first = nsec("example.", "m.example.", &[RecordType::SOA, RecordType::NS]);
        let last = nsec("m.example.", "example.", &[RecordType::A]);
        let both_covered = [first.clone(), last.clone()];
        assert_eq!(
            prove_nxdomain_t(&zone, &n("b.example."), &both_covered),
            Denial::Secure
        );
        // Without any proof.
        assert_eq!(
            prove_nxdomain_t(&zone, &n("b.example."), &[]),
            Denial::Bogus(BogusReason::NoDenialProof)
        );
        // The name exists.
        assert_eq!(
            prove_nxdomain_t(&zone, &n("m.example."), &both_covered),
            Denial::bad()
        );
        // Covers the name but not the wildcard: *.example. sorts after
        // example. so a chain a -> z would cover both; build one that skips it.
        let only_name = [nsec("b.example.", "c.example.", &[RecordType::A])];
        assert_eq!(
            prove_nxdomain_t(&zone, &n("bb.example."), &only_name),
            Denial::bad()
        );
    }

    #[test]
    fn nsec_empty_non_terminal_is_nodata_not_nxdomain() {
        let zone = n("example.");
        // wild.example. is an ENT: its NSEC neighbour ends below it.
        let r = nsec("ns1.example.", "*.wild.example.", &[RecordType::A]);
        let recs = [r];
        assert_eq!(
            prove_nodata_t(&zone, &n("wild.example."), RecordType::A, &recs),
            Denial::Secure
        );
        assert_eq!(
            prove_nxdomain_t(&zone, &n("wild.example."), &recs),
            Denial::bad()
        );
    }

    #[test]
    fn nsec_nodata_checks_bitmap_and_cname() {
        let zone = n("example.");
        let a_only = [nsec("www.example.", "example.", &[RecordType::A])];
        assert_eq!(
            prove_nodata_t(&zone, &n("www.example."), RecordType::AAAA, &a_only),
            Denial::Secure
        );
        assert_eq!(
            prove_nodata_t(&zone, &n("www.example."), RecordType::A, &a_only),
            Denial::bad()
        );
        let cname = [nsec("www.example.", "example.", &[RecordType::CNAME])];
        assert_eq!(
            prove_nodata_t(&zone, &n("www.example."), RecordType::AAAA, &cname),
            Denial::bad()
        );
    }

    #[test]
    fn nsec_ds_nodata_rejects_child_apex_bitmap() {
        let zone = n("example.");
        let apex = [nsec(
            "child.example.",
            "z.example.",
            &[RecordType::SOA, RecordType::NS],
        )];
        assert_eq!(
            prove_nodata_t(&zone, &n("child.example."), RecordType::DS, &apex),
            Denial::bad()
        );
        let cut = [nsec("child.example.", "z.example.", &[RecordType::NS])];
        assert_eq!(
            prove_nodata_t(&zone, &n("child.example."), RecordType::DS, &cut),
            Denial::Secure
        );
        assert_eq!(
            prove_nodata_t(&zone, &n("child.example."), RecordType::A, &cut),
            Denial::bad()
        );
    }

    #[test]
    fn nsec_wildcard_answer_needs_covering_nsec() {
        let zone = n("example.");
        let cover = [nsec("a.example.", "z.example.", &[RecordType::A])];
        assert_eq!(
            prove_wildcard_answer_t(&zone, &n("m.example."), &n("*.example."), &cover),
            Denial::Secure
        );
        assert_eq!(
            prove_wildcard_answer_t(&zone, &n("m.example."), &n("*.example."), &[]),
            Denial::Bogus(BogusReason::NoDenialProof)
        );
        let wrong = [nsec("n.example.", "z.example.", &[RecordType::A])];
        assert_eq!(
            prove_wildcard_answer_t(&zone, &n("m.example."), &n("*.example."), &wrong),
            Denial::bad()
        );
    }

    #[test]
    fn nsec_wildcard_answer_rejects_wrong_closest_encloser() {
        // Closest existing name is a.example.; synthesizing from *.example.
        // with an NSEC whose implied CE is a.example. must not validate.
        let zone = n("example.");
        let cover = [nsec(
            "a.example.",
            "z.a.example.",
            &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
        )];
        let nsec_rec = nsecs(&[&cover[0]]);
        assert!(nsec_rec[0].covers(&n("x.a.example.")));
        assert_eq!(
            nsec_encloser(&zone, &n("x.a.example."), &nsec_rec[0]),
            Some(n("a.example."))
        );
        assert_eq!(
            prove_wildcard_answer_t(&zone, &n("x.a.example."), &n("*.example."), &cover),
            Denial::bad()
        );
        // Same NSEC is fine when the wildcard matches that CE.
        assert_eq!(
            prove_wildcard_answer_t(&zone, &n("x.a.example."), &n("*.a.example."), &cover),
            Denial::Secure
        );
    }

    #[test]
    fn nsec_at_delegation_does_not_cover_names_below() {
        let zone = n("example.");
        let cut = [nsec("child.example.", "z.example.", &[RecordType::NS])];
        assert_eq!(
            prove_nxdomain_t(&zone, &n("www.child.example."), &cut),
            Denial::bad()
        );
    }

    /// Chain of three NSEC3 records over the names of a tiny zone.
    fn tiny_chain(opt_out: bool, iter: u16) -> (Vec<Record>, Name) {
        let zone = "example.";
        let apex = h("example.", iter);
        let www = h("www.example.", iter);
        let mut hashes = [apex.clone(), www.clone()];
        hashes.sort();
        let recs = vec![
            nsec3(
                zone,
                &hashes[0],
                &hashes[1],
                0,
                iter,
                &[RecordType::A, RecordType::RRSIG],
            ),
            nsec3(
                zone,
                &hashes[1],
                &hashes[0],
                u8::from(opt_out),
                iter,
                &[RecordType::A, RecordType::RRSIG],
            ),
        ];
        (recs, n(zone))
    }

    #[test]
    fn nsec3_nodata_matching_record() {
        let zone = n("example.");
        let apex = h("example.", 0);
        let r = nsec3(
            "example.",
            &apex,
            &plus_one(apex.clone()),
            0,
            0,
            &[RecordType::SOA, RecordType::NS, RecordType::RRSIG],
        );
        assert_eq!(
            prove_nodata_t(
                &zone,
                &n("example."),
                RecordType::A,
                std::slice::from_ref(&r)
            ),
            Denial::Secure
        );
        assert_eq!(
            prove_nodata_t(&zone, &n("example."), RecordType::NS, &[r]),
            Denial::bad()
        );
    }

    #[test]
    fn nsec3_high_iterations_are_insecure_and_not_hashed() {
        let zone = n("example.");
        let r = nsec3(
            "example.",
            &[1; 20],
            &[2; 20],
            0,
            NSEC3_MAX_ITERATIONS + 1,
            &[RecordType::A],
        );
        let expected = Denial::Insecure(InsecureWhy::Nsec3Iterations);
        assert_eq!(
            prove_nxdomain_t(&zone, &n("x.example."), std::slice::from_ref(&r)),
            expected
        );
        assert_eq!(
            prove_nodata_t(
                &zone,
                &n("x.example."),
                RecordType::A,
                std::slice::from_ref(&r)
            ),
            expected
        );
        assert_eq!(
            prove_wildcard_answer_t(
                &zone,
                &n("x.example."),
                &n("*.example."),
                std::slice::from_ref(&r)
            ),
            expected
        );
        assert_eq!(prove_no_ds_t(&zone, &n("x.example."), &[r]), expected);
        // The limit itself is still usable.
        let (ok, z) = tiny_chain(false, NSEC3_MAX_ITERATIONS);
        assert!(!matches!(
            prove_nxdomain_t(&z, &n("nope.example."), &ok),
            Denial::Insecure(InsecureWhy::Nsec3Iterations)
        ));
    }

    #[test]
    fn nsec3_unknown_algorithm_is_insecure() {
        let zone = n("example.");
        let mut r = nsec3("example.", &[1; 20], &[2; 20], 0, 0, &[RecordType::A]);
        if let RData::NSEC3 { hash_algorithm, .. } = &mut r.rdata {
            *hash_algorithm = 7;
        }
        assert_eq!(
            prove_nodata_t(&zone, &n("x.example."), RecordType::A, &[r]),
            Denial::Insecure(InsecureWhy::Nsec3Algorithm)
        );
    }

    #[test]
    fn nsec3_closest_encloser_nxdomain_and_opt_out() {
        let (recs, zone) = tiny_chain(false, 0);
        // The two NSEC3 records split the hash space in two covering
        // intervals; the closest encloser is the apex (matching) and both
        // the next closer and the wildcard fall into some interval.
        let q = n("nope.example.");
        assert_eq!(prove_nxdomain_t(&zone, &q, &recs), Denial::Secure);
        // Opt-out span over the next closer: without the wildcard proof the
        // answer is Insecure, with it Secure (as Unbound and BIND).
        let apex = h("example.", 0);
        let (hn, hw) = (h("nope.example.", 0), h("*.example.", 0));
        let apex_rec = nsec3(
            "example.",
            &apex,
            &plus_one(apex.clone()),
            0,
            0,
            &[RecordType::SOA, RecordType::NS],
        );
        let nc = nsec3("example.", &minus_one(hn.clone()), &plus_one(hn), 1, 0, &[]);
        let wc = nsec3("example.", &minus_one(hw.clone()), &plus_one(hw), 1, 0, &[]);
        assert_eq!(
            prove_nxdomain_t(&zone, &q, &[apex_rec.clone(), nc.clone()]),
            Denial::Insecure(InsecureWhy::OptOut)
        );
        assert_eq!(
            prove_nxdomain_t(&zone, &q, &[apex_rec.clone(), nc.clone(), wc.clone()]),
            Denial::Secure
        );
        // Without opt-out the missing wildcard proof is fatal.
        let mut plain = nc;
        if let RData::NSEC3 { flags, .. } = &mut plain.rdata {
            *flags = 0;
        }
        assert_eq!(
            prove_nxdomain_t(&zone, &q, &[apex_rec, plain]),
            Denial::bad()
        );
        // Missing encloser match: only a non-matching record.
        let apex = h("example.", 0);
        let lone = nsec3(
            "example.",
            &plus_one(apex.clone()),
            &minus_one(apex),
            0,
            0,
            &[RecordType::A],
        );
        assert_eq!(prove_nxdomain_t(&zone, &q, &[lone]), Denial::bad());
    }

    #[test]
    fn nsec3_no_ds_requires_closest_encloser_for_opt_out() {
        let zone = n("example.");
        let apex = h("example.", 0);
        let cut = n("cut.example.");
        let hc = h("cut.example.", 0);
        // Apex NSEC3 matching, and an opt-out record covering the cut's hash.
        let apex_rec = nsec3(
            "example.",
            &apex,
            &plus_one(apex.clone()),
            0,
            0,
            &[RecordType::SOA, RecordType::NS],
        );
        let cover = nsec3("example.", &minus_one(hc.clone()), &plus_one(hc), 1, 0, &[]);
        assert_eq!(
            prove_no_ds_t(&zone, &cut, &[apex_rec.clone(), cover.clone()]),
            Denial::Insecure(InsecureWhy::OptOut)
        );
        // Without the closest-encloser match the cover alone is not enough.
        assert_eq!(
            prove_no_ds_t(&zone, &cut, std::slice::from_ref(&cover)),
            Denial::bad()
        );
        // A cover without opt-out proves non-existence, not a DS-less cut.
        let mut plain = cover;
        if let RData::NSEC3 { flags, .. } = &mut plain.rdata {
            *flags = 0;
        }
        assert_eq!(
            prove_no_ds_t(&zone, &cut, &[apex_rec, plain]),
            Denial::bad()
        );
    }

    #[test]
    fn nsec3_wildcard_answer_needs_next_closer_cover() {
        let zone = n("example.");
        let q = n("x.example.");
        let hx = h("x.example.", 0);
        let cover = nsec3(
            "example.",
            &minus_one(hx.clone()),
            &plus_one(hx.clone()),
            0,
            0,
            &[],
        );
        assert_eq!(
            prove_wildcard_answer_t(&zone, &q, &n("*.example."), std::slice::from_ref(&cover)),
            Denial::Secure
        );
        let opt = nsec3(
            "example.",
            &minus_one(hx.clone()),
            &plus_one(hx.clone()),
            1,
            0,
            &[],
        );
        assert_eq!(
            prove_wildcard_answer_t(&zone, &q, &n("*.example."), &[opt]),
            Denial::Insecure(InsecureWhy::OptOut)
        );
        let matching = nsec3(
            "example.",
            &hx,
            &plus_one(hx.clone()),
            0,
            0,
            &[RecordType::A],
        );
        assert_eq!(
            prove_wildcard_answer_t(&zone, &q, &n("*.example."), &[matching]),
            Denial::bad()
        );
        assert_eq!(
            prove_wildcard_answer_t(&zone, &q, &n("*.example."), &[]),
            Denial::Bogus(BogusReason::NoDenialProof)
        );
    }

    #[test]
    fn nsec3_hashes_are_memoised_per_proof() {
        let (recs, zone) = tiny_chain(false, 0);
        let budget = ValidationBudget::unlimited();
        // Distinct names hashed: a.b.example. (matching), b.example. (walk,
        // reused as next closer), example. (encloser), *.example. (wildcard).
        // Without the memo the next closer b.example. is hashed twice.
        let _ = prove_nxdomain(&zone, &n("a.b.example."), &recs, &budget);
        assert_eq!(budget.nsec3_hashes_used(), 4);
    }

    #[test]
    fn nsec3_hash_budget_is_enforced_and_fails_closed() {
        let (recs, zone) = tiny_chain(false, 0);
        let qname = n(&format!("{}example.", "l.".repeat(100)));
        // The walk over 100 labels is cut off at the limit
        // instead of hashing every ancestor (before: unbounded, 100+ hashes
        // per proof and per call).
        let budget = ValidationBudget::with_limits(u32::MAX, 20);
        assert_eq!(
            prove_nxdomain(&zone, &qname, &recs, &budget),
            Denial::Bogus(BogusReason::Nsec3Budget)
        );
        assert_eq!(budget.nsec3_hashes_used(), 20);
        assert_eq!(BogusReason::Nsec3Budget.code(), "dnssec.nsec3_budget");
        assert_eq!(BogusReason::Nsec3Budget.ede_code(), 6);
        // The budget is per resolution: a spent budget refuses the next proof.
        assert_eq!(
            prove_nodata(&zone, &n("www.example."), RecordType::AAAA, &recs, &budget),
            Denial::Bogus(BogusReason::Nsec3Budget)
        );
        // Whatever the default budget does, it never hashes more than its cap.
        let default = ValidationBudget::default();
        for _ in 0..3 {
            let _ = prove_nxdomain(&zone, &qname, &recs, &default);
        }
        assert!(default.nsec3_hashes_used() <= crate::dnssec::MAX_NSEC3_HASHES_PER_RESOLVE);
    }

    #[test]
    fn nsec3_iteration_limit_is_100() {
        assert_eq!(NSEC3_MAX_ITERATIONS, 100);
        let (recs, zone) = tiny_chain(false, 101);
        let budget = ValidationBudget::default();
        assert_eq!(
            prove_nxdomain(&zone, &n("nope.example."), &recs, &budget),
            Denial::Insecure(InsecureWhy::Nsec3Iterations)
        );
        assert_eq!(budget.nsec3_hashes_used(), 0);
    }
}
