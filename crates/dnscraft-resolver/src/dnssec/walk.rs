//! Glue between the iteration and the validation building blocks: fetches
//! DNSKEY RRsets (counted against the query budget) and descends the chain of
//! trust at referrals (Task 9b).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};

use dnscraft_proto::{Message, Name, RData, Rcode, Record, RecordType};

use super::denial::{Denial, prove_nodata, prove_nxdomain, prove_wildcard_answer};

use super::status::{BogusReason, Status, Trust, check_no_ds, child_trust, rrsets};
use super::{
    DelegationTrust, DsStatus, KeysOutcome, ValidatedKeys, VerifyFailure, ds_status,
    validate_dnskey_rrset_budgeted, validate_rrset_budgeted,
};
use crate::BoxFuture;
use crate::error::ResolveError;
use crate::iterate::{Candidate, Context};

/// Servers asked for a DNSKEY RRset: the one that just answered plus a few
/// other known addresses of the zone.
const MAX_DNSKEY_SERVERS: usize = 3;

/// Makes sure the DNSKEY RRset of `zone` is fetched and validated when
/// `trust` still asks for it; other states are returned unchanged.
///
/// The result of a fetch is remembered for the rest of the resolution, so a
/// zone's DNSKEY RRset is requested at most once.
pub(crate) async fn settle(
    ctx: &Context<'_>,
    zone: &Name,
    trust: Trust,
    server: SocketAddr,
    rest: &VecDeque<Candidate>,
) -> Result<Trust, ResolveError> {
    if !trust.is_pending() {
        return Ok(trust);
    }
    if let Some(known) = ctx
        .zone_trust
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(zone)
    {
        return Ok(known.clone());
    }
    let mut servers = vec![server];
    for c in rest {
        if let Candidate::Addr(a) = c
            && !servers.contains(a)
        {
            servers.push(*a);
        }
    }
    servers.truncate(MAX_DNSKEY_SERVERS);

    let mut response = None;
    for s in servers {
        if let Some(msg) = ctx.query_server(s, zone, RecordType::DNSKEY).await?
            && msg.rcode() == Rcode::NOERROR
        {
            response = Some(msg);
            break;
        }
    }
    let settled = match response {
        None => Trust::Bogus(BogusReason::DnskeyUnavailable),
        Some(msg) => {
            let delegation = match &trust {
                Trust::Ds(ds) => DelegationTrust::Ds(ds),
                _ => DelegationTrust::Anchors(&ctx.config.trust_anchors),
            };
            match validate_dnskey_rrset_budgeted(
                zone,
                &msg.answers,
                &msg.answers,
                delegation,
                ctx.config.clock.now(),
                &ctx.dnssec_budget,
            ) {
                Ok(KeysOutcome::Secure(keys)) => Trust::Secure(Arc::new(keys)),
                Ok(KeysOutcome::Insecure(_)) => Trust::Insecure,
                Err(e) => Trust::Bogus(BogusReason::Chain(e)),
            }
        }
    };
    ctx.zone_trust
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(zone.clone(), settled.clone());
    Ok(settled)
}

/// Maximum nesting of hidden-cut lookups (intermediate signer zones).
const MAX_CUT_DEPTH: u8 = 8;
/// Maximum number of DS probes for hidden cuts per resolution.
const MAX_PROBES: u32 = 8;

/// What a DS lookup at a name found.
enum Cut {
    /// The name is a zone cut with this outcome (secure, insecure or bogus).
    Zone(Trust),
    /// No validated evidence of a cut (carries why).
    NotCut(BogusReason),
}

/// DS lookup at `s`, a name below `parent` (whose keys are `pkeys`), at
/// `server` (which hosts `parent` and possibly `s`).
///
/// This is the "DS walk" for cuts that no referral showed because parent and
/// child are served by the same servers. A DS response signed by an
/// intermediate zone (`parent` < I < `s`) establishes I first.
fn cut_at<'a>(
    ctx: &'a Context<'a>,
    parent: &'a Name,
    pkeys: &'a Arc<ValidatedKeys>,
    s: &'a Name,
    server: SocketAddr,
    depth: u8,
) -> BoxFuture<'a, Result<Cut, ResolveError>> {
    Box::pin(async move {
        if let Some(known) = ctx
            .zone_trust
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(s)
        {
            return Ok(Cut::Zone(known.clone()));
        }
        if depth > MAX_CUT_DEPTH {
            return Ok(Cut::Zone(Trust::Bogus(BogusReason::DnskeyUnavailable)));
        }
        let Some(msg) = ctx.query_server(server, s, RecordType::DS).await? else {
            return Ok(Cut::NotCut(BogusReason::DnskeyUnavailable));
        };
        if !matches!(msg.rcode(), Rcode::NOERROR | Rcode::NXDOMAIN) {
            return Ok(Cut::NotCut(BogusReason::DnskeyUnavailable));
        }
        let all: Vec<Record> = msg
            .answers
            .iter()
            .chain(&msg.authorities)
            .cloned()
            .collect();
        let keys = match choose_signer(parent, s, &all, |t| {
            matches!(t, RecordType::DS | RecordType::NSEC | RecordType::NSEC3)
        }) {
            Some(i) => match cut_at(ctx, parent, pkeys, &i, server, depth + 1).await? {
                Cut::Zone(Trust::Secure(k)) => k,
                Cut::Zone(Trust::Bogus(r)) | Cut::NotCut(r) => {
                    return Ok(Cut::Zone(Trust::Bogus(r)));
                }
                Cut::Zone(_) => {
                    return Ok(Cut::Zone(Trust::Bogus(BogusReason::Verify(
                        VerifyFailure::SignerNotZone,
                    ))));
                }
            },
            None => pkeys.clone(),
        };
        let ds: Vec<Record> = msg
            .answers
            .iter()
            .filter(|r| r.rtype() == RecordType::DS && r.name == *s)
            .cloned()
            .collect();
        let cut = if ds.is_empty() {
            match check_no_ds(s, &all, &keys, ctx.config.clock.now(), &ctx.dnssec_budget) {
                Ok(()) => Cut::Zone(Trust::Insecure),
                Err(e) => Cut::NotCut(e),
            }
        } else if let Err(e) = validate_rrset_budgeted(
            &ds,
            &msg.answers,
            &keys,
            ctx.config.clock.now(),
            &ctx.dnssec_budget,
        ) {
            Cut::Zone(Trust::Bogus(BogusReason::Verify(e)))
        } else {
            match ds_status(&ds) {
                DsStatus::Usable => {
                    Cut::Zone(settle(ctx, s, Trust::Ds(ds), server, &VecDeque::new()).await?)
                }
                DsStatus::Unsupported(_) => Cut::Zone(Trust::Insecure),
                DsStatus::Absent => Cut::NotCut(BogusReason::NoDsProof),
            }
        };
        if let Cut::Zone(t) = &cut {
            ctx.zone_trust
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(s.clone(), t.clone());
        }
        Ok(cut)
    })
}

/// A signer below `zone` (and at or above `owner`) among the RRSIGs of
/// `records` whose covered type satisfies `covered`: the sign of a hidden cut.
fn choose_signer(
    zone: &Name,
    owner: &Name,
    records: &[Record],
    covered: impl Fn(RecordType) -> bool,
) -> Option<Name> {
    records.iter().find_map(|r| match &r.rdata {
        RData::RRSIG {
            type_covered,
            signer_name,
            ..
        } if r.rtype() == RecordType::RRSIG
            && covered(*type_covered)
            && zone.zone_of(signer_name)
            && signer_name != zone
            && signer_name.zone_of(owner) =>
        {
            Some(signer_name.clone())
        }
        _ => None,
    })
}

/// Keys of the signer zone `signer` below `zone`, or why there are none.
async fn signer_keys(
    ctx: &Context<'_>,
    zone: &Name,
    zkeys: &Arc<ValidatedKeys>,
    signer: &Name,
    server: SocketAddr,
) -> Result<Result<Arc<ValidatedKeys>, BogusReason>, ResolveError> {
    Ok(match cut_at(ctx, zone, zkeys, signer, server, 0).await? {
        Cut::Zone(Trust::Secure(k)) => Ok(k),
        Cut::Zone(Trust::Bogus(r)) | Cut::NotCut(r) => Err(r),
        // Signatures by a zone that is not secure prove nothing.
        Cut::Zone(_) => Err(BogusReason::Verify(VerifyFailure::SignerNotZone)),
    })
}

/// Looks for a hidden cut between `zone` and `target` by asking for the DS of
/// every label on the way down (at most [`MAX_PROBES`] per resolution).
///
/// Returns `Insecure` for a proven insecure cut, `Secure` when `target`
/// itself is a secure zone, `Bogus` otherwise. Only validated proofs change
/// the outcome, so stripping signatures can never lead to `Insecure`.
async fn probe(
    ctx: &Context<'_>,
    zone: &Name,
    zkeys: &Arc<ValidatedKeys>,
    target: &Name,
    server: SocketAddr,
) -> Result<Trust, ResolveError> {
    let mut path = Vec::new();
    let mut cur = target.clone();
    while cur != *zone {
        path.push(cur.clone());
        match cur.parent() {
            Some(p) if zone.zone_of(&p) => cur = p,
            _ => break,
        }
    }
    if cur != *zone {
        return Ok(Trust::Bogus(BogusReason::NoDsProof));
    }
    path.reverse();
    let mut cur_zone = zone.clone();
    let mut cur_keys = zkeys.clone();
    for label in path {
        if ctx.probes.fetch_add(1, Ordering::Relaxed) >= MAX_PROBES {
            break;
        }
        match cut_at(ctx, &cur_zone, &cur_keys, &label, server, 0).await? {
            Cut::NotCut(_) => {}
            Cut::Zone(Trust::Insecure) => return Ok(Trust::Insecure),
            Cut::Zone(Trust::Secure(k)) => {
                if label == *target {
                    return Ok(Trust::Secure(k));
                }
                cur_zone = label;
                cur_keys = k;
            }
            Cut::Zone(Trust::Bogus(r)) => return Ok(Trust::Bogus(r)),
            Cut::Zone(_) => break,
        }
    }
    Ok(Trust::Bogus(BogusReason::NoDsProof))
}

/// Trust in the child `cut` after a referral from `zone` (answered by
/// `server`), whose own trust is `trust`.
///
/// The DS/NSEC records of the referral may be signed by a zone below `zone`
/// that shares its servers (for example `co.uk` on the `uk` servers); that
/// zone is established first. A referral without usable proof falls back to a
/// DS probe, which finds insecure delegations of hidden zones.
pub(crate) async fn descend(
    ctx: &Context<'_>,
    zone: &Name,
    trust: Trust,
    cut: &Name,
    referral: &Message,
    server: SocketAddr,
    rest: &VecDeque<Candidate>,
) -> Result<Trust, ResolveError> {
    let keys = match settle(ctx, zone, trust, server, rest).await? {
        Trust::Secure(keys) => keys,
        // A pending state cannot be left after `settle`; fail closed.
        Trust::Anchor | Trust::Ds(_) => return Ok(Trust::Bogus(BogusReason::DnskeyUnavailable)),
        other @ (Trust::Off | Trust::Insecure | Trust::Bogus(_)) => return Ok(other),
    };
    let now = ctx.config.clock.now();
    let eff = match choose_signer(zone, cut, &referral.authorities, |t| {
        matches!(t, RecordType::DS | RecordType::NSEC | RecordType::NSEC3)
    }) {
        Some(signer) => match signer_keys(ctx, zone, &keys, &signer, server).await? {
            Ok(k) => k,
            Err(r) => return Ok(Trust::Bogus(r)),
        },
        None => keys.clone(),
    };
    let t = child_trust(cut, &referral.authorities, &eff, now, &ctx.dnssec_budget);
    if let Trust::Bogus(BogusReason::NoDsProof | BogusReason::Verify(VerifyFailure::NoSignatures)) =
        t
    {
        return match probe(ctx, zone, &keys, cut, server).await? {
            Trust::Bogus(_) => Ok(t),
            found => Ok(found),
        };
    }
    Ok(t)
}

enum SetOutcome {
    Valid {
        /// The wildcard owner of an expanded RRset.
        wildcard: Option<Name>,
        /// The zone that signed the RRset.
        signer: Name,
        /// Longest TTL the RRset may keep (RFC 4035 section 5.3.3).
        max_ttl: u32,
    },
    Insecure,
    Bogus(BogusReason),
}

/// Validates one RRset of a response from `zone`, following hidden cuts.
async fn validate_set(
    ctx: &Context<'_>,
    zone: &Name,
    zkeys: &Arc<ValidatedKeys>,
    set: &[Record],
    sigs: &[Record],
    server: SocketAddr,
) -> Result<SetOutcome, ResolveError> {
    let Some(first) = set.first() else {
        return Ok(SetOutcome::Bogus(BogusReason::Verify(
            VerifyFailure::RrsetMismatch,
        )));
    };
    let covers = |t: RecordType| t == first.rtype();
    let signed = sigs.iter().any(|r| {
        r.name == first.name
            && matches!(&r.rdata, RData::RRSIG { type_covered, .. } if covers(*type_covered))
    });
    if !signed {
        // Unsigned in a secure zone: only a proven insecure cut explains it.
        return Ok(match probe(ctx, zone, zkeys, &first.name, server).await? {
            Trust::Insecure => SetOutcome::Insecure,
            _ => SetOutcome::Bogus(BogusReason::Verify(VerifyFailure::NoSignatures)),
        });
    }
    let keys = match choose_signer(zone, &first.name, sigs, covers) {
        Some(signer) => match signer_keys(ctx, zone, zkeys, &signer, server).await? {
            Ok(k) => k,
            Err(r) => return Ok(SetOutcome::Bogus(r)),
        },
        None => zkeys.clone(),
    };
    Ok(
        match validate_rrset_budgeted(set, sigs, &keys, ctx.config.clock.now(), &ctx.dnssec_budget)
        {
            Ok(v) => SetOutcome::Valid {
                wildcard: v.wildcard,
                signer: v.signer,
                max_ttl: v.max_ttl,
            },
            Err(e) => SetOutcome::Bogus(BogusReason::Verify(e)),
        },
    )
}

/// The best denial result over the proof records grouped by signer: every
/// signer zone gets its own proof attempt, since the records of a proof must
/// all come from the zone whose denial is shown.
fn prove_by_signer(
    proofs: &[(Name, Record)],
    only: Option<&Name>,
    prove: impl Fn(&Name, &[Record]) -> Denial,
) -> Denial {
    let mut signers: Vec<&Name> = Vec::new();
    for (s, _) in proofs {
        if only.is_none_or(|o| o == s) && !signers.contains(&s) {
            signers.push(s);
        }
    }
    let mut result: Option<Denial> = None;
    for signer in signers {
        let records: Vec<Record> = proofs
            .iter()
            .filter(|(s, _)| s == signer)
            .map(|(_, r)| r.clone())
            .collect();
        let d = prove(signer, &records);
        result = Some(result.map_or(d, |p| p.better(d)));
    }
    result.unwrap_or(Denial::Bogus(BogusReason::NoDenialProof))
}

/// A cap on the lifetime of a validated RRset: its TTL must not exceed the
/// original TTL of the validating RRSIG nor outlive that signature
/// (RFC 4035 section 5.3.3).
#[derive(Clone, Debug)]
pub(crate) struct TtlCap {
    pub name: Name,
    pub rtype: RecordType,
    pub max_ttl: u32,
}

/// The type a record is about: its own, or the covered type of an RRSIG.
pub(crate) fn covered_type(r: &Record) -> Option<RecordType> {
    match &r.rdata {
        RData::RRSIG { type_covered, .. } if r.rtype() == RecordType::RRSIG => Some(*type_covered),
        _ if r.rtype() == RecordType::RRSIG => None,
        _ => Some(r.rtype()),
    }
}

/// Lowers the TTL of every record that belongs to a validated RRset in
/// `caps` and notes the smallest cap applied in `min_cap`.
pub(crate) fn apply_caps(records: &mut [Record], caps: &[TtlCap], min_cap: &mut Option<u32>) {
    for r in records {
        let Some(covered) = covered_type(r) else {
            continue;
        };
        let cap = caps
            .iter()
            .filter(|c| c.rtype == covered && c.name == r.name)
            .map(|c| c.max_ttl)
            .min();
        if let Some(cap) = cap {
            r.ttl = r.ttl.min(cap);
            *min_cap = Some(min_cap.map_or(cap, |m| m.min(cap)));
        }
    }
}

/// Whether an NXDOMAIN response carries a record that proves the name
/// exists: an RRset for the queried type (or any record at the name for
/// `ANY`; the CNAME itself for `CNAME`). The rcode is not covered by
/// signatures, so a validated positive answer can be turned into NXDOMAIN
/// without breaking any signature. A CNAME/DNAME link whose target is
/// re-resolved is no such evidence.
pub(crate) fn nxdomain_contradicted(
    message: &Message,
    zone: &Name,
    qname: &Name,
    qtype: RecordType,
) -> bool {
    message.rcode() == Rcode::NXDOMAIN
        && message
            .answers
            .iter()
            .filter(|r| zone.zone_of(&r.name) && r.rtype() != RecordType::RRSIG)
            .any(|r| match qtype {
                RecordType::ANY => r.name == *qname,
                RecordType::CNAME => r.name == *qname && r.rtype() == RecordType::CNAME,
                // A DNAME above `qname` (synthesis) is a link, not the name itself.
                _ => r.rtype() == qtype && (r.rtype() != RecordType::DNAME || r.name == *qname),
            })
}

/// Validation result of the final response of `zone` (whose trust is `trust`,
/// already settled) to `qname`/`qtype`, answered by `server`.
///
/// Positive RRsets must validate; wildcard expansions need a proof that
/// `qname` does not exist; an answer without data (NXDOMAIN or NODATA) needs
/// a complete NSEC/NSEC3 proof. A CNAME chain that leaves the response is
/// judged link by link: the resolver asks again for the target, and the
/// denial for it is checked in that response.
///
/// For every validated RRset (answers and proof records) the longest TTL it
/// may keep is appended to `caps`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn assess_final(
    ctx: &Context<'_>,
    zone: &Name,
    trust: &Trust,
    message: &Message,
    qname: &Name,
    qtype: RecordType,
    server: SocketAddr,
    caps: &mut Vec<TtlCap>,
) -> Result<Status, ResolveError> {
    let zkeys = match trust {
        Trust::Off | Trust::Anchor | Trust::Ds(_) => return Ok(Status::Indeterminate),
        Trust::Insecure => return Ok(Status::Insecure),
        Trust::Bogus(r) => return Ok(Status::Bogus(*r)),
        Trust::Secure(keys) => keys,
    };
    let dnames: Vec<&Name> = message
        .answers
        .iter()
        .filter(|r| r.rtype() == RecordType::DNAME)
        .map(|r| &r.name)
        .collect();
    // A CNAME below a DNAME is synthesized by the server (unsigned, RFC 6672
    // section 3.1); the resolver synthesizes its own, so it is not validated.
    let synthesized = |r: &Record| {
        r.rtype() == RecordType::CNAME && dnames.iter().any(|d| **d != r.name && d.zone_of(&r.name))
    };
    let mut status = Status::Secure;
    let mut proved = false;
    let mut expansions: Vec<(Name, Name, Name)> = Vec::new();
    for set in rrsets(&message.answers, zone, |r| !synthesized(r)) {
        let owned: Vec<Record> = set.into_iter().cloned().collect();
        match validate_set(ctx, zone, zkeys, &owned, &message.answers, server).await? {
            SetOutcome::Valid {
                wildcard,
                signer,
                max_ttl,
            } => {
                proved = true;
                if let Some(first) = owned.first() {
                    caps.push(TtlCap {
                        name: first.name.clone(),
                        rtype: first.rtype(),
                        max_ttl,
                    });
                }
                if let (Some(source), Some(first)) = (wildcard, owned.first()) {
                    expansions.push((first.name.clone(), source, signer));
                }
            }
            SetOutcome::Insecure => status = status.combine(Status::Insecure),
            SetOutcome::Bogus(r) => return Ok(Status::Bogus(r)),
        }
    }
    // SOA/NSEC/NSEC3 of negative answers (and wildcard proofs) must carry
    // valid signatures; the NSEC/NSEC3 records that do feed the proofs,
    // together with their signer.
    let mut proofs: Vec<(Name, Record)> = Vec::new();
    for set in rrsets(&message.authorities, zone, |r| {
        matches!(
            r.rtype(),
            RecordType::SOA | RecordType::NSEC | RecordType::NSEC3
        )
    }) {
        let owned: Vec<Record> = set.into_iter().cloned().collect();
        match validate_set(ctx, zone, zkeys, &owned, &message.authorities, server).await? {
            // An expanded NSEC/NSEC3 is a replay, not a proof.
            SetOutcome::Valid {
                wildcard: None,
                signer,
                max_ttl,
            } => {
                if let Some(first) = owned.first() {
                    caps.push(TtlCap {
                        name: first.name.clone(),
                        rtype: first.rtype(),
                        max_ttl,
                    });
                }
                proofs.extend(
                    owned
                        .into_iter()
                        .filter(|r| r.rtype() != RecordType::SOA)
                        .map(|r| (signer.clone(), r)),
                );
            }
            SetOutcome::Valid { .. } => {}
            SetOutcome::Insecure => status = status.combine(Status::Insecure),
            SetOutcome::Bogus(r) => return Ok(Status::Bogus(r)),
        }
    }
    let note = |d: Denial, status: Status| match d {
        Denial::Secure => Ok(status),
        Denial::Insecure(why) => Ok(status.combine(Status::from_insecure(why))),
        Denial::Bogus(r) => Err(r),
    };
    for (owner, source, signer) in &expansions {
        let d = prove_by_signer(&proofs, Some(signer), |z, recs| {
            prove_wildcard_answer(z, owner, source, recs, &ctx.dnssec_budget)
        });
        match note(d, status) {
            Ok(s) => status = s,
            Err(r) => return Ok(Status::Bogus(r)),
        }
    }
    // The rcode is not signed: NXDOMAIN next to a validated RRset for the
    // very question is a forgery.
    if nxdomain_contradicted(message, zone, qname, qtype) {
        return Ok(Status::Bogus(BogusReason::RcodeMismatch));
    }
    // Is a denial for `qname` claimed? Not when the response has data for it
    // or a link (CNAME, or a DNAME above) that the resolver follows.
    let in_zone = |r: &Record| zone.zone_of(&r.name);
    let answered = message.answers.iter().filter(|r| in_zone(r)).any(|r| {
        let direct = r.name == *qname
            && r.rtype() != RecordType::RRSIG
            && (qtype == RecordType::ANY || r.rtype() == qtype || r.rtype() == RecordType::CNAME);
        let dname = r.rtype() == RecordType::DNAME && r.name != *qname && r.name.zone_of(qname);
        direct || dname
    });
    if !answered {
        let claim = match message.rcode() {
            Rcode::NXDOMAIN => Some(prove_by_signer(&proofs, None, |z, recs| {
                if z.zone_of(qname) {
                    prove_nxdomain(z, qname, recs, &ctx.dnssec_budget)
                } else {
                    Denial::Bogus(BogusReason::BadDenialProof)
                }
            })),
            Rcode::NOERROR => Some(prove_by_signer(&proofs, None, |z, recs| {
                if z.zone_of(qname) {
                    prove_nodata(z, qname, qtype, recs, &ctx.dnssec_budget)
                } else {
                    Denial::Bogus(BogusReason::BadDenialProof)
                }
            })),
            _ => None,
        };
        if let Some(d) = claim {
            proved = true;
            match note(d, status) {
                Ok(s) => status = s,
                Err(r) => return Ok(Status::Bogus(r)),
            }
        }
    }
    if !proved {
        status = status.combine(Status::Indeterminate);
    }
    Ok(status)
}
