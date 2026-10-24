//! Glue between the iteration and the validation building blocks: fetches
//! DNSKEY RRsets (counted against the query budget) and descends the chain of
//! trust at referrals (Task 9b).

use std::collections::VecDeque;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};

use dnscraft_proto::{Message, Name, RData, Rcode, Record, RecordType};

use super::status::{BogusReason, Status, Trust, check_no_ds, child_trust, rrsets};
use super::{
    DelegationTrust, DsStatus, KeysOutcome, ValidatedKeys, VerifyFailure, ds_status,
    validate_dnskey_rrset, validate_rrset,
};
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
            match validate_dnskey_rrset(
                zone,
                &msg.answers,
                &msg.answers,
                delegation,
                ctx.config.clock.now(),
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

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

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
            .filter(|r| r.rtype == RecordType::DS && r.name == *s)
            .cloned()
            .collect();
        let cut = if ds.is_empty() {
            match check_no_ds(s, &all, &keys, ctx.config.clock.now()) {
                Ok(()) => Cut::Zone(Trust::Insecure),
                Err(e) => Cut::NotCut(e),
            }
        } else if let Err(e) = validate_rrset(&ds, &msg.answers, &keys, ctx.config.clock.now()) {
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
        } if r.rtype == RecordType::RRSIG
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
    let t = child_trust(cut, &referral.authorities, &eff, now);
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
    Valid { wildcard: bool },
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
    let covers = |t: RecordType| t == first.rtype;
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
        match validate_rrset(set, sigs, &keys, ctx.config.clock.now()) {
            Ok(v) => SetOutcome::Valid {
                wildcard: v.wildcard.is_some(),
            },
            Err(e) => SetOutcome::Bogus(BogusReason::Verify(e)),
        },
    )
}

/// Validation result of the final response of `zone` (whose trust is `trust`,
/// already settled), answered by `server`.
pub(crate) async fn assess_final(
    ctx: &Context<'_>,
    zone: &Name,
    trust: &Trust,
    message: &Message,
    server: SocketAddr,
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
        .filter(|r| r.rtype == RecordType::DNAME)
        .map(|r| &r.name)
        .collect();
    // A CNAME below a DNAME is synthesized by the server (unsigned, RFC 6672
    // section 3.1); the resolver synthesizes its own, so it is not validated.
    let synthesized = |r: &Record| {
        r.rtype == RecordType::CNAME && dnames.iter().any(|d| **d != r.name && d.zone_of(&r.name))
    };
    let mut positive = false;
    let mut wildcard = false;
    let mut insecure = false;
    for set in rrsets(&message.answers, zone, |r| !synthesized(r)) {
        let owned: Vec<Record> = set.into_iter().cloned().collect();
        match validate_set(ctx, zone, zkeys, &owned, &message.answers, server).await? {
            SetOutcome::Valid { wildcard: w } => {
                positive = true;
                // TODO(Task 10): prove that no closer name exists.
                wildcard |= w;
            }
            SetOutcome::Insecure => insecure = true,
            SetOutcome::Bogus(r) => return Ok(Status::Bogus(r)),
        }
    }
    // SOA/NSEC/NSEC3 of negative answers (and wildcard proofs) must at least
    // carry valid signatures.
    for set in rrsets(&message.authorities, zone, |r| {
        matches!(
            r.rtype,
            RecordType::SOA | RecordType::NSEC | RecordType::NSEC3
        )
    }) {
        let owned: Vec<Record> = set.into_iter().cloned().collect();
        match validate_set(ctx, zone, zkeys, &owned, &message.authorities, server).await? {
            SetOutcome::Valid { .. } => {}
            SetOutcome::Insecure => insecure = true,
            SetOutcome::Bogus(r) => return Ok(Status::Bogus(r)),
        }
    }
    // TODO(Task 10): negative answers (NXDOMAIN/NODATA) and wildcard
    // expansions stay Indeterminate until the denial proof is checked.
    Ok(if insecure {
        Status::Insecure
    } else if positive && !wildcard {
        Status::Secure
    } else {
        Status::Indeterminate
    })
}
