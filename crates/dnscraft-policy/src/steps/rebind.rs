//! Step 10: DNS rebind protection (strip private A/AAAA from resolver answers).
//!
//! When every address record is private and removed, **CNAME chain records are
//! kept**: the response is NOERROR with only the CNAMEs (NODATA-for-alias
//! shape). Only A/AAAA are stripped from the answer section; the section is
//! not cleared.
//!
//! HTTPS/SVCB `ipv4hint` / `ipv6hint` (RFC 9460 §7.3) and private A/AAAA in the
//! additional section are also scrubbed — see [`strip_svcb_hints`].

use std::net::{Ipv4Addr, Ipv6Addr};

use dnscraft_proto::{Message, Name, RData, Rcode, Record, SvcbData};
use dnscraft_resolver::ForwardZoneId;

use crate::config::RequestContext;
use crate::decision::{DecisionStep, RebindSkipReason};
use crate::pipeline::{Draft, StepCtx, clear_ad};
use crate::private::is_private_for_rebind;
use crate::snapshot::RebindException;
use crate::synth::{DEFAULT_BLOCK_TTL, ensure_nodata_soa};

/// SvcParamKey `ipv4hint` (RFC 9460 §7.3 / §14.3.3).
const IPV4HINT: u16 = 4;
/// SvcParamKey `ipv6hint` (RFC 9460 §7.3 / §14.3.3).
const IPV6HINT: u16 = 6;

/// Runs rebind stripping on a resolver answer. Skipped when `draft.synthetic`
/// (defence in depth; synthetic paths return before step 10).
///
/// Mutates `message` in place: private A/AAAA removed from answers and
/// additionals; private addresses removed from HTTPS/SVCB hints; if every
/// answer-section address was stripped → NOERROR with remaining non-address
/// records (e.g. CNAMEs / HTTPS), no EDE. Clears AD on any change.
pub(crate) fn run(
    ctx: &RequestContext,
    step: StepCtx<'_>,
    draft: &mut Draft,
    message: &mut Message,
    forward_zone: Option<&ForwardZoneId>,
) {
    if draft.synthetic {
        return;
    }

    let profile = step.snapshot.profile_for_view(draft.selection.view_idx);
    let default_rebind = step.snapshot.default_rebind;

    if !profile.config.rebind_enabled(default_rebind) {
        draft.steps.push(DecisionStep::RebindSkipped {
            reason: RebindSkipReason::Disabled,
        });
        return;
    }

    if exception_matches(&ctx.query.name, &profile.rebind_exceptions) {
        draft.steps.push(DecisionStep::RebindSkipped {
            reason: RebindSkipReason::Exception,
        });
        return;
    }

    if let Some(z) = forward_zone {
        let checked = step
            .snapshot
            .rebind_check_forward_zones
            .iter()
            .any(|id| id == z);
        if !checked {
            draft.steps.push(DecisionStep::RebindSkipped {
                reason: RebindSkipReason::ForwardZoneExempt,
            });
            return;
        }
    }

    let mut stripped: u32 = 0;
    stripped = stripped.saturating_add(strip_address_rrs(&mut message.answers));
    stripped = stripped.saturating_add(strip_svcb_rrs(&mut message.answers));
    stripped = stripped.saturating_add(strip_address_rrs(&mut message.additionals));

    if stripped == 0 {
        return;
    }

    clear_ad(message);
    draft
        .steps
        .push(DecisionStep::RebindStripped { count: stripped });

    // All addresses gone from the answer section: keep any CNAME / HTTPS /
    // other non-address records and ensure NOERROR — NODATA-for-alias when
    // CNAMEs remain; empty answer gets a synthetic SOA so clients can
    // negatively cache.
    let any_address_left = message
        .answers
        .iter()
        .any(|r| matches!(&r.rdata, RData::A(_) | RData::AAAA(_)));
    if !any_address_left {
        let _ = message.set_rcode(Rcode::NOERROR);
        if message.answers.is_empty() {
            ensure_nodata_soa(message, &ctx.query.name, DEFAULT_BLOCK_TTL);
        }
    }
}

fn strip_address_rrs(rrs: &mut Vec<Record>) -> u32 {
    let before = rrs.len();
    rrs.retain(|rec| match &rec.rdata {
        RData::A(v4) => !is_private_for_rebind((*v4).into()),
        RData::AAAA(v6) => !is_private_for_rebind((*v6).into()),
        _ => true,
    });
    u32::try_from(before.saturating_sub(rrs.len())).unwrap_or(u32::MAX)
}

fn strip_svcb_rrs(rrs: &mut [Record]) -> u32 {
    let mut total = 0u32;
    for rec in rrs.iter_mut() {
        let (is_https, data) = match &rec.rdata {
            RData::HTTPS(d) => (true, d.clone()),
            RData::SVCB(d) => (false, d.clone()),
            _ => continue,
        };
        match strip_svcb_hints(&data) {
            HintRewrite::Unchanged | HintRewrite::Malformed => {}
            HintRewrite::Changed {
                data: new_data,
                stripped,
            } => {
                total = total.saturating_add(stripped);
                rec.rdata = if is_https {
                    RData::HTTPS(new_data)
                } else {
                    RData::SVCB(new_data)
                };
            }
        }
    }
    total
}

/// Outcome of scrubbing `ipv4hint` / `ipv6hint` on one SVCB/HTTPS RDATA.
///
/// Hint values are opaque octets per RFC 9460 §7.3: key 4 is `n × 4` bytes of
/// IPv4 addresses; key 6 is `n × 16` bytes of IPv6. A length that is not a
/// multiple of the address size is treated as malformed — the whole record is
/// left unchanged so we never drop data we cannot parse.
#[derive(Debug, PartialEq, Eq)]
enum HintRewrite {
    Unchanged,
    Changed { data: SvcbData, stripped: u32 },
    Malformed,
}

/// Scrubs private addresses from HTTPS/SVCB hint parameters (RFC 9460 §7.3).
///
/// Empty hints after filtering are dropped; remaining params keep strictly
/// increasing key order. Non-hint params are copied unchanged.
fn strip_svcb_hints(data: &SvcbData) -> HintRewrite {
    let mut new_params: Vec<(u16, Box<[u8]>)> = Vec::with_capacity(data.params.len());
    let mut stripped = 0u32;
    let mut changed = false;

    for (key, value) in &data.params {
        match *key {
            IPV4HINT => match filter_ipv4_hint(value) {
                Ok((kept, removed)) => {
                    stripped = stripped.saturating_add(removed);
                    if removed > 0 {
                        changed = true;
                    }
                    if !kept.is_empty() {
                        if kept.as_ref() != value.as_ref() {
                            changed = true;
                        }
                        new_params.push((*key, kept));
                    } else {
                        // Param dropped entirely.
                        changed = true;
                    }
                }
                Err(()) => return HintRewrite::Malformed,
            },
            IPV6HINT => match filter_ipv6_hint(value) {
                Ok((kept, removed)) => {
                    stripped = stripped.saturating_add(removed);
                    if removed > 0 {
                        changed = true;
                    }
                    if !kept.is_empty() {
                        if kept.as_ref() != value.as_ref() {
                            changed = true;
                        }
                        new_params.push((*key, kept));
                    } else {
                        changed = true;
                    }
                }
                Err(()) => return HintRewrite::Malformed,
            },
            _ => new_params.push((*key, value.clone())),
        }
    }

    if !changed {
        return HintRewrite::Unchanged;
    }
    HintRewrite::Changed {
        data: SvcbData {
            priority: data.priority,
            target: data.target.clone(),
            params: new_params,
        },
        stripped,
    }
}

fn filter_ipv4_hint(value: &[u8]) -> Result<(Box<[u8]>, u32), ()> {
    if value.len() % 4 != 0 {
        return Err(());
    }
    let mut kept = Vec::with_capacity(value.len());
    let mut removed = 0u32;
    for chunk in value.chunks_exact(4) {
        let addr = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
        if is_private_for_rebind(addr.into()) {
            removed = removed.saturating_add(1);
        } else {
            kept.extend_from_slice(chunk);
        }
    }
    Ok((kept.into(), removed))
}

fn filter_ipv6_hint(value: &[u8]) -> Result<(Box<[u8]>, u32), ()> {
    if value.len() % 16 != 0 {
        return Err(());
    }
    let mut kept = Vec::with_capacity(value.len());
    let mut removed = 0u32;
    for chunk in value.chunks_exact(16) {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(chunk);
        let addr = Ipv6Addr::from(octets);
        if is_private_for_rebind(addr.into()) {
            removed = removed.saturating_add(1);
        } else {
            kept.extend_from_slice(chunk);
        }
    }
    Ok((kept.into(), removed))
}

/// Pre-parsed `exact` or `*.suffix` against the qname (suffix includes the apex).
fn exception_matches(qname: &Name, exceptions: &[RebindException]) -> bool {
    for ex in exceptions {
        match ex {
            RebindException::Exact(name) => {
                if name == qname {
                    return true;
                }
            }
            RebindException::Suffix(zone) => {
                if zone.zone_of(qname) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unit {
    use super::*;
    use std::sync::Arc;

    use dnscraft_proto::{Class, Header, RecordType};

    #[test]
    fn exception_exact_and_suffix() {
        let suffix = RebindException::Suffix(Name::from_ascii("example.com").unwrap());
        let exact = RebindException::Exact(Name::from_ascii("nas.lan").unwrap());
        let list = Arc::from(vec![suffix, exact]);

        let q = Name::from_ascii("cdn.internal.example.com.").unwrap();
        assert!(exception_matches(&q, &list));
        assert!(exception_matches(
            &Name::from_ascii("example.com.").unwrap(),
            &list
        ));
        assert!(!exception_matches(
            &Name::from_ascii("example.org.").unwrap(),
            &list
        ));
        assert!(exception_matches(
            &Name::from_ascii("nas.lan.").unwrap(),
            &list
        ));
        assert!(!exception_matches(
            &Name::from_ascii("other.lan.").unwrap(),
            &list
        ));
    }

    fn ipv4_bytes(addrs: &[Ipv4Addr]) -> Box<[u8]> {
        let mut v = Vec::with_capacity(addrs.len() * 4);
        for a in addrs {
            v.extend_from_slice(&a.octets());
        }
        v.into()
    }

    fn ipv6_bytes(addrs: &[Ipv6Addr]) -> Box<[u8]> {
        let mut v = Vec::with_capacity(addrs.len() * 16);
        for a in addrs {
            v.extend_from_slice(&a.octets());
        }
        v.into()
    }

    #[test]
    fn ipv4hint_mixed_keeps_public_drops_private() {
        let data = SvcbData {
            priority: 1,
            target: Name::from_ascii(".").unwrap(),
            params: vec![
                (1, b"\x02h2".to_vec().into()),
                (
                    IPV4HINT,
                    ipv4_bytes(&[Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(192, 0, 2, 1)]),
                ),
            ],
        };
        match strip_svcb_hints(&data) {
            HintRewrite::Changed {
                data: out,
                stripped,
            } => {
                assert_eq!(stripped, 1);
                assert_eq!(out.params.len(), 2);
                assert_eq!(out.params[0].0, 1);
                assert_eq!(out.params[1].0, IPV4HINT);
                assert_eq!(
                    out.params[1].1.as_ref(),
                    ipv4_bytes(&[Ipv4Addr::new(192, 0, 2, 1)]).as_ref()
                );
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn ipv4hint_all_private_drops_param() {
        let data = SvcbData {
            priority: 1,
            target: Name::from_ascii(".").unwrap(),
            params: vec![(
                IPV4HINT,
                ipv4_bytes(&[Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(192, 168, 1, 1)]),
            )],
        };
        match strip_svcb_hints(&data) {
            HintRewrite::Changed {
                data: out,
                stripped,
            } => {
                assert_eq!(stripped, 2);
                assert!(out.params.is_empty());
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn ipv6hint_ula_stripped() {
        let ula = Ipv6Addr::new(0xfd12, 0, 0, 0, 0, 0, 0, 1);
        let pub_v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let data = SvcbData {
            priority: 1,
            target: Name::from_ascii(".").unwrap(),
            params: vec![(IPV6HINT, ipv6_bytes(&[ula, pub_v6]))],
        };
        match strip_svcb_hints(&data) {
            HintRewrite::Changed {
                data: out,
                stripped,
            } => {
                assert_eq!(stripped, 1);
                assert_eq!(out.params[0].1.as_ref(), ipv6_bytes(&[pub_v6]).as_ref());
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn malformed_ipv4hint_length_leaves_unchanged() {
        let data = SvcbData {
            priority: 1,
            target: Name::from_ascii(".").unwrap(),
            params: vec![(IPV4HINT, vec![10, 0, 0, 1, 99].into())],
        };
        assert_eq!(strip_svcb_hints(&data), HintRewrite::Malformed);
    }

    #[test]
    fn additional_section_private_a_stripped() {
        let mut msg = Message {
            header: Header::default(),
            questions: Vec::new(),
            answers: vec![Record::new(
                Name::from_ascii("www.example.test.").unwrap(),
                Class::IN,
                60,
                RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            )],
            authorities: Vec::new(),
            additionals: vec![
                Record::new(
                    Name::from_ascii("ns.example.test.").unwrap(),
                    Class::IN,
                    60,
                    RData::A(Ipv4Addr::new(10, 0, 0, 53)),
                ),
                Record::new(
                    Name::from_ascii("ns.example.test.").unwrap(),
                    Class::IN,
                    60,
                    RData::A(Ipv4Addr::new(192, 0, 2, 53)),
                ),
            ],
            edns: None,
        };
        let n = strip_address_rrs(&mut msg.additionals);
        assert_eq!(n, 1);
        assert_eq!(msg.additionals.len(), 1);
        assert_eq!(
            msg.additionals[0].rdata,
            RData::A(Ipv4Addr::new(192, 0, 2, 53))
        );
        assert_eq!(msg.answers[0].rtype(), RecordType::A);
    }
}
