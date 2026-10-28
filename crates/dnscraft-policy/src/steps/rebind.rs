//! Step 10: DNS rebind protection (strip private A/AAAA from resolver answers).
//!
//! When every address record is private and removed, **CNAME chain records are
//! kept**: the response is NOERROR with only the CNAMEs (NODATA-for-alias
//! shape). Only A/AAAA are stripped from the answer section; the section is
//! not cleared.
//!
//! HTTPS/SVCB `ipv4hint` / `ipv6hint` (RFC 9460 §7.3) and private A/AAAA in the
//! additional section are also scrubbed — see [`strip_svcb_hints`].
//!
//! Whenever an RRset of type `T` is removed or rewritten, covering RRSIG
//! records (`type_covered == T`) in that section are removed too: the
//! remaining octets no longer match the signature (RFC 4035 §3.1.1 / §5).
//! Validating stubs then see an unsigned, modified answer and AD is never
//! set for it.
//!
//! Note: [`dnscraft_resolver`] clears the additional section on recursive and
//! forwarded answers before policy sees them, so additional-section stripping
//! is exercised by calling [`run`] with a constructed [`Message`] (see unit
//! tests). Defence in depth if a future resolver path retains glue.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dnscraft_proto::{Message, Name, RData, Rcode, Record, RecordType, SvcbData};
use dnscraft_resolver::ForwardZoneId;

use crate::config::RequestContext;
use crate::decision::{DecisionStep, RebindSkipReason};
use crate::pipeline::{Draft, StepCtx, clear_ad};
use crate::private::is_private_for_rebind;
use crate::snapshot::RebindException;
use crate::synth::{DEFAULT_BLOCK_TTL, ensure_nodata_soa};

/// SvcParamKey `mandatory` (RFC 9460 §7.1 / §8).
const MANDATORY: u16 = 0;
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
    // other non-address *data* records and ensure NOERROR — NODATA-for-alias
    // when CNAMEs remain. Emptiness for the synthetic SOA ignores RRSIG/NSEC
    // (DNSSEC proof RRs are not "data"); leftover proofs are cleared so the
    // answer section is truly empty before `ensure_nodata_soa`.
    let any_address_left = message
        .answers
        .iter()
        .any(|r| matches!(&r.rdata, RData::A(_) | RData::AAAA(_)));
    if !any_address_left {
        let _ = message.set_rcode(Rcode::NOERROR);
        let any_data_left = message.answers.iter().any(|r| !is_dnssec_proof(r));
        if !any_data_left {
            message.answers.retain(|r| !is_dnssec_proof(r));
            ensure_nodata_soa(message, &ctx.query.name, DEFAULT_BLOCK_TTL);
        }
    }
}

/// RRSIG / NSEC / NSEC3 are DNSSEC proof material, not answer data.
fn is_dnssec_proof(r: &Record) -> bool {
    matches!(
        r.rtype(),
        RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
    )
}

/// Drops RRSIGs whose `type_covered` equals `covered` (RFC 4035 §3.1.1 / §5:
/// a signature must cover the RRset as transmitted).
fn strip_rrsigs_covering(rrs: &mut Vec<Record>, covered: RecordType) {
    rrs.retain(|r| {
        !matches!(
            &r.rdata,
            RData::RRSIG { type_covered, .. } if *type_covered == covered
        )
    });
}

fn strip_address_rrs(rrs: &mut Vec<Record>) -> u32 {
    let mut touched_a = false;
    let mut touched_aaaa = false;
    let before = rrs.len();
    rrs.retain(|rec| match &rec.rdata {
        RData::A(v4) if is_private_for_rebind((*v4).into()) => {
            touched_a = true;
            false
        }
        RData::AAAA(v6) if is_private_for_rebind((*v6).into()) => {
            touched_aaaa = true;
            false
        }
        _ => true,
    });
    let count = u32::try_from(before.saturating_sub(rrs.len())).unwrap_or(u32::MAX);
    // RRset changed → covering RRSIGs are stale (RFC 4035 §3.1.1 / §5).
    if touched_a {
        strip_rrsigs_covering(rrs, RecordType::A);
    }
    if touched_aaaa {
        strip_rrsigs_covering(rrs, RecordType::AAAA);
    }
    count
}

fn strip_svcb_rrs(rrs: &mut Vec<Record>) -> u32 {
    let mut total = 0u32;
    let mut touched_https = false;
    let mut touched_svcb = false;
    let mut i = 0;
    while i < rrs.len() {
        let (is_https, data) = match &rrs[i].rdata {
            RData::HTTPS(d) => (true, d.clone()),
            RData::SVCB(d) => (false, d.clone()),
            _ => {
                i += 1;
                continue;
            }
        };
        match strip_svcb_hints(&data) {
            HintRewrite::Unchanged | HintRewrite::Malformed => {
                i += 1;
            }
            HintRewrite::Changed {
                data: new_data,
                stripped,
            } => {
                total = total.saturating_add(stripped);
                rrs[i].rdata = if is_https {
                    touched_https = true;
                    RData::HTTPS(new_data)
                } else {
                    touched_svcb = true;
                    RData::SVCB(new_data)
                };
                i += 1;
            }
            HintRewrite::DropRecord { stripped } => {
                // RFC 9460 §8: a client MUST ignore an RRSet if a key listed in
                // `mandatory` is missing. Dropping a mandatory hint would leave
                // an invalid record — remove the whole RR instead.
                total = total.saturating_add(stripped);
                if is_https {
                    touched_https = true;
                } else {
                    touched_svcb = true;
                }
                rrs.remove(i);
            }
        }
    }
    if touched_https {
        strip_rrsigs_covering(rrs, RecordType::HTTPS);
    }
    if touched_svcb {
        strip_rrsigs_covering(rrs, RecordType::SVCB);
    }
    total
}

/// Outcome of scrubbing `ipv4hint` / `ipv6hint` on one SVCB/HTTPS RDATA.
///
/// Hint values are opaque octets per RFC 9460 §7.3: key 4 is `n × 4` bytes of
/// IPv4 addresses; key 6 is `n × 16` bytes of IPv6. A length of zero or a
/// length that is not a multiple of the address size is malformed — the whole
/// record is left unchanged so we never drop data we cannot parse.
#[derive(Debug, PartialEq, Eq)]
enum HintRewrite {
    Unchanged,
    Changed {
        data: SvcbData,
        stripped: u32,
    },
    /// Drop the entire HTTPS/SVCB RR (mandatory listed a hint we emptied).
    DropRecord {
        stripped: u32,
    },
    Malformed,
}

/// Scrubs private addresses from HTTPS/SVCB hint parameters (RFC 9460 §7.3).
///
/// Empty hints after filtering are dropped; remaining params keep strictly
/// increasing key order. Non-hint params are copied unchanged.
fn strip_svcb_hints(data: &SvcbData) -> HintRewrite {
    let mandatory_keys = match parse_mandatory_keys(data) {
        Ok(keys) => keys,
        Err(()) => return HintRewrite::Malformed,
    };

    let mut new_params: Vec<(u16, Box<[u8]>)> = Vec::with_capacity(data.params.len());
    let mut stripped = 0u32;
    let mut changed = false;
    let mut dropped_keys: Vec<u16> = Vec::new();

    for (key, value) in &data.params {
        match *key {
            IPV4HINT => match filter_hint(value, 4, parse_v4) {
                Ok((kept, removed)) => {
                    stripped = stripped.saturating_add(removed);
                    apply_hint_result(
                        *key,
                        value,
                        kept,
                        removed,
                        &mut new_params,
                        &mut changed,
                        &mut dropped_keys,
                    );
                }
                Err(()) => return HintRewrite::Malformed,
            },
            IPV6HINT => match filter_hint(value, 16, parse_v6) {
                Ok((kept, removed)) => {
                    stripped = stripped.saturating_add(removed);
                    apply_hint_result(
                        *key,
                        value,
                        kept,
                        removed,
                        &mut new_params,
                        &mut changed,
                        &mut dropped_keys,
                    );
                }
                Err(()) => return HintRewrite::Malformed,
            },
            _ => new_params.push((*key, value.clone())),
        }
    }

    if !changed {
        return HintRewrite::Unchanged;
    }

    // RFC 9460 §8: if `mandatory` lists a key we just removed, clients must
    // ignore the RRSet — drop the whole record rather than leave it invalid.
    if dropped_keys
        .iter()
        .any(|k| mandatory_keys.binary_search(k).is_ok())
    {
        // Count every address that lived in the original hint params (they all
        // disappear with the RR).
        let all_addrs = count_hint_addresses(data);
        return HintRewrite::DropRecord {
            stripped: all_addrs.max(stripped),
        };
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

fn apply_hint_result(
    key: u16,
    original: &[u8],
    kept: Box<[u8]>,
    removed: u32,
    new_params: &mut Vec<(u16, Box<[u8]>)>,
    changed: &mut bool,
    dropped_keys: &mut Vec<u16>,
) {
    if removed > 0 || kept.as_ref() != original {
        *changed = true;
    }
    if kept.is_empty() {
        *changed = true;
        dropped_keys.push(key);
    } else {
        new_params.push((key, kept));
    }
}

fn parse_v4(chunk: &[u8]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
}

fn parse_v6(chunk: &[u8]) -> IpAddr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(chunk);
    IpAddr::V6(Ipv6Addr::from(octets))
}

/// Filters a hint value. Empty (`len == 0`) or non-multiple lengths are
/// malformed. Returns `(kept_bytes, removed_count)`.
fn filter_hint(
    value: &[u8],
    addr_len: usize,
    parse: fn(&[u8]) -> IpAddr,
) -> Result<(Box<[u8]>, u32), ()> {
    if value.is_empty() || !value.len().is_multiple_of(addr_len) {
        return Err(());
    }
    let mut kept = Vec::with_capacity(value.len());
    let mut removed = 0u32;
    for chunk in value.chunks_exact(addr_len) {
        if is_private_for_rebind(parse(chunk)) {
            removed = removed.saturating_add(1);
        } else {
            kept.extend_from_slice(chunk);
        }
    }
    Ok((kept.into(), removed))
}

/// Parses `mandatory` (key 0): a sequence of 2-octet keys in increasing order
/// (RFC 9460 §7.1). Missing key 0 → empty list. Malformed length / order → Err.
fn parse_mandatory_keys(data: &SvcbData) -> Result<Vec<u16>, ()> {
    let Some((_, value)) = data.params.iter().find(|(k, _)| *k == MANDATORY) else {
        return Ok(Vec::new());
    };
    if value.len() % 2 != 0 {
        return Err(());
    }
    let mut keys = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_chunks::<2>().0 {
        let key = u16::from_be_bytes([chunk[0], chunk[1]]);
        if let Some(&prev) = keys.last()
            && key <= prev
        {
            return Err(());
        }
        keys.push(key);
    }
    Ok(keys)
}

fn count_hint_addresses(data: &SvcbData) -> u32 {
    let mut n = 0u32;
    for (key, value) in &data.params {
        let size = match *key {
            IPV4HINT => 4usize,
            IPV6HINT => 16usize,
            _ => continue,
        };
        if value.is_empty() || value.len() % size != 0 {
            continue;
        }
        n = n.saturating_add(u32::try_from(value.len() / size).unwrap_or(u32::MAX));
    }
    n
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod unit {
    use super::*;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use dnscraft_filtering::{
        FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ManualClock, SetId,
        SnapshotBuilder,
    };
    use dnscraft_proto::{Class, Header, RecordType};
    use dnscraft_resolver::dnssec::TrustAnchors;
    use dnscraft_resolver::{Query, Resolver, ResolverConfig};
    use dnscraft_testkit::Hierarchy;

    use crate::config::{
        ClientFlags, DnsProtocol, PolicyConfig, ProfileConfig, RequestContext, SafeSearchConfig,
        ViewConfig,
    };
    use crate::decision::DecisionStep;
    use crate::directory::NoClients;
    use crate::ids::{ListenerId, ProfileId, ViewId};
    use crate::pipeline::{Draft, StepCtx};
    use crate::select::SelectionCause;
    use crate::snapshot::PolicySnapshot;

    #[derive(Debug, Default)]
    struct EmptyBodies;
    impl ListBodies for EmptyBodies {
        fn body(&self, _id: &ListId) -> Option<Arc<str>> {
            None
        }
    }

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
    fn malformed_ipv6hint_length_leaves_unchanged() {
        // 20 bytes is a multiple of 4 but not of 16 — must not truncate silently.
        let mut bytes = vec![0u8; 20];
        bytes[0] = 0xfd;
        let data = SvcbData {
            priority: 1,
            target: Name::from_ascii(".").unwrap(),
            params: vec![(IPV6HINT, bytes.into())],
        };
        assert_eq!(strip_svcb_hints(&data), HintRewrite::Malformed);
    }

    #[test]
    fn empty_hint_value_is_malformed() {
        let data = SvcbData {
            priority: 1,
            target: Name::from_ascii(".").unwrap(),
            params: vec![(IPV4HINT, Box::new([])), (1, b"\x02h2".to_vec().into())],
        };
        assert_eq!(strip_svcb_hints(&data), HintRewrite::Malformed);
    }

    #[test]
    fn mandatory_lists_dropped_hint_drops_whole_record() {
        // mandatory = [4]; ipv4hint is all-private → emptying key 4 would
        // violate RFC 9460 §8 → DropRecord.
        let data = SvcbData {
            priority: 1,
            target: Name::from_ascii(".").unwrap(),
            params: vec![
                (MANDATORY, vec![0, 4].into()),
                (IPV4HINT, ipv4_bytes(&[Ipv4Addr::new(10, 0, 0, 1)])),
            ],
        };
        match strip_svcb_hints(&data) {
            HintRewrite::DropRecord { stripped } => assert_eq!(stripped, 1),
            other => panic!("expected DropRecord, got {other:?}"),
        }
    }

    /// Kills the mutant that replaces `rrs.remove(i)` with `i += 1` in the
    /// `DropRecord` arm of [`strip_svcb_rrs`] (only `strip_svcb_hints` was
    /// unit-tested before). Also asserts the covering RRSIG is dropped.
    #[test]
    fn strip_svcb_rrs_drop_record_removes_https_and_rrsig() {
        let owner = Name::from_ascii("svc.example.test.").unwrap();
        let data = SvcbData {
            priority: 1,
            target: Name::from_ascii(".").unwrap(),
            params: vec![
                (MANDATORY, vec![0, 4].into()),
                (IPV4HINT, ipv4_bytes(&[Ipv4Addr::new(10, 0, 0, 1)])),
            ],
        };
        let mut rrs = vec![
            Record::new(owner.clone(), Class::IN, 60, RData::HTTPS(data)),
            Record::new(
                owner,
                Class::IN,
                60,
                RData::RRSIG {
                    type_covered: RecordType::HTTPS,
                    algorithm: 13,
                    labels: 3,
                    original_ttl: 60,
                    expiration: 0,
                    inception: 0,
                    key_tag: 0,
                    signer_name: Name::from_ascii("example.test.").unwrap(),
                    signature: Box::new([0u8; 8]),
                },
            ),
        ];

        let stripped = strip_svcb_rrs(&mut rrs);
        assert_eq!(stripped, 1, "one private hint address counted");
        assert!(
            rrs.is_empty(),
            "HTTPS DropRecord + RRSIG(HTTPS) must both be gone: {rrs:?}"
        );
    }

    async fn harness() -> (
        PolicySnapshot,
        Arc<FilterEngine>,
        Arc<Resolver>,
        Arc<ManualClock>,
    ) {
        let h = Hierarchy::start().await.unwrap();
        let overrides = h
            .nameserver_addrs()
            .iter()
            .map(|(n, a)| (Name::from_ascii(&n.to_string()).unwrap(), *a))
            .collect::<HashMap<_, _>>();
        let resolver = Arc::new(
            Resolver::new(ResolverConfig {
                root_hints: h.root_hints(),
                query_timeout: Duration::from_millis(300),
                nameserver_addr_overrides: overrides,
                trust_anchors: TrustAnchors::empty(),
                prefetch: false,
                ..ResolverConfig::default()
            })
            .await
            .unwrap(),
        );
        let set = FilterSetConfig::new(SetId::new("default").unwrap(), "default");
        let filter = Arc::new(FilterEngine::from_snapshot(
            SnapshotBuilder::new(Arc::new(EmptyBodies) as Arc<dyn ListBodies>)
                .build(&FilterConfig {
                    lists: Vec::new(),
                    sets: vec![set],
                    ..FilterConfig::default()
                })
                .unwrap(),
        ));
        let known_sets: Vec<_> = filter.snapshot().set_ids().cloned().collect();
        let cfg = PolicyConfig {
            default_rebind: true,
            ptr_prefixes: Vec::new(),
            local_nxdomain_suffixes: Vec::new(),
            rebind_check_forward_zones: Vec::new(),
            views: vec![ViewConfig {
                id: ViewId::new("default").unwrap(),
                is_default: true,
                subnets: Vec::new(),
                nodes: Vec::new(),
                profile: ProfileId::new("default").unwrap(),
            }],
            client_ids: Vec::new(),
            records: Vec::new(),
            profiles: vec![ProfileConfig {
                id: ProfileId::new("default").unwrap(),
                filter_set: SetId::new("default").unwrap(),
                suppress_aaaa: false,
                firefox_canary: false,
                icloud_private_relay: false,
                rebind: Some(true),
                rebind_exceptions: Vec::new(),
                forward_zones: None,
                safesearch: SafeSearchConfig::default(),
                schedules: Vec::new(),
            }],
        };
        let snap = PolicySnapshot::build(cfg, &known_sets, &[]).unwrap();
        let clock = Arc::new(ManualClock::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
        ));
        (snap, filter, resolver, clock)
    }

    /// The recursive/forward resolver clears `additionals` before policy sees
    /// the answer; this test therefore calls [`run`] with a constructed
    /// message so removing the additionals strip line fails the assertion.
    #[tokio::test]
    async fn run_strips_private_additional_and_clears_ad() {
        let (snap, filter, resolver, clock) = harness().await;
        let clients = NoClients;
        let filter_set = SetId::new("default").unwrap();
        let step = StepCtx {
            snapshot: &snap,
            clients: &clients,
            resolver: resolver.as_ref(),
            forward_zones_allow: None,
            filter: filter.as_ref(),
            filter_set: &filter_set,
            clock: clock.as_ref(),
            paused: false,
        };
        let ctx = RequestContext {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            protocol: DnsProtocol::Udp53,
            listener_id: ListenerId::new("udp-53").unwrap(),
            node_id: None,
            client_id: None,
            query: Query {
                name: Name::from_ascii("www.example.test.").unwrap(),
                qtype: RecordType::MX,
                qclass: Class::IN,
            },
            flags: ClientFlags::default(),
            test_query: false,
        };
        let selection = snap.select(&ctx);
        assert_eq!(selection.matched_by, SelectionCause::Default);
        let mut draft = Draft::new(selection, filter_set.clone());
        let mut message = Message {
            header: Header {
                ad: true,
                ..Header::default()
            },
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

        run(&ctx, step, &mut draft, &mut message, None);

        assert!(
            draft
                .steps
                .contains(&DecisionStep::RebindStripped { count: 1 }),
            "run() must strip additional private A: {:?}",
            draft.steps
        );
        assert!(!message.header.ad);
        assert_eq!(message.additionals.len(), 1);
        assert_eq!(
            message.additionals[0].rdata,
            RData::A(Ipv4Addr::new(192, 0, 2, 53))
        );
        assert_eq!(message.answers.len(), 1);
    }
}
