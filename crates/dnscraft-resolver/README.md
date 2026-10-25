# dnscraft-resolver

Recursive, DNSSEC-validating DNS resolver with an in-memory cache.

This crate walks the delegation chain from the root servers itself — no upstream
resolver, no filter lists, no listeners. You hand it a question; it returns an
answer. Policy, clients, and DoT/DoH sit in other modules.

Formal requirements live in [`SPEC-resolver.md`](../../SPEC-resolver.md).
This README is the practical overview: what works today, how to try it, and how
to call the API.

## Status

Usable for real-internet lookups and as a library dependency while the rest of
DNScraft is built.

| Area | State |
|------|--------|
| Iterative recursion from root hints | done |
| QNAME minimisation (RFC 9156) | done (on by default) |
| DNSSEC validation (NSEC / NSEC3) | done |
| Cache, prefetch, serve-stale | done |
| In-flight query coalescing | done |
| Local private reverse zones (RFC 6303) | done |
| Forward zones | done |
| Persistent cache across restarts | out of scope (by design) |

## Quick try

Needs outbound UDP/TCP 53 and a working network:

```bash
cargo run -p dnscraft-resolver --example query -- example.com A
```

Optional second argument is the record type (`AAAA`, `MX`, `TXT`, …). Set
`DNSCRAFT_TRACE=1` for debug logs on stderr.

Expected for a signed zone: `dnssec: Secure`, `ad: true`. A deliberately broken
zone such as `dnssec-failed.org` should yield `SERVFAIL` with an Extended DNS
Error.

## Library usage

```rust
use dnscraft_proto::{Class, Name, RecordType};
use dnscraft_resolver::{Query, RequestFlags, Resolver, ResolverConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resolver = Resolver::new(ResolverConfig::default()).await?;

    let query = Query {
        name: Name::from_ascii("example.com.")?,
        qtype: RecordType::A,
        qclass: Class::IN,
    };

    let answer = resolver.resolve(&query, RequestFlags::default()).await?;
    println!("{:?} from {:?}", answer.dnssec, answer.source);
    for rr in &answer.message.answers {
        println!("{rr:?}");
    }
    Ok(())
}
```

`Resolver::new` primes the root server set (RFC 8109) and primes again every
`root_reprime_interval` (default 24 h, checked when a resolution starts). With
trust anchors configured the priming answer must validate against the root
DNSKEY; a forged or unsigned reply is ignored. If priming fails, the built-in
IANA hints are kept — check `resolver.priming_status()` if you care.

### Request flags

| Flag | Effect |
|------|--------|
| `checking_disabled` (CD) | Skip DNSSEC validation; answer is not cached |
| `dnssec_ok` (DO) | Keep RRSIG / NSEC / NSEC3 in the message; otherwise they are stripped |

### Answer fields

- `message` — final DNS message (`RA` set, `AA` clear; `AD` only when we
  validated Secure ourselves)
- `dnssec` — `Secure` / `Insecure` / `Bogus` / `Indeterminate`
- `source` — `Cache`, `Recursion`, or `Stale`
- `ede` — Extended DNS Error when useful (e.g. DNSSEC failure)

Bogus answers are rewritten to `SERVFAIL` and are never stored in the cache.

### Cache control

```rust
use dnscraft_resolver::FlushScope;

resolver.flush(FlushScope::All);
resolver.flush(FlushScope::Domain(name)); // name and everything below it
let s = resolver.stats();
// s.cache_hits, s.dnssec_secure, s.resolve_latency_ns, …
```

## Behaviour in short

**Recursion.** Starts at the root, follows referrals, resolves glueless name
servers when needed. Outgoing traffic uses UDP with TCP fallback on the TC bit,
EDNS(0) with a 1232-byte buffer, randomised ports/ids, and RTT-based server
selection (IPv4/IPv6 with cool-down after unreachable).

**Answer hygiene.** The message returned to the client is rebuilt from what
the resolver accepted, whether or not the zone is signed: the RRset for the
question, the CNAME/DNAME links it followed (each from the response that was
authoritative for it; a server-made CNAME below a DNAME is replaced by the
resolver's own), and for negative answers the SOA and NSEC/NSEC3 proof. Records
for other names and the whole additional section are dropped, so a hostile
authority cannot plant `www.bank.com` in an answer for `x.evil.com`. Forwarded
answers get the same treatment. Name server addresses learned from the network
are filtered (loopback, link-local, multicast, reserved, IPv4-mapped; private
ranges unless `allow_private_nameservers`) and capped at 16 per referral.
Documentation ranges are not filtered. Root hints and forward targets are
operator-configured and never filtered.

**DNSSEC.** Validates against the built-in IANA root trust anchors (KSK-2017 and
KSK-2024). Negative trust anchors can be configured per domain for broken zones.
Empty trust anchors turn validation off (`Indeterminate` everywhere). Validated
TTLs are capped by the RRSIG original TTL and by the time left until the
signature expires, and cache entries never outlive the signatures
(RFC 4035 section 5.3.3). The rcode is not signed: NXDOMAIN together with a
validated RRset for the question is `Bogus` (`dnssec.rcode_mismatch`, EDE 6) in
a secure zone and counts as a broken server elsewhere. The CPU budget for
signature checks and NSEC3 hashes is per resolution, forwarded validation
included.

**Cache.** Positive and negative caching (RFC 2308), size-bounded (default 64
MiB), TTL clamp, optional prefetch of popular near-expiry entries, and
serve-stale (RFC 8767) for up to one day when authoritative servers are
unreachable. A stale answer carries a 30 s TTL (RFC 8767 section 5.11), a clear
AD bit, and is reported as `Indeterminate`, because signature validity is not
re-checked. Memory only — cold start after every process restart. A flush wins
over resolutions already running: their results are not stored.

**Local zones.** RFC 6303 private reverse zones are answered locally so those
PTRs never hit the public internet. A forward zone the query is allowed to use
opts out only for names it covers (equal to the zone or below it). A forward
zone inside a local zone, such as `corp.10.in-addr.arpa.`, leaves the rest of
`10.in-addr.arpa.` local. A zone omitted from the query's allow-list does not
opt out.

**Forwarding.** A target that times out or answers SERVFAIL, REFUSED, FORMERR or
NOTIMP is skipped and the next one is tried. Loop protection compares
`RequestFlags::client` with the targets of the zone the query is allowed to
use, so listeners must pass the real peer address; a loop through NAT is
bounded by `query_timeout` instead. `RequestFlags::forward_zones` is `None`
when every configured zone may forward, and `Some(ids)` when only those ids
may. A name with no allowed covering zone is resolved from the root. The cache
and in-flight keys include that route, so a forwarded answer and a recursive
answer for the same name stay separate. `Answer.forward_zone` reports the zone
that produced the answer, including a later cache hit.

**Load.** At most `max_concurrent_resolutions` upstream resolutions run at once.
Cache hits never wait. A miss that gets no slot within `query_timeout` fails
with `resolver.overloaded`. Prefetch only runs when a slot is free and backs off
for 30 s after a failure.

**Not in this crate.** Filters, split-horizon, ACLs, listeners (Do53/DoT/DoH/DoQ)
and client query logs. A profile chooses the allow-list and passes it as
`RequestFlags::forward_zones`; selecting the profile belongs to `policy`.

## Configuration

`ResolverConfig::default()` is a sensible starting point. Important knobs:

| Field | Default | Notes |
|-------|---------|--------|
| `root_hints` | IANA named.root | Overridable for tests |
| `query_timeout` | 1.5 s | Per server exchange |
| `max_referral_depth` | `16` | Referrals followed for one lookup |
| `qname_minimisation` | `true` | RFC 9156 |
| `trust_anchors` | IANA root KSKs | Empty → no validation |
| `negative_trust_anchors` | `[]` | Escape hatch for broken zones |
| `cache_size_mb` | `64` | Cache limit in MiB; `0` stores nothing. Ignored when `cache_capacity_bytes` is set |
| `cache_capacity_bytes` | `None` | Exact cache limit in bytes. When `Some`, it replaces `cache_size_mb` entirely (see note below) |
| `ttl_min` / `ttl_max` | `0` / `86400` | Clamp before store |
| `serve_stale` | 1 day | `Duration::ZERO` disables |
| `prefetch` | `true` | Background refresh |
| `max_cname_chain` | `16` | Loop / amplification guard |
| `max_queries_per_resolve` | `64` | Budget per question |
| `max_nested_depth` | `4` | Nesting of name server address lookups |
| `max_concurrent_resolutions` | `1024` | Cap on parallel upstream resolutions |
| `resolve_deadline` | 10 s | Upper bound on one upstream resolution; expiry is `resolver.unreachable` (serve-stale may apply) |
| `root_reprime_interval` | 24 h | Priming again; `Duration::ZERO` primes once |
| `allow_private_nameservers` | `false` | Accept RFC 1918 / CGNAT / ULA name server addresses from delegations |
| `ipv6_cooldown` | 60 s | IPv6 name servers are deprioritised this long after a network-unreachable send error |
| `forward_zones` | `[]` | Zones answered by stub forwarders instead of iteration; see [Forward zones](#forward-zones) |
| `clock` | `SystemClock` | Time source. Test hook (`ManualClock` in tests) |
| `nameserver_addr_overrides` | `{}` | Test hook: name server host to address, see below |

`clock`, `cache_capacity_bytes` and `nameserver_addr_overrides` are test hooks, not production settings.

### Forward zones

A `ForwardZone` sends queries for `zone` and every name below it to `targets`
with the recursion-desired bit set, instead of walking the delegation chain. A
name goes to the most specific zone that covers it and that the query is
allowed to use.

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `id` | `ForwardZoneId` | none, required | Stable id, `[a-z0-9-]{1,64}`. Unique among `forward_zones`. Profiles name this id |
| `zone` | `Name` | none, required | Apex of the forwarded zone |
| `targets` | `Vec<SocketAddr>` | none, required | Recursive servers, tried in smoothed-RTT order |
| `validate` | `bool` | `false` | `false` is an implicit negative trust anchor: status `Insecure`, no AD bit, records not checked. `true` validates against a trust anchor for `zone`, with DNSKEYs fetched from `targets` |

Per query, `RequestFlags::forward_zones` (`Option<Arc<[ForwardZoneId]>>`)
selects which configured zones may forward:

| Value | Effect |
|-------|--------|
| `None` (default) | Every configured zone may forward |
| `Some(ids)` | Only those ids may forward. A name under a zone that is not listed is resolved from the root, and that zone does not suppress a local answer |

Duplicate ids fail `Resolver::new` with `resolver.forward_zone.duplicate_id`.
An id outside `[a-z0-9-]{1,64}` fails `ForwardZoneId::new` with
`resolver.forward_zone.empty`, `resolver.forward_zone.too_long` or
`resolver.forward_zone.invalid_char`.

```rust
use std::sync::Arc;

use dnscraft_proto::Name;
use dnscraft_resolver::{ForwardZone, ForwardZoneId, RequestFlags, ResolverConfig};

fn forwarding_config() -> Result<ResolverConfig, Box<dyn std::error::Error>> {
    Ok(ResolverConfig {
        forward_zones: vec![ForwardZone {
            id: ForwardZoneId::new("corp")?,
            zone: Name::from_ascii("corp.example.")?,
            targets: vec!["192.0.2.53:53".parse()?],
            validate: false,
        }],
        ..ResolverConfig::default()
    })
}

fn only_corp() -> Result<RequestFlags, Box<dyn std::error::Error>> {
    Ok(RequestFlags {
        forward_zones: Some(Arc::from(vec![ForwardZoneId::new("corp")?])),
        ..RequestFlags::default()
    })
}
```

Loop protection for forwarding is described under **Forwarding** in
[Behaviour in short](#behaviour-in-short).

The eventual DNScraft TOML shape is sketched in the [spec](../../SPEC-resolver.md#configuration-excerpt-toml);
this crate still takes a Rust `ResolverConfig` directly.

## Errors

Construction failures (`ResolverError`) and resolution failures (`ResolveError`)
expose a stable `code()` string for APIs and i18n. Human-readable text on the
error is for logs, not for end users.

| Error | Code |
|-------|------|
| `ResolverError::NoRootHints` | `resolver.no_root_hints` |
| `ResolverError::InvalidConfig` | `resolver.invalid_config` |
| `ResolverError::DuplicateForwardZone` | `resolver.forward_zone.duplicate_id` |
| `ForwardZoneIdError::Empty` | `resolver.forward_zone.empty` |
| `ForwardZoneIdError::TooLong` | `resolver.forward_zone.too_long` |
| `ForwardZoneIdError::InvalidChar` | `resolver.forward_zone.invalid_char` |
| `ResolveError::Unreachable` | `resolver.unreachable` |
| `ResolveError::QueryBudgetExceeded` | `resolver.query_budget` |
| `ResolveError::ReferralDepthExceeded` | `resolver.referral_depth` |
| `ResolveError::CnameLimitExceeded` | `resolver.cname_limit` |
| `ResolveError::CnameLoop` | `resolver.cname_limit` |
| `ResolveError::ForwardLoop` | `resolver.forward_loop` |
| `ResolveError::Overloaded` | `resolver.overloaded` |
| `ResolveError::Encode` | `resolver.encode` |

DNSSEC failures are not `ResolveError`s: they return an `Answer` with
`dnssec: Bogus`, `SERVFAIL`, and an Extended DNS Error.

## DNSSEC failure codes

Every DNSSEC outcome carries a stable, locale-neutral code string. On a Bogus
answer the code is the EXTRA-TEXT of the Extended DNS Error (RFC 8914) and the
INFO-CODE is given below. These strings are stable API: they are meant to serve
as the i18n keys for a future web UI, so do not rename them.

Only Bogus answers (`SERVFAIL`) and one Insecure case (`dnssec.nsec3_iterations`)
carry an EDE on an answer. The `dnssec.insecure_*` codes exist on the API but
are not emitted on answers, and `dnssec.bad_anchor` is an error from building
trust anchors, not an answer status.

| Code | EDE INFO-CODE | On | Meaning |
|------|---------------|----|---------|
| `dnssec.bad_signature` | 6 | Bogus | RRSIG does not verify against the DNSKEY |
| `dnssec.signature_expired` | 7 | Bogus | RRSIG expiration is in the past |
| `dnssec.signature_not_yet_valid` | 8 | Bogus | RRSIG inception is more than 300 s in the future |
| `dnssec.key_tag_mismatch` | 6 | Bogus | RRSIG key tag differs from the DNSKEY's |
| `dnssec.algorithm_mismatch` | 6 | Bogus | RRSIG and DNSKEY algorithms differ |
| `dnssec.no_matching_key` | 9 | Bogus | No DNSKEY matches the RRSIG's key tag and algorithm |
| `dnssec.unsupported_algorithm` | 1 | Bogus | Signature algorithm rejected by policy or not supported by `ring` |
| `dnssec.labels_mismatch` | 6 | Bogus | RRSIG labels field exceeds the owner's label count |
| `dnssec.signer_not_zone` | 6 | Bogus | Signer is not the DNSKEY owner or an ancestor of the owner |
| `dnssec.key_not_zone_key` | 6 | Bogus | DNSKEY lacks the zone flag, has protocol != 3, or is revoked |
| `dnssec.type_covered_mismatch` | 6 | Bogus | RRSIG covers a different type than the RRset |
| `dnssec.rrset_mismatch` | 6 | Bogus | RRset is empty or its records disagree on owner, class or type |
| `dnssec.no_signatures` | 10 | Bogus | No RRSIG covers the RRset |
| `dnssec.malformed_key` | 6 | Bogus | Key material or record contents cannot be interpreted |
| `dnssec.validation_budget` | 6 | Bogus | Per-resolution signature budget spent (fail closed) |
| `dnssec.no_trust_anchor` | 6 | Bogus | Validated forward zone has no trust anchor for it |
| `dnssec.no_dnskeys` | 9 | Bogus | DNSKEY RRset of a zone contains no keys for it |
| `dnssec.ds_no_match` | 9 | Bogus | No DNSKEY matches the DS RRset or trust anchor |
| `dnssec.dnskey_unavailable` | 9 | Bogus | No server delivered the DNSKEY RRset of a zone that has a DS |
| `dnssec.no_ds_proof` | 12 | Bogus | Referral without DS has no valid proof that none exists |
| `dnssec.no_denial_proof` | 12 | Bogus | Negative answer or wildcard expansion without NSEC/NSEC3 proof |
| `dnssec.bad_denial_proof` | 6 | Bogus | NSEC/NSEC3 records do not prove what they must |
| `dnssec.nsec3_budget` | 6 | Bogus | Per-resolution NSEC3 hash budget spent (fail closed) |
| `dnssec.rcode_mismatch` | 6 | Bogus | NXDOMAIN although a validated RRset exists for the question |
| `dnssec.nsec3_iterations` | 27 | Insecure | NSEC3 iteration count above the limit; answer is `Insecure`, not `SERVFAIL` |
| `dnssec.insecure_unsupported_algorithm` | 1 | API only | DS uses an algorithm this resolver does not support |
| `dnssec.insecure_unsupported_digest` | 2 | API only | DS uses a digest type this resolver does not support |
| `dnssec.bad_anchor` | none | Error | A record given as trust anchor is neither DS nor DNSKEY |

## Hardening limits

Fixed safety limits. Each value is a constant in the source named in the last
column. The configurable limits are in the [Configuration](#configuration) table.

| Limit | Value | Purpose | Source |
|-------|-------|---------|--------|
| Signature verifications per resolution | 64 | Caps CPU spent on key and signature floods; spent budget makes the answer Bogus | `MAX_VERIFICATIONS_PER_RESOLVE` in `src/dnssec/budget.rs` |
| RRSIGs tried per RRset | 8 | Bounds signature attempts on one RRset | `MAX_SIGS_PER_RRSET` in `src/dnssec/budget.rs` |
| Keys tried per RRSIG (same key tag and algorithm) | 4 | Bounds key-tag collision attempts | `MAX_KEYS_PER_TAG` in `src/dnssec/budget.rs` |
| NSEC3 hashes per resolution | 128 | Caps closest-encloser walks for long names | `MAX_NSEC3_HASHES_PER_RESOLVE` in `src/dnssec/budget.rs` |
| NSEC3 max iterations | 100 | Above this the zone is treated as Insecure (EDE 27) | `NSEC3_MAX_ITERATIONS` in `src/dnssec/denial.rs` |
| RRSIG inception skew | 300 s | Tolerated clock skew for a future inception; expiration is checked strictly | `SIG_INCEPTION_SKEW` in `src/dnssec/verify.rs` |
| DNSKEY servers asked per zone | 3 | Bounds DNSKEY fetches for one zone | `MAX_DNSKEY_SERVERS` in `src/dnssec/walk.rs` |
| Hidden-cut nesting | 8 | Bounds intermediate signer-zone lookups | `MAX_CUT_DEPTH` in `src/dnssec/walk.rs` |
| Hidden-cut DS probes per resolution | 8 | Bounds DS probes for hidden cuts | `MAX_PROBES` in `src/dnssec/walk.rs` |
| Addresses per referral | 16 | Glue and looked-up addresses together | `MAX_ADDRS_PER_REFERRAL` in `src/iterate.rs` |
| Glueless name server hosts per zone cut | 4 | Bounds nested name server lookups | `MAX_GLUELESS_PER_CUT` in `src/iterate.rs` |
| QNAME minimisation: queries per zone | 10 | RFC 9156 section 2.3, final query included | `MAX_MINIMISE_COUNT` in `src/iterate.rs` |
| QNAME minimisation: single-label steps | 4 | RFC 9156 section 2.3, then several labels per step | `MINIMISE_ONE_LAB` in `src/iterate.rs` |
| Tracked servers (smoothed RTT) | 4096 | Least recently used address is forgotten past this | `MAX_TRACKED_SERVERS` in `src/server_selection.rs` |
| Smoothed RTT cap | 8000 ms | Upper bound of any sample | `SRTT_CAP_MS` in `src/server_selection.rs` |
| Stale answer TTL | 30 s | TTL written into served-stale answers (RFC 8767) | `STALE_ANSWER_TTL` in `src/cache.rs` |
| Cache bookkeeping per entry | 256 bytes | Added to each entry's size for the cache budget | `ENTRY_OVERHEAD` in `src/cache.rs` |
| Prefetch popularity | 3 hits | Hits needed before a near-expiry entry is refreshed | `POPULAR_HITS` in `src/prefetch.rs` |
| Prefetch window floor | 2 s | Window is the larger of TTL / 10 and this | `MIN_WINDOW` in `src/prefetch.rs` |
| Prefetch backoff after failure | 30 s | Wait before the same key is prefetched again | `PREFETCH_BACKOFF` in `src/lib.rs` |
| Root re-priming retry after failure | 300 s | Shorter of this and `root_reprime_interval` | `REPRIME_RETRY` in `src/lib.rs` |
| CNAME chain scrubbed in forwarded answers | 32 | Bounds the chain walk when rebuilding a forwarded answer | `MAX_SCRUB_CHAIN` in `src/forward.rs` |

## Design choice

Recursion and DNSSEC logic are written in-house on `dnscraft-proto`; crypto comes
from `ring`. See [ADR-0001](../../docs/adr/0001-recursion-engine.md).

## Tests

```bash
cargo test -p dnscraft-resolver
cargo test -p dnscraft-testkit   # signed fake hierarchy used by resolver tests
cargo bench -p dnscraft-resolver --bench cache
```

Integration tests drive a local authoritative hierarchy from `dnscraft-testkit`
(no internet required). The `query` example is the manual acceptance check
against the real root. The cache-hit benchmark targets p50 under 1 ms.
