# Spec: resolver

> Module id `resolver` · crate `crates/dnscraft-resolver` · depends on: nothing
> Project-wide decisions (stack, commands, style, boundaries, i18n): [SPEC.md](SPEC.md)

## Objective

A recursive, validating resolver: it answers a DNS question by walking the delegation
chain itself starting at the root servers, validates DNSSEC, and caches results.
It knows nothing about filters, clients, or listeners; it takes a `Query` and returns an `Answer`.

## Requirements

### Recursion
- Starts from built-in root hints (IANA), refreshed via a priming query at startup (RFC 8109).
- QNAME minimisation (RFC 9156).
- Outgoing over IPv4 and IPv6; prefers the faster address family and falls back to the other.
- Nameserver selection by smoothed measured RTT; timeouts retry against other servers.
- EDNS(0) with a 1232-byte buffer; TCP fallback when the TC bit is set.
- Randomized source ports and query ids; responses are checked against question, id, and server.
- Loop and amplification guards: limits on CNAME chains (≤ 16), delegation depth, and
  outgoing queries per incoming question.
- Identical in-flight queries are coalesced (in-flight dedup).
- EDNS Client Subnet is never sent; incoming ECS options from clients are stripped.

### DNSSEC
- Validation per RFC 4033–4035 including NSEC and NSEC3 (RFC 5155).
- Built-in root trust anchors (KSK-2017 and KSK-2024); rollover tracking per RFC 5011.
- Result per answer: `Secure`, `Insecure`, `Bogus`, `Indeterminate`.
- `Secure` → AD bit; `Bogus` → `SERVFAIL` with an Extended DNS Error (RFC 8914).
- The client's CD bit is honoured (answer passed through without validation).
- Negative trust anchors configurable per domain (escape hatch for broken zones).

### Forward zones
- Configured zones (and reverse zones such as `30.172.in-addr.arpa`) are sent to a list of
  target servers instead of being resolved from the root; targets are tried in RTT order with failover.
- DNSSEC per forward zone: `validate = false` by default (implicit negative trust anchor),
  because private zones are usually unsigned and may sit below a signed public zone.
  `validate = true` for signed internal zones.
- Loop protection: a forwarded query is never forwarded again by this resolver
  (detects misconfiguration where the remote side forwards back).
- Answers are cached like recursive answers.
- Locally served private reverse zones (RFC 6303) are answered locally unless a forward zone covers them;
  private-range PTR queries never leak to the public internet.

### Cache
- Positive and negative cache (RFC 2308), bounded in MB, LRU-like eviction.
- Configurable TTL clamping (default: min 0 s, max 86400 s).
- Prefetch: popular entries are refreshed shortly before expiry.
- Serve-stale (RFC 8767): expired entries up to 1 day when authoritative servers are unreachable.
- Flush all or per domain through the module API (used later by `control-api`).
- In-memory only; the cache is not persisted across restarts (decided: simplicity over warm start).

### Interface (boundary towards `policy`)

```rust
pub struct Resolver { /* ... */ }

impl Resolver {
    pub async fn new(config: ResolverConfig) -> Result<Self, ResolverError>;
    pub async fn resolve(&self, query: &Query, flags: RequestFlags) -> Result<Answer, ResolveError>;
    pub fn flush(&self, scope: FlushScope);
    pub fn stats(&self) -> ResolverStats;   // cache hits, latencies, DNSSEC outcomes
}

pub struct Answer {
    pub message: Message,           // final answer records + rcode
    pub dnssec: DnssecStatus,
    pub source: AnswerSource,       // Cache | Recursion | Stale
    pub ede: Option<ExtendedError>,
}
```

Every error variant exposes a stable `code()` (e.g. `resolver.dnssec_bogus`) for the API;
see i18n rules in [SPEC.md](SPEC.md#internationalization-i18n).

### Configuration (excerpt, TOML)

```toml
[resolver]
cache_size_mb = 64
ttl_min = 0
ttl_max = 86400
serve_stale = "1d"
prefetch = true
outgoing_ipv6 = true
negative_trust_anchors = []

[[resolver.forward_zones]]
zone = "site-b.internal"
targets = ["172.30.0.1", "172.30.0.2"]
validate = false

[[resolver.forward_zones]]
zone = "30.172.in-addr.arpa"
targets = ["172.30.0.1"]
```

## Out of scope for this module

Filtering, split-horizon, ACLs, listeners/protocols, logging of client queries,
which profile may use which forward zone (decided in `policy`), any user-facing text.

## Testing

- **Fake hierarchy** in `dnscraft-testkit`: local authoritative servers for `.` → `test.` → `example.test.`,
  running in-process on loopback with random ports; root hints point at them.
- DNSSEC test zones: one each for `secure`, `insecure` (no DS), `bogus` (wrong signature,
  expired RRSIG, missing DNSKEY), NSEC and NSEC3 denial.
- Failure cases: timeout, lame delegation, CNAME loop, TC bit → TCP, SERVFAIL from individual servers.
- `criterion` benchmark for cache lookups.
- Manual acceptance against the real internet via a small example binary
  (`cargo run -p dnscraft-resolver --example query -- example.com A`).

## Success Criteria

1. Against the fake hierarchy, A, AAAA, CNAME chains, NXDOMAIN, and NODATA resolve correctly.
2. DNSSEC: `secure` → `Secure` + AD; `insecure` → `Insecure`, no AD; every `bogus` variant → `SERVFAIL` + EDE; with CD bit → answer without validation.
3. Manually against the internet: `example.com A` → `Secure`; `dnssec-failed.org A` → `SERVFAIL`.
4. Cache hit p50 < 1 ms (benchmark); a second identical query causes no network traffic (test).
5. With authoritative servers taken offline in the testkit, an expired entry yields a stale answer.
6. 50 concurrent identical queries produce only one outgoing resolution chain.
7. A forward zone is resolved via its targets only (no root traffic), fails over when the first target is down, and a forwarding loop ends in `SERVFAIL` instead of hanging; a private-range PTR without forward zone is answered locally and never sent upstream.
8. Line coverage ≥ 80 %.

## Decisions

- **Engine (ADR-0001, Option D):** recursion and DNSSEC validation logic are written in-house on top of
  `dnscraft-proto`; cryptographic primitives come from `ring`.
- Cache is not persisted across restarts.

## Open Questions

None at the moment.
