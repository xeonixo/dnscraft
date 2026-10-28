# Spec: resolver

> Module id `resolver` · crate `crates/dnscraft-resolver` · depends on: nothing
> Project-wide decisions (stack, commands, style, boundaries, i18n): [SPEC.md](SPEC.md)

## Objective

A recursive, validating resolver: it answers a DNS question by walking the delegation
chain itself starting at the root servers, validates DNSSEC, and caches results.
It knows nothing about filters, clients, or listeners; it takes a `Query` and returns an `Answer`.

## Requirements

### Recursion
- Starts from built-in root hints (IANA), refreshed via a priming query at startup and again every
  24 h (RFC 8109). With trust anchors configured, the priming answer must validate (`. NS` against the
  root DNSKEY); otherwise the built-in hints stay in use. Root addresses are taken only for names under
  `root-servers.net.`.
- The answer handed to the client is rebuilt from what the resolver accepted: the RRset for the question,
  the CNAME/DNAME links followed (from the response authoritative for each) and, for negative answers,
  the SOA and NSEC/NSEC3 proof. Other records of a response (unrelated owners, additional section) are
  dropped, with or without DNSSEC validation. Forwarded answers are scrubbed the same way.
- Name server addresses learned from the network (glue, address lookups) must be routable: loopback,
  unspecified, link-local, multicast, reserved and IPv4-mapped addresses are never used; private-use
  addresses (RFC 1918, CGNAT, ULA) only with `allow_private_nameservers`. At most 16 addresses are taken
  per referral. Operator-configured addresses (root hints, forward targets) are not filtered.
- One upstream resolution is bounded by `resolve_deadline` (default 10 s).
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
- Validated TTLs never exceed the RRSIG's original TTL nor outlive its expiration (RFC 4035 section 5.3.3);
  cache entries expire with the signatures.
- The rcode is not signed: NXDOMAIN next to a validated RRset for the question is `Bogus` in a secure
  zone and treated as a broken server elsewhere.
- Per-resolution work budgets (signature verifications, NSEC3 hashes) also cover forwarded validation.
- Result per answer: `Secure`, `Insecure`, `Bogus`, `Indeterminate`.
- `Secure` → AD bit; `Bogus` → `SERVFAIL` with an Extended DNS Error (RFC 8914).
- The client's CD bit is honoured (answer passed through without validation).
- Negative trust anchors configurable per domain (escape hatch for broken zones).

### Forward zones
- Configured zones (and reverse zones such as `2.0.192.in-addr.arpa`) are sent to a list of
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
- Flush returns a `FlushReport { evicted }` count (WX4, proposed 2026-10-27; today's
  `flush` returns nothing). A domain scope removes the name and everything below it, all
  types, positive, negative and stale entries. Answers still in flight when a flush runs
  must not be written back into the cache (the existing epoch counter is the guard; a test
  must cover it). Node-local; a repeated flush is a no-op with `evicted: 0`.
- In-memory only; the cache is not persisted across restarts (decided: simplicity over warm start).

### Upstream health (WX3, proposed 2026-10-27)

Required observable state, read by `control-api` through `Resolver::upstreams()`.
Owner: `resolver` (counters). Route and shape: `SPEC-control-api.md` § Web-UI extra endpoints.

- Items: each forward-zone target one by one (`kind = forward_target`, with its zone and
  configured address), plus one aggregate `kind = recursion` item for root-hint traffic.
  Individual root servers are not reported in v1.
- Passive only: samples come from real upstream exchanges. The resolver sends no extra
  probe traffic for health.
- Per target: a bounded ring of at most 256 samples within a rolling 5-minute window; the
  success or failure of each exchange, its RTT, and the stable `code()` of the last
  failure. A failure is a timeout, SERVFAIL, refusal, malformed reply, or a `Bogus`
  validation result.
- Derived fields: `rtt_ms` p50 and p95 over successful exchanges, `success_rate`,
  `samples`, `last_checked`. State rule (defaults): `unknown` below 3 samples; `down`
  below 50 % success with at least 10 samples; `degraded` below 95 % success or p95 above
  1 s; otherwise `up`.
- Memory is bounded by the target count times 256 samples. Counters are copied into a
  read-only snapshot; no handle into the resolver is exposed.

### Interface (boundary towards `policy`)

```rust
pub struct Resolver { /* ... */ }

impl Resolver {
    pub async fn new(config: ResolverConfig) -> Result<Self, ResolverError>;
    pub async fn resolve(&self, query: &Query, flags: RequestFlags) -> Result<Answer, ResolveError>;
    pub fn flush(&self, scope: FlushScope) -> FlushReport;   // WX4: evicted count
    pub fn stats(&self) -> ResolverStats;   // cache hits, latencies, DNSSEC outcomes
    pub fn upstreams(&self) -> Vec<UpstreamHealth>;          // WX3: passive, 5 min window
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
id = "site-b"
zone = "site-b.internal"
targets = ["192.0.2.1:53", "192.0.2.2:53"]
validate = false

[[resolver.forward_zones]]
id = "reverse-192-0-2"
zone = "2.0.192.in-addr.arpa"
targets = ["192.0.2.1:53"]
validate = false
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
8. (WX3) Upstream health: a target whose exchanges all time out is reported `down` with `last_error` set; a target with fewer than 3 samples is `unknown`; samples older than 5 minutes are not counted; no probe query is sent to any upstream by the health code.
9. (WX4) A domain flush removes the name and its subtree, returns the evicted count, and an answer that was in flight during the flush is not cached afterwards.
10. (WX3) A forwarded answer that fails DNSSEC validation is counted as one failed exchange of its target (the DNSKEY exchange stays a separate sample), with the `dnssec.*` code as `last_error`.
11. Line coverage ≥ 80 %.

## Decisions

- **Engine (ADR-0001, Option D):** recursion and DNSSEC validation logic are written in-house on top of
  `dnscraft-proto`; cryptographic primitives come from `ring`.
- Cache is not persisted across restarts.

## Open Questions

None at the moment.
