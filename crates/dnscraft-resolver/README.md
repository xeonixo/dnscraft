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
| Forward zones | in progress |
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

`Resolver::new` primes the root server set (RFC 8109). If priming fails, the
built-in IANA hints are kept — check `resolver.priming_status()` if you care.

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
let _ = resolver.stats(); // resolutions + outgoing queries so far
```

## Behaviour in short

**Recursion.** Starts at the root, follows referrals, resolves glueless name
servers when needed. Outgoing traffic uses UDP with TCP fallback on the TC bit,
EDNS(0) with a 1232-byte buffer, randomised ports/ids, and RTT-based server
selection (IPv4/IPv6 with cool-down after unreachable).

**DNSSEC.** Validates against the built-in IANA root trust anchors (KSK-2017 and
KSK-2024). Negative trust anchors can be configured per domain for broken zones.
Empty trust anchors turn validation off (`Indeterminate` everywhere).

**Cache.** Positive and negative caching (RFC 2308), size-bounded (default 64
MiB), TTL clamp, optional prefetch of popular near-expiry entries, and
serve-stale (RFC 8767) for up to one day when authoritative servers are
unreachable. Memory only — cold start after every process restart.

**Local zones.** RFC 6303 private reverse zones are answered locally so those
PTRs never hit the public internet. A configured forward zone that covers the
same name opts out of the local answer (full forwarding lands with Task 14).

**Not in this crate.** Filters, split-horizon, ACLs, listeners (Do53/DoT/DoH/DoQ),
client query logs, or which profile may use which forward zone — that belongs
to `policy` and friends.

## Configuration

`ResolverConfig::default()` is a sensible starting point. Important knobs:

| Field | Default | Notes |
|-------|---------|--------|
| `root_hints` | IANA named.root | Overridable for tests |
| `query_timeout` | 1.5 s | Per server exchange |
| `qname_minimisation` | `true` | RFC 9156 |
| `trust_anchors` | IANA root KSKs | Empty → no validation |
| `negative_trust_anchors` | `[]` | Escape hatch for broken zones |
| `cache_size_mb` | `64` | `0` disables the cache |
| `ttl_min` / `ttl_max` | `0` / `86400` | Clamp before store |
| `serve_stale` | 1 day | `Duration::ZERO` disables |
| `prefetch` | `true` | Background refresh |
| `max_cname_chain` | `16` | Loop / amplification guard |
| `max_queries_per_resolve` | `64` | Budget per question |

The eventual DNScraft TOML shape is sketched in the [spec](../../SPEC-resolver.md#configuration-excerpt-toml);
this crate still takes a Rust `ResolverConfig` directly.

## Errors

Construction failures (`ResolverError`) and resolution failures (`ResolveError`)
expose a stable `code()` string (e.g. `resolver.unreachable`,
`resolver.query_budget`) for APIs and i18n. Human-readable text on the error is
for logs, not for end users.

## Design choice

Recursion and DNSSEC logic are written in-house on `dnscraft-proto`; crypto comes
from `ring`. See [ADR-0001](../../docs/adr/0001-recursion-engine.md).

## Tests

```bash
cargo test -p dnscraft-resolver
cargo test -p dnscraft-testkit   # signed fake hierarchy used by resolver tests
```

Integration tests drive a local authoritative hierarchy from `dnscraft-testkit`
(no internet required). The `query` example is the manual acceptance check
against the real root.
