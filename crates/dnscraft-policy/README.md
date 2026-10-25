# dnscraft-policy

View/profile selection and the twelve pipeline steps between DNScraft listeners
and the resolver / filter engine.

Formal requirements: [`SPEC-policy.md`](../../SPEC-policy.md).

## Status

Library for configuration validation, hot-reloadable snapshots, pause
protection, and the query pipeline through rebind / AAAA suppression.
SafeSearch and schedules are accepted in config and exposed as
“not applied yet” stubs until evaluation lands (P13/P14).

## Pipeline

| Step | Action |
|------|--------|
| — | Select view/profile (Client ID → longest-prefix subnet → default) |
| 1 | View local records (exact A/AAAA/CNAME/TXT/SRV/MX/PTR) |
| 2 | `ClientDirectory` names / PTR / special-use NXDOMAIN |
| 3 | Bypass canaries (Firefox DoH, iCloud Private Relay) |
| 4 | Filter original qname (`FilterEngine::match_name`) |
| 5 | SafeSearch rewrite (**stub** → `NotApplied`) |
| 6 | Filter rewritten SafeSearch host (**stub** → `NotApplied`) |
| 7 | Forward zone / recursion (`Resolver::resolve`) |
| 8 | CNAME-chain uncloaking (`match_chain`) |
| 9 | Answer-IP rules (`match_answer_ip`) |
| 10 | Rebind: strip private A/AAAA from answers **and** additional section; scrub HTTPS/SVCB `ipv4hint`/`ipv6hint` (RFC 9460 §7.3); if `mandatory` listed a dropped hint, drop the whole RR (§8) |
| 11 | AAAA suppression (`suppress_aaaa` + qtype AAAA → NODATA + SOA) |

ECS is never forwarded. Synthesised / modified answers always clear AD.

## Pause protection

`pause(Global | Profile(id), For(duration) | UntilResumed)` skips filter steps
4 / 6 / 8 / 9 only. Local records, canaries, rebind, and AAAA still run. A
paused query records exactly one `DecisionStep::ProtectionPaused { scope }`.
`For(Duration::ZERO)` is rejected (`policy.config.invalid`).

## Config surface (high level)

| Field | Notes |
|-------|--------|
| `views` / `profiles` | Exactly one default view; profile ids unique |
| `filter_set` | Must exist in the filter engine |
| `rebind` / `rebind_exceptions` / `rebind_check_forward_zones` | Exceptions are exact or `*.suffix` |
| `suppress_aaaa` | NODATA on AAAA only |
| `firefox_canary` / `icloud_private_relay` | Bypass answers |
| `forward_zones` | Optional allow-list of resolver zone ids |
| `safesearch.providers` | `google` / `bing` / `youtube` / `duckduckgo` (case-insensitive) |
| `schedules` | `start < end`, `end ≤ 7d` from Monday 00:00 UTC; unique `[a-z0-9-]{1,64}` ids |

`apply_config` validates then swaps `Arc<PolicySnapshot>` under a short lock
(never held across `.await`). Counters and pauses survive by id; removed ids
are dropped.

## `ClientDirectory` (for `control-api`)

Defined in this crate so policy does not depend on `dnscraft-clients`:

```rust
pub trait ClientDirectory: Send + Sync {
    fn addresses(&self, fqdn: &Name) -> Option<Arc<[IpAddr]>>;
    fn reverse(&self, ip: IpAddr) -> Option<Arc<str>>;
    fn local_domains(&self) -> Arc<[String]>;
}
```

`control-api` adapts the clients crate to this trait. Unknown names under a
directory’s local domain fall through to the rest of the pipeline; known names
with no address of the queried type yield NODATA.

## AD / EDE matrix (summary)

| Answer kind | AD | EDE |
|-------------|----|-----|
| Unmodified Secure resolver answer | keep | pass through |
| Insecure / Bogus / Indeterminate | clear | DNSSEC EDE kept when present |
| View / directory / bypass / filter synth | clear | Block → 15; forged IP → 4 |
| Rebind / AAAA modification | clear | drop resolver EDE |
| Empty after rebind strip | clear | none (NODATA + SOA) |

## Test query

`test_query: true` returns the full `DecisionRecord` and sets `loggable = false`
(no query-log write). Counters are **not** incremented for test queries.

## Bench / coverage

```bash
cargo bench -p dnscraft-policy --bench pipeline
cargo llvm-cov -p dnscraft-policy --summary-only
```

Cached resolve + empty-filter miss: p50 must stay under 1 ms (see progress.md).
