# dnscraft-policy

View/profile selection and the twelve pipeline steps between DNScraft listeners
and the resolver / filter engine.

Formal requirements: [`SPEC-policy.md`](../../SPEC-policy.md).

## Status

Library for configuration validation, hot-reloadable snapshots, pause
protection, and the query pipeline through SafeSearch, schedules, rebind /
AAAA suppression.

## Pipeline

| Step | Action |
|------|--------|
| — | Select view/profile (Client ID → longest-prefix subnet → default) |
| 1 | View local records (exact A/AAAA/CNAME/TXT/SRV/MX/PTR) |
| 2 | `ClientDirectory` names / PTR / special-use NXDOMAIN |
| 3 | Bypass canaries (Firefox DoH, iCloud Private Relay) |
| 4 | Filter original qname (`FilterEngine::match_name`) |
| 5 | SafeSearch rewrite (A/AAAA/HTTPS → CNAME to provider safe host) |
| 6 | Filter rewritten SafeSearch host (`match_name`; block/rewrite like 4a/4b) |
| 7 | Forward zone / recursion (`Resolver::resolve`) |
| 8 | CNAME-chain uncloaking (`match_chain`) |
| 9 | Answer-IP rules (`match_answer_ip`) |
| 10 | Rebind: strip private A/AAAA from answers **and** additional section; scrub HTTPS/SVCB `ipv4hint`/`ipv6hint` (RFC 9460 §7.3); if `mandatory` listed a dropped hint, drop the whole RR (§8). When an RRset of type `T` is removed or rewritten, covering RRSIGs (`type_covered == T`) in that section are dropped too (RFC 4035 §3.1.1 / §5) so validating stubs see an unsigned, modified answer — AD is never set for it |
| 11 | AAAA suppression (`suppress_aaaa` + qtype AAAA → NODATA + SOA) |

ECS is never forwarded. Synthesised / modified answers always clear AD.

## Pause protection

`pause(Global | Profile(id), For(duration) | UntilResumed)` skips filter steps
4 / 6 / 8 / 9 only. Local records, canaries, **SafeSearch**, rebind, and AAAA
still run. A paused query records exactly one
`DecisionStep::ProtectionPaused { scope }`.
`For(Duration::ZERO)` is rejected (`policy.config.invalid`).

## SafeSearch table

| Provider | Rewritten hosts (summary) | Safe target |
|----------|---------------------------|-------------|
| `google` | `www.google.com` + country domains from [supported_domains](https://www.google.com/supported_domains) (fetched 2026-10-25) | `forcesafesearch.google.com` |
| `youtube` | `www.youtube.com`, `m.youtube.com`, `youtubei.googleapis.com`, `youtube.googleapis.com`, `www.youtube-nocookie.com` | `restrict.youtube.com` (strict) / `restrictmoderate.youtube.com` (moderate) |
| `bing` | `www.bing.com`, `edgeservices.bing.com` | `strict.bing.com` |
| `duckduckgo` | `duckduckgo.com` (+ `www` / `start`, see progress.md) | `safe.duckduckgo.com` |

Only qtypes A / AAAA / HTTPS are rewritten; a block on the original qname
always wins. Hosts and citations live in `src/safesearch_table.rs`.

## Config surface (high level)

| Field | Notes |
|-------|--------|
| `views` / `profiles` | Exactly one default view; profile ids unique |
| `filter_set` | Must exist in the filter engine |
| `rebind` / `rebind_exceptions` / `rebind_check_forward_zones` | Exceptions are exact or `*.suffix` |
| `suppress_aaaa` | NODATA on AAAA only |
| `firefox_canary` / `icloud_private_relay` | Bypass answers |
| `forward_zones` | Optional allow-list of resolver zone ids |
| `safesearch` | `enabled`, `providers`, `youtube_mode` (`strict` \| `moderate`, default strict) |
| `schedules` | Windows from Monday 00:00 UTC (`start` inclusive, `end` exclusive, `end ≤ 7d`); unique ids; no overlaps; while active, swap `filter_set` for steps 4/6/8/9 via `active_schedule` + `offset_in_week` |

## Schedule semantics

Windows are offsets within one UTC week from Monday 00:00. A Sunday→Monday span
is two windows. The hot path uses a pre-sorted schedule list on the snapshot and
[`active_schedule`](fn.active_schedule.html) (no allocation). Pause still wins
(filtering Passes). `DecisionRecord.filter_set` is the effective set;
`PolicyStatus.active_schedules` exposes the active schedule id per profile.
Open question: local time zones (tz dependency) — only `offset_in_week` would
change.

`apply_config` validates then swaps `Arc<PolicySnapshot>` under a short lock
(never held across `.await`). Counters and pauses survive by id; removed ids
are dropped.

## Client ID registry (for listeners)

`PolicyEngine::is_client_id_registered(&self, id: &str) -> bool` is the
read-only check public listeners use before completing a TLS handshake or
routing a DoH path. It takes a short snapshot read lock, looks up the already
lower-cased id in the snapshot map (no allocation), and returns `false` for
unknown or syntactically invalid ids (never panics). Hot reload is automatic:
after `apply_config` removes an id, the next call returns `false`. The
`dnscraft_tls::ClientIdRegistry` adapter lives in the listeners crate so policy
does not depend on tls.

## Failure codes (config)

| Code | Meaning |
|------|---------|
| `policy.config.invalid` | Generic validation (no default view, zero pause, …) |
| `policy.config.schedule_window` | `start >= end` or `end > 7d` |
| `policy.config.duplicate_schedule_id` | Two schedules share an id on one profile |
| `policy.config.invalid_schedule_id` | Id outside `[a-z0-9-]{1,64}` |
| `policy.config.overlapping_schedules` | Two windows overlap (`end > next.start`) |
| `policy.config.unknown_filter_set` | Profile / schedule set missing from filtering |
| `policy.config.unknown_safesearch_provider` | Provider not in the known list |
| `policy.config.duplicate_safesearch_provider` | Same provider listed twice |

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
| Empty after rebind strip (data RRs only; RRSIGs of stripped types removed) | clear | none (NODATA + SOA) |

## Test query

`test_query: true` returns the full `DecisionRecord` and sets `loggable = false`
(no query-log write). Counters are **not** incremented for test queries.

## Bench / coverage

```bash
cargo bench -p dnscraft-policy --bench pipeline
cargo llvm-cov -p dnscraft-policy --summary-only
```

Cached resolve + empty-filter miss: p50 must stay under 1 ms (see progress.md).
