# Spec: filtering

> Module id `filtering` · crate `crates/dnscraft-filtering` · depends on: nothing
> Project-wide decisions (stack, commands, style, boundaries, i18n): [SPEC.md](SPEC.md)

## Objective

Decide for a domain name whether it is blocked, allowed, or untouched, and say exactly
why. The module loads AdGuard-compatible filter lists and custom rules, keeps them
fresh, and answers match requests fast enough to sit in the query path of every DNS
request. Filter sets are named bundles that `policy` selects per subnet/Client ID; this
module does not know clients, views, schedules, or DNS transport.

## Assumptions

1. `filtering` is a library: it gets its configuration as Rust values (lists, custom
   rules, filter sets) and does not own the SQLite database (`control-api` does).
2. Downloaded list files are cached in the data directory, so a restart works without
   network access and does not hammer list providers.
3. `policy` turns a verdict into a DNS response (block mode, CNAME uncloaking across the
   resolver's answer chain); `filtering` only supplies the verdicts and the configured
   block mode of the filter set.
4. Statistics over time (hits per day, top blocked) are computed by `control-api` from
   the query log; `filtering` exposes cheap in-memory counters and load-time facts.

## Requirements

### Rule syntax (AdGuard DNS subset)

Accepted list formats, detected per line:

| Format | Example | Meaning |
|---|---|---|
| Adblock domain rule | `\|\|ads.example^` | block the domain and all subdomains |
| Exception | `@@\|\|cdn.example^` | allow (overrides blocks of equal or lower priority) |
| Exact start/end anchors | `\|ads.example^`, `ads.example\|` | as in AdGuard DNS filtering |
| Plain domain | `ads.example` | block the domain and all subdomains |
| Hosts line | `0.0.0.0 ads.example`, `127.0.0.1 a b c` | **always block**, whatever the IP (owner decision: lists never redirect) |
| Wildcard pattern | `\|\|ad*.example^` | glob as AdGuard defines it |
| Regex | `/^ads?[0-9]*\.example$/` | linear-time regex engine only; matched against the canonical name (lower-case, no trailing dot) |
| IP rule | `\|\|192.0.2.10^`, `@@\|\|2001:db8::1^` | matches DNS **answers** containing that IPv4/IPv6 address (A/AAAA); `policy` applies it to the resolved answer (AdGuard behaviour against malware hosts with changing names) |
| Comment | `! …`, `# …` | ignored |

Supported modifiers: `$important`, `$badfilter`, `$dnstype=…` (incl. negation `~`),
`$denyallow=…`, `$dnsrewrite=…`.

- `$dnsrewrite` from **custom rules** may answer with an rcode (`REFUSED`, `NXDOMAIN`, …)
  or with records (A, AAAA, CNAME, TXT, …). From **downloaded lists** only rcode and
  `@@…$dnsrewrite` (disable) forms are honoured. A **record-form** rewrite (A/AAAA/CNAME/
  TXT) on a downloaded-list rule causes the **whole rule to be dropped** and counted as
  `rewrite_from_list` with a warning. This deliberately differs from hosts lines (which
  keep their block and ignore the IP): a record-rewrite line has no block-only meaning
  the list author wrote, so the engine does not invent one. The invariant is the same:
  a compromised list must not redirect domains.
- `$client`, `$ctag`: ignored with a warning (profiles in `policy` replace them).
- Cosmetic/URL rules from browser lists (`##`, `$script`, paths, `$domain=`): skipped and
  counted, never an error (EasyList Germany and EasyPrivacy contain many).
- Names are matched case-insensitively on the canonical form without trailing dot.
  Non-ASCII rules are converted to punycode (IDNA); unconvertible ones are skipped with a
  warning.
- Priority (highest first), as in AdGuard: `$important` exception > `$important` block >
  exception > block. `$badfilter` disables the identical rule **from the sources it may
  affect**: a `$badfilter` in a downloaded list or a blocked service never disables an
  identical **custom** rule of the set (a list must not silently remove the user's own
  rules); a custom `$badfilter` disables identical rules everywhere in the set, including
  list and service rules. Temporary allows (below) rank like `$important` exceptions.

### Parsing and validation API

- `parse_rule(&str) -> Result<Rule, RuleError>`: used for list loading and by the web
  editor for live validation. `RuleError` carries a stable `code()` (e.g.
  `filter_rule.unknown_modifier`), message parameters, and the byte span of the problem.
- `build_rule(RuleSpec) -> String`: the guided rule builder ("block / allow · domain ·
  include subdomains · record types · important") generates canonical rule text, so a
  user never has to type `|`, `^`, `@@`, or `$` (German Mac keyboard requirement).
- Round trip: `parse_rule(build_rule(spec))` yields the same semantics.

### Filter lists

- A list has id, name, URL (HTTPS, or a local file path), enabled flag, and is shared by
  any number of filter sets (loaded and stored once).
- Update interval: global, default **24 h**; manual "update now" per list and for all.
- Retry backoff: a scheduled round with any failed list or catalog update retries after 5 min,
  doubling per further consecutive failed round, capped at the update interval. A clean round
  returns to the regular interval. Manual updates do not change the schedule.
- Downloads: conditional requests (`ETag`/`If-Modified-Since`), timeout 30 s, size cap
  64 MiB per list, redirects at most 5 and HTTPS → HTTP downgrades refused. A failed
  download or parse keeps the last good version and records the error.
- Per list status: last attempt, last success, HTTP status/error `code()`, rules parsed,
  rules skipped (by reason), unique contribution after dedup within the set.
- Reload never blocks matching: a new index is built in the background and swapped in
  atomically; queries during the rebuild use the previous index.
- Tests never download from the internet (local HTTP test server).

### Filter sets

- A filter set has: id, name, enabled lists, custom rules (text, one rule per line),
  enabled blocked services, temporary allows, block mode, and a paused-until flag.
- Block mode (per set): `REFUSED` (default — owner's current setup), `NXDOMAIN`,
  null IP (`0.0.0.0` / `::`), custom IPv4/IPv6. `policy` renders the response.
- Pause: the set returns `Pass` for every name until a given time (or until resumed).

### Blocked services

- Catalog from AdGuard HostlistsRegistry `services.json` + `services_i18n.json`, downloaded
  at runtime like a list (GPL-3.0 data, never bundled), cached in the data directory,
  same update and retry-backoff rules as lists. Without a catalog the feature shows as
  unavailable (`services()` is `None`; `services_updated_at()` is `None`). A cached catalog
  loads offline at start-up; `services_updated_at()` reports the last successful download
  (Unix seconds).
- A set enables services by id; their rules join the set with source "service: <id>".
- The catalog API exposes id, name, icon (SVG data from the catalog), group, and the
  translated names by locale for the web UI.

### Temporary allow

- `allow_temporarily(set, TempAllow { domain, include_subdomains, until, created_at })`; expires
  automatically (injectable clock), listed with remaining time, removable early. `created_at` is
  stamped by the engine from its clock; a caller-supplied value is replaced.

### Matching

- `match_name(set, name, qtype) -> Verdict`, where `Verdict` is `Pass`, `Allowed(Reason)`,
  `Blocked(Reason)`, or `Rewrite(Rewrite, Reason)`.
- `Reason` names the rule text, its source (list id + line number, custom rule line,
  service id, temporary allow), and whether it was `$important` — the "Why blocked?"
  data shown in the query log and the test query.
- CNAME uncloaking support: `match_chain(set, &[names], qtype)` returns the first
  blocking verdict along the chain (an allow on the queried name does not unblock a
  blocked CNAME target unless it is `$important`, matching AdGuard).
- `match_answer_ip(set, ip) -> Verdict`: IP rules against an address from the answer; `policy` calls it for every A/AAAA record of a resolved answer and blocks the whole answer on a block verdict.
- Counters per list and per set (matches, blocks) as atomics, read by `control-api`.

### Interface (sketch)

```rust
pub struct FilterEngine { /* … */ }

impl FilterEngine {
    /// Returns a shared handle; the update scheduler holds only a weak reference.
    pub fn new(config: FilterConfig, store: ListStore, clock: Arc<dyn Clock>) -> Result<Arc<Self>, FilterError>;
    /// `now` is passed explicitly so tests can freeze time; errors are unknown set ids.
    pub fn match_name(&self, set: &SetId, name: &DomainName, qtype: u16, now: SystemTime) -> Result<Verdict, FilterError>;
    pub fn match_chain(&self, set: &SetId, names: &[DomainName], qtype: u16, now: SystemTime) -> Result<Verdict, FilterError>;
    pub fn match_answer_ip(&self, set: &SetId, ip: IpAddr, now: SystemTime) -> Result<Verdict, FilterError>;
    pub async fn apply_config(&self, config: FilterConfig) -> Result<ReloadReport, FilterError>;
    pub async fn update_lists(&self, which: ListSelection) -> Vec<ListStatus>;
    pub async fn update_services(&self) -> ServicesUpdateReport;
    pub fn allow_temporarily(&self, set: &SetId, rule: TempAllow) -> Result<(), FilterError>;
    pub fn list_status(&self) -> Vec<ListStatus>;
    pub fn services(&self) -> Option<Arc<ServiceCatalog>>;
    pub fn services_updated_at(&self) -> Option<u64>;
    pub fn stats(&self) -> FilterStats;
}
pub fn parse_rule(text: &str) -> Result<Rule, RuleError>;
pub fn build_rule(spec: &RuleSpec) -> Result<String, BuildError>;
```

Every error exposes a stable `code()` for API and i18n (`filter_list.fetch_failed`,
`filter_list.too_large`, `filter_rule.invalid_regex`,
`filter_index.unknown_source`, `filter_index.too_large`, `filter_index.too_many_sources`, …).

### Budgets (from SPEC.md, reference set ≈ 2.25 M rules, 19 lists)

| Metric | Target |
|---|---|
| Match per query (p99, warm) | < 10 µs |
| (Re)load of the reference set | < 10 s, matching never blocked |
| Memory for the loaded reference set | fits the process budget of ≤ 150 MB RSS (target ≤ 80 MB for filtering) |

Measured with a `criterion` benchmark on a generated rule set of the same size and shape
(mostly plain domains, some wildcards/regex), plus a manual run against the real lists.

**Owner waiver (2026-10-27).** The deep-name match p99 (measured ≈ 18.9 µs against the
10 µs target) and the reload peak memory were waived by the owner. They are tracked as
known deviations, not release gates; the other budget rows remain targets.

## Configuration excerpt (TOML, bootstrap only; normally edited in the UI)

```toml
[filtering]
update_interval = "24h"
max_list_size_mb = 64

[[filtering.lists]]
id = "adguard-dns"
url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"

[[filtering.sets]]
id = "default"
lists = ["adguard-dns"]
block_mode = "refused"
services = ["tiktok"]
custom_rules = ["@@||example.org^"]
```

## Testing

- Unit tests for every syntax form, modifier, priority rule, and the builder round trip;
  `proptest` for parser robustness and builder/parser round trips.
- A fuzz target for the rule/list parser (lists are untrusted input).
- Integration tests: local HTTP server for downloads (ETag, 304, oversize, timeout,
  redirect to HTTP, garbage content, last-good fallback), hot reload under concurrent
  matching, temporary allow expiry with a manual clock.
- Golden tests: small excerpts of real list styles (adblock, hosts, plain, EasyList-style
  with cosmetic rules) checked into `tests/data/` (excerpts only, licence-compatible).
- Coverage ≥ 80 % lines (SPEC.md).

## Boundaries

- Always: treat list content and catalog data as untrusted; keep the last good version;
  report skipped rules instead of failing a whole list.
- Ask first: new dependencies (expected: an HTTP client with rustls, a linear-time regex
  engine, an IDNA converter — decided in the plan); changing the default block mode or
  update interval.
- Never: let a downloaded list redirect a domain (hosts IPs, `$dnsrewrite` records);
  bundle GPL catalog data in the repo or image; download in tests.

## Success Criteria

1. All 19 reference lists parse; skipped rules are counted by reason and none is a
   DNS-relevant rule we claim to support (checked manually once against the real lists).
2. Priority semantics match AdGuard for a table of cases (`@@`, `$important`,
   `$badfilter`, `$denyallow`, `$dnstype`), including CNAME-chain verdicts.
3. Every verdict carries the rule text and its source; the builder never emits a rule
   that the parser rejects.
4. Budgets met: match p99 < 10 µs, reload < 10 s without blocking matches, memory target
   for the reference-sized generated set.
5. List updates: 304 handling, size cap, timeout and HTTPS-downgrade refusal tested; a
   failing update keeps serving the last good list and reports a stable error code.
6. Blocked services load from a (test) catalog, toggle per set, and show translated names.
7. Temporary allows expire on time (manual clock) and rank above normal blocks.
8. Line coverage ≥ 80 %, parser fuzz target runs 10 min without findings.

## Decisions (owner, 2026-10-25)

- Syntax: AdGuard DNS subset as above; `$client`/`$ctag` ignored with warning.
- Block mode: selectable per filter set; default `REFUSED`.
- List updates every 24 h by default.
- Hosts lines in lists always block, never redirect.
- `$dnsrewrite` record rewrites are honoured only in custom rules; in downloaded lists
  only rcode and disable forms apply, and a record-form rewrite drops the whole rule
  (counted as `rewrite_from_list`).
- IP rules (`||1.2.3.4^`) are supported and match answer addresses (owner, 2026-10-25, after Checkpoint A).
- Spec approved 2026-10-25. Dependencies are proposed in the plan for approval.

## Open Questions

None.
