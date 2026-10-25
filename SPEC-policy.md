# Spec: policy

> Module id `policy` · crate `crates/dnscraft-policy` · depends on: `resolver`, `filtering`
> (and a `ClientDirectory` **trait** only — no hard dependency on the `clients` crate;
> see [CAPABILITY-MAP.md](CAPABILITY-MAP.md))
> Project-wide decisions: [SPEC.md](SPEC.md)

## Objective

Turn a DNS question plus request context (who asked, on which listener) into an
answer and a structured **decision record** for the query log and the test
query. Policy is the pipeline between `listeners` and `resolver` /
`filtering`: it selects a split-horizon **view** and **profile**, applies local
records, bypass / SafeSearch / filters, recursion or forwarding, answer-side
checks (CNAME uncloaking, IP rules, rebind, AAAA suppression), and synthesises
block responses.

## Assumptions

1. `policy` is a library. Configuration arrives as Rust values (`control-api`
   owns SQLite); hot-reload swaps an `Arc` snapshot (same pattern as
   `FilterEngine`).
2. Filtering verdicts come from `dnscraft-filtering`
   (`match_name` / `match_chain` / `match_answer_ip`, `Verdict`, `BlockMode`,
   temporary allows, per-set pause). Policy never re-implements AdGuard syntax.
3. Recursion / DNSSEC / cache / forward zones are owned by `dnscraft-resolver`.
   Policy calls `Resolver::resolve` (or a thin façade) and may later pass a
   per-query forward-zone allow-list (see Open Questions).
4. Device names / PTR data come from `ClientDirectory` (defined here or in a
   tiny shared traits module). The `clients` crate implements it; policy does
   not depend on UniFi types.
5. Listeners supply `RequestContext` (source IP, protocol, Client ID from SNI
   or DoH path). Public Client-ID admission (unknown SNI → reject) is enforced
   at TLS/listener layer ([SPEC-tls.md](SPEC-tls.md)); policy still maps a
   present Client ID to a view/profile.
6. Coverage target ≥ 80 % lines (SPEC.md).

## Requirements

### Request context and selection

```rust
pub struct RequestContext {
    pub source_ip: IpAddr,
    pub protocol: DnsProtocol,       // Udp53 | Tcp53 | DoT | DoH | DoQ
    pub listener_id: ListenerId,     // which bind/address accepted the query
    pub client_id: Option<ClientId>, // from SNI / DoH path when present
    pub query: Query,                // name, type, class
    pub flags: ClientFlags,          // CD, DO from the client message
    pub test_query: bool,            // true → full DecisionRecord, never log
}

pub struct Selection {
    pub view_id: ViewId,
    pub profile_id: ProfileId,
    pub matched_by: SelectionCause,  // ClientId | Subnet(prefix) | Default
}
```

**Selection order (highest wins):**

1. **Client ID** exact match on a view’s `client_ids` list (beats any subnet).
2. **Longest-prefix** match of `source_ip` against view subnet/CIDR lists
   (IPv4 and IPv6 separately).
3. **Default view** (exactly one required).

If a Client ID is present but not listed on any view, fall through to subnet /
default (the ID may still appear in the log via `clients` enrichment). Unknown
public Client IDs never reach policy (listener rejected them).

### Views and profiles

| Object | Owns |
|---|---|
| **View** | Selection keys (CIDRs, Client IDs); split-horizon **records** (A, AAAA, CNAME, TXT, SRV, MX); pointer to one **profile** |
| **Profile** | `filter_set` id; pause protection; schedules (low priority); bypass controls; rebind exceptions; `suppress_aaaa`; SafeSearch; optional allow-list of forward-zone ids |

Blocked services and custom rules live on the **filter set** ([SPEC-filtering.md](SPEC-filtering.md)); the profile selects which set is active (schedules may swap the set — see below).

### Pause protection

- Durations: **5 minutes**, **1 hour**, or **until resumed**.
- Scope: **global** (all profiles) **and** **per profile** — both required for
  MVP (phone “pause everything” vs “pause kids’ profile”).
- While paused: filtering for that scope returns as if the filter set were
  paused (`Pass` on qname / chain / answer-IP). Local records, bypass,
  SafeSearch, rebind, and recursion still run.
- Distinct from filter-set pause in `filtering` (which is also honoured when
  the set’s `paused_until` is set). Policy pause is the user-facing “Pause
  protection” control (SPEC.md).

### Pipeline order

For each query, after selection:

| Step | Action | Why this order |
|---|---|---|
| 1 | **View local records** — exact name (+ type) in the view’s record table | Split-horizon must win over public data and filters for names the admin authored |
| 2 | **ClientDirectory local names / PTR** — FQDN under `local_domains()` or reverse for private/ULA PTR | Same “answer locally” idea; data from UniFi/manuals, not the view editor |
| 3 | **Bypass / canary** — per profile: `use-application-dns.net` → NXDOMAIN; `mask.icloud.com` / `mask-h2.icloud.com` → configured answers (block Private Relay or not) | Must not depend on filter lists; fixed product behaviour |
| 4 | **SafeSearch** (if enabled on profile, low priority) — rewrite qname to the provider’s safe host | Rewrite before filtering so the safe host is what gets checked / resolved |
| 5 | **Filter qname** — `FilterEngine::match_name(set, name, qtype)` | Block/allow/rewrite before spending recursion budget |
| 5a | `Blocked` → synthesise via set `BlockMode` + EDE; stop | |
| 5b | `Rewrite` → synthesise records/rcode from `Rewrite`; if CNAME, may continue chain handling like a local CNAME; stop or follow per rewrite kind | |
| 5c | `Allowed` / `Pass` → continue | Temporary allows rank as important allows inside filtering |
| 6 | **Forward zone or recursion** — `Resolver::resolve` (forward zones from resolver config, optionally restricted by profile allow-list) | Only after local/filter decisions |
| 7 | **CNAME uncloaking** — collect names in the answer chain; `match_chain`; on block, replace answer with block synthesis | Matches AdGuard / SPEC-filtering |
| 8 | **Answer-IP filtering** — for each A/AAAA in the final answer, `match_answer_ip`; block wins | Malware hosts with rotating names |
| 9 | **DNS rebind protection** — drop (or refuse) answers whose A/AAAA are private/loopback/ULA **unless** the qname (or a suffix) is on the profile’s exception list; if all addresses removed → NODATA or synthesised empty | After filters so legitimate filter rewrites to private IPs still work if the admin used custom rules / exceptions |
| 10 | **AAAA suppression** — if profile `suppress_aaaa` and qtype is **AAAA** only → NODATA (NOERROR empty); other qtypes unchanged | IPv4-only clients; keep HTTPS/SVCB/etc. intact |
| 11 | **Emit** message + `DecisionRecord` | |

Justification summary: **authoritative local data first**, then **policy canaries**, then **cheap filter**, then **expensive resolve**, then **answer hygiene** (chain, IP rules, rebind, AAAA).

### DNSSEC, AD bit, and EDE

Sources: [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914.html).

| Answer kind | AD bit | EDE |
|---|---|---|
| View record, ClientDirectory name/PTR, bypass, SafeSearch rewrite, filter rewrite, block synthesis | **Clear** (not validated public DNSSEC data) | Block with rcode REFUSED/NXDOMAIN/SERVFAIL: **15 Blocked** (operator policy). Null/custom IP with NOERROR: **4 Forged Answer**. EXTRA-TEXT may carry the stable filter reason code / short English diagnostic for logs — never secrets |
| Unmodified resolver answer with `DnssecStatus::Secure` | **Set** (pass through resolver’s AD) | Resolver’s EDE if any (e.g. stale) |
| Resolver answer then modified (AAAA stripped, rebind address removed, CNAME chain blocked) | **Clear** | Block path → 15; empty after rebind stripped all addresses → **NOERROR/NODATA**, no EDE (not a blocklist hit) |
| `DnssecStatus::Bogus` | Clear; SERVFAIL already from resolver | Keep resolver DNSSEC EDE |

Do **not** use EDE 17 Filtered for normal profile filtering (17 means the *client* asked to be filtered). Operator-configured lists → **15 Blocked**.

### Decision record

```rust
pub struct DecisionRecord {
    pub view_id: ViewId,
    pub profile_id: ProfileId,
    pub selection: SelectionCause,
    pub client_id: Option<ClientId>,
    pub steps: Vec<DecisionStep>,     // ordered pipeline breadcrumbs
    pub filter: Option<FilterHit>,    // rule text, source, important
    pub forward_zone: Option<Name>,
    pub dnssec: Option<DnssecStatus>,
    pub answer_source: AnswerOrigin,  // LocalView | LocalClient | Bypass | Filter | Resolver | …
    pub timings: DecisionTimings,     // select, filter, resolve, total (µs)
    pub rcode: Rcode,
}

pub struct FilterHit {
    pub reason: Reason,               // from filtering
    pub block_mode: Option<BlockMode>,
}
```

- Normal queries: `control-api` persists a compact form in the query log.
- **Test query** (`test_query: true`): return the full `DecisionRecord` to the
  API/UI and **do not** write the query log.

### Local records

- Per view: map of owner name → RR sets for types A, AAAA, CNAME, TXT, SRV, MX.
- TTL configurable per record (default 60 s).
- CNAME at a node means no other types at that node (RFC 1034); validate on apply.
- Wildcards: **exact names only in v1** (no `*.example` view records). Revisit if the UI needs them.

### DNS rebind protection

- Default **on** for every profile.
- Treat as “private” for this check: RFC 1918, RFC 6890 specials as configured,
  loopback, link-local, and **ULA `fc00::/7`** (home IPv6 — SPEC.md uses ULA for
  clients reaching DNScraft).
- Exceptions: list of domains / `*.suffix` on the profile (e.g. internal CDNs).
- Filter `$dnsrewrite` / view records that intentionally point at private IPs
  are not subject to rebind (they never went through the public answer path),
  or are covered by automatic exception for the rewritten qname — prefer the
  former (synthetic answers skip step 9).

### Bypass control

Per profile flags:

- `firefox_canary`: if true, `use-application-dns.net` → NXDOMAIN (discourage
  DoH bypass).
- `icloud_private_relay`: if true, answer `mask.icloud.com` /
  `mask-h2.icloud.com` so Private Relay is blocked. Exact RDATA must be checked
  against current Apple documentation at implement time (cite URL in the PR);
  until verified, mark the constant table `unverified` in code comments.

### Schedules (low priority)

- Optional time windows on a profile that switch `filter_set` and/or enabled
  blocked services.
- Off by default. **v1:** accept/store config and expose in the model, but
  evaluation may be a follow-up task before the profile checkpoint — must not
  block the rest of the pipeline. Document “not applied yet” in status if stubbed.

### SafeSearch (low priority)

- Optional per profile; off by default.
- Rewrite well-known search / video hosts to their safe endpoints (Google, Bing,
  YouTube, DuckDuckGo). Exact target names verified against provider docs at
  implement time.
- **v1:** same as schedules — config surface first, full rewrite behaviour can
  follow without blocking core pipeline work.

### Forward zones vs profiles

- Zone definitions and targets stay in **resolver** config (`ForwardZone`).
- Profile field `forward_zones: Option<Vec<ForwardZoneId>>`:
  - `None` — all configured forward zones apply (resolver default).
  - `Some(ids)` — only those zones may forward; other names recurse.
- **Approved:** extend `Resolver` / `RequestFlags` with an optional per-query
  forward-zone allow-list so profiles can restrict forwarding without multiple
  resolver instances.

### ClientDirectory integration

```rust
pub trait ClientDirectory: Send + Sync {
    fn by_ip(&self, ip: IpAddr) -> Option<ClientInfo>;
    fn by_name(&self, name: &str) -> Option<ClientInfo>;
    fn reverse(&self, ip: IpAddr) -> Option<String>;
    fn local_domains(&self) -> &[String];
}
```

- A/AAAA for `by_name` → addresses from `ClientInfo`.
- PTR for `reverse` when the qname is in an in-addr.arpa / ip6.arpa zone for
  **RFC 1918**, **ULA (`fc00::/7`)**, and **loopback** — plus any extra prefixes
  the admin lists under `policy.ptr_prefixes` (default empty).
- Optional: inject a no-op directory when clients is disabled.

### RFC 6724 / ULA source address

SPEC.md Platforms: clients are expected to use a **ULA source** when querying a
ULA DNScraft address. Policy selection by IPv6 subnet depends on that.

- **Decision:** treat as a documented assumption; module success criteria do
  **not** require a full OS verification matrix. Add a short note to the
  operator docs / first-run networking section.
- Manual acceptance: spot-check on the owner’s main devices when IPv6 views are
  configured. If GUA-sourced queries to a ULA listener are observed, follow up
  (UI warning or doc tweak) — not a v1 blocker.

### Hot path and budgets

| Budget | Target (SPEC.md) |
|---|---|
| Filter match | < 10 µs |
| Cached answer end-to-end p50 | < 1 ms |

Rules:

- Config in `Arc<PolicySnapshot>`; swap under a short lock; **no lock held across
  `await`** on resolver I/O.
- Selection and local-record lookup are pure RAM (prefix trie / hashmap).
- `test_query` uses the same path; only logging is skipped.

### Interface (sketch)

```rust
pub struct PolicyEngine { /* Arc<PolicySnapshot>, FilterEngine, Resolver, ClientDirectory */ }

impl PolicyEngine {
    pub fn new(config: PolicyConfig, filter: Arc<FilterEngine>,
               resolver: Arc<Resolver>, clients: Arc<dyn ClientDirectory>,
               clock: Arc<dyn Clock>) -> Result<Self, PolicyError>;

    pub async fn handle(&self, ctx: RequestContext) -> Result<(Message, DecisionRecord), PolicyError>;

    pub async fn apply_config(&self, config: PolicyConfig) -> Result<(), PolicyError>;

    pub fn pause(&self, scope: PauseScope, until: PauseUntil) -> Result<(), PolicyError>;
    pub fn resume(&self, scope: PauseScope) -> Result<(), PolicyError>;
}
```

### Error codes

| Code | When |
|---|---|
| `policy.config.invalid` | no default view, overlapping Client ID on two views, bad record set, etc. |
| `policy.config.unknown_filter_set` | profile references missing set |
| `policy.config.unknown_forward_zone` | profile allow-list id missing |
| `policy.record.cname_conflict` | CNAME coexists with other types at a name |
| `policy.selection.no_view` | defensive; should be unreachable if default exists |
| `policy.resolve` | resolver error bubbled with cause code when not turned into an answer |
| `policy.internal` | invariant violation |

### Observability

Per-profile / per-view counters (queries, blocks, local hits) as atomics for
`control-api`. Decision timings feed the test-query UI.

## Configuration excerpt (TOML, bootstrap only; normally edited in the UI)

```toml
[policy]
# rebind defaults apply unless overridden per profile
default_rebind = true
# extra prefixes for ClientDirectory PTR (RFC 1918 + ULA + loopback always on)
ptr_prefixes = []

[[policy.views]]
id = "lan"
subnets = ["192.0.2.0/24", "2001:db8:1::/64"]
profile = "default"
# client_ids = ["iphone-k7q2x9"]

[[policy.views.records]]
name = "nas.lan.example.com"
type = "A"
rdata = "192.0.2.10"
ttl = 60

[[policy.views]]
id = "default"
subnets = []               # catch-all
profile = "default"

[[policy.profiles]]
id = "default"
filter_set = "default"
suppress_aaaa = false
firefox_canary = true
icloud_private_relay = true
rebind = true
rebind_exceptions = ["*.example.com"]
# forward_zones = ["vpn-site-a"]   # optional allow-list
# safesearch = false
# schedules = []
```

## Testing

- Table tests: selection (Client ID > longer prefix > shorter > default),
  pipeline step order (local beats filter beats recursion), pause scopes,
  rebind exceptions, AAAA suppression, AD/EDE matrix, test_query does not log
  (hook/spy).
- Integration: `dnscraft-testkit` authoritative hierarchy behind the resolver;
  stub `FilterEngine::from_snapshot`; mock `ClientDirectory`.
- No real UniFi / Cloudflare / LE. Coverage ≥ 80 %.

## Boundaries

- Always: Arc snapshot swap; clear AD on synthesised/modified answers; EDE 15 for
  operator blocks; never log test queries.
- Ask first: new dependencies; changing pipeline order; shipping schedules /
  SafeSearch evaluation before the stub is replaced; view-record wildcards.
- Never: depend on `dnscraft-clients` directly; select profiles inside
  filtering; call the internet from tests.

## Success Criteria

1. Selection table tests match the Client ID / LPM / default rules.
2. Pipeline golden tests: view record and ClientDirectory answers never hit the
   resolver; blocked qnames never hit the resolver; CNAME chain block works.
3. Rebind strips private answers except exceptions; filter/view synthetics skip
   rebind.
4. AD/EDE behaviour matches the matrix above.
5. Cached path stays within the 1 ms p50 guideline when the resolver cache hits
   and the filter misses (criterion bench).
6. Line coverage ≥ 80 %; DoD gates green once implemented.

## Open Questions

None — sensible defaults locked 2026-10-25 (owner asked to decide reasonably).

## Decisions (2026-10-25)

1. **AAAA suppression:** only when qtype is AAAA → NODATA; do not strip AAAA
   from other types’ answers in v1.
2. **Rebind empty:** if every address was private and removed → **NOERROR /
   NODATA**; if any public address remains, return those. No EDE for pure rebind
   stripping.
3. **View records:** **exact names only** in v1 (no wildcards).
4. **Schedules / SafeSearch:** config surface in v1; evaluation may follow as a
   low-priority task — core pipeline must not wait on them.
5. **Forward-zone allow-list:** **yes** — extend resolver `RequestFlags` (or
   equivalent) for a per-query allow-list.
6. **Pause:** **both** global and per-profile in MVP.
7. **PTR:** RFC 1918 + ULA + loopback by default; optional extra
   `policy.ptr_prefixes`.
8. **RFC 6724:** document the assumption; spot-check on real devices later —
   **not** a module gate.
9. **Canaries:** implement against current Apple/Mozilla docs at coding time;
   cite URLs; mark unverified until checked.
10. **DDR / SVCB for `_dns.resolver.arpa`:** **listeners** synthesise DDR answers
    using hostnames/ports from tls + listener config. Policy view records are
    **not** required for DDR. (Listeners may still call policy for the client’s
    normal queries on the LAN.)
11. Spec status: **decisions locked**; formal “approved” for P1 still to be
    marked by the owner (no code before that).
