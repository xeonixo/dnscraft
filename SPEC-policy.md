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
- Scope: **global** (all profiles) or **per profile**.
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
| 10 | **AAAA suppression** — if profile `suppress_aaaa` and qtype was AAAA (or remove AAAA from mixed answers when applicable — see Open Questions) | IPv4-only clients |
| 11 | **Emit** message + `DecisionRecord` | |

Justification summary: **authoritative local data first**, then **policy canaries**, then **cheap filter**, then **expensive resolve**, then **answer hygiene** (chain, IP rules, rebind, AAAA).

### DNSSEC, AD bit, and EDE

Sources: [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914.html).

| Answer kind | AD bit | EDE |
|---|---|---|
| View record, ClientDirectory name/PTR, bypass, SafeSearch rewrite, filter rewrite, block synthesis | **Clear** (not validated public DNSSEC data) | Block with rcode REFUSED/NXDOMAIN/SERVFAIL: **15 Blocked** (operator policy). Null/custom IP with NOERROR: **4 Forged Answer**. EXTRA-TEXT may carry the stable filter reason code / short English diagnostic for logs — never secrets |
| Unmodified resolver answer with `DnssecStatus::Secure` | **Set** (pass through resolver’s AD) | Resolver’s EDE if any (e.g. stale) |
| Resolver answer then modified (AAAA stripped, rebind address removed, CNAME chain blocked) | **Clear** | Block path → 15; empty after rebind → optional 15 or no EDE (Open Questions) |
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
- Wildcards: not required in v1 (Open Questions).

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
  `mask-h2.icloud.com` so Private Relay is blocked (exact record content: follow
  Apple’s documented canary behaviour — cite at implement time; mark unverified
  until checked against current Apple docs).

### Schedules (low priority)

- Optional time windows on a profile that switch `filter_set` and/or enabled
  blocked services.
- Off by default; v1 may stub the config surface and defer evaluation to a
  follow-up task (must not block the rest of the pipeline).

### SafeSearch (low priority)

- Optional per profile; off by default.
- Rewrite well-known search / video hosts to their safe endpoints (Google, Bing,
  YouTube, DuckDuckGo). Exact target names verified against provider docs at
  implement time.
- Same deferral option as schedules if needed.

### Forward zones vs profiles

- Zone definitions and targets stay in **resolver** config (`ForwardZone`).
- Profile field `forward_zones: Option<Vec<ForwardZoneId>>`:
  - `None` — all configured forward zones apply (resolver default).
  - `Some(ids)` — only those zones may forward; other names recurse.
- Implementation may require a small resolver API extension (per-query filter);
  until then, document as a hard requirement in the plan.

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
- PTR for `reverse` when the qname is in an in-addr.arpa / ip6.arpa zone under
  private/ULA space (and not already answered by a view record).
- Optional: inject `None` directory when clients is disabled.

### RFC 6724 / ULA source address

SPEC.md Platforms: clients are expected to use a **ULA source** when querying a
ULA DNScraft address. Policy selection by IPv6 subnet depends on that.

- Document as an **assumption to verify** on real clients (iOS, Android, Linux,
  Windows) during acceptance.
- If violated (GUA source to ULA server), the query may hit the wrong view —
  mitigation ideas (Open Questions): warn in UI, optional “associate GUA with
  view via clients,” or require host/macvlan networking docs only.

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
- Ask first: new dependencies; changing pipeline order; enabling schedules /
  SafeSearch as non-stub; resolver API changes for per-profile forward zones.
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

1. **AAAA suppression** — only for qtype AAAA (NODATA/empty), or also strip AAAA
   from answers when the client queried ALL/`HTTPS`/etc.? Propose: **AAAA qtype
   only** in v1.
2. **Rebind after partial strip** — if some addresses remain public, return them;
   if none remain, NODATA vs NXDOMAIN vs REFUSED? Propose: **NODATA (NOERROR
   empty)**.
3. **Wildcard view records** — needed in v1 or exact names only?
4. **Schedules / SafeSearch** — stub config in v1 and implement later, or full
   behaviour before Checkpoint?
5. **Forward-zone allow-list** — OK to extend `Resolver` / `RequestFlags` for a
   per-query filter?
6. **Global vs per-profile pause** UX — both required for MVP?
7. **PTR scope** — answer ClientDirectory PTRs only for RFC 1918 + ULA, or also
   other local ranges the admin lists?
8. **RFC 6724** — accept the assumption and document, or require a verification
   matrix before marking the module done?
9. **iCloud / Firefox canary exact answers** — confirm against current Apple /
   Mozilla docs at implement time (mark any leftover as unverified).
10. **Default view records for `dns.<domain>` DDR** — owned by listeners/policy
    jointly; who authors the SVCB — listeners with policy local records?

## Decisions

None yet — draft for owner review (2026-10-25).
