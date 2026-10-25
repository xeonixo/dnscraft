# Spec: clients

> Module id `clients` · crate `crates/dnscraft-clients` · depends on: nothing
> Project-wide decisions (stack, commands, style, boundaries, i18n): [SPEC.md](SPEC.md)

## Objective

Enrich a source IP with a human-readable client identity (display name, VLAN,
addresses, last seen) for the query log and for local-name / PTR data that
`policy` answers. Sources are the UniFi Network local Integration API on a UniFi
OS gateway, plus manual names for single IPs and CIDR ranges. This module never
selects filter profiles or views — that stays in `policy`
([CAPABILITY-MAP.md](CAPABILITY-MAP.md)).

## Assumptions

1. `clients` is a library: it receives configuration as Rust values and does not
   own the SQLite database (`control-api` does). Manual names may later be
   persisted by `control-api`; this crate only holds the live index.
2. Consumers: `control-api` (log enrichment, UI device filter) and `policy`
   (local names / PTR) via a small read trait so `policy` does not depend on
   this crate.
3. UniFi is optional. With UniFi disabled or unreachable, manual names still
   work and lookups return `None` rather than blocking DNS answering.
4. Secrets (UniFi API key) come only from environment variables or Docker
   secrets (`*_FILE`), never from the config export (SPEC.md).
5. Non-goal (SPEC.md): Docker API / socket access. Bridge-NAT containers are
   named manually; macvlan containers appear as UniFi clients.

## Requirements

### UniFi Integration API (research)

Prefer the official **Network Integration API** over the classic undocumented
controller endpoints.

| Topic | Finding | Source |
|---|---|---|
| Local base URL | `https://{console}/proxy/network/integration` then paths under `/v1/…` (OpenAPI `servers`) | [OpenAPI 10.6.106](https://developer.ui.com/network/v10.6.106/openapi.json) |
| Auth | API key in header `X-API-KEY` (docs also show `X-API-Key`; send the documented form) | [Getting started / AI onboarding](https://developer.ui.com/network/v10.6.106/ai-gettingstarted.md); [OpenAPI](https://developer.ui.com/network/v10.6.106/openapi.json) |
| Key creation | UniFi Site Manager: Settings → API Keys; on-console: Integrations / Control Plane (UI labels vary by OS version) | [developer.ui.com/network](https://developer.ui.com/network) |
| Sites | `GET /v1/sites` | same OpenAPI |
| Clients | `GET /v1/sites/{siteId}/clients` — **currently connected** only; `GET …/clients/{clientId}` for details | OpenAPI operation *List Connected Clients* |
| Pagination | `offset` (default 0), `limit` (default 25, **max 200**), optional `filter` DSL | OpenAPI parameters |
| Client fields | Common: `id` (uuid), `name`, `type` (`WIRED` / `WIRELESS` / `VPN` / `TELEPORT`), optional `ipAddress`, `connectedAt`, `access`. Wired/wireless also: `macAddress`, `uplinkDeviceId` | schemas *Client overview* / *Wired|Wireless client overview* |
| IPv6 on clients | **No** multi-address or dedicated IPv6 field in the Integration client schemas; only singular `ipAddress` | OpenAPI schemas (verified 2026-10-25 against v10.6.106) |
| Networks / VLAN | `GET /v1/sites/{siteId}/networks` and `…/networks/{networkId}`: `id`, `name`, `vlanId`, `enabled`, `default`. Gateway-managed **details** add `ipv4Configuration.hostIpAddress` + `prefixLength` (and IPv6 config) | schemas *Network overview* / *Gateway managed network details* / *Gateway Managed IPv4 Configuration* |
| Client → network link | **Not** exposed on Integration clients (no `networkId`) | OpenAPI client schemas |
| Rate limits | **Unverified** for the local Integration API (OpenAPI has no 429 / throttle docs). Site Manager / cloud connector tooling often cites ~100 req/min per console — treat as guidance only until measured | community / third-party clients; mark unverified |
| TLS | Gateways commonly use a self-signed cert. Default must **not** be "accept any certificate". Supported modes: SHA-256 **certificate pin** (preferred for self-signed), or a configurable CA / system trust when the admin installs a real cert. Explicit insecure skip-verify only as an opt-in escape hatch (logged as a security warning) | Security requirement (SPEC.md); pinning practice mirrors [UnifiApi docs](https://unifi-api.hexdocs.pm/readme.html) (third-party, cited for threat model only) |

#### What the official API lacks (vs classic controller API)

The classic undocumented surface (`/proxy/network/api/s/{site}/…`, e.g.
`stat/sta`, `rest/user`, cookie or sometimes API-key auth) historically returns
richer client rows (`network_id`, hostname aliases, multiple addresses, known
offline clients). Community references:
[ubntwiki controller API](https://ubntwiki.com/products/software/unifi-controller/api),
[Wachhund unifi-best-practices](https://github.com/Wachhund/unifi-best-practices).

**Decision for this module:** implement against the **Integration API only** in
v1. Document the gaps (IPv6 multi-address, offline/known clients, direct
network id). If owner testing shows the gaps block log enrichment or PTR, a
follow-up may add an **optional**, clearly labelled classic-API reader — never
as the default, and never required for build/tests. See Open Questions.

#### VLAN derivation without `networkId`

On each sync, fetch network **details** for gateway-managed networks and build
subnet → `(vlanId, network name)` from `hostIpAddress`/`prefixLength` (and IPv6
subnets when present). Assign a client's VLAN by longest-prefix match of its
`ipAddress` against that table. If no prefix matches, VLAN is unknown (`None`).

### Polling and freshness

- Default poll interval: **60 s** (proposed; see Open Questions), with ±10 %
  jitter like the filtering scheduler.
- Change detection: compare a content hash / generation of the normalised client
  + network snapshot; rebuild lookup indexes only when the generation changes.
- On gateway unreachable, auth failure, TLS failure, or parse error: **keep the
  last good snapshot**, set `stale = true`, record `last_error` with a stable
  `code()`, and continue serving lookups. Never block the DNS hot path on a
  sync (sync runs on a background task; lookups read an `Arc` snapshot).
- Manual "sync now" for the UI / first-run wizard.
- UniFi disabled (`enabled = false`): empty UniFi contribution; manuals only.

### Data model

```rust
pub enum ClientSource {
    Manual,
    Unifi,
}

pub struct ClientInfo {
    pub id: ClientId,           // stable: manual uuid or UniFi client uuid
    pub display_name: String,   // raw display string (UI / log)
    pub dns_label: String,      // normalised single label for <label>.<local-domain>
    pub source: ClientSource,
    pub macs: Vec<MacAddr>,     // zero or more; UniFi wired/wireless usually one
    pub addresses: Vec<IpAddr>, // all known IPs for this client in the snapshot
    pub vlan: Option<VlanInfo>,
    pub last_seen: Option<SystemTime>, // UniFi: connectedAt; manuals: None or updated_at
    pub online: bool,           // false if retained offline (if owner enables retention)
}

pub struct VlanInfo {
    pub id: u16,                // 802.1Q vlanId from UniFi networks
    pub name: String,           // network name, e.g. "IoT"
}

pub struct ClientLookup { /* Arc snapshot + indexes */ }

impl ClientLookup {
    /// Hot path for query-log enrichment. Lock-free read of Arc; O(1) hash.
    pub fn by_ip(&self, ip: IpAddr) -> Option<ClientInfo>;
    /// Forward local name: exact dns_label match (case-insensitive).
    pub fn by_name(&self, label: &str) -> Option<ClientInfo>;
    /// PTR: IP → preferred dns_label (same precedence as by_ip).
    pub fn reverse(&self, ip: IpAddr) -> Option<String>;
}
```

`policy` consumes a trait (sketch):

```rust
pub trait ClientDirectory: Send + Sync {
    fn by_ip(&self, ip: IpAddr) -> Option<ClientInfo>;
    fn by_name(&self, label: &str) -> Option<ClientInfo>;
    fn reverse(&self, ip: IpAddr) -> Option<String>;
}
```

### Precedence (IP → client)

When building the IP index, later lower-priority sources lose collisions:

1. **Manual single IP** (exact host entry)
2. **Manual CIDR** — **longest prefix wins** among overlapping ranges
3. **UniFi** (Integration snapshot)

Name collisions among UniFi devices after normalisation: keep a deterministic
tie-break (lexicographically smaller UniFi `id` wins the dns_label; losers get
`{label}-{id_suffix8}`). Manual entries that collide with UniFi labels: manual
wins the label; UniFi loser is renamed as above.

### Name normalisation (DNS labels)

For `<device>.<local-domain>`:

1. Unicode NFKC, lower-case.
2. Spaces and underscores → `-`; strip characters outside `[a-z0-9-]`.
3. Collapse repeated `-`; trim leading/trailing `-`.
4. Empty result → `client` + short id suffix.
5. Labels longer than 63 octets: truncate on a hyphen boundary when possible,
   then append a short hash suffix to keep uniqueness.
6. IDNA: the **label** is ASCII after step 2–5; the parent `local_domain` may be
   Unicode and is converted with UTS 46 when `policy` builds the FQDN.

### IPv6 and rotating privacy addresses

- Ingest whatever the Integration API returns in `ipAddress` when it is IPv6.
- Because the official schema has only one address, a privacy-address rotation
  may look like a new client IP each poll. Index the latest IP; optionally keep
  previously seen UniFi IPs for the same `id` until
  `ipv6_address_ttl` (proposed default **24 h**) after last observation, so PTR
  / log enrichment still works briefly after rotation.
- Do not invent extra IPv6 addresses. Multi-address support waits on API growth
  or an owner-approved classic-API add-on.

### Offline / disconnected clients

Integration *List Connected Clients* is active-only. Proposed default: when a
UniFi client disappears from a successful sync, **retain** it in the snapshot
for `offline_retain` (proposed **7 d**) marked `online = false`, so PTR and log
filters keep working for recently seen devices. Successful sync that omits the
client starts/continues the retain clock; eviction after the TTL. See Open
Questions.

### Memory budget

| Scale | Expected | Budget |
|---|---|---|
| Home (~60 clients + containers) | tiny (≪ 1 MB indexes) | negligible vs 150 MB process RSS |
| Upper bound | **10 000** clients / addresses indexed | soft warn above 2 000; hard refuse apply above 10 000 with `clients.too_many` |
| Manual entries | ≤ 1 000 | config validation |

Indexes: `HashMap<IpAddr, ClientId>`, `HashMap<dns_label, ClientId>`,
`Arc<[ClientInfo]>`. No disk cache of UniFi payloads required for v1 (restart
re-syncs); optional last-good JSON under `<data>/clients/` may be added later
for faster cold start (ask first).

### Interface (sketch)

```rust
pub struct ClientEngine { /* config, Arc<ClientLookup>, sync task */ }

impl ClientEngine {
    pub fn new(config: ClientsConfig, clock: Arc<dyn Clock>) -> Result<Self, ClientsError>;
    pub fn lookup(&self) -> Arc<ClientLookup>;
    pub async fn apply_config(&self, config: ClientsConfig) -> Result<(), ClientsError>;
    pub async fn sync_now(&self) -> Result<SyncReport, ClientsError>;
    pub fn status(&self) -> ClientsStatus; // last sync, stale, counts, last_error
}

impl ClientDirectory for ClientLookup { /* … */ }
```

### Error codes

Every error exposes stable `code()` (`area.reason`), covered by a uniqueness
test:

| Code | When |
|---|---|
| `clients.config.invalid` | bad URL, empty pin when required, overlapping manuals that cannot be ordered, etc. |
| `clients.secret.missing` | UniFi enabled but API key env/`*_FILE` absent |
| `clients.tls.untrusted` | cert does not match pin / CA |
| `clients.tls.handshake` | other TLS failures |
| `clients.connect` | TCP / DNS of gateway hostname failed |
| `clients.http.status` | non-success HTTP (incl. 401/403/429) |
| `clients.http.body` | JSON parse / schema mismatch (lenient skip of bad rows preferred; fatal only if page unusable) |
| `clients.sync.partial` | some pages failed; last good kept |
| `clients.too_many` | hard client/address cap exceeded |
| `clients.name.collision` | reserved for validation surfaces that refuse ambiguous manuals (rare; usually auto-suffix) |

### Observability

`ClientsStatus`: `last_attempt`, `last_success`, `stale`, `client_count`,
`manual_count`, `unifi_count`, `address_count`, `last_error: Option<code()>`,
`poll_interval`. Cheap counters for sync successes/failures. Alerts surface
("UniFi unreachable") is owned by `control-api` / web-ui using these fields.

## Configuration excerpt (TOML, bootstrap only; normally edited in the UI)

```toml
[clients]
local_domain = "home.arpa"          # open question: default
offline_retain = "7d"
ipv6_address_ttl = "24h"

[clients.unifi]
enabled = true
base_url = "https://192.0.2.1"     # documentation range; gateway address
# site_id optional: if omitted, use the sole site or fail with clients.config.invalid
site_id = "00000000-0000-0000-0000-000000000000"
poll_interval = "60s"
# TLS: exactly one of pin / ca_file; insecure_skip_verify = false by default
tls_pin_sha256 = "sha256:AB:CD:…"   # or ca_file = "/path/to/ca.pem"
# api_key from env DNSCRAFT_UNIFI_API_KEY or DNSCRAFT_UNIFI_API_KEY_FILE

[[clients.manual]]
name = "paperless"
ip = "198.51.100.5"

[[clients.manual]]
name = "Docker on server1"
cidr = "198.51.100.0/24"
```

## Testing

- Hand-written local HTTPS mock of the Integration API (sites, paginated
  clients, network details) — same style as the filtering HTTP test server.
  Fixtures are invented (`example.com` names, documentation IP ranges); **never**
  real captures from the owner's network.
- Table tests: precedence (manual IP > longer CIDR > shorter CIDR > UniFi),
  name normalisation, collision suffixes, VLAN longest-prefix assignment,
  offline retain / IPv6 TTL with a manual clock.
- Failure tests: connect refused, bad pin, 401, truncated JSON, empty site list,
  > max clients; last-good retained and `stale` set.
- No internet and no real UniFi endpoints in CI (SPEC.md Testing Strategy).
- Coverage: no hard threshold for this crate in SPEC.md; aim for ≥ 80 % of
  non-HTTP logic anyway.

## Boundaries

- Always: keep last good snapshot on sync failure; never block DNS on UniFi I/O;
  secrets only via env / `*_FILE`; treat UniFi JSON as untrusted (size caps per
  page, timeouts).
- Ask first: new dependencies; enabling the classic controller API; raising the
  10 000 client hard cap; default poll interval / local domain changes after
  approval.
- Never: default `insecure_skip_verify`; Docker socket access; real UniFi calls
  in tests; select profiles/views inside this crate.

## Success Criteria

1. With a mock UniFi server, sync builds indexes; `by_ip` / `by_name` / `reverse`
   match the precedence and normalisation rules above.
2. Gateway down: lookups still return the last good data with `stale = true` and
   a stable error code on status; no await on the lookup path.
3. Manual single IP overrides UniFi for the same address; longest manual CIDR
   wins among manuals.
4. TLS: pin mismatch fails closed with `clients.tls.untrusted`; skip-verify is
   opt-in only.
5. VLAN filled via network subnet match when prefixes are available; unknown
   when not.
6. Invented fixtures only; DoD gates (`fmt`, `clippy -D warnings`,
   `test --workspace`) green once implemented.

## Open Questions

Hand these to the owner before implementation / plan (P1):

1. **`local_domain` default** — propose `home.arpa` (RFC 8375). Prefer something
   else (e.g. `lan`, a real split-horizon zone under the public domain)?
2. **Poll interval** — propose 60 s. Faster (15–30 s) for snappier names, or
   slower (2–5 min) to be kinder to the gateway?
3. **Offline retain** — keep disconnected UniFi clients for PTR/log for 7 days?
   Or drop immediately when they leave *List Connected Clients*?
4. **IPv6 gap** — accept Integration API’s single `ipAddress` for v1, or approve
   an optional classic-API (`stat/sta`) reader for multi-address / richer fields?
5. **VLAN display** — show `name`, `id`, or `name (id)` in logs/UI?
6. **Site selection** — auto-pick when exactly one site, else require `site_id`?
7. **TLS bootstrap UX** — first-run: paste SHA-256 pin (from `openssl s_client`)
   vs upload CA vs temporary insecure (with loud warning) to fetch the pin?
8. **API key env name** — `DNSCRAFT_UNIFI_API_KEY` / `_FILE` OK?
9. **Last-good disk cache** — re-sync only on startup (simpler), or persist
   snapshot under `<data>/clients/` for offline boot before the first successful
   poll?
10. **Rate-limit behaviour** — on HTTP 429, backoff and keep last good (proposed).
    Any owner-measured local limit to honour proactively?

## Decisions

None yet — draft for owner review (2026-10-25).
