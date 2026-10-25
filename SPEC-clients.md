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

**Decision for this module (owner, 2026-10-25):** use **both** local surfaces
behind the same gateway TLS + API key where possible:

| Role | API | Why |
|---|---|---|
| Sites, networks (VLAN id/name, IPv4/IPv6 prefixes) | Integration `/v1/…` | Official, stable schemas |
| Client inventory with **all addresses including IPv6** | Classic `…/api/s/{site}/stat/sta` (and `rest/user` for known/offline if needed) | Integration clients expose only singular `ipAddress`; owner wants complete IPv6 |

Classic JSON is undocumented and version-skewed: parse **defensively** (every
field optional, skip/log bad rows, never fail the whole sync on one client).
Map Integration site UUID ↔ classic site key (`default`, …) during sync; if
mapping fails, record `clients.config.invalid` / `clients.http.body` and keep
last good. Prefer `X-API-KEY` on the classic path when the console accepts it;
if a given OS build only accepts session cookies for classic, document that as
an implementation discovery and ask before adding username/password auth
(API-key-only remains the product goal).

Build/tests use hand-written mocks for **both** surfaces; never a real gateway.

#### VLAN derivation

Prefer classic `network_id` (or equivalent) joined to Integration/classic
network metadata when present. Fallback: longest-prefix match of each client
address against gateway-managed network prefixes from Integration details
(`hostIpAddress`/`prefixLength`, IPv6 subnets). If neither works, VLAN is
`None`.

### Polling and freshness

- Default poll interval: **60 s**, with ±10 % jitter like the filtering
  scheduler.
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
    pub dns_label: String,      // normalised single label
    pub local_domain: String,   // parent domain used for this client's FQDN (see below)
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
    pub domain_name: Option<String>, // per-network DHCP domain, if set (source UNVERIFIED, see Local domain)
}

pub struct ClientLookup { /* Arc snapshot + indexes */ }

impl ClientLookup {
    /// Hot path for query-log enrichment. Lock-free read of Arc; O(1) hash.
    /// Returns `Arc` (no deep clone on the hot path).
    pub fn by_ip(&self, ip: IpAddr) -> Option<Arc<ClientInfo>>;
    /// Forward local name: FQDN `<label>.<domain>` (case-insensitive), or bare
    /// label only when it is unambiguous across all local domains.
    pub fn by_name(&self, name: &str) -> Option<Arc<ClientInfo>>;
    /// PTR: IP → FQDN `<label>.<domain>` (same IP precedence as by_ip).
    pub fn reverse(&self, ip: IpAddr) -> Option<String>;
    /// Domains currently treated as "local" (snapshot; cheap clone).
    pub fn local_domains(&self) -> Arc<[String]>;
}
```

### Trait boundary (vs `policy`)

`policy` must not depend on this crate ([CAPABILITY-MAP.md](CAPABILITY-MAP.md)).
`ClientLookup` therefore exposes the same method set as policy’s
`ClientDirectory` trait; the **binary / `control-api`** adapts
`Arc<ClientLookup>` → `Arc<dyn ClientDirectory>` (thin wrapper). Do not put the
trait in a way that creates a `policy → clients` Cargo dependency.

**Naming:** UniFi/manual devices are `ClientInfo` (enrichment). DoH/DoT
**Client IDs** (`iphone-k7q2x9`) are a different identifier owned by
policy/control-api for profile selection — never confused with UniFi client
UUIDs.

### Local domain (dynamic)

FQDN = `<dns_label>.<local_domain>`. The parent domain is **not** a single fixed
string when UniFi already publishes one:

1. **Per-network UniFi DHCP domain** — use for clients on that network/VLAN.
   Different VLANs may have different domains. **Unverified:** a DHCP
   `domainName` field is **not** in the research table above and may not exist
   on the Integration network schemas. The likely source is the classic
   `rest/networkconf` `domain_name` field, also unverified until checked against
   a real (not mock) response at implementation time; if neither exists, step 1
   yields nothing and step 2 applies.
2. Else **config `local_domain`** (default `home.arpa`) — fallback when UniFi
   omits `domainName`, UniFi is disabled, or the client has no network match.
3. **DNScraft override** — if the admin sets `local_domain_mode = "config"` (or
   an explicit per-manual `domain`), that wins over UniFi for the affected
   names. Default mode is `unifi_then_config` (“use what is there”).

`local_domains()` returns the set of parents currently in use so `policy` knows
which queries are local-name candidates. Domains are normalised (lower-case,
no trailing dot; IDNA/UTS 46 for non-ASCII).

A local domain may be a **real public domain** (the UniFi DHCP domain can equal
the domain hosting `dns.<domain>`). `policy` therefore answers only names this
directory actually knows (`by_name`) and lets unknown names under a local domain
fall through to forwarding/recursion; special-use suffixes (`home.arpa`, `local`,
`lan`, `internal`) are handled there as NXDOMAIN
([SPEC-policy.md](SPEC-policy.md) pipeline step 2). `by_name` returns `None` for
unknown names and never invents one.

### Precedence (IP → client)

When building the IP index, later lower-priority sources lose collisions:

1. **Manual single IP** (exact host entry)
2. **Manual CIDR** — **longest prefix wins** among overlapping ranges
3. **UniFi** (classic + Integration snapshot)

Name collisions **within the same local_domain** after normalisation:
**first-seen wins**. The label assignment (`client id → dns_label`) is persisted
in the last-good disk cache; an existing client keeps its label across syncs and
restarts, and a newcomer whose label collides gets `{label}-{id_suffix8}`. Names
therefore do not flip when a client joins or a UniFi id sorts differently. The
same label under **different** domains is fine (`phone.iot.example.com` ≠
`phone.lan.example.com`). Manual entries that collide with UniFi on the same
FQDN: manual wins; the UniFi client is (re)labelled with the suffix as above.
Assignments of evicted clients are dropped with the client.

**IP conflicts** (two clients claim the same address, e.g. DHCP reuse while an
offline client is still retained, or a retained rotating IPv6 address), applied
after the source precedence above: an **online** client beats a retained-offline
one; among equals the one with the most recent `last_seen` wins; the loser’s
stale address is dropped from the IP index (the loser keeps its other
addresses). `reverse(ip)` follows the same winner.

### Name normalisation (DNS labels)

For the **left-most label** of `<device>.<local-domain>`:

1. Case-fold and compatibility-map with the `idna` crate’s UTS 46 mapping
   (already a workspace dependency; no new normalisation crate), then lower-case.
2. Spaces and underscores → `-`; strip characters outside `[a-z0-9-]`.
3. Collapse repeated `-`; trim leading/trailing `-`.
4. Empty result → `client` + short id suffix.
5. Labels longer than 63 octets: truncate on a hyphen boundary when possible,
   then append a short hash suffix to keep uniqueness.
6. IDNA: the label is ASCII after steps 2–5; the parent domain may be Unicode and
   is converted with UTS 46 when building the FQDN.

### IPv6 and rotating privacy addresses

- **Goal:** every IPv4 and IPv6 address UniFi knows for a client is indexed for
  `by_ip` / `reverse` (link-local may be ignored — see Decisions).
- Primary source: classic client objects (fields vary by controller version;
  accept arrays or singular fields defensively). Merge with Integration
  `ipAddress` when present so a single-address Integration row still works if
  classic is temporarily failing.
- Privacy addresses rotate: keep previously observed UniFi addresses for the
  same client id until `ipv6_address_ttl` (default **24 h**) after last
  observation, then drop them from the index so PTR/log enrichment survives
  brief rotations without unbounded growth.
- Never invent addresses that UniFi did not report.

### Offline / disconnected clients

When a UniFi client disappears from a successful sync, **retain** it for
`offline_retain` (default **7 d**) marked `online = false`, so PTR and log
filters keep working. Evict after the TTL. Classic `rest/user` may supply
known-but-offline rows; same retain/evict rules apply.

### Memory budget

| Scale | Expected | Budget |
|---|---|---|
| Home (~60 clients + containers) | tiny (≪ 1 MB indexes) | negligible vs 150 MB process RSS |
| Upper bound | **10 000** clients / addresses indexed | soft warn above 2 000; hard refuse apply above 10 000 with `clients.too_many` |
| Manual entries | ≤ 1 000 | config validation |

Indexes: `HashMap<IpAddr, ClientId>`, `HashMap<Fqdn, ClientId>` (full
`<label>.<domain>`, not bare label alone), `Arc<[Arc<ClientInfo>]>`.
**Last-good disk cache** under `<data>/clients/` (atomic write, treat as
untrusted) so restart serves enrichment before the first successful poll
(see Decisions); it also stores the persisted label assignments.

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
| `clients.ip.conflict` | informational: two clients claimed one IP; loser dropped from index (counter, not fatal) |
| `clients.name.collision` | reserved for validation surfaces that refuse ambiguous manuals (rare; usually auto-suffix) |

### Observability

`ClientsStatus`: `last_attempt`, `last_success`, `stale`, `client_count`,
`manual_count`, `unifi_count`, `address_count`, `last_error: Option<code()>`,
`poll_interval`. Cheap counters for sync successes/failures. Alerts surface
("UniFi unreachable") is owned by `control-api` / web-ui using these fields.

## Configuration excerpt (TOML, bootstrap only; normally edited in the UI)

```toml
[clients]
# Fallback parent domain when UniFi has no DHCP domainName for the client's network.
# Mode "unifi_then_config" (default): use UniFi per-VLAN domain when present.
# Mode "config": always use local_domain below (admin override).
local_domain = "home.arpa"
local_domain_mode = "unifi_then_config"
offline_retain = "7d"
ipv6_address_ttl = "24h"

[clients.unifi]
enabled = true
base_url = "https://192.0.2.1"     # documentation range; gateway address
# site_id optional: if omitted, use the sole site or fail with clients.config.invalid
site_id = "00000000-0000-0000-0000-000000000000"
poll_interval = "60s"
# classic client feed on by default (needed for full IPv6); Integration still used for sites/networks
classic_clients = true
# TLS: pin or ca_file; insecure_skip_verify = false by default
tls_pin_sha256 = "sha256:AB:CD:…"   # or ca_file = "/path/to/ca.pem"
# api_key from env DNSCRAFT_UNIFI_API_KEY or DNSCRAFT_UNIFI_API_KEY_FILE

[[clients.manual]]
name = "paperless"
ip = "198.51.100.5"
# optional domain = "…" overrides UniFi/fallback for this entry only

[[clients.manual]]
name = "Docker on server1"
cidr = "198.51.100.0/24"
```

## Testing

- Hand-written local HTTPS mocks for Integration **and** classic client feeds
  (sites, networks, `stat/sta`-shaped payloads with multiple IPv6 addresses) —
  same style as the filtering HTTP test server. Fixtures are invented
  (`example.com` names, documentation ranges `192.0.2.0/24`, `2001:db8::/32`);
  **never** real captures from the owner's network.
- Table tests: precedence (manual IP > longer CIDR > shorter CIDR > UniFi),
  name normalisation (UTS 46 case/compat mapping), first-seen label stability
  (existing client keeps its label when a colliding newcomer or a smaller id
  appears; assignment survives restart via the disk cache), collision suffixes,
  IP conflicts (online beats retained-offline; most recent `last_seen` among
  equals; loser’s address gone from `by_ip`/`reverse`), VLAN join / longest-prefix,
  per-VLAN UniFi `domainName` vs config fallback vs `local_domain_mode = "config"`,
  offline retain / IPv6 TTL with a manual clock, merge of classic multi-IPv6
  with Integration singular `ipAddress`.
- Failure tests: connect refused, bad pin, 401, truncated JSON, empty site list,
  classic parse skew (unknown fields), > max clients; last-good retained and
  `stale` set.
- No internet and no real UniFi endpoints in CI (SPEC.md Testing Strategy).
- Coverage: no hard threshold for this crate in SPEC.md; aim for ≥ 80 % of
  non-HTTP logic anyway.

## Boundaries

- Always: keep last good snapshot on sync failure; never block DNS on UniFi I/O;
  secrets only via env / `*_FILE`; treat UniFi JSON as untrusted; defensive
  classic parsing. HTTP defaults aligned with filtering: **30 s** timeout per
  request, **response size cap** (propose 8 MiB per page), HTTPS only to the
  gateway URL.
- Ask first: new dependencies (e.g. `unicode-normalization`, only if UTS 46
  proves insufficient for label folding); username/password cookie login if API-key-on-classic
  fails on real hardware; raising the 10 000 client hard cap; changing approved
  defaults below.
- Never: default `insecure_skip_verify`; Docker socket access; real UniFi calls
  in tests; select profiles/views inside this crate.

## Success Criteria

1. With mock Integration + classic servers, sync builds indexes; `by_ip` /
   `by_name` / `reverse` match the precedence and normalisation rules above.
2. A fixture client with several IPv6 addresses is reachable via `by_ip` /
   `reverse` for **each** of them (complete IPv6).
3. Two networks with different UniFi DHCP `domainName` values produce different
   FQDNs; missing `domainName` falls back to config `local_domain`.
4. Gateway down: lookups still return the last good data with `stale = true` and
   a stable error code on status; no await on the lookup path.
4a. Labels are stable: a later client with a colliding label never renames an
   existing one; two clients claiming one IP resolve to the online / most
   recently seen one.
5. Manual single IP overrides UniFi for the same address; longest manual CIDR
   wins among manuals.
6. TLS: pin mismatch fails closed with `clients.tls.untrusted`; skip-verify is
   opt-in only.
7. VLAN filled via network id join or subnet match when available; unknown when
   not.
8. Invented fixtures only; DoD gates (`fmt`, `clippy -D warnings`,
   `test --workspace`) green once implemented.

## Open Questions

None — owner accepted the proposed defaults (2026-10-25), with the explicit
preference for complete IPv6 via the classic client feed, and dynamic local
domain from UniFi when present.

## Decisions (owner, 2026-10-25)

1. **Local domain:** dynamic — prefer UniFi per-network DHCP `domainName` (source unverified, see Local domain) when
   present (`local_domain_mode = "unifi_then_config"`); else config
   `local_domain` default `home.arpa` (RFC 8375). Admin may force config-only
   or set a per-manual `domain`.
2. **Poll interval:** 60 s ±10 % jitter.
3. **Offline retain:** 7 days (`online = false`), then evict.
4. **IPv6:** complete — classic `stat/sta` (etc.) is **on by default**
   (`classic_clients = true`) to index all reported addresses; Integration
   remains for sites/networks and as a merge/fallback source.
5. **VLAN display:** `name (id)` in logs/UI (e.g. `IoT (40)`); structured fields
   stay separate (`vlan.id`, `vlan.name`).
6. **Site selection:** auto-pick when exactly one site; otherwise require
   `site_id`.
7. **TLS bootstrap UX:** first-run offers pin paste and CA file; optional
   temporary insecure fetch that **only** displays the pin for the admin to
   confirm (never silently leaves skip-verify on).
8. **API key env:** `DNSCRAFT_UNIFI_API_KEY` / `DNSCRAFT_UNIFI_API_KEY_FILE`.
9. **Last-good disk cache:** persist under `<data>/clients/` (atomic write like
   filtering `ListStore`) so restart serves names before the first successful
   poll; treat file as untrusted.
10. **HTTP 429:** exponential backoff, keep last good, surface
    `clients.http.status`; no proactive local QPS cap until measured.
11. **Link-local IPv6 (`fe80::/10`):** do **not** index (useless for DNS source
    identity across the LAN). ULA and GUA are indexed.
12. Spec status: **draft decisions locked**; formal “approved” for P1/plan still
    to be marked by the owner when ready (no code before that).
13. **Review 2026-10-25:** FQDN index keys; HTTP 30 s / 8 MiB caps; trait
    adapted by control-api (no `policy → clients` dep); disk last-good confirmed.
14. **Review 2026-10-25 (Claude):** label collisions are **first-seen wins**
    (assignment persisted in the disk cache) instead of smaller-id wins; IP
    conflicts resolved online > retained-offline > most recently seen; label
    folding uses `idna` UTS 46 (no `unicode-normalization` unless proven
    necessary); per-network DHCP domain source marked **unverified**
    (`rest/networkconf` `domain_name` likely); unknown names under a local domain
    are left to the normal pipeline (policy); `by_ip`/`by_name` return
    `Option<Arc<ClientInfo>>`, `local_domains()` returns `Arc<[String]>`.
