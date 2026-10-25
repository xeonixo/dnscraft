# Spec: tls

> Module id `tls` · crate `crates/dnscraft-tls` · depends on: nothing (uses `dnscraft-proto`
> only for optional DNS-01 propagation queries against Cloudflare nameservers)
> Project-wide decisions (stack, commands, style, boundaries, i18n): [SPEC.md](SPEC.md)

## Objective

Obtain, store, renew, and hot-reload TLS certificates for encrypted DNS listeners
(DoT / DoH / DoQ), and keep the public hostname’s A/AAAA records current (DynDNS).
Certificates cover `dns.<domain>` and `*.dns.<domain>` so Client-ID SNIs work.
This module does **not** bind sockets (that is `listeners`) and does **not** own
the Client-ID registry (that is `policy` / `control-api`); it exposes a cert
resolver and small helpers those modules call.

## Assumptions

1. `tls` is a library: configuration as Rust values; secrets
   (`DNSCRAFT_CLOUDFLARE_API_TOKEN` / `*_FILE`) from env / Docker secrets only.
2. Crypto stack matches the rest of the workspace: **rustls + ring**, no aws-lc
   (same decision as reqwest in filtering — see `tasks/archive/progress-2026-10.md`).
3. ACME challenge is **DNS-01** via Cloudflare only (no HTTP-01; the node may
   not be reachable on 80 from the internet).
4. DDR (RFC 9462) answers are produced by `listeners`; this module only supplies
   the hostnames / certificate material those answers advertise.
5. Alerts (cert expiry, DynDNS failure) are surfaced as status fields;
   `control-api` / web-ui render them (SPEC.md Alerts — UI only, no push/email).

## Requirements

### Research notes (with sources)

#### instant-acme

| Topic | Finding | Source |
|---|---|---|
| Crate | Async pure-Rust ACME (RFC 8555) client | [github.com/djc/instant-acme](https://github.com/djc/instant-acme/) |
| Version at research | **0.9.0** on main `Cargo.toml` (2026-10-25); docs.rs also lists 0.8.x — **pin the exact semver in the plan** after `cargo search` at implement time | [Cargo.toml](https://raw.githubusercontent.com/djc/instant-acme/main/Cargo.toml) |
| Default crypto | Feature `aws-lc-rs` is **default** | same |
| Ring | Feature `ring`; if both `ring` and `aws-lc-rs` are enabled, aws-lc wins — therefore depend with `default-features = false, features = ["hyper-rustls", "ring", …]` | [README features](https://github.com/djc/instant-acme/) |
| DNS-01 | Select `ChallengeType::Dns01`, use key-authorization DNS value, publish TXT at `_acme-challenge.<name>`, then mark challenge ready | crate docs / examples |
| Account persistence | Serialize/deserialize `AccountCredentials` (store under data dir, 0o600) | README |
| ARI (RFC 9773) | Supported via features `time` + `x509-parser`; `account.renewal_info(&cert_id)` → suggested window; ARI renewals are rate-limit exempt at Let’s Encrypt | [RFC 9773](https://www.rfc-editor.org/rfc/rfc9773.html); [LE rate limits — ARI](https://letsencrypt.org/docs/rate-limits/); instant-acme README |

#### Cloudflare DNS API

| Topic | Finding | Source |
|---|---|---|
| Auth | API **Token** `Authorization: Bearer …` | [Create API token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) |
| Scopes | Template **Edit zone DNS** → permission **Zone → DNS → Edit**, resource **Include → Specific zone → \<one zone\>** only | same |
| Create / update / delete | `POST/PUT/DELETE /zones/{zone_id}/dns_records` (and list/filter by name+type) | [Create DNS Record](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/) |
| ACME TXT | Create TXT `_acme-challenge.<hostname>` with the challenge value; short TTL (e.g. 120); delete after validation | same + ACME practice |
| DynDNS | Upsert A and/or AAAA for the public DoH/DoT hostname; **proxied = false** (DNS-only) so DoT/DoQ on 853 and origin DoH are not broken by HTTP proxying | design (Cloudflare orange-cloud is HTTP(S) proxy) |
| Public IP echo | Default `https://cloudflare.com/cdn-cgi/trace` (or `https://1.1.1.1/cdn-cgi/trace`); parse `ip=` line; IPv4 vs IPv6 via separate force-family fetches | [cdn-cgi endpoint](https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/); common DynDNS practice |
| Propagation check | After writing TXT, query **Cloudflare’s authoritative nameservers for the zone** (from NS records / zone API) for `_acme-challenge.…` TXT using `dnscraft-proto` (or a tiny UDP helper in this crate) — **not** a public recursive resolver | brief requirement; avoids cached negatives |

#### Let’s Encrypt

| Topic | Finding | Source |
|---|---|---|
| Production directory | `https://acme-v02.api.letsencrypt.org/directory` | LE docs |
| Staging directory | `https://acme-staging-v02.api.letsencrypt.org/directory` — separate accounts; untrusted roots | [Staging](https://letsencrypt.org/docs/staging-environment/) |
| Notable production limits | e.g. 50 certs / registered domain / 7 days; 5 certs / exact identifier set / 7 days; 5 failed authorizations / identifier / hour; ARI renewals exempt from all limits | [Rate limits](https://letsencrypt.org/docs/rate-limits/) (page updated 2026-08-05) |
| CI / tests | Prefer **Pebble** locally + mock Cloudflare; never hit real LE or Cloudflare in automated tests (SPEC.md) | [Staging — Pebble note](https://letsencrypt.org/docs/staging-environment/); SPEC.md Testing Strategy |

### Certificate set

- Names (**default and required every order**): exactly
  `dns.<public_domain>` and `*.dns.<public_domain>` (Client-ID hostnames/SNIs +
  node hostnames like `node1.dns.<public_domain>`). No extra SANs unless the owner
  later adds an explicit allow-list in config (empty by default).
- Key type: **ECDSA only** — `ecdsa_p256` (default) or `ecdsa_p384`. No RSA.
- One leaf + chain PEM on disk; private key separate file, never logged, never
  included in config export/backup (SPEC.md).
- Staging switch: `acme.directory = "staging" | "production" | <url>` for tests.
- Same certificate set is shared by **all** encrypted listeners (DoT/DoH/DoQ,
  ports 443 and 853).

### Issuance and renewal

1. Ensure ACME account exists (persist credentials under `<data>/tls/account.json`, 0o600).
2. New order for the identifier set; for each DNS-01 challenge: create Cloudflare
   TXT → wait until authoritative NS serves the value (timeout + backoff) →
   ready → finalize → download chain. For the wildcard name, the challenge host
   is `_acme-challenge.dns.<public_domain>` (RFC 8555 / CA practice — not a
   label under `*`). Both apex and wildcard challenges must succeed in the same
   order. Delete TXT records after validation (best-effort; orphan cleanup on
   next run).
3. Renewal: prefer **ARI** suggested window when the CA supports it; else renew
   when `not_after - now < renew_before` (default **30 days**).
4. Retry/backoff on transient errors (HTTP 503/`Retry-After`, Cloudflare 429,
   propagation timeout): exponential backoff with jitter, cap, and
   `tls.acme.*` / `tls.cloudflare.*` error codes on status. Never delete the
   last good cert on a failed renewal.
5. After success: atomic store write + hot-reload into the shared cert resolver.

### Certificate store

- Directory `<data>/tls/` mode **0o700**; files **0o600**.
- Layout (illustrative): `account.json`, `cert.pem`, `key.pem`, `meta.json`
  (not_after, identifiers, ari id), `state.json` (last_error code, last issue / renew attempt;
  written even before the first certificate exists).
- Writes: temp file + `fsync` + rename (same pattern as filtering `ListStore`).
- On startup: load last good cert even if ACME/Cloudflare are unreachable so
  listeners can still serve (possibly with a soon-expiring cert + alert).

### Hot reload and listener integration

```rust
/// Shared rustls server cert resolver; listeners clone Arc.
pub struct CertResolver { /* RwLock<Arc<CertifiedKey>> (workspace pattern; no ArcSwap dependency) */ }

impl rustls::server::ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>>;
}

/// Labels that are never Client IDs: configured node names (`node1`, …) plus a
/// fixed set (`dns`, `www`, `api`, `admin`, `ns`). Built from config; cheap to clone.
pub struct ReservedLabels { /* HashSet<String> */ }
impl ReservedLabels {
    pub fn new(node_names: impl IntoIterator<Item = String>) -> Self;
    pub fn contains(&self, label: &str) -> bool;
}

pub enum SniKind {
    ClientId(String), // "<id>.dns.<public_domain>", <id> not reserved; always lower-cased
    NodeHostname,     // "<reserved>.dns.<public_domain>" (e.g. node1)
    Apex,             // "dns.<public_domain>"
    Other,            // anything else / not under the domain
}

/// SNI helpers for listeners (Client ID registry is elsewhere).
pub fn parse_client_id_sni(sni: &str, public_domain: &str,
                           reserved: &ReservedLabels) -> SniKind;

pub trait ClientIdRegistry: Send + Sync {
    fn is_registered(&self, client_id: &str) -> bool;
}

/// Hook for public listeners: unknown/missing Client ID → reject handshake.
/// Implemented by combining parse_client_id_sni + ClientIdRegistry.
/// `NodeHostname` / `Apex` carry no Client ID: a public source is rejected, but
/// the listener must not count it as an *unknown Client ID* (no ban strike).
pub fn accept_public_sni(
    sni: Option<&str>,
    public_domain: &str,
    reserved: &ReservedLabels,
    registry: &dyn ClientIdRegistry,
) -> bool;
```

- Apex `dns.<domain>` may be used for LAN DDR / non–Client-ID DoT; public
  internet exposure still requires a registered Client ID (SPEC.md Internet
  exposure) — listeners enforce that policy; `tls` only provides the predicate
  helper.
- **Addressing vs SNI (differs by protocol):**
  - **DoH:** the client connects to the **node hostname** (`node1.dns.<domain>`,
    A/AAAA from DynDNS); the Client ID is in the path (`/dns-query/<id>`). SNI is
    the node hostname.
  - **DoT/DoQ** (e.g. Android “Private DNS”): the one configured hostname is both
    the name the client **resolves** and the TLS **SNI**, so it is
    `<client-id>.dns.<domain>` and **must have an A/AAAA record**. The
    wildcard records `*.dns.<domain>` / `dns.<domain>` (see DynDNS) point every
    Client-ID hostname at the public entry node.
  The wildcard cert covers all of these. `ClientIdRegistry`
  (policy/control-api) is the single source of truth for “registered”.
- **Reserved labels:** node hostnames (`node1.dns.<domain>`, …) share the
  namespace with Client IDs. Labels equal to a configured node name or to the
  fixed set `dns`, `www`, `api`, `admin`, `ns` are **reserved** (explicit list,
  not a `node*` prefix rule, so legitimate IDs are not caught). They parse as
  `NodeHostname`, never as a Client ID, and Client-ID registration
  (policy/control-api) must reject IDs that collide with a reserved label
  (`ReservedLabels` is the shared helper).
- Reloading swaps the `CertifiedKey` under the resolver without dropping
  existing connections (new handshakes see the new cert).
- Reuse workspace **reqwest** (rustls+ring) for Cloudflare and the IP echo;
  no second HTTP stack. Avoid DynDNS updates while an ACME challenge TXT is
  in flight (serialize Cloudflare writers).

### Multi-node

- **Who renews:** the **master** only obtains/renews the ACME certificate.
  Sub-nodes never create ACME orders while they know a master exists.
- **Distribution:** the master **pushes the certificate and private key** to
  sub-nodes over the cluster channel so every node can terminate TLS for
  `*.dns.<public_domain>`. Protocol, encryption, and conflict rules belong in
  **SPEC-cluster.md**. Until cluster exists, interim: only the master needs a
  live ACME path; sub-nodes load whatever was last synced/copied.
- **DynDNS:** **per-node hostname** under the wildcard, e.g.
  `node1.dns.<public_domain>`, `node2.dns.<public_domain>` — each public node
  updates **only its own** A/AAAA. No shared single record contended by peers.
  In addition, exactly one node is the **public entry node**
  (`dyndns.public_entry = true`, at most one in v1; config validation rejects
  two) and maintains the wildcard records `*.dns.<public_domain>` and
  `dns.<public_domain>` (A/AAAA, DNS-only). Every Client-ID hostname therefore
  resolves to that node (explicit `<node>.dns.…` records take precedence over
  the wildcard). Client-ID hostnames work on any node that has the cert; DoH
  profiles / DDR may point at a specific node hostname. Multiple public entry
  nodes (geo, failover) are out of scope for v1 — future work for SPEC-cluster.
- Public DoH/DoT remains **per-node, off by default** (SPEC.md).

### DynDNS

- Lives **inside this module** (not a separate crate) — same Cloudflare token
  and zone as ACME.
- Interval: default **5 minutes**, ±10 % jitter; also on startup and on
  “update now”.
- Discover public IPv4 and IPv6 **separately** (echo URL configurable; default
  Cloudflare `cdn-cgi/trace`).
- Compare to the current Cloudflare record content; **PATCH/PUT only on change**.
- Records: DNS-only (`proxied: false`), TTL automatic or 300; hostname is the
  **node’s** public name (see Multi-node). On the public entry node, the same
  discovered IPs also drive the wildcard `*.dns.<public_domain>` and apex
  `dns.<public_domain>` records (same compare-then-update rule). A node without
  `public_entry` never touches them.
- Failures set `stale`/error codes without touching the certificate path.

### ACME DNS-01 propagation

- After writing `_acme-challenge` TXT, poll the zone’s Cloudflare authoritative
  nameservers every **5 s** until the expected TXT appears or **2 minutes**
  elapse → then `tls.acme.propagation`.

### Error codes

| Code | When |
|---|---|
| `tls.config.invalid` | bad domain, empty SANs, missing pin-equivalent for CF not applicable, etc. |
| `tls.secret.missing` | Cloudflare token env/`*_FILE` absent when ACME or DynDNS enabled |
| `tls.acme.account` | account create/load failed |
| `tls.acme.order` | new-order / finalize failed |
| `tls.acme.challenge` | DNS-01 ready/validation failed |
| `tls.acme.rate_limited` | LE rate limit / Retry-After |
| `tls.acme.propagation` | TXT not visible on authoritative NS before timeout |
| `tls.cloudflare.http` | Cloudflare API non-success (incl. 401/403/429) |
| `tls.cloudflare.zone` | zone id / name resolution failed |
| `tls.store.io` | disk read/write/permissions |
| `tls.store.corrupt` | PEM/meta unreadable; keep previous if any |
| `tls.dyndns.echo` | public IP echo failed / unparseable |
| `tls.dyndns.update` | A/AAAA upsert failed (node, wildcard, or apex record) |
| `tls.dyndns.entry_conflict` | more than one node claims `public_entry` (config/cluster validation) |
| `tls.cert.expiring` | status flag when days-to-expiry below warn threshold (default 14 d) |
| `tls.cert.expired` | not_after in the past |

### Observability / alerts surface

`TlsStatus`: cert `not_after`, `days_to_expiry`, identifiers, `last_issue`,
`last_renew_attempt`, ACME directory (staging/prod), DynDNS last IPv4/IPv6 and
last change time, `last_error` codes. Metrics: days to expiry (gauge), renew
success/fail counters. Web UI alert when `tls.cert.expiring` /
`tls.dyndns.update` / ACME failures are set.

### Interface (sketch)

```rust
pub struct TlsEngine { /* config, store, CertResolver, tasks */ }

impl TlsEngine {
    pub fn open(config: TlsConfig, data_dir: &Path, clock: Arc<dyn Clock>) -> Result<Self, TlsError>;
    pub fn resolver(&self) -> Arc<CertResolver>;
    pub fn status(&self) -> TlsStatus;
    pub async fn apply_config(&self, config: TlsConfig) -> Result<(), TlsError>;
    pub async fn renew_now(&self) -> Result<(), TlsError>;
    pub async fn dyndns_now(&self) -> Result<(), TlsError>;
}
```

## Configuration excerpt (TOML, bootstrap only; normally edited in the UI)

```toml
[tls]
public_domain = "example.com"          # cert SANs: dns.example.com + *.dns.example.com
extra_sans = []                        # empty by default; not used unless explicitly set later
key_type = "ecdsa_p256"                # or "ecdsa_p384"
renew_before = "30d"
expiry_warn = "14d"

[tls.acme]
directory = "production"               # or "staging"
# contact email: required in the UI / first-run (admin fills it in)
email = "admin@example.com"
propagation_timeout = "2m"
propagation_poll = "5s"

[tls.cloudflare]
# token from DNSCRAFT_CLOUDFLARE_API_TOKEN / _FILE
# zone_id optional if resolvable by public_domain
zone_id = ""

[tls.dyndns]
enabled = true
# reserved (non-Client-ID) labels besides the fixed set; usually the cluster's node names
reserved_labels = ["node1", "node2"]
# per-node public hostname under the wildcard (not shared across nodes)
hostname = "node1.dns.example.com"
# exactly one node: also maintains *.dns.example.com and dns.example.com
public_entry = false
interval = "5m"
echo_url = "https://cloudflare.com/cdn-cgi/trace"
ipv4 = true
ipv6 = true
proxied = false
```

## Testing

- **Pebble** as ACME server + **hand-written mock Cloudflare API** (create/list/delete
  DNS records) + optional mock authoritative DNS for propagation.
- Unit tests: SNI Client-ID parse (incl. reserved labels / node hostname /
  apex) / `accept_public_sni`, wildcard-record upsert only on the
  `public_entry` node, PEM store atomic replace,
  DynDNS “only update on change”, ARI window scheduling with manual clock.
- Never call real Let’s Encrypt, Cloudflare, or `cdn-cgi/trace` in CI (SPEC.md).
- Staging directory may be used in **manual** acceptance only.

## Boundaries

- Always: ring-only crypto features; last-good cert on failure; secrets via env/
  `*_FILE`; private keys never in logs or exports; DNS-only DynDNS records.
- Ask first: new dependencies (no ArcSwap — `RwLock<Arc<_>>`) beyond `instant-acme` (ring features), `rustls`,
  existing `reqwest`; adding non-empty `extra_sans`; changing master-only renew
  or per-node DynDNS.
- Never: aws-lc; RSA keys; default insecure TLS to Cloudflare/ACME; real external
  APIs in automated tests; register Client IDs inside this crate.

## Success Criteria

1. Against Pebble + mock Cloudflare, issue a cert for `dns.example.com` and
   `*.dns.example.com`, persist it, and serve it from `CertResolver`.
2. Renewal keeps last good cert if ACME fails; status shows a stable error code.
3. DynDNS updates A/AAAA only when the echo IP differs; failures are isolated
   from the cert path.
4. `accept_public_sni` rejects unknown Client IDs and accepts registered ones for
   `*.dns.<domain>`; a node-hostname SNI (e.g. `node1.dns.example.com`) is
   classified `NodeHostname`, not as an unknown Client ID.
4a. With `public_entry = true`, DynDNS creates `*.dns.example.com` and
   `dns.example.com` A/AAAA on the mock Cloudflare, so a Client-ID hostname
   resolves to the node; with `public_entry = false` those records are never
   touched; two entry nodes are rejected (`tls.dyndns.entry_conflict`).
5. Feature flags on `instant-acme` do not pull aws-lc into the workspace
   (`cargo tree -i aws-lc-rs` empty).
6. DoD gates green once implemented.

## Open Questions

None — owner decisions locked 2026-10-25.

## Decisions (owner, 2026-10-25)

1. **SANs:** default (and every order) is exactly `dns.<domain>` and
   `*.dns.<domain>`; `extra_sans` stays empty unless explicitly extended later.
2. **Keys:** ECDSA only — P-256 (default) and P-384 selectable; **no RSA**.
3. **DynDNS:** stays **inside `tls`** (not a separate module/crate). Q3 was only
   “where does the code live?” — answered: same crate as ACME/certs.
4. **Multi-node DynDNS:** **per-node hostname** (e.g. `node1.dns.<domain>`), each
   node updates only its own A/AAAA.
5. **Renewal:** master only; master **pushes cert+key to sub-nodes** (SPEC-cluster
   for the channel).
6. **ACME email:** admin **fills it in** (required in UI / first-run).
7. **Propagation:** 2 minutes timeout, 5 s polls — accepted as sensible.
8. **Order identifiers:** always apex + wildcard together.
9. **Listeners:** one cert set for all encrypted listeners (443 and 853).
10. Spec status: **approved by the owner 2026-10-25** (incl. the Claude review corrections).
11. **Review 2026-10-25:** wildcard DNS-01 at `_acme-challenge.dns.<domain>`;
    node hostname ≠ Client-ID SNI documented; shared reqwest; serialize CF writes.
12. **Review 2026-10-25 (Claude):** DoT/DoQ hostname == SNI, so Client-ID
    hostnames must resolve; DoH-only claim of “connect to node hostname, ID in
    SNI” corrected. DynDNS on the single **public entry node**
    (`dyndns.public_entry`) maintains `*.dns.<domain>` and `dns.<domain>`;
    multiple entry nodes deferred to SPEC-cluster. Node names + a fixed set
    (`dns`, `www`, `api`, `admin`, `ns`) are **reserved labels** (`ReservedLabels`,
    `SniKind`); Client-ID registration rejects collisions. `CertResolver` uses
    `RwLock<Arc<CertifiedKey>>`, no ArcSwap.
