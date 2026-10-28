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
3. ACME challenge is **DNS-01** (no HTTP-01; the node may not be reachable on
   80 from the internet). Publication goes through the configured
   `dns_provider`: Cloudflare (automatic), `manual` (operator copies the TXT),
   or `none` (issuance fails with a clear code).
4. DDR (RFC 9462) answers are produced by `listeners`; this module only supplies
   the hostnames / certificate material those answers advertise.
5. Alerts (cert expiry, DynDNS failure) are surfaced as status fields **and**
   optionally delivered to an HTTPS webhook; `control-api` / web-ui render the
   status and own webhook dispatch (SPEC.md Alerts). SMTP/email is deferred.

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
- `tls_mode = manual` replaces ACME material with operator-uploaded
  leaf+key+chain (see **Manual certificate mode**); `source` in status records
  whether the served cert is `acme` or `manual`.
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

**Signing a node CSR (multi-node, `sign_csr`).** The master can also finalize an
order with a CSR it did not generate, so a sub-node keeps its own key
(SPEC-cluster § TLS certificate distribution). The same account, DNS-01 TXT
handling, propagation wait, rate-limit state and order progress apply. The
request may name only `dns.<public_domain>` and `*.dns.<public_domain>`; any
other name, a non-DNS SAN, or a request whose signature does not verify is
refused before an order starts (`tls.acme.order`). The chain is returned to the
caller only: the stored certificate, key and resolver are not changed. Orders
are serialized (one pending-order slot per account), so a node order waits for
an in-flight renewal and the reverse.

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
- `dns_provider.kind = "manual"`: the operator publishes the TXT value returned
  in `tls.dns.manual`; propagation polling is skipped (the CA still validates
  on finalize). `kind = "none"` fails before ordering.

### Resolved feature specifications (owner, 2026-10-27)

Each numbered item below resolves the correspondingly numbered Open Question
that appeared here before 2026-10-27. Config field, status field and error
codes are the cross-crate contract (`tasks/plan-tls-api-gaps.md` § B–E).

1. **Manual certificate mode (`tls_mode = manual`, Q1).**
   Config: `manual = { cert_pem, chain_pem, key_pem }` (key is `Secret`).
   API: `TlsEngine::upload_manual_cert(cert_pem, &Secret, chain_pem)` validates
   leaf/key/chain together, persists via the store (`key.pem` 0o600), installs
   atomically and records `meta.source = manual`. A bootstrap `manual` config is
   imported on open **only when the store has no certificate** (an API upload is
   never reverted by a restart). Status: `source: "acme" | "manual"`.
   Errors: `tls.cert.manual.invalid` (bad PEM, key/cert mismatch),
   `tls.cert.absent` (nothing stored).
2. **Certificate detail in `TlsStatus` (Q2).** Parsed from the leaf with
   `x509-parser` (DER already carried by rustls-pki-types): `not_before`,
   `issuer` (RFC 4514), `subject` (RFC 4514), `serial` (colon-separated
   upper-case hex), `signature_algorithm` (e.g. `ecdsa-with-SHA256`),
   `key_usage` (basic flags) and `chain` (`Vec<String>`, PEM blocks leaf-first).
   **Cert-only**: no private key ever appears in status, `Debug`, logs or export.
3. **Generic DNS provider / manual DNS-01 (Q3, Q20).**
   Config: `dns_provider = { kind = "cloudflare" | "manual" | "none",
   cloudflare = { zone_id }, zones = [{ name, zone_id }],
   manual_txt = { name, value } }`.
   `cloudflare` publishes TXT records through the API; `manual` requires the
   operator to publish the challenge value (issuance returns the required
   name/value in the error); `none` always fails ACME/DynDNS validation.
   Multi-zone: a record name resolves to the configured zone with the **longest
   suffix match**, falling back to `cloudflare.zone_id` / `public_domain`.
   DynDNS requires `kind = "cloudflare"`. Errors: `tls.dns.provider.auth`,
   `tls.dns.provider.zone`, `tls.dns.manual`.
4. **ARI renewal window in status (Q4).** `TlsStatus.ari =
   { suggested_window_start, suggested_window_end, certificate_id, supported }`,
   present when a certificate is stored; `supported` is true only when the CA
   returned both bounds. Renewal still picks a uniform instant in the window and
   sends `replaces`; ARI failures never fail renewal.
5. **ACME account management (Q5).** Config:
   `acme.account = { eab = { kid, hmac_key }, tos_agreed, auto_deactivate }`.
   Account creation requires `tos_agreed = true` and passes EAB when configured.
   `TlsEngine::acme_account_status()` returns `{ exists, directory,
   account_id, tos_agreed, eab_configured, auto_deactivate, deactivated }`
   (never the key). Account-key rollover uses `update_key` and rewrites
   `account.json`; deactivation removes it. `auto_deactivate = true` deactivates
   the account when ACME is turned off by config apply (best-effort). Errors:
   `tls.acme.account.eab`, `tls.acme.account.tos`,
   `tls.acme.account.rollover`.
6. **ACME order / progress status (Q6).** `TlsEngine::order_status()` returns
   `{ state: idle|pending|valid|invalid, identifiers, challenges = [{ identifier,
   txt_name, status }], next_attempt_at, last_error }`. There is one in-flight
   order per node (single-flight); a request to finish without one is
   `tls.acme.order_pending`.
7. **Rate-limit / quota visibility (Q7).** `TlsEngine::rate_limit_status()`
   returns `{ limited, retry_after, retry_at }` from the most recent attempt;
   `tls.acme.rate_limited` carries the structured `retry_after` (`Duration`)
   parsed from `Retry-After`, and the renew scheduler backs off at least that
   long (exponential, ±25 %, capped at 6 h).
8. **Issuance / renewal history (Q8).** `state.json` keeps the last **10**
   `IssueRecord { timestamp, outcome: issued|renewed|failed, error, serial }`;
   exposed as `TlsStatus.history` (oldest first). Successful attempts clear
   `last_error`; failures keep the previous certificate.
9. **Revocation (Q9).** `TlsEngine::revoke(reason)` maps `unspecified`,
   `key_compromise`, `ca_compromise`, `affiliation_changed`, `superseded`,
   `cessation_of_operation`, `certificate_hold`, `remove_from_crl`,
   `privilege_withdrawn`, `aa_compromise`. ACME-sourced certs are revoked at the
   CA; manual certs are revoked locally. The resolver is cleared, `state.json`
   records the reason, and `TlsStatus.revoked = true` with
   `last_error = tls.cert.revoked`; a restart does not serve a revoked cert.
   Unknown reasons → `tls.config.invalid`. A successful re-issue clears the flag.
10. **Key rotation / re-key (Q10).** `TlsEngine::rotate_key()` forces a new
    order with a freshly generated ECDSA key (same `key_type`) even when not
    due. Any failure is surfaced as `tls.cert.rotate.failed`; the old cert is
    kept. ACME-disabled nodes refuse rotation.
11. **Preflight / dry-run (Q11).** `TlsEngine::preflight()` is offline (never
    contacts the CA, Cloudflare or the echo service) and returns
    `{ ok, checks = [{ name, ok, code, message }] }` for: store health,
    certificate loadability, trust pin, ACME account (`exists || tos_agreed`)
    and DNS provider kind. `PreflightReport::into_result()` maps a failing
    report to `tls.acme.preflight.failed`.
12. **Certificate export (Q12).** `TlsEngine::export_cert()` returns the stored
    fullchain PEM (leaf first, certificates only). It refuses any bundle
    containing `PRIVATE KEY` and errors `tls.cert.absent` when nothing is stored.
13. **Bootstrap self-signed certificate status (Q13).** The self-signed
    fallback is installed by the caller before ACME succeeds; it is included in
    the same status fields (`not_before`, `not_after`, `days_to_expiry`,
    `serial`, `chain`) and is replaced atomically on the first successful issue.
    No separate fingerprint history is kept (only the current leaf).
14. **Trust pinning (Q14).** Config: `trust_pin = { sha256, pinned_at }`
    (64 hex chars; `:` separators and upper case are normalised). `preflight`
    compares the SHA-256 of the leaf DER (ring) and reports
    `tls.pin.mismatch`; a pin without a stored certificate also fails.
15. **Store health (Q15).** `TlsStatus.store = { path, writable, last_write,
    corrupt }`. Writability is probed with a private temp file in `<data>/tls/`;
    `last_write` is the newest mtime of `cert.pem`/`state.json`; `corrupt` means
    the stored ciphertext/PEM/key pair cannot be loaded
    (`tls.store.corrupt` / `tls.store.permissions`). Preflight surfaces
    `tls.store.unhealthy`.
16. **Per-node DynDNS API model (Q16).** `control-api` exposes
    `GET /api/v1/nodes` (minimal node list) and per-node `dyndns` under
    `/api/v1/tls`; the full node inventory and conflict rules remain delegated
    to `SPEC-cluster.md`. This crate keeps per-node `dyndns.hostname` and
    `dyndns.public_entry`.
17. **IPv6 stable identifier (Q17).** Config:
    `dyndns.ipv6_identifier = { mode = "eui64" | "stable_privacy" | "static",
    static_address }`. `static` publishes the configured address and rejects
    non-IPv6 values; `eui64` / `stable_privacy` use the OS-selected address
    (from the echo service, or from `dyndns.interfaces` when set). Errors:
    `tls.dyndns.ipv6`.
18. **DynDNS `stale` flag (Q18).** `TlsStatus.dyndns_stale` is `true` after a
    failed pass and cleared by the next success; it never touches the cert path.
19. **Next / last scheduled run (Q19).** `TlsStatus.next_renew_at` (from ARI or
    `not_after - renew_before`), `next_dyndns_at` (last pass + jittered
    interval) and `last_dyndns_success`.
20. **Multi-provider / multi-zone (Q20).** Satisfied by `dns_provider.zones`
    (longest-suffix resolution, deduplicated after normalisation); one token per
    provider. Cross-provider fan-out is out of scope.
21. **Managed record inventory (Q21).** Config `dyndns.record_inventory = true`.
    `TlsEngine::record_inventory()` lists the A/AAAA records for the managed
    names, each `{ name, record_type, content, managed, conflict }` where
    `conflict` marks duplicate name+type records. This is read-only (no
    adoption/cleanup in v1) and errors `tls.dns.provider.auth` when the provider
    is not Cloudflare.
22. **IP discovery details (Q22).** Config `dyndns.interfaces = []` (empty =
    public-IP echo). When non-empty, the first global IPv6 address on those
    interfaces is used (Linux `/proc/net/if_inet6`; link-local skipped).
    Interface names are trimmed and deduplicated; an empty name is a config
    error. If no address is found the pass fails with `tls.dyndns.ipv6`.
23. **TLS protocol/cipher policy for DNS listeners (Q23).** Owned by
    `SPEC-listeners.md` (L1/L2): `tls_policy = { min_version = "1.2"|"1.3",
    ciphersuites = [], alpn = ["h2","http/1.1"] }`, error
    `listeners.tls.policy`. This spec only supplies certificate material.
24. **Certificate distribution status (Q24).** Delegated to `SPEC-cluster.md`;
    per-node `cert_version`, `sync_lag` and `distribution_error` are specified
    there. No cluster code is added to `dnscraft-tls` in this pass.
25. **DynDNS audit trail (Q25).** Every write appends
    `{ timestamp, name, record_type, content }` to `state.json` (last 50),
    exposed by `TlsEngine::dyndns_audit()`; unchanged records produce no entry.
26. **Expiry / failure notifications (Q26).** Config:
    `notifications = { webhook_url, on_expiry, on_dyndns_failure }` (HTTPS only;
    loopback `http://` only behind the test hatch). Delivery is performed by
    `control-api` (A5) using this config; the TLS crate only exposes status.
    A failed delivery is `tls.notify.failed`. **SMTP/email is deferred** — no
    mail crate is added.

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
| `tls.cert.manual.invalid` | manual upload: bad PEM, key/cert mismatch, or unusable chain |
| `tls.cert.revoked` | status flag + `last_error` after a successful revocation |
| `tls.cert.rotate.failed` | forced re-key/re-issue failed (old cert kept) |
| `tls.cert.absent` | export/revoke requested with no stored certificate |
| `tls.acme.account.eab` | EAB missing, malformed, or rejected by the CA |
| `tls.acme.account.tos` | account creation without `tos_agreed = true` |
| `tls.acme.account.rollover` | account-key rollover failed or unsupported |
| `tls.acme.order_pending` | finish/abort requested with no in-flight order |
| `tls.acme.preflight.failed` | one or more preflight checks failed |
| `tls.store.unhealthy` | store not writable or corrupt (preflight/status) |
| `tls.dns.provider.auth` | DNS provider credentials missing / `kind = none` |
| `tls.dns.provider.zone` | no configured zone matches the record name |
| `tls.dns.manual` | manual DNS-01: operator must publish the TXT value |
| `tls.dyndns.ipv6` | static identifier invalid or no global address on the interfaces |
| `tls.pin.mismatch` | leaf SHA-256 differs from `trust_pin.sha256` |
| `tls.notify.failed` | webhook notification delivery failed (control-api) |

### Observability / alerts surface

`TlsStatus` (additive over the original fields): `not_after`, `not_before`,
`days_to_expiry`, `identifiers`, `issuer`, `subject`, `serial`,
`signature_algorithm`, `key_usage`, `chain`, `source`, `last_issue`,
`last_renew_attempt`, `history` (last 10), ACME directory (staging/prod),
`acme_enabled`, `ari`, `next_renew_at`, `next_dyndns_at`,
`last_dyndns_success`, `dyndns_stale`, `store` health, `revoked`, `last_error`
codes, DynDNS last IPv4/IPv6 and last change time. `TlsEngine` additionally
exposes `acme_account_status()`, `order_status()`, `rate_limit_status()`,
`record_inventory()`, `dyndns_audit()`, `preflight()` and `export_cert()`.
Metrics: days to expiry (gauge), renew success/fail counters, exposed in-process via
`TlsEngine::metrics() -> TlsMetrics` (no exporter yet; Prometheus output stays under SPEC.md "Later"). Web UI alert when
`tls.cert.expiring` / `tls.cert.revoked` / `tls.dyndns.update` / ACME failures
are set.

### Interface (sketch)

```rust
pub struct TlsEngine { /* config, store, CertResolver, tasks */ }

impl TlsEngine {
    pub fn open(config: TlsConfig, data_dir: &Path, clock: Arc<dyn Clock>) -> Result<Self, TlsError>;
    pub fn resolver(&self) -> Arc<CertResolver>;
    pub fn status(&self) -> TlsStatus;
    pub async fn apply_config(&self, config: TlsConfig) -> Result<(), TlsError>;

    // Unchanged signatures.
    pub async fn renew_now(&self) -> Result<(), TlsError>;
    pub async fn dyndns_now(&self) -> Result<DynDnsResult, TlsError>;

    // Added 2026-10-27 (spec gaps).
    pub async fn upload_manual_cert(
        &self, cert_pem: &str, key_pem: &Secret, chain_pem: &str,
    ) -> Result<(), TlsError>;
    pub async fn revoke(&self, reason: Option<&str>) -> Result<(), TlsError>;
    pub async fn preflight(&self) -> PreflightReport;
    pub async fn rotate_key(&self) -> Result<(), TlsError>;
    pub fn export_cert(&self) -> Result<String, TlsError>;
    pub async fn acme_account_status(&self) -> Result<AcmeAccountStatus, TlsError>;
    pub fn order_status(&self) -> AcmeOrderStatus;
    pub async fn rate_limit_status(&self) -> RateLimitStatus;
    pub async fn record_inventory(&self) -> Result<Vec<InventoryRecord>, TlsError>;
    pub async fn dyndns_audit(&self) -> Vec<DynDnsAuditEntry>;
    pub async fn metrics(&self) -> TlsMetrics;
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
directory = "production"               # or "staging" / custom URL
# contact email: required in the UI / first-run (admin fills it in)
email = "admin@example.com"
propagation_timeout = "2m"
propagation_poll = "5s"
[tls.acme.account]
tos_agreed = true                      # required to create an account
auto_deactivate = false                # deactivate when ACME is turned off
# eab = { kid = "...", hmac_key = "..." }  # when the CA requires EAB

# Operator-uploaded certificate (bootstrap; normally uploaded via the UI/API).
# [tls.manual]
# cert_pem = "-----BEGIN CERTIFICATE-----..."
# chain_pem = ""
# key_pem = "-----BEGIN PRIVATE KEY-----..."   # Secret; never logged/exported

# [tls.trust_pin]
# sha256 = "0123...ef"                 # leaf SHA-256, 64 hex chars
# pinned_at = "2026-10-27T00:00:00Z"

[tls.dns_provider]
kind = "cloudflare"                    # "cloudflare" | "manual" | "none"
[tls.dns_provider.cloudflare]
# token from DNSCRAFT_CLOUDFLARE_API_TOKEN / _FILE
# zone_id optional if resolvable by public_domain
zone_id = ""
# Additional zones, resolved by longest suffix match.
# zones = [{ name = "sub.example.com", zone_id = "..." }]
# Operator-published TXT for kind = "manual" (one entry per DNS-01 value; apex + wildcard need two):
# manual_txt = [
#   { name = "_acme-challenge.dns.example.com", value = "..." },
#   { name = "_acme-challenge.dns.example.com", value = "..." },
# ]

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
# interfaces = ["eth0"]                # empty = public-IP echo
# record_inventory = false             # enable GET /api/v1/tls/records
[tls.dyndns.ipv6_identifier]
mode = "eui64"                         # "eui64" | "stable_privacy" | "static"
# static_address = "2001:db8::10"      # required for mode = "static"

[tls.notifications]
# webhook_url = "https://hooks.example.com/dnscraft"   # HTTPS only
on_expiry = false
on_dyndns_failure = false
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

- Always: ring-only crypto features; last-good cert on failure (revoked certs
  are removed from the resolver and never re-served); secrets via env/`*_FILE`;
  private keys never in logs, status or exports; cert-only fullchain export;
  DNS-only DynDNS records; offline preflight (no external calls).
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
7. A manual upload validates leaf+key+chain, persists `key.pem` 0o600, exposes
   `source = manual`, and `export_cert` returns the fullchain without any key.
8. `revoke` clears the resolver, persists `revoked`, survives restart (not
   served again), and a later successful issue clears it.
9. `status` carries cert detail, ARI window, bounded history, scheduling,
   store health and `dyndns_stale`; `preflight` is fully offline.

## Decisions (2026-10-27)

Owner decision: **spec everything now**; all 26 former Open Questions are
resolved by the feature specifications above and implemented in
`crates/dnscraft-tls` (Phase 1, T1–T6). In order:

1. Manual certificate mode — specified (§ Resolved 1). `tls_mode = manual`.
2. Certificate detail — issuers/subject/validity/serial/sig-alg/key-usage/chain
   in `TlsStatus` (2), cert-only.
3. Generic DNS provider + manual DNS-01 (3); Cloudflare remains the automatic
   implementation.
4. ARI window/id/supported in `TlsStatus.ari` (4).
5. ACME account EAB/ToS/rollover/deactivate/auto-deactivate (5).
6. Order/progress status + `tls.acme.order_pending` (6).
7. Rate-limit `retry_after`/`retry_at` status (7).
8. Bounded (10) issue/renew history (8).
9. Revocation with reason + `tls.cert.revoked` (9).
10. Forced key rotation via `rotate_key` (10).
11. Offline preflight/dry-run report (11).
12. Certificate-only fullchain export (12).
13. Bootstrap self-signed cert uses the same status fields (13).
14. Trust pin (`trust_pin`) with `tls.pin.mismatch` (14).
15. Store health status + probe (15).
16. Per-node DynDNS API surface; full inventory delegated to SPEC-cluster (16).
17. IPv6 identifier `eui64`/`stable_privacy`/`static` (17).
18. `dyndns_stale` status field (18).
19. `next_renew_at` / `next_dyndns_at` / `last_dyndns_success` (19).
20. Multi-zone provider config (20).
21. Read-only record inventory with conflict flags (21).
22. Interface-based IPv6 discovery (22).
23. Listener TLS policy delegated to `SPEC-listeners.md` (23).
24. Cross-node certificate distribution delegated to `SPEC-cluster.md` (24);
    per-node `cert_version`/`sync_lag`/`distribution_error` specified there.
25. Bounded (50) DynDNS audit trail (25).
26. HTTPS webhook notification config; dispatch owned by control-api; SMTP
    deferred (no mail crate) (26).

Status: **approved by the owner 2026-10-27**; the 2026-10-25 decisions below
remain in force.

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
