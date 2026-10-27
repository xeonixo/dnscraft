# Implementation Plan: TLS & control-api spec gaps

> Owner decision 2026-10-27: **spec everything now** (all 32 open questions) **and
> implement the code**. Sources: `SPEC-tls.md` § Open Questions (26),
> `SPEC-control-api.md` § Open Questions (6), `tasks/todo-web-ui-tls.md` § A.
> Existing ground truth: `crates/dnscraft-tls` and `crates/dnscraft-api` are
> already substantially built (TlsStatus, TlsMode acme|self_signed, self-signed
> bootstrap, `/api/v1/tls` CRUD, `renew_now`/`dyndns_now`).

## Overview

Resolve every "Open Questions" entry in the two specs into a specified feature
(requirements + config + status fields + error codes + endpoints) and implement
it in the owning crate. Parallelism is by **crate** (disjoint file ownership):
`dnscraft-tls`, `dnscraft-api`, `dnscraft-listeners`. The cross-crate contract
below is the single source of truth; each agent codes against it so the crates
integrate after all three land.

## Cross-crate contract (authoritative)

### A. `tls_mode`
`acme` | `self_signed` | `manual`. Added to control-api `TlsMode`; the `tls`
crate gains a `CertSource { Acme, Manual }` that control-api folds into `TlsMode`
with its self-signed fallback.

### B. Extended `dnscraft_tls::TlsStatus` (additive; `Option` unless noted)
- Cert detail (Q2): `not_before: Option<SystemTime>`, `issuer: Option<String>`
  (RFC 4514), `subject: Option<String>`, `serial: Option<String>` (colon-hex),
  `signature_algorithm: Option<String>`, `key_usage: Vec<String>`,
  `chain: Vec<String>` (fullchain PEM leaf-first, **cert-only, never key**).
- ARI (Q4): `ari: Option<AriStatus { suggested_window_start: Option<SystemTime>,
  suggested_window_end: Option<SystemTime>, certificate_id: Option<String>,
  supported: bool }>`.
- History (Q8): `history: Vec<IssueRecord { timestamp: SystemTime,
  outcome: IssueOutcome /* issued|renewed|failed */, error: Option<String>,
  serial: Option<String> }>` (bounded, last 10).
- Scheduling (Q19): `next_renew_at: Option<SystemTime>`,
  `next_dyndns_at: Option<SystemTime>`, `last_dyndns_success: Option<SystemTime>`.
- Store health (Q15): `store: Option<StoreHealth { path: String, writable: bool,
  last_write: Option<SystemTime>, corrupt: bool }>`.
- DynDNS (Q18): `dyndns_stale: bool`.
- Revocation (Q9): `revoked: bool` (+ error `tls.cert.revoked`).
- Source (Q1): `source: CertSource`.

### C. `dnscraft_tls::TlsConfig` additions
- `manual: Option<ManualCertConfig>` (Q1; PEM strings, key as `Secret`; persisted
  to files, `0o600`).
- `trust_pin: Option<TrustPin { sha256: String, pinned_at: SystemTime }>` (Q14).
- `acme.account: AcmeAccountConfig { eab: Option<Eab { kid, hmac_key }>,
  tos_agreed: bool, auto_deactivate: bool }` (Q5).
- `dns_provider: DnsProvider` (Q3/Q20) replacing hardcoded Cloudflare:
  `{ kind: "cloudflare"|"manual"|"none", cloudflare: CloudflareConfig,
  zones: Vec<ZoneConfig>, manual_txt: Option<ManualDns01Config> }`.
- `dyndns.ipv6_identifier: Ipv6Identifier { mode: "eui64"|"stable_privacy"|"static",
  static_address: Option<String> }` (Q17).
- `dyndns.interfaces: Vec<String>` (Q22; empty = public-IP echo).
- `dyndns.record_inventory: bool` (Q21).
- `notifications: NotificationsConfig { webhook_url: Option<String>,
  on_expiry: bool, on_dyndns_failure: bool }` (Q26; SMTP deferred).

### D. New `TlsEngine` methods (async where noted)
`upload_manual_cert(cert_pem,&key_pem: Secret,chain_pem)`, `revoke(reason)`,
`preflight() -> PreflightReport`, `rotate_key()`, `export_cert() -> String`
(fullchain, cert-only), `acme_account_status()`, `order_status()`,
`rate_limit_status()`, `record_inventory()`, `dyndns_audit()`; existing
`renew_now`/`dyndns_now`/`status`/`apply_config`/`resolver` unchanged.

### E. New error codes (`tls.*` in the tls crate)
`tls.cert.manual.invalid`, `tls.cert.revoked`, `tls.cert.rotate.failed`,
`tls.acme.account.eab`, `tls.acme.account.tos`, `tls.acme.account.rollover`,
`tls.acme.order_pending`, `tls.acme.preflight.failed`, `tls.store.unhealthy`,
`tls.dns.provider.auth`, `tls.dns.provider.zone`, `tls.dns.manual`,
`tls.dyndns.ipv6`, `tls.pin.mismatch`, `tls.notify.failed`.
`tls.acme.rate_limited` gains a `retry_after` param (Q7).

### F. New control-api endpoints (control-api crate)
| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/api/v1/tls/status` | viewer/admin | typed TLS DTO (§ B + `mode` + `fingerprint`) |
| PUT | `/api/v1/tls/certificate` | admin | manual cert upload (JSON PEM) → `tls_mode=manual` |
| GET | `/api/v1/tls/certificate` | admin | fullchain PEM export (cert-only) |
| POST | `/api/v1/tls/renew` | admin | trigger renewal (returns `{started:true}`) |
| POST | `/api/v1/tls/revoke` | admin | revoke + reason |
| POST | `/api/v1/tls/rotate` | admin | force re-issue (key rotation) |
| POST | `/api/v1/tls/preflight` | admin | dry-run / connectivity |
| POST | `/api/v1/tls/dyndns` | admin | trigger DynDNS update |
| GET | `/api/v1/tls/records` | admin | record inventory / check |
| GET | `/api/v1/tls/account` | admin | ACME account status |
| GET | `/api/v1/tls/order` | admin | order/progress status |
| GET | `/api/v1/tls/audit` | admin | DynDNS audit trail |

Per-node DynDNS (control-api Q5 / tls Q16): minimal `GET /api/v1/nodes` +
per-node `dyndns` under `/api/v1/tls`; full node inventory deferred to
`SPEC-cluster.md`.

### G. control-api typed status DTO
Extend `dnscraft_api::tls::TlsStatus` from `{ mode, fingerprint }` to the full
§ B schema plus `mode`/`fingerprint`; `GET /api/v1/tls/status` returns it, and
`GET /api/v1/status` embeds it.

### H. Listener TLS policy (Q23) — `dnscraft-listeners`
Add `tls_policy` to listener config: `min_version: "1.2"|"1.3"`,
`ciphersuites: Vec<String>` (optional), `alpn: Vec<String>` (default
`["h2","http/1.1"]`). Error `listeners.tls.policy`.

### I. Cross-cluster (spec-only, no code this pass)
Q24 cert distribution + Q16 full per-node inventory are written into
`SPEC-tls.md` § Multi-node / `SPEC-control-api.md` as specified, **delegated to
`SPEC-cluster.md`** (status fields: per-node `cert_version`, `sync_lag`,
`distribution_error`). No code: the cluster crate is out of scope.

## Task list

### Phase 1 — TLS crate (`dnscraft-tls` + `SPEC-tls.md`) — Agent T
- T1 status.rs/pem_util.rs: cert detail, ARI, history, scheduling, store health,
  stale, revoked, `CertSource` (Q2, Q4, Q8, Q15, Q18, Q19, Q9 status).
- T2 config.rs: manual cert, trust pin, acme account, dns_provider, ipv6 id,
  interfaces, record inventory, notifications (Q1, Q14, Q5, Q3, Q20, Q17, Q22,
  Q21, Q26 config).
- T3 acme.rs/issue.rs/renew.rs: account mgmt, order/progress, rate-limit params,
  revocation, key rotation, preflight, ARI internals (Q5, Q6, Q7, Q9, Q10, Q11, Q4).
- T4 dyndns.rs/cloudflare.rs/propagation.rs: generic provider + manual DNS-01,
  multi-zone, ipv6 identifier, record inventory, ip discovery, audit trail
  (Q3, Q20, Q17, Q21, Q22, Q25).
- T5 store.rs: manual cert persistence, history state, store health (Q1, Q8, Q15).
- T6 engine.rs + error.rs: wire the new methods and codes (Q1–Q26 surface).
- T7 SPEC-tls.md: replace § Open Questions with full sections + Decisions.

### Phase 2 — API crate (`dnscraft-api` + `SPEC-control-api.md`) — Agent A
- A1 api/tls_routes.rs: the 12 new endpoints (F).
- A2 tls.rs: full typed DTO + `TlsMode::Manual` (G).
- A3 error.rs: forward `tls.*` codes; add `control_api.*` where needed.
- A4 config_apply.rs: per-sub-block TLS apply/rollback diff (control-api Q6).
- A5 notifications: webhook dispatch on expiry/dyndns failure (Q26; SMTP deferred).
- A6 SPEC-control-api.md: endpoint table + DTO schema + resolve § Open Questions.

### Phase 3 — Listeners crate (`dnscraft-listeners` + `SPEC-listeners.md`) — Agent L
- L1 TLS policy config + application + validation + `listeners.tls.policy` (Q23).
- L2 SPEC-listeners.md: § TLS protocol/cipher policy.

### Checkpoints
- **After Phases 1–3:** `cargo fmt`, `cargo clippy -D warnings`,
  `cargo test --workspace`, `cargo tree -i aws-lc-rs` empty (no aws-lc),
  `cargo deny check` green. No real LE/Cloudflare/OIDC in tests.
- **Integration:** API crate compiles against the new TLS surface; `cargo test -p dnscraft-api`.

## Parallelization map

```
Agent T (dnscraft-tls)   ─┐
Agent A (dnscraft-api)   ─┼─ parallel: disjoint files, shared contract (§ above)
Agent L (dnscraft-listeners) ─┘
```
API depends on TLS types at compile time only — the contract fixes the shapes, so
all three author in parallel and the workspace is verified after they land.

## Risks
| Risk | Impact | Mitigation |
|---|---|---|
| Contract drift between T and A | compile failure | § B/D/E/F fixed above; agents read this file first |
| 26-feature scope in one TLS agent | shallow work | order T1–T7 by dependency; verify per-file with `cargo build -p dnscraft-tls` |
| `error.rs`/`status.rs`/`config.rs` contention | merge conflict | single owner (Agent T) for the tls crate's shared files |
| New deps (X.509 parsing, mail) | aws-lc/openSSL creep | use rustls-pki-types + ring digest only; no mail crate (SMTP deferred) |
