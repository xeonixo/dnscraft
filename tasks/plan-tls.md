# Implementation Plan: `tls` module

> Spec: [SPEC-tls.md](../SPEC-tls.md) · Project spec: [SPEC.md](../SPEC.md) ·
> Tasks: [todo-tls.md](todo-tls.md) · Resume log: [progress.md](progress.md) ·
> Shared decisions for all three plans: [plan-policy.md § Cross-module decisions](plan-policy.md#cross-module-decisions)

## Overview

Build `crates/dnscraft-tls`, a library with these parts:
- **SNI helpers** for the listeners: `ReservedLabels`, `SniKind`, `accept_public_sni`.
- **Certificate store** with a hot-reloadable `CertResolver`.
- **ACME DNS-01 issuance and renewal** through `instant-acme` (ring), with Cloudflare TXT records
  and a propagation check against the zone's authoritative nameservers.
- **DynDNS** for the node hostname. The public entry node also maintains the wildcard and apex
  records.

All of it runs behind a `TlsEngine` with status fields. The crate does not bind sockets and
does not own the Client-ID registry.

## Architecture Decisions

- **ACME behind a trait.** The issuance flow talks to an internal `AcmeDirectory` /
  `AcmeOrder` trait pair.
  - Production implements it with `instant-acme`.
  - Unit tests use a fake, so the order/challenge/TXT/finalize logic is tested without Pebble.
  - Pebble only proves the real wiring, in one `#[ignore]` integration test. Running it in CI is
    an owner decision (open question 2).
- **One HTTP stack.** Prefer instant-acme's `HttpClient` trait implemented over the workspace
  reqwest (rustls + ring, webpki roots). Then `hyper-rustls` is not enabled and no second TLS
  stack or root store exists.
  - L4 is a spike that proves this first.
  - If the trait cannot be implemented cleanly on 0.8.5, fall back to the `hyper-rustls` +
    `ring` features. The roots must then be webpki, because the container has no system store.
    Owner sign-off at Checkpoint A.
- **Both challenges share one TXT name.** Apex and wildcard both validate at
  `_acme-challenge.dns.<domain>`. Both TXT records are created before either challenge is set
  ready, and the propagation check waits for **both** values (RFC 8555 §8.4 allows several TXT
  values at one name).
- **Keys and CSR.**
  - `rcgen` (ring) generates the ECDSA P-256/P-384 key and the CSR. A fresh key on every
    issuance and renewal.
  - The private key is written 0600 and never logged.
  - `Debug` of key-holding types is redacted.
- **Store.** `<data>/tls/` (0700):
  - `account.json`, `cert.pem` (leaf + chain), `key.pem`;
  - `meta.json` (identifiers, `not_after`, ARI cert id, last error);
  - atomic writes like filtering's `atomic_write`.
  - `not_after` is read from the certificate itself (`x509-parser`). `meta.json` is a cache and
    is never trusted over the certificate.
- **`CertResolver`.** `RwLock<Arc<CertifiedKey>>`, keys loaded via the rustls ring provider.
  `import(chain, key)` is public so the future cluster can push a certificate.
- **Cloudflare writers serialised.** One `tokio::sync::Mutex` guards record writes, so DynDNS
  never writes while a challenge TXT is in flight.
- **Master-only renewal** is a config flag (`acme.enabled`). `cluster` sets it later. A node
  with ACME disabled only loads and imports certificates.
- **Propagation check.**
  - The nameserver names come from the Cloudflare zone details (`name_servers`).
  - They resolve to addresses through `tokio::net::lookup_host` once per issuance.
  - TXT queries go over UDP with `dnscraft-proto`, poll 5 s, timeout 2 min (injectable clock
    and sleeper).
- **DynDNS family forcing.** The IPv4 echo uses a reqwest client bound to `0.0.0.0`, the IPv6
  echo one bound to `::`. A family without a route is skipped and reported, and does not count
  as an error.
- **Clock.** The crate has its own small `Clock` trait (same shape as the other crates). Renewal,
  backoff and DynDNS scheduling are tested with `ManualClock`.

## Dependencies (need approval — one table for all three plans)

See [plan-policy.md § Dependencies](plan-policy.md#dependencies-need-approval--all-three-plans).
This module needs:

| Crate | Kind | Why |
|---|---|---|
| `instant-acme` 0.8.5, `default-features = false`, features `ring`, `rcgen`, `time`, `x509-parser` (+ `hyper-rustls` only as the L4 fallback) | normal | RFC 8555 client, ARI |
| `rustls` 0.23 (ring) | normal | `CertResolver`, `CertifiedKey` |
| `rcgen` 0.14, `default-features = false`, features `ring`, `pem` | normal | key + CSR (also pulled by instant-acme's `rcgen` feature) |
| `x509-parser` 0.18 | normal | `not_after` of stored and imported certificates (also pulled by instant-acme) |
| `rustls-pki-types` 1, feature `std` (PEM via `PemObject`) | normal | PEM parsing without `rustls-pemfile` (already used by testkit) |
| `tokio-rustls` 0.26 | dev | handshake test against `CertResolver` |

Already in the workspace: reqwest, tokio, serde, serde_json, thiserror, tracing, ring, dnscraft-proto.
Gate in every task touching dependencies: `cargo tree -i aws-lc-rs` and `cargo tree -i openssl-sys` print nothing.

## Dependency graph

```
L1 skeleton, config, errors, secrets
   ├── L2 SNI helpers (pure; listeners need it)
   ├── L3 store + CertResolver
   └── L4 instant-acme spike (risk, early) ──┐
                                             │
L5 Cloudflare client ── L6 propagation check │
            └──────────────┬─────────────────┘
                     L7 issuance flow
                           │
                     L8 renewal scheduler (ARI, backoff, expiry status)
                           │
L9 DynDNS (needs L5) ── L10 TlsEngine ── L11 polish
```

## Task List

### Phase 1: Foundation
- [x] L1: Crate skeleton, config, errors, secrets
- [ ] L2: SNI helpers
- [ ] L3: Certificate store and `CertResolver`
- [ ] L4: instant-acme wiring spike (ring, reqwest `HttpClient`, account persistence)

### Checkpoint A: Foundation
- [ ] `cargo tree -i aws-lc-rs` empty; Pebble account test passes locally; HTTP-stack decision recorded; lead review

### Phase 2: Issuance
- [ ] L5: Cloudflare DNS client + mock
- [ ] L6: Propagation check against the authoritative NS
- [ ] L7: Issuance flow (apex + wildcard, two TXT values, finalize, store, reload)
- [ ] L8: Renewal scheduler (ARI / `renew_before`, backoff, expiry status)

### Checkpoint B: Issuance
- [ ] Fake-ACME tests + Pebble (`--ignored`) issue and renew; last good kept on failure; lead review

### Phase 3: DynDNS and engine
- [ ] L9: DynDNS (node record, public entry wildcard/apex, only on change)
- [ ] L10: `TlsEngine` (open, apply_config, renew_now, dyndns_now, status, lifecycle)
- [ ] L11: Polish: README (token scope, Pebble how-to), coverage, docs

### Checkpoint C: Complete
- [ ] All spec success criteria; security review (key handling, file modes, logs); **owner approval**

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| instant-acme pulls aws-lc or a second TLS stack | High (boundary) | L4 first; `default-features = false`; `cargo tree` gate in each task; reqwest `HttpClient` adapter. |
| The two TXT values at one name are mishandled (overwrite instead of add) | High (wildcard order fails) | Explicit test in L5/L7: the mock Cloudflare holds 2 TXT records at one name; the propagation check needs both. |
| Pebble not available in CI | Med | Fake-ACME unit tests cover the logic; the Pebble test is `#[ignore]` with a documented `docker run`; a CI job only if the owner approves. |
| Let's Encrypt rate limits during manual acceptance | Med | Manual runs use `directory = "staging"` first; ARI renewals are exempt; backoff with jitter. |
| IPv6 echo on hosts without IPv6 | Low | Skip the family, report it in status, no error code. |
| Key material leaking into logs or exports | High | Redacted `Debug`, 0600 files, a test that greps the formatted status and errors for the PEM header. |

## Open Questions

See [plan-policy.md § Open questions](plan-policy.md#open-questions-for-the-owner) (dependency approval, Pebble in CI).
