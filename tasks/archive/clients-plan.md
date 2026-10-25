# Implementation Plan: `clients` module

> Spec: [SPEC-clients.md](../../SPEC-clients.md) · Project spec: [SPEC.md](../../SPEC.md) ·
> Tasks: [clients-todo.md](clients-todo.md) · Resume log: [progress.md](../progress.md) ·
> Shared decisions for all three plans: [plan-policy.md § Cross-module decisions](../plan-policy.md#cross-module-decisions)

## Overview

Build `crates/dnscraft-clients`. It is a library that turns manual names and UniFi data into an
`Arc` snapshot. The snapshot answers `by_ip`, `by_name`, `reverse` and `local_domains`. UniFi
data comes from the official Integration API (sites, networks) and the classic `stat/sta` feed
(all client addresses, including IPv6). A background task syncs every 60 s. On a sync failure
the last good snapshot stays in use, and it survives restarts through a disk cache. The crate
never selects profiles, and it never blocks DNS on I/O.

## Architecture Decisions

- **Pure core, thin I/O.** All rules live in one pure function, and the HTTP code only produces
  its input:
  `build(manuals, unifi_observations, previous_state, config, now) -> (ClientLookup, State)`.
  - The rules are precedence, first-seen labels, IP conflicts, offline retention, IPv6 TTL,
    VLAN and domain derivation.
  - `UnifiObservation` is a normalised, source-independent row.
  - So every rule is table-testable without a server.
- **Snapshot.**
  - `ClientLookup` holds `Arc<[Arc<ClientInfo>]>` plus `HashMap<IpAddr, u32>` (exact IPs:
    manual single IPs and UniFi addresses) and `HashMap<Fqdn, u32>`.
  - Manual CIDRs (≤ 1 000) sit in a vector sorted by prefix length, longest first.
  - `by_ip` checks the exact map for a manual IP, then the CIDR vector, then UniFi.
  - The engine holds `RwLock<Arc<ClientLookup>>`, the workspace pattern (no ArcSwap).
- **`ClientInfo.addresses` is `Arc<[IpAddr]>`.** `control-api` can then adapt to policy's
  `ClientDirectory` by cloning an `Arc`. That trait returns policy-owned types, not
  `ClientInfo`; see the cross-module decisions.
- **Persistent state.** Label assignments, retained offline clients and IPv6 address
  observations are stored in `State`. `State` is part of the last-good disk cache
  (`<data>/clients/state.json`). The file is written atomically with mode 0600 and loaded as
  untrusted input (caps re-checked).
- **TLS to the gateway.**
  - reqwest gets a preconfigured `rustls::ClientConfig` (ring provider).
  - Pin mode uses a custom `ServerCertVerifier`. It compares the SHA-256 (`ring::digest`) of
    the leaf DER against the pin and still checks the handshake signature with the provider's
    algorithms.
  - CA mode uses a root store built from `ca_file`.
  - Insecure mode is opt-in only, and the engine logs a security warning on each apply.
- **Defensive classic parsing.** Use `serde_json::Value` (no rigid structs). Every field is
  optional. A bad row is skipped and counted, and never fails the page.
- **Clock.** The crate has its own small `Clock` trait, the same shape as filtering's
  (`now()`, `ManualClock` for tests), because `clients` has no dependency on `filtering`.
- **Secrets.** A small `read_secret("DNSCRAFT_UNIFI_API_KEY")` helper reads the env var or
  `*_FILE`. The key value is never logged and never shows up in `Debug`.

## Dependencies (need approval — one table for all three plans)

See [plan-policy.md § Dependencies](../plan-policy.md#dependencies-need-approval--all-three-plans).
This module needs:

| Crate | Kind | Why |
|---|---|---|
| `rustls` 0.23 | normal | custom pin verifier (already in the lockfile via reqwest) |
| `ipnet` 2 | normal | manual CIDRs, network prefixes (already in the lockfile) |
| `time` 0.3, feature `parsing` | normal | RFC 3339 `connectedAt` (already in the lockfile) |
| `rcgen` 0.14 (ring) | dev | self-signed certificate for the mock gateway |
| `tokio-rustls` 0.26 | dev | HTTPS mock server (already in the lockfile) |

Already in the workspace: reqwest, serde, serde_json, idna, tokio, thiserror, tracing, ring.

## Dependency graph

```
C1 skeleton, config, errors ── C2 label normalisation
        │                               │
        └──────── C3 manual lookup ◄────┘
                        │
C4 gateway HTTP + TLS modes (risk, early)     O1 owner hardware check (manual, before C7)
                        │                               │
        C5 UniFi merge (pure: precedence, labels, conflicts, retain, VLAN, domain)
                        │
        C6 Integration API ── C7 classic API
                        │
        C8 engine (sync task, stale, status) ── C9 disk cache
                        │
        C10 polish, coverage, docs
```

## Task List

### Phase 1: Core
- [x] C1: Crate skeleton, types, config validation, errors
- [x] C2: DNS label normalisation and FQDN building
- [x] C3: Manual-only `ClientLookup` (exact IP, longest CIDR, names, PTR)
- [x] C4: Gateway HTTP client with TLS pin / CA / insecure modes

### Checkpoint A: Core + TLS
- [x] DoD green; pin mismatch fails closed against the HTTPS mock
- [ ] Lead review (verifier + index layout)

### Phase 2: UniFi
- [x] O1: Owner checks the classic API on real hardware (manual, no code) — classic accepts `X-API-KEY`; fields `ip` / `ipv6_addresses` / `domain_name`
- [x] C5: UniFi merge into the snapshot (pure)
- [x] C6: Integration API: sites, networks, paged clients
- [x] C7: Classic API: `stat/sta`, `rest/user`, `rest/networkconf`, site mapping

### Checkpoint B: Sync path
- [x] A `sync_once` against both mocks builds the expected lookup; failure tests keep the last good snapshot — review fixes landed, re-review open

### Phase 3: Engine
- [x] C8: `ClientEngine`: background sync, change detection, stale/status, backoff
- [x] C9: Last-good disk cache + persisted label state
- [x] C10: Polish: README, coverage ≥ 80 % (non-HTTP), parser proptest

### Checkpoint C: Complete
- [x] All spec success criteria met (table in progress.md)
- [ ] Independent review; **owner approval**

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| The classic API rejects `X-API-KEY` on the owner's UniFi OS version | High: no complete IPv6 | O1 checks it on real hardware before C7. If it fails, ask the owner about cookie login (spec: ask first) or Integration-only mode (singular `ipAddress`). The `classic_clients` switch already exists. |
| `rest/networkconf` has no `domain_name` (spec: unverified) | Low | O1 checks it. If the field is missing, step 1 of the domain derivation yields nothing and config `local_domain` applies (already specified). |
| Classic JSON differs between versions | Med | Parse via `Value`, skip and count bad rows, fixtures with unknown and missing fields, proptest that arbitrary JSON never panics. |
| Pin verifier mistakes (accepting too much) | High | Tests: wrong pin, right pin, CA mode with an unrelated CA, insecure mode only when set. The signature is still verified through the provider. |
| Label churn when clients come and go | Med | First-seen state persisted; tests cover restart, newcomer collision and eviction. |

## Open Questions

- O1 needs about two minutes of the owner's time on the real gateway (commands in
  [clients-todo.md](clients-todo.md#task-o1-owner-checks-the-classic-api-on-real-hardware)). Answers are
  yes/no plus field names only. No data goes into the repo.
