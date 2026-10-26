# Implementation Plan: Over-engineering Cleanup (ponytail-audit)

> Source: repo-wide `ponytail-audit` (2026-10-26). 36 findings, ~900 lines / 1 dep removable.
> This is a new work stream, disjoint from the feature modules in `plan.md` / `todo-*.md`.
> Tasks tracked in [todo-audit-cleanup.md](todo-audit-cleanup.md).

## Overview

Delete duplicated, dead, and over-abstracted code found by the audit. The single
largest win is cross-crate duplication (Clock ×4, Secret ×3, config helpers ×3):
these need one shared home. The rest is local per-crate dead code, one-liner
wrappers, and hand-rolled stdlib. Every task is independently verifiable against
the full workspace build; no task changes runtime behavior.

## Architecture Decisions

1. **New leaf crate `crates/dnscraft-common`.** The shared `Clock`, `Secret`,
   and config/network helpers are needed by `clients`, `filtering`, `listeners`,
   `tls` — but `clients` and `filtering` are currently leaves that depend on no
   internal crate, and `proto` (the only existing shared crate) is semantically
   the DNS wire format, not a utility home. A tiny leaf crate with no internal
   deps is the natural, minimal host. `api`/`resolver` `clock.rs` are *divergent*
   variants and stay where they are (not part of the dedup).
2. **Canonical copies are the "most complete" one.** `is_private_v4`/`is_cgnat`
   keep the `policy` version (has NAT64). `DnsProtocol` gains `as_str()` in
   `policy` and replaces the two free `protocol_str` fns.
3. **Deletions only, no renames of public API unless the finding says so.**
   Where a wrapper is a 1-line alias (`FilterEngine::open`, `service()`), the
   call sites are inlined and the alias removed; nothing else is renamed.

## Task List

### Phase 0 — Foundation: `dnscraft-common` (sequential)
- [ ] Task 1: crate + `Clock`/`wait_until`, migrate clients/filtering/listeners/tls
- [ ] Task 2: `Secret`/`read_secret`, migrate api/clients/tls
- [ ] Task 3: config/network helpers, migrate tls/clients/api/listeners/policy/filtering

### Checkpoint: Foundation
- [ ] `cargo build --workspace` green; no `Clock`/`Secret`/helper copies remain in the migrated crates

### Phase 1 — Per-crate cleanup (independent, parallelizable)
- [ ] Task 4: listeners — `release_per_source` ×5, `ConnActivity` ×3
- [ ] Task 5: api routes — `actor`/`if_match` ×5, `IdBody` ×2, `valid_cidr`, `serialize_err`, `protocol_str`
- [ ] Task 6: api config/store — `validate_*` inline, `SharedConfigService`, `contains_redacted_placeholder`, `IpTruncate` merge
- [ ] Task 7: api auth — `Auth` wrapper → `SessionStore`
- [ ] Task 8: mcp — `SafeText`, `canonical_domain`, `iso_duration`, `service()`, `allowed_origins`
- [ ] Task 9: tls — dead fns, `redact_acme_err`, `NodeEntry.name`, `Default` derive, `allow_http_for_tests`, `read_echo_body`
- [ ] Task 10: filtering/clients — `open`/`snapshot_arc`, `is_unicast_link_local` → stdlib
- [ ] Task 11: policy — `name_to_domain`/`ede_text` inline, `emit()` dead params
- [ ] Task 12: resolver — `BoxFuture` dedup, `FromStr` delete, `Clock` in `ResolverConfig`

### Checkpoint: Per-crate
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings` green; `cargo test --workspace --locked` green

### Phase 2 — Deps + mechanical sweep (independent)
- [ ] Task 13: deps — drop `chrono`, `rustls-pki-types` workspace dep
- [ ] Task 14: remove 11 `#[non_exhaustive]` on intra-workspace enums

### Checkpoint: Complete
- [ ] Full Definition of Done (fmt, clippy -D warnings, test) green on every task
- [ ] `git grep` confirms no residual duplicates; ready for review

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| New crate reshuffles dep edges (clients/filtering gain a dep) | Med | `dnscraft-common` is a leaf with zero internal deps; no cycles possible |
| `chrono` drop breaks a date format `time` can't express | Low | Task 13 verifies output; fall back to keeping `chrono` if `time`/`std` falls short |
| Removing `#[non_exhaustive]` relaxes an API guarantee | Low | Audit confirmed no external matcher; re-verify with `cargo check --workspace` |
| Dedup tasks touch 5+ files (mechanical) | Low | Grouped atomically so the tree stays green after each task |

## Open Questions

- Confirm `dnscraft-common` is the preferred home vs. reusing `dnscraft-proto` (rejected here: proto would pull idna into clients/filtering).
