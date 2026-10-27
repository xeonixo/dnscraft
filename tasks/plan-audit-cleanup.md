# Implementation Plan: Over-engineering Cleanup (ponytail-audit, consolidated)

> Sources: repo-wide `ponytail-audit` (2026-10-26, 36 findings) **and** re-audit
> (2026-10-27). The 2026-10-26 tasks were only partially executed; this plan
> merges the still-open findings with the new ones into one canonical list.
> Tasks tracked in [todo-audit-cleanup.md](todo-audit-cleanup.md).
>
> **Invariant:** behavior-preserving deletions only. No task changes runtime
> behavior. Each task is independently verifiable against the full workspace build.

## What is already done (verified 2026-10-27)

| Finding | State |
|---|---|
| `Clock` → `dnscraft-common` for `clients`/`filtering`/`listeners`/`tls` | done — they re-export `dnscraft_common::clock` |
| `dnscraft-common` crate exists (`clock`, `secret`, `net`, `config`, `duration`) | done |
| mcp `canonical_domain` → `protected::canonicalize` | done |
| `rustls-pki-types` pinned to workspace in `testkit` | done |
| `#[non_exhaustive]` on intra-workspace enums | 7 of 11 removed; 4 remain |

Everything else from the 2026-10-26 audit is **still open** (verified: `Secret` ×3,
`normalise_domain`/`check_https_url`/`is_private_v4`/`jittered` ×3–5,
`release_per_source` ×5, `actor`/`if_match` ×5, `chrono`, `SafeText`,
`name_to_domain`/`ede_text`, resolver `BoxFuture`/`FromStr`, etc.).

## Architecture decisions

1. **`dnscraft-common` stays the shared home.** It already exists and `clients`/
   `filtering`/`listeners`/`tls`/`api`/`resolver` depend on it. Finish the migration:
   move `Secret`, the config/network helpers, and the *divergent* clock variants
   into it (see decision 3). Only `mcp` gains a new `dnscraft-common` dependency.
2. **Canonical copies are the most complete one.** `is_private_v4`/`is_cgnat` keep
   the `policy` version (NAT64-aware). `DnsProtocol` gains `as_str()` in `policy`
   and replaces the two free `protocol_str` fns.
3. **One `Clock` trait, not four.** This *reverses* the earlier "api/resolver
   clock.rs are divergent, stay where they are" decision and contradicts the
   current ADR-0005 ("every crate carries its own clock copy") — which the code
   already violates (four crates re-export `dnscraft_common::clock`). Fold
   resolver's monotonic `instant()` into `dnscraft_common::Clock` as a defaulted
   method, re-export it from `api` and `mcp`, delete the three remaining local
   `clock.rs`, and rewrite ADR-0005 to state the one-clock rule.
4. **Deletions only, no public-API renames** unless the finding says so. Where a
   wrapper is a 1-line alias (`FilterEngine::open`, `service()`), inline call
   sites and remove the alias.

## Task list

### Phase 0 — finish `dnscraft-common` migration (sequential)

- [x] Task 1: `Secret`/`read_secret` → common; delete api/clients/tls copies; drop `zeroize` from clients — commit `7af9314`
- [x] Task 2: config/network helpers → common (`normalise_domain`, `check_https_url`, `is_loopback_host_str`, `is_private_v4`/`is_cgnat` NAT64, `jittered`, `unix_seconds` i64, `sha256_hex`) — commit `d411c44`
- [x] Task 3: one `Clock` — fold resolver `instant()` into common, re-export from api/mcp, delete 3 local `clock.rs`, rewrite ADR-0005 — commit `6901399`

### Checkpoint 0 — ✅ `cargo build --workspace --locked` green; no residual `Clock`/`Secret`/helper copies

**Residuals kept intentionally** (behavior differences, not re-doable without loosening validation):
- `crates/dnscraft-clients/src/config.rs::check_https_url` — stricter than common (reqwest URL parse). Keep.
- `crates/dnscraft-listeners/src/admission.rs::is_private_v4` — 3-line guard; listeners excludes `0.0.0.0/8`+broadcast. Keep.
- `crates/dnscraft/src/events.rs::unix_seconds` — f64 sub-second; different semantics. Keep.
- tls/clients `read_secret` wrappers — error adapters over the one common impl. Keep.

### Phase 1 — per-crate cleanup (independent, parallelizable)

- [x] Task 4: listeners — `release_per_source` ×5, `ConnActivity` ×3 — commit `3bc4191`
- [x] Task 5: api routes — `actor`/`if_match` ×5, `IdBody` ×2, `valid_cidr`, `serialize_err` ×2, `protocol_str` ×2 — commit `bf8b07b`
- [x] Task 6: api config/store — inline validators, `SharedConfigService`, `contains_redacted_placeholder`, `IpTruncate` — commit `93e5569`
- [x] Task 7: api auth — `Auth` pass-through → `SessionStore` — commit `b5d98f5`
- [x] Task 8: api tls — `AcmeResolver` single-impl trait → concrete `CertResolver` *(new)* — commit `cc46a45`
- [x] Task 9: mcp — `SafeText`, `iso_duration`, `service()` — commit `7a59bb1` (⚠️ `allowed_origins` was a **false positive**: live Origin/CSRF validation. Dropped.)
- [x] Task 10: tls — dead fns, `redact_acme_err`, `NodeEntry.name`, `allow_http_for_tests`, `read_echo_body` — commit `ff48ff1`
- [x] Task 11: filtering/clients — `open`/`snapshot_arc`, `is_unicast_link_local` → stdlib — commit `4596d7c`
- [x] Task 12: policy — `name_to_domain`/`ede_text` inline, `emit()` dead params — commit `896ff7b`
- [x] Task 13: resolver — `BoxFuture` ×2 — commit `e03c4bc` (⚠️ `FromStr` was a **false positive**: used by policy `serde_ids`. Dropped.)

### Checkpoint 1 — ✅ `cargo clippy --workspace --all-targets --locked -- -D warnings` + fmt + build + tests green (controller fixup commit `2e2f8b9` for the clippy/fmt gates)

**Notes:**
- Known pre-existing macOS-only listener test failures (bind `127.0.0.2`, EINPROGRESS errno) remain — environmental, not from this work.
- DoH idle timer moved monotonic→wall-clock during the `ConnActivity` unification (`SystemTime`); identical under `SystemClock`, minor NTP-jump sensitivity. Tracked, not blocking.

### Phase 2 — deps + mechanical + dead code (independent)

- [x] Task 14: deps — drop `chrono` (replace with `time` + `formatting`) — commit `18a3b1b` (direct dep removed; `chrono` stays *transitively* via `openidconnect`/`oauth2`)
- [x] Task 15: remove 4 remaining `#[non_exhaustive]` (were on **structs**, not enums) — commit `bb61535`
- [x] Task 16: delete `spikes/` (not a workspace member; superseded) *(new)* — commit `2333bf0`

### Checkpoint 2 (Complete) — ✅ fmt + `clippy -D warnings` + build + tests green; no residual duplicates; no direct `chrono`/`#[non_exhaustive]` left

## Risks and mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Folding `instant()` into common `Clock` touches resolver + api + mcp at once | Med | Task 3 is atomic and gated by Checkpoint 0 build |
| mcp gains a `dnscraft-common` dep (new dep edge) | Low | common is a leaf with zero internal deps; no cycle |
| `chrono` drop breaks a date format `time` can't express | Low | Task 14 verifies output; fall back to keeping `chrono` |
| `spikes/` deletion loses exploratory notes | Low | it's git history; confirm no active reference before delete |
| ADR-0005 rewrite vs. "no shared clock crate" intent | Low | code already contradicts the ADR; rewrite to match reality (one clock) |

## Open questions

- None blocking. ADR-0005 reversal is folded into Task 3 (decision 3 above).
