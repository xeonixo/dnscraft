# Tasks: over-engineering cleanup (ponytail-audit, consolidated)

> Plan: [plan-audit-cleanup.md](plan-audit-cleanup.md) · Sources: ponytail-audit 2026-10-26 + re-audit 2026-10-27
>
> Definition of done per task: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
> `cargo test --workspace --locked` green; commit. Behavior-preserving deletions only.

## Phase 0 — finish `dnscraft-common` migration

## Task 1: `Secret`/`read_secret` → common — ✅ done (commit `7af9314`)

**Description:** `dnscraft_common::secret` already exists (`Secret` + `read_secret`
returning `Result<Secret, String>`). Delete the three local copies — tls
(`secret.rs`, 183 l, adds `Deserialize`), clients (`secret.rs`, 148 l), api
(`secret.rs`, 45 l) — and map `String` → the crate error at each call site. tls's
`Deserialize` impl moves to common (or stays local if it needs the redacted marker
handling). Drop `zeroize` from clients' deps (only used in its `secret.rs`).

**Acceptance criteria:**
- [x] One `Secret` + one `read_secret` in `dnscraft-common`; 3 local copies removed
- [x] tls `Deserialize` behavior (redacted marker round-trip) preserved
- [x] `zeroize` removed from `crates/dnscraft-clients/Cargo.toml`

**Verification:** `cargo build --workspace --locked`; `cargo test --workspace --locked`
**Dependencies:** none
**Files:** `dnscraft-common/src/secret.rs`, `dnscraft-{tls,clients,api}/src/secret.rs` (delete), call sites, 3× `Cargo.toml`
**Estimated scope:** Medium

## Task 2: config/network helpers → common — ✅ done (commit `d411c44`; clients `check_https_url` + listeners `is_private_v4` kept as stricter/guard variants)

**Description:** `dnscraft_common::net`/`config` already hold `is_loopback_host_str`,
`is_private_v4`/`is_cgnat`/`nat64`, `normalise_domain`, `check_https_url`, `jittered`.
Delete the still-live copies and re-export: `normalise_domain`/`check_https_url`/
`is_loopback_host_str` in tls+clients, `jittered` in filtering+clients,
`is_private_v4` in api/listeners/policy. Also move the i64 `unix_seconds` helper
(mcp/api/cluster-store) and `sha256_hex` (api/audit, cluster/lib) to common.

**Acceptance criteria:**
- [x] One copy of each helper; the `policy` NAT64-aware `is_private_v4`/`is_cgnat` is canonical
- [x] `unix_seconds` (i64) and `sha256_hex` defined once in common
- [x] The f64 `unix_seconds` in `dnscraft/src/events.rs` (sub-second) stays local (different semantics)

**Verification:** `cargo build --workspace --locked`; `cargo test --workspace --locked`
**Dependencies:** Task 1
**Files:** `dnscraft-common/src/{net,config}.rs`, `dnscraft-{tls,clients,api,listeners,policy,filtering,cluster,mcp}/src/**`
**Estimated scope:** Large (mechanical, atomic)

## Task 3: one `Clock` (replaces ADR-0005) — ✅ done (commit `6901399`)

**Description:** Fold resolver's monotonic `instant()` into
`dnscraft_common::Clock` as a defaulted method (`fn instant(&self) -> Instant
{ Instant::now() }`), implement it on `SystemClock`/`ManualClock`. Re-export
`dnscraft_common::clock` from `api` (drop its 103-l `clock.rs`) and `mcp` (drop its
95-l `clock.rs`, add `dnscraft-common` dep). Delete resolver's 89-l `clock.rs` and
use common's `Clock`. Rewrite `docs/adr/0005-injectable-clock.md` to state the
one-clock rule (current ADR says "every crate carries its own copy", which the code
already violates).

**Acceptance criteria:**
- [x] Exactly one `Clock` trait + `SystemClock` + `ManualClock` in the workspace
- [x] api/mcp/resolver `clock.rs` deleted; resolver still gets monotonic time via `clock.instant()`
- [x] ADR-0005 updated to match reality

**Verification:** `cargo build --workspace --locked`; `cargo test --workspace --locked`
**Dependencies:** Task 1 (mcp gains the common dep here)
**Files:** `dnscraft-common/src/clock.rs`, `dnscraft-{api,mcp,resolver}/src/clock.rs` (delete), `dnscraft-mcp/Cargo.toml`, `docs/adr/0005-injectable-clock.md`
**Estimated scope:** Medium

### Checkpoint 0 — `cargo build --workspace --locked` green; no residual `Clock`/`Secret`/helper copies

## Phase 1 — per-crate cleanup (independent)

## Task 4: listeners — dedup `release_per_source` ×5 and `ConnActivity` ×3 — ✅ done (commit `3bc4191`)

**Description:** Extract one `release_per_source(&Mutex<HashMap<IpAddr,u32>>)` free
fn shared by `doh`, `doh_h3`, `doq`, `dot`, `tcp`; unify the three `ConnActivity`
structs on `SystemTime`.

**Acceptance criteria:**
- [x] 5 copies of `release_per_source` → 1; 3 `ConnActivity` → 1

**Verification:** `cargo test -p dnscraft-listeners --locked`
**Dependencies:** none (clock already in common)
**Files:** `crates/dnscraft-listeners/src/{doh,doh_h3,doq,dot,tcp}.rs`
**Estimated scope:** Medium

## Task 5: api routes — dedup `actor`/`if_match`/`IdBody`, `valid_cidr`, `serialize_err`, `protocol_str` — ✅ done (commit `bf8b07b`)

**Description:** Make `actor` + `if_match` `pub(crate)` in `config_routes.rs`, delete
the 4 copies (filter/clients/listener/tls routes); move `IdBody` to one location and
re-export; replace `valid_cidr` with `valid_ip_or_cidr` + `split_once`; move
`serialize_err` to `error.rs`; replace both `protocol_str` fns with
`DnsProtocol::as_str()` (added in `policy`).

**Acceptance criteria:**
- [x] `actor`/`if_match`/`IdBody` each defined once; callers unchanged
- [x] No hand-rolled `valid_cidr`, duplicate `serialize_err`, or free `protocol_str`

**Verification:** `cargo test -p dnscraft-api --locked`; `cargo build --workspace --locked`
**Dependencies:** Task 2 (protocol_str touches policy)
**Files:** `crates/dnscraft-api/src/api/{config,clients,filter,listener,tls}_routes.rs`, `query_log.rs`, `error.rs`, `crates/dnscraft-policy/src/config.rs`, `crates/dnscraft/src/events.rs`
**Estimated scope:** Medium

## Task 6: api config/store — inline validators, drop aliases/dead code, merge `IpTruncate` — ✅ done (commit `93e5569`)

**Description:** Inline `validate_auth`/`validate_query_log`/`validate_rate_limit`
into `ControlApiConfig::validate`; delete `SharedConfigService` alias (use
`Arc<ConfigService>`); delete `contains_redacted_placeholder` (dead,
`#[allow(dead_code)]`); merge `IpTruncate` (add `truncate()` to the api copy, delete
the binary copy).

**Acceptance criteria:**
- [x] No dead/`#[allow(dead_code)]` items remain in these files
- [x] One `IpTruncate`; binary reuses the api one

**Verification:** `cargo test -p dnscraft-api --locked`; `cargo build --workspace --locked`
**Dependencies:** none
**Files:** `crates/dnscraft-api/src/config.rs`, `config_apply.rs`, `audit.rs`, `crates/dnscraft/src/config.rs`
**Estimated scope:** Small

## Task 7: api auth — drop `Auth` pass-through wrapper — ✅ done (commit `b5d98f5`)

**Description:** `Auth` is a single-implementation pass-through around
`SessionStore`. Replace `State<Auth>` with `State<SessionStore>` and delete the struct.

**Acceptance criteria:**
- [x] `Auth` removed; session access goes through `SessionStore` directly

**Verification:** `cargo test -p dnscraft-api --locked`
**Dependencies:** none
**Files:** `crates/dnscraft-api/src/api/auth/mod.rs` + route handlers using `State<Auth>`
**Estimated scope:** Small

## Task 8: api tls — drop `AcmeResolver` single-impl trait *(new)* — ✅ done (commit `cc46a45`)

**Description:** `trait AcmeResolver` in `crates/dnscraft-api/src/tls.rs` has exactly
one impl (`dnscraft_tls::CertResolver`) that forwards to methods `CertResolver`
already has. `FallbackResolver` holds `Arc<dyn AcmeResolver>` only for a test double
that does not exist. Hold the concrete `CertResolver` (or its `Arc`) directly and
delete the trait + forwarding impl.

**Acceptance criteria:**
- [x] `AcmeResolver` trait gone; `FallbackResolver` uses `dnscraft_tls::CertResolver`
- [x] `resolve`/`leaf_der` behavior unchanged

**Verification:** `cargo test -p dnscraft-api --locked`
**Dependencies:** none
**Files:** `crates/dnscraft-api/src/tls.rs`
**Estimated scope:** Small

## Task 9: mcp — drop `SafeText`, inline `iso_duration`, dedup `service()`, `allowed_origins` — ✅ done (commit `7a59bb1`; `allowed_origins` audit item dropped as false positive)

**Description:** Delete the `SafeText` newtype (export `sanitize(x, CAP)` only, apply
at call sites); inline `iso_duration()` as `format!("PT{}S", as_secs())`; replace the
`service()` alias with `transport::build` at its one call site; remove the dead
`allowed_origins` field (derived at runtime per `config.rs` doc).

**Acceptance criteria:**
- [x] `SafeText` gone; call sites use `sanitize(x, CAP)`
- [x] `iso_duration`/`service` wrappers gone
- [ ] `allowed_origins` field gone *(dropped — live Origin/CSRF validation; see plan-audit-cleanup)*

**Verification:** `cargo test -p dnscraft-mcp --locked`
**Dependencies:** none
**Files:** `crates/dnscraft-mcp/src/{sanitize,lib,tools/read,tools/write,config,transport}.rs`
**Estimated scope:** Medium

## Task 10: tls — delete dead fns/fields, inline `redact_acme_err`, `read_echo_body` — ✅ done (commit `ff48ff1`)

**Description:** Delete `plan_renewal` + `apply_cert_flags` (test-only) and
`NodeEntry.name` (unused); inline `redact_acme_err` (body is `e.to_string()`); move
`allow_http_for_tests` to test helpers; replace `read_echo_body` with the shared
`read_capped` pattern.

**Acceptance criteria:**
- [x] No dead/test-only fns or unused fields remain
- [x] `redact_acme_err` call sites use `e.to_string()`; no `allow_http_for_tests` in prod config

**Verification:** `cargo test -p dnscraft-tls --locked`
**Dependencies:** Task 2 (config helpers already in common)
**Files:** `crates/dnscraft-tls/src/{renew,acme,config,dyndns}.rs`
**Estimated scope:** Medium

## Task 11: filtering/clients — delete aliases, stdlib `is_unicast_link_local` — ✅ done (commit `4596d7c`)

**Description:** Delete `FilterEngine::open()` and `snapshot_arc()` (1-line aliases),
inline call sites; replace hand-rolled `is_unicast_link_local` with
`Ipv6Addr::is_unicast_link_local()`.

**Acceptance criteria:**
- [x] `open`/`snapshot_arc` gone; call sites use `new`/`snapshot`
- [x] `is_unicast_link_local` fn gone

**Verification:** `cargo test -p dnscraft-filtering -p dnscraft-clients --locked`
**Dependencies:** none
**Files:** `crates/dnscraft-filtering/src/engine.rs`, `crates/dnscraft-clients/src/merge.rs`
**Estimated scope:** Small

## Task 12: policy — inline `name_to_domain`/`ede_text`, drop dead `emit` params — ✅ done (commit `896ff7b`)

**Description:** Inline the one-line wrappers `name_to_domain` and `ede_text`; remove
the always-`None` `forward_zone`/`dnssec` params from `emit()`.

**Acceptance criteria:**
- [x] `name_to_domain`/`ede_text` gone; `emit()` takes no unused params

**Verification:** `cargo test -p dnscraft-policy --locked`
**Dependencies:** none
**Files:** `crates/dnscraft-policy/src/util.rs`, `engine.rs`
**Estimated scope:** Small

## Task 13: resolver — dedup `BoxFuture`, delete `FromStr` — ✅ done (commit `e03c4bc`; `FromStr` audit item dropped as false positive)

**Description:** Inline the two identical `BoxFuture<'a,T>` type aliases; delete
`FromStr for ForwardZoneId` (only its own test uses it). (The concrete-clock change
is handled in Task 3.)

**Acceptance criteria:**
- [x] No duplicate `BoxFuture` alias
- [ ] `FromStr` impl removed *(dropped — used by policy `serde_ids`; see plan-audit-cleanup)*

**Verification:** `cargo test -p dnscraft-resolver --locked`
**Dependencies:** none
**Files:** `crates/dnscraft-resolver/src/{iterate,dnssec/walk,config}.rs`
**Estimated scope:** Small

### Checkpoint 1 — `cargo clippy --workspace --all-targets --locked -- -D warnings` + `cargo test --workspace --locked` green

## Phase 2 — deps + mechanical + dead code

## Task 14: deps — drop `chrono` — ✅ done (commit `18a3b1b`; chrono stays transitive via openidconnect/oauth2)

**Description:** Replace `chrono` usage in `dnscraft-api` (2 sites, RFC3339 formatting)
with `time` + the `formatting` feature (already enabled in `dnscraft-cluster`); remove
`chrono` from the workspace. (`rustls-pki-types` is already `{ workspace = true }` in
testkit — nothing to do.)

**Acceptance criteria:**
- [x] `chrono` no longer in `Cargo.toml`/`Cargo.lock`; date output unchanged

**Verification:** `cargo build --workspace --locked`; `cargo test --workspace --locked`
**Dependencies:** none
**Files:** `Cargo.toml`, `crates/dnscraft-api/src/{cluster_status,tls}.rs`
**Estimated scope:** Small

## Task 15: remove 4 remaining `#[non_exhaustive]` on intra-workspace enums — ✅ done (commit `bb61535`; they were structs, not enums)

**Description:** Drop the 4 remaining `#[non_exhaustive]` annotations on enums matched
only inside the workspace (`filtering/modifiers.rs`, `filtering/parser.rs`,
`resolver/stats.rs` + 1 more). Re-verify with a full check.

**Acceptance criteria:**
- [x] `#[non_exhaustive]` removed; no `match` breaks

**Verification:** `cargo check --workspace --locked`
**Dependencies:** none
**Files:** `crates/dnscraft-filtering/src/{modifiers,parser}.rs`, `crates/dnscraft-resolver/src/stats.rs`, 1 more
**Estimated scope:** Small

## Task 16: delete `spikes/` *(new)* — ✅ done (commit `2333bf0`)

**Description:** `spikes/hickory-recursor` and `spikes/listeners` (~935 lines + 2
`Cargo.lock`) are exploratory, not workspace members, and superseded by
`dnscraft-resolver`/`dnscraft-listeners`. Confirm no active reference, then delete the
directory.

**Acceptance criteria:**
- [x] `spikes/` gone; `git grep` shows no reference to it; workspace build unaffected *(exploratory subdirs removed in `2333bf0`; empty `spikes/` may remain locally)*

**Verification:** `cargo build --workspace --locked`
**Dependencies:** none
**Files:** `spikes/**`
**Estimated scope:** Small (delete-only)

### Checkpoint 2 (Complete) — fmt, clippy `-D warnings`, `cargo test --workspace --locked` all green; `git grep` shows no residual duplicates
