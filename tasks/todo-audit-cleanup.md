# Tasks: over-engineering cleanup (ponytail-audit)

> Plan: [plan-audit-cleanup.md](plan-audit-cleanup.md) · Source: repo-wide ponytail-audit (2026-10-26)
>
> Definition of done per task: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
> `cargo test --workspace --locked` green; commit. Behavior-preserving deletions only.

## Phase 0 — Foundation: `dnscraft-common` crate

## Task 1: Create `dnscraft-common`; move `Clock`/`wait_until` out of 4 crates

**Description:** New leaf workspace crate `crates/dnscraft-common` (no internal
deps) holding the byte-identical `Clock` trait, `SystemClock`, `ManualClock`, and
async `wait_until`. Migrate `clients`, `filtering`, `listeners`, `tls` to depend
on it and delete their local `clock.rs` (and the duplicated `RacyClock` test
helper + tick-miss test where identical).

**Acceptance criteria:**
- [ ] `dnscraft-common::clock` compiles and is `pub`
- [ ] The 4 crates no longer define their own `Clock`/`SystemClock`/`ManualClock`/`wait_until`
- [ ] All import sites and `Cargo.toml` updated; behavior unchanged

**Verification:**
- [ ] `cargo build --workspace --locked`
- [ ] `cargo test --workspace --locked` (clock/tick tests still pass)

**Dependencies:** None
**Files:** `crates/dnscraft-common/**` (new), 4× `clock.rs` (delete), 4× `Cargo.toml`, import sites
**Estimated scope:** Large (mechanical, atomic)

## Task 2: Move `Secret`/`read_secret` to common

**Description:** Move the triplicated `Secret(Zeroizing<String>)` newtype and the
`read_secret`/`read_secret_parts` env-var + `_FILE` loader into
`dnscraft-common`, parameterized over the error type. Migrate `api`, `clients`,
`tls`.

**Acceptance criteria:**
- [ ] One `Secret` + one `read_secret` in common; 3 local copies removed
- [ ] Error type genericized without changing callers' error shape

**Verification:**
- [ ] `cargo build --workspace --locked`; `cargo test --workspace --locked`
**Dependencies:** Task 1
**Files:** `dnscraft-common/src/secret.rs` (new), `api/clients/tls` `secret.rs` (delete/update)
**Estimated scope:** Medium

## Task 3: Move config/network helpers to common

**Description:** Move `normalise_domain`, `check_https_url`, `is_loopback_host_str`
(from tls+clients), `is_private_v4`/`is_cgnat` (keep the `policy` version, with
NAT64), and `jittered` (clients+filtering) into `dnscraft-common`. Update
`tls`, `clients`, `api`, `listeners`, `policy`, `filtering`.

**Acceptance criteria:**
- [ ] One copy of each helper; all original definitions deleted
- [ ] The `policy` NAT64-aware `is_private_v4`/`is_cgnat` is the canonical one

**Verification:**
- [ ] `cargo build --workspace --locked`; `cargo test --workspace --locked`
**Dependencies:** Task 1
**Files:** `dnscraft-common/src/net.rs`+`config.rs` (new), 6 crates' `config.rs`/`admission.rs`/`private.rs`/`engine.rs`/`scheduler.rs`
**Estimated scope:** Large (mechanical, atomic)

### Checkpoint: Foundation
- [ ] `cargo build --workspace --locked` green; no residual copies in migrated crates

## Phase 1 — Per-crate cleanup (independent)

## Task 4: listeners — dedup `release_per_source` ×5 and `ConnActivity` ×3

**Description:** Extract one `release_per_source(&Mutex<HashMap<IpAddr,u32>>)`
free fn shared by `doh`, `doh_h3`, `doq`, `dot`, `tcp`; unify the three
`ConnActivity` structs on `SystemTime`.

**Acceptance criteria:**
- [ ] 5 copies of `release_per_source` → 1; 3 `ConnActivity` → 1
**Verification:** `cargo test -p dnscraft-listeners --locked`
**Dependencies:** Task 1 (clock already in common)
**Files:** `crates/dnscraft-listeners/src/{doh,doh_h3,doq,dot,tcp}.rs`
**Estimated scope:** Medium

## Task 5: api routes — dedup `actor`/`if_match`/`IdBody`, `valid_cidr`, `serialize_err`, `protocol_str`

**Description:** Make `actor` + `if_match` `pub(crate)` in `config_routes.rs`,
delete the 4 copies; move `IdBody` to one location and re-export; replace
`valid_cidr` with `valid_ip_or_cidr` + `split_once`; move `serialize_err` to
`error.rs`; replace `protocol_str` fns with `DnsProtocol::as_str()` (added in
`policy`).

**Acceptance criteria:**
- [ ] `actor`/`if_match`/`IdBody` each defined once; callers unchanged
- [ ] No hand-rolled `valid_cidr` or duplicate `serialize_err`/`protocol_str`
**Verification:** `cargo test -p dnscraft-api --locked`
**Dependencies:** Task 3 (protocol_str touches policy)
**Files:** `crates/dnscraft-api/src/api/{config,clients,filter,listener,tls}_routes.rs`, `query_log.rs`, `error.rs`, `crates/dnscraft-policy/src/config.rs`, `crates/dnscraft/src/events.rs`
**Estimated scope:** Medium

## Task 6: api config/store — inline validators, drop aliases/dead code, merge `IpTruncate`

**Description:** Inline `validate_auth`/`validate_query_log`/`validate_rate_limit`
into `ControlApiConfig::validate`; delete `SharedConfigService` alias (use
`Arc<ConfigService>`); delete `contains_redacted_placeholder` (dead, `#[allow(dead_code)]`);
merge `IpTruncate` (add `truncate()` to the api copy, delete the binary copy).

**Acceptance criteria:**
- [ ] No dead/`#[allow(dead_code)]` items remain in these files
- [ ] One `IpTruncate`; binary reuses the api one
**Verification:** `cargo test -p dnscraft-api --locked`; `cargo build --workspace`
**Dependencies:** None
**Files:** `crates/dnscraft-api/src/config.rs`, `config_apply.rs`, `audit.rs`, `crates/dnscraft/src/config.rs`
**Estimated scope:** Small

## Task 7: api auth — drop `Auth` pass-through wrapper

**Description:** `Auth` is a single-implementation pass-through around
`SessionStore`. Replace `State<Auth>` with `State<SessionStore>` and delete the
struct.

**Acceptance criteria:**
- [ ] `Auth` removed; session access goes through `SessionStore` directly
**Verification:** `cargo test -p dnscraft-api --locked`
**Dependencies:** None
**Files:** `crates/dnscraft-api/src/api/auth/mod.rs` + route handlers using `State<Auth>`
**Estimated scope:** Small

## Task 8: mcp — drop `SafeText`, inline `iso_duration`, dedup `canonical_domain`, `service()`, `allowed_origins`

**Description:** Delete the `SafeText` newtype (export `sanitize()` only);
replace `canonical_domain()` with `protected::canonicalize()`; inline
`iso_duration()` as `format!("PT{}S", as_secs())`; re-export `transport::build`
as `service`; remove dead `allowed_origins` field.

**Acceptance criteria:**
- [ ] `SafeText` gone; call sites use `sanitize(x, CAP)`
- [ ] `iso_duration`/`canonical_domain`/`service` wrapper gone; `allowed_origins` gone
**Verification:** `cargo test -p dnscraft-mcp --locked`
**Dependencies:** None
**Files:** `crates/dnscraft-mcp/src/{sanitize,lib,tools/read,tools/write,config}.rs`
**Estimated scope:** Medium

## Task 9: tls — delete dead fns/fields, inline `redact_acme_err`, derive `Default`, dedup `read_echo_body`

**Description:** Delete `plan_renewal` + `apply_cert_flags` (test-only) and
`NodeEntry.name` (unused); inline `redact_acme_err` (body is `e.to_string()`);
derive `Default` for `CloudflareConfig`; move `allow_http_for_tests` to test
helpers; replace `read_echo_body` with the shared `read_capped` pattern.

**Acceptance criteria:**
- [ ] No dead/test-only fns or unused fields remain
- [ ] `redact_acme_err` call sites use `e.to_string()`; no `allow_http_for_tests` in prod config
**Verification:** `cargo test -p dnscraft-tls --locked`
**Dependencies:** Task 3 (config helpers already in common)
**Files:** `crates/dnscraft-tls/src/{renew,acme,config,dyndns,cloudflare}.rs`
**Estimated scope:** Medium

## Task 10: filtering/clients — delete aliases, stdlib `is_unicast_link_local`

**Description:** Delete `FilterEngine::open()` and `snapshot_arc()` (1-line
aliases), inline call sites; replace hand-rolled `is_unicast_link_local` with
`Ipv6Addr::is_unicast_link_local()`.

**Acceptance criteria:**
- [ ] `open`/`snapshot_arc` gone; call sites use `new`/`snapshot`
- [ ] `is_unicast_link_local` fn gone
**Verification:** `cargo test -p dnscraft-filtering -p dnscraft-clients --locked`
**Dependencies:** None
**Files:** `crates/dnscraft-filtering/src/engine.rs`, `crates/dnscraft-clients/src/merge.rs`
**Estimated scope:** Small

## Task 11: policy — inline `name_to_domain`/`ede_text`, drop dead `emit` params

**Description:** Inline the one-line wrappers `name_to_domain` and `ede_text`;
remove the always-`None` `forward_zone`/`dnssec` params from `emit()`.

**Acceptance criteria:**
- [ ] `name_to_domain`/`ede_text` gone; `emit()` takes no unused params
**Verification:** `cargo test -p dnscraft-policy --locked`
**Dependencies:** None
**Files:** `crates/dnscraft-policy/src/util.rs`, `engine.rs`
**Estimated scope:** Small

## Task 12: resolver — dedup `BoxFuture`, delete `FromStr`, concrete clock in `ResolverConfig`

**Description:** Inline the two identical `BoxFuture<'a,T>` type aliases;
delete `FromStr for ForwardZoneId` (only its own test uses it); replace
`Arc<dyn Clock>` in `ResolverConfig` with the concrete clock (single impl).

**Acceptance criteria:**
- [ ] No duplicate `BoxFuture` alias; `FromStr` impl removed; `ResolverConfig` holds a concrete clock
**Verification:** `cargo test -p dnscraft-resolver --locked`
**Dependencies:** None
**Files:** `crates/dnscraft-resolver/src/{iterate,dnssec/walk,config}.rs`
**Estimated scope:** Small

### Checkpoint: Per-crate
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings` green; `cargo test --workspace --locked` green

## Phase 2 — Deps + mechanical sweep

## Task 13: deps — drop `chrono`, pin `rustls-pki-types` to workspace

**Description:** Replace `chrono` usage in `dnscraft-api` with the already-present
`time` crate (or `std::time`), remove `chrono` from the workspace; set
`rustls-pki-types` in `dnscraft-testkit` to `{ workspace = true }`.

**Acceptance criteria:**
- [ ] `chrono` no longer in `Cargo.toml`/`Cargo.lock`; date output unchanged
- [ ] `rustls-pki-types` uses workspace version
**Verification:** `cargo build --workspace --locked`; `cargo test --workspace --locked`
**Dependencies:** None
**Files:** `Cargo.toml`, `crates/dnscraft-api/src/**`, `crates/dnscraft-testkit/Cargo.toml`
**Estimated scope:** Small

## Task 14: remove 11 `#[non_exhaustive]` on intra-workspace enums

**Description:** Drop the 11 `#[non_exhaustive]` annotations on enums matched
only inside the workspace (audit confirmed no external matcher). Re-verify with
a full check.

**Acceptance criteria:**
- [ ] `#[non_exhaustive]` removed; no `match` breaks
**Verification:** `cargo check --workspace --locked`
**Dependencies:** None
**Files:** 6 files across api/config.rs, dnscraft/config.rs, etc.
**Estimated scope:** Small

### Checkpoint: Complete
- [ ] fmt, clippy `-D warnings`, `cargo test --workspace --locked` all green
- [ ] `git grep` shows no residual duplicates; ready for review
