# Tasks: `clients` module

> Plan: [clients-plan.md](clients-plan.md) · Spec: [SPEC-clients.md](../../SPEC-clients.md) · Resume log: [progress.md](../progress.md)
> Definition of done per task: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
> `cargo test --workspace --locked` green; lead review; committed. Fixtures are invented (documentation ranges,
> `example.com`); never real captures. No test touches a real gateway.

## Phase 1: Core

## Task C1: Crate skeleton, types, config validation, errors

**Description:** Create `crates/dnscraft-clients` (workspace member, workspace lints) with the approved
dependencies. Contents:
- Types from the spec: `ClientId`, `MacAddr`, `ClientSource`, `ClientInfo` (`addresses: Arc<[IpAddr]>`), `VlanInfo`.
- `ClientsConfig`:
  - `local_domain`, `local_domain_mode`, `offline_retain`, `ipv6_address_ttl` (as `Duration`), manual entries.
  - `UnifiConfig`: `base_url`, `site_id`, `poll_interval`, `classic_clients`, `TlsMode::{Pin, CaFile, Insecure}`.
- `ClientsConfig::validate()`:
  - HTTPS-only base URL, plus a `#[doc(hidden)]` test hatch for loopback.
  - ≤ 1 000 manual entries; each manual entry has exactly one of `ip` or `cidr`.
  - Pin format `sha256:` + 32 hex bytes.
  - Domain normalisation via `idna`.
- `ClientsError` with every code from the spec table.
- `Clock` trait with a system clock and `ManualClock`.
- `read_secret(name)`: env var or `<name>_FILE`, trimmed, never in `Debug`.

**Acceptance criteria:**
- [x] Every public item documented; every error variant has a unique `code()` (enumerating test)
- [x] Config table tests: valid example from the spec, http URL rejected, bad pin, both ip+cidr, 1 001 manuals
- [x] `read_secret`: env, `_FILE`, missing → `clients.secret.missing`; secret not in `Debug` output

**Verification:** `cargo test -p dnscraft-clients`

**Dependencies:** plan + dependency table approved

**Files:** `Cargo.toml`, `crates/dnscraft-clients/{Cargo.toml,src/lib.rs,src/types.rs,src/config.rs,src/error.rs,src/clock.rs,src/secret.rs}`

**Scope:** M · **Done:** 2026-10-25 (Cursor)

## Task C2: DNS label normalisation and FQDN building

**Description:** `normalise_label(display, id) -> String` per the spec, steps 1–6:
- UTS 46 mapping via `idna`, then lower-case.
- Spaces and `_` become `-`; strip everything outside `[a-z0-9-]`; collapse and trim `-`.
- An empty result becomes `client-<id8>`.
- More than 63 octets: truncate at a hyphen boundary when possible, then add a hash suffix.

`fqdn(label, domain)` builds the name with the parent domain converted via UTS 46.
`suffixed(label, id)` returns `{label}-{id_suffix8}` and still fits in 63 octets.

**Acceptance criteria:**
- [x] Table tests: umlauts / full-width / ligatures (UTS 46), `"Docker on server1"`, emoji-only → `client-…`, 80-char name, trailing/leading/repeated `-`
- [x] Output always matches `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` (proptest)
- [x] `suffixed` stays ≤ 63 and differs for different ids

**Verification:** `cargo test -p dnscraft-clients label`

**Dependencies:** C1 · **Files:** `src/label.rs`, `tests/label.rs` · **Scope:** S · **Done:** 2026-10-25 (Cursor)

## Task C3: Manual-only `ClientLookup`

**Description:** Build a snapshot from manual entries only: `ClientLookup::build_manual(…)`. Rules:
- `by_ip`: exact manual IP first, then the longest matching manual CIDR.
- `by_name`: FQDN, case-insensitive, trailing dot accepted. A bare label resolves only when it is
  unambiguous across all local domains.
- `reverse`: follows the same winner as `by_ip`.
- `local_domains()`: the parents in use. A per-manual `domain` overrides the default.
- Label collisions within a domain: first-seen (config order) wins, the later entry gets `suffixed`.

No UniFi yet. This task fixes the index layout that C5 extends.

**Acceptance criteria:**
- [x] Precedence table: manual IP > /28 > /24 > no match; IPv4 and IPv6
- [x] `by_name` FQDN vs bare label (unique / ambiguous); unknown name → `None`
- [x] `by_ip` returns `Arc` clones (no deep copy); lookup of 1 000 manuals in < 1 µs p50 (criterion or simple timing test, documented)

**Verification:** `cargo test -p dnscraft-clients lookup`

**Dependencies:** C2 · **Files:** `src/lookup.rs`, `tests/lookup.rs` · **Scope:** M · **Done:** 2026-10-25 (Cursor)

## Task C4: Gateway HTTP client with TLS modes

**Description:** `GatewayClient::new(&UnifiConfig, api_key)`:
- reqwest with a preconfigured rustls `ClientConfig` (ring):
  - Pin verifier: SHA-256 of the leaf DER equals the pin. Handshake signatures are verified via
    `rustls::crypto::verify_tls12/13_signature` with the ring provider's algorithms.
  - CA-file root store.
  - Insecure mode: accept any certificate, emit a `tracing::warn!` with a stable code.
- Defaults: `X-API-KEY` header, 30 s timeout, 8 MiB body cap (streamed; abort when exceeded), no
  redirects off the gateway origin.
- Error mapping to `clients.tls.untrusted` / `clients.tls.handshake` / `clients.connect` /
  `clients.http.status` / `clients.http.body`.
- A hand-written HTTPS mock server for tests (tokio-rustls + rcgen self-signed), reused by C6/C7.

**Acceptance criteria:**
- [x] Right pin → OK; wrong pin → `clients.tls.untrusted`; CA mode with the mock's CA → OK, with another CA → untrusted
- [x] Insecure only when configured; warning emitted; never the default
- [x] 401 / 429 → `clients.http.status`; body > 8 MiB → `clients.http.body`; refused port → `clients.connect`; API key header sent, key absent from errors/logs

**Verification:** `cargo test -p dnscraft-clients gateway`

**Dependencies:** C1 · **Files:** `src/gateway.rs`, `src/tls.rs`, `tests/support/mock_gateway.rs`, `tests/gateway.rs` · **Scope:** M · **Done:** 2026-10-25 (Cursor)

## Checkpoint A: Core + TLS
- [x] DoD green (`fmt` / `clippy -D warnings` / `cargo test -p dnscraft-clients`)
- [x] Lead review of the verifier code (security-sensitive) and the index layout (Claude 2026-10-25: passed; optional items in brief C11)
- [x] progress.md updated

## Phase 2: UniFi

## Task O1: Owner checks the classic API on real hardware

**Description:** Manual, by the owner, before C7. Do not commit outputs. Report only yes/no and field names.
Use the real gateway address and an API key created in UniFi (Settings → Control Plane → Integrations / API Keys).

```sh
GW=https://<gateway-ip>; KEY=<api-key>
# 1. Does the classic client feed accept the API key? (expect HTTP 200 and JSON with "data")
curl -sk -o /dev/null -w '%{http_code}\n' -H "X-API-KEY: $KEY" "$GW/proxy/network/api/s/default/stat/sta"
# 2. Which address fields exist on a client row? (prints field names only)
curl -sk -H "X-API-KEY: $KEY" "$GW/proxy/network/api/s/default/stat/sta" | jq -r '.data[0] | keys[]' | grep -Ei 'ip|network|name|seen'
# 3. Do networks carry a DHCP domain? (prints field names only)
curl -sk -H "X-API-KEY: $KEY" "$GW/proxy/network/api/s/default/rest/networkconf" | jq -r '.data[0] | keys[]' | grep -Ei 'domain|vlan|subnet|ipv6'
```

**Acceptance criteria:**
- [x] Owner reports: (1) status code, (2) IPv4/IPv6 field names (e.g. `ip`, `ipv6`, `ipv6_addresses`…), (3) whether `domain_name` exists
- [x] Results recorded in progress.md as field names only. If (1) is not 200: STOP and ask the owner (cookie login vs Integration-only)

**Result (2026-10-25):** (1) classic `stat/sta` + `networkconf` → **200** with `X-API-KEY` (401 without / bogus; Bearer unused). (2) `ip`, `ipv6_addresses` (array), `network_id`, `hostname`/`name`, `last_seen`. (3) `domain_name` yes (sometimes empty).

**Dependencies:** none (can run any time) · **Scope:** XS (manual) · **Done:** 2026-10-25 (Cursor on owner gateway)

## Task C5: UniFi merge into the snapshot (pure)

**Description:** Extend the builder to
`build(manuals, observations: &[UnifiObservation], networks: &[NetworkInfo], prev: &State, cfg, now) -> (ClientLookup, State)`.
Rules:
- Manual beats UniFi on the same IP and on the same FQDN (the UniFi client gets a suffix).
- First-seen labels come from `State`. Existing clients keep their label; newcomers that collide
  get a suffix. Assignments of evicted clients are dropped.
- IP conflicts: online beats retained-offline; among equals the most recent `last_seen` wins;
  the loser keeps its other addresses.
- A client missing from a successful sync is retained `online = false` for `offline_retain`,
  then evicted.
- IPv6 addresses are kept for `ipv6_address_ttl` after the last observation; link-local is
  never indexed.
- VLAN: network-id join first, then longest-prefix fallback.
- Domain: per-network domain (mode `unifi_then_config`), else config; mode `config` always uses config.
- Caps: warn above 2 000 clients, refuse above 10 000 (`clients.too_many`).
- `clients.ip.conflict` counter.

**Acceptance criteria:**
- [x] Table tests for each rule above with `ManualClock` (retain 7 d, TTL 24 h boundaries), including "newcomer with a smaller id never renames an existing client"
- [x] A client with 3 IPv6 + 1 IPv4 resolves via `by_ip`/`reverse` for each address; `fe80::` is not indexed
- [x] Two networks with different domains give different FQDNs; missing domain → config fallback; mode `config` overrides

**Verification:** `cargo test -p dnscraft-clients merge`

**Dependencies:** C3 · **Files:** `src/merge.rs`, `src/state.rs`, `src/lookup.rs`, `tests/merge.rs` · **Scope:** M · **Done:** 2026-10-25 (Cursor)

## Task C6: Integration API

**Description:** `integration::fetch(&GatewayClient, site) -> (Vec<NetworkInfo>, Vec<UnifiObservation>)`:
- `GET /v1/sites`: auto-pick the only site, else require `site_id` (`clients.config.invalid`).
- Networks plus details: `vlanId`, name, IPv4/IPv6 prefixes.
- Clients paged with `limit=200` / `offset` until a short page, with a page cap (10 000 / 200 + 1).
- `connectedAt` parsed via `time`.
- Unknown fields are ignored; a bad row is skipped and counted.
- A failure on a later page → `clients.sync.partial` (caller keeps last good).

Mock fixtures are written from the OpenAPI schemas cited in the spec.

**Acceptance criteria:**
- [x] One site auto-picked; two sites without `site_id` → error; 450 clients over 3 pages
- [x] Network details give prefixes + VLAN; missing details → VLAN via id only
- [x] Page 2 returns 500 → `clients.sync.partial`; truncated JSON → `clients.http.body`

**Verification:** `cargo test -p dnscraft-clients integration`

**Dependencies:** C4, C5 · **Files:** `src/integration.rs`, `tests/integration_api.rs`, `tests/fixtures/integration/*.json` · **Scope:** M · **Done:** 2026-10-25 (Cursor) — fixtures inlined via mock (no JSON files needed)

## Task C7: Classic API

**Description:** `classic::fetch(&GatewayClient, site_key)`:
- `stat/sta` (connected) and `rest/user` (known/offline) parsed via `serde_json::Value`.
- Addresses: accept singular and array fields. Use the field names confirmed by O1, plus the
  common variants as fallbacks.
- `network_id` → join to networks.
- `rest/networkconf` `domain_name` if present (O1).
- Map Integration site UUID ↔ classic site key (`default`, …) via `/api/self/sites` (or the
  documented equivalent); a mapping failure → error, last good kept.
- Merge with the Integration rows by MAC or client id. If classic fails, the Integration rows
  alone still produce a snapshot (singular IPs).

**Acceptance criteria:**
- [x] Fixture with multi-IPv6 rows, unknown fields, wrong types, missing MAC → good rows kept, bad rows counted
- [x] Classic down, Integration up → snapshot from Integration only, status records the classic error
- [x] `classic_clients = false` → no classic request is made (mock asserts)

**Verification:** `cargo test -p dnscraft-clients --test classic_api`

**Dependencies:** C6, O1 · **Files:** `src/classic.rs`, `src/sync.rs`, `tests/classic_api.rs` · **Scope:** M · **Done:** 2026-10-25 (Cursor) — fixtures inlined via mock

## Checkpoint B: Sync path
- [x] `sync_once` against both mocks builds the expected lookup (spec success criteria 1, 2, 3, 5, 7)
- [x] Failure tests (connect refused, bad pin, 401, truncated JSON, empty site list, > max clients) keep the previous snapshot
- [x] Lead review; progress.md updated (Claude 2026-10-25: passed after C11/C11b)

**Done:** 2026-10-25 (Cursor) — covered by `tests/engine.rs` (happy path + failure matrix; `too_many` via merge unit test). Lead review found Engine bugs; **C11 + C11b fixes 2026-10-25** (state on unchanged hash, order-independent hash, sync lock, apply_config validate→build→store, immediate first sync, deterministic poll waits, `Secret` zeroize). Awaiting Lead re-review.

## Phase 3: Engine

## Task C8: `ClientEngine`

**Description:**
- `ClientEngine::new(config, data_dir, clock)`, `lookup()`, `apply_config()`, `sync_now()`, `status()`.
- Background task: interval 60 s ±10 % jitter. It holds a `Weak` to the engine and is aborted on drop.
- Change detection: a hash of the normalised observations + networks; rebuild only on change.
- On error: keep the snapshot, set `stale`, record `last_error` code.
- 429 / 5xx → exponential backoff with cap.
- UniFi disabled → manuals only.
- `apply_config` rebuilds immediately from cached observations (manual edits need no sync).
- Lookups never await.

**Acceptance criteria:**
- [x] `ManualClock` tests: poll cadence with jitter bounds, backoff on 429, recovery clears `stale`
- [x] Unchanged data → no rebuild (generation counter unchanged)
- [x] Dropping the engine stops the task (no leak; test with a `Weak`)

**Verification:** `cargo test -p dnscraft-clients --test engine`

**Dependencies:** C7 · **Files:** `src/engine.rs`, `src/status.rs`, `tests/engine.rs` · **Scope:** M · **Done:** 2026-10-25 (Cursor)

## Task C9: Last-good disk cache

**Description:**
- Persist after each successful build to `<data>/clients/state.json`:
  - last observations + networks;
  - `State` (labels, retained clients, address observations);
  - a format version.
- The directory is created 0700; the atomic write (unique temp, `create_new`, 0600, fsync,
  rename) follows filtering's `atomic_write`.
- On start, load as untrusted input: size cap 16 MiB, caps re-validated; a corrupt file is
  ignored with a warning and the next sync starts fresh.
- The snapshot is served before the first poll.

**Acceptance criteria:**
- [x] Restart with the gateway down serves the previous names with `stale = true`
- [x] Labels survive restart (newcomer after restart still gets the suffix)
- [x] Corrupt / oversized / wrong-version file → ignored, no panic; file mode 0600

**Verification:** `cargo test -p dnscraft-clients --test cache`

**Dependencies:** C8 · **Files:** `src/cache.rs`, `src/engine.rs`, `tests/cache.rs` · **Scope:** S · **Done:** 2026-10-25 (Cursor)

## Task C10: Polish

**Description:**
- README: config table, TLS bootstrap (how to read the pin), API key env names, failure behaviour.
- Docs on every public item.
- Proptest: arbitrary JSON into the classic/Integration parsers never panics.
- Coverage ≥ 80 % for non-HTTP modules (`cargo llvm-cov` if available locally, else report the gap).
- Cross-check against the spec success criteria 1–8, then list the results in progress.md.

**Acceptance criteria:**
- [x] README complete; no `missing_docs` warnings
- [x] Parser proptests pass (≥ 1 000 cases)
- [x] Success criteria table in progress.md, each item with its covering test

**Verification:** `cargo test -p dnscraft-clients` + DoD

**Dependencies:** C9 · **Files:** `crates/dnscraft-clients/README.md`, `tests/proptest_parsers.rs` · **Scope:** S · **Done:** 2026-10-25 (Cursor) — llvm-cov 86.28 % lines

## Checkpoint C: Complete
- [x] All spec success criteria met (table in progress.md)
- [x] Independent review (security: verifier, secret handling, untrusted cache) (Claude 2026-10-25: passed after C12/C13)
- [x] **Owner approval** (2026-10-25)

**C12 (2026-10-25, Cursor):** cache labels re-validated on load (`[a-z0-9-]{1,63}`, no leading/trailing `-`; warn `clients.cache.invalid_label`); `fqdn` rejects non-normalised labels; optional hardenings (Zeroizing in `read_secret_parts`, rustls TLS classify via nested `io::Error`, no `install_default`, reused `GatewayClient`, classic site-key charset, cache `File::take`, `clients.sync.backoff`, sync lock only around build+install). Do not tick Independent review / Owner approval here.

**C13 (2026-10-25, Cursor):** discard stale fetches on UniFi config change — `apply_config(enabled=false)` manuals-only (keep labels, drop obs/retain); mid-flight fetch superseded when `UnifiConfig` changes / disabled / older seq; monotonic fetch seq. Do not tick Independent review / Owner approval.
