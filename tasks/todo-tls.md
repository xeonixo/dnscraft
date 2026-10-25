# Tasks: `tls` module

> Plan: [plan-tls.md](plan-tls.md) · Spec: [SPEC-tls.md](../SPEC-tls.md) · Resume log: [progress.md](progress.md)
> Definition of done per task: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
> `cargo test --workspace --locked` green; `cargo tree -i aws-lc-rs` empty; lead review; committed.
> Never call real Let's Encrypt, Cloudflare or `cdn-cgi/trace` from tests; use `example.com` and documentation ranges.

## Phase 1: Foundation

## Task L1: Crate skeleton, config, errors, secrets

**Description:** Create `crates/dnscraft-tls` (workspace member, workspace lints) with the approved
dependencies.

`TlsConfig` holds the spec excerpt as Rust values:
- `public_domain`, `extra_sans` (must be empty in v1), `KeyType::{EcdsaP256, EcdsaP384}`,
  `renew_before`, `expiry_warn`;
- `AcmeConfig`: `enabled`, `directory` (production / staging / URL), `email`, propagation
  timeout and poll;
- `CloudflareConfig`: `zone_id` optional;
- `DynDnsConfig`: `enabled`, `hostname`, `public_entry`, `reserved_labels`, `interval`,
  `echo_url`, `ipv4`, `ipv6`, `proxied` (must be false).

`validate()` checks:
- The domain is normalised.
- The DynDNS hostname is `<label>.dns.<public_domain>` with a reserved label.
- The email is present when ACME is enabled.
- Only HTTPS URLs, with a `#[doc(hidden)]` loopback test hatch.

Also in this task:
- `validate_public_entry(&[NodeEntry])` → `tls.dyndns.entry_conflict` when more than one entry
  node is configured (used later by cluster/control-api).
- `TlsError` with every code from the spec.
- `Clock` + `ManualClock`.
- `read_secret("DNSCRAFT_CLOUDFLARE_API_TOKEN")`, redacted in `Debug`.

**Acceptance criteria:**
- [x] Every error variant has a unique `code()` (enumerating test); public items documented
- [x] Config table tests incl. non-empty `extra_sans`, `proxied = true`, hostname outside `dns.<domain>`, missing email, two public entry nodes
- [x] Missing token with ACME or DynDNS enabled → `tls.secret.missing`; token never in `Debug`

**Verification:** `cargo test -p dnscraft-tls config`

**Dependencies:** plan + dependency table approved

**Files:** `Cargo.toml`, `crates/dnscraft-tls/{Cargo.toml,src/lib.rs,src/config.rs,src/error.rs,src/clock.rs,src/secret.rs}`

**Scope:** M

## Task L2: SNI helpers

**Description:** Implement `ReservedLabels::new(node_names)` (plus the fixed set `dns`, `www`, `api`,
`admin`, `ns`), `contains`, `SniKind`, `parse_client_id_sni`, the `ClientIdRegistry` trait and
`accept_public_sni`, as in the spec.
- Matching is case-insensitive, and a trailing dot is accepted.
- Only exactly one label below `dns.<domain>` counts as a Client ID. `a.b.dns.<domain>` is `Other`.
- `accept_public_sni`: missing SNI, `Apex`, `NodeHostname` and `Other` → false. `ClientId` →
  true only when registered.
- Doc comment: `NodeHostname`/`Apex` must not count as an unknown-ID strike.

**Acceptance criteria:**
- [x] Table tests: registered / unregistered ID, `node1.dns.example.com` → `NodeHostname`, apex, `DNS.Example.COM.`, two-label subdomain, other domain, suffix trick `dns.example.com.evil.net`
- [x] Proptest: `parse_client_id_sni` never panics; `ClientId(x)` implies `!reserved.contains(x)`

**Verification:** `cargo test -p dnscraft-tls sni`

**Dependencies:** L1 · **Files:** `src/sni.rs`, `tests/sni.rs` · **Scope:** S

## Task L3: Certificate store and `CertResolver`

**Description:** `CertStore::open(data_dir)`:
- The directory is created 0700 (an existing directory with wider permissions is tightened or
  refused with `tls.store.io`).
- `load()` returns chain + key + parsed `not_after` and identifiers via `x509-parser`. An
  unreadable PEM → `tls.store.corrupt` while the previous files are kept.
- `save(chain, key, meta)`: atomic writes, 0600.
- `account.json` read/write.

`CertResolver`:
- `RwLock<Arc<CertifiedKey>>`, initially empty (resolve → `None`).
- `install(chain, key)` builds the `CertifiedKey` with the ring provider, then swaps.
- `import(chain_pem, key_pem)` validates and persists, then installs (for a future cluster push).
- Implements `ResolvesServerCert`.

**Acceptance criteria:**
- [x] Round trip save → load; file modes 0600 / 0700 asserted; corrupt PEM → `tls.store.corrupt`, old cert still served
- [x] tokio-rustls handshake (rcgen self-signed) sees cert A, `install(B)`, the next handshake sees B while an open connection stays up
- [x] Key PEM never appears in `Debug`/`Display` of any public type (test)

**Verification:** `cargo test -p dnscraft-tls store`

**Dependencies:** L1 · **Files:** `src/store.rs`, `src/resolver.rs`, `tests/store.rs`, `tests/resolver.rs` · **Scope:** M

## Task L4: instant-acme wiring spike

**Description:** This task proves the dependency wiring before the flow is built on top of it.
- Add `instant-acme` 0.8.5 with `default-features = false` and features `ring`, `rcgen`, `time`, `x509-parser`.
- Implement instant-acme's `HttpClient` over the workspace reqwest client.
  - If 0.8.5's trait shape makes that unreasonable, enable `hyper-rustls` + `ring` with webpki
    roots instead, and record why in progress.md.
- Define the internal `AcmeDirectory` / `AcmeOrder` traits; the instant-acme implementation
  covers account create/load only so far.
- Account credentials go to `account.json` (0600) and are reused on the next start.
- Directory URL mapping: production / staging / custom.
- Pebble test `#[ignore]`: create an account against a local Pebble and reload it. The README
  section documents the `docker run` and `PEBBLE_VA_ALWAYS_VALID=1`. The test trusts Pebble's
  test CA via a test-only root option.

**Acceptance criteria:**
- [x] `cargo tree -i aws-lc-rs` and `cargo tree -i openssl-sys` empty; output pasted into the commit message
- [x] Unit test: credentials persisted 0600 and reloaded (fake directory)
- [x] `cargo test -p dnscraft-tls -- --ignored pebble` passes locally against Pebble (lead runs it at Checkpoint A)

**Verification:** `cargo test -p dnscraft-tls acme` (+ ignored Pebble test locally)

**Dependencies:** L1, L3 · **Files:** `Cargo.toml`, `crates/dnscraft-tls/{Cargo.toml,src/acme.rs,src/acme_http.rs}`, `tests/pebble.rs` · **Scope:** M

## Checkpoint A: Foundation
- [x] DoD green; dependency tree free of aws-lc/openssl
- [x] HTTP-stack decision (reqwest adapter vs hyper-rustls) recorded in progress.md; owner informed if the fallback was used
- [x] Lead review (2026-10-25; fixes in 23c0714)

## Phase 2: Issuance

## Task L5: Cloudflare DNS client + mock

**Description:** `CloudflareClient`:
- Bearer token.
- Zone id from config or resolved by name (`GET /zones?name=`); zone details include `name_servers`.
- Records: list by name + type; create, update (PUT/PATCH) and delete.
- TXT records are added, never upserted, so two values can coexist at one name.
- A/AAAA records are upserted with `proxied: false` and TTL auto.
- Cloudflare's `success` / `errors` envelope is parsed; non-success → `tls.cloudflare.http`
  (401/403/429 included, `Retry-After` kept); zone not found → `tls.cloudflare.zone`.
- 30 s timeout, 1 MiB body cap.
- One writer mutex shared via `Arc` (used by L7 and L9).
- The hand-written mock Cloudflare server (plain HTTP on loopback through the test hatch) keeps
  records in memory and records the requests.

**Acceptance criteria:**
- [x] Mock: two TXT values at `_acme-challenge.dns.example.com` coexist; delete removes only the one asked for
- [x] Zone by name; unknown zone → `tls.cloudflare.zone`; 429 → `tls.cloudflare.http` with retry hint
- [x] Token sent as `Authorization: Bearer`; token absent from errors

**Verification:** `cargo test -p dnscraft-tls --test cloudflare`

**Dependencies:** L1 · **Files:** `src/cloudflare.rs`, `tests/support/mock_cloudflare.rs`, `tests/cloudflare.rs` · **Scope:** M

## Task L6: Propagation check

**Description:** `wait_for_txt(name, expected: &[String], nameservers: &[SocketAddr], poll, timeout, clock)`:
- Builds a TXT query with `dnscraft-proto`, sent over UDP to each nameserver, with a random
  query id and a matching check on the response.
- Succeeds when **all** expected values are present at **every** nameserver.
- Polls every 5 s; after 2 min → `tls.acme.propagation`.
- Nameserver names are resolved once via `tokio::net::lookup_host`.
- Tests use a `dnscraft-testkit` responder (or a tiny UDP responder) whose TXT set changes over
  time.

**Acceptance criteria:**
- [x] Values appear after 2 polls → success; only one of two values → keeps waiting; never → `tls.acme.propagation` (`ManualClock` / paused time)
- [x] Mismatched query id / truncated response ignored, no panic

**Verification:** `cargo test -p dnscraft-tls --test propagation`

**Dependencies:** L1 · **Files:** `src/propagation.rs`, `tests/propagation.rs` · **Scope:** S

## Task L7: Issuance flow

**Description:** `issue(&dyn AcmeDirectory, &CloudflareClient, &CertStore, &CertResolver, cfg)`:
1. Account.
2. Order for `dns.<d>` + `*.dns.<d>`.
3. For each authorization, collect the DNS-01 value.
4. Under the writer mutex, create all TXT records.
5. `wait_for_txt` for all values.
6. Set the challenges ready and poll the order (errors → `tls.acme.challenge`, rate limit →
   `tls.acme.rate_limited`).
7. Finalize with an rcgen ECDSA key + CSR (key type from config).
8. Download the chain, store, install.
9. Delete the TXT records (best effort), with orphan cleanup of stale `_acme-challenge` TXT
   records at the start of the next run.

Then implement the remaining instant-acme order methods behind the trait.

**Acceptance criteria:**
- [ ] Fake-ACME test: the whole flow issues, stores and installs; TXT records deleted afterwards; key type P-384 honoured
- [ ] Failure at challenge / finalize / propagation → stable code, previous cert still installed and on disk
- [ ] Pebble `#[ignore]` test issues a cert for `dns.example.com` + `*.dns.example.com` (`PEBBLE_VA_ALWAYS_VALID=1`) and `CertResolver` serves it

**Verification:** `cargo test -p dnscraft-tls issue` (+ ignored Pebble test locally)

**Dependencies:** L4, L5, L6 · **Files:** `src/issue.rs`, `src/acme.rs`, `tests/issue.rs`, `tests/pebble.rs` · **Scope:** M

## Task L8: Renewal scheduler

**Description:** `next_renewal(meta, ari_window, now)`:
- With an ARI window, pick a random point inside it.
- Otherwise use `not_after − renew_before` (30 d).

Scheduler loop on the injectable clock:
- Renew at that time.
- Transient errors → exponential backoff with jitter (cap 6 h), honouring `Retry-After`.
- The last good cert is never deleted.
- Status flags `tls.cert.expiring` (< `expiry_warn`, 14 d) and `tls.cert.expired`.
- Only runs when `acme.enabled`.

**Acceptance criteria:**
- [ ] `ManualClock` table: no cert → issue now; ARI window used when present; fallback 30 d; backoff sequence capped; `Retry-After` respected
- [ ] Expiring / expired flags at the 14 d / 0 d boundaries
- [ ] `acme.enabled = false` → never orders, still loads/imports

**Verification:** `cargo test -p dnscraft-tls renew`

**Dependencies:** L7 · **Files:** `src/renew.rs`, `src/status.rs`, `tests/renew.rs` · **Scope:** M

## Checkpoint B: Issuance
- [ ] Spec success criteria 1, 2, 5 shown (fake ACME + Pebble locally)
- [ ] Lead review; progress.md updated

## Phase 3: DynDNS and engine

## Task L9: DynDNS

**Description:** `dyndns_once(cfg, echo, cloudflare)`:
- Echo per family (clients bound to `0.0.0.0` / `::`), parse the `ip=` line, validate the family.
- Compare with the current Cloudflare A/AAAA for the node hostname; update only on change.
- On the public entry node, also `*.dns.<d>` and `dns.<d>`, with the same compare rule. Other
  nodes never touch them.
- Uses the shared writer mutex.
- Interval 5 min ±10 %, plus startup and `dyndns_now`.
- A family without a route is skipped (status note). Echo failure → `tls.dyndns.echo`, update
  failure → `tls.dyndns.update`; neither touches the cert path.
- The echo URL is configurable; tests use a local echo mock.

**Acceptance criteria:**
- [ ] Same IP → zero write requests (mock asserts); changed IP → exactly one update per record
- [ ] `public_entry = true` creates wildcard + apex A/AAAA; `false` never requests those names (spec 4a)
- [ ] Echo garbage / wrong family → `tls.dyndns.echo`; Cloudflare 500 → `tls.dyndns.update`, cert untouched

**Verification:** `cargo test -p dnscraft-tls dyndns`

**Dependencies:** L5 · **Files:** `src/dyndns.rs`, `tests/dyndns.rs` · **Scope:** M

## Task L10: `TlsEngine`

**Description:**
- `TlsEngine::open(config, data_dir, clock)`: loads the last good cert into the resolver even
  when ACME and Cloudflare are unreachable.
- `resolver()`, `status()` (`TlsStatus` fields from the spec), `apply_config()` (validates,
  restarts tasks; a domain change triggers a new order), `renew_now()`, `dyndns_now()`.
- Background tasks hold a `Weak` and are aborted on drop.

**Acceptance criteria:**
- [ ] Start with a stored cert and unreachable mocks → resolver serves it, status shows the error code and days to expiry
- [ ] `renew_now` / `dyndns_now` work against mocks; concurrent calls do not double-order (single-flight)
- [ ] Engine drop stops all tasks (`Weak` test)

**Verification:** `cargo test -p dnscraft-tls engine`

**Dependencies:** L8, L9 · **Files:** `src/engine.rs`, `src/status.rs`, `tests/engine.rs` · **Scope:** M

## Task L11: Polish

**Description:**
- README:
  - Cloudflare token scope (Zone → DNS → Edit, one zone);
  - env names;
  - staging-first manual acceptance;
  - Pebble how-to;
  - file layout and modes;
  - reserved labels for control-api.
- Docs on every public item; coverage report.
- A test that formats every status/error and asserts no `BEGIN` PEM marker and no token
  appears.
- Spec success criteria table in progress.md.

**Acceptance criteria:**
- [ ] README complete; no `missing_docs`
- [ ] Secret-leak test passes
- [ ] Success criteria table with covering tests

**Verification:** DoD + `cargo test -p dnscraft-tls`

**Dependencies:** L10 · **Files:** `crates/dnscraft-tls/README.md`, `tests/no_leak.rs` · **Scope:** S

## Checkpoint C: Complete
- [ ] All spec success criteria met
- [ ] Independent security review (keys, file modes, token handling, SNI predicate)
- [ ] Manual acceptance against LE **staging** with the owner's Cloudflare zone (owner runs it; not automated)
- [ ] **Owner approval**
