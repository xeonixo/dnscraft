# dnscraft-tls

ACME DNS-01 certificates (Cloudflare), hot-reloadable `CertResolver`,
DynDNS, and SNI helpers for DNScraft encrypted DNS listeners (`dns.<domain>` /
`*.dns.<domain>`).

Formal requirements: [`SPEC-tls.md`](../../SPEC-tls.md).

This crate does **not** bind sockets (`listeners`) and does **not** own the
Client-ID registry (`policy` / `control-api`).

## Cloudflare token

| Item | Value |
|------|--------|
| Permission | **Zone → DNS → Edit** (one zone) |
| Env | `DNSCRAFT_CLOUDFLARE_API_TOKEN` |
| File secret | `DNSCRAFT_CLOUDFLARE_API_TOKEN_FILE` (Docker / systemd credentials) |

Use a token scoped to a **single** zone that matches `public_domain`. Prefer
`*_FILE` over putting the token in the process environment. The token never
appears in `Debug` output (`Secret([redacted])`).

## Staging first (manual acceptance)

Automated tests never call real Let’s Encrypt, Cloudflare, or `cdn-cgi/trace`.
Owner / lead run this checklist against **Let’s Encrypt staging** once before
Checkpoint C / production cutover.

### Manual checklist (LE staging + real Cloudflare zone)

1. **Token:** Create a Cloudflare API token with **Zone → DNS → Edit** on exactly
   one zone; export it as `DNSCRAFT_CLOUDFLARE_API_TOKEN` (or `*_FILE`).
2. **Config:** `public_domain` = that zone’s apex; `acme.directory = "staging"`;
   `acme.email` set; `dyndns.hostname` = `<node>.dns.<domain>` with the label in
   `reserved_labels`; `proxied = false`. Prefer a throwaway data dir.
3. **Issue:** Start the node / call `TlsEngine::renew_now` (or equivalent UI).
   Confirm `_acme-challenge.dns.<domain>` TXT appears briefly, then is removed.
4. **Cert:** Inspect `<data>/tls/cert.pem` — SANs must be `dns.<domain>` and
   `*.dns.<domain>`; `key.pem` mode `0600`; `state.json` has `last_issue` and
   no `last_error`.
5. **Handshake:** Point a test client at `dns.<domain>` (DoT/DoH) with the
   staging-trusting roots if needed; confirm the served leaf matches the store
   (`CertResolver` / `openssl s_client -servername dns.<domain>`).
6. **DynDNS (optional):** With `dyndns.enabled`, confirm the node A/AAAA matches
   the echo IP; with `public_entry = true`, also `*.dns.<domain>` and
   `dns.<domain>`; with `false`, those names are untouched.
7. **Failure path:** Temporarily break the token or set Fake failure — renew
   must leave the previous `cert.pem`/`key.pem` in place and record a stable
   `tls.*` code in `state.json` / status.
8. **Promote:** Only after the above is green, wipe or replace `account.json`
   when switching `directory` to `production` (staging and production accounts
   differ), then repeat issue once on production.

## On-disk layout

Under `<data_dir>/tls/` (directory mode **0700**):

| File | Mode | Contents |
|------|------|----------|
| `account.json` | 0600 | ACME account credentials |
| `cert.pem` | 0600 | Leaf + chain PEM |
| `key.pem` | 0600 | Private key PEM |
| `meta.json` | 0600 | Cached identifiers / `not_after` / ARI id |
| `state.json` | 0600 | `last_error` code, `last_issue`, `last_renew_attempt` |

Writes are atomic (temp + fsync + rename). A failed renewal never replaces the
last good `cert.pem` / `key.pem`; errors land only in `state.json`.

`key.pem` and `account.json` must be mode **0600**. On load, group/other bits
yield `tls.store.permissions` (file name + mode only — never key/account bytes).
[`TlsEngine::open`](src/engine.rs) still succeeds: a too-open `key.pem` is **not**
installed into the resolver (refuse to serve that material); a too-open
`account.json` alone does not unload a good cert. In both cases
`status.last_error` / `state.json` record `tls.store.permissions` so the operator
can `chmod 0600` without restarting into a panic.

## Failure codes

| Code | Meaning |
|------|---------|
| `tls.config.invalid` | Config validation failed |
| `tls.secret.missing` | Cloudflare token env / `*_FILE` absent |
| `tls.acme.account` | ACME account create/load |
| `tls.acme.order` | ACME new-order / finalize |
| `tls.acme.challenge` | DNS-01 challenge |
| `tls.acme.rate_limited` | ACME 429 (`retry_after()` when known) |
| `tls.acme.propagation` | Challenge TXT not visible in time |
| `tls.cloudflare.http` | Cloudflare API non-success |
| `tls.cloudflare.zone` | Zone id / name not found |
| `tls.store.io` | Store disk I/O |
| `tls.store.corrupt` | Unreadable / mismatched PEM |
| `tls.store.permissions` | `key.pem` / `account.json` group/other bits |
| `tls.dyndns.echo` | Public IP echo failed |
| `tls.dyndns.update` | A/AAAA upsert failed |
| `tls.dyndns.entry_conflict` | More than one `public_entry` node |
| `tls.cert.expiring` | Status flag below warn threshold |
| `tls.cert.expired` | Status flag past `not_after` |

## Reserved labels (control-api / Client IDs)

SNI under `*.dns.<public_domain>` is either a **Client ID**, a **node hostname**,
or the apex `dns.<domain>`. Labels that must never be Client IDs:

- Fixed: `dns`, `www`, `api`, `admin`, `ns` ([`FIXED_RESERVED_LABELS`](src/sni.rs))
- Configured node names in `dyndns.reserved_labels` (e.g. `node1`, `node2`)

`control-api` / policy must reject Client-ID registrations that collide with
these. The DynDNS hostname’s leftmost label must be one of the configured
reserved (node) labels.

## DynDNS

- Echo URL configurable (default Cloudflare `cdn-cgi/trace`); IPv4 / IPv6 forced
  via bound clients (`0.0.0.0` / `::`).
- Upserts A/AAAA only when the content changes; DNS-only (`proxied = false`).
- `public_entry = true` (at most one node) also maintains `*.dns.<domain>` and
  `dns.<domain>`; other nodes never touch those names.
- Failures use `tls.dyndns.echo` / `tls.dyndns.update` and never touch the cert
  path.

## Engine

[`TlsEngine`](src/engine.rs) loads the last-good cert into `CertResolver` even
when ACME/Cloudflare are unreachable, runs renewal (ARI / `renew_before`) and
DynDNS in the background, and exposes `renew_now` / `dyndns_now` / `status` /
`apply_config`. Issuance is single-flight (scheduler and `renew_now` share one
order).

## Local Pebble (`#[ignore]`)

Ignored integration tests talk to a local
[Pebble](https://github.com/letsencrypt/pebble) server. CI does **not** run them;
the lead runs them at checkpoints.

```bash
# Terminal 1 — Pebble (challenges always valid for account-only tests)
docker run --rm -it -p 14000:14000 -p 15000:15000 \
  -e PEBBLE_VA_ALWAYS_VALID=1 \
  --name pebble \
  ghcr.io/letsencrypt/pebble:latest

# Copy the test CA out of the image (path may vary by tag)
docker cp pebble:/test/certs/pebble.minica.pem /tmp/pebble.minica.pem

# Terminal 2 — ignored tests
PEBBLE_ROOT_CA=/tmp/pebble.minica.pem \
PEBBLE_DIRECTORY_URL=https://localhost:14000/dir \
  cargo test -p dnscraft-tls -- --ignored pebble
```

The client trusts `PEBBLE_ROOT_CA` only (no global insecure-TLS switch). Full
DNS-01 issuance tests use the hand-written mock Cloudflare + loopback auth NS
alongside Pebble (see `tests/pebble.rs`).

## Crypto / deps

`instant-acme` with `default-features = false` and
`features = ["ring", "rcgen", "time", "x509-parser"]` — **no** `aws-lc-rs`,
**no** OpenSSL. ACME HTTP uses workspace `reqwest` (rustls+ring). Gate:

```bash
cargo tree -p dnscraft-tls -i aws-lc-rs    # must be empty
cargo tree -p dnscraft-tls -i openssl-sys  # must be empty
```

## Tests

```bash
cargo test -p dnscraft-tls --locked
```

Mocks only: Fake ACME, loopback Cloudflare API, loopback echo, `ManualClock`.
Never hit the internet from automated tests.
