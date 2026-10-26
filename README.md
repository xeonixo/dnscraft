# DNScraft

A lightweight, self-hosted, recursive DNS resolver for home networks — written in Rust.

> **Status** (see [tasks/progress.md](tasks/progress.md)): `resolver`, `filtering`,
> `clients`, `tls` and `policy` are **complete**. `listeners` is **in progress**
> (Do53 / DoT / DoH h2+h1.1 / DoQ; next Checkpoint C). `control-api`, `web-ui`,
> `mcp` and `cluster` are **pending**.

- Recursive resolution from the root servers with DNSSEC validation — no upstream provider
- AdGuard-compatible filter lists, custom rules, "why was this blocked?"
- Split-horizon answers per source subnet, forward zones for private networks
- Do53, DoT, DoH (HTTP/2 + HTTP/1.1), DoQ — public access via per-device Client IDs (DoH over HTTP/3 planned)
- Certificates via ACME DNS-01 (Cloudflare)
- UniFi integration for device names in the query log
- Multi-node (master + sub-nodes), Docker-first, multiple NICs (planned)
- Web UI with OIDC single sign-on, fully internationalized (planned)

## Try the resolver

```bash
cargo run -p dnscraft-resolver --example query -- example.com A
```

## Workspace layout

| Crate | Role | Module id |
|-------|------|-----------|
| [`dnscraft-proto`](crates/dnscraft-proto/README.md) | DNS wire format and DNSSEC record types | (shared) |
| [`dnscraft-testkit`](crates/dnscraft-testkit/README.md) | Fake DNS hierarchy for tests | (shared) |
| [`dnscraft-resolver`](crates/dnscraft-resolver/README.md) | Recursive resolution, DNSSEC, cache | [`resolver`](CAPABILITY-MAP.md) |
| [`dnscraft-filtering`](crates/dnscraft-filtering/README.md) | AdGuard-compatible filter lists | [`filtering`](CAPABILITY-MAP.md) |
| [`dnscraft-clients`](crates/dnscraft-clients/README.md) | UniFi + manual client enrichment | [`clients`](CAPABILITY-MAP.md) |
| [`dnscraft-tls`](crates/dnscraft-tls/README.md) | ACME DNS-01, cert store, DynDNS, SNI helpers | [`tls`](CAPABILITY-MAP.md) |
| [`dnscraft-policy`](crates/dnscraft-policy/README.md) | Views/profiles and the query pipeline | [`policy`](CAPABILITY-MAP.md) |
| [`dnscraft-listeners`](crates/dnscraft-listeners/README.md) | Do53 / DoT / DoH / DoQ listeners | [`listeners`](CAPABILITY-MAP.md) |

## Documentation

- [CAPABILITY-MAP.md](CAPABILITY-MAP.md) — modules, dependencies, build order
- [SPEC.md](SPEC.md) — project-wide specification
- [SPEC-resolver.md](SPEC-resolver.md) · [SPEC-filtering.md](SPEC-filtering.md) ·
  [SPEC-clients.md](SPEC-clients.md) · [SPEC-tls.md](SPEC-tls.md) ·
  [SPEC-policy.md](SPEC-policy.md) · [SPEC-listeners.md](SPEC-listeners.md)
- Crate READMEs: [proto](crates/dnscraft-proto/README.md),
  [testkit](crates/dnscraft-testkit/README.md),
  [resolver](crates/dnscraft-resolver/README.md),
  [filtering](crates/dnscraft-filtering/README.md),
  [clients](crates/dnscraft-clients/README.md),
  [tls](crates/dnscraft-tls/README.md),
  [policy](crates/dnscraft-policy/README.md),
  [listeners](crates/dnscraft-listeners/README.md)
- [docs/adr/](docs/adr/) — architecture decision records:
  [0001 recursion engine](docs/adr/0001-recursion-engine.md),
  [0002 ring-only crypto](docs/adr/0002-ring-only-crypto.md),
  [0003 policy ClientDirectory](docs/adr/0003-policy-client-directory.md),
  [0004 listeners Admission](docs/adr/0004-listeners-shared-admission.md),
  [0005 injectable Clock](docs/adr/0005-injectable-clock.md)
- [fuzz/README.md](fuzz/README.md) — fuzz targets, corpora and CI job
- [tasks/progress.md](tasks/progress.md) — progress log (resume point)
- [tasks/cursor-next.md](tasks/cursor-next.md) — agent workflow rules and templates

## Development

Definition of done (all green; same commands as [`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check
```

MSRV is **1.88** (`rust-version` in the workspace `Cargo.toml`); CI uses the
`stable` toolchain. TLS/crypto is **ring-only**: `cargo deny` bans `aws-lc-rs`,
`aws-lc-sys`, `openssl` and `openssl-sys` (see [`deny.toml`](deny.toml)).
Fuzz targets live under [`fuzz/`](fuzz/README.md) (nightly + `cargo-fuzz` in CI).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
