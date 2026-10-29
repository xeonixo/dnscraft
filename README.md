# DNScraft

Self-hosted recursive DNS for home networks — Rust, Docker-first, no upstream
resolver required.

DNScraft walks the delegation chain from the root with DNSSEC validation,
applies AdGuard-compatible filter lists, answers split-horizon names per
source subnet, and serves Do53 / DoT / DoH / DoQ. A control API (and optional
MCP endpoint) manages configuration, the query log, and stats. A multi-node
cluster and an embedded web UI are part of the same binary.

## Features

- **Recursion + DNSSEC** — no forwarding of public names to a third-party resolver
- **Filtering** — AdGuard DNS / hosts syntax, custom rules, temporary allows,
  blocked-services catalog, “why was this blocked?”
- **Policy** — views by source IP/subnet, local records, forward zones,
  SafeSearch, schedules, rebind protection, pause
- **Clients** — UniFi inventory + manual names for the query log and local PTR
- **Encrypted DNS** — DoT, DoH (HTTP/2 + HTTP/1.1 + HTTP/3), DoQ; public access
  via per-device Client IDs (`<id>.dns.<domain>` / `/dns-query/<id>`)
- **TLS** — ACME DNS-01 (Cloudflare), cert store, DynDNS
- **Control plane** — REST `/api/v1`, OIDC + break-glass login, API tokens,
  audit log, backups
- **MCP** — 14 tools for AI assistants on `/mcp/v1` (opt-in; same RBAC family)
- **Cluster** — master + sub-nodes, config sync, write relay, log aggregation
- **Web UI** — SvelteKit SPA (en/de), embeddable into the binary (`web-ui` feature)

## Status

| Area | State |
|------|--------|
| `resolver`, `filtering`, `clients`, `tls`, `policy`, `listeners` | Complete |
| `control-api`, `mcp`, `cluster` | Complete and wired into the `dnscraft` binary |
| `web-ui` | App + mock server usable; `rust-embed` landed behind `--features web-ui` (copy `web/build` → `embed-web-ui/` for a real release build) |

Details and resume point: [`tasks/progress.md`](tasks/progress.md). Module index:
[`CAPABILITY-MAP.md`](CAPABILITY-MAP.md).

## Quick start

### Local (loopback)

Requires Rust **1.88+** (workspace `rust-version`; CI uses `stable`).

```bash
cargo run -p dnscraft -- deploy/dnscraft.example.toml
dig @127.0.0.1 -p 5300 example.com A +short
curl -fsS http://127.0.0.1:8080/healthz
```

The sample binds plain DNS on `127.0.0.1:5300` and the control API on loopback
`:8080`. Persistence defaults under the process `data_dir` (see the TOML).
Secrets (TLS PEMs, OIDC, UniFi, Cloudflare, cluster join) come from the
environment or `*_FILE` — never from the config file. See
[`deploy/README.md`](deploy/README.md).

### Docker

```bash
docker compose up --build
curl -fsS http://127.0.0.1:8080/healthz
dig @127.0.0.1 -p 5300 example.com A +short
```

DNS on host port **5300**, control API on **8080**, data in the
`dnscraft-data` volume. Image variants (glibc vs musl/scratch) and Buildx:
[`deploy/README.md`](deploy/README.md).

### Resolver library only

```bash
cargo run -p dnscraft-resolver --example query -- example.com A
```

### Web UI (dev)

```bash
cd web && pnpm install --frozen-lockfile
pnpm build && pnpm mock   # mock control-api on :4173 + static SPA
# or: pnpm dev            # Vite against a real/mock API
```

See [`web/README.md`](web/README.md).

## Architecture

```text
                    ┌─────────────────────────────────────────┐
  Do53/DoT/DoH/DoQ  │              dnscraft (binary)          │
 ─────────────────► │  listeners → policy → filtering/resolver│
                    │         ↑              ↑                │
                    │    clients/tls    control-api           │
                    │                   ├─ /api/v1  REST      │
                    │                   ├─ /mcp/v1  MCP       │
                    │                   ├─ cluster  mTLS      │
                    │                   └─ optional web UI    │
                    └─────────────────────────────────────────┘
```

Query path: listeners stamp metadata → `PolicyEngine` selects a view/profile →
filter / local records / forward / recurse → answer. The control plane never
shares sockets with public DoH/DoT/DoQ listeners.

| Crate | Role |
|-------|------|
| [`dnscraft`](crates/dnscraft/README.md) | Server binary (TOML bootstrap + assembler) |
| [`dnscraft-proto`](crates/dnscraft-proto/README.md) | DNS wire format + DNSSEC types |
| [`dnscraft-common`](crates/dnscraft-common/README.md) | Shared `Clock`, `Secret`, net/config helpers |
| [`dnscraft-testkit`](crates/dnscraft-testkit/README.md) | Fake DNS hierarchy for tests |
| [`dnscraft-resolver`](crates/dnscraft-resolver/README.md) | Recursion, DNSSEC, cache |
| [`dnscraft-filtering`](crates/dnscraft-filtering/README.md) | Filter lists and matching |
| [`dnscraft-clients`](crates/dnscraft-clients/README.md) | UniFi + manual client directory |
| [`dnscraft-tls`](crates/dnscraft-tls/README.md) | ACME, cert store, DynDNS |
| [`dnscraft-policy`](crates/dnscraft-policy/README.md) | Views/profiles and query pipeline |
| [`dnscraft-listeners`](crates/dnscraft-listeners/README.md) | Do53 / DoT / DoH / DoQ |
| [`dnscraft-api`](crates/dnscraft-api/README.md) | REST, auth, query log, stats, MCP/cluster wiring |
| [`dnscraft-mcp`](crates/dnscraft-mcp/README.md) | MCP protocol + 14 tools |
| [`dnscraft-cluster`](crates/dnscraft-cluster/README.md) | Master/sub-node protocol |
| [`web/`](web/README.md) | SvelteKit SPA |

Build order and module ids: [`CAPABILITY-MAP.md`](CAPABILITY-MAP.md).

## Configuration

Node-local bootstrap is TOML. Versioned runtime config (filters, policy,
listeners, …) lives in SQLite under `data_dir` and is edited via the API / UI;
the TOML seeds an empty store and still owns non-replicated fields (bind
addresses, cluster role, secrets paths).

| File | Use |
|------|-----|
| [`deploy/dnscraft.example.toml`](deploy/dnscraft.example.toml) | Local loopback smoke |
| [`deploy/dnscraft.docker.toml`](deploy/dnscraft.docker.toml) | Compose / image default |

```bash
# Health
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz

# REST surface (auth required for /api/v1/*)
# MCP is opt-in: [control_api.mcp] enabled = true
```

Full endpoint list: [`docs/API-REFERENCE.md`](docs/API-REFERENCE.md).

## Documentation

| Doc | Contents |
|-----|----------|
| [`SPEC.md`](SPEC.md) | Project-wide goals and non-goals |
| [`SPEC-*.md`](SPEC.md) | Per-module requirements |
| [`docs/API-REFERENCE.md`](docs/API-REFERENCE.md) | REST + MCP explorer |
| [`docs/adr/`](docs/adr/) | Architecture decisions |
| [`deploy/README.md`](deploy/README.md) | Docker images, ports, secrets |
| [`fuzz/README.md`](fuzz/README.md) | Fuzz targets and CI |
| [`tasks/progress.md`](tasks/progress.md) | Progress log / resume point |
| [`tasks/cursor-next.md`](tasks/cursor-next.md) | Agent workflow rules |

ADRs: [0001 recursion](docs/adr/0001-recursion-engine.md) ·
[0002 ring-only crypto](docs/adr/0002-ring-only-crypto.md) ·
[0003 policy ClientDirectory](docs/adr/0003-policy-client-directory.md) ·
[0004 listeners admission](docs/adr/0004-listeners-shared-admission.md) ·
[0005 injectable Clock](docs/adr/0005-injectable-clock.md) ·
[0006 MCP rmcp](docs/adr/0006-mcp-rmcp-stateless.md).

## Development

Same gates as [`.github/workflows/ci.yml`](.github/workflows/ci.yml):

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check
```

MSRV **1.88**. Crypto is **ring-only** (`deny.toml` bans `aws-lc-*` and
`openssl*`). Fuzz targets need nightly + `cargo-fuzz` ([`fuzz/`](fuzz/README.md)).

Web UI: `pnpm check`, `pnpm lint`, `pnpm test`, `pnpm test:e2e` under `web/`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
