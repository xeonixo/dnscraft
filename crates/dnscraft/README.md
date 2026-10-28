# dnscraft

DNScraft server binary: loads a TOML bootstrap, builds the resolver / filter /
policy / listener engines, opens the control API, and optionally mounts MCP and
the cluster runtime.

The DNS work lives in the other crates; this package is the assembler that
turns a config file + environment secrets into a running node.

## Build and run

```bash
cargo build -p dnscraft
cargo run -p dnscraft -- deploy/dnscraft.example.toml
```

The only argument is a TOML config path. Samples:

| File | Use |
|------|-----|
| [`deploy/dnscraft.example.toml`](../../deploy/dnscraft.example.toml) | Loopback Do53 on `127.0.0.1:5300`; control API defaults on loopback |
| [`deploy/dnscraft.docker.toml`](../../deploy/dnscraft.docker.toml) | Compose / image (`0.0.0.0` binds for published ports) |

```bash
dig @127.0.0.1 -p 5300 example.com A +short
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

Docker: see the [root README](../../README.md) and [`deploy/README.md`](../../deploy/README.md).

## What starts

1. Parse TOML + load env/`*_FILE` secrets (TLS PEMs, cluster join token, …).
2. Open `data_dir` SQLite (`dnscraft.db`): seed from TOML when empty, then
   `apply_stored_current` so a second boot restores the last API snapshot
   without inventing a new version.
3. Build engines (resolver, filtering, clients, tls, policy) and start listeners.
4. Serve the control API (`/healthz`, `/readyz`, `/api/v1`, …).
5. If `[control_api.mcp] enabled = true`, mount `/mcp/v1`.
6. If `[cluster] role` is `master` or `sub_node`, start `ClusterRuntime`
   (registry / offline queue in `cluster.db`).

Public DoH/DoT/DoQ listeners never expose the control plane; path isolation is
enforced in `dnscraft-listeners` and regression-tested in `dnscraft-api`.

## Configuration (bootstrap)

```toml
public_domain = "example.com"
# node_id = "local"           # cluster / view matching; default standalone "local"
# data_dir = "/var/lib/dnscraft"

[log]
queries = true                # optional stdout JSON-lines debug stream
# ip_truncate = "none"        # none | last_octet | last_group

[[listeners]]
id = "lan-udp"
protocol = "udp53"            # udp53 | tcp53 | dot | doh | doq
address = "127.0.0.1:5300"
# exposure = "local"          # "public" only for dot/doh/doq
# h3 = false                  # doh: also serve HTTP/3 on the same UDP port

# [control_api]               # bind, auth, query_log, mcp, …
# [cluster]                   # role = "standalone" | "master" | "sub_node"
# [resolver] / [filtering] / [clients] / [tls] / [policy] / …
```

- `public_domain` (required) — SNI/DDR apex (`dns.<domain>`).
- `listeners` — one `[[listeners]]` table each; `id` must match `[a-z0-9-]{1,64}`.
- Versioned runtime config (filter sets, views, …) is owned by the control-api
  store after first boot; editing those sections in TOML only affects an empty
  database seed.
- Full field docs: module SPECs and [`docs/API-REFERENCE.md`](../../docs/API-REFERENCE.md).

## Secrets

TLS material and other credentials never go in the TOML file. For each secret
set **exactly one** of the PEM-in-env or `*_FILE` variable (both set → error).

| Variable | Purpose |
|---|---|
| `DNSCRAFT_TLS_CERT` / `*_FILE` | PEM chain for encrypted listeners |
| `DNSCRAFT_TLS_KEY` / `*_FILE` | PEM private key |
| `DNSCRAFT_OIDC_CLIENT_SECRET` / `*_FILE` | OIDC client secret |
| `DNSCRAFT_UNIFI_API_KEY` / `*_FILE` | UniFi API key |
| `DNSCRAFT_CLOUDFLARE_API_TOKEN` / `*_FILE` | ACME DNS-01 |
| `DNSCRAFT_CLUSTER_JOIN_TOKEN` / `*_FILE` | Sub-node enrollment |
| `DNSCRAFT_CLUSTER_MASTER_CERT_FILE` | Pinned master PEM (bootstrap) |

Incomplete pairs exit with code 2 (`dnscraft.config.tls_env_incomplete` /
conflict variants). Without TLS secrets, encrypted listeners bind but fail
handshakes with `listeners.tls.no_cert` until ACME or an upload installs a cert.

## Query log

Persisted query log and stats live in the control-api SQLite store (API + MCP).
When `[log] queries = true`, each answered query is also written to **stdout**
as one JSON object (startup notices go to stderr):

```json
{"answer_size":42,"client_id":null,"duration_ms":7,"listener_id":"lan-udp","profile_id":"default","protocol":"udp53","qclass":"IN","qname":"example.com.","qtype":"A","rcode":"NoError","source":"192.0.2.10","time":1700000000.0,"view_id":"default"}
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | graceful shutdown after SIGTERM/SIGINT |
| `2` | config/usage error, TLS bootstrap error, or startup failure |

## Manual interop (not run)

> **Not run** — needs a real certificate and a public domain.

```bash
dig @dns.example.com example.com A +short
kdig @dns.example.com +tls +tls-hostname=dns.example.com example.com A
curl --http2 --doh-url https://dns.example.com/dns-query https://example.com/ -o /dev/null -w '%{http_code}\n'
```

## Embedded web UI

The binary depends on `dnscraft-api` without the `web-ui` feature by default.
To serve the SPA from the same process:

1. `cd web && pnpm build`
2. Copy `web/build/*` into `crates/dnscraft-api/embed-web-ui/`
3. Build with `--features web-ui` on `dnscraft-api` (wire that feature through
   this package’s Cargo.toml when cutting a UI-enabled release)

See [`tasks/w10-rust-embed-notes.md`](../../tasks/w10-rust-embed-notes.md) and
[`web/README.md`](../../web/README.md).
