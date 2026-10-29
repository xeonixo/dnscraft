# Deploying DNScraft (Docker)

Container delivery for the [`dnscraft`](../crates/dnscraft/) binary. Sample
config: [`dnscraft.example.toml`](dnscraft.example.toml) (loopback dev) and
[`dnscraft.docker.toml`](dnscraft.docker.toml) (compose / image default).

Project overview and non-Docker quick start: [root README](../README.md).
Binary behaviour (control API, MCP, cluster): [`crates/dnscraft/README.md`](../crates/dnscraft/README.md).

## Quick smoke (compose)

From the repository root:

```bash
docker compose up --build
curl -fsS http://127.0.0.1:8080/healthz
dig @127.0.0.1 -p 5300 example.com A +short
```

Data persists in the `dnscraft-data` volume (`data_dir = /var/lib/dnscraft`).

## Images

| File | Runtime | Notes |
|------|---------|--------|
| [`Dockerfile`](../Dockerfile) | Debian bookworm-slim (glibc) | **Default.** Includes `curl` for `HEALTHCHECK` on `/healthz` (loopback inside the container). |
| [`Dockerfile.musl`](../Dockerfile.musl) | `scratch` + static musl binary | Smaller attack surface; no shell/curl — mount config and use compose/Kubernetes HTTP probes. |

### Releases

Pushing a tag `vX.Y.Z` (must equal the `dnscraft` crate version) runs
[`release.yml`](../.github/workflows/release.yml): it builds the glibc image for
`linux/amd64` + `linux/arm64` (each on a native runner, in parallel), pushes it to `ghcr.io/xeonixo/dnscraft`
(`X.Y.Z`, `X.Y`, `latest`) and creates a GitHub Release.

```bash
# bump version in crates/*/Cargo.toml, commit, then:
git tag v0.1.0 && git push origin v0.1.0
docker pull ghcr.io/xeonixo/dnscraft:0.1.0
```

### Why glibc is the default

The workspace targets glibc Linux in CI. A musl static build needs the Alpine
musl toolchain in Docker (see `Dockerfile.musl`) but is not wired into CI yet.
`rusqlite` uses the bundled SQLite amalgamation; `ring` links cleanly on both
glibc and musl when built inside the musl builder stage.

## Build (single platform)

```bash
docker build -t dnscraft:local -f Dockerfile .
```

Musl / scratch:

```bash
docker build -t dnscraft:musl -f Dockerfile.musl .
# Mount config at runtime, e.g.:
docker run --rm -v "$PWD/deploy/dnscraft.docker.toml:/config/config.toml:ro" \
  -v dnscraft-data:/var/lib/dnscraft -p 5300:5300/udp -p 5300:5300/tcp \
  dnscraft:musl
```

## Multi-arch (`linux/amd64`, `linux/arm64`)

Requires [Docker Buildx](https://docs.docker.com/build/building/multi-platform/).

Glibc (recommended):

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f Dockerfile \
  -t dnscraft:latest \
  --load \
  .
```

For a registry push (not required for local dev), drop `--load` and use `--push`.

Musl / scratch:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f Dockerfile.musl \
  -t dnscraft:musl \
  --push \
  .
```

`Dockerfile.musl` maps `TARGETARCH` to `x86_64-unknown-linux-musl` or
`aarch64-unknown-linux-musl` and installs the target via `rustup` in the build
stage.

## Run without compose

```bash
docker build -t dnscraft:local .
docker run --rm \
  -p 5300:5300/udp -p 5300:5300/tcp -p 8080:8080/tcp \
  -v dnscraft-data:/var/lib/dnscraft \
  -v "$PWD/deploy/dnscraft.docker.toml:/etc/dnscraft/config.toml:ro" \
  dnscraft:local
```

## Secrets (never in the image)

Supply at runtime via environment variables or `*_FILE` paths (Docker secrets /
mounted PEM files). The binary rejects conflicting duplicate sources.

| Variable | Purpose |
|----------|---------|
| `DNSCRAFT_TLS_CERT` / `DNSCRAFT_TLS_CERT_FILE` | PEM chain for DoT/DoH/DoQ listeners |
| `DNSCRAFT_TLS_KEY` / `DNSCRAFT_TLS_KEY_FILE` | PEM private key |
| `DNSCRAFT_OIDC_CLIENT_SECRET` / `*_FILE` | OIDC client secret (control-api auth) |
| `DNSCRAFT_ADMIN_PASSWORD_FILE` | Seeds the local `break-glass` admin on a fresh install (only while no local account exists) |
| `DNSCRAFT_UNIFI_API_KEY` / `*_FILE` | UniFi integration |
| `DNSCRAFT_CLOUDFLARE_API_TOKEN` / `*_FILE` | ACME DNS-01 (see `dnscraft-tls`) |
| `DNSCRAFT_CLUSTER_JOIN_TOKEN` / `*_FILE` | Sub-node enrollment |
| `DNSCRAFT_CLUSTER_MASTER_CERT_FILE` | Pinned master certificate (PEM) |

TLS material is also managed by the `[tls]` ACME engine when configured; env
bootstrap is for operator-provided certificates.

## Ports (docker smoke config)

| Port | Protocol | Service |
|------|----------|---------|
| 5300 | UDP/TCP | Plain DNS (documentation listeners on `0.0.0.0`) |
| 8080 | TCP | Control API (`/healthz`, `/readyz`, REST, optional MCP) |

The docker sample binds the control API on `0.0.0.0:8080` so published port
mappings (`8080:8080`) reach the process. That exposes the REST/MCP surface on
every container interface — put a reverse proxy or firewall in front in
production, and prefer TLS + auth. Local dev without Docker uses
[`dnscraft.example.toml`](dnscraft.example.toml) (loopback listeners only; no
`[control_api]` section — binary defaults apply).

Public encrypted listeners (`192.0.2.0/24`, `example.com`) stay commented in
[`dnscraft.example.toml`](dnscraft.example.toml); enable them only with real
certs and domains you control.

## Health checks

- **Glibc image:** `HEALTHCHECK` in `Dockerfile` and compose call
  `http://127.0.0.1:8080/healthz` from inside the container (works whether the
  API binds loopback or `0.0.0.0`). Publish `8080:8080` for host access.
- **Musl/scratch:** use compose/Kubernetes HTTP probes against a published
  `8080:8080` mapping, or run the glibc image when you need an in-container
  probe.
