# Capability Map: DNScraft

Lightweight, self-hosted, recursive DNS resolver with filter lists, split-horizon,
encrypted protocols, UniFi integration, and multi-node operation.

This file is the index of all modules. Module ids are stable and never renamed.

| Module id | Responsibility | Depends on | Spec |
|---|---|---|---|
| `resolver` | Recursive resolution from the root servers, DNSSEC validation, cache | – | [SPEC-resolver.md](SPEC-resolver.md) |
| `filtering` | AdGuard-compatible filter lists (adblock syntax, hosts), allow/block, rewrites | – | [SPEC-filtering.md](SPEC-filtering.md) |
| `clients` | Client enrichment: IPv4/IPv6 → device, VLAN via the UniFi API (UniFi OS gateway); manual names for IPs/ranges | – | [SPEC-clients.md](SPEC-clients.md) (draft) |
| `tls` | ACME DNS-01 via Cloudflare (wildcard for Client IDs), certificate store, hot reload, DynDNS of the public hostname | – | [SPEC-tls.md](SPEC-tls.md) (draft) |
| `policy` | Query → profile by source subnet/IP: filter set, split-horizon answers | resolver, filtering | [SPEC-policy.md](SPEC-policy.md) (draft) |
| `listeners` | Do53 UDP/TCP, DoT, DoH (h2/h3), DoQ; multiple NICs/addresses; public listeners for registered Client IDs | policy, tls | pending |
| `control-api` | REST API, configuration, query log (filterable by device), statistics, OIDC (Authentik) + local break-glass login, locale-neutral error codes | policy, clients | pending |
| `web-ui` | TypeScript frontend, fully internationalized, embedded into the binary as static assets | control-api | pending |
| `mcp` | MCP server for AI assistants: query log, "why blocked?", test query, stats (viewer); temporary allow, rules, pause (admin); internal listener only, same tokens/roles/audit as the API | control-api | pending |
| `cluster` | Master/sub-nodes: config sync, writes from any node (forwarded to master, offline fallback), keep serving without the master, log/stats aggregation on the master | control-api | pending |

## Build order

```
resolver, filtering, clients, tls   (can run in parallel)
        → policy
        → listeners
        → control-api
        → web-ui, cluster, mcp
```

## Shared crates (not capabilities)

- `dnscraft-proto`: DNS wire format and DNSSEC record types, used by every module that touches DNS messages. Built first (plan phase "wire format").
- `dnscraft-testkit`: test-only helpers.

## Decisions recorded at map level

- `clients` only enriches logs (device, VLAN, IPs) and does not select profiles.
  Therefore `policy` does not depend on `clients`; `control-api` consumes it.
- Query logs are aggregated on the master only (hub-and-spoke, not full mesh).
  Sub-nodes keep a short local buffer (e.g. 24 h), stream to the master, and backfill
  after the master was unreachable. Details belong in `SPEC-cluster.md`.
