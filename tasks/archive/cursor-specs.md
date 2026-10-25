# Cursor briefs — module specs (done)

> S1–S3 produced SPEC-clients.md, SPEC-tls.md and SPEC-policy.md (2026-10-25).

## S1: Draft `SPEC-clients.md`

```text
Task: write SPEC-clients.md for module `clients` (CAPABILITY-MAP.md). Spec only, no code.

Use the structure of SPEC-filtering.md (Objective, scope/non-goals, behaviour, interface sketch, config,
error codes, limits, testing, success criteria, open questions). Inputs from SPEC.md:
- Objective "Client identification via UniFi": device name, VLAN, IPv4/IPv6 per client, for the query log.
- Feature rows "Manual client names" (single IPs and CIDR ranges, take precedence over UniFi names; macvlan
  containers named via UniFi) and "Local names and reverse DNS" (PTR for private ranges and
  <device>.<local-domain> answered from UniFi data — `clients` provides the data, `policy` answers).
- Decision in CAPABILITY-MAP.md: `clients` only enriches; it never selects profiles. Consumers: control-api
  (log enrichment) and policy (local names / PTR lookups).
- Non-goal: Docker API/socket access.
- Secrets (UniFi API key) only from env / *_FILE.

Research and write down (with source URLs):
- The UniFi Network local API on a UniFi OS gateway: authentication with an API key (header name), base
  path, which endpoints list clients/devices/networks (VLAN id/name), pagination, what is returned for
  IPv6 (all addresses? only one?), rate limits, TLS (self-signed cert → pinning or configurable CA, never
  "accept any cert" by default). Distinguish the official "Integration API" from the older undocumented
  controller endpoints; prefer the official one and say what it lacks.
- Polling vs push: propose a poll interval and a change detection strategy; behaviour when the gateway is
  unreachable (keep last good data, staleness flag, never block DNS answering).

Design to cover:
- Data model: Client { id, display name, source (manual/unifi), MACs, IPv4/IPv6 addresses, VLAN, last seen },
  lookup `by_ip(IpAddr) -> Option<ClientInfo>` (hot path for log enrichment: lock-free read, O(log n)
  or hash), `by_name(&str)` for <device>.<local-domain>, reverse map for PTR.
- Precedence rules: manual single IP > manual range (longest prefix wins) > UniFi. Name normalisation for
  DNS labels (umlauts/spaces → valid label, collisions resolved deterministically).
- IPv6: privacy addresses rotate; how stale addresses expire.
- Memory budget for ~60 clients + containers (tiny) and an upper bound for larger networks.
- Error codes (`clients.*`), observability (last sync, client count, error).
- Testing: mock UniFi server (hand-written, like the filtering HTTP test server), fixtures invented, never
  real captures from the owner's network.

Open questions section: list every decision you could not derive from SPEC.md (e.g. local domain default,
poll interval, whether offline clients keep their names for PTR, VLAN display format).
Add the spec link in CAPABILITY-MAP.md (replace "pending"). Commit "spec: draft SPEC-clients.md". STOP and
hand the open questions to the owner.
```

## S2: Draft `SPEC-tls.md`

```text
Task: write SPEC-tls.md for module `tls`. Spec only, no code. Structure like SPEC-filtering.md.

Inputs from SPEC.md: "Certificates via ACME DNS-01 using Cloudflare" (wildcard for Client IDs:
*.dns.<domain>), certificate store, hot reload, feature rows "DynDNS" (public A/AAAA of the DoH/DoT
hostname at Cloudflare; public IP from a configurable echo service, default Cloudflare cdn-cgi/trace),
"DDR (RFC 9462)" (tls provides the certificate/hostnames, listeners answer), "Alerts" (certificate expiry,
DynDNS failures), "Internet exposure" (SNI-based Client IDs, unknown SNI → handshake rejected),
"Multi-node" (public DoH/DoT per node; which node obtains/renews the certificate?), tech stack
(`instant-acme`, `rustls`, ring — no aws-lc, like the reqwest decision in progress.md).

Research and write down (with source URLs):
- instant-acme: current version, DNS-01 flow, account key persistence, ARI (RFC 9773 renewal info)
  support, crypto backend (must work with ring).
- Cloudflare API: token scopes needed (Zone:DNS:Edit on one zone only), creating/deleting the
  _acme-challenge TXT record, propagation check strategy (query Cloudflare's authoritative servers
  directly via our own resolver/proto crate, not a public resolver), DynDNS record update.
- Let's Encrypt rate limits and staging; test with Pebble + a mock Cloudflare API (SPEC.md Testing Strategy).

Design to cover:
- Certificate set: names (dns.<domain>, *.dns.<domain>, optional extra SANs), key type (ECDSA P-256
  default), renewal window, retry/backoff, staging switch.
- Store on disk (0o700, atomic writes like the filtering ListStore), private keys never logged or exported
  (config export excludes them), hot reload into rustls via a ResolvesServerCert implementation that
  listeners can share; SNI → Client ID extraction helper and the "unknown SNI → reject" hook (Client ID
  registry itself lives in policy/control-api — define the trait boundary).
- Multi-node: propose who renews (master only, distributing via cluster sync later) and what a sub-node
  does meanwhile; mark cluster details as "belongs to SPEC-cluster.md".
- DynDNS: interval, IPv4/IPv6 separately, only update on change, failure codes.
- Error codes (`tls.*`), alerts surface, metrics (days to expiry).

Open questions for the owner (e.g. extra SANs, ECDSA vs RSA fallback, whether DynDNS is in tls or its own
small module, renewal on master only). Link the spec in CAPABILITY-MAP.md. Commit "spec: draft SPEC-tls.md".
STOP.
```

## S3: Draft `SPEC-policy.md`

```text
Task: write SPEC-policy.md for module `policy` (depends on resolver + filtering only; see CAPABILITY-MAP).
Spec only, no code. Read the public APIs first: crates/dnscraft-resolver/README.md and
crates/dnscraft-filtering/README.md (FilterEngine::match_name / match_chain / match_answer_ip, Verdict,
BlockMode, temporary allows, pause).

Policy is the query pipeline between listeners and resolver. Cover every SPEC.md feature row whose module
column contains `policy`: split-horizon views (per subnet / Client ID: own records A/AAAA/CNAME/TXT/SRV/MX
and own filter set, blocked services, schedules, pause), pause protection (5 min / 1 h / until resumed,
global or per profile), local names and reverse DNS (data from `clients` via a trait so policy does not
depend on the crate), DNS rebind protection with per-domain exceptions, Client ID → profile, forward zones
optionally limited to profiles, schedules (low priority), SafeSearch (low priority), bypass control
(use-application-dns.net, mask.icloud.com / mask-h2.icloud.com), test query (explain without logging),
per-profile AAAA suppression, and the open RFC 6724 ULA source-address assumption (SPEC.md "Platforms").

Design to cover:
- Request context in (source IP, listener, protocol, optional Client ID) → view/profile selection
  (longest-prefix match, Client ID beats subnet, default view) → pipeline order. Write the order down
  explicitly and justify it, e.g.: local view records → bypass/canary → filtering (qname) → forward zone /
  recursion → CNAME chain + answer-IP filtering → rebind check → AAAA suppression → block-mode synthesis.
- Output: the answer plus a structured decision record (view, profile, matched rule + source, forward zone,
  DNSSEC status, timings) that control-api logs and the test query shows. Define it as a type sketch.
- Interaction with DNSSEC: what happens to AD when a view record or a rewrite answers; block responses and EDE
  (RFC 8914 code 15 "Blocked" / 17 "Filtered").
- Hot path budgets (SPEC.md: cached answer p50 < 1 ms, filter match < 10 µs): no locks held across await,
  config swap via Arc like FilterEngine.
- Config model (views, profiles, records) and validation error codes (`policy.*`).
- Testing: table tests for selection and pipeline order, integration with dnscraft-testkit's authoritative
  servers, success criteria.

Open questions for the owner. Link the spec in CAPABILITY-MAP.md. Commit "spec: draft SPEC-policy.md". STOP.
```
