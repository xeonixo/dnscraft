# Spec: DNScraft (project-wide)

> Project-wide decisions. Module-specific requirements live in `SPEC-<module-id>.md`;
> the index is [CAPABILITY-MAP.md](CAPABILITY-MAP.md).

## Objective

Replace AdGuard Home on a home network (tens of clients plus Docker containers), keeping
the familiar AdGuard-compatible filter lists while closing these gaps:

- **Full recursion** from the root servers, no upstream provider, with DNSSEC validation.
- **Split-horizon:** different answers per source subnet
  (e.g. `192.0.2.0/24` ≠ `198.51.100.0/24`).
- **Client identification via UniFi** (UniFi OS gateway, local API):
  device name, VLAN, IPv4/IPv6, so the query log can be filtered by device.
- **All common protocols:** Do53 (UDP/TCP), DoT, DoH (HTTP/2, HTTP/3), DoQ.
- **Usable from anywhere:** encrypted protocols reachable from the internet for known devices (e.g. an iPhone on mobile data).
- **Certificates via ACME DNS-01** using Cloudflare.
- **Multi-node:** one master, several sub-nodes, for redundancy and central management.
- **Polished web UI** with SSO via Authentik (OIDC).
- **AI-assistant ready:** a built-in MCP server lets an assistant (e.g. Claude) search the query log, explain blocks, run test queries, and — with an admin token — change filters, using the same permissions as the API.
- **Consistently internationalized** (see [Internationalization](#internationalization-i18n)).
- **Docker-first** and **as lightweight as possible**.

Users: the network owner (single admin). Clients on the network are plain DNS consumers.

### Non-goals

- DHCP, authoritative hosting of public zones, DNSSEC signing of own zones
  (Cloudflare signs the public zone).
- Forwarding public names to upstream providers (forward zones for private zones are in scope, see feature table).
- Importing an existing AdGuard Home configuration (migration is a one-off manual task).
- AdGuard "Safe Browsing" / "Parental Control" (they query an external AdGuard service;
  phishing/scam lists cover the need), DNSCrypt.
- Per-device profiles: profiles are selected by subnet/IP range; a registered Client ID may be pinned to a view, which applies only to IPs no subnet matches (never overrides a matching subnet).
- Docker API / socket access: containers behind bridge NAT appear as the Docker host anyway;
  manual names cover the need. May be revisited (via a read-only socket proxy) if `clients` shows real value.

### Feature scope (beyond the core objective)

Adopted from AdGuard Home and refined; each item belongs to the listed module spec.

| Feature | Module | Notes |
|---|---|---|
| Custom filter rules | filtering, web-ui | Same syntax as filter lists. **Editor must not require hard-to-type characters** (`\|`, `^`, `@@`, `$` are awkward on a German Mac layout): a guided rule builder ("block / allow · domain · include subdomains · for profile") generates the rule; a raw editor (CodeMirror 6) adds syntax highlighting, validation, autocomplete, and insert buttons for special tokens |
| "Why blocked?" | filtering, web-ui | Every log entry shows the matching rule and its source list; one-click allow from the log |
| Pause protection | policy | 5 min / 1 h / until resumed, global or per profile |
| Local names and reverse DNS | clients, policy | PTR for private ranges and `<device>.<local-domain>` answered from UniFi data, no extra DNS server |
| Built-in DNS rebind protection | policy | Drop public answers pointing to private/loopback ranges; per-domain exceptions |
| Selectable blocking mode | filtering | `0.0.0.0`/`::`, NXDOMAIN, REFUSED, custom IP |
| Per-client rate limit | listeners | Configurable queries/s per source IP, private ranges included |
| Automatic list updates | filtering | Configurable interval; last update, rule count, and errors per list visible |
| Config backup/export/import | control-api | One file restores the whole configuration (secrets excluded) |
| Client ID via DoH/DoT | listeners, policy, web-ui | Device identified by DoT SNI (`<id>.dns.<domain>`) or DoH path (`/dns-query/<id>`); a Client ID can carry a label and a device reference (shown as the client name in the query log when no directory client matches the IP); the web UI generates Apple `.mobileconfig` profiles (iOS/macOS, in the browser, no server call) and shows the Android "Private DNS" hostname |
| Forward zones (conditional forwarding) | resolver, policy | Private zones and their reverse zones (e.g. a remote site over site-to-site VPN running its own, third-party resolver) are sent to configured DNS servers instead of being resolved recursively; optionally limited to certain profiles |
| Blocked services (one-click) | filtering, web-ui | Service catalog (name, icon, rules, translated names) from AdGuard's HostlistsRegistry `services.json` + `services_i18n.json`, **downloaded at runtime** like a filter list (GPL-3.0 data, not bundled); toggle per profile |
| Schedules | policy | Time windows per profile that switch filter sets/blocked services; off by default, low priority |
| SafeSearch enforcement | policy | Rewrite Google/Bing/YouTube/DuckDuckGo to their safe endpoints per profile; off by default, low priority |
| Break-glass login | control-api | Local admin (password + optional TOTP) in addition to Authentik OIDC; reachable from private ranges only |
| Theming | web-ui | Light / dark / follow system, switchable |
| Mobile-friendly UI | web-ui | Responsive layout, fully usable on a phone (pause protection, allow a domain from the log) |
| CNAME uncloaking | filtering | Every name in a CNAME chain is checked against the filters; a blocked target blocks the whole answer |
| Bypass control | policy | Per profile: answer the Firefox canary `use-application-dns.net` with NXDOMAIN; control iCloud Private Relay via `mask.icloud.com` / `mask-h2.icloud.com` |
| DDR (RFC 9462) | listeners, tls | Answer `_dns.resolver.arpa` SVCB so iOS/macOS/Windows 11 upgrade to DoH/DoT on the LAN automatically |
| Test query | policy, web-ui | "What does client X get for name Y, and why?": shows view, profile, matching rule, forward zone, DNSSEC status, final answer; never pollutes the query log |
| Health checks | control-api | `/healthz` (process alive) and `/readyz` (resolver primed, config loaded, listeners bound) on the internal API; Docker `HEALTHCHECK` in the image |
| Audit log | control-api, web-ui | Who changed what, when, on which node (OIDC user, local admin, or API token) |
| API tokens | control-api | Scoped tokens (`admin`/`viewer`) for scripts and the later Home Assistant integration; revocable, shown once |
| Live log, search, CSV export | control-api, web-ui | Streaming tail of the query log (SSE), search/filter by device, domain, status, profile; CSV export of a filtered view |
| Filter list effectiveness | filtering, web-ui | Per list: rules loaded, unique contribution after dedup, hits in the last 24 h/30 days, to identify lists worth removing |
| Temporary allow | filtering, web-ui | Allow a domain for a chosen duration (e.g. 1 h), per profile; expires automatically |
| Config versions and rollback | control-api, web-ui | Every change creates a version; diff and one-click rollback |
| Automatic backups | control-api | Daily export to a directory with configurable retention (secrets excluded) |
| Update notice | control-api, web-ui | Checks GitHub releases (opt-out) and shows an "update available" hint; no self-update |
| Bug report / feedback | control-api, web-ui | From Help or an error screen: short description + expected vs. actual. Opens a GitHub issue in the browser with a filled template — DNScraft never posts to GitHub itself (no token, no auto-submit). Offline → copy markdown to clipboard. **Issue body is LLM-triage-ready:** fixed English section headings (`## Summary`, `## Expected`, `## Actual`, `## Diagnostics`); human prose only in the first three; a single fenced `json` block under Diagnostics with a versioned schema (`schema_version`, `dnscraft_version`, `os`, `arch`, `node_role`, `locale`, `error_codes[]`, `recent_log_lines[]` as structured events with `level`/`target`/`message`, optional opted-in fields). Keys and `error_codes` are the same stable `code()` strings the API already uses — never localized. No secrets/query names/Client IDs unless the admin opts in per field. GitHub issue form + label `from-product` so bots/agents can filter |
| First-run wizard | web-ui | Create local admin, networks/views, filter lists, optional OIDC and UniFi |
| Statistics dashboard | control-api, web-ui | Queries over time, blocked ratio, top domains, top blocked, top clients, DNSSEC outcomes, cache hit ratio, per node and aggregated |
| Query log retention and anonymization | control-api | Default: everything visible; retention configurable (default **30 days**); optional IP truncation |
| Roles | control-api, web-ui | `admin` (everything) and `viewer` (logs, statistics, read-only config), mapped from configurable Authentik groups |
| Split-horizon views | policy | Per subnet (Client-ID pin for IPs no subnet matches): own records (A, AAAA, CNAME, TXT, SRV, MX) **and** own filter set, blocked services, schedules, pause state |
| Manual client names | clients, web-ui | Names for single IPs or whole ranges (e.g. `198.51.100.0/24` = "Container host", `198.51.100.5` = "printer"); take precedence over UniFi names. Containers on macvlan are named automatically via UniFi |
| DynDNS | tls | Per-node A/AAAA for each `nsN.dns.<domain>` plus public-entry CNAMEs for `dns.<domain>` / `*.dns.<domain>` → entry hostname (DoT Client-IDs); public IP from a configurable echo (default Cloudflare `cdn-cgi/trace`) |
| Alerts | control-api, web-ui | Certificate expiry, failed list updates, node offline, DynDNS failures: shown in the web UI only (no push/e-mail for now) |
| MCP server | mcp | Model Context Protocol server (Streamable HTTP) on the internal API listener only. Thin layer over `control-api`: same API tokens and roles (`viewer` = read tools: query log search, "why blocked?", test query, statistics, list/node status; `admin` = also write tools: temporary allow, add rule, pause a filter set), every write in the audit log. Query-log content (domain names, client names) is attacker-influenced and returned strictly as structured data, never as instructions; write tools are marked destructive so clients ask for confirmation. Off by default |

### Later (not specified now, but the API must not prevent it)

- Home Assistant integration (pause switch, counters) and Prometheus metrics.

## License

`MIT OR Apache-2.0` (see `LICENSE-MIT`, `LICENSE-APACHE`).

## Tech Stack

| Area | Choice |
|---|---|
| Backend language | Rust stable, edition 2024, Cargo workspace |
| Async runtime | `tokio` |
| DNS protocol / recursion | **In-house** (ADR-0001): wire format in `dnscraft-proto`, recursion and DNSSEC validation logic in `dnscraft-resolver` |
| Cryptography | `ring` (DNSSEC signature verification and digests); never hand-written crypto |
| HTTP (API, DoH) | `axum` / `hyper` |
| TLS / QUIC | `rustls`, `quinn` (DoQ, HTTP/3) |
| ACME | `instant-acme` |
| OIDC | `openidconnect` |
| Persistence | SQLite via `rusqlite` (config, query log) |
| Logging | `tracing` |
| Frontend | TypeScript, SvelteKit with `adapter-static`, `pnpm` |
| Frontend i18n | Paraglide JS (compile-time, tree-shaken message functions) |
| Delivery | One statically linked binary (musl), frontend embedded via `rust-embed`; Docker image on `scratch`/`distroless` |

Exact versions are set to the current stable release at project start and pinned
via `Cargo.lock` / `pnpm-lock.yaml`.

### Lightweight budgets

Budgets are guidelines, not hard gates: they are measured continuously (benchmark job)
and a regression of more than 20 % needs a justification, but a miss does not block a release.

| Metric | Target |
|---|---|
| Docker image | ≤ 30 MB |
| Idle RSS with the reference filter set loaded | ≤ 150 MB |
| Filter set (re)load, reference set | < 10 s, without blocking query answering |
| Cached answer (p50, measured locally) | < 1 ms |
| Filter match per query | < 10 µs |
| Runtime dependencies outside the container | none (no external DB server, no Redis) |

### Reference filter set

A heavy but realistic AdGuard Home setup defines the load and are used for
benchmarks and memory measurements. Total ≈ 2.25 M rules before deduplication; the
overlap between lists is large, so unique domains are expected well below that.

| List | URL | Rules (AdGuard, 2026-10-23) |
|---|---|---|
| AdGuard DNS filter | https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt | 191,207 |
| AdAway Default Blocklist | https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt | 0 |
| AdAway | https://adaway.org/hosts.txt | 6,542 |
| EasyList Germany | https://easylist.to/easylistgermany/easylistgermany.txt | 5,614 |
| StevenBlack | https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | 71,506 |
| Perflyst and Dandelion Sprout's Smart-TV Blocklist | https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt | 160 |
| NoCoin Filter List | https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt | 312 |
| Phishing URL Blocklist (PhishTank and OpenPhish) | https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt | 27,502 |
| Scam Blocklist by DurableNapkin | https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt | 944 |
| Dandelion Sprout's Game Console Adblock List | https://adguardteam.github.io/HostlistsRegistry/assets/filter_6.txt | 15 |
| WindowsSpyBlocker - Hosts spy rules | https://adguardteam.github.io/HostlistsRegistry/assets/filter_23.txt | 347 |
| EasyPrivacy | https://easylist.to/easylist/easyprivacy.txt | 56,399 |
| 1Hosts (Xtra) | https://adguardteam.github.io/HostlistsRegistry/assets/filter_70.txt | 786,135 |
| OISD Blocklist Big | https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt | 236,110 |
| HaGeZi's Ultimate Blocklist | https://adguardteam.github.io/HostlistsRegistry/assets/filter_49.txt | 246,590 |
| HaGeZi's Gambling Blocklist | https://adguardteam.github.io/HostlistsRegistry/assets/filter_47.txt | 608,486 |
| HaGeZi's Windows/Office Tracker Blocklist | https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt | 383 |
| HaGeZi's DNS Rebind Protection | https://adguardteam.github.io/HostlistsRegistry/assets/filter_71.txt | 57 |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt | 16,340 |

Benchmarks run against a locally downloaded snapshot (fetched by a script, not committed);
automated tests never download lists.

### Docker and multiple NICs

- Primary delivery is a container; the binary also runs natively (systemd).
- Listens on multiple interfaces/addresses at once (IPv4 + IPv6), configurable per
  address and protocol; `0.0.0.0`/`::` as an option.
- Replies are always sent from the address the query arrived on (`IP_PKTINFO` / `IPV6_RECVPKTINFO`).
- **Real client IPs are mandatory** (split-horizon, per-device log). Supported network modes:
  `macvlan`/`ipvlan` (recommended, multiple VLANs) and `network_mode: host`.
  Bridge networking with NAT is documented as unsuitable for LAN clients.

## Protocol defaults

- EDNS Client Subnet (ECS) is **never sent** to authoritative servers (privacy).
- `ANY` queries are answered minimally per RFC 8482.
- Per-profile option to suppress AAAA answers (IPv4-only clients); off by default.

## Configuration model

- The **web UI is the primary way to configure** DNScraft; configuration lives in SQLite.
- Bootstrap settings only come from environment variables / a small TOML file:
  listen addresses and ports, data directory, node role, OIDC client settings, secrets (`*_FILE`).
- Export/import of the complete configuration as one file (secrets excluded) for backup and migration.

## Multi-node

- 3–4 nodes are the expected size; the design must not assume a fixed number. Tested with 3.
- **One master**, any number of sub-nodes. Every node answers DNS on its own with its last known configuration.
- **Writes from any node:** the UI works on every node. A sub-node forwards changes to the master;
  only while the master is unreachable does it store them locally and reconcile later
  (last write per configuration object wins, based on a hybrid logical clock). Conflicts are listed in the UI.
- Query logs and statistics are aggregated on the master only (see CAPABILITY-MAP).
- **Client failover via DHCP:** the UniFi gateway hands out all node addresses as DNS servers;
  no virtual IP/VRRP.
- Public DoH/DoT is enabled **per node** (off by default), matching where port forwarding points.

## Platforms and networks

- Container images and binaries for **`linux/amd64` and `linux/arm64`** (multi-arch image).
- IPv6: clients reach DNScraft via a **ULA** address; views and ACLs therefore use ULA prefixes.
  Assumption to verify during `policy`: clients pick their ULA source address when querying a ULA server (RFC 6724).

## Internet exposure

DoT, DoH, and DoQ may be reachable from the internet so registered devices can use
DNScraft from anywhere. Exposure is opt-in and follows these rules:

- **Only encrypted protocols** are offered on public listeners. Do53 is never answered for public source IPs.
- **Only registered Client IDs** are served from public source IPs. The Client ID comes from
  the DoT/DoQ SNI (`<id>.dns.<domain>`) or the DoH path (`/dns-query/<id>`); unknown or missing IDs
  get no answer (TLS handshake rejected for unknown SNI, `404` for unknown DoH paths), so the
  server is not an open resolver and does not confirm it is one.
- Client IDs are unguessable by default (random suffix, e.g. `iphone-k7q2x9`), can be revoked
  instantly in the UI, and each maps to a profile (filter set) like a subnet does.
- **Rate limits and abuse protection** for public sources: per Client ID and per source IP,
  temporary bans after repeated invalid IDs or handshake failures.
- **The web UI, API and MCP server are never served on a public listener**, even if DoH shares port 443
  on the same address: public listeners route only `/dns-query/<id>`.
- **DoH on 443** is the recommended path for mobile devices (port 853 is blocked on some
  networks); DoT/DoQ on 853 additionally.
- Generated Apple `.mobileconfig` profiles point to the public hostname and may contain
  on-demand rules (e.g. use the local resolver on the home Wi-Fi).
- Public queries are logged like local ones, attributed to the Client ID.

## Internationalization (i18n)

i18n is a cross-cutting requirement, not a module. Every module that produces
user-facing text must follow these rules.

- **Source locale is English (`en`).** Initial locales: `en`, `de`. Adding a locale must
  require only a new message file, no code changes.
- **No hard-coded user-facing strings** in the frontend. Every visible string, including
  `aria-label`, `title`, placeholders, and validation messages, comes from the message catalog.
  A lint rule/CI check fails the build on untranslated literals and on keys missing in any shipped locale.
- **The backend never sends localized prose.** API errors and events carry a stable,
  machine-readable code plus structured parameters; the frontend renders the text:

  ```json
  { "error": { "code": "filter_list.fetch_failed", "params": { "url": "https://…", "status": 404 } } }
  ```

  Error codes are part of the API contract and documented in the OpenAPI schema.
- **Server logs (`tracing`) stay English** and are not translated; they are for operators, not UI.
- **Formatting via `Intl`:** dates, times, relative times, numbers, byte sizes, and durations use
  `Intl.*` with the active locale. Timestamps travel as UTC (RFC 3339) and are rendered in the
  viewer's time zone.
- **Plurals and gender** use ICU MessageFormat-style messages, never string concatenation.
- **Locale selection:** user preference (stored per user) → browser `Accept-Language` → `en`.
- **Layout must survive translation:** no fixed-width text containers; use CSS logical
  properties (`margin-inline-start` etc.) so RTL locales remain possible later.
- Domain names are displayed as received; IDNs are shown in Unicode with the punycode form available.

## Commands

```bash
# Backend
cargo build --release --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check
cargo llvm-cov --workspace --html          # coverage

# Frontend (in web/)
pnpm install --frozen-lockfile
pnpm check                                  # svelte-check + tsc
pnpm lint                                   # includes i18n checks (missing keys, raw literals)
pnpm test                                   # vitest
pnpm build                                  # → web/build, embedded into the binary

# Container
docker build -t dnscraft:dev .
docker compose -f deploy/compose.dev.yml up

# Run locally
cargo run -p dnscraft -- --config deploy/dnscraft.dev.toml
```

## Project Structure

```
dnscraft/
├── Cargo.toml                 → workspace definition
├── crates/
│   ├── dnscraft/              → binary: startup, config loading, module wiring
│   ├── dnscraft-proto/        → shared DNS wire format and DNSSEC record types (no I/O)
│   ├── dnscraft-resolver/     → module resolver
│   ├── dnscraft-filtering/    → module filtering
│   ├── dnscraft-clients/      → module clients
│   ├── dnscraft-tls/          → module tls
│   ├── dnscraft-policy/       → module policy
│   ├── dnscraft-listeners/    → module listeners
│   ├── dnscraft-api/          → module control-api
│   ├── dnscraft-cluster/      → module cluster
│   ├── dnscraft-mcp/          → module mcp
│   └── dnscraft-testkit/      → test helpers: fake DNS hierarchy, DNSSEC test zones (uses hickory as an independent oracle)
├── web/                       → module web-ui (SvelteKit)
│   └── messages/              → i18n catalogs (en.json, de.json, …)
├── deploy/                    → Dockerfile variants, compose examples (macvlan, host), sample config
├── docs/                      → operations docs, ADRs (docs/adr/)
├── CAPABILITY-MAP.md
├── SPEC.md
└── SPEC-<module-id>.md
```

Unit tests live in `#[cfg(test)]` modules next to the code; integration tests in
`crates/<crate>/tests/`.

## Code Style

- All code, comments, identifiers, commit messages, and Markdown docs are in **English**.
- `cargo fmt` defaults, zero Clippy warnings.
- Errors: `thiserror` in library crates, `anyhow` only in the binary crate.
- No `unwrap()`/`expect()` outside tests, except for provably impossible cases with a comment.
- No `unsafe` without an ADR.
- Structured logging with `tracing`: fields, not string interpolation.
- Modules talk through narrow traits at the crate boundary; configuration as typed `serde` structs.

```rust
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("no authoritative server reachable for {zone}")]
    Unreachable { zone: Name },
    #[error("DNSSEC validation failed for {name}: {reason}")]
    Bogus { name: Name, reason: BogusReason },
}

impl ResolveError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unreachable { .. } => "resolver.unreachable",
            Self::Bogus { .. } => "resolver.dnssec_bogus",
        }
    }
}

#[tracing::instrument(skip(self), fields(qname = %query.name(), qtype = ?query.query_type()))]
async fn resolve(&self, query: &Query) -> Result<Answer, ResolveError> {
    if let Some(hit) = self.cache.get(query) {
        tracing::debug!(ttl = hit.ttl(), "cache hit");
        return Ok(hit);
    }
    // ...
}
```

Frontend: TypeScript `strict`, ESLint + Prettier, components in PascalCase,
API types generated from the `control-api` OpenAPI schema, never hand-maintained.

```svelte
<script lang="ts">
  import * as m from '$lib/paraglide/messages';
  export let blocked: number;
</script>

<!-- "{count, plural, one {# query blocked} other {# queries blocked}}" -->
<p>{m.dashboard_blocked_count({ count: blocked })}</p>
```

## Testing Strategy

| Level | Tooling | Scope |
|---|---|---|
| Unit | `cargo test` | parsers, filter matching, cache, policy selection |
| Fuzzing | `cargo-fuzz` (nightly) | every decoder in `dnscraft-proto` that sees untrusted input; short runs in CI, longer runs before releases |
| Integration | `cargo test` + `dnscraft-testkit` | recursion and DNSSEC against a **local fake hierarchy** (root → TLD → zone), no internet access |
| Protocol | integration tests | Do53/DoT/DoH/DoQ end-to-end against running listeners with test certificates |
| External APIs | mock servers | UniFi, Cloudflare, ACME (Pebble), Authentik (mock OIDC); never real endpoints |
| Frontend | `vitest`, one Playwright smoke test per shipped locale | components, login flow, query-log filtering |
| i18n | lint/CI check | no raw literals, no missing keys across locales |
| Performance | `criterion` | filter match, cache lookup against the budgets above |
| Manual | `dig`, `kdig`, `q` | acceptance against the real internet per module |

Coverage: ≥ 80 % lines for `proto`, `resolver`, `filtering`, `policy`; no hard threshold for other crates.

## Boundaries

- **Always:**
  - Run `fmt`, `clippy`, and tests before every commit.
  - Load secrets (Cloudflare token, UniFi API key, OIDC client secret) only from environment variables or Docker secrets (`*_FILE`).
  - Update the spec first when a decision changes.
  - Write docs and code in English; route every user-facing string through i18n.
  - Default ACL: only private ranges (RFC 1918, RFC 4193 ULA, loopback) may query; never an open resolver.
    Public sources are served only on encrypted listeners and only for registered Client IDs (see [Internet exposure](#internet-exposure)).
- **Ask first:**
  - New dependencies (especially heavy or native ones).
  - SQLite schema changes.
  - Changes to default ports, the default ACL, or the internet exposure rules.
  - CI configuration.
- **Never:**
  - Keys, tokens, or secrets in the repo, including test fixtures and sample configs.
  - Real UniFi/Cloudflare/ACME production endpoints in automated tests.
  - Silently disable or weaken DNSSEC validation.
  - Expose Do53, the web UI/API or the MCP server on a public listener by default.
  - Delete or skip failing tests without asking.

## Success Criteria (whole project)

- Every module in the capability map meets the success criteria of its spec.
- One container on the home server replaces AdGuard Home for all clients across multiple VLANs.
- The lightweight budgets are measured and met.
- The web UI is fully usable in `en` and `de` with zero missing keys and no hard-coded strings.
- An MCP client (e.g. Claude) connected with a viewer token can answer "why was X blocked for device Y?" from live data; with an admin token it can grant a temporary allow, which shows up in the audit log.

## Open Questions

None at the moment.
