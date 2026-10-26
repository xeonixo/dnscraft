# dnscraft-listeners

DNS listeners for DNScraft: Do53 (UDP/TCP), DoT, DoH (HTTP/2 + HTTP/1.1 + HTTP/3)
and DoQ. Turns each wire query into a `policy::RequestContext`, calls
`PolicyEngine::handle`, and writes the answer back with the transport's framing
and the internet-exposure rules from SPEC.md.

Formal requirements: [`SPEC-listeners.md`](../../SPEC-listeners.md).
Plan / remaining tasks: [`tasks/todo-listeners.md`](../../tasks/todo-listeners.md).

## Listener model

A listener is one of the protocols below, each with a unique `id`, a bind
`address` (concrete or wildcard), and an `exposure` (local or public).

| Protocol | Transport | Public allowed | Notes |
|---|---|---|---|
| `udp53` | UDP (RFC 1035/6891) | no | EDNS truncation; wildcard replies from the arrival address (pktinfo) |
| `tcp53` | TCP (RFC 1035/7766) | no | length-prefixed, pipelined, out-of-order answers; TCP keepalive (RFC 7828) |
| `dot` | TLS + TCP (RFC 7858) | yes | Client ID from SNI |
| `doh` | HTTPS (RFC 8484) over HTTP/2 + HTTP/1.1 | yes | Client ID from the URL path |
| `doq` | QUIC (RFC 9250) | yes | Client ID from SNI; stream id 0 only |

`ListenerConfig` fields: `id` (`[a-z0-9-]{1,64}`), `protocol`, `address`,
`exposure` (`local` default, `public` only for `dot`/`doh`/`doq`), and `h3`
(`doh` only: also serve HTTP/3 on the same UDP port).

## Status

Checkpoint C approved; N12 DoH HTTP/3 done; **N13** (fuzz / bench / README /
coverage) done. **Next:** N14 optional minimal binary.

**Implemented**

- Do53 UDP (`serve_udp`) and TCP (`serve_tcp`): concrete and wildcard binds,
  length-prefix framing, pipelining, idle timeout, edns-tcp-keepalive
- DoT (`serve_dot`): TLS via N6 configs, framed loop shared with Do53 TCP,
  Client ID from SNI
- DoH (`serve_doh` / `serve_doh_h3`): HTTP/2 and HTTP/1.1 over TLS; HTTP/3 on UDP
  when `h3 = true` (`Alt-Svc` on h2); GET/POST `/dns-query` and `/dns-query/<id>`;
  Client ID from path
- DoQ (`serve_doq`): quinn + QUIC TLS config; Client ID from SNI; length-prefixed
  streams with id 0
- Shared message core (`handle_wire`): validation, ECS strip, OPT echo, EDE,
  padding, size limits; DDR interception on local Do53
- Shared `Admission`: source class, token buckets, bans; public SNI/path
  Client-ID gates; pre-handshake ban refusals
- TLS helpers: per-family ALPN, `accept_encrypted`, `PolicyClientIds`, hot reload
  of the underlying `CertResolver`
- Injectable `Clock` / `ManualClock`
- DDR (`DdrEndpoints`): local Do53 `IN SVCB _dns.resolver.arpa.` answers one
  SVCB per same-family encrypted listener (opportunistic discovery only —
  certificates cover `dns.<domain>` / `*.dns.<domain>`, not IP SANs; verified
  discovery per RFC 9462 §4.2 is out of scope)
- Fuzz targets (`listeners_handle_wire`, `listeners_doh_request`) and a criterion
  UDP benchmark (see [Benchmarks](#benchmarks) / [Fuzzing](#fuzzing))

**Not implemented yet** (see [`todo-listeners.md`](../../tasks/todo-listeners.md))

- Minimal `dnscraft` binary (N14)

## Admission

`Admission::check(listener, source, client_id_state, now)` runs in this order:

1. **Ban** — a banned public source is dropped/closed before anything else.
2. **Public Do53** — a public source on `udp53`/`tcp53` is dropped silently (no
   `REFUSED`, no amplification).
3. **Public-listener Client ID** — only `(exposure public, source public)` needs
   a registered Client ID (SNI for DoT/DoQ, path for DoH); `unknown`/`absent`
   are refused. Node hostname / apex SNI are rejected *without* a ban strike.
4. **Rate (source)** — a token bucket per source IP (all sources).
5. **Rate (Client ID)** — a token bucket per Client ID (public sources only).

`strike(source, reason)` records ban strikes (private sources are a no-op);
after `ban_strikes` strikes within `ban_window` the source is banned for
`ban_duration`. Rate and ban tables are LRU-capped at `max_tracked_sources`.

`SourceClass::of` classifies as **private** RFC 1918, loopback, link-local, ULA,
CGNAT and IPv4-mapped forms; everything else is **public**.

## Limits

Defaults in `config.rs` (`DEFAULT_*`); a change to any field *except* the two
admission rates restarts the affected listeners on `apply_config`.

| Field | Default | Meaning |
|---|---|---|
| `udp_payload_max` | 1232 | EDNS UDP payload advertised / enforced (DNS Flag Day 2020) |
| `query_timeout` | 10 s | per-query deadline (UDP drop; TCP/DoT/DoH/DoQ SERVFAIL) |
| `tcp_idle_timeout` | 10 s | TCP/DoT idle; also the HTTP/3 request budget (below) |
| `tls_handshake_timeout` | 5 s | TLS handshake deadline |
| `max_inflight_per_listener` | 4096 | in-flight queries per listener |
| `max_connections_per_listener` | 1024 | concurrent connections per listener |
| `max_connections_per_source` | 32 | concurrent connections per source IP |
| `max_quic_streams_per_connection` | 64 | QUIC bidirectional streams per connection |
| `max_queries_per_connection` | 64 | in-flight queries per TCP/DoT connection |
| `rate_per_source` | 200/s (burst 400) | token bucket per source IP |
| `rate_per_client_id` | 50/s (burst 100) | token bucket per Client ID (public) |
| `public.max_tracked_sources` | 100 000 | LRU cap for rate + ban tables |
| `public.ban_strikes` / `ban_window` / `ban_duration` | 5 / 60 s / 15 min | ban threshold / strike window / ban length |

- **HTTP/3 request budget** is `tcp_idle_timeout` (default 10 s). It covers the
  header + body *read* only — not the response-send phase — and is bounded by the
  per-connection stream cap (`max_quic_streams_per_connection`). There is no
  separate request-timeout setting.

## DDR

On a **local Do53** listener, an `IN SVCB` query for `_dns.resolver.arpa.` is
answered before policy with one SVCB per same-family encrypted local listener
(priority 1…n, target `dns.<domain>` / `<node>.dns.<domain>`, `alpn`, `port`,
`dohpath=/dns-query{?dns}` for DoH, `ipv4hint`/`ipv6hint` from the bind address
or the query's arrival address on a wildcard). No encrypted local listener →
NODATA + SOA. Never answered on DoT/DoH/DoQ, and `ddr.enabled = false` lets
policy handle the name. Discovery is **opportunistic only** (no IP SANs).

## TLS and hot reload

TCP-family ALPN `dot` / `h2` + `http/1.1` (TLS 1.2+), QUIC family TLS 1.3 with
ALPN `doq` / `h3` and 0-RTT off (`max_early_data_size = 0`). The server config
wraps a `CertResolver`, so installing a new certificate is picked up by the next
handshake **without a restart**; already-open connections keep working. No
certificate installed → handshake fails with `listeners.tls.no_cert` (counted),
and the listener stays bound. SNI labels are lower-cased before the Client-ID
registry lookup.

## HTTP/3

When `h3 = true` on a DoH listener, the same DoH routes are served over
`quinn` + `h3`/`h3-quinn` on UDP (ALPN `h3`), reusing `doh_request.rs` so the
path/admission handling is identical to HTTP/2. HTTP/2 responses then carry
`Alt-Svc: h3=":<port>"; ma=86400`. Stream/connection caps are the same as DoQ.
The shared header bound is `MAX_DOH_HEADER_LIST_SIZE` (16 KiB), applied to both
h2 (`max_header_list_size`) and h3 (`max_field_section_size`).

## Error codes

`ListenersError::code()` returns stable, locale-neutral codes for APIs/i18n:

| Code | Meaning |
|---|---|
| `listeners.config.invalid` | configuration out of range / inconsistent |
| `listeners.config.public_plaintext` | public listener on a plaintext protocol |
| `listeners.config.duplicate_id` | two listeners share an id |
| `listeners.bind` | socket bind failed |
| `listeners.tls.no_cert` | encrypted listener has no certificate |
| `listeners.tls.handshake` | TLS handshake failed |
| `listeners.admission.public_do53` | Do53 from a public source (dropped) |
| `listeners.admission.unknown_client_id` | public listener, unknown/missing Client ID |
| `listeners.rate_limited` | source or Client ID over its token bucket |
| `listeners.banned` | source temporarily banned |
| `listeners.doh.bad_request` | malformed DoH request (bad base64, wrong type, …) |
| `listeners.doq.protocol` | DoQ protocol violation (e.g. non-zero message id) |

DoH also maps to HTTP statuses (400/404/405/413/415/429) per RFC 8484; those are
transport responses, not `ListenersError` codes.

## Config reload semantics

`ListenerSet::apply_config` diffs by listener `id` + settings:

- Unchanged listeners keep their sockets and open connections.
- A changed `address` (or removed listener) rebinds/closes.
- A change to any `Limits` field **other than** `rate_per_source` /
  `rate_per_client_id` restarts the affected listeners.
- A change to only the two admission rates (or to `public`) rebuilds the
  `Admission` tables in place: rate buckets are reset, but the active ban table
  is **carried over** (existing bans keep their expiry; new ban params apply to
  new strikes only), so no listener restarts.

## Crate layout

| Module | Role |
|--------|------|
| `config` | `ListenersConfig` / limits / public / DDR + `validate()` |
| `error` | `ListenersError` with stable `code()` |
| `clock` | `Clock` / `ManualClock` / `SystemClock` / `wait_until` |
| `handler` | `QueryHandler` + `FakeHandler` |
| `socket` | `bind_udp` / `bind_tcp` via `socket2` |
| `core` | `handle_wire` / `QueryMeta` / `QueryEvent` |
| `ddr` | RFC 9462 `_dns.resolver.arpa` SVCB / NODATA |
| `edns` | ECS strip, OPT echo, padding (block 468) |
| `admission` | `SourceClass` / `Admission` / `AdmitDecision` |
| `ratelimit` | token buckets + LRU map (internal) |
| `bans` | strike / ban table (internal) |
| `udp` | Do53 UDP `serve_udp` / `UdpStats` |
| `framing` | 2-byte length prefix read/write |
| `tcp` | Do53 TCP `serve_tcp` / `TcpStats` |
| `tls` | Server configs, SNI admission, `accept_encrypted`, hot reload |
| `conn` | Shared framed TCP/DoT query loop |
| `dot` | DoT `serve_dot` / `DotStats` |
| `doh_request` | DoH path + GET/POST wire extraction |
| `doh` | DoH `serve_doh` / `DohStats` (h2 + http/1.1) |
| `doh_h3` | DoH over HTTP/3 `serve_doh_h3` |
| `doq` | DoQ `serve_doq` / `DoqStats` |
| `set` / `events` / `status` | `ListenerSet`, `QueryEventSink`, status |

## Example

A minimal Do53 UDP+TCP demo (real resolver, loopback high ports) lives at
[`examples/serve.rs`](examples/serve.rs):

```bash
cargo run -p dnscraft-listeners --example serve
dig @127.0.0.1 -p 5353 example.com A +short
dig @127.0.0.1 -p 5353 example.com A +tcp +short
```

It builds a `PolicyEngine`, then spawns `serve_udp` / `serve_tcp` with a shared
`Admission` and `SystemClock`. Prefer that file over copying snippets: the
`UdpServeParams` / `TcpServeParams` surfaces are large and change with the
listener tasks.

## Benchmarks

```bash
cargo bench -p dnscraft-listeners
```

`benches/udp.rs` (criterion, `harness = false`) drives a real `serve_udp` over
loopback UDP and reports queries/sec plus p50 / p99 round-trip latency. See the
N13 entry in [`tasks/progress.md`](../../tasks/progress.md) for the numbers.

## Fuzzing

See [`fuzz/README.md`](../../fuzz/README.md). The listener targets are
`listeners_handle_wire` (arbitrary wire bytes + derived `QueryMeta` through
`handle_wire`; never panics/hangs) and `listeners_doh_request` (arbitrary
method/path/query/headers/body through `parse_doh_path`, `extract_wire`,
`content_type_of`; never panics). Both run in CI on a weekly 10-minute schedule.

## Manual interop (not run)

> **Not run** — the `dnscraft` binary (N14) that would serve these ports does not
> exist yet; this is the recipe to follow once it does, with a certificate
> installed and `public_domain` set. Commands assume a listener on `dns.example.`
> with `public_domain = example.com`.

```bash
# Do53
dig @dns.example.com example.com A +short

# DoT (knot-dnsutils)
kdig @dns.example.com +tls +tls-hostname=dns.example.com example.com A

# DoH (curl 8.x built with HTTP/2)
curl --http2 --doh-url https://dns.example.com/dns-query https://example.com/ -o /dev/null -w '%{http_code}\n'

# DoH over HTTP/3 (curl built with HTTP/3)
curl --http3 --doh-url https://dns.example.com/dns-query https://example.com/ -o /dev/null -w '%{http_code}\n'

# DoQ (knot-dnsutils)
kdig @dns.example.com +quic example.com A
```

## Tests

```bash
cargo test -p dnscraft-listeners --test config
cargo test -p dnscraft-listeners --test socket
cargo test -p dnscraft-listeners --test core
cargo test -p dnscraft-listeners --test admission
cargo test -p dnscraft-listeners --test udp
cargo test -p dnscraft-listeners --test tcp
cargo test -p dnscraft-listeners --test tls
cargo test -p dnscraft-listeners --test dot
cargo test -p dnscraft-listeners --test doh
cargo test -p dnscraft-listeners --test doh_h3
cargo test -p dnscraft-listeners --test doq
cargo test -p dnscraft-listeners --test ddr
cargo test -p dnscraft-listeners --test runtime
cargo test -p dnscraft-listeners --test checkpoint_b
cargo test -p dnscraft-listeners --test checkpoint_c
```
