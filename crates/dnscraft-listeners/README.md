# dnscraft-listeners

DNS listeners for DNScraft: Do53 (UDP/TCP), DoT, DoH (HTTP/2 + HTTP/1.1) and
DoQ. Turns each wire query into a `policy::RequestContext`, calls
`PolicyEngine::handle`, and writes the answer back with the transport's framing
and the internet-exposure rules from SPEC.md.

Formal requirements: [`SPEC-listeners.md`](../../SPEC-listeners.md).
Plan / remaining tasks: [`tasks/todo-listeners.md`](../../tasks/todo-listeners.md).

## Status

In progress (N9 DoQ done; **next: Checkpoint C** — encrypted e2e + review).

**Implemented today**

- Do53 UDP (`serve_udp`) and TCP (`serve_tcp`): concrete and wildcard binds,
  length-prefix framing, pipelining, idle timeout, edns-tcp-keepalive
- DoT (`serve_dot`): TLS via N6 configs, framed loop shared with Do53 TCP,
  Client ID from SNI
- DoH (`serve_doh`): HTTP/2 and HTTP/1.1 over TLS; GET/POST `/dns-query` and
  `/dns-query/<id>`; Client ID from path
- DoQ (`serve_doq`): quinn + QUIC TLS config; Client ID from SNI; length-prefixed
  streams with id 0
- Shared message core (`handle_wire`): validation, ECS strip, OPT echo, EDE,
  padding, size limits
- Shared `Admission`: source class, token buckets, bans; public SNI/path
  Client-ID gates; pre-handshake ban refusals
- TLS helpers: per-family ALPN, `accept_encrypted`, `PolicyClientIds`, hot reload
  of the underlying `CertResolver`
- Injectable `Clock` / `ManualClock`

**Not implemented yet** (see [`todo-listeners.md`](../../tasks/todo-listeners.md))

- DoH over HTTP/3 (task N12; `ALPN_H3` is reserved on the QUIC config only)
- DDR `_dns.resolver.arpa` SVCB answers (task N10; `DdrConfig` is validated in
  config only)
- `ListenerSet` runtime / query-event sink / fuzz+bench polish (N11, N13)

## Crate layout

| Module | Role |
|--------|------|
| `config` | `ListenersConfig` / limits / public / DDR + `validate()` |
| `error` | `ListenersError` with stable `code()` |
| `clock` | `Clock` / `ManualClock` / `SystemClock` / `wait_until` |
| `handler` | `QueryHandler` + `FakeHandler` |
| `socket` | `bind_udp` / `bind_tcp` via `socket2` |
| `core` | `handle_wire` / `QueryMeta` / `QueryEvent` |
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
| `doq` | DoQ `serve_doq` / `DoqStats` |

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
cargo test -p dnscraft-listeners --test doq
cargo test -p dnscraft-listeners --test checkpoint_b
```
