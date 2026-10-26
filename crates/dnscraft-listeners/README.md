# dnscraft-listeners

DNS listeners for DNScraft: Do53 (UDP/TCP), DoT, DoH (HTTP/2, HTTP/1.1, HTTP/3)
and DoQ. Turns each wire query into a `policy::RequestContext`, calls
`PolicyEngine::handle`, and writes the answer back with the transport's framing
and the internet-exposure rules from SPEC.md.

Formal requirements: [`SPEC-listeners.md`](../../SPEC-listeners.md).

## Status

N1: configuration, errors, clock, handler, sockets.
N2: transport-independent [`handle_wire`](fn.handle_wire.html) — decode /
validate / EDNS (ECS strip, OPT echo, EDE, padding) / encode with size limit.
N3: [`Admission`](struct.Admission.html) — source class, token buckets, bans.
N4: Do53 [`serve_udp`](fn.serve_udp.html) — concrete + wildcard (`quinn-udp` 0.5.16).
N5: Do53 [`serve_tcp`](fn.serve_tcp.html) — RFC 7766 framing, pipelining, idle timeout.
N6: TLS configs / SNI admission / hot reload — [`tcp_server_config`](fn.tcp_server_config.html),
[`accept_encrypted`](fn.accept_encrypted.html), [`PolicyClientIds`](struct.PolicyClientIds.html).
N7: DoT [`serve_dot`](fn.serve_dot.html) — framed loop in `conn` + N6 TLS.
N8: DoH [`serve_doh`](fn.serve_doh.html) — HTTP/2 + HTTP/1.1 over N6 TLS; path Client ID.

Encrypted transports continue in N9–N14. Checkpoint B: e2e +
`cargo run -p dnscraft-listeners --example serve` (dig `@127.0.0.1 -p 5353`).

## Crate layout (so far)

| Module | Role |
|--------|------|
| `config` | `ListenersConfig` / limits / public / DDR + `validate()` |
| `error` | `ListenersError` with stable `code()` |
| `clock` | `Clock` / `ManualClock` / `SystemClock` |
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

## Tests

```bash
cargo test -p dnscraft-listeners config
cargo test -p dnscraft-listeners socket
cargo test -p dnscraft-listeners core
cargo test -p dnscraft-listeners --test admission
cargo test -p dnscraft-listeners --test udp
cargo test -p dnscraft-listeners --test tcp
cargo test -p dnscraft-listeners --test tls
cargo test -p dnscraft-listeners --test dot
cargo test -p dnscraft-listeners --test doh
```
