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

Admission, transports and runtime land in later tasks (N3–N14).

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

## Tests

```bash
cargo test -p dnscraft-listeners config
cargo test -p dnscraft-listeners socket
cargo test -p dnscraft-listeners core
```
