# dnscraft-listeners

DNS listeners for DNScraft: Do53 (UDP/TCP), DoT, DoH (HTTP/2, HTTP/1.1, HTTP/3)
and DoQ. Turns each wire query into a `policy::RequestContext`, calls
`PolicyEngine::handle`, and writes the answer back with the transport's framing
and the internet-exposure rules from SPEC.md.

Formal requirements: [`SPEC-listeners.md`](../../SPEC-listeners.md).

## Status

N1: crate skeleton — configuration validation, stable error codes, injectable
`Clock`, `QueryHandler` trait (with `PolicyEngine` impl and `FakeHandler`), and
`bind_udp` / `bind_tcp` helpers that set `IPV6_V6ONLY` before bind.

Transports, admission, message core and runtime land in later tasks (N2–N14).

## Crate layout (so far)

| Module | Role |
|--------|------|
| `config` | `ListenersConfig` / limits / public / DDR + `validate()` |
| `error` | `ListenersError` with stable `code()` |
| `clock` | `Clock` / `ManualClock` / `SystemClock` |
| `handler` | `QueryHandler` + `FakeHandler` |
| `socket` | `bind_udp` / `bind_tcp` via `socket2` |

## Tests

```bash
cargo test -p dnscraft-listeners config
cargo test -p dnscraft-listeners socket
```
