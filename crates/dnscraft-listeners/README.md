# dnscraft-listeners

DNS listeners for DNScraft: Do53 (UDP/TCP), DoT, DoH (HTTP/2 + HTTP/1.1) and
DoQ. Turns each wire query into a `policy::RequestContext`, calls
`PolicyEngine::handle`, and writes the answer back with the transport's framing
and the internet-exposure rules from SPEC.md.

Formal requirements: [`SPEC-listeners.md`](../../SPEC-listeners.md).
Plan / remaining tasks: [`tasks/todo-listeners.md`](../../tasks/todo-listeners.md).

## Status

Checkpoint C approved; N12 DoH HTTP/3 done. **Next: N13** (fuzz/bench/README).

**Implemented today**

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

**Not implemented yet** (see [`todo-listeners.md`](../../tasks/todo-listeners.md))

- Fuzz / bench / README polish (N13); optional binary (N14)

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

## Limits

Defaults live in `config.rs` (`DEFAULT_*`). One interaction to be aware of:

- **HTTP/3 request budget** is `tcp_idle_timeout` (default 10 s). It covers the
  header + body *read* only — not the response-send phase — and is bounded by the
  per-connection stream cap (`max_quic_streams_per_connection`). There is no
  separate request-timeout setting.

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
