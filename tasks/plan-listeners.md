# Implementation Plan: `listeners` module

> Spec: [SPEC-listeners.md](../SPEC-listeners.md) (approved 2026-10-25) · Project spec: [SPEC.md](../SPEC.md) ·
> Tasks: [todo-listeners.md](todo-listeners.md) · Resume log: [progress.md](progress.md) ·
> Neighbours: [archive/policy-plan.md](archive/policy-plan.md), [archive/tls-plan.md](archive/tls-plan.md)
> Built by **one Cursor agent**, one task per session (template B in [cursor-next.md](cursor-next.md)); Claude reviews at every checkpoint.

## Overview

A new library crate `crates/dnscraft-listeners` that binds Do53 (UDP/TCP), DoT, DoH (h2 + http/1.1, later
h3) and DoQ listeners, admits each query (source class, Client ID, rate limit, bans), turns it into a
`policy::RequestContext`, calls `PolicyEngine::handle`, and writes the answer back with the transport's
framing. A last, optional phase adds a minimal `crates/dnscraft` binary so DNScraft can run next to
AdGuard Home before `control-api` exists.

## Architecture Decisions

1. **Transport-independent core first.** `core::handle_wire(bytes, QueryMeta) -> Option<Vec<u8>>` does
   decode → validation → admission decision → `RequestContext` → policy → id/RA/EDNS/EDE/padding/limit.
   Every transport is a thin I/O shell around it. This keeps the risky logic unit-testable and fuzzable,
   and makes all transports answer identically (success criterion 2).
2. **Policy behind a trait.** `QueryHandler` (`async fn handle(&self, RequestContext) -> PolicyAnswer`)
   with an impl for `PolicyEngine`; tests use a fake handler, integration tests the real engine on the
   testkit hierarchy.
3. **No `unsafe`.** Wildcard UDP/QUIC reply-source uses `quinn-udp` (`IP_PKTINFO`/`IPV6_RECVPKTINFO`).
   Concrete-address sockets are the documented default; wildcard support is verified by a spike first.
4. **Shared TLS.** All encrypted listeners use `Arc<tls::CertResolver>`; one `rustls::ServerConfig` per
   ALPN family. SNI admission reuses `tls::accept_public_sni`; the Client-ID registry is a read-only
   accessor on the policy snapshot (task L0, cross-module).
5. **Bounded state everywhere.** Rate buckets and ban table are LRU-capped (`max_tracked_sources`); every
   accept loop has a connection cap and every connection a query/stream cap.
6. **HTTP stack:** `hyper` 1 + `hyper-util` directly (no `axum` in this crate; `control-api` uses axum
   later). DoH h3 via `h3` + `h3-quinn` is a separate, late task so it can be dropped if the owner
   defers HTTP/3.
7. **Events, not logging.** A non-blocking `QueryEventSink` (bounded channel, drop + count when full).

## Dependencies (need owner approval — versions checked 2026-10-25 with `cargo search`)

| Crate | Version | Features | Why | Alternatives |
|---|---|---|---|---|
| `quinn` | 0.11.12 | `default-features = false`, `runtime-tokio`, `rustls-ring` | DoQ + HTTP/3 transport; ring-only (N0 ✓) | `s2n-quic` (aws-lc) ✗ |
| `quinn-udp` | **0.5.16** (direct, Do53 wildcard; same version quinn 0.11.12 pulls, no duplicate) | default | `IP_PKTINFO` reply-source without our own `unsafe` (N0 ✓ on aarch64; 0.5.16 re-checked at Checkpoint A) | `socket2` + `nix` + `unsafe` ✗ |
| `socket2` | 0.6.5 (already in the tree via hyper-util) | `all` only if `set_only_v6` needs it, else default | `IPV6_V6ONLY` on every IPv6 listener socket before bind (Checkpoint A) | validation rule forbidding `0.0.0.0` + `::` on one port ✗ (owner chose V6ONLY) |
| `hyper` | 1.12.0 | `server`, `http1`, `http2` | DoH h2 / http/1.1 server (N0 ✓) | `axum` (more than needed here) |
| `hyper-util` | 0.1.21 | `tokio`, `server-auto` (+ client helpers in tests) | connection driver for hyper (N0 ✓) | – |
| `h3` | 0.0.8 | default | DoH over HTTP/3 (pre-1.0; N0 ✓ one GET) | – |
| `h3-quinn` | 0.0.10 | default | h3 ↔ quinn glue (N0 ✓; re-exports quinn) | – |
| `base64` | **0.23.1 already in workspace tree** (also 0.22.1 via instant-acme) | `std` | DoH `GET ?dns=` base64url — use 0.23, no new crate line needed beyond the dep | 30-line local decoder |
| `tokio-rustls` | 0.26.6 (workspace) | `ring`, `tls12` | DoT / DoH-h2 TLS (N0 ✓ ALPN `h2`) | already in the tree |
| dev: `rcgen` | 0.14.10 (workspace) | – | test certificates | already in the tree |
| `toml` (N14 only) | 1.1 (latest stable at implement time) | default | bootstrap config of the minimal binary | `serde_json` config (less readable) |

**N0 corrections / notes (2026-10-25):** `quinn` 0.11.12 still pulls **`quinn-udp` 0.5.16** transitively; our Do53 wildcard code depends on **0.6.3** directly — both versions coexist in the spike tree (fine). Keep `default-features = false` on quinn or aws-lc returns. h3: do not drop the server `Connection` before the client finishes reading (early drop → `ApplicationClose H3_NO_ERROR` on `recv_response`). ULA-on-dummy not tested (needs root).

**Checkpoint A review (Claude, 2026-10-25; owner accepted):** (1) On Linux `[::]` is dual-stack: binding `0.0.0.0:p` then `[::]:p` fails with `EADDRINUSE` (measured) → every IPv6 socket sets `IPV6_V6ONLY` via `socket2` before bind (helper in N1, used by N4/N5/N7/N8/N9/N12). (2) On a dual-stack socket IPv4 peers appear as `::ffff:a.b.c.d` (measured: peer, `dst_ip` and `src_ip` all mapped; the reply still leaves from the right IPv4 address) → `QueryMeta.source` is `to_canonical()`-ed at entry (N2). (3) `quinn-udp` pinned to 0.5.16 (quinn's own version; spike re-run green, identical `RecvMeta.dst_ip` / `Transmit.src_ip`). (4) The spike used blocking std sockets; N4 must show the tokio integration (`readable()` + `try_io`). (5) Do not copy the spike's `max_early_data_size = u32::MAX`: 0-RTT stays off for DoQ and h3.

Gate after adding any of them: `cargo tree -i aws-lc-rs`, `-i aws-lc-sys`, `-i openssl-sys` empty;
`cargo deny check` green.

## Task List

### Phase 0: Approval and risk spike
- [x] **Owner approves SPEC-listeners.md + the dependency table** (2026-10-25; decisions in the spec)
- [x] L0: Policy accessor for registered Client IDs (cross-module, XS)
- [x] N0: Spike — pktinfo reply-source, quinn ring-only, h3/h3-quinn compile, hyper h2 server (spikes/listeners/)

### Checkpoint A: Approval + spike
- [x] Spike findings in progress.md; dependency table confirmed or adjusted; owner go for Phase 1

### Phase 1: Core + Do53
- [x] N1: Crate skeleton — config, validation, errors, `Clock`, `QueryHandler` trait
- [x] N2: Message core — validation, EDNS, ECS strip, EDE, id/flags, size limit, padding
- [x] N3: Admission — source class, token buckets, ban table (bounded), decision API
- [x] N4: Do53 UDP — concrete + wildcard sockets, reply source, in-flight cap
- [x] N5: Do53 TCP — RFC 7766 framing, pipelining, out-of-order, idle timeout, caps

### Checkpoint B: Do53 end to end
- [x] Do53 UDP/TCP against the real `PolicyEngine` on the testkit hierarchy (IPv4 + IPv6); `examples/serve.rs` answers `dig` on a high port; Claude review ✓ (2026-10-26)

### Phase 2: Encrypted transports
- [x] N6: TLS server configs from `CertResolver`, SNI admission, `no_cert` state, hot reload
- [x] N7: DoT
- [x] N8: DoH over HTTP/2 + HTTP/1.1
- [x] N9: DoQ

### Checkpoint C: Encrypted end to end
- [x] DoT / DoH / DoQ answer identically to Do53; public admission matrix; cert hot reload; Claude review ✓ (2026-10-26)

### Phase 3: Discovery, runtime, HTTP/3
- [x] N10: DDR `_dns.resolver.arpa`
- [x] N11: `ListenerSet` runtime — start, partial bind failure, `apply_config`, shutdown, status, query events
- [ ] N12: DoH over HTTP/3 + `Alt-Svc` (owner: in v1)

### Phase 4: Polish (+ optional binary)
- [ ] N13: Fuzz targets, bench, README, coverage, success-criteria table
- [ ] N14: Minimal `crates/dnscraft` binary (owner: yes)

### Checkpoint D: Complete
- [ ] All spec success criteria; independent security review (exposure, admission, resource caps); owner approval

## Dependency graph

```
L0 (policy accessor) ──────────────┐
N0 spike ─┬─ N1 skeleton ─ N2 core ─ N3 admission ─┬─ N4 UDP ─┐
          │                                        └─ N5 TCP ─┴─ [B] ─ N6 TLS ─┬─ N7 DoT ─┐
          │                                                                     ├─ N8 DoH ─┼─ [C] ─ N10 DDR ─ N11 runtime ─ N12 h3 ─ N13 polish ─ N14 bin ─ [D]
          └─────────────────────────────────────────────────────────────────────└─ N9 DoQ ─┘
```

One agent works sequentially in this order; N7/N8/N9 are independent of each other once N6 is done.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| pktinfo on wildcard sockets behaves differently on arm64 / in Docker macvlan | High | N0 spike on the dev box (aarch64) first; concrete addresses as the documented default |
| `h3` / `h3-quinn` are pre-1.0 and churn | Med | isolated late task N12, behind `h3 = true`; can be deferred |
| quinn pulls aws-lc through a default feature | High | `default-features = false` + explicit features; `cargo deny` bans fail the build |
| Amplification / resource exhaustion from public sources | High | drop public Do53, caps on every loop, bounded LRU tables, bans; security review at D |
| Identical answers across 5 transports drift apart | Med | single `handle_wire` core; cross-transport equality test at C |
| Flaky socket tests | Med | loopback only, ephemeral ports, `ManualClock` for limits; no wall-clock sleeps (lesson from clients C11b) |
| DDR clients ignore opportunistic discovery | Low | documented; verified DDR is an open question (IP SANs) |

## Open Questions

See [SPEC-listeners.md § Open Questions](../SPEC-listeners.md#open-questions-owner): dependencies, HTTP/3 in v1,
wildcard binds, public Do53 drop vs REFUSED, minimal binary (N14), verified DDR.
