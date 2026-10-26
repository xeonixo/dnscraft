# Progress log

Resume point for interrupted sessions. Newest entry first.
Active plans: [plan-listeners.md](plan-listeners.md) / [todo-listeners.md](todo-listeners.md).
Briefs and reusable templates for Cursor agents: [cursor-next.md](cursor-next.md).

**Archive:** [archive/](archive/) holds the plans and tasks of every finished module, the old briefs, and the
full log of 2026-10-24 … 25 ([archive/progress-2026-10.md](archive/progress-2026-10.md)) — including the
success-criteria tables, measurements and review findings of resolver, filtering, clients, tls and policy.

**Workflow:** Cursor agents (or Haiku/Sonnet subagents) implement one task at a time; Claude reviews
(diff, `fmt`, `clippy`, tests, mutation probes, temporary probe tests); each task is ticked off in its
`todo-<module>.md`, logged here and committed.

## Current state

| Module | State | Plan / tasks | Evidence |
|---|---|---|---|
| `resolver` | COMPLETE (Checkpoint E, 2026-10-25) | [plan](archive/resolver-plan.md) · [tasks](archive/resolver-todo.md) | archived log |
| `filtering` | COMPLETE (Checkpoint D, 2026-10-25) | [plan](archive/filtering-plan.md) · [tasks](archive/filtering-todo.md) | archived log |
| `clients` | COMPLETE (Checkpoint C, 2026-10-25) | [plan](archive/clients-plan.md) · [tasks](archive/clients-todo.md) | archived log, coverage 86.2 % |
| `tls` | COMPLETE (Checkpoint C, 2026-10-25, LE staging accepted) | [plan](archive/tls-plan.md) · [tasks](archive/tls-todo.md) | archived log, coverage 80.3 % |
| `policy` | COMPLETE (Checkpoint C, 2026-10-25; P13 SafeSearch, P14 schedules) | [plan](archive/policy-plan.md) · [tasks](archive/policy-todo.md) | archived log, coverage 92.9 % |
| `listeners` | Checkpoint B impl done; **STOP for Claude review** | [plan](plan-listeners.md) · [tasks](todo-listeners.md) | [SPEC-listeners.md](../SPEC-listeners.md); crate `dnscraft-listeners` |
| `control-api`, `web-ui`, `mcp`, `cluster` | pending (see [CAPABILITY-MAP.md](../CAPABILITY-MAP.md)) | – | – |

- Toolchain: MSRV **1.88**, toolchain `stable`; all dependencies on their latest stable versions
  (2026-10-25); ring-only TLS enforced by `cargo deny` bans; `cargo deny check` runs in CI.
- Blockers: none.
- Open owner questions: schedule windows in local time (needs a time-zone dependency; today UTC week
  offsets, see SPEC-policy.md "Schedules").
- Optional follow-ups noted in reviews (not blocking): clients — record fetch errors only for
  non-superseded fetches; policy — `strip_rrsigs_covering` filters by type, not (owner, type);
  tls — `RETRY_AFTER_MAX_LEN` cap untested.

## Log

- 2026-10-25 — **listeners: Checkpoint B (impl).** E2e: `tests/checkpoint_b.rs` — PolicyEngine on testkit hierarchy (view `lan.example.test.`, block `blocked.example.test.`, recurse `www.example.test.`) over UDP+TCP on IPv4 and IPv6. Example: `cargo run -p dnscraft-listeners --example serve` binds `127.0.0.1:5353` (falls back to `:15353` if busy); real root-hint resolver; verified `dig … example.com A` UDP+TCP. Dep: `dnscraft-filtering` (lib), `dnscraft-testkit` (dev), tokio `signal`. **STOP for Claude review** (tick remaining Checkpoint B box after review).

- 2026-10-25 — **listeners: N5 Do53 TCP.** `serve_tcp` / `TcpServeParams`: accept with `max_connections_per_listener` + `max_connections_per_source`; public Do53 → close; per connection 2-byte framing (`framing::read_frame`/`write_frame`), pipelined queries with one writer task (out-of-order answers), idle via `wait_until` + `tcp_idle_timeout`, edns-tcp-keepalive (option 11) echoed with idle units when requested; max message 65 535. `TcpStats` counters. Tests: pipeline Notify out-of-order, ManualClock idle, both caps, half-prefix/zero-length framing, keepalive. DoD green. Next: Checkpoint B.

- 2026-10-25 — **listeners: N4 Do53 UDP.** `serve_udp`: concrete binds via tokio `recv_from`/`send_to`; wildcard (`0.0.0.0`/`::`) via `quinn-udp` 0.5.16 (`RecvMeta.dst_ip` → `Transmit.src_ip`), driven by `readable()` + `try_io` (no sleep loops). Per datagram: admission → in-flight semaphore → `handle_wire` with `udp_size_limit` (EDNS `min(client, udp_payload_max)` / 512) → deadline via `wait_until` + clock. `UdpStats` counters. Dep: `quinn-udp =0.5.16`. Tests: IPv4/IPv6 FakeHandler + PolicyEngine local record, wildcard 127.0.0.1/2 reply source, same-port v4+v6 unspecified, TC/512 truncation, inflight + public drop. DoD green; crypto trees empty; deny ok. Next: N5.

- 2026-10-25 — **listeners: N3 admission.** `SourceClass::of` (RFC 1918 / loopback / link-local / ULA / CGNAT + IPv4-mapped; documentation ranges public). `Admission::check` → Admit | Drop(code) | Refuse(code): ban → public Do53 drop → public-listener Client ID → per-source token bucket → per-Client-ID bucket (public sources). UDP rate/ban → Drop; TCP/DoT/DoH/DoQ rate → Refuse; banned → Drop (close). `strike` for transports (private no-op). LRU tables capped by `max_tracked_sources`. Tests: source-class table, admission matrix, ManualClock refill/ban/expiry/window, flood 10×cap. DoD green; crypto trees empty; `cargo deny check` ok. Next: N4.

- 2026-10-25 — **listeners: N2 message core.** `handle_wire(bytes, QueryMeta, handler) -> Option<HandleWireResult>`: header-less / QR=1 → None; FORMERR/NOTIMP/REFUSED/BADVERS before policy; `source.to_canonical()`; ECS stripped; OPT echo `min(client, udp_payload_max)` + EDE only when client sent OPT; id 0 for DoH/DoQ; RD copy, RA set; `encode_with_limit` (TC); pad to multiple of 468 when `pad` + OPT (RFC 8467). Returns `QueryEvent` when the handler ran (N11 sink later). Deps: `dnscraft-proto`, `dnscraft-resolver` (direct); dev `proptest`. Tests: 17 core (+ padding property, IPv4-mapped, proptest 1024). DoD green; `cargo tree -i aws-lc-rs` / `-i openssl-sys` empty; `cargo deny check` ok. Next: N3.

- 2026-10-25 — **listeners: N1 crate skeleton.** New workspace member `crates/dnscraft-listeners`: `ListenersConfig` / `ListenerConfig` / `Limits` / `PublicConfig` / `DdrConfig` + `validate()` (unique ids, public plaintext, public requires `enabled`, h3 only on doh, UDP/TCP bind conflicts, limits > 0, `N/s` rates); `ListenersError` with stable `code()`s + uniqueness test; `Clock` / `ManualClock` / `SystemClock`; `QueryHandler` + `PolicyEngine` impl + `FakeHandler`; `bind_udp` / `bind_tcp` via `socket2` 0.6.5 (default features; IPv6 → `set_only_v6(true)` before bind). Deps added: `dnscraft-policy`, `thiserror`, `tokio`, `socket2` 0.6.5 (workspace). No quinn/hyper/h3 yet. Tests: 20 (3 lib + 14 config + 3 socket). DoD green. Crypto tree:
  ```
  $ cargo tree -i aws-lc-rs
  error: package ID specification `aws-lc-rs` did not match any packages
  $ cargo tree -i aws-lc-sys
  error: package ID specification `aws-lc-sys` did not match any packages
  $ cargo tree -i openssl-sys
  error: package ID specification `openssl-sys` did not match any packages
  $ cargo deny check
  advisories ok, bans ok, licenses ok, sources ok
  ```
  Next: N2.

- 2026-10-25 — **listeners: Checkpoint A approved** (Claude review, owner go for Phase 1). Re-ran the spike (`cargo run --locked`, 4/4 PASS; `cargo tree -i aws-lc-rs` / `-i aws-lc-sys` / `-i openssl-sys` no match) and the L0 gates (fmt, clippy `-D warnings`, `client_id` tests, `cargo deny check` green). Extra probes in a scratch copy of the spike: `0.0.0.0:p` + `[::]:p` → `EADDRINUSE` (dual-stack); IPv4 peers on `[::]` arrive as `::ffff:…` with correct reply source; `quinn-udp` 0.5.16 behaves like 0.6.3. Owner decisions: **`socket2` 0.6 direct with `IPV6_V6ONLY`** on all IPv6 sockets; **`quinn-udp` 0.5.16** (no duplicate). Plan/tasks updated: N1 socket helper, N2 `to_canonical()` source, N4 tokio integration + same-port v4/v6 test, N6 `PolicyClientIds` acceptance + lower-cased SNI, N8 lower-cased path id, N9/N12 `Endpoint::new` + 0-RTT off. L0 review: `Borrow<str>` consistent with derived `Hash`/`Eq` on `Arc<str>`; no findings.

- 2026-10-25 — **spikes: listeners N0** (pktinfo, quinn ring-only, h3, hyper h2). Standalone crate `spikes/listeners/` (own `[workspace]` + `Cargo.lock`; main workspace / root `Cargo.lock` untouched). Host: aarch64 Linux. Commands: `cd spikes/listeners && cargo run`; `cargo tree -i aws-lc-rs` / `-i aws-lc-sys` / `-i openssl-sys` → each `error: package ID specification … did not match any packages`.

  | Question | Result | Exact versions + features | Caveats |
  |---|---|---|---|
  | quinn-udp wildcard learns dst + reply FROM it | **Works** on `0.0.0.0` and `[::]`; verified 127.0.0.1, 127.0.0.2 (no extra addr needed on Linux `/8` loopback), ::1 | `quinn-udp` **0.6.3** (direct); `RecvMeta.dst_ip` / `Transmit.src_ip` | ULA on dummy iface **not tested** (`ip link add type dummy` → Operation not permitted, uid≠0) |
  | quinn ring-only + ResolvesServerCert | **Works**; bi-stream echo | `quinn` **0.11.12** `default-features=false`, `runtime-tokio`, `rustls-ring`; `rustls` 0.23.46; `rcgen` 0.14.10; `QuicServerConfig::try_from` + `with_cert_resolver` | quinn also pulls `quinn-udp` **0.5.16** transitively (coexists with 0.6.3) |
  | h3 + h3-quinn one GET | **Works** (in-process Rust client); curl has `Features: HTTP3` | `h3` **0.0.8**, `h3-quinn` **0.0.10** | pre-1.0; keep server `Connection` alive until client drains or `recv_response` sees `H3_NO_ERROR`; ALPN `h3`; h3-quinn re-exports quinn |
  | hyper 1 + hyper-util h2 over tokio-rustls | **Works**; negotiated ALPN `h2` | `hyper` **1.12.0** (`server`,`http1`,`http2`), `hyper-util` **0.1.21** (`tokio`,`server-auto`,…), `tokio-rustls` **0.26.6** `ring`+`tls12` | `AutoBuilder` + `http2::Builder` client in spike |
  | `base64` in main tree? | **Yes** — `base64@0.23.1` (hyper-util/pem/reqwest) and `base64@0.22.1` (instant-acme) | plan: use **0.23.1**, no new major | – |

  Plan dependency table updated with N0 notes. **STOP: Checkpoint A** — Claude reviews spike; owner go for Phase 1 (do not start N1).

- 2026-10-25 — **policy: L0 client id accessor.** `PolicyEngine::is_client_id_registered(&self, id: &str) -> bool`: validates charset/length without allocating (`ClientId::is_valid_str`), short snapshot read lock, `HashMap` lookup via new `Borrow<str>` on id types. Invalid → false, never panics. Tests: registered / unknown / invalid; `apply_config` removing the id → false. Policy README: one paragraph (adapter stays in listeners). DoD: fmt, clippy `-D warnings`, workspace tests, `cargo deny check` green; `cargo tree -i aws-lc-rs` / `-i openssl-sys` empty.

- 2026-10-25 — **Owner approved SPEC-listeners.md, the plan and the dependency table** with all six recommendations: deps as listed; HTTP/3 in v1 (late task N12); wildcard binds supported, concrete addresses preferred; public Do53 dropped silently; minimal `dnscraft` binary (N14) in scope; DDR opportunistic only. Next: L0 + N0 (Cursor).

- 2026-10-25 — **listeners: spec draft + plan + tasks** (Claude). SPEC-listeners.md (draft): listener model (id, protocol, address, exposure), admission (source class, public Do53 dropped, Client ID via SNI / DoH path, token buckets, bounded ban table), shared message core, per-transport rules (RFC 1035/6891/7766/7828/7858/8484/9113/9114/9250/8467/9462 to verify and cite at implement time), TLS via `tls::CertResolver`, DDR, query events, runtime/reload, 8 success criteria, 6 open owner questions. Plan: one Cursor agent, 16 tasks (L0 policy accessor, N0 spike for pktinfo/quinn ring-only/h3/hyper, N1–N13, optional N14 minimal binary), checkpoints A–D. Dependencies for approval: quinn 0.11 (ring-only features), quinn-udp 0.6, hyper 1 + hyper-util 0.1, h3 0.0.8 + h3-quinn 0.0.10, base64 (if not in the tree), toml (N14). **STOP: owner approval.**

- 2026-10-25 — **Tasks cleaned up** (Claude): tls plan/tasks archived (archive/tls-plan.md, tls-todo.md);
  the finished briefs of the clients/tls/policy round moved to archive/cursor-clients-tls-policy.md;
  cursor-next.md now holds only the reusable rules and templates; the full log up to now moved to
  archive/progress-2026-10.md. References in SPEC-tls.md, the filtering README and safesearch_table.rs
  point to the archived log.
