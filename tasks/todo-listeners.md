# Tasks: `listeners` module

> Plan: [plan-listeners.md](plan-listeners.md) · Spec: [SPEC-listeners.md](../SPEC-listeners.md) · Resume log: [progress.md](progress.md)
> Definition of done per task: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
> `cargo test --workspace --locked`, `cargo deny check` green; `cargo tree -i aws-lc-rs` / `-i openssl-sys` empty;
> Claude review at checkpoints; one commit per task.
> Tests use loopback only, ephemeral ports, `rcgen` test certificates, documentation ranges and `example.com`;
> limits and timeouts are tested with `ManualClock` — no wall-clock sleeps to wait for background work.

## Phase 0: Approval and risk spike

**Precondition for every task below:** progress.md logs the owner's approval of SPEC-listeners.md and the
dependency table in plan-listeners.md.

## Task L0: Policy accessor for registered Client IDs (cross-module)

**Description:** Public listeners must know whether a Client ID is registered before the TLS handshake
completes / before routing a DoH path. The policy snapshot already holds `client_ids: HashMap<ClientId,
ViewIdx>`. Add `PolicyEngine::is_client_id_registered(&self, id: &str) -> bool` (cheap: snapshot read
lock + map lookup, case-sensitive on the already lower-cased id) and an adapter
`PolicyClientIds(Arc<PolicyEngine>)` implementing `dnscraft_tls::ClientIdRegistry` **in the listeners
crate** (policy must not depend on tls). Hot reload: the check always uses the current snapshot.

**Acceptance criteria:**
- [x] Registered id → true, unknown → false, invalid charset → false (no panic)
- [x] After `apply_config` removing the id → false on the next call
- [x] Policy README documents the accessor

**Verification:** `cargo test -p dnscraft-policy client_id`

**Dependencies:** owner approval ✓ (2026-10-25) · **Files:** `crates/dnscraft-policy/src/engine.rs`, `tests/engine.rs`, `README.md` · **Scope:** XS

## Task N0: Spike — pktinfo, quinn ring-only, h3, hyper h2

**Description:** Throw-away prototypes under `spikes/listeners/` — a standalone crate with its own
`[workspace]` table and `Cargo.lock`, like `spikes/hickory-recursor` (not a member of the main workspace) —
that answer four questions with evidence:
1. `quinn-udp`: a wildcard `0.0.0.0:<port>` and `[::]:<port>` UDP socket receives the destination
   address of each datagram and replies from it, on the dev box (aarch64 Linux) — test with two local
   addresses (e.g. 127.0.0.1 and 127.0.0.2, ::1 and a ULA on a dummy interface if available).
2. `quinn` with `default-features = false, features = ["runtime-tokio", "rustls-ring"]` builds a server
   endpoint with our `CertResolver` and `cargo tree -i aws-lc-rs` stays empty.
3. `h3` + `h3-quinn` serve one HTTP/3 request on that endpoint (curl `--http3` if available, else a
   Rust client).
4. `hyper` 1 + `hyper-util` serve HTTP/2 over `tokio-rustls` with ALPN `h2`.

**Acceptance criteria:**
- [x] Findings (works / doesn't / caveats, exact feature lists, versions) logged in progress.md
- [x] Dependency table in plan-listeners.md confirmed or corrected
- [x] Spike code committed under `spikes/listeners/` only; main workspace untouched

**Verification:** commands listed in the progress entry; `cargo tree -i aws-lc-rs` output pasted

**Dependencies:** owner approval ✓ (2026-10-25) · **Files:** `spikes/listeners/**`, `tasks/progress.md` · **Scope:** M

## Checkpoint A: Approval + spike
- [x] Spike findings reviewed by Claude; dependency table final (2026-10-25; findings in plan-listeners.md "Checkpoint A review")
- [x] **Owner go for Phase 1** (2026-10-25; `socket2` V6ONLY and `quinn-udp` 0.5.16 accepted)

## Phase 1: Core + Do53

## Task N1: Crate skeleton, config, errors, handler trait

**Description:** Create `crates/dnscraft-listeners` (workspace member, workspace lints, approved
dependencies only). `ListenersConfig` / `ListenerConfig` / `Limits` / `PublicConfig` / `DdrConfig` as
Rust values of the spec excerpt (no TOML parsing here — the binary does that later). `validate()`:
unique ids (`policy::ListenerId`), public exposure only for dot/doh/doq, public listeners require
`public.enabled`, `h3` only on doh, no two listeners on the same (protocol family, address, port),
limits > 0, rate strings parsed (`N/s`). `ListenersError` with stable `code()`s from the spec +
uniqueness test. `Clock` / `ManualClock` (per-crate pattern). `QueryHandler` trait + impl for
`PolicyEngine`; `FakeHandler` for tests (records contexts, returns canned answers).
Socket helper `bind_udp(addr)` / `bind_tcp(addr)` (std sockets via `socket2`, non-blocking, `SO_REUSEADDR`
for TCP; IPv6 → `set_only_v6(true)` **before** bind) that every transport uses (Checkpoint A finding 1).

**Acceptance criteria:**
- [x] Spec excerpt as Rust values validates; each rejection rule has a test with its code
- [x] `QueryHandler` impl for `PolicyEngine` compiles and is exercised by one test
- [x] Crate README skeleton
- [x] Socket helper: `0.0.0.0:p` and `[::]:p` bind side by side (UDP and TCP); an IPv6 socket reports `only_v6() == true`

**Verification:** `cargo test -p dnscraft-listeners config` and `cargo test -p dnscraft-listeners socket`

**Dependencies:** L0, Checkpoint A · **Files:** `Cargo.toml`, `crates/dnscraft-listeners/{Cargo.toml,src/lib.rs,src/config.rs,src/error.rs,src/clock.rs,src/handler.rs,src/socket.rs}` · **Scope:** M

## Task N2: Message core (`handle_wire`)

**Description:** Transport-independent `handle_wire(bytes, QueryMeta) -> Option<Vec<u8>>` where
`QueryMeta = { protocol, listener_id, source, client_id, size_limit, pad }`:
decode with dnscraft-proto; undecodable without header → None; QR=1 → None; opcode ≠ QUERY → NOTIMP; `source` is normalised with `IpAddr::to_canonical()` before anything else
(IPv4-mapped → IPv4, Checkpoint A finding 2);
QDCOUNT ≠ 1 → FORMERR; class not IN/CH/ANY → REFUSED; CHAOS → REFUSED; EDNS version ≠ 0 → BADVERS;
strip ECS; build `RequestContext` (RD/CD/DO); call handler; set id (0 for DoH/DoQ per RFC, else the
query id), copy RD, set RA; OPT echo with `min(client, udp_payload_max)`; attach `PolicyAnswer.ede` only
when the client sent OPT; encode with `size_limit` (TC on truncation); pad to a multiple of 468 when
`pad` and OPT present (RFC 8467). Also returns the `QueryEvent` data for N11 (no sink yet).

**Acceptance criteria:**
- [x] Table test per rule above (FORMERR/NOTIMP/REFUSED/BADVERS/TC/RA/RD/id/ECS/EDE/padding)
- [x] `::ffff:192.0.2.1` source reaches the handler / `RequestContext` as `192.0.2.1`
- [x] Padding length property: padded size % 468 == 0 and ≤ limit
- [x] Never panics on arbitrary input (proptest ≥ 1024 cases; fuzz target added in N13)

**Verification:** `cargo test -p dnscraft-listeners core`

**Dependencies:** N1 · **Files:** `src/core.rs`, `src/edns.rs`, `tests/core.rs` · **Scope:** M

## Task N3: Admission — source class, rate limits, bans

**Description:** `SourceClass::of(IpAddr)` (private = RFC 1918, loopback, link-local, ULA, CGNAT,
IPv4-mapped forms; else public). `Admission::check(listener, source, client_id_state, now) ->
Admit | Drop(code) | Refuse(code)` implementing spec "Source classification and admission" items 2–6.
Token bucket per source IP and per Client ID (rate + burst from config). Ban table: strikes per public
source within `ban_window` → ban for `ban_duration`; `strike(source, reason)` API for transports. Both
tables LRU-bounded by `max_tracked_sources` (evict oldest; never allocate per packet beyond that).

**Acceptance criteria:**
- [ ] Source-class table test (each range + mapped forms + public examples from documentation ranges treated as public)
- [ ] Admission matrix test: protocol × exposure × source class × Client ID state
- [ ] `ManualClock`: bucket refill, ban after N strikes, ban expiry, strike window expiry
- [ ] Flood test: 10 × `max_tracked_sources` distinct sources keep both tables at the cap

**Verification:** `cargo test -p dnscraft-listeners admission`

**Dependencies:** N1 · **Files:** `src/admission.rs`, `src/ratelimit.rs`, `src/bans.rs`, `tests/admission.rs` · **Scope:** M

## Task N4: Do53 UDP

**Description:** UDP listener task: concrete-address socket via tokio; wildcard socket via `quinn-udp` 0.5
with destination-address recv + source-address send (spike N0), driven by tokio (`UdpSocket::readable()` +
`try_io`, no sleep loops). Sockets come from the N1 helper (IPv6 = V6ONLY). Per datagram: admission (public source →
drop), `handle_wire` with `size_limit = min(client EDNS size, udp_payload_max)` or 512 without OPT,
bounded in-flight set (`max_inflight_per_listener`, excess dropped and counted), deadline
`query_timeout` (expiry → drop). Counters for status.

**Acceptance criteria:**
- [ ] IPv4 + IPv6 loopback query answered through `FakeHandler` and through the real `PolicyEngine`
- [ ] Wildcard socket replies from the arrival address (two loopback addresses)
- [ ] `0.0.0.0` and `::` listeners on the same port both answer (IPv4 and IPv6 query)
- [ ] Truncation: large answer → TC=1 within the limit; no OPT → 512 limit
- [ ] In-flight cap and public-source drop counted

**Verification:** `cargo test -p dnscraft-listeners udp`

**Dependencies:** N2, N3 · **Files:** `src/udp.rs`, `tests/udp.rs`, `tests/support/mod.rs` · **Scope:** M

## Task N5: Do53 TCP

**Description:** TCP listener: accept loop with `max_connections_per_listener` and
`max_connections_per_source`; per connection read 2-byte length-prefixed messages, run queries
concurrently (pipelining) and write answers as they complete (out of order, RFC 7766 §6.2.1.1), one
writer task per connection; idle timeout `tcp_idle_timeout`; edns-tcp-keepalive (RFC 7828) in responses
when requested; max message 65 535; public source → close immediately.

**Acceptance criteria:**
- [ ] Pipelined queries with a slow first answer (FakeHandler delay via `Notify`, not sleep) come back out of order with the right ids
- [ ] Idle timeout and both connection caps tested
- [ ] Half-written length prefix / oversize length → connection closed, counter incremented

**Verification:** `cargo test -p dnscraft-listeners tcp`

**Dependencies:** N2, N3 · **Files:** `src/tcp.rs`, `src/framing.rs`, `tests/tcp.rs` · **Scope:** M

## Checkpoint B: Do53 end to end
- [ ] Do53 UDP + TCP against `PolicyEngine` built on the testkit hierarchy (view record, blocked name, recursion) on IPv4 + IPv6
- [ ] `examples/serve.rs` (no config file: hard-coded loopback high ports + testkit-free real resolver from root) answers `dig @127.0.0.1 -p 5353 example.com` — owner can try it
- [ ] DoD green; Claude review; progress.md updated

## Phase 2: Encrypted transports

## Task N6: TLS server configs, SNI admission, hot reload

**Description:** Build `rustls::ServerConfig`s (ring provider) from `Arc<CertResolver>`: TCP family with
ALPN `dot` / `h2` + `http/1.1`, QUIC family (TLS 1.3) with ALPN `doq` / `h3`. Wrap the resolver so that
on **public** listeners a ClientHello with an unregistered / missing SNI fails the handshake (via
`tls::accept_public_sni` + `PolicyClientIds`; the SNI label is lower-cased before the registry lookup
because `is_client_id_registered` is case-sensitive), records a ban strike — except `SniKind::NodeHostname` /
`Apex`, which fail without a strike. No certificate installed → handshake fails with
`listeners.tls.no_cert` (counted), listener stays bound. `tls_handshake_timeout` enforced by the callers
(helper here). Extract the Client ID for `QueryMeta`.

**Acceptance criteria:**
- [ ] `PolicyClientIds(Arc<PolicyEngine>)` implements `dnscraft_tls::ClientIdRegistry` (L0 adapter) and follows `apply_config`
- [ ] Handshake matrix (local/public × registered/unknown/missing/node/apex SNI, incl. upper-case SNI of a registered id) with rcgen certs
- [ ] Cert A → install cert B → a new handshake sees B without restart; an open connection keeps working
- [ ] `no_cert` state then install → next handshake succeeds

**Verification:** `cargo test -p dnscraft-listeners tls`

**Dependencies:** L0, N3, Checkpoint B · **Files:** `src/tls.rs`, `tests/tls.rs`, `tests/support/certs.rs` · **Scope:** M

## Task N7: DoT

**Description:** DoT listener = TCP shell (N5 framing and limits) over `tokio-rustls` with the N6
config and handshake timeout; Client ID from SNI into `QueryMeta`; padding on.

**Acceptance criteria:**
- [ ] DoT query answered identically to Do53 (except padding) for the same question
- [ ] Public listener: registered SNI answered, unknown SNI rejected + strike, ban after N strikes
- [ ] Handshake timeout closes slow-loris connections

**Verification:** `cargo test -p dnscraft-listeners dot`

**Dependencies:** N5, N6 · **Files:** `src/dot.rs`, `tests/dot.rs` · **Scope:** S

## Task N8: DoH over HTTP/2 + HTTP/1.1

**Description:** `hyper` 1 server (via `hyper-util` auto connection builder) over the N6 TLS config.
Routes: local listeners `/dns-query` and `/dns-query/<id>` (`<id>` lower-cased before the registry lookup); public listeners `/dns-query/<id>` only (unknown
id → 404 + strike, other paths → 404 without strike). `GET ?dns=` (base64url, no padding; reject padding
and oversize), `POST` with `Content-Type: application/dns-message` and a body cap; errors 400/405/413/415;
rate limit → 429. Response: `application/dns-message`, `Cache-Control: max-age=<min TTL of answer>` for
NOERROR/NXDOMAIN, id 0, padding on. No other routes, no directory listing, no server banner details.

**Acceptance criteria:**
- [ ] GET and POST answers equal the Do53 answer (id 0, padding aside); HTTP/2 and HTTP/1.1 both tested
- [ ] Error-status table test (400/404/405/413/415/429) incl. public-path rules
- [ ] `Cache-Control` max-age equals the minimum TTL

**Verification:** `cargo test -p dnscraft-listeners doh`

**Dependencies:** N6 · **Files:** `src/doh.rs`, `src/doh_request.rs`, `tests/doh.rs` · **Scope:** M

## Task N9: DoQ

**Description:** `quinn` endpoint (spike N0 features) with the N6 QUIC config (ALPN `doq`, 0-RTT off), built with
`Endpoint::new` on a socket from the N1 helper (IPv6 = V6ONLY).
Per connection accept bidirectional streams up to `max_quic_streams_per_connection`; each stream: read
2-byte length + message, require message id 0 (else close the connection with `DOQ_PROTOCOL_ERROR`),
`handle_wire`, write length + answer, finish the stream. Idle timeout; Client ID from SNI; public
admission and strikes as DoT.

**Acceptance criteria:**
- [ ] DoQ answer equals Do53 answer; several concurrent streams on one connection
- [ ] Non-zero id → `DOQ_PROTOCOL_ERROR`; stream cap enforced; idle timeout
- [ ] Public SNI matrix as DoT

**Verification:** `cargo test -p dnscraft-listeners doq`

**Dependencies:** N6 · **Files:** `src/doq.rs`, `tests/doq.rs` · **Scope:** M

## Checkpoint C: Encrypted end to end
- [ ] One test sends the same question over UDP, TCP, DoT, DoH (h2 + http/1.1) and DoQ and compares the decoded answers
- [ ] Public admission matrix across DoT/DoH/DoQ; cert hot reload
- [ ] DoD green; Claude review (security focus: admission, strikes, caps); progress.md updated

## Phase 3: Discovery, runtime, HTTP/3

## Task N10: DDR `_dns.resolver.arpa`

**Description:** In `handle_wire`, before policy: on a **local Do53** listener a `SVCB` query for
`_dns.resolver.arpa` (class IN) is answered from the listener set: one SVCB record per local encrypted
listener of the same address family that is bound (priority 1…n, target `<ddr.target>.dns.<public_domain>`,
`alpn`, `port`, `dohpath=/dns-query{?dns}` for DoH, `ipv4hint`/`ipv6hint` = the listener address or, for a
wildcard, the query's arrival address). None → NODATA with SOA. Not on encrypted listeners. Uses
`dnscraft_proto::SvcbData` (RFC 9460 key order, mandatory keys none).

**Acceptance criteria:**
- [ ] SVCB answer decodes with the testkit's hickory oracle and lists the expected endpoints
- [ ] NODATA when no encrypted local listener; not answered on DoT/DoH/DoQ (goes to policy as usual)
- [ ] `ddr.enabled = false` → policy handles the name

**Verification:** `cargo test -p dnscraft-listeners ddr`

**Dependencies:** Checkpoint C · **Files:** `src/ddr.rs`, `src/core.rs`, `tests/ddr.rs` · **Scope:** S

## Task N11: `ListenerSet` runtime and query events

**Description:** `ListenerSet::start / apply_config / status / shutdown(grace)` per the spec; a failed
bind marks that listener `listeners.bind` in status and the others keep running; `apply_config` diffs by
listener id + settings and rebinds only changed ones (unchanged keep their sockets and connections);
shutdown stops accepting and drains in-flight queries up to `grace`. `QueryEventSink` trait + bounded
`ChannelSink` (try_send, drop + `events_dropped` counter); events only for `loggable` answers.

**Acceptance criteria:**
- [ ] Partial bind failure (port in use) reported, other listeners serve
- [ ] Reload: unchanged listener keeps an open TCP connection; changed address rebinds; removed one closes
- [ ] Full sink never blocks answering (test with capacity 1 and a stalled consumer); `test_query` answers emit no event
- [ ] Shutdown drains an in-flight query within grace

**Verification:** `cargo test -p dnscraft-listeners runtime`

**Dependencies:** N4, N5, N7, N8, N9, N10 · **Files:** `src/set.rs`, `src/events.rs`, `src/status.rs`, `tests/runtime.rs` · **Scope:** M

## Task N12: DoH over HTTP/3 (owner: in v1)

**Description:** When `h3 = true` on a DoH listener, also run a `quinn` endpoint on UDP with ALPN `h3` and
serve the same DoH routes through `h3` + `h3-quinn`, reusing `doh_request.rs`. 0-RTT off
(`max_early_data_size = 0`; do not copy the spike's `u32::MAX`). Socket from the N1 helper via `Endpoint::new`. HTTP/2 responses carry
`Alt-Svc: h3=":<port>"; ma=86400`.

**Acceptance criteria:**
- [ ] HTTP/3 GET + POST equal the HTTP/2 answers; public path rules identical
- [ ] `Alt-Svc` present only when h3 is enabled
- [ ] Stream/connection caps as DoQ

**Verification:** `cargo test -p dnscraft-listeners h3`

**Dependencies:** N8, N9 · **Files:** `src/doh_h3.rs`, `tests/doh_h3.rs` · **Scope:** M

## Phase 4: Polish (+ optional binary)

## Task N13: Fuzz, bench, README, coverage

**Description:** Fuzz targets `listeners_handle_wire` and `listeners_doh_request` in `fuzz/` (+ CI matrix
entry, seeds), 10 min each clean. Criterion bench: UDP loopback qps with a cached answer (report
p50/p99 and qps). README: listener model, admission rules, limits table, DDR, TLS/hot reload, error codes,
manual interop recipe (`dig`, `kdig +tls/+https/+quic`, `curl --http2/--http3`). Success-criteria table in
progress.md. Coverage ≥ 80 % lines.

**Acceptance criteria:**
- [ ] Fuzz 10 min per target clean (execs logged)
- [ ] Bench numbers logged (target ≥ 20 000 qps on loopback)
- [ ] Coverage ≥ 80 % (or gap listed with reason); README complete

**Verification:** `cargo llvm-cov -p dnscraft-listeners --summary-only`; fuzz commands in the log

**Dependencies:** N11 (N12 if done) · **Files:** `fuzz/**`, `benches/udp.rs`, `README.md`, `tasks/progress.md` · **Scope:** M

## Task N14: Minimal `dnscraft` binary (owner go 2026-10-25)

**Description:** `crates/dnscraft` binary: reads a small bootstrap TOML (data dir, listeners, resolver
root/forward zones, filter lists, one default view/profile) + env secrets, builds resolver → filtering →
policy → (optional) tls → listeners, logs query events to stdout as JSON lines, handles SIGTERM with
graceful shutdown. No UI/API. Sample config in `deploy/` with documentation addresses only.

**Acceptance criteria:**
- [ ] Starts from the sample config on high ports and answers `dig`/`kdig` (manual, steps in README)
- [ ] Invalid config → exit code 2 with the stable error code; SIGTERM drains
- [ ] Integration test: spawn the binary on loopback, one UDP query, clean shutdown

**Verification:** `cargo test -p dnscraft`; manual run documented

**Dependencies:** N13 · **Files:** `crates/dnscraft/**`, `deploy/dnscraft.example.toml` · **Scope:** M

## Checkpoint D: Complete
- [ ] All spec success criteria met (table in progress.md)
- [ ] Independent security review (public exposure, amplification, admission, bans, resource caps, TLS)
- [ ] **Owner approval**
