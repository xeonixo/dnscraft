# Spec: `listeners` module

> Status: **DRAFT — awaiting owner approval** (written by Claude, 2026-10-25).
> Module index: [CAPABILITY-MAP.md](CAPABILITY-MAP.md) · Project spec: [SPEC.md](SPEC.md) ·
> Neighbours: [SPEC-policy.md](SPEC-policy.md) (query pipeline), [SPEC-tls.md](SPEC-tls.md) (certificates, SNI helpers).
> Plan / tasks (after approval): [tasks/plan-listeners.md](tasks/plan-listeners.md), [tasks/todo-listeners.md](tasks/todo-listeners.md).

## Objective

Accept DNS queries on every configured address and protocol — Do53 (UDP, TCP), DoT, DoH (HTTP/2 and
HTTP/3) and DoQ — turn each wire message into a `policy::RequestContext`, hand it to `PolicyEngine::handle`,
and send the answer back on the same transport, from the same local address, within the protocol's
framing and size rules. Enforce the internet-exposure rules of SPEC.md (public sources only on encrypted
listeners, only for registered Client IDs, rate limits and temporary bans), answer DDR (RFC 9462)
discovery queries, and emit one structured query event per answered query for the query log.

This module does **not** resolve, filter, select views (that is `policy`), obtain certificates (that is
`tls`), store the query log or serve the web UI/API (that is `control-api`). It is a library crate
(`crates/dnscraft-listeners`); the `dnscraft` binary wires it later.

## Assumptions

1. `policy::PolicyEngine::handle(RequestContext) -> PolicyAnswer` is the only query entry point; its
   message id is 0 and the listener sets the client's id. `PolicyAnswer.ede` is attached by the listener.
2. `tls::TlsEngine::resolver()` returns the shared `Arc<CertResolver>` (hot reload included);
   `tls::accept_public_sni` + `tls::ClientIdRegistry` decide public DoT/DoQ admission; `SniKind` tells a
   node hostname / apex apart from an unknown Client ID (no ban strike for those).
3. Registered Client IDs are the ones the policy snapshot knows (`views[].client_ids`). Policy exposes a
   cheap read-only check for them (small cross-module task L0 in the plan).
4. Real client source addresses reach the process (macvlan/ipvlan or host networking, SPEC.md).
5. Linux is the production platform (amd64, arm64). Other platforms only need to compile.

## Requirements

### Research notes (verify every item against the source at implement time; cite in code)

| Topic | Source | What we take from it |
|---|---|---|
| UDP/TCP DNS, 512-byte classic limit | RFC 1035 §4.2 | framing, TC bit |
| EDNS(0) | RFC 6891 | OPT echo, UDP payload size, BADVERS |
| UDP size default 1232 | DNS Flag Day 2020 (https://www.dnsflagday.net/2020/) | `udp_payload_max` default |
| TCP transport, pipelining, out-of-order, idle timeouts | RFC 7766 | per-connection concurrency, 2-byte length prefix |
| edns-tcp-keepalive | RFC 7828 | optional; advertise idle timeout on TCP/DoT |
| DNS over TLS | RFC 7858, ALPN `dot` (RFC 7858 §3.2 / IANA) | port 853, framing as TCP |
| DNS over HTTPS | RFC 8484 | `GET ?dns=` base64url (no padding), `POST` `application/dns-message`, id 0 recommended, HTTP caching |
| HTTP/2, HTTP/3 | RFC 9113, RFC 9114 | DoH transports; `Alt-Svc` (RFC 7838) to advertise h3 |
| DNS over QUIC | RFC 9250 | ALPN `doq`, one query per bidirectional stream, 2-byte length prefix, message id **must be 0**, error codes (`DOQ_PROTOCOL_ERROR` …) |
| EDNS padding | RFC 7830, RFC 8467 | pad responses on encrypted transports (block length 468 for responses) |
| ECS | RFC 7871 | strip client ECS options; never forward them (SPEC.md) |
| DDR | RFC 9462, SVCB RFC 9460 | `_dns.resolver.arpa` SVCB; `alpn`, `port`, `dohpath`, `ipv4hint`/`ipv6hint`; opportunistic vs verified discovery |
| Extended DNS errors | RFC 8914 | attach `PolicyAnswer.ede` when the client sent OPT |
| ANY | RFC 8482 | already handled by policy |

### Listener model

A **listener** is one `(id, protocol, socket address, exposure)` entry:

- `protocol`: `udp53`, `tcp53`, `dot`, `doh` (serves HTTP/2 + HTTP/1.1 over TLS on TCP, and HTTP/3 over
  QUIC on the same port number when `h3 = true`), `doq`.
- `address`: a concrete IPv4/IPv6 address or a wildcard (`0.0.0.0`, `::`). Several listeners may share a
  port on different addresses. For wildcard UDP/QUIC sockets the reply source address must equal the
  query's destination address (`IP_PKTINFO` / `IPV6_RECVPKTINFO`, via `quinn-udp` — no `unsafe` in our
  code). Concrete-address sockets get this for free.
- `exposure`: `local` (default) or `public`. Public listeners are only allowed for `dot`, `doh`, `doq`
  (config error otherwise) and only when the node has public DoH/DoT enabled (SPEC.md: per node, off by
  default).
- `id`: `policy::ListenerId` (`[a-z0-9-]{1,64}`), unique; passed to policy as `RequestContext.listener_id`.

### Source classification and admission

Every query is admitted before policy sees it:

1. **Source class:** `private` = RFC 1918, loopback, link-local, ULA `fc00::/7`, CGNAT `100.64.0.0/10`,
   IPv4-mapped forms of these; everything else is `public`.
2. **Do53 from a public source** (any listener): dropped silently (UDP) / connection closed (TCP);
   counted as `listeners.admission.public_do53`. Never answered (SPEC.md "Internet exposure").
3. **Public listener, public source:** requires a registered Client ID.
   - DoT / DoQ: Client ID from SNI `<id>.dns.<domain>` via `tls::accept_public_sni`; unknown or missing →
     the TLS handshake is rejected (ban strike). `SniKind::NodeHostname` / `Apex` → rejected without a
     strike.
   - DoH: path `/dns-query/<id>`; unknown id → `404` (ban strike); any other path → `404` (no strike);
     the web UI/API is never routed on a public listener.
4. **Private source on a local listener:** Client ID optional (DoT SNI / DoH path may carry one; an
   unknown id on a local listener is ignored, not rejected).
5. **Rate limit:** token bucket per source IP (all sources, private included — SPEC.md "Per-client rate
   limit") and per Client ID for public sources. Over limit → UDP: drop; TCP/DoT/DoQ: `REFUSED`;
   DoH: `429`. Defaults in the configuration excerpt.
6. **Temporary bans:** a public source IP that collects `ban_strikes` strikes (unknown Client ID,
   failed TLS handshake, malformed DoH/DoQ framing) within `ban_window` is banned for `ban_duration`:
   connections/handshakes from it are closed immediately. Bans and buckets live in bounded tables
   (LRU, `max_tracked_sources`), so a spoofed-source flood cannot grow memory.

### Message handling (all transports)

- Decode with `dnscraft-proto`. Undecodable → `FORMERR` when a header could be parsed, otherwise drop.
- `QR=1`, `opcode != QUERY` → `NOTIMP`; `QDCOUNT != 1` → `FORMERR`; class other than IN/CH/ANY →
  `REFUSED`. CHAOS `version.bind` / `id.server` → `REFUSED` (no fingerprinting).
- EDNS: if the query has OPT, the response has OPT; advertised UDP size = `min(client, udp_payload_max)`;
  unknown EDNS version → `BADVERS`. ECS options are removed and never answered. Client cookies are
  ignored (no server cookies in v1).
- Build `RequestContext { source_ip, protocol, listener_id, client_id, query, flags (RD/CD/DO),
  test_query: false }`; call `PolicyEngine::handle`; set the client's id (DoH/DoQ: 0 per RFC), copy RD,
  set RA, attach EDE when the client sent OPT.
- **UDP size:** encode with the limit (`encode_with_limit`), set TC when truncated; TCP/DoT/DoQ/DoH use
  the 65 535 limit.
- **Padding:** on DoT/DoH/DoQ responses pad to a multiple of 468 bytes when the client sent OPT
  (RFC 8467 recommended policy).
- **Deadline:** every query has an overall deadline (`query_timeout`, default 10 s matching the resolver
  deadline); on expiry → `SERVFAIL` (UDP: drop).
- **Concurrency caps:** in-flight queries per listener, connections per listener and per source IP,
  streams per QUIC connection — all configurable, with defaults below.

### Per transport

- **UDP 53:** one task per socket, bounded in-flight set; reply from the destination address.
- **TCP 53 / DoT:** 2-byte length prefix, pipelined queries answered out of order (RFC 7766), idle timeout
  (`tcp_idle_timeout`, default 10 s; advertise via edns-tcp-keepalive when the client asked), max
  queries per connection, TLS handshake timeout (`tls_handshake_timeout`, default 5 s).
- **DoH:** paths `/dns-query` (local listeners) and `/dns-query/<id>`; `GET` with `dns=` (base64url, no
  padding) and `POST` with `Content-Type: application/dns-message`; other methods `405`, wrong type `415`,
  oversized `413`, malformed `400`. Response `Content-Type: application/dns-message`,
  `Cache-Control: max-age=<min TTL>` for NOERROR/NXDOMAIN answers. HTTP/2 and HTTP/1.1 via `hyper`;
  HTTP/3 via `h3` + `h3-quinn` on the same port number over UDP when `h3 = true`, advertised with
  `Alt-Svc` on HTTP/2 responses.
- **DoQ:** `quinn` endpoint, ALPN `doq`, one query per client-initiated bidirectional stream, 2-byte
  length prefix, message id must be 0 (else `DOQ_PROTOCOL_ERROR`), stream/connection limits,
  idle timeout. 0-RTT disabled (replay risk, RFC 9250 §4.5).

### TLS

- One `rustls::ServerConfig` per protocol family (ALPN `dot` / `h2`+`http/1.1` / `h3` / `doq`), all with
  `Arc<CertResolver>` from `tls` (hot reload without restart), ring provider, TLS 1.2+ for TCP, TLS 1.3
  for QUIC. A listener whose resolver has no certificate yet stays bound but rejects handshakes with
  `listeners.tls.no_cert` (status + counter) until `tls` installs one.

### DDR (RFC 9462)

- `_dns.resolver.arpa` `SVCB` queries arriving on a **local Do53** listener are answered by the listener
  (not by policy) with one SVCB record per encrypted local listener reachable on the same address family:
  priority, target `dns.<public_domain>` (or the node hostname), `alpn`, `port`, `dohpath=/dns-query{?dns}`
  for DoH, and `ipv4hint`/`ipv6hint` with the listener's address. No encrypted local listener → NODATA.
- DNScraft's certificate names are `dns.<domain>` / `*.dns.<domain>`, not IP addresses, so clients can use
  **opportunistic** discovery only (RFC 9462 §4.3, allowed for private resolver addresses); verified
  discovery (§4.2) would need IP SANs — out of scope (open question).
- DDR answers are logged like other queries (`AnswerOrigin` "listener/ddr").

### Query events (for the query log)

- After each answered query the listener sends a `QueryEvent { time, listener_id, protocol, source_ip,
  client_id, query, rcode, answer_size, duration, decision: DecisionRecord }` to a `QueryEventSink`
  trait object; events with `loggable == false` are not sent. The sink is non-blocking (bounded channel
  provided by this crate); when full, events are dropped and counted (`events_dropped`) — logging never
  slows answering. `control-api` implements the consumer later.

### Runtime, reload and status

- `ListenerSet::start(config, Arc<PolicyEngine>, Option<Arc<CertResolver>>, sink, clock)` binds all
  listeners; a bind failure of one listener is reported in status (`listeners.bind`) and does not stop the
  others. `apply_config` rebinds only changed listeners, keeps unchanged ones (open connections survive);
  `shutdown` stops accepting, drains in-flight queries up to a grace period.
- `status()` per listener: bound / error code, protocol, address, connections, queries, dropped,
  rate-limited, banned sources, TLS failures.

### Error codes

Every error has a stable `code()` (`listeners.<area>.<reason>`), covered by a uniqueness test, e.g.
`listeners.config.invalid`, `listeners.config.public_plaintext`, `listeners.config.duplicate_id`,
`listeners.bind`, `listeners.tls.no_cert`, `listeners.tls.handshake`, `listeners.admission.public_do53`,
`listeners.admission.unknown_client_id`, `listeners.rate_limited`, `listeners.banned`,
`listeners.doh.bad_request`, `listeners.doq.protocol`.

### Interface (sketch)

```rust
pub struct ListenersConfig { pub listeners: Vec<ListenerConfig>, pub limits: Limits, pub public: PublicConfig, pub ddr: DdrConfig }
pub struct ListenerConfig { pub id: ListenerId, pub protocol: Protocol, pub address: SocketAddr, pub exposure: Exposure, pub h3: bool }
pub trait QueryEventSink: Send + Sync { fn try_send(&self, event: QueryEvent) -> bool; }
pub struct ListenerSet { /* … */ }
impl ListenerSet {
    pub async fn start(cfg: ListenersConfig, policy: Arc<PolicyEngine>, certs: Option<Arc<CertResolver>>,
                       sink: Arc<dyn QueryEventSink>, clock: Arc<dyn Clock>) -> Result<Self, ListenersError>;
    pub async fn apply_config(&self, cfg: ListenersConfig) -> Result<(), ListenersError>;
    pub fn status(&self) -> ListenersStatus;
    pub async fn shutdown(self, grace: Duration);
}
```

The transport-independent core (`handle_wire(bytes, meta) -> Option<bytes>`) is public for tests and fuzzing.

## Configuration excerpt (TOML, bootstrap only)

```toml
[[listeners]]
id = "lan-udp"        ; protocol = "udp53" ; address = "0.0.0.0:53"
[[listeners]]
id = "lan-tcp"        ; protocol = "tcp53" ; address = "0.0.0.0:53"
[[listeners]]
id = "lan-dot"        ; protocol = "dot"   ; address = "[fd00::53]:853"
[[listeners]]
id = "public-doh"     ; protocol = "doh"   ; address = "0.0.0.0:443" ; exposure = "public" ; h3 = true

[listeners_limits]
udp_payload_max = 1232
query_timeout = "10s"
tcp_idle_timeout = "10s"
tls_handshake_timeout = "5s"
max_inflight_per_listener = 4096
max_connections_per_listener = 1024
max_connections_per_source = 32
max_quic_streams_per_connection = 64
rate_per_source = "200/s"          # burst 400; private sources included
rate_per_client_id = "50/s"        # public sources only

[listeners_public]
enabled = false                    # per node (SPEC.md)
ban_strikes = 5
ban_window = "1m"
ban_duration = "15m"
max_tracked_sources = 100000

[listeners_ddr]
enabled = true
target = "dns"                     # dns.<public_domain>; or a node hostname label
```

## Testing

- Unit: source classification table, admission matrix (protocol × exposure × source class × Client ID
  state), token bucket and ban table with `ManualClock`, bounded-table eviction, message validation
  (FORMERR/NOTIMP/REFUSED/BADVERS), EDNS echo / ECS strip / padding sizes, UDP truncation, DoH request
  parsing (GET/POST/errors), DDR SVCB encoding.
- Integration (loopback only, real sockets, test certificates from `rcgen`): Do53 UDP + TCP (pipelining,
  out-of-order), DoT, DoH h2/h1.1/h3, DoQ end-to-end against a `PolicyEngine` built on the testkit DNS
  hierarchy; reply-source-address test on a wildcard UDP socket; hot cert reload during open DoT
  connections; public listener rejects unknown SNI / DoH path; bans after N strikes; reload keeps
  unchanged listeners.
- Fuzz: `handle_wire` and the DoH request parser.
- Bench: Do53 UDP queries/s on loopback with a cached answer (report; target ≥ 20 000 qps on the dev box).
- Manual (owner): `dig`, `kdig +tls / +https / +quic`, an iPhone with a `.mobileconfig` later.

## Boundaries

- **Always:** reply from the arrival address; drop Do53 from public sources; bounded memory for every
  per-source table; no `unsafe`; ring-only TLS; never route anything but `/dns-query` on a public DoH
  listener.
- **Ask first:** new dependencies beyond the plan's table; changing admission rules; enabling 0-RTT;
  server cookies; IP-SAN certificates for verified DDR.
- **Never:** answer Do53 for public sources; log or echo ECS; expose the API/UI on a public listener.

## Success Criteria

1. Do53 UDP and TCP answer through `PolicyEngine` on IPv4 and IPv6; wildcard UDP replies come from the
   arrival address.
2. DoT, DoH (h2, http/1.1, h3) and DoQ answer the same query identically (modulo transport rules: id 0,
   padding, no TC).
3. Admission matrix: public Do53 never answered; public encrypted only with registered Client IDs; node
   hostname / apex do not count as strikes; bans after N strikes expire after the ban duration.
4. Limits: UDP truncation with TC, rate limits per source / Client ID, connection and stream caps,
   handshake and idle timeouts — each with a test; per-source tables stay within `max_tracked_sources`.
5. Certificate hot reload is picked up by new handshakes without a restart; open connections survive.
6. DDR `_dns.resolver.arpa` SVCB lists the local encrypted listeners with correct alpn/port/dohpath/hints.
7. Query events are emitted for loggable queries only; a full sink never blocks answering.
8. Coverage ≥ 80 % lines; fuzz targets 10 min clean; DoD gates green; `cargo deny check` green.

## Open Questions (owner)

1. **Dependencies** (versions checked 2026-10-25): `quinn` 0.11 (features `runtime-tokio`, `rustls-ring`,
   no aws-lc), `quinn-udp` 0.6 (pktinfo), `h3` 0.0.8 + `h3-quinn` 0.0.10 (HTTP/3 — pre-1.0, experimental),
   `hyper` 1 + `hyper-util` 0.1 (HTTP/2 + HTTP/1.1 server), `base64` (DoH GET), `tokio-rustls` (already in
   the tree). OK? Alternative for h3: ship DoH h3 later and start with h2/http1.1 only.
2. **HTTP/3 in v1** or later? (Mobile clients use h2 fine; h3 adds the most code and the least mature deps.)
3. **Wildcard binds:** keep `0.0.0.0`/`::` with pktinfo, or require concrete addresses per NIC (simpler,
   fully portable)? Recommendation: support both, document concrete addresses as preferred.
4. **Public Do53 handling:** drop silently (recommended, no amplification) or `REFUSED`?
5. **Runnable binary:** should a minimal `crates/dnscraft` binary (TOML bootstrap: listeners + resolver +
   filtering + policy, no UI) be part of this module's plan, so DNScraft can run next to AdGuard for
   testing before `control-api` exists? Recommendation: yes, as the last phase.
6. **Verified DDR** needs IP SANs, which Let's Encrypt does not issue for private addresses — accept
   opportunistic discovery only?
