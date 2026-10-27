# Todo: TLS & control-api spec gaps (spec everything + implement)

> Contract & ordering: `tasks/plan-tls-api-gaps.md`. Parallel by crate.
> Tick items only when the owning crate's focused check passes.

## Phase 1 — TLS crate (Agent T)

- [x] T1 `status.rs`/`pem_util.rs`: cert detail (issuer/subject/not_before/serial/sig-alg/key-usage/chain), ARI window, bounded history, next/last run, store health, `dyndns_stale`, `revoked`, `CertSource` (Q2, Q4, Q8, Q15, Q18, Q19, Q9)
- [x] T2 `config.rs`: manual cert, trust pin, ACME account (EAB/ToS), `dns_provider`, IPv6 identifier, interface selection, record inventory, notifications (Q1, Q14, Q5, Q3, Q20, Q17, Q22, Q21, Q26)
- [x] T3 `acme.rs`/`issue.rs`/`renew.rs`: account mgmt, order/progress, rate-limit retry-after, revoke, key rotation, preflight, ARI internals (Q5, Q6, Q7, Q9, Q10, Q11, Q4)
- [x] T4 `dyndns.rs`/`cloudflare.rs`/`propagation.rs`: generic provider + manual DNS-01, multi-zone, IPv6 identifier, record inventory, IP discovery, audit trail (Q3, Q20, Q17, Q21, Q22, Q25)
- [x] T5 `store.rs`: manual cert persistence, history state, store health (Q1, Q8, Q15)
- [x] T6 `engine.rs` + `error.rs`: new `TlsEngine` methods + `tls.*` codes wired (D/E)
- [x] T7 `SPEC-tls.md`: resolve § Open Questions → full sections + Decisions

## Phase 2 — API crate (Agent A)

- [x] A1 `api/tls_routes.rs`: 12 new TLS endpoints (F)
- [x] A2 `tls.rs`: full typed status DTO + `TlsMode::Manual` (G)
- [x] A3 `error.rs`: forward `tls.*`, add `control_api.*` codes
- [x] A4 `config_apply.rs`: per-sub-block TLS apply/rollback diff (control-api Q6)
- [x] A5 notifications: webhook dispatch on expiry/dyndns failure (Q26)
- [x] A6 `SPEC-control-api.md`: endpoint table + DTO schema + resolve § Open Questions

## Phase 3 — Listeners crate (Agent L)

- [x] L1 listener `tls_policy` (min version, ciphersuites, ALPN) + validation + `listeners.tls.policy` (Q23)
- [x] L2 `SPEC-listeners.md`: § TLS protocol/cipher policy

## Checkpoints

- [x] `cargo clippy -D warnings` clean (workspace-wide, 2026-10-27)
- [x] `cargo test --workspace` green — except 7 pre-existing macOS-only `dnscraft-listeners` failures (bind `127.0.0.2` → AddrNotAvailable; errno 115-vs-36); reproduced on pristine HEAD, unrelated to this work
- [x] `cargo tree -i aws-lc-rs` empty (no aws-lc) — also `openssl-sys` empty
- [x] `cargo deny check` green (advisories/bans/licenses/sources ok)
- [~] `cargo fmt` — `dnscraft-tls`/`-api`/`-listeners` clean; 2 pre-existing diffs on HEAD remain in `crates/dnscraft-clients/src/clock.rs` and `crates/dnscraft-policy/src/synth.rs` (edition-2024 rustfmt drift, not touched by this task)
- [ ] No real LE/Cloudflare/OIDC contacted in tests

---

## Spec-gap additions (independent review 2026-10-27)

> Full detail, severity and evidence: [`todo-spec-gaps.md`](todo-spec-gaps.md) § TLS (`GT1`–`GT12`).

- [ ] **GT1** manual DNS-01 (`manual`) can never complete (🟠)
- [ ] **GT2** `next_attempt_at` never populated; stale `order_status` on early errors (🟠)
- [ ] **GT3** `apply_config` re-uploads `config.manual`, reverting API uploads + clearing `revoked` (🟠)
- [ ] **GT4–GT12** `deactivated`, key rollover surface, `tls.dns.provider.zone`, stale rate-limit status, preflight when ACME off, ACME revoke when off, DynDNS echo handling, audit drop on partial write, metrics (🟡)
