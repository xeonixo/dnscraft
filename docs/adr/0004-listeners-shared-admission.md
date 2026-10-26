# ADR-0004: Shared Admission and public Client-ID gating

- Status: Accepted
- Date: 2026-10-26
- Deciders: SPEC-listeners + listeners plan (owner-approved 2026-10-25); refined in N3 / N6 / shared-admission follow-up
- Scope: `crates/dnscraft-listeners` admission, TLS accept path, DoT / DoH / DoQ

## Context

Public listeners must not answer strangers: public Do53 is dropped; encrypted public listeners
require a registered Client ID (SNI for DoT/DoQ, path for DoH). Rate limits and temporary bans
must apply consistently across transports. Duplicating those rules per `serve_*` risked
diverging matrices and double-counting strikes.

## Decision

1. One shared **`Admission`** (source class, per-source / per-Client-ID token buckets, ban table)
   consulted by every transport ([SPEC-listeners.md](../../SPEC-listeners.md) admission section;
   task N3).
2. **Pre-handshake refusals** for banned public sources (close before TLS/QUIC work); SNI/path
   Client-ID gates apply for public×public; node hostname / apex reject without a ban strike
   (SPEC-listeners; commit `fcd74fe`, "listeners: shared admission, pre-handshake bans, SNI
   strikes, per-protocol ALPN", 2026-10-26).
3. Injectable `SourceClassifier` for tests; production uses the default private/public table.

## Consequences

- All `serve_*` params share an `Arc<Mutex<Admission>>` (or equivalent) so bans are global per
  process, not per listener socket.
- TLS cert resolution stays cert-presence oriented; Client-ID policy stays in admission / SNI
  helpers (`PolicyClientIds`, `inspect_public_sni` / path parsing).
- HTTP/3 (N12) and DDR (N10) must reuse the same admission rules when added.

## Alternatives considered

- **Per-transport admission tables:** rejected — SPEC requires one matrix; shared ban table is
  explicit in the listeners plan/todo.
- **Admit only after TLS handshake:** rejected for banned sources — would spend handshake CPU on
  known-bad peers (pre-handshake close recorded in `fcd74fe` / progress log). Deeper rationale
  for ordering strikes vs handshake edge cases: partly in SPEC-listeners; any further product
  rationale beyond the spec text is **rationale not recorded**.

## Links

- [SPEC-listeners.md](../../SPEC-listeners.md) — admission / public Client ID rules
- [tasks/todo-listeners.md](../../tasks/todo-listeners.md) — N3, N6, Checkpoint C
- Commits: N3 admission (see progress log 2026-10-25); `fcd74fe` (shared admission follow-up)
