# ADR-0002: Ring-only crypto backend

- Status: Accepted
- Date: 2026-10-25
- Deciders: project owner (cargo-deny in CI approved 2026-10-25; see
  [tasks/archive/progress-2026-10.md](../../tasks/archive/progress-2026-10.md))
- Scope: whole workspace (`deny.toml`, rustls / quinn / instant-acme / reqwest feature flags)

## Context

DNSSEC verification and TLS/QUIC both need a crypto provider. Upstream crates often default to
`aws-lc-rs` (rustls, instant-acme, reqwest) or OpenSSL. The project already chose `ring` for DNSSEC
digests and signature verification in [SPEC.md](../../SPEC.md) ("Cryptography") and
[ADR-0001](0001-recursion-engine.md). Mixing aws-lc or OpenSSL into the TLS path would create two
crypto stacks and violate the ring-only gates used in reviews (`cargo tree -i aws-lc-rs` /
`openssl-sys` empty).

## Decision

Use **rustls with the `ring` provider** everywhere (including quinn via `rustls-ring`, instant-acme
with `default-features = false` + `ring`, reqwest with an explicit rustls `ClientConfig` on ring).
Enforce the choice in [`deny.toml`](../../deny.toml): ban `aws-lc-rs`, `aws-lc-sys`, `openssl`,
and `openssl-sys`. CI runs `cargo deny check` (commit `ac07b6d`, "ci: cargo-deny", 2026-10-25).

## Consequences

- Every new TLS/QUIC dependency must disable aws-lc defaults and select ring features.
- `cargo deny check` and empty `cargo tree -i aws-lc-rs` / `openssl-sys` are part of Definition of Done.
- License clarification for `ring`'s OpenSSL-derived file lives in `deny.toml`.

## Alternatives considered

- **aws-lc-rs (rustls default):** rejected — conflicts with the DNSSEC `ring` choice and the SPEC-tls
  "Never: aws-lc" rule ([SPEC-tls.md](../../SPEC-tls.md)).
- **OpenSSL / native-tls:** rejected — same bans; not used for outbound HTTPS either.
- **Document-only policy without cargo-deny:** rejected — owner approved deny bans in CI
  (2026-10-25 archived progress log).

## Links

- [SPEC.md](../../SPEC.md) — Cryptography / TLS · QUIC rows
- [SPEC-tls.md](../../SPEC-tls.md) — rustls + ring, no aws-lc
- [`deny.toml`](../../deny.toml) — `[bans]`
- Commit `ac07b6d` (ci: cargo-deny)
