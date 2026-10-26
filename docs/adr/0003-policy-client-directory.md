# ADR-0003: Policy does not depend on dnscraft-clients

- Status: Accepted
- Date: 2026-10-25
- Deciders: recorded at map / plan level (CAPABILITY-MAP; policy plan cross-module decisions)
- Scope: `crates/dnscraft-policy` ↔ `crates/dnscraft-clients` ↔ future `control-api`

## Context

Policy must answer local device names and PTRs using data that ultimately comes from UniFi /
manual client records (`dnscraft-clients`). Putting a Cargo dependency from `policy` onto
`clients` would pull UniFi HTTP/TLS types into the DNS hot-path crate and invert the build order
(`clients` is parallel to `resolver`/`filtering`/`tls`; `policy` sits above resolver+filtering).

## Decision

Define a **`ClientDirectory` trait in `dnscraft-policy`** with policy-owned types
(`addresses` / `reverse` / `local_domains`). `dnscraft-policy` must **not** take a Cargo
dependency on `dnscraft-clients`. The future `control-api` crate adapts clients'
lookup surface to `dyn ClientDirectory`. DoH/DoT **Client IDs** remain separate from UniFi
client records.

Recorded in [CAPABILITY-MAP.md](../../CAPABILITY-MAP.md) ("Decisions recorded at map level") and
[SPEC-policy.md](../../SPEC-policy.md) (objective / ClientDirectory integration). First
implementation: commit `58d5f52` (policy: P5 ClientDirectory names/PTR, 2026-10-25).

## Consequences

- Policy tests use `NoClients` or a stub directory; no UniFi mocks in the policy crate.
- `control-api` owns the adapter (not yet implemented; module pending).
- Changing the trait is a cross-module change (policy + future adapter).

## Alternatives considered

- **Direct `dnscraft-clients` dependency from policy:** rejected in CAPABILITY-MAP / SPEC-policy
  ("Never: depend on `dnscraft-clients` directly").
- **Trait living in a third shared crate:** not chosen; rationale for preferring policy-local
  trait over a shared crate is **rationale not recorded** beyond "policy-owned types" in the
  spec/plan.

## Links

- [CAPABILITY-MAP.md](../../CAPABILITY-MAP.md)
- [SPEC-policy.md](../../SPEC-policy.md) — ClientDirectory integration
- Commit `58d5f52` (policy: P5)
