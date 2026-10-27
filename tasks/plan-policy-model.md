# Plan: policy model v2 — GP1/GP2/GP3 (source-IP selection, global records, node validity)

> Source: `tasks/todo-spec-gaps.md` § Policy (GP1–GP3). Owner delegated the decisions
> 2026-10-27. The spec is authoritative (`SPEC-policy.md` reviews 13 & 14). One commit per
> task, Log entries in `progress.md`. Multi-crate: policy → listeners → control-api → assembler.

## Decisions (ratified 2026-10-27)

- **GP1 — selection is source-IP only.** Remove `ViewConfig.client_ids`, the
  `SelectionCause::ClientId` branch, the `client_ids` snapshot map, and
  `PolicyEngine::is_client_id_registered`. The Client-ID registry becomes a flat
  top-level `client_ids` list in `PolicyConfig` — a **registry** (for listener admission),
  not a selection key. Listeners read it through the existing `PolicyClientIds` trait.
  `RequestContext.client_id` stays (auth/logging facet only).
- **GP2 — local records are a global name space.** Move records off `ViewConfig` into a
  top-level `records` table in `PolicyConfig` keyed by owner name; each entry is a default
  (ttl + rdata) plus optional `overrides` keyed by `ViewId`. Pipeline step 1 looks up the
  global table and applies the selected view's override, else the default.
- **GP3 — node validity.** `ViewConfig` gains `nodes: Vec<NodeId>` (empty = every node).
  `RequestContext` gains `node_id: Option<NodeId>`. Selection skips views whose `nodes` is
  non-empty and does not contain the node's id; the default view is always valid.

## Current state (verified)

- `ViewConfig` holds `client_ids` + per-view `records` (`config.rs:184-198`).
- `select.rs` order is ClientId → subnet → default; `SelectionCause::ClientId` exists.
- `snapshot.rs` builds `client_ids: HashMap<ClientId, ViewIdx>` and per-view `records`.
- `engine.rs:100` exposes `is_client_id_registered`; listeners consume it via `PolicyClientIds`.
- `RequestContext` has no `node_id`; `PolicyConfig` has no global `records`.

## Sub-decisions

- **Client-ID registry shape**: flat `Vec<ClientId>` (no label in v1; the `/doh-clients`
  screen derives the DoH/DoT endpoints from the id).
- **NodeId type**: a small validated `NodeId` newtype in `dnscraft-policy::ids` (mirroring
  `ClientId`), or reuse a plain `Arc<str>`; recommend the newtype for validation parity.

## Scope (multi-crate)

1. `dnscraft-policy` — config model, snapshot, selection, engine, pipeline step 1, decision,
   error codes, ids.
2. `dnscraft-listeners` — `PolicyClientIds` source over the registry (replacing the
   policy-engine-derived source); pass `node_id` into `RequestContext`.
3. `dnscraft-api` — view config routes (drop `client_ids`, add `nodes`); new records CRUD
   (global name space + overrides); `config_apply` diff for records/registry/nodes;
   `protected_list`.
4. `dnscraft` (assembler) — binary config model + `node_id` wiring.

## Risks

- **Breaking config schema** (stored JSON + TOML): records and the Client-ID registry move;
  existing configs with `views[].client_ids` / `views[].records` need a migration or a
  documented breaking change. Prefer a versioned bootstrap re-seed (D4 already seeds once).
- **Listeners must not regress admission** while the registry source changes: the
  `PolicyClientIds` abstraction already isolates this; keep `EmptyClientIds` as the no-config
  default (public encrypted listeners then reject every Client ID).

## Blocked on

- The in-flight policy agent (`GP4/GP5/GP6`) also edits `dnscraft-policy`; start GP1–GP3
  only after it lands, or in a separate worktree.
