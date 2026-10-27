# Todo: policy model v2 — GP1/GP2/GP3

> Contract & ordering: `plan-policy-model.md`. Gaps: `todo-spec-gaps.md` § Policy.
> One commit per task, Log entries in `progress.md`. Crate-scoped gates per task.

## Phase 0 — policy crate (config + snapshot + selection + pipeline)

- [ ] **P1** Config model: drop `ViewConfig.client_ids`; add `ViewConfig.nodes: Vec<NodeId>`
      (empty = all); add top-level `client_ids` registry and global `records` (default +
      `overrides`) to `PolicyConfig`. Serde + validation (default view valid on every node;
      registry ids valid; records exact-name, no wildcard, CNAME exclusivity).
- [ ] **P2** Snapshot build: remove the `client_ids` map; build the global record table with
      per-view overrides; store per-view `nodes`.
- [ ] **P3** Selection: remove the `ClientId` branch and `SelectionCause::ClientId`; filter
      views by `node_id` (skip views whose non-empty `nodes` lacks the node; default always
      valid).
- [ ] **P4** Engine: remove `is_client_id_registered`; add `node_id` to `RequestContext` +
      `build`; expose `registered_client_ids()` for the listeners' `PolicyClientIds`.
- [ ] **P5** Pipeline step 1: resolve from the global table + selected view's override.

## Phase 1 — listeners crate

- [ ] **L1** `PolicyClientIds` source over the policy registry (replace the
      `is_client_id_registered` path); keep `EmptyClientIds` default.
- [ ] **L2** Pass `node_id` into `RequestContext` from listener/bootstrap config.

## Phase 2 — control-api crate

- [ ] **A1** View config routes: drop `client_ids`, add `nodes`; `config_apply` diff for nodes.
- [ ] **A2** Records CRUD endpoints (global name space + per-view overrides) + `config_apply`
      diff; update `protected_list` if it reads view records.
- [ ] **A3** Client-ID registry CRUD (list/create/delete) for the `/doh-clients` screen.

## Phase 3 — assembler (binary)

- [ ] **AS** Binary config model for `client_ids`/`records`/`nodes` + `node_id` wiring into
      the policy engine and listeners.

## Checkpoints

- [ ] After Phase 0: `cargo test -p dnscraft-policy` green; selection table tests prove
      Client IDs never change selection; global-record override tests pass.
- [ ] After Phase 1: `cargo test -p dnscraft-listeners` green (minus 7 known macOS failures);
      admission matrix unchanged.
- [ ] After Phase 2: view/records/registry CRUD round-trips; config apply rolls back on error.
- [ ] After Phase 3: workspace gates green; smoke config boots with source-IP selection.
