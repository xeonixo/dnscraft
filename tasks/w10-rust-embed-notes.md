# W10 rust-embed draft (uncommitted — owner review)

## Files touched (draft, leave unstaged)

- `crates/dnscraft-api/src/web_ui.rs` — `rust-embed` asset handler with security headers, cache policy, SPA `index.html` fallback, path traversal guard.
- `crates/dnscraft-api/embed-web-ui/index.html` — placeholder so `web-ui` feature compiles without `web/build`.
- `crates/dnscraft-api/src/api/router.rs` — `web-ui` feature replaces the outer fallback with static serving for non-API paths.
- `crates/dnscraft-api/src/lib.rs` — `mod web_ui` behind the same feature.
- `crates/dnscraft-api/Cargo.toml` — optional `rust-embed` dependency and `web-ui` feature (not committed by agent if lockfile would churn).

## Enable locally

1. Build the SPA: `cd web && pnpm build`.
2. Copy `web/build/*` into `crates/dnscraft-api/embed-web-ui/` (or point `#[folder = "..."]` at `../../web/build` once paths are stable).
3. Add to `crates/dnscraft-api/Cargo.toml`:

   ```toml
   [features]
   web-ui = ["dep:rust-embed"]

   [dependencies]
   rust-embed = { version = "8.7.0", optional = true }
   ```

4. Build control-api with `--features web-ui`.

## Routing intent

- `GET/HEAD` under `/api/v1`, `/mcp/v1`, `/healthz`, `/readyz` — unchanged (unknown API paths stay JSON 404).
- Any other `GET/HEAD` — embedded asset or SPA fallback.
- No directory traversal (`..`, `\` rejected).
