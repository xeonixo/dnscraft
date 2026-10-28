# W10 rust-embed (control-api `web-ui` feature)

## Files

- `crates/dnscraft-api/src/web_ui.rs` — `rust-embed` asset handler: security headers, cache policy, SPA `index.html` fallback, path traversal guard, CSP from `csp-script-hashes.json` when present.
- `crates/dnscraft-api/embed-web-ui/index.html` — placeholder so `--features web-ui` compiles without copying `web/build`.
- `crates/dnscraft-api/src/api/router.rs` — outer fallback serves the SPA for non-`/api`/`/mcp` paths when `web-ui` is enabled; API/MCP misses stay JSON 404.
- `crates/dnscraft-api/src/lib.rs` — `mod web_ui` behind the feature.
- `crates/dnscraft-api/Cargo.toml` — optional `rust-embed` + `web-ui` feature.

## Release embed

Owner human review is the next gate; release still requires copying `web/build` into `embed-web-ui/`.

1. `cd web && pnpm build` (also writes `build/csp-script-hashes.json`).
2. Replace `crates/dnscraft-api/embed-web-ui/` contents with `web/build/*` (keep the hashes file).
3. Build control-api with `--features web-ui`.

## Routing

- `GET/HEAD` under `/api/…`, `/mcp/…` — JSON envelopes (unknown paths stay `control_api.not_found`).
- `/healthz`, `/readyz` — unchanged explicit routes.
- Any other `GET/HEAD` — embedded asset or SPA `index.html`.
- `..` / `\` rejected with 400.
