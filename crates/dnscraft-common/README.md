# dnscraft-common

Shared building blocks used across DNScraft crates. No DNS protocol logic and
no I/O beyond reading secret files from disk.

## Modules

| Module | Purpose |
|--------|---------|
| `clock` | Injectable [`Clock`](src/clock.rs) + `SystemClock` / `ManualClock` (ADR-0005) |
| `secret` | `Secret` wrapper (redacted `Debug`, zeroize-on-drop) and env/`*_FILE` loaders |
| `config` | Small shared config helpers |
| `duration` | Human duration parsing used in TOML (`15m`, `24h`, …) |
| `hash` | Hash helpers (e.g. SHA-256 digests for redaction / fingerprints) |
| `net` | Address classification helpers (loopback / private / ULA) |

## Design notes

- **Clock injection** keeps retention, rate limits, ACME timers, and cluster
  heartbeats testable without wall-clock sleeps. Prefer `ManualClock` in tests.
- **Secrets** never appear in `Debug` or serde output as plaintext
  (`"redacted"`). Prefer `DNSCRAFT_*_FILE` over putting values in the process
  environment.
- Crypto elsewhere stays **ring-only** (ADR-0002); this crate only uses `ring`
  where a digest helper is needed.

## Tests

```bash
cargo test -p dnscraft-common --locked
cargo clippy -p dnscraft-common --all-targets --locked -- -D warnings
```
