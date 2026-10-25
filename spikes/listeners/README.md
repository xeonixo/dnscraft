# Spike: listeners N0

Throw-away crate (own `[workspace]`, own `Cargo.lock`) answering the four N0
risk questions on aarch64 Linux. **Not** a member of the main workspace.

```bash
cd spikes/listeners
cargo run
cargo tree -i aws-lc-rs    # must not match
cargo tree -i aws-lc-sys   # must not match
cargo tree -i openssl-sys  # must not match
```

Findings are logged in `tasks/progress.md` (N0 entry). Do not reuse this code
in `dnscraft-listeners` without rewriting.
