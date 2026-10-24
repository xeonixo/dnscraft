# DNScraft

A lightweight, self-hosted, recursive DNS resolver for home networks — written in Rust.

> **Status:** specification phase. No code yet.

- Recursive resolution from the root servers with DNSSEC validation — no upstream provider
- AdGuard-compatible filter lists, custom rules, "why was this blocked?"
- Split-horizon answers per source subnet, forward zones for private networks
- Do53, DoT, DoH (HTTP/2 + HTTP/3), DoQ — usable from anywhere via per-device Client IDs
- Certificates via ACME DNS-01 (Cloudflare)
- UniFi integration for device names in the query log
- Multi-node (master + sub-nodes), Docker-first, multiple NICs
- Web UI with OIDC single sign-on, fully internationalized

## Documentation

- [CAPABILITY-MAP.md](CAPABILITY-MAP.md) — modules, dependencies, build order
- [SPEC.md](SPEC.md) — project-wide specification
- [SPEC-resolver.md](SPEC-resolver.md) — resolver module

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
