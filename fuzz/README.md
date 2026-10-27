# Fuzzing

Coverage-guided fuzz targets for the wire decoders in
[`dnscraft-proto`](../crates/dnscraft-proto/README.md), the filter-list
parser in `dnscraft-filtering`, the listener core / DoH request parser in
`dnscraft-listeners`, the MCP transport / tool-input validators in
`dnscraft-mcp`, and the cluster join-token / log-batch / config validators in
`dnscraft-cluster`, built with
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and libFuzzer. The fuzz
crate (`dnscraft-proto-fuzz`) is separate from the workspace and has its own
`Cargo.lock`.

## Targets

Defined in `fuzz/Cargo.toml`, sources in `fuzz/fuzz_targets/`:

| Target | Source | What it checks |
|--------|--------|----------------|
| `name_decode` | `name_decode.rs` | `Name::decode` at offset 0 and at an offset taken from the input; a decoded name re-encodes and decodes to itself |
| `message_decode` | `message_decode.rs` | `Message::decode` never panics on arbitrary bytes |
| `message_roundtrip` | `message_roundtrip.rs` | Encode, decode and encode again gives identical bytes; the encoding with a 512-octet limit decodes again |
| `rule_parse` | `rule_parse.rs` | `parse_list` (both sources) and `parse_rule` never panic; every parsed rule has source text; a described rule builds with `build_rule` and parses again |
| `listeners_handle_wire` | `listeners_handle_wire.rs` | `handle_wire` never panics or hangs on arbitrary wire bytes with a `QueryMeta` derived from the input (async, on a current-thread tokio runtime) |
| `listeners_doh_request` | `listeners_doh_request.rs` | `parse_doh_path`, `extract_wire` and `content_type_of` never panic on arbitrary method/path/query/headers/body |
| `mcp_request` | `mcp_request.rs` | `validate_mcp_request` never panics on arbitrary method/headers/body; method, declared and buffered body size, `Origin` and `MCP-Protocol-Version` checks |
| `mcp_tool_input` | `mcp_tool_input.rs` | `parse_mcp_tool_input` never panics when arbitrary JSON is fed to all 13 tool parsers (`serde_json` + `deny_unknown_fields` + per-tool value checks) |
| `cluster_join_token` | `cluster_join_token.rs` | `EnrollRequest` deserializes from arbitrary JSON without panicking; `check_protocol` accepts only the current version and every rejection has a well-formed `cluster.*` code |
| `cluster_log_batch` | `cluster_log_batch.rs` | `LogBatch::validate` over arbitrary JSON (matching and mismatching `node_id`) never panics; sequence/count and protocol checks reject with `cluster.*` codes |
| `cluster_config` | `cluster_config.rs` | `ClusterConfig::from_toml` (parse + role/bind/URL validation) never panics on arbitrary TOML; accepted configs validate again |

The `mcp_request` input is byte 0 (method selector), then an HTTP-like header
block terminated by a blank line, then the body. Invalid header lines are
skipped. The pure validator never copies the body; a size above the configured
cap is rejected by length. `Mcp-Method` / `Mcp-Name` versus the JSON-RPC body
is enforced by rmcp's tower layer, not by `transport.rs`, so it is not part of
that target. The `mcp_tool_input` input is raw JSON; each unit is passed to
every tool name.

Seeds (`fuzz/corpus/<target>/`) are named by purpose: valid JSON-RPC and tool
inputs, malformed JSON, method/header mismatches, unsupported and duplicate
protocol versions, disallowed origins, over-cap bodies, unknown fields and
hostile domains (`example.com$dnsrewrite=…`, `||ads.example^`, wildcards,
control characters). The cluster targets seed a valid and a malformed
enrollment request, a contiguous and a ragged log batch, and standalone,
master, sub-node, public-bind and role-mismatch configs.

## Prerequisites

- A nightly Rust toolchain: `rustup toolchain install nightly`. The root
  `rust-toolchain.toml` pins stable, so select nightly explicitly (see below).
- cargo-fuzz: `cargo install cargo-fuzz`.
- A C++ compiler (for example `g++` or `clang++`). libFuzzer is built from C++
  sources through `libfuzzer-sys`.

## Running one target

From the `fuzz` directory, for 60 seconds:

```bash
cd fuzz
cargo +nightly fuzz run name_decode --target x86_64-unknown-linux-gnu -- -max_total_time=60
```

Replace `name_decode` with `message_decode`, `message_roundtrip`, `rule_parse`,
`listeners_handle_wire`, `listeners_doh_request`, `mcp_request`,
`mcp_tool_input`, `cluster_join_token`, `cluster_log_batch` or
`cluster_config`. Use the `gnu` target: the
`musl` default enables static linking, which does not work with the sanitizers
that cargo-fuzz uses.

## Corpora and artifacts

- Named seed inputs live in `fuzz/corpus/<target>/` and are committed. libFuzzer
  adds new interesting inputs as hex-named files in the same directory; those
  generated units are git-ignored (see `.gitignore`).
- Crashes and timeouts are written to `fuzz/artifacts/<target>/`. This
  directory is git-ignored. Reproduce a crash with
  `cargo +nightly fuzz run <target> <artifact-file>`.
- `fuzz/target/` (build output) and `fuzz/coverage/` are git-ignored.

## CI

The `fuzz` job in `.github/workflows/ci.yml` runs on every push and pull
request, plus a Monday schedule for a longer run:

- Matrix over `name_decode`, `message_decode`, `message_roundtrip`, `rule_parse`,
  `listeners_handle_wire`, `listeners_doh_request`, `mcp_request`,
  `mcp_tool_input`, `cluster_join_token`, `cluster_log_batch` and
  `cluster_config`, with `fail-fast: false`.
- `RUSTUP_TOOLCHAIN=nightly` overrides the stable pin for this job only.
- `cargo-fuzz` via `taiki-e/install-action`.
- Duration: **60 s** on push/PR (smoke); **600 s** on the weekly schedule.
- Concurrency cancels superseded PR runs, but not pushes to `main`.

The separate `coverage` job fails if line coverage of `dnscraft-proto`,
`dnscraft-resolver`, `dnscraft-filtering` or `dnscraft-policy` drops under
**80 %** (`--fail-under-lines 80`).
