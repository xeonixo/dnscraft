# dnscraft-filtering

AdGuard-compatible domain filter engine for DNScraft.

This crate loads filter lists and custom rules, keeps them fresh on disk, and
answers match requests with a verdict (pass, allow, block, rewrite) and the
exact rule that caused it. It speaks no DNS on the wire and knows nothing about
clients, views, or listeners — `policy` turns verdicts into responses.

Formal requirements: [`SPEC-filtering.md`](../../SPEC-filtering.md).

## Status

Usable as a library for list parsing, matching, hot reload, and blocked-services
catalog. Consumed by `dnscraft-policy` (and by the listeners example / e2e tests).

| Area | State |
|------|--------|
| AdGuard DNS / hosts / glob / regex / IP rules | done |
| Guided rule builder (`build_rule` / `describe_rule`) | done |
| Domain + IP index, AdGuard priority, CNAME chain | done |
| Filter sets, custom rules, `$badfilter`, pause | done |
| Temporary allows, match counters | done |
| List store, conditional fetch, hot reload | done |
| Blocked-services catalog (runtime download) | done |
| Process RSS budget (reference set) | steady ≤ 80 MB; build peak see [progress log](../../tasks/archive/progress-2026-10.md) |

## Quick try

Parse the 19 reference lists (cached under `target/reference-lists/`; first run
downloads if the network is available):

```bash
cargo run --release -p dnscraft-filtering --example parse_lists
```

Optional: `-- --cache DIR`. Automated tests never run this example and never
touch the internet.

## Library usage

```rust
use std::sync::Arc;
use std::time::SystemTime;

use dnscraft_filtering::{
    Clock, DomainName, FilterConfig, FilterEngine, ListStore, SetId, SystemClock,
};

async fn example(config: FilterConfig, store: ListStore) -> Result<(), Box<dyn std::error::Error>> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let engine = FilterEngine::new(config, store, clock)?;

    let set = SetId::new("default")?;
    let name = DomainName::parse("ads.example")?;
    let now = SystemTime::now();
    let verdict = engine.match_name(&set, &name, 1, now)?;
    println!("{verdict:?}");
    Ok(())
}
```

- **Production:** `FilterEngine::new` / `open` — build from the list store (no
  network at startup), start the update scheduler.
- **Tests without I/O:** `FilterEngine::from_snapshot(snapshot)` — matching only;
  `apply_config` / `update_lists` return `filter_engine.no_store`.
- Matching takes an explicit `now` so clocks can be frozen in tests; `engine.now()`
  reads the injected clock.

Also: `parse_rule` / `parse_list` / `build_rule` for the editor, and
`match_chain` / `match_answer_ip` for CNAME uncloaking and answer IP rules.

## Rule syntax

Accepted list formats (detected per line):

| Format | Example | Meaning |
|--------|---------|---------|
| Adblock domain | `\|\|ads.example^` | block domain and subdomains |
| Exception | `@@\|\|cdn.example^` | allow (overrides equal/lower priority blocks) |
| Exact start/end | `\|ads.example^`, `ads.example\|` | as in AdGuard DNS |
| Plain domain | `ads.example` | block domain and subdomains |
| Hosts line | `0.0.0.0 ads.example` | **always block** (lists never redirect) |
| Wildcard | `\|\|ad*.example^` | glob (`*` spans dots) |
| Regex | `/^ads?[0-9]*\.example$/` | ASCII, size-capped; on canonical name |
| IP rule | `\|\|194.0.2.10^` | matches A/AAAA **answers**, not query names |
| Comment | `! …`, `# …` | ignored |

Supported modifiers: `$important`, `$badfilter`, `$dnstype=` (incl. `~`),
`$denyallow=`, `$dnsrewrite=` (rcode always; record forms only from custom rules).
`$client` / `$ctag` are ignored with a warning. Cosmetic / browser-only lines
(`##`, `$script`, paths, …) are skipped and counted, never fatal.

### Priority (highest first)

1. `$important` exception (and temporary allows)
2. `$important` block
3. exception
4. block

`$badfilter` disables the identical rule elsewhere in the same set.

## Errors

Every error exposes a stable `code()` string (`area.reason`) for APIs and i18n.
Human-readable text is for logs, not end users.

### Names and ids

| Error | Code |
|-------|------|
| `NameError::Empty` | `filter_name.empty` |
| `NameError::EmptyLabel` | `filter_name.empty_label` |
| `NameError::LabelTooLong` | `filter_name.label_too_long` |
| `NameError::TooLong` | `filter_name.too_long` |
| `NameError::InvalidChar` | `filter_name.invalid_char` |
| `NameError::NonAscii` | `filter_name.non_ascii` |
| `IdError::Empty` | `filter_id.empty` |
| `IdError::TooLong` | `filter_id.too_long` |
| `IdError::InvalidChar` | `filter_id.invalid_char` |

### Rules and builder

| Error | Code |
|-------|------|
| `RuleError::Empty` | `filter_rule.empty` |
| `RuleError::Comment` | `filter_rule.comment` |
| `RuleError::TooLong` | `filter_rule.too_long` |
| `RuleError::InvalidDomain` | `filter_rule.invalid_domain` |
| `RuleError::Unsupported` | `filter_rule.unsupported_syntax` |
| `RuleError::InvalidSyntax` | `filter_rule.invalid_syntax` |
| `RuleError::MultipleNames` | `filter_rule.multiple_names` |
| `RuleError::ReservedHost` | `filter_rule.reserved_host` |
| `RuleError::UnknownModifier` | `filter_rule.unknown_modifier` |
| `RuleError::DuplicateModifier` | `filter_rule.duplicate_modifier` |
| `RuleError::InvalidModifier` | `filter_rule.invalid_modifier` |
| `RuleError::ClientModifier` | `filter_rule.client_modifier` |
| `RuleError::RewriteFromList` | `filter_rule.rewrite_from_list` |
| `RuleError::InvalidIdna` | `filter_rule.invalid_idna` |
| `RuleError::InvalidRegex` | `filter_rule.invalid_regex` |
| `RuleError::RegexTooLarge` | `filter_rule.regex_too_large` |
| `BuildError::InvalidDomain` | `filter_build.invalid_domain` |
| `BuildError::PatternNotAllowed` | `filter_build.pattern_not_allowed` |
| `BuildError::RewriteOnAllow` | `filter_build.rewrite_on_allow` |
| `BuildError::EmptyNegatedTypes` | `filter_build.empty_negated_types` |
| `BuildError::InvalidTxt` | `filter_build.invalid_txt` |
| `BuildError::Unparsable` | `filter_build.unparsable` |

### Engine, sets, index

| Error | Code |
|-------|------|
| `FilterError::UnknownSet` | `filter_set.unknown` |
| `FilterError::BuildFailed` | `filter_engine.build_failed` |
| `FilterError::NoStore` | `filter_engine.no_store` |
| `SnapshotError::UnknownList` | `filter_set.unknown_list` |
| `SnapshotError::DuplicateSet` | `filter_set.duplicate_set` |
| `SnapshotError::DuplicateList` | `filter_set.duplicate_list` |
| `IndexError::UnknownSource` | `filter_index.unknown_source` |
| `IndexError::TooLarge` | `filter_index.too_large` |
| `IndexError::TooManySources` | `filter_index.too_many_sources` |

### Store, fetch, services

| Error | Code |
|-------|------|
| `StoreError::Io` | `filter_store.io` |
| `StoreError::TooLarge` | `filter_store.too_large` |
| `StoreError::InvalidSource` | `filter_store.invalid_source` |
| `StoreError::Serialize` | `filter_store.serialize` |
| `FetchError::Timeout` | `filter_fetch.timeout` |
| `FetchError::Connect` | `filter_fetch.connect` |
| `FetchError::HttpStatus` | `filter_fetch.http_status` |
| `FetchError::TooLarge` | `filter_fetch.too_large` |
| `FetchError::RedirectRefused` | `filter_fetch.redirect_refused` |
| `FetchError::TooManyRedirects` | `filter_fetch.too_many_redirects` |
| `FetchError::NotText` | `filter_fetch.not_text` |
| `FetchError::Tls` | `filter_fetch.tls` |
| `FetchError::Io` | `filter_fetch.io` |
| `ServiceError::Malformed` | `filter_services.malformed` |
| `ServiceError::Io` | `filter_services.io` |

`FilterError::Name` / `Id` / `Rule` delegate to the wrapped error's code.

## Limits and constants

| Limit | Value | Purpose | Source |
|-------|-------|---------|--------|
| Max rule line | 4 KiB | Caps pathological list lines | `MAX_LINE_LEN` in `src/parser.rs` |
| Skip samples kept | 60 (5 per reason) | Skip report for operators | `SKIP_SAMPLE_LIMIT` / `SKIP_SAMPLES_PER_REASON` |
| Regex program size | 8 KiB | Reject oversized `/regex/` | `REGEX_SIZE_LIMIT` in `src/pattern.rs` |
| Regex DFA size | 64 KiB | Cap compiled DFA | `REGEX_DFA_SIZE_LIMIT` |
| Regex rules per index | 500 | Bounds per-query pattern scan for hostile lists | `MAX_REGEX_RULES` in `src/index.rs` |
| Glob rules per index | 5 000 | Same, for wildcards | `MAX_GLOB_RULES` |
| Regex size budget per index | 2 MiB (estimated) | Caps total compiled regex memory | `REGEX_BUDGET_BYTES` |
| Regex error message | 200 bytes | Truncate engine text | `REGEX_MESSAGE_MAX` |
| List body size | 64 MiB | Download / store cap | `DEFAULT_MAX_BODY_BYTES` in `src/store.rs` |
| HTTPS redirects | 5 | Cap redirect chains; HTTPS→HTTP refused | `MAX_REDIRECTS` in `src/fetch.rs` |
| Fetch timeout | 30 s | Per download | `FetcherConfig` default |
| Update interval | 24 h ±10 % jitter | Scheduler default | `DEFAULT_UPDATE_INTERVAL` in `src/set.rs` |
| Domain entry overhead | 11 B | Index flags/source/text offset | `ENTRY_OVERHEAD_BYTES` in `src/index.rs` |
| TXT rewrite length | 255 | One DNS character-string | `MAX_TXT_LEN` in `src/builder.rs` |
| Source ids per index | 65 535 | `u16` source field | `IndexError::TooManySources` |

## Budgets (reference set ≈ 2.25 M rules)

| Metric | Target | Measured (see progress.md) |
|--------|--------|----------------------------|
| Match p99 (warm) | < 10 µs | hit/miss/IP meet; deep-10 labels ≈ 19 µs miss |
| Reload | < 10 s, never blocks matches | build ≈ 1.1–1.6 s; hot-reload concurrency tested |
| Memory | ≤ 80 MB filtering / ≤ 150 MB process RSS | steady ≈ 58.5 MB RSS; build peak higher (Checkpoint B) |

## Design notes

- List bodies stay on disk; rule text is resolved on demand (`RuleTextSource`).
- Reload builds a new snapshot on a blocking thread and swaps an `Arc` atomically.
- GPL HostlistsRegistry services data is downloaded at runtime and never committed.
- Fuzz target: `rule_parse` in the workspace `fuzz/` crate (CI runs a short job).

## Tests

```bash
cargo test -p dnscraft-filtering
cargo llvm-cov -p dnscraft-filtering
cargo +nightly fuzz run rule_parse -- -max_total_time=60
cargo bench -p dnscraft-filtering --features testgen --bench matching
```
