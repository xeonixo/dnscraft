# Progress log

Resume point for interrupted sessions. Newest entry first.
Task details: [todo.md](todo.md) · Plan: [plan.md](plan.md)

Earlier modules: [archive/](archive/) (resolver plan + tasks). Briefs for working with Cursor: [cursor-next.md](cursor-next.md) (filtering briefs: [archive/cursor-filtering.md](archive/cursor-filtering.md)).

**Workflow:** each task is implemented by a Haiku/Sonnet subagent, reviewed by the lead
(diff, `fmt`, `clippy`, tests), ticked off in `todo.md`, logged here, and committed.

## Current state

- Module `resolver` COMPLETE (Checkpoint E approved 2026-10-25).
- Module `filtering`: **C1 done** (engine polish, README, coverage, fuzz, real-list acceptance). **Checkpoint D ready for Claude/owner review** — implementer does **not** tick Checkpoint D. Checkpoint B owner: RAM may grow — not blocking. Deep-name p99 miss left for Checkpoint D if revisited.
- Module `clients`: **SPEC-clients.md decisions locked** (defaults + full IPv6 via classic `stat/sta` + dynamic local domain from UniFi DHCP). Formal “approved” for P1 still open.
- Module `tls`: **SPEC-tls.md decisions locked**. Formal “approved” for P1 still open.
- Module `policy`: **SPEC-policy.md decisions locked** (sensible defaults). Formal “approved” for P1 still open for clients/tls/policy.
- Blockers: none for coding; next: formal approve → P1 plans, and/or T1 tech debt; filtering Checkpoint D when ready.

## Log

- 2026-10-25 — SPEC-policy.md decisions (Cursor): AAAA suppress only on AAAA qtype; rebind-empty → NODATA; exact view names only; schedules/SafeSearch config-first; resolver forward allow-list OK; pause global+per-profile; PTR RFC1918+ULA+loopback(+optional); RFC 6724 documented not gated; DDR owned by listeners; canaries cite docs at implement time.

- 2026-10-25 — Spec draft SPEC-policy.md (Cursor, S3): View/profile selection (Client ID > LPM > default); pipeline local→bypass→SafeSearch→filter→resolve→chain/IP→rebind→AAAA; DecisionRecord; AD/EDE 15/4; ClientDirectory trait; pause; budgets. CAPABILITY-MAP draft link. **STOP for owner Open Questions.**

- 2026-10-25 — SPEC-tls.md owner decisions (Cursor): SANs = `dns.` + `*.dns.` only; ECDSA P-256/P-384 (no RSA); DynDNS stays in `tls`; per-node DynDNS hostname; master renews and pushes cert to subs; ACME email required in UI; propagation 2m/5s; always apex+wildcard; one cert for all listeners.

- 2026-10-25 — Spec draft SPEC-tls.md (Cursor, S2): instant-acme (ring features, no aws-lc; ARI), Cloudflare Zone:DNS:Edit + DNS-01 TXT + DynDNS (cdn-cgi/trace, DNS-only), LE staging/Pebble, CertResolver hot reload, SNI Client-ID helper + registry trait, master-only renew (cluster sync later). CAPABILITY-MAP draft link. **STOP for owner Open Questions.**

- 2026-10-25 — SPEC-clients.md local domain (Cursor): Owner wants domain “as present” — prefer UniFi per-VLAN DHCP `domainName`, config `home.arpa` only as fallback; `local_domain_mode` + optional per-manual `domain` override. FQDN indexes / `local_domains()` for policy.

- 2026-10-25 — SPEC-clients.md owner decisions (Cursor): Accepted proposed defaults (`home.arpa`, 60 s poll, 7 d offline retain, VLAN `name (id)`, site auto-pick, pin/CA bootstrap, `DNSCRAFT_UNIFI_API_KEY`, disk last-good, 429 backoff). Explicit ask: **complete IPv6** → classic client feed on by default (`classic_clients = true`), defensive parse, no link-local index. Open Questions cleared; formal approve still pending for P1.

- 2026-10-25 — Spec draft SPEC-clients.md (Cursor, S1): UniFi Network Integration API research (base `/proxy/network/integration/v1`, `X-API-KEY`, paginated clients/networks; gaps: single `ipAddress`, no client `networkId`, connected-only). Design: Arc lookup `by_ip`/`by_name`/`reverse`, manual > longest CIDR > UniFi, VLAN via network `hostIpAddress`/`prefixLength`, last-good + stale on sync failure, TLS pin/CA (never accept-any by default), `clients.*` codes, mock-server testing. CAPABILITY-MAP link set to draft. **STOP for owner Open Questions.**

- 2026-10-25 — Filtering C1 done (Cursor): Engine API — SPEC primary `FilterEngine::new(config, store, clock)` (+ `open` alias); matching-only `from_snapshot` (documented test helper); `now()` uses injected clock. Deduped `TYPE_NAMES` → `modifiers::TYPE_NAMES` + `type_name_for`. README at `crates/dnscraft-filtering/README.md` (syntax, priority, every `code()`, limits, `parse_lists`). Coverage **91.13 %** lines (`cargo llvm-cov -p dnscraft-filtering`). Fuzz `rule_parse` 10 min clean after fix: **312 106** execs / 601 s, no crash (first run found BOM+IPv4 → domain via IDNA; fixed: strip per-line BOM in parser; builder rejects IP-literal domains; seeds `bom_ip_literal` / `bare_ipv4`). Real lists (cached): parse **2.241363 M** rules / **1.870509 M** unique domains / **18 978** skipped (cosmetic/browser_only dominate; no DNS-relevant supported rule mis-skipped); AdGuard DNS filter **72** IP rules; parse wall **1.13 s** (tool total 3.10 s). Index build (`real_lists_snapshot` release): **1.63 s**, steady VmRSS **58.1 MB**, Index **52.5 MB** (11 B/entry), build peak **ΔVmHWM ≈ 113.3 MB** (M4a cite; owner relaxed at Checkpoint B). Reload never blocks matches (`tests/reload.rs`).

  **SPEC-filtering.md success criteria (evidence):**
  1. ✓ 19 lists parse; skip report by reason (parse_lists + Checkpoint A/C1) — no claimed DNS rule in skips
  2. ✓ Priority / CNAME / modifiers — `tests/matching.rs`, `tests/engine.rs`, `tests/modifiers.rs`
  3. ✓ Reason text+source; builder↔parser — matching + builder tests; IP/`describe` None
  4. ✓ Budgets — match hit/miss/IP p99 < 10 µs (M4b); deep-10 miss ~19 µs (noted); reload < 10 s; steady ≤ 80 MB; peak miss (Checkpoint B)
  5. ✓ List updates — L2/L3 tests (304, size, timeout, HTTPS-downgrade, last-good + codes); reload concurrency
  6. ✓ Blocked services — L4 `tests/services.rs`
  7. ✓ Temporary allows — `tests/engine.rs` (manual clock, important rank)
  8. ✓ Coverage ≥ 80 % (91.13 %); fuzz 10 min clean (312 106 execs)

  **Checkpoint D:** hand back for Claude/owner — do not mark.

- 2026-10-25 — Filtering L4 done (Cursor): Blocked-services catalog from HostlistsRegistry URLs (runtime download only; GPL data never committed/embedded). `ServiceCatalog` parses `services.json` + optional `services_i18n.json` (lenient: unknown fields ignored, bad entries skipped+counted); `translated_name` / `translated_group` with locale → `en` → default fallback. Cache under `ListStore::services_dir()` via `Fetcher::fetch_and_store_services` (conditional GET / size cap / last-good). `FilterSetConfig.services` → rules join set as `RuleSource::Service{id}`; unknown ids on `Snapshot::unknown_services` (not fatal). `FilterEngine::services()` / `update_services` / `services_last_error`; malformed update keeps previous + `filter_services.malformed`. Codes: `filter_services.malformed`, `filter_services.io`. tests/services.rs: fixture load+toggle verdicts, i18n fallback, malformed keep-previous, offline cache, unavailable without catalog. Checkpoint C: criterion 5 (L2/L3 + reload concurrency) + criterion 6 (L4) — ticked. Left for C1: SPEC `new(config,store,clock)` naming polish, README, coverage ≥ 80 %, fuzz 10 min, real-list acceptance evidence for all 8 criteria.

- 2026-10-25 — Filtering L3 done (Cursor): `FilterEngine` holds `RwLock<Arc<Snapshot>>` (clone under short lock); `open` / `open_without_scheduler` build from `ListStore` cache with no network; `apply_config` + `update_lists(ListSelection)` rebuild via `spawn_blocking`, atomic swap, coalesce (oneshot waiters). `StoreListBodies` implements `ListBodies` (body per list, never all at once) + seek/`pread`-style `rule_at` with 64-line LRU; custom text stays inline in `SnapshotTexts`. Scheduler (`src/scheduler.rs`): FilterConfig interval (default 24 h) ±10 % jitter, `ManualClock::tick_notify` + `wait_until` (tests do not sleep wall time), `update_now`. `ReloadReport` / `list_status` with last attempt/success, error code, rules parsed/skipped, unique contribution. New codes: `filter_engine.build_failed`, `filter_engine.no_store`. tests/reload.rs: concurrent match during rebuild (< 1 ms Arc clone, never half-built), startup offline, failed fetch keeps last good, schedule with ManualClock, unique contribution fixture, on-disk rule text. Deferred to L4/C1: `services()` catalog wiring, SPEC `new(config,store,clock)` naming polish vs matching-only `new(snapshot)`, README.

- 2026-10-25 — Checkpoint B owner: RAM budget relaxed (“RAM darf ruhig größer werden”); Cursor continues with L3. Deep-name p99 and M4a peak left as-is for now (not blocking). Checkpoint B checkboxes left for owner/Claude to tick formally if desired.

- 2026-10-25 — Filtering M4b done (Cursor): criterion `benches/matching.rs` + feature-gated `src/testgen.rs` (`--features testgen`, ~2.249 M rules across lists: 1.87 M subdomain + 85 k exact + 500 globs + 30 regexes + 100 IP + 15 % cross-list dups). Measured release (`--sample-size 50`), raw p50/p99 n=1000 warm:

  | Path | p50 | p99 | vs < 10 µs |
  |---|---|---|---|
  | match_hit | 3.875 µs | **4.000 µs** | meet |
  | match_miss | 2.916 µs | 2.959 µs | meet |
  | match_deep_10 (10 labels) | 16.249 µs | **18.916 µs** | **miss** |
  | match_chain_3 (3 lookups) | 22.249 µs | 24.624 µs | n/a (3×; ~8 µs/lookup) |
  | match_ip | 42 ns | 84 ns | meet |

  Criterion estimates: hit 3.87 µs, miss 2.88 µs, deep 16.3 µs, chain 22.3 µs, ip 22.2 ns. **Build** `reference_set` **1.11 s** (one-shot wall incl. generation 1.16 s) — **< 10 s meet**. Index::memory after synthetic build: 1.955 M entries, names 34.3 MB + overhead 20.5 MB. **Memory (M4a real lists, cite):** steady VmRSS **~58.5 MB** / Index::memory **52.5 MB** (≤ 80 MB meet); build peak **ΔVmHWM ~112 MB** (target ≤ +60 MB — still miss from M4a). Deep-name miss: suffix walk ≈ one binary search per label. Fallback options for Checkpoint B: (1) accept deep p99 ~20 µs as rare, (2) hash-of-suffix / bloom prefilter, (3) cap label walk. Owner reviews Checkpoint B — **not marked here**.

- 2026-10-25 — Filtering M3 done (Cursor): `Snapshot::match_chain` (CNAME uncloaking: first block wins; non-important allow on qname does not unblock CNAME; `$important` allow on qname or target does). Thin `FilterEngine` over immutable snapshot: `TempAllow` in per-set `RwLock` map (ranks as important allow, expires at `until` via injected `now`, list/remove, `RuleSource::TemporaryAllow`, no snapshot rebuild). Per-set and per-list Relaxed atomics (`matches`/`blocks`/`allows`), `stats()` plain struct; one increment per `match_*` call. Pause via existing `paused_until` (temps do not override). 16 tests in tests/engine.rs. Open for L3: swap `Arc<Snapshot>`, scheduler, coalesce rebuilds; Checkpoint B still needs M4b numbers.

- 2026-10-25 — Filtering F6 done (Cursor): `MatchKind::Ip` / `Rule::ip`, parser accepts `||1.2.3.4^`, bare `1.2.3.4`, IPv6, `$important`/`$badfilter` (hosts *names* that are IPs stay invalid). Separate sorted IPv4/IPv6 index arrays; `Index::match_answer_ip` / `Snapshot::match_answer_ip` (pause + custom vs list priority). `describe_rule` returns `None` for IP. tests/ip_rules.rs. parse_lists: AdGuard DNS filter **72 IP rules**, `invalid_syntax` for that list gone (total IP across lists 81).

- 2026-10-25 — Filtering R1 done (Cursor): regex compile uses `unicode(false)` + `regex::bytes::Regex` (ASCII hostnames; `\w{2}…` AdGuard rule no longer `regex_too_large`). `://x^` → Exact like `|x^`, `://*.x^` → glob `||*.x^`, path after `://` stays browser_only. parse_lists after fix: 2.241282 M rules (was 2.241279), AdGuard DNS filter skipped `browser_only=6` (was 17 `: //` anchors), `invalid_regex=0`, `regex_too_large=0` (was hitting the weekday `\w` rule); still 72 `invalid_syntax` IP rules → F6.

- 2026-10-25 — Filtering M4a done (Cursor): slimmed domain entries to **11.00 B/entry** (drop `lines` + `text_lens`; `source` as `u16`; `RuleTextSource::rule_at(source, offset)` derives line + scans to newline). Streaming `parse_list_each` (no `Vec<Rule>` per list). Build: in-place pending sort, in-place arena compact among survivors, then pack. Real lists (DiskBodies, bodies not held): build **1.58 s**, Index::memory **52.5 MB** (names 31.7 + overhead 20.9), VmRSS after **58.5 MB** (≤80 MB ✓). Build peak **ΔVmHWM ≈ 112 MB** (target ≤ +60 MB — **missed**). Why: pending (~2.24 M × 16 B) + name arena must coexist before compact/pack; largest list body (~15 MB) adds on top while streaming. Next options for Checkpoint B: (1) chunked per-list sorted runs + merge, (2) hash-of-suffix table (no sorted pending), (3) accept reload that drops the old index before rebuild (brief outage / Pass during rebuild). Hot-reload peak today ≈ old 58 MB + build 112 MB ≫ 150 MB RSS budget.

- 2026-10-25 — Checkpoint A complete: parser fixes (hosts names that are IP literals → invalid_syntax/ip_address; leading-dot `.x^` → glob `||*.x^`; skip samples 5 per reason, cap 60); fuzz target `rule_parse` + CI matrix entry + 17 seeds; 10 min fuzz clean (305 944 execs). examples/parse_lists.rs committed (manual real-list tool, cache in target/reference-lists). Open small items for Cursor briefs: regex rule `\w{2}…` hits regex_too_large (compile with unicode(false)); `://x^` rules in AdGuard DNS filter treated as browser_only (should be domain-start anchor). Cursor can start with tasks/cursor-next.md.

- 2026-10-25 — Filtering M2 done (Sonnet, reviewed): FilterConfig/FilterSetConfig/ListConfig, SnapshotBuilder parses lists one at a time, sets with equal ordered list combination share Arc index, separate custom index per set (merged private index if custom has $badfilter or @@$dnsrewrite), unique contribution per combination. Real lists, one set with all 19: build 1.21 s, index 67.7 MB (names 31.7 + overhead 36.0; 1.897 M entries, 343 k duplicates) → steady state fits 80 MB, BUT transient build peak ≈ +147 MB (IndexBuilder pending/arena + largest list's Vec<Rule>) → M4 must cut the build peak (reload = old index + build peak vs 150 MB RSS budget).

- 2026-10-25 — Filtering M1 done (Sonnet, reviewed): reversed-name arena + sorted offsets, 19 B/entry overhead (offsets 4, flags 1, src 4, line 4, text off 4, len 2), side table for dnstype/denyallow/dnsrewrite, patterns separate; RuleTextSource trait (bodies stay on disk); AdGuard priority, tie-break longest name → source → line; badfilter + dedup at build. 1 M rules build 335 ms, lookup 1.9 µs hit / 0.4 µs miss. Memory estimate for 1.87 M entries ≈ 80–95 MB → M4 must measure; slimming options: drop `lines` (derive from offset), u16 source ids, drop text_lens (scan to newline) → ~11 B/entry.

- 2026-10-25 — Checkpoint A run (Haiku tool examples/parse_lists.rs, uncommitted until fuzz clean): 19 lists, 2.28 M lines, 2.24 M rules, 1.87 M unique domains, 19 129 skipped (≈18.8 k browser/cosmetic from EasyList DE/EasyPrivacy), parse 0.67 s, no path rule became a regex. Fuzz found hosts-name-is-IPv4 inconsistency; fixes running (IPv4 hosts names, leading-dot rules → subdomains-only, samples per reason). Owner: IP rules wanted → Task F6. M1 told to keep list bodies on disk (48 MB) and resolve rule text on demand.

- 2026-10-25 — Filtering F4 + F5 builder done (Sonnet, reviewed): globs (`*` spans dots, `||` start/after-dot, `^`/`|` = end, `||*.x^` subdomains only, letter/digit required), O(n·m) matcher; regex via `regex` (case-insensitive, 64 KiB/256 KiB limits, unanchored on canonical name, `\/` → browser-only); literal prefilters checked for no false negatives. Builder: canonical `[@@]||x^$important,dnstype=…,dnsrewrite=…`, describe_rule inverse, proptest round trips; TXT forbids `\ $ / #`. Follow-ups: dedupe TYPE_NAMES (builder vs modifiers) in C1; check at Checkpoint A how many EasyList `/path/` rules become hostname regexes (AdGuard-compatible but may over-block). 112 tests.

- 2026-10-25 — Filtering F3 done (Sonnet, reviewed): $important, $badfilter (key = parsed rule minus badfilter), $dnstype (incl. ~), $denyallow, $dnsrewrite (rcode, A/AAAA/CNAME/TXT; record rewrites from lists skipped as RewriteFromList; @@…$dnsrewrite disables), $client/$ctag rules skipped (not applied globally), unknown/duplicate modifiers, IDNA (UTS 46). Rule 40 B (modifiers boxed only when present). 17 modifier tests.

- 2026-10-25 — Filtering L2 done (Sonnet, reviewed): reqwest 0.12.28 (rustls+ring+webpki roots, gzip; 0.13 rejected: defaults to aws-lc/platform verifier); no aws-lc/openssl in tree. Conditional GET, streaming size cap incl. gzip bombs, https-only redirects (max 5), not_text detection, last-good body kept. 16 tests vs hand-written local HTTP server. Known gaps: TLS error code by message match (untested), file-change detection in memory only.

- 2026-10-25 — Filtering F2 done (Sonnet, reviewed): strict parse_rule + lenient parse_list; Rule 32 B, text recovered from list body by offset; bare/unanchored domain → ||x^ (subdomains), |x^ → exact, hosts lines → exact block (reserved names skipped); cosmetic/browser-only/modifier/pattern/regex skipped with reasons + 20 samples; 1 M hosts lines parse in ~159 ms (release).

- 2026-10-25 — Filtering L1 done (Sonnet, reviewed): ListStore in <data>/filtering/{lists,services}, 0o700 dirs, atomic temp+fsync+rename writes, versioned ListMeta (corrupt → None + warn), size cap on write and read, https-only sources (test hatch), local file sources. serde/serde_json added. 10 integration tests.

- 2026-10-25 — Filtering F1 done (Sonnet, reviewed): crate skeleton, DomainName (strict length/charset, lenient hyphen position, suffix iteration, reversed form), ids, RuleSource/Reason/Verdict/Rewrite/BlockMode (default Refused), Clock, error codes. No dnscraft-proto dependency yet. 17 tests.

- 2026-10-25 — Docs completed (Haiku, lead-verified constants): resolver README config/forward zones/DNSSEC codes/hardening limits; READMEs for dnscraft-proto, dnscraft-testkit, fuzz. Checkpoint E approved. Filtering spec started; owner decisions: AdGuard DNS subset syntax ($important,$badfilter,$dnstype,$denyallow,$dnsrewrite, regex; $client/$ctag ignored with warning), block mode selectable with default REFUSED, list updates every 24 h, hosts-file lines in lists always block (never redirect).

- 2026-10-25 — Checkpoint E review: 2 Sonnet reviewers (code + security), lead verified top findings. Fixed in 3 batches with fail-before regression tests: KeyTrap/NSEC3 budgets, inception skew; PTR leak, inflight cancellation, O(log n) LRU, flush epoch, forward failover, stale Indeterminate/30 s, concurrency cap; answer scrubbing, rcode-flip Bogus, DNAME CNAME check, RRSIG TTL cap, private/loopback glue filter, srtt bound, validated priming + 24 h re-prime, 10 s deadline. Live statuses unchanged. 390 tests green.

- 2026-10-24 — Task 16 done: `ResolverStats` (cache hits, stale, DNSSEC outcomes, latency sums); error codes documented (CnameLoop/Limit share `resolver.cname_limit` by design); criterion `cache_hit` p50 ≈ 214 ns; example already live-verified (example.com Secure, dnssec-failed.org SERVFAIL/Bogus); llvm-cov 92.78 % lines. Workspace DoD green.

- 2026-10-24 — Task 16 started.

- 2026-10-24 — Task 14 done (Grok + lead review): stub forward with RD=1 via targets (RTT/failover); `ForwardZone { zone, targets, validate }`; validate=false → Insecure; loop via `RequestFlags::client` ∈ targets → `resolver.forward_loop` (keeps inflight coalescing); 4 forward + local_zones green. DoD green.

- 2026-10-24 — Task 14 started.

- 2026-10-24 — Checkpoint D passed: criterion 4 (2nd query zero traffic + release cache-hit p50≈542 ns / p99≈625 ns over 200 samples; formal `criterion` bench still Task 16), 5 (stale within window), 6 (50 concurrent → one chain). Workspace DoD green. Owner approved.

- 2026-10-24 — Task 13 done (Grok + lead review): serve-stale on Unreachable only; window via `serve_stale` (default 1d, ZERO disables); EDE 3 + AnswerSource::Stale + TTL 0 + AD clear; stale not stored. Beyond window → Err(Unreachable). 3 integration + 3 unit tests. DoD green. Left unrelated SPEC.md (bug-report row) unstaged.

- 2026-10-24 — Task 13 started.

- 2026-10-24 — Task 12 done (Grok + lead review): in-flight dedup (key = name/type/class + CD; DO stripped per waiter); prefetch for popular (≥3 hits) near-expiry entries (window max(10% TTL, 2s)); config `prefetch` default true; 2 integration + unit tests. Workspace DoD green.

- 2026-10-24 — Checkpoint B checkboxes synced in todo.md; Checkpoint C passed (49 dnssec tests; live Secure/SERVFAIL cross-checked with delv/kdig).

- 2026-10-24 — Task 12 started.

- 2026-10-24 — Task 11 done (Grok + lead review fix): byte-budget LRU message cache, RFC 2308 negative TTL (incl. CNAME→NODATA), TTL clamp, flush All/Domain, CD/Bogus not stored. 13 integration + 9 unit tests. Follow-ups: O(n) LRU scan, NXDOMAIN still per-qtype.

- 2026-10-24 — Task 11 started (Grok agent; Sonnet unavailable).

- 2026-10-24 — Task 10 done (Sonnet + lead review fix): NSEC/NSEC3 denial (NXDOMAIN, NODATA, wildcards, opt-out, closest encloser), NTAs via config. Review found NSEC wildcard answers omitted closest-encloser consistency → fixed + unit/forge regression. 17 denial/nta integration tests; workspace green.

- 2026-10-24 — Task 9b done (Sonnet, 2 review rounds): trust state per zone cut, AD only for Secure, Bogus → SERVFAIL + EDE (text = code), CD → unvalidated/Indeterminate, DO=false strips DNSSEC records, signed no-DS proof required for Insecure. Review round 1 found false Bogus on hidden zone cuts (bbc.co.uk, www.nic.uk, www.cloudflare.com) → DS walk (signer below zone, label probe max 8, intermediate zones). Live results match delv. 253 tests green. TODO(Task 10): negative/wildcard stay Indeterminate; NSEC3 closest-encloser check.

- 2026-10-24 — Follow-up fix (Haiku, reviewed): no full-QNAME retry at a server that did not answer a minimised query; move to next candidate (one timeout per dead server). Regression test with a silent server. 232 tests green.

- 2026-10-24 — Task 7 done (Sonnet, reviewed): RFC 9156 minimisation with A qtype, relaxed fallback on NXDOMAIN/errors/alias nodes, MAX_MINIMISE_COUNT 10 / ONE_LAB 4, config switch. Live: example.com 4 queries, microsoft 13 (+2), _dmarc.google.com TXT 4. Follow-up: plain timeout currently retries full name at the same dead server (double timeout).

- 2026-10-24 — Bug fix (Sonnet, reviewed): glue was discarded unless inside the delegated child → gtld-servers.net glue dropped → circular glueless chase via nstld.com. Fixed with lazy glueless resolution, per-resolve NS host map, cycle skip, cap 4 glueless per cut. Review found the fix accepted ANY glue (poisoning risk) → restricted to responder bailiwick (RFC 2181 §5.4.1) by Haiku agent with unit tests. 225 tests green.

- 2026-10-24 — Task 15 done + wired (Haiku, reviewed): RFC 6303 local zones answered before recursion, forward zones exempt; `examples/query.rs` added (pulled forward from Task 16). First real-internet run: all lookups fail with query budget exhaustion → bug ticket.

- 2026-10-24 — Follow-up of Task 6 (Haiku, reviewed): Resolver owns shared ServerStats; iterate.rs orders candidates by SRTT and uses query_servers (TC→TCP); transport/server_selection exposed as doc(hidden) pub, test #[path] hack removed. Priming still uses plain exchange (acceptable).

- 2026-10-24 — W5 fuzz runs (libFuzzer, 600 s each, aarch64): name_decode 139.2 M execs, message_decode 105.3 M, message_roundtrip 7.1 M — 0 crashes, 0 timeouts. Task 15 code done (Haiku; local_zones.rs, awaiting wiring into lib.rs).

- 2026-10-24 — Tasks 5, 6, 9a done in parallel (Sonnet, reviewed; 203 workspace tests, stable 3x). 5: CNAME/DNAME chains (bailiwick rule, RFC 6604), shared query budget. 6: TC→TCP, strict response matching, SRTT server selection, IPv6 cool-down — not yet wired into iterate.rs (follow-up). 9a: own validator over ring (alg 8/10/13/14/15, RSA ≥1024 legacy), DS matching with SHA-1 suppression, RFC 1982 validity, EDE mapping, wildcard hook; root fixture verifies.

- 2026-10-24 — Task 4 done (Sonnet, reviewed): Resolver API, iterative resolution with priming, glueless NS lookups, injectable clock, test hook for per-name nameserver addresses; root hints verified against IANA named.root. 9 tests.
- 2026-10-24 — Task 8 done (Sonnet, reviewed): signed testkit hierarchy via hickory (independent signer): secure/NSEC3/opt-out/insecure/bogus-sig/bogus-expired/bogus-nokey, wildcards, DS at cut from parent, DO-bit responses. Embedded RSA keys are test-only fixtures (not secrets). `rustls-pki-types` added as direct testkit dep (already transitive via hickory). 15 tests. Workspace: 164 tests, stable 3x.

- 2026-10-24 — Task W4 done (Sonnet agent, reviewed): DNSKEY/DS/RRSIG/NSEC/NSEC3/NSEC3PARAM, type bitmaps, key tag, DS digest, NSEC3 hash (RFC 5155 vectors), canonical signing input — verifies the live root DNSKEY RRSIG with ring. Review found RRSIG signer must be lowercased per RFC 6840 §5.1 (checked against RFC text) → fixed by Haiku agent. Note: hickory sorts RRsets by raw (not lowercased) RDATA; we follow RFC 4034 §6.3.
- 2026-10-24 — Task W5 code (Sonnet agent): fuzz/ crate with 3 targets + seeds, proptest suite (5 properties, also 10k cases), CI fuzz job. libFuzzer needed gcc-c++ → installed by lead.

- 2026-10-24 — Task W3 done (Sonnet agent, reviewed): Header/Rcode, EDNS (ECS, EDE, padding, cookie), Message decode with count sanity check, OPT interception, trailing-data check; encode_with_limit drops whole RRsets (TC only for answer/authority). Testkit now decodes every response with dnscraft-proto (oracle). 71 unit + 7 oracle + 4 testkit-oracle tests.

- 2026-10-24 — Task W2 done (Sonnet agent, reviewed): RecordType/Class, Record, RData for 12 types + Unknown; RDATA parsed against an RDLENGTH-bounded slice; encode returns Result and rolls back on error; 38 new unit + 6 oracle tests. Follow-up: `Record` does not enforce rtype == rdata variant.

- 2026-10-24 — Task W1 done (Sonnet agent, reviewed): `Name` with iterative hardened decoder (backward-only pointers, 128 jumps, 255-octet limit), compression map, RFC 4034 ordering; 17 unit + 4 hickory-oracle tests. Follow-up for later perf work: compression map allocates a lowercase key per suffix.

- 2026-10-24 — Owner chose Option D at Checkpoint A. ADR amended, SPEC/map updated, plan revised: new phase 1b (W1–W5), Task 9 split into 9a/9b.

- 2026-10-24 — Task 2 done (Sonnet agent, reviewed; key claims re-verified on crates.io/GitHub): `hickory-recursor` abandoned, successor experimental and missing serve-stale/forward zones/EDE/NTA/dedup/ports; ADR-0001 proposes Option C. Plan revised accordingly.

- 2026-10-24 — Task 3 done (Sonnet agent, reviewed): hand-written authoritative responder on tokio + hickory-proto 0.26.3; 5 integration tests, stable over 3 runs. Review findings carried into Task 8: DS at zone cut must be answered by the parent; wildcard support missing.

- 2026-10-24 — Task 1 done (Haiku agent, reviewed): workspace, toolchain pin, lints, CI workflow. fmt/clippy/test green locally.

- 2026-10-24 — Specs approved and pushed. Plan approved. Toolchain installed (Rust 1.99.1, dig, kdig).
