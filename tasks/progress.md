# Progress log

Resume point for interrupted sessions. Newest entry first.
Task details: [todo.md](todo.md) · Plan: [plan.md](plan.md)

Earlier modules: [archive/](archive/) (resolver plan + tasks). Briefs for working with Cursor: [cursor-next.md](cursor-next.md).

**Workflow:** each task is implemented by a Haiku/Sonnet subagent, reviewed by the lead
(diff, `fmt`, `clippy`, tests), ticked off in `todo.md`, logged here, and committed.

## Current state

- Module `resolver` COMPLETE (Checkpoint E approved 2026-10-25).
- Module `filtering`: Checkpoint A done; M4a (index slim + build peak) done — steady state OK, **build peak still over budget** (owner decides at Checkpoint B). Next: R1, F6, M3, M4b.
- Blockers: none for continuing the Cursor brief order; Checkpoint B needs owner review of M4a peak numbers.

## Log

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
