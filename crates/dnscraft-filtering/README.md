# dnscraft-filtering

Domain filtering engine for DNScraft: parses AdGuard/hosts-style rule lists,
matches query names against them, and returns a verdict (pass, allow, block,
rewrite) with the rule that caused it.

It does no DNS transport and knows nothing about clients; policy and listeners
live in other modules. Formal requirements: [`SPEC-filtering.md`](../../SPEC-filtering.md).

## Status

Task F1 only: core types (`DomainName`, ids, `Verdict`, `BlockMode`), `Clock`,
and error types with stable codes. Parser, index, and matching follow.
