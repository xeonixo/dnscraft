# Implementation Plan: Namen-Modul — Split-DNS (lokal + öffentlich via Cloudflare)

> Branch: `feature/public-domain-zones` (from `main`).
> Task list: [todo-domain-zones.md](todo-domain-zones.md).
> Date: 2026-10-29. Status: **draft, needs owner review**.
>
> Does **not** replace [plan.md](plan.md) (Named Client IDs). That plan stays the active
> Client-ID workstream; this file is a parallel feature plan.

## Overview

Der Owner betreibt **Split-DNS** mit klarer Priorität:

1. **Zuerst das Öffentliche** (Cloudflare) — kanonischer Wert, den das Internet sieht.
2. **Davon abweichen** nur dort, wo der **Ursprung der Anfrage** es braucht
   (Netzbereich / View). Ohne Abweichung gilt intern derselbe Wert wie öffentlich.

Deshalb ein **Namen-Modul**, name-zentriert — kein Silo „lokal vs. Cloudflare“.

| Kontext | Bedeutung | Speicherung |
|---|---|---|
| **Öffentlich** (Basis) | Was Cloudflare published | Live bei Cloudflare |
| **Netzbereich X** | Abweichung für Queries aus View X | `policy.records.overrides[view]` |
| *(kein Override)* | Intern = öffentlich | DNScraft antwortet mit dem öffentlichen Wert (lokal als Default/`rdata` gespiegelt oder „same as public“) |

DNScraft bleibt kein autoritativer Public-DNS-Server (SPEC Non-goal). Cloudflare bleibt
Authoritative für die öffentliche Seite; DNScraft proxied Zone DNS:Edit und liefert die
Split-Abweichungen je Netzbereich.

Heute: Freitext-`zone=wert`-Overrides; öffentlicher Wert außerhalb. Ziel: Editor mit
**Öffentlich zuerst**, darunter nur die Netzbereiche, die abweichen.

## What exists today (verified)

| Piece | Location | Relevance |
|---|---|---|
| Local names UI | `web/src/routes/names/+page.svelte` | List + sheet; overrides = raw textarea |
| Netzbereiche | `web/src/routes/zones/+page.svelte` | Views for split selection — pickers feed the Namen editor |
| Nav „Namen“ | `web/src/lib/nav.ts` → `/names` | **One module** for split + public |
| Policy records API | `GET/PUT/DELETE /policy/records` | Local default + `overrides` map |
| Cloudflare client | `crates/dnscraft-tls/src/cloudflare.rs` | ACME/DynDNS-oriented; extend for zone browse/edit |
| Extra zones config | `TlsConfig.dns_provider.zones` | Attach apexes for public side |
| Token storage | `cloudflare_secrets` + `PUT /tls/cloudflare-token` | Shared with ACME/DynDNS |
| CF mock | `crates/dnscraft-tls/tests/support/mock_cloudflare.rs` | Tests without real CF |
| MCP / TLD grouping Q29 | specs | Out of scope for this plan |

## Dependency graph

```
D1 owner: split-centric Namen UX + CF attach + record types
        │
T0 Overrides-UI: Netzbereiche als strukturierte Liste (kein Freitext)
        │
T1 CloudflareClient: list zones + list zone records
        │
T2 Control-API GET domain-zones / records
        │
T3 Namen-Modul: Name-Karte zeigt lokal + öffentlich (read)
        │
T4 CF + API: mutate public records; attach/detach zones
        │
T5 Namen-Editor: öffentlicher Kontext schreiben + Token/empty states
        │
T6 Specs, i18n, DoH/TLS cross-links
```

## Architecture decisions

1. **Public first, deviate by origin.** Opening a name leads with the **öffentliche**
   value. Below: Netzbereiche that **override** it for queries from that view. A
   Netzbereich without a row inherits public. Purely-internal names (no public DNS)
   are the exception (no CF row / „nur intern“). Purely-public names need no overrides.

2. **Proxy public; store only deviations locally.** Public RDATA lives at Cloudflare
   (live API). Local config keeps Netzbereich `overrides` (and a local default that
   mirrors public so LAN clients get the same answer when DNScraft is authoritative
   for the name). No silent second source of truth: editing „Öffentlich“ writes CF
   and updates the local default to match; editing a Netzbereich only touches overrides.

3. **One nav item `/names`.** No sibling „Domain-Zonen“ nav. Zone attach / CF inventory
   can live as a secondary sheet or advanced section inside Namen (“Öffentliche Zonen
   anbinden”), not a separate mental module.

4. **Elegant Abweichungen (replaces the textarea).** Under Öffentlich: add/remove
   override rows per Netzbereich (picker from `GET /policy/views` + value). Empty /
   absent = inherit public. No `gue-01-default=…` freitext. Copy: **Netzbereich**,
   never „Zone“ for views.

5. **Reuse the existing Cloudflare API token.** Missing token → CTA to TLS. Write lock
   shared with ACME/DynDNS.

6. **Attached zones.** Discover zones the token sees; admin attaches apexes into
   `dns_provider.zones` (+ implicit `public_domain`). Detach ≠ delete at Cloudflare.

7. **Record types v1:** A/AAAA/CNAME/TXT/MX/SRV locally and publicly; `proxied` on
   public rows with warning for DoT/DoQ hostnames.

8. **Roles:** viewer reads; admin mutates local + public + attach.

9. **SPEC:** Non-goal (no authoritative hosting) stays; add Split-DNS / Cloudflare
   mirror under web-ui + control-api + tls.

## Task List

### Phase 0
- [ ] D1 Owner confirms decisions 1–9 (esp. name-centric split UX)

### Phase 1: Local Split UX + CF read
- [ ] Task 0: Netzbereich-Overrides-UI (structured, no textarea)
- [ ] Task 1: CloudflareClient zone inventory + record list
- [ ] Task 2: Control-API GET domain-zones / records
- [ ] Task 3: Namen UI — name card / editor shows public + local contexts (read)

### Checkpoint: Split readable
- [ ] Overrides usable without freitext; public side visible when CF attached

### Phase 2: Public write
- [ ] Task 4: Mutate CF records + attach/detach
- [ ] Task 5: Namen editor writes public context

### Checkpoint: Split editable
- [ ] Same name: set public A at CF + local overrides per Netzbereich

### Phase 3
- [ ] Task 6: Specs, i18n, DoH/TLS links

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Confusing „Zone“ wording | High | UI: Netzbereich vs öffentlich / Cloudflare; never reuse `nav_zones` for CF |
| Race ACME/DynDNS | High | Shared `write_guard` |
| Name exists only on one side | Med | Clear empty states: „Noch nicht öffentlich“ / „Nur öffentlich“ + actions |
| Drift public vs local | Med | Show both values side-by-side; no silent sync in v1 (owner edits each side) |
| Large CF zones | Med | Pagination + search; name-centric path may fetch by FQDN |
| Scope creep auto-sync | Med | v1: no automatic copy local→CF; optional later |

## Open Questions

1. **Nur-intern:** Names like `nas.lan` stay without a public row — OK?
2. **Attach model:** discover + attach, or only `public_domain` zone first?
3. **List view:** merge CF + local into one name list (badge: öffentlich / mit
   Abweichungen / nur intern), or start from attached CF zone walk?
4. **Record types / proxied:** as in decision 7?

## Assumptions

1. Shared Cloudflare token with TLS.
2. **Öffentlich zuerst**; Netzbereich-Overrides = Abweichungen nach Query-Ursprung.
3. Editing Öffentlich → Cloudflare + local default stay aligned; overrides unchanged.
4. One Namen-Modul, name-centric (not Lokal-Tab vs Cloudflare-Tab as two worlds).
5. Overrides UI in scope (replaces `zone=wert` textarea).
6. Cloudflare only; MCP and Namen TLD-grouping (Q29) out of scope.
