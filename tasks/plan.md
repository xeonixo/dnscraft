# Implementation Plan: Named Client IDs, device link, `.mobileconfig`

> Replaces the 2026-10-26 orchestration plan (all of its streams are archived or complete; a copy
> is kept at `tasks/archive/plan-orchestration-2026-10-26.md`, and git has the history).
> Authority for status of other modules: [progress.md](progress.md).
> Task list: [todo.md](todo.md). Date: 2026-10-28. Status: **draft, needs owner review**.

## Overview

The `/doh-clients` screen today lists bare Client-ID strings. The owner wants to (1) treat a Client ID
as a named device that can be tied to an entry in *Geräte*, (2) hand an iPhone a ready-made Apple
configuration profile (`.mobileconfig`) that points it at the public DoH endpoint with its Client ID,
and (3) possibly give that iPhone its own Netzbereich/profile even on mobile data.

(1) and (2) fit the current architecture. (3) narrows an earlier owner decision (#13, zone selection is source-IP only). The owner answered D1 on
2026-10-28: rules stay with the device on the road, only some records differ, so it is Phase 2.

## What exists today (verified by reading the code and specs)

- A Client ID is a string in the config snapshot `policy.client_ids` (`GET/POST/DELETE
  /api/v1/policy/client-ids`, `crates/dnscraft-api/src/api/policy_routes.rs`). No label, no device,
  no profile. Rename = delete + create.
- Listeners only need "is this id registered?" (`PolicyClientIds` in `dnscraft-listeners/src/tls.rs`,
  `ClientIdRegistry` in `dnscraft-tls`). Public DoH path `/dns-query/<id>`, DoT/DoQ SNI
  `<id>.dns.<public_domain>`.
- `RequestContext.client_id` reaches the policy pipeline and the decision record, but
  `PolicySnapshot::select` ignores it: **view/zone selection is source-IP only** (longest-prefix
  subnet → default view). That is owner decision #13 of `SPEC-policy.md` (2026-10-26): the Client ID
  "only authenticates the client to the listener and enriches the log, never the chosen zone".
- Consequence: an iPhone on mobile data (public IP, no matching Netzbereich) always gets the default
  Netzbereich and its profile.
- The query log stores `client_id` and `client_name`; `client_name` comes from the client directory
  by IP, so a public DoH query has an id but usually no name.
- `.mobileconfig` generation is promised by `SPEC.md` ("UI generates Apple `.mobileconfig` profiles")
  and listed as an open question in `SPEC-web-ui.md`; nothing is implemented.
- The public hostname is `tls.public_domain` (config, `GET /api/v1/tls`).

## Dependency graph

```
D1 owner answer (done) ──────────────────────────────────► Phase 2
        │
T1 client_ids as objects (API + snapshot) ──┬─► T2 log attribution by label
                                            ├─► T3 DoH-Clients page (cards, device link, copy URL)
                                            │        └─► T4 .mobileconfig + Android hostname (client-side)
                                            └─► T5 docs/spec updates
Phase 2:  T6 spec change ─► T7 policy: subnet → pin → default ─► T8 API field `view` ─► T9 UI (editor, detail, zones, Namen overrides)
```

## Architecture decisions

1. **Keep the Client ID a registration, add metadata next to it.** `policy.client_ids` entries accept
   either a string (today) or `{ "id", "label"?, "device"? }`. The registry used by listeners keeps
   seeing plain ids. Old snapshots, rollbacks and cluster sync keep working because a string is still
   valid.
2. **Device link is a reference, not a copy.** `device` stores the directory client's stable id
   (manual client name/IP or UniFi id as the clients crate exposes it). It only drives display and
   the log label; it never changes policy. If the device disappears the link shows "unbekannt", not an
   error.
3. **Log label precedence for a request that has a Client ID:** directory name by IP (LAN) → Client-ID
   label → bare id. No new log column; `client_name` is filled.
4. **`.mobileconfig` is generated in the browser** (pure TS function + Blob download). It only needs
   public data (public domain, Client ID, label), so no new endpoint, no secrets, no server state.
   QR code and profile signing are out of scope for v1.
5. **Phase 2 (decided direction, 2026-10-28): a Client ID is the fallback for an unrecognised IP.**
   Owner intent: the device keeps its *filter rules* (profile) on the road, only *some local records*
   (e.g. `nas.lan`) must differ there. The model already supports this:
   - Selection order becomes **subnet match → Client-ID pin → default view**. At home the LAN IP
     matches a Netzbereich as today; away (carrier IP, no match) the pin replaces the default view.
     That also avoids the trap of a pin overriding the LAN view while the phone is at home.
   - A pin points at a **view (Netzbereich)**, which already points at a profile. For "same rules,
     different records" the owner creates a view such as "Unterwegs" with the **same profile** as the
     home view and **per-view record overrides** (records are a global name space with
     `overrides` keyed by view id, `SPEC-policy.md` review 14). No new concept.
   - This reverses owner decision #13 only in part: the Client ID still never beats a matching
     subnet; it only replaces the default for unmatched IPs.

6. **DoH everywhere (owner, 2026-10-28):** the profile uses the same DoH URL at home and away; no
   Wi-Fi exclusion by default (the SSID rule from T4 stays an optional field, off). Consequence: at home
   the DoH request must still arrive with the device's **LAN source IP**, otherwise the home Netzbereich
   cannot match. Mechanism: a local record `dns.<public_domain>` with a **per-view override** for the
   home Netzbereich pointing at DNScraft's LAN IP (the iPhone resolves the DoH host name through the
   DHCP-provided DNS at home, away through public DNS). Both paths use the existing records/overrides
   model, no new concept. T4b adds a setup checklist and a check for exactly this.

## Task list

See [todo.md](todo.md) for the checklist with acceptance criteria. Phases:

- **Phase 0 – Decision (no code):** D1 (answered, see below), D2 (naming/storage).
- **Phase 1 – Named Client IDs and `.mobileconfig` (no policy change):** T1–T5.
- **Checkpoint A.**
- **Phase 2 – Client ID is the fallback Netzbereich for unrecognised IPs:** T6–T9.
- **Checkpoint B.**

## Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Phase 2 partly reverses owner decision #13 | High | Narrow change (pin only replaces the default for unmatched IPs); T6 changes the spec first and needs owner approval before any code |
| iOS rejects the profile: DoH needs a publicly trusted certificate | High | Show a warning on the page when `tls.mode` is `self_signed`; verify on a real iPhone at Checkpoint A (cannot be tested in the simulator of this repo) |
| Unsigned `.mobileconfig` shows "not verified" on install | Medium | Document it in the UI; signing deferred |
| Config schema change (string → object) breaks old snapshots, rollback or cluster sub-nodes | High | Keep strings valid, add a round-trip test with an old snapshot, test config rollback and cluster write relay |
| Client ID in a profile on a device is effectively a bearer credential | Medium | Treat it like a token in the UI: copy buttons, no listing on public listeners, revoke path stays; mention in the profile page |
| Label/hostile strings end up in plist XML | Medium | XML-escape and length-cap; unit test with `<`, `&`, RTL and 150-char labels |
| Query log label lookup adds a hot-path cost | Low | Registry label map is a read-only snapshot (`Arc`), same lookup as admission |
| DoH everywhere: hairpin NAT or missing split-horizon record makes the home request arrive from the router/WAN IP, so the home Netzbereich does not match | Medium | T4b checklist + "zuletzt zugeordnet über" indicator per Client ID; docs; optional SSID rule as fallback |
| Overlap with an unrelated dirty working tree (UnifiPanel etc.) | Low | Tasks list files explicitly; do not touch `web/src/lib/settings/Unifi*` |

## Open questions (need the owner)

1. **D1 (answered 2026-10-28, owner):** Rules must stay with the device on the road; only some
   records differ. → Phase 2 stays, with the order subnet → Client-ID pin → default (see decision 5).
   Still to confirm: is "pin only replaces the default for unmatched IPs" what the owner wants?
2. **D2:** Is a Client ID label required or optional? Unique? (Proposal: optional, unique
   case-insensitively, max 64 chars.)
3. Should the Apple profile include on-demand rules for the home Wi-Fi (`SSIDMatch` → use the local
   resolver instead of the public DoH endpoint)? Needs the SSID names as input. (Proposal: optional
   field "Heim-WLAN (SSID)" in the download dialog.)
4. Should `device` offer UniFi clients only, or also manual clients? (Proposal: all directory
   clients.)
