# Web-UI — Spec-/Prototyp-Abgleich der Nicht-TLS-Screens

> Quelle: 4 Agents (Reverse-Zonen, Query-Log-Felder, Cluster-Tiefe, Spec-Abgleich aller
> Screens), 2026-10-27. Referenz: `SPEC-web-ui.md`, `SPEC-policy.md`,
> `SPEC-listeners.md`, `SPEC-cluster.md`, `SPEC-control-api.md`,
> `docs/design/web-ui-prototype.html`. TLS/DNS-Lücken: siehe `todo-web-ui-tls.md`.

Legende: **Spec-Lücke** = in keinem Fach-Spec definiert → in Specs nachziehen.
**Prototyp-Lücke** = spec-definiert, aber im Prototyp fehlt/falsch → UI nachziehen.

---

## A. In die Specs nachgezogen (diese Session)

- `SPEC-web-ui.md`: `/cluster`-Route in die Screen-/Route-Inventur aufgenommen;
  Open questions 29–31 (Namen-Gruppierung, Listener-Modell, Settings-Konsolidierung);
  „Required control-api additions" um Cluster-Endpunkte, Client-ID-CRUD,
  Geräteprofile, manuelle-Client-Form erweitert.
- `SPEC-control-api.md`: `/api/v1/cluster/nodes|join-tokens|nodes/{id}` in die
  Endpunkt-Tabelle; Open questions 7–8 (Client-ID-CRUD, Cluster-Shapes).
- `SPEC-listeners.md`: Assumption 3 von `views[].client_ids` auf „TBD" korrigiert
  (Widerspruch zu `SPEC-policy.md`).

## B. Offene Spec-Lücken (noch nicht in Specs geschrieben)

1. **Client-ID-Speicherung/CRUD** — `policy/views` trägt `client_ids` nicht mehr;
   kein Endpunkt speichert/rotiert/widerruft IDs. → `SPEC-control-api` Open question 7.
2. **Manuelle-Client-Form** — API existiert (`/api/v1/clients/manual`), aber
   Formfelder, Precedence-/Kollisionsdarstellung sind undefiniert. → `SPEC-web-ui`.
3. **Zonen-Datensätze** — Prototyp zeigt „N Datensätze" je Zone; Spec sagt „keine
   Records hier" (globaler Namespace). → UI-Fix + ggf. Spec-Klarstellung.
4. **RR-Sets** — Spec modelliert mehrere rdata-Werte je Typ; Prototyp erlaubt nur
   einen Wert je Name/Typ.
5. **Test-Abfrage-Widerspruch** — Inventur führt den Screen (`SPEC-web-ui.md:428`),
   aber `:1046` sagt „nicht in v1" und `SPEC-control-api` verortet den Endpunkt in
   der MCP-Phase.
6. **Forward-Zonen-Datenmodell** — Delegation an Resolver-Config ohne Definition von
   Upstream-Protokoll/Port/TLS, mehreren Upstreams, Reverse-Zonen (plural/CIDR).
7. **Profile-Pause-Scope** — `GET/POST/PUT/DELETE /api/v1/policy/pause` existiert,
   aber Request-Shape für global vs. pro Profil ist undefiniert.
8. **UniFi-Verbindungs-Settings** — Gateway/Site/API-Key/TLS-Pin/Poll-Intervall haben
   keinen Screen-Heimatort in `SPEC-web-ui.md` (nur der Sync-Endpunkt existiert).
9. **`node_id`-Facette** — Cluster verlangt `node_id` in Query-Log/Statistik
   (`SPEC-cluster.md:727`), fehlt in den Web-UI-Inventarzeilen.

## C. Prototyp-Build (diese Session, siehe unten „Build-Status")

| # | Screen | Fix |
|---|---|---|
| 1 | Zonen | „N Datensätze" entfernen; genau-eine-Standard-Zone + Catch-all = leere Bereiche klarmachen |
| 2 | Namen | Gruppierung nach Suffix (öffentliche TLD vs `.lan`/`.local`) |
| 3 | Forward-Zonen | Reverse-Zone optional + mehrere/CIDR |
| 4 | Profile | SafeSearch-Provider + YouTube-Modus, Rebind-Ausnahmen, Forward-Zonen-Auswahl, globale Pause + Fortsetzen |
| 5 | Query-Log | Zone/Profil, `answer_source`, DNSSEC, `selection_cause`, `cache_hit`, Source-/Dest-Port, Upstream im Detail |
| 6 | Geräte | manuelles Anlegen/Bearbeiten/Löschen; UniFi bleibt auf `/clients` (spec-konform) |
| 7 | DoH-Clients | Widerruf/Löschen, Umbenennen, Zulassungs-/Nutzungsstatus |
| 8 | Listener | ein Protokoll je Listener (nicht Multi-Protokoll), DoH `h3`, Status, Limits, Public-Admission, DDR |
| 9 | Knoten | Beitritts-Token-Sheet, Node-Detail, Widerruf, Zertifikat-Verteilung, Warnungen |

## D. Build-Status

Alle 9 Build-Items sind im Prototyp eingebaut (2026-10-27):

1. ✅ Zonen — „N Datensätze" entfernt; genau-eine-Standard-Zone + Catch-all = leere
   Bereiche + Lösch-/Validierungsregeln im Fußnotentext.
2. ✅ Namen — Gruppierung nach Suffix (Öffentliche TLDs vs. Lokale Suffixe `.lan`);
   Lead + Fußnote klären den globalen Namespace und das NXDOMAIN-Suffix-Verhalten.
3. ✅ Forward-Zonen — Reverse-Zonen optional + mehrere/CIDR (Sheet) + Fußnote
   „ohne Reverse-Zone → privates PTR bleibt lokal".
4. ✅ Profile — Globale Pause + Fortsetzen, Pause (dieses Profil), YouTube-Modus
   (strict/moderate), SafeSearch-Provider komplett, Rebind-Ausnahmen,
   Forward-Zonen-Auswahl (None/Some).
5. ✅ Query-Log — Detail-Sheet um Zone/Profil, `answer_source`, `selection_cause`,
   DNSSEC, `cache_hit`, Quell-/Zielport, Node erweitert.
6. ✅ Geräte — manuelles Anlegen-Sheet (Name, IP/CIDR, MAC, Domain) + Precedence-
   /Kollisions- und VLAN-Hinweis; UniFi-Integration bleibt auf `/clients`.
7. ✅ DoH-Clients — Zulassungsstatus („zuletzt"), Widerruf/Umbenennen als Spec-Lücke
   im Fußnotentext (kein Endpunkt).
8. ✅ Listener — ein Protokoll je Listener, DoH `h3`-Toggle, per-Listener-Status,
   Limits (korrigiert: Source 200 / Client-ID 50), Public-Admission, DDR.
9. ✅ Knoten — Beitritts-Token-Sheet, Cluster-CA, Zertifikat-Verteilung, Warnungen
   (Lag/Clock-Skew), Node-Detail (joined/last_seen/queue), `node_id`-Facette.

Verifikation: Tag-Balance (div/section), keine doppelten IDs, alle
`getElementById`-Referenzen und `onclick`-Handler aufgelöst.
