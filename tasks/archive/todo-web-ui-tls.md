# Web-UI TLS/DNS — Interface-Abgleich & offene Lücken

> Quelle: Agent-Recherche (Real-World-Produkte + Spec-Abgleich), 2026-10-27.
> Referenz: `SPEC-tls.md` · `SPEC-web-ui.md` · `SPEC-control-api.md` · `docs/design/web-ui-prototype.html`
> Legende: **common** = die meisten echten Produkte haben es (Technitium, AdGuard, Pi-hole, Caddy, OPNsense, CertMate, …) · **rare** = Nische/optional.

---

## A. Spec-Lücken — Features, die in keinem Fach-Spec auftauchen

Diese gehören zu einer TLS/DNS-Seite, sind aber in keinem der drei Specs definiert. **In die Specs nachziehen**, bevor sie echt implementiert werden.

### A1. Zertifikat-Quelle & Ausstellung

- **Manuelles Zertifikat hochladen** (PEM cert+key+chain, Paste, Download, Replace) — **common** — fehlt in `SPEC-tls.md` + `SPEC-control-api.md`; nur `self_signed | acme`.
- **Zertifikatskette / Issuer-Detail** (issuer, subject, not_before, serial, chain, Signatur-Algorithmus, Key-Usage) — **common** — `TlsStatus` hat nur `not_after`/`days_to_expiry`/`identifiers`; kein issuer/serial/chain.
- **Generischer DNS-Provider / manueller DNS-01** (nicht nur Cloudflare; TXT-Wert anzeigen/kopieren) — **common** — `SPEC-tls.md` hardcodiert Cloudflare.
- **HTTP-01 Challenge** — **common**, aber **bewusstes Non-Goal** (`SPEC-tls.md`: „DNS-01 only, no HTTP-01") — nicht nachziehen, nur als „nicht implementiert" dokumentiert lassen.

### A2. ACME-Konto & Lebenszyklus

- **Ausstellungs-/Erneuerungs-Historie** — **common** — nur `last_issue`/`last_renew_attempt`; keine Historie.
- **ACME-Konto-Verwaltung** (ToS-Zustand, EAB, Konto-Key-Rollover, Staging↔Prod-Migration) — **rare**.
- **ACME-Order/Fortschritt-Status** (pending order, Auth-Liste, Challenge-Fortschritt, „nächster Versuch um") — **rare** — nur `last_error`.
- **Rate-Limit/Quota-Sichtbarkeit** (Retry-After, verbleibende Limits) — **rare** — nur `tls.acme.rate_limited`.
- **ARI-Renewal-Fenster im Status** (RFC 9773 suggested window) — **rare** — ARI intern genutzt, aber nicht im `TlsStatus`.

### A3. Zertifikat-Aktionen

- **Widerruf (revoke)** + Widerrufsgrund — **rare**.
- **Key-Rotation / Re-Key** (erzwungene Neuausstellung) — **rare** — `key_type` konfigurierbar, aber kein Rotate-Flow.
- **Dry-Run / Preflight** (Staging-Testlauf, DNS-/Credential-Check vor Apply) — **rare**.

### A4. Keys / Backup / Trust

- **Zertifikat-Export/Backup** (PEM, fullchain, optional verschlüsselt) — **common** — Private Keys dürfen nicht in config-export, aber reiner Zertifikat-Export fehlt.
- **Bootstrap-Self-Signed-Zertifikat-Status** (eigener not_after/Regenerierung) — **rare** — `TlsStatus` deckt nur ACME-Cert ab.
- **Trust-Pinning** (erwarteten Fingerprint hinterlegen + Mismatch anzeigen) — **rare** — nur Anzeige, kein Pin-Flow.
- **Store-Gesundheit** (Pfad, Permissions, letzter Erfolg, Korruption-Recovery) — **rare** — `tls.store.io`/`tls.store.corrupt` existieren, aber kein Detail.

### A5. DynDNS & DNS

- **Per-Node DynDNS** (Konfig pro Knoten, Node-Inventar) — **common** (per-host) — `SPEC-tls.md` hat „per-node hostname", aber kein per-node Modell in `SPEC-control-api`.
- **IPv6 MAC/EUI-64 / stabile lokale Kennung** — **rare** — nur `ipv4`/`ipv6` booleans.
- **DNS Record-Check / Diagnostik** (dig, Delegation/NS, Propagation, Präsenz-Check) — **rare**.
- **`POST /api/v1/tls/renew` + `/api/v1/tls/dyndns`** — **common** (update now) — `renew_now()` existiert in Rust, kein HTTP-Endpunkt.
- **Ablauf-/Fehler-Notifications** (email/webhook) — **common** — bewusst nur Status-Felder (Assumption 5), kein Kanal.
- **Nächster/letzter Lauf-Zeitstempel** (Renewal + DynDNS) — **common** — nur last_attempt/last_change.
- **Cloudflare „Test connection"** (Token-Scope/Zone-Check vor Speichern) — **rare**.
- **DynDNS `stale`-Flag** — **rare** — Text sagt „stale setzen", aber `TlsStatus` hat kein Feld.
- **Multi-Provider / Multi-Zone** — **rare** — ein Token, eine Zone angenommen.
- **Managed-Record-Inventar** (fremde/pre-existing Records anzeigen/übernehmen) — **rare**.
- **IP-Discovery-Details** (Interface vs echo, IPv6-Präfix-Delegation) — **rare**.

### A6. Security / UI-Vertrag (Interface-Design)

- **Typisiertes TLS-Status-DTO** (JSON-Schema für `GET /api/v1/status` / `/api/v1/tls/status`) — **wichtig** — control-api sagt nur „may expose TlsStatus fields", kein Schema → die UI kann sich an nichts verbindlich binden.
- **Config-Apply/Rollback pro Sub-Block** (Feld-Diff, Partial-Failure für TLS/ACME/DynDNS) — **rare**.
- **TLS-Protokoll/Cipher-Policy** für DNS-Listener (min. TLS-Version, Cipher, ALPN) — **rare**.
- **Zertifikat-Verteilung über Knoten** (per-node cert version, sync-lag) — **rare** — an SPEC-cluster delegiert.
- **API-Listener-TLS/Reverse-Proxy-Modus** auf dem Screen (`control_api.tls`, `trusted_proxies`) — **rare**.
- **DynDNS-Audit-Trail** (welche IP → welcher Record, wann) — **rare**.

---

## B. Prototyp-Lücken — Spec-konform, aber im UI fehlt/falsch

Diese sind **spec-definiert**, aber im Prototyp noch nicht korrekt umgesetzt. → **UI nachziehen**.

1. **`tls.cert.expiring` / `tls.cert.expired`** nicht gerendert — Ablauf immer grün, kein Warn-/Kritisch-Zustand (`SPEC-tls.md` l.242).
2. **`last_error` / `tls.*`-Fehlercodes** nicht gerendert — statischer Bindestrich, keine Feld-Zuordnung, keine Übersetzung.
3. **DynDNS/ACME-Fehler-Banner** fehlt — nur das Self-Signed-Banner existiert.
4. **Viewer-Read-Only-Zustand** fehlt — `Speichern` + alle Felder immer editierbar (Role-Gating nicht abgebildet).
5. **`tls.config.*`-Validierung** fehlt — keine Inline-Fehler im Formular.
6. **Loading/empty/offline/permission/not-ready/error-States** fehlen komplett.
7. **HTTP-01** wird als wählbarer Tab gezeigt, obwohl die Spec es verbietet → als deaktiviert/„nicht unterstützt" rendern, nicht wählbar.
8. **Bestätigungs-Sheet** (`tls-confirm-sheet`) zeigt nur `public_domain`/`acme.directory`/Fingerprint — kein Diff der tatsächlich geänderten Felder, kein DynDNS-Summary.
9. **Custom-ACME-Directory-URL** fehlt (Spec erlaubt `<url>`).
10. **`tls.secret.missing`**-Zustand fehlt (Token-Env fehlt) — Token-Zeile nur maskiert.
11. **Per-Node-Selektor** ist nur im DNS-Tab, aber der Status-Block (DynDNS letzte IPv4/IPv6) ändert sich nicht mit.
12. **`Proxied`** ist ein editierbarer Switch, obwohl die Spec `false` erzwingt → als fix angezeigt/read-only.
13. **`tls.dyndns.entry_conflict`** (zweiter Knoten mit public_entry) nicht dargestellt.
14. **`If-Match`/`config_version`-Konflikt** (412) + Diff für TLS-Writes fehlt.
15. **Non-empty `extra_sans`** ohne Approve-Hinweis (Spec: braucht Owner-Freigabe).
16. **ACME-Konto** zeigt nur „nicht eingerichtet" — kein Fehlercode/State-Enum/Recovery-Hinweis.
17. **Self-Signed-Banner** ist hardcoded, hat keinen Link zu TLS-Einstellungen, verschwindet nicht dynamisch bei `tls_mode=acme`.
18. **Intervall** ohne Jitter/Next-Run-Info.

---

## C. Bereits im Prototyp erledigt (nicht erneut anfassen)

- Status: `tls_mode`, Fingerprint (SF Mono), `not_after`, `days_to_expiry`, SANs, `last_issue`, `last_renew_attempt`, DynDNS letzte IPv4/IPv6.
- Config: `public_domain`, `extra_sans`, `key_type`, `renew_before`, `expiry_warn`, `acme.directory/email/propagation_*`, `cloudflare.zone_id`, `dyndns.*`.
- Quelle-Switcher (Selbstsigniert/ACME/Eigenes Zertifikat) + Challenge-Switcher (DNS-01/HTTP-01) + SAN-Ableitung + per-Node-DynDNS + IPv6-Kennung + Record-Check.
