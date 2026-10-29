# Todo: mehrere Ziele pro Name (CNAME, Round-Robin)

Wunsch (Owner, 2026-10-29): ein Name soll mehrere Ziele haben können, auch bei CNAME.

## Randbedingungen
- DNS erlaubt pro Name genau einen CNAME; Cloudflare lehnt mehrere ab. Mehrere Ziele sind daher **nur lokal** möglich.
- Antwort pro Query: **ein** CNAME-Ziel, rotierend (Round-Robin), nie mehrere CNAMEs in einer Antwort.
- A/AAAA/TXT/MX/SRV dürfen regulär mehrere Werte im RRset haben.

## Heute
- `ViewRecordConfig.rdata` ist ein einzelner `RData` (`crates/dnscraft-policy/src/config.rs`), Wire `rdata: String`.
- `overrides: BTreeMap<ViewId, Option<RData>>` ebenfalls einzelwertig.
- UI: Schlüssel ist `name+type`, eine Zeile pro Eintrag (`web/src/routes/names/+page.svelte`).

## Offen
- [ ] Policy-Modell: `rdata` → Liste (rückwärtskompatibel: String bleibt gültig), Overrides analog.
- [ ] Resolver (`local_zones.rs`): Mehrfachwerte ausliefern; CNAME rotierend, A/AAAA als RRset.
- [ ] Control-API `/policy/records`: Liste lesen/schreiben.
- [ ] UI-Editor: mehrere Werte je Name/Typ; Cloudflare-Seite bleibt Einzelwert (Hinweis bei CNAME).
- [ ] SPEC-policy / SPEC-web-ui: Verhalten dokumentieren.

Abhängigkeit: erst nach der Zonenauswahl auf der Namen-Seite (gleiche Datei).
