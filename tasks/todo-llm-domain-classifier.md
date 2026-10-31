# Todo: LLM-Klassifikator für unbekannte Domains (nicht implementiert)

Idee: Domains, die in keiner Blockliste stehen, per LLM (OpenRouter) als
Tracking/Werbung/Malware/unkritisch einstufen lassen. Nur Vorschlag an den Owner,
kein Auto-Block.

## Festlegungen

- Bekannte Tracker/Werbung kommen weiter aus Listen (Hagezi, OISD, EasyPrivacy, …) über
  `dnscraft-filtering` (fetch/parser/scheduler). Das LLM ersetzt sie nicht.
- Niemals im DNS-Hot-Path: asynchron, Ergebnis pro registrierbarer Domain cachen.
- Datenschutz: Domains verlassen das Haus → opt-in, nur unbekannte Domains, nur eTLD+1,
  keine Client-/Node-Infos im Prompt.

## Bereits gebaut: Tracker-Datenbank (Enrichment)

Kategorie/Name pro Domain aus AdGuards `trackers.json` (whotracks.me), Laufzeit-Download,
Cache im Services-Verzeichnis, Lookup beim Auslesen (`TrackerDb`, `FilterEngine::trackers`),
Badge in Query-Log-Tabelle/-Karten/-Detail und pro CNAME-Hop. Siehe
`crates/dnscraft-filtering/src/trackers.rs`.

- Erledigt: `[trackers] enabled`/`url` in der Binary-Konfiguration (Neustart nötig); Lizenzhinweis
  (CC BY-NC-SA 4.0, nur nicht-kommerziell) in `crates/dnscraft/README.md`.
- Erledigt: `trackerKind` trennt Tracking (Werbung, Analyse, Telemetrie, Social) von funktional
  (CDN, Hosting, essenziell, …); farbige Kategorie im Badge, Hinweis im Regel-Sheet beim Freigeben.
- Offen: „Seite kaputt“-Modus (geblockte Domains der letzten ~60 s je Client, funktionale zuerst).

## Aufgaben

- [ ] **E1** Eval vor dem Bau: Query-Log-Domains gegen Hagezi als Ground Truth, Kandidaten-
      Modelle (Free-Tier vs. günstiges Bezahlmodell) auf Precision/Recall vergleichen.
      Aktuelle OpenRouter-Free-Limits und Prompt-Logging-Policy prüfen.
- [ ] **E2** Signale zusätzlich zum Domainnamen mitgeben: CNAME-Kette (wird bereits
      geloggt), Domain-Alter, TLD.
- [ ] **E3** Worker + Cache (Tabelle `domain_classification`: domain, label, confidence,
      model, ts), Rate-Limit, Backoff.
- [ ] **E4** Web-UI: Vorschlagsliste „Unbekannte Domains, wahrscheinlich Tracking“ mit
      Übernehmen/Verwerfen.
