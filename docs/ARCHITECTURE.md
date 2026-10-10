# Architektur und Erweiterung um neue Plattformen

## Überblick

```
┌──────────────┐    ┌─────────────────────────────────────────────┐
│ ecomsec-cli  │───▶│ ecomsec-core                                │
│ CLI / Web UI │    │  Engine ─▶ FileScanner (IOC, Regeln,        │
│ Text/JSON/   │    │            Zeitstempel, Uploads, Exposed)   │
│ HTML-Report  │    │         ─▶ Advisories (Version + Evidence)  │
└──────────────┘    │         ─▶ Platform::integrity()            │
        │           │         ─▶ Platform::additional_checks()    │
        ▼           │         ─▶ Baseline-Diff                    │
┌──────────────┐    │         ─▶ Risikoakzeptanz, Empfehlungen    │
│ Adapter      │◀───│  StateStore (JSON pro Ziel)                 │
│ jtl5 / sw6 / │    └─────────────────────────────────────────────┘
│ shopify      │
└──────────────┘
```

Alles ist synchron und read-only. Die Engine kennt keine Plattform-Details; alles
Plattformspezifische kommt über den Trait `ecomsec_core::Platform`.

## Der Trait `Platform`

```rust
pub trait Platform: Send + Sync {
    fn info(&self) -> PlatformInfo;                                   // Pflicht
    fn file_scan_profile(&self) -> Option<FileScanProfile> { None }   // self-hosted
    fn rules(&self) -> RuleSet { RuleSet::empty() }                   // eigene Inhaltsregeln
    fn advisories(&self) -> Vec<Advisory> { vec![] }                  // CVE-Datenbank
    fn patch_evidence(&self, adv: &Advisory, ctx: &PlatformContext) -> Option<PatchEvidence> { None }
    fn integrity(&self, ctx: &PlatformContext) -> Result<IntegrityReport> { Ok(default) }
    fn additional_checks(&self, ctx: &PlatformContext) -> Result<Vec<Finding>> { Ok(vec![]) }
    fn recommendations(&self, report: &Report) -> Vec<Recommendation> { vec![] }
}
```

| Methode | Zweck |
|---|---|
| `info` | Id, Name, Art (`SelfHosted`/`Hosted`), erkannte Version, Webroot bzw. Ziel, Details |
| `file_scan_profile` | Webroot, Public-Root, ausgeschlossene/generierte/Upload-/Log-/Kern-Verzeichnisse, sensible Konfigurationsdateien, Template-Endungen |
| `rules` | zusätzliche Regeln (z. B. CVE-Payloads der Template-Engine) – werden mit den Kernregeln zusammengeführt |
| `advisories` | bekannte Schwachstellen mit betroffenen Versionsbereichen und Fix-Versionen |
| `patch_evidence` | wird nur gefragt, wenn die Version fehlt oder im betroffenen Bereich liegt: dateibasierter Nachweis (Back-Patch, entfernte gefährliche Funktionen) |
| `integrity` | Zeilen für die Ansicht „Shop-Integrität“ (`IntegrityItem`) plus daraus abgeleitete Findings und Einschränkungen |
| `additional_checks` | weitere Findings (E-Mail-Historie, API-Scans …) |
| `recommendations` | plattformspezifische Empfehlungen, die in die vier Gruppen einsortiert werden |

`PlatformContext` liefert Referenzdatum, `skip_remote` und den `StateStore` für Snapshots
(`ctx.state.snapshot("key")` / `save_snapshot`), mit denen Änderungen zwischen Scans erkannt werden
(neue Admin-Konten, geänderte Zahlungsempfänger, neue Script-Tags …).

## Neue Plattform in fünf Schritten

1. **Crate anlegen**: `crates/ecomsec-<id>/` mit Abhängigkeit auf `ecomsec-core`
   (plus `mysql` für MySQL-Shops oder `ureq` für APIs). In `Cargo.toml` des Workspace eintragen.
2. **Erkennung und Öffnen**: `fn detect(root: &Path) -> bool` und `fn open(...) -> Result<Self>`
   (Konfiguration parsen, Version ermitteln). Für DB-Zugangsdaten gibt es
   `ecomsec_core::db::DbCredentials` (`from_url`, `connect`) und Helfer `query_rows`,
   `table_exists`, `columns`, `col`.
3. **`Platform` implementieren**. Findings mit `Finding::new(...)` (DB/API) oder
   `Finding::file(...)` (Dateien) erzeugen; die Befund-ID wird stabil aus Kategorie, Regel und
   Subjekt abgeleitet – Subjekte daher deterministisch wählen (Tabellenname + Primärschlüssel,
   relativer Pfad, API-Id).
4. **Regeln** als eingebettete TOML (`include_str!`) in `rules()` zurückgeben, siehe
   [RULES.md](RULES.md).
5. **Registrieren** in `crates/ecomsec-cli/src/platforms.rs` (`PLATFORMS`, `detect`, `TargetSpec::open`).

Für die Bewertung von Advisories reicht meist die Versionsnummer. Wenn ein Hersteller
Back-Patches ohne Versionssprung verteilt, liefert `patch_evidence` die zweite Meinung; die
Engine schreibt in die Begründung, ob Version oder Datei die Grundlage war.

## Zustand

Pro Ziel (`<platform>-<hash(root|shop)>`) im State-Verzeichnis:

| Datei | Inhalt |
|---|---|
| `accepted.json` | Risikoakzeptanzen (Befund-ID → Subjekt, Begründung, Zeit) |
| `snapshot-*.json` | Adapter-Snapshots für Änderungserkennung |
| `baseline.json` | Hash-Manifest |
| `checkpoint.json` | Fortsetzungspunkt des Dateiscans (max. 24 h gültig) |
| `history.json` | Scan-Verlauf (max. 200 Einträge) |
| `last-report.json` | letzter vollständiger Report |

## Report-Schema

`Report` (Version 1) enthält `platform`, `reference_date`, `verdict`, `summary`, `findings[]`,
`integrity[]`, `advisories[]`, `recommendations[]`, `limitations[]`. Der HTML-Report und das
Web-Dashboard rendern dasselbe JSON; `--format json` ist daher die stabile Schnittstelle für
Monitoring und Weiterverarbeitung.
