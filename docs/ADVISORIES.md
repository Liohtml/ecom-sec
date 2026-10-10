# Schwachstellen-Datenbank (Advisories)

ecomsec kennt drei Quellen für bekannte Schwachstellen:

| Quelle | Aktualität | Wo |
|---|---|---|
| **Eingebettete Dateien** `advisories/<platform>.toml` | Stand des Builds | im Binary, immer aktiv |
| **Heruntergeladene Dateien** (`ecomsec advisories update`) | Stand von `main` im Repository | `<State-Dir>/advisories/`, bei jedem Scan automatisch gemergt |
| **OSV.dev** (`ecomsec scan --online`) | tagesaktuell | prüft alle Composer-Pakete (Shopware-Core, Plugins, Symfony, Smarty …); sendet nur Paketname + Version |

Einträge aus heruntergeladenen oder per `--advisories DIR` angegebenen Dateien überschreiben
eingebettete Einträge mit derselben `id`.

```bash
ecomsec advisories list                 # was ist geladen?
ecomsec advisories update               # neueste Fassung aus dem Repository holen
ecomsec advisories lint advisories/     # Dateien prüfen (läuft auch in der CI)
ecomsec scan --root /var/www/shop --online   # zusätzlich OSV.dev abfragen
```

## Dateiformat

```toml
[[advisory]]
id = "CVE-2026-54390"              # CVE- oder GHSA-ID, eindeutig
platform = "jtl5"                  # jtl5 | shopware6 | shopify
title = "Unauthentifizierte Smarty Template Injection (SSTI) mit RCE ab 5.4.0"
severity = "critical"              # critical | warning | info
score = 9.8                        # optional, CVSS
affected = [">=5.2.0 <5.5.4", ">=5.6.0 <5.6.2", ">=5.7.0 <5.7.2"]
fixed_in = ["5.5.4", "5.6.2", "5.7.2"]
backpatch_note = "…"               # optional
reference = "https://…"            # Primärquelle
published = 2026-06-17
tags = ["ssti", "rce"]
source = "https://nvd.nist.gov/vuln/detail/CVE-2026-54390"   # optional
aliases = ["GHSA-…"]               # optional, für den Sync-Abgleich
withdrawn = false                  # true: bleibt dokumentiert, wird nicht bewertet
draft = false                      # true: Entwurf, wird nicht bewertet
```

Versionsbereiche: `>=a <b`, `<b`, `>=a`, exakte Version `5.7.1`, `*`. `<=` ist nicht erlaubt
(obere Grenze immer exklusiv = erste behobene Version). `fixed_in` darf nicht innerhalb eines
`affected`-Bereichs liegen; `ecomsec advisories lint` prüft das.

Die Bewertung im Scan: Liegt die Shop-Version in keinem Bereich und ist mindestens so hoch wie
eine `fixed_in`-Version, gilt der Eintrag als gepatcht. Liegt sie in einem Bereich, fragt die
Engine den Plattform-Adapter nach einem dateibasierten Nachweis (z. B. Back-Patch), bevor sie
„verwundbar“ meldet.

## Automatische Pflege

Der Workflow `.github/workflows/advisories.yml` läuft wöchentlich (und per Hand):

1. **Sync** – `scripts/advisory_sync.py` fragt die NVD-API (Stichworte und CPEs für JTL-Shop,
   Shopware, Shopify-Apps) und OSV.dev (Shopware-Composer-Pakete) nach Einträgen ab, die in den
   letzten 30 Tagen angelegt oder geändert wurden. Bekannte IDs (`advisories/*.toml`, `aliases`)
   und `advisories/ignored.toml` werden ausgefiltert. Ergebnis: `advisories/candidates.json`
   und Entwürfe unter `advisories/drafts/` (`draft = true`, daher inaktiv).
2. **Agent** – mit hinterlegtem Secret `ANTHROPIC_API_KEY` recherchiert ein Claude-Code-Agent
   jeden Kandidaten in den Primärquellen, ergänzt Versionsbereiche und behobene Versionen,
   trägt passende Einträge in `advisories/<platform>.toml` ein, nicht zutreffende in
   `ignored.toml`, lässt `advisories lint` und die Tests laufen und öffnet einen Pull Request.
   Der Agent darf ausschließlich Dateien unter `advisories/` ändern.
3. **Fallback** – ohne API-Key entsteht ein Pull Request nur mit den Entwürfen.

In beiden Fällen entscheidet ein Mensch per Review und Merge. Erst nach dem Merge auf `main`
erreichen die Einträge die Nutzer – per `ecomsec advisories update` sofort, per Release im
Binary.

Benötigte Secrets: `ANTHROPIC_API_KEY` (Agent), optional `NVD_API_KEY` (höheres Rate-Limit).

## Grenzen

- Für JTL-Shop und JTL-Plugins gibt es keine maschinenlesbare Hersteller-Quelle; der Sync
  findet nur, was in NVD landet. Forum-Ankündigungen muss der Agent oder ein Mensch nachtragen.
- Shopify-Apps und -Themes haben keine Schwachstellen-Datenbank; hier bleibt die
  Risikobewertung nach Berechtigungen und Herkunft im Scan.
- OSV deckt nur Composer-Pakete ab, keine JTL-Plugins aus dem Extension Store.
