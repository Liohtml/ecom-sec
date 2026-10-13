# ecomsec in CI/CD, Monitoring und Security-Tools

`ecomsec` ist ein einzelnes, statisch gebautes Programm mit maschinenlesbaren Ausgaben und
aussagekräftigen Exit-Codes – damit lässt es sich in jede Pipeline, jeden Cronjob und jedes
Security-Dashboard einbinden. Der Scan bleibt dabei **read-only**: Shop-Dateien und Datenbank
werden nie verändert.

## Ausgabeformate

| Format | Befehl | Wofür |
|---|---|---|
| Text | `--format text` (Standard) | Terminal, Cron-Mails |
| JSON | `--format json` | Monitoring, eigene Auswertungen – stabile Schnittstelle |
| HTML | `--format html --output report.html` | Bericht zum Weitergeben (eine Datei, offline) |
| SARIF 2.1.0 | `--format sarif` | GitHub Code Scanning, GitLab, Azure DevOps, DefectDojo |
| JUnit-XML | `--format junit` | Test-Dashboards (GitLab, Jenkins, Azure DevOps) |
| Markdown | `--format markdown` | PR-/MR-Kommentare, Chat-Benachrichtigungen |
| SBOM | `ecomsec sbom --format cyclonedx\|spdx-json` | Software-Stückliste der Composer-Pakete (Dependency-Track, Trivy, Grype) |

Alle Formate funktionieren auch mit `ecomsec report` (letzten gespeicherten Scan erneut ausgeben,
ohne neu zu scannen).

### SARIF im Detail

* eine Regel pro Befund-Regel (z. B. `ioc_filename`, `php_eval_base64`) mit deutschem Hilfetext
* Schweregrad: kritisch → `error`, Warnung → `warning`, Hinweis → `note`
  (zusätzlich `security-severity` 9.0 / 5.5 / 2.0 für GitHub)
* Dateibefunde mit `physicalLocation` relativ zum Shop-Verzeichnis (`%SRCROOT%`),
  Datenbank-/API-Befunde mit `logicalLocation`
* `partialFingerprints.ecomsecFindingId/v1` = stabile Befund-ID → Dashboards erkennen denselben
  Befund über Scans hinweg
* als unbedenklich markierte Befunde werden mit `suppressions` (Begründung) ausgegeben

### JUnit im Detail

Ein Testfall pro Befund-Kategorie (Webshell, Exploit-Payload, Patch-Status, Admin-Konto, …).
Ein Testfall schlägt fehl, wenn die Kategorie offene kritische Befunde oder Warnungen enthält;
Hinweise und unbedenkliche Befunde stehen in `system-out`. Score und Note stehen in den
`properties` der Test-Suite.

## Exit-Codes

| Code | Bedeutung |
|---|---|
| `0` | keine Befunde ab dem gewählten Schweregrad |
| `1` | Warnungen (nur mit `--fail-on warning`), Baseline-Abweichung (`baseline diff`), Update verfügbar (`self-update --check`) |
| `2` | kritische Befunde (Standard `--fail-on critical`) |
| `10` | Fehler (Plattform nicht erkannt, Konfiguration, I/O, kein Composer-Inventar für `sbom`) |

`--fail-on never` liefert immer `0` (z. B. wenn ein späterer Schritt die Bewertung übernimmt).
Mit `--time-budget` unterbrochene Scans setzen beim nächsten Aufruf fort; der Report kennzeichnet
sie als unvollständig.

## Sicherheitsniveau (Score)

Jeder Report enthält `score` (0–100), `grade` (A–F) und `score_drivers` (die Faktoren, die Punkte
gekostet haben). Die Gewichte sind fest und in `crates/ecomsec-core/src/score.rs` dokumentiert:

| Faktor | Abzug | max. |
|---|---|---|
| offene kritische Befunde (ohne Patch-Status/Dateirechte) | 12 je Befund | 48 |
| offene Warnungen (ohne Patch-Status/Dateirechte) | 2 je Befund | 16 |
| verwundbare Shop-Version (Advisory) | 15 je Advisory | 30 |
| Patch-Status unbekannt | 4 je Advisory | 8 |
| verwundbare Composer-Pakete (OSV, `--online`) | 3 kritisch/hoch, sonst 1 | 12 |
| aktive Admin-Konten ohne 2FA | 10 × Anteil | 10 |
| Konfigurationsdateien mit offenen Rechten | 6 kritisch, 3 Warnung | 9 |
| keine Integritäts-Baseline | 5 | 5 |
| Scan unvollständig (Zeitbudget) | 8 | 8 |
| übersprungene/eingeschränkte Prüfungen | 1 je Prüfung | 4 |

Mit offenen kritischen Befunden ist der Score höchstens 49 (Note D oder schlechter), mit offenen
Warnungen höchstens 89 (Note B oder schlechter). Noten: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40.
Der Verlauf (`ecomsec history`, Dashboard › *Hilfe & Service*) zeigt die Entwicklung.

```bash
ecomsec report --format json | jq '{score, grade, drivers: [.score_drivers[:3][] | .label]}'
```

## GitHub Actions

Typischer Aufbau: der Shop (oder ein Abbild davon, z. B. aus einem Deployment-Artefakt) liegt im
Workspace; `ecomsec` scannt und lädt das Ergebnis in GitHub Code Scanning hoch.

```yaml
name: ecomsec
on:
  push:
  schedule:
    - cron: "30 4 * * 1"   # wöchentlich, Montag 04:30 UTC

permissions:
  contents: read
  security-events: write   # für upload-sarif

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: ecomsec installieren
        run: curl -fsSL https://raw.githubusercontent.com/liohtml/ecom-sec/main/install.sh | sh

      - name: Scan (SARIF)
        id: scan
        # Exit-Code merken, damit der Upload auch bei Befunden läuft.
        run: |
          set +e
          ecomsec scan --root . --skip-remote --state-dir .ecomsec-state \
            --format sarif --output ecomsec.sarif
          echo "code=$?" >> "$GITHUB_OUTPUT"

      - name: SARIF hochladen
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ecomsec.sarif
          category: ecomsec

      - name: Zusammenfassung
        if: always()
        run: ecomsec report --root . --state-dir .ecomsec-state --format markdown >> "$GITHUB_STEP_SUMMARY"

      - name: Bei kritischen Befunden fehlschlagen
        if: steps.scan.outputs.code != '0'
        run: |
          echo "ecomsec meldet Exit-Code ${{ steps.scan.outputs.code }} (2 = kritisch, 10 = Fehler)"
          exit 1
```

Hinweise:

* Code Scanning zeigt Dateibefunde direkt an der Datei; Befunde ohne Datei (Datenbank, Advisories)
  erscheinen ohne Codeposition.
* Damit Risikoakzeptanzen (`findings accept`) in CI wirken, das State-Verzeichnis (`--state-dir`)
  zwischen Läufen erhalten, z. B. mit `actions/cache`, oder die Befunde per Regel/Verzeichnis
  akzeptieren und `accepted.json` versionieren.
* Für einen PR-Kommentar `--format markdown` in eine Datei schreiben und z. B. mit
  `gh pr comment --body-file` posten.

## GitLab CI

Das Container-Image ist distroless (ohne Shell) und eignet sich daher nicht als `image:` für
`script:`-Jobs. In GitLab das Binary per `install.sh` in ein kleines Image installieren:

```yaml
ecomsec:
  image: alpine:3
  before_script:
    - apk add --no-cache curl
    - curl -fsSL https://raw.githubusercontent.com/liohtml/ecom-sec/main/install.sh | sh
  script:
    # Exit-Code merken, Berichte trotzdem erzeugen
    - code=0; ecomsec scan --root "$CI_PROJECT_DIR" --skip-remote --state-dir .ecomsec-state --format junit --output ecomsec-junit.xml || code=$?
    - ecomsec report --root "$CI_PROJECT_DIR" --state-dir .ecomsec-state --format sarif --output gl-ecomsec.sarif
    - ecomsec report --root "$CI_PROJECT_DIR" --state-dir .ecomsec-state --format markdown
    - exit $code
  artifacts:
    when: always
    reports:
      junit: ecomsec-junit.xml
    paths:
      - ecomsec-junit.xml
      - gl-ecomsec.sarif
  cache:
    key: ecomsec-state
    paths:
      - .ecomsec-state/
```

Im Merge Request erscheinen die Kategorien dann als Testfälle („Bekannte Webshell“,
„Patch-Status“, …); fehlgeschlagene Kategorien listen die betroffenen Befunde.

## SBOM

```bash
ecomsec sbom --root /var/www/shop --format cyclonedx --output sbom.cdx.json
ecomsec sbom --root /var/www/shop --format spdx-json --output sbom.spdx.json --no-dev
```

Grundlage ist das Composer-Inventar der Installation (Shopware: `composer.lock` bzw.
`vendor/composer/installed.json`; JTL-Shop: `includes/vendor/composer/installed.json`). Jede
Komponente erhält eine Package-URL (`pkg:composer/vendor/name@version`) und – soweit im Inventar
hinterlegt – die deklarierten Lizenzen. Für Shopify gibt es kein Inventar; der Befehl bricht dann
mit Exit-Code 10 ab. Die SBOM lässt sich z. B. in Dependency-Track importieren oder mit
`grype sbom:sbom.cdx.json` prüfen.

## Docker

```bash
docker run --rm -v /var/www/shop:/shop:ro -v ecomsec-state:/state \
  ghcr.io/liohtml/ecom-sec:latest scan --skip-remote --format sarif > ecomsec.sarif
```

Details zu Volumes, Benutzer und Dashboard: [docker/README.md](../docker/README.md).

## Pre-Commit / Deployment-Hook

Vor dem Ausrollen eines Shop-Updates prüfen, ob das Paket selbst sauber ist:

```bash
#!/bin/sh
# .git/hooks/pre-push oder Deployment-Skript
ecomsec scan --root ./build --skip-remote --skip-baseline --dry-run --format markdown --fail-on critical
```

`--dry-run` speichert weder Report noch Verlauf, `--skip-baseline` verhindert Vergleiche mit der
Baseline des Live-Systems.

## Aktualisieren

```bash
ecomsec self-update --check   # nur prüfen (Exit-Code 1, wenn ein Update verfügbar ist)
ecomsec self-update           # neueste Version laden, SHA-256 prüfen, Binary ersetzen
```

`self-update` fragt `api.github.com` nach dem neuesten Release, lädt das Paket für die laufende
Plattform sowie `SHA256SUMS`, prüft die Prüfsumme und ersetzt das Binary atomar (Windows: die alte
Version wird als `ecomsec.exe.old` beiseitegelegt). Bei GitHub-Ratenlimits hilft
`GITHUB_TOKEN=… ecomsec self-update`. Liegt das Binary in einem Systemverzeichnis, ist `sudo`
nötig. Neben `--online` und `advisories update` ist dies die einzige Funktion mit Netzwerkzugriff.
