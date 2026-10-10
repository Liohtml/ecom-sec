# ecomsec – Kompromittierungs-Check für Shop-Systeme

`ecomsec` ist ein in Rust geschriebener **Security Scan / Kompromittierungs-Check** für
E-Commerce-Installationen. Er bildet den Funktionsumfang des JTL-Shop-5-Plugins
„EcomSec Security Scan“ als eigenständiges, plattformunabhängiges Werkzeug nach und
erweitert ihn um weitere Shopsysteme (Shopware 6, Shopify) sowie eine Adapter-
Schnittstelle für beliebige weitere Plattformen.

* **Read-only** – ändert nichts am Shop, sendet keine Daten nach außen, benötigt keinen Root.
* **Ohne SSH nutzbar** – läuft überall dort, wo das Webroot lesbar ist (Shared Hosting, Container, CI).
* **Ein Binary** – keine PHP-Erweiterungen, keine externen Dienste, keine Laufzeitabhängigkeiten.
* **Drei Ansichten** wie im Original: *Security Scan*, *Shop-Integrität*, *Handlungsempfehlungen* –
  als Terminal-Report, JSON, eigenständige HTML-Datei oder lokales Web-Dashboard (hell/dunkel).

> Der Scan ist eine Triage-Hilfe und ersetzt keine forensische Analyse. Ein sauberes Ergebnis ist
> keine Garantie.

---

## Was geprüft wird

### Security Scan (Dateisystem)

| Prüfung | Beschreibung |
|---|---|
| Bekannte Webshell-Dateinamen | IOC-Liste (CISA TA15-314A, NSA/ASD-Webshell-Guidance, MITRE ATT&CK T1505.003): c99/r57/WSO/b374k/Alfa/…, Doppel-Endungen (`bild.jpg.php`), versteckte PHP-Dateien, getarnte Fehlerseiten, Diagnose-Dateien |
| Neue/geänderte Dateien | PHP, `.htaccess`, `.user.ini` mit Änderungszeit ab dem **Referenzdatum** (Standard 17.06.2026 = Veröffentlichung CVE-2026-54390) |
| Zeitstempel-Manipulation | ctime nach Referenzdatum bei zurückdatierter mtime (`touch -r`), Zeitstempel in der Zukunft; Massenvorkommen durch Deployments werden zu einem Hinweis zusammengefasst |
| PHP in Upload-/Medienverzeichnissen | kritisch, plattformspezifische Verzeichnisliste |
| Webserver-Konfiguration | `.htaccess`/`.user.ini`: PHP-Handler für Bilder, `auto_prepend_file`, deaktivierte Sicherheitsfunktionen, fremde RewriteRules, kodierte Blöcke |
| Verdächtige Code-Muster | YARA-ähnliche Regeln: eval/base64-Ketten, China Chopper, Hex-Escapes, Obfuscator-Muster, Reverse Shells, Dropper, Mailer, serverseitige Skimmer, RFI, Polyglot-Bilder, clientseitige Magecart-Skimmer |
| CVE-spezifische Payloads | JTL: rohes SSTI-Muster `{capture}…{eval}`, Modifier-Ketten `|unserialize`/`|file_get_contents`, kompilierte Templates mit Injection; Shopware: Twig-SSTI (`_self.env`, `filter("system")`) |
| Angriffsspuren in Logs | Log-Verzeichnisse werden mit den Payload-Regeln durchsucht |
| Öffentlich erreichbare Dateien | SQL-Dumps, Archive, Konfigurationskopien, Schlüssel, `.env` unterhalb des Public-Roots |
| Integritäts-Baseline | optionales SHA-256-Manifest: geänderte / fehlende / neue Dateien |

### Shop-Integrität

| JTL-Shop 5 | Shopware 6 | Shopify |
|---|---|---|
| CVE-2026-54390-Status: zuerst anhand der Version (5.5.4 / 5.6.2 / 5.7.2 / ≥ 5.8 gepatcht), sonst Prüfung von `MailSmarty`/`SmartyRenderer` (registrierte `unserialize`/`file_get_contents`-Modifier, Härtungsmarker für Back-Patch) – die Bewertung nennt, ob Version oder Datei die Grundlage war | CVE-Status (Twig-SSTI CVE-2023-2017, SQLi CVE-2024-22406) anhand `composer.lock` | – (SaaS) |
| Admin-Konten (`tadminlogin`): letzter Login, 2FA, aktiv, Gruppe; neue/geänderte Konten seit letztem Scan | Backend-Benutzer (`user`), API-Integrationen (`integration`) mit Änderungserkennung | Mitarbeiterkonten (`users.json`, nur Shopify Plus), 2FA-Status |
| PayPal-Empfänger/Händlerkennung (teilmaskiert) mit Änderungserkennung zwischen Scans | Zahlungsanbieter-Schlüssel in `system_config` (PayPal, Mollie, Stripe, …) mit Änderungserkennung | Hinweis auf manuelle Prüfung des Auszahlungskontos |
| Rechte von `config.JTL-Shop.ini.php`, `.htaccess` | Rechte von `.env`, `config/jwt/private.pem`; `APP_ENV` | – |
| E-Mail-Historie (`temailhistory`, 90 Tage) auf Angriffs-Payload in Betreff/Namen | Mail-Templates, Flow-Builder-Sequenzen auf Twig-Payload | Script-Tags, Webhooks (Datenabfluss), Apps & Scopes, Live-Theme (Layout/JS/Snippets) auf Skimmer & Fremdhosts |
| E-Mail-Vorlagen, Kunden-/Kontakt-/Newsletter-/Bestelldaten mit Smarty-Syntax | Snippets, CMS-Elemente, Theme mit `<script>`-Injektionen | Snapshots für Script-Tags/Webhooks/Apps/Staff – Neuzugänge seit letztem Scan sind kritisch |
| Plugins/Cronjobs nach Referenzdatum | Apps/Plugins nach Referenzdatum | Theme-Dateien nach Referenzdatum geändert |

### Handlungsempfehlungen

Priorisierte Checkliste in vier Gruppen: **Zuerst prüfen** (Fehlalarme ausschließen, bevor der Shop
abgeschaltet wird), **Sofortmaßnahmen**, **Kompromittierungs-Prüfung**, **Langfristige Härtung** –
jeweils mit Verweis auf die auslösenden Befunde und plattformspezifischen Ergänzungen.

### Triage / Risikoakzeptanz

Befunde lassen sich einzeln, per Verzeichnis oder per Regel **als unbedenklich markieren** (mit
Begründung). Die Markierung ist an eine stabile Befund-ID gebunden, bleibt über Scans erhalten
und zählt nicht mehr in die Bewertung.

---

## Installation

```bash
cargo build --release
# Binary: target/release/ecomsec
```

Voraussetzungen: Rust ≥ 1.80. Keine Laufzeitabhängigkeiten.

## Schnellstart

```bash
# JTL-Shop 5 oder Shopware 6 werden automatisch erkannt
ecomsec scan --root /var/www/shop

# Ohne Datenbank (z. B. nur Dateisystem per SFTP-Mount)
ecomsec scan --root /var/www/shop --skip-remote

# Shopify (nur Lese-Scopes: read_script_tags, read_themes, read_apps, read_users)
ecomsec scan --platform shopify --shop my-store.myshopify.com --token shpat_…

# Berichte
ecomsec scan --root /var/www/shop --format html --output report.html
ecomsec scan --root /var/www/shop --format json | jq .summary

# Web-Dashboard (Scan starten, Befunde triagieren, Verlauf)
ecomsec serve --root /var/www/shop --bind 127.0.0.1:8787 --auth-token geheim
```

### Shared Hosting / Zeitbudget

Große Shops werden in Etappen gescannt. Mit `--time-budget 45s` bricht der Dateiscan nach 45 s ab,
speichert einen Checkpoint und setzt beim nächsten Aufruf an derselben Stelle fort – analog zur
gestaffelten Abarbeitung des Originals, die 504-Timeouts vermeidet:

```bash
while ! ecomsec scan --root /var/www/shop --time-budget 45s --format json > r.json; do :; done
```

(Exit-Code 0/1/2 je nach Ergebnis, 10 bei Fehlern; siehe unten.)

### Triage

```bash
ecomsec findings list --root /var/www/shop
ecomsec findings accept --root /var/www/shop 5acb77c9c21963b4 --reason "Dump der Agentur, entfernt am 20.06."
ecomsec findings accept --root /var/www/shop --group templates_c --reason "kompilierte Templates"
ecomsec findings accept --root /var/www/shop --rule ctime_newer_than_mtime --reason "Deployment 01.10."
ecomsec findings unaccept --root /var/www/shop --all
```

### Baseline

Nach einer verifizierten Prüfung ein Hash-Manifest anlegen; spätere Scans melden Abweichungen:

```bash
ecomsec baseline create --root /var/www/shop        # alle Code-Dateien
ecomsec baseline create --root /var/www/shop --core-only
ecomsec baseline diff   --root /var/www/shop
```

### Weitere Befehle

```
ecomsec report   [--format text|json|html]   # letzten Report erneut ausgeben
ecomsec history                               # Scan-Verlauf
ecomsec platforms                             # unterstützte Plattformen
ecomsec rules [--tag cve-2026-54390]          # eingebaute Signaturen
```

## Exit-Codes

| Code | Bedeutung |
|---|---|
| 0 | keine Befunde ab dem gewählten Schweregrad |
| 1 | Warnungen (`--fail-on warning`) bzw. Baseline-Abweichung |
| 2 | kritische Befunde (Standard `--fail-on critical`) |
| 10 | Fehler (Plattform nicht erkannt, Konfiguration, I/O) |

Damit eignet sich `ecomsec` für Cron (wöchentlich, wie vom Original empfohlen) und CI.

## Konfiguration

Optional `ecomsec.toml` im Arbeitsverzeichnis, `--config DATEI` oder `$ECOMSEC_CONFIG`
(siehe [`ecomsec.example.toml`](ecomsec.example.toml)):

```toml
[target]
platform = "jtl5"
root = "/var/www/shop"

[scan]
reference_date = "2026-06-17"
time_budget = "45s"
exclude = ["includes/vendor/some-huge-package"]
rule_dirs = ["/etc/ecomsec/rules"]

[shopify]
shop = "my-store.myshopify.com"
token_env = "SHOPIFY_ACCESS_TOKEN"
allow_hosts = ["cdn.my-agency.de"]

[state]
dir = "/var/lib/ecomsec"
```

Zustand (Akzeptanzen, Snapshots, Baseline, Verlauf, letzter Report) liegt als JSON unter
`$ECOMSEC_STATE_DIR`, sonst `$XDG_STATE_HOME/ecomsec`, sonst `~/.local/state/ecomsec`, jeweils in
einem Unterverzeichnis pro Ziel.

## Eigene Regeln

Regeln sind TOML-Dateien im YARA-ähnlichen Format (Strings als Literal oder Regex, Bedingung
`any`/`all`/`N`), siehe [`docs/RULES.md`](docs/RULES.md). Eigene Verzeichnisse per `--rules DIR`.

## Architektur und neue Plattformen

```
crates/
  ecomsec-core        Findings-Modell, Regel-Engine, Dateiscanner (Zeitbudget/Checkpoint),
                      Baseline, Zustand, Empfehlungen, Platform-Trait
  ecomsec-jtl5        Adapter JTL-Shop 5
  ecomsec-shopware6   Adapter Shopware 6
  ecomsec-shopify     Adapter Shopify (Admin API)
  ecomsec-cli         CLI, Text/JSON/HTML-Reports, Web-Dashboard (axum)
```

Ein Adapter implementiert den Trait `ecomsec_core::Platform` (Layout für den Dateiscanner,
Versions-/CVE-Wissen, Patch-Nachweis, Integritätsprüfungen, Zusatzprüfungen, Empfehlungen).
Anleitung: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Hinweise zu Signaturen und Advisories

* Die IOC-Listen und Regeln sind aus öffentlichen Quellen (CISA, NSA/ASD, MITRE, Sansec-Analyse zu
  CVE-2026-54390) zusammengestellt und im Repository versioniert; sie erheben keinen
  Vollständigkeitsanspruch.
* Der dateibasierte Patch-Nachweis für CVE-2026-54390 ist eine Heuristik (registrierte
  Smarty-Modifier bzw. Härtungsmarker im Mail-Renderer). Die Bewertung gibt immer an, ob sie
  auf der Versionsnummer oder auf der geprüften Datei beruht.
* Die Advisory-Datenbank ist bewusst klein und im Code der Adapter hinterlegt; Versionsbereiche
  sind gegen die jeweiligen Hersteller-Advisories zu verifizieren.

## Entwicklung

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all
```

Lizenz: MIT.
