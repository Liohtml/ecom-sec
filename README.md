<p align="center">
  <img src="docs/img/hero.gif" alt="ecomsec – Kompromittierungs-Check für deinen Online-Shop" width="100%">
</p>

<h1 align="center">ecomsec Security Scan</h1>

<p align="center">
  <b>Wurde mein Shop gehackt?</b> – In unter einer Minute Klarheit. Für JTL-Shop 5, Shopware 6, WooCommerce, Magento 2 und Shopify.
</p>

<p align="center">
  <a href="#-in-2-minuten-loslegen">Loslegen</a> ·
  <a href="#-das-bekommst-du">Funktionen</a> ·
  <a href="#-täglich-automatisch-prüfen">Überwachung</a> ·
  <a href="#-screenshots">Screenshots</a> ·
  <a href="#-häufige-fragen">FAQ</a> ·
  <a href="#-unterstützte-shopsysteme">Shopsysteme</a> ·
  <a href="#-ki-audit-optional">KI-Audit</a> ·
  <a href="docs/ARCHITECTURE.md">Für Entwickler</a>
</p>

<p align="center">
  <a href="https://crates.io/crates/ecomsec"><img alt="crates.io" src="https://img.shields.io/crates/v/ecomsec?logo=rust&label=crates.io"></a>
  <a href="https://crates.io/crates/ecomsec"><img alt="Downloads" src="https://img.shields.io/crates/d/ecomsec?label=Downloads"></a>
  <img alt="Kostenlos" src="https://img.shields.io/badge/Preis-kostenfrei-2ea44f">
  <img alt="Lizenz MIT" src="https://img.shields.io/badge/Lizenz-MIT-blue">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-1.80%2B-orange">
  <img alt="Read-only" src="https://img.shields.io/badge/Zugriff-nur%20lesend-informational">
  <img alt="Plattformen" src="https://img.shields.io/badge/JTL--Shop%205%20%C2%B7%20Shopware%206%20%C2%B7%20WooCommerce%20%C2%B7%20Magento%202%20%C2%B7%20Shopify-unterst%C3%BCtzt-6f42c1">
</p>

---

## 🔎 Was ist das?

`ecomsec` ist ein **Kompromittierungs-Check** für Online-Shops. Er durchsucht deine Installation
nach Spuren eines Angriffs – Webshells, Hintertüren, manipulierte Dateien, fremde Admin-Konten,
umgeleitete Zahlungen – und sagt dir in einer klaren Ampel, ob du handeln musst.

Entstanden ist das Werkzeug als Antwort auf die aktiv ausgenutzte Sicherheitslücke
**CVE-2026-54390** in JTL-Shop 5. Es prüft, ob dein Shop gepatcht ist **und** ob vorher schon
jemand drin war.

|   |   |
|---|---|
| ✅ **Nur lesend** | Es wird nichts verändert, nichts gelöscht, nichts nach außen gesendet. |
| ✅ **Ohne SSH, ohne Root** | Läuft überall, wo das Shop-Verzeichnis lesbar ist – auch auf Shared Hosting. |
| ✅ **Ein einziges Programm** | Keine Installation von PHP-Erweiterungen, Datenbanken oder Diensten. |
| ✅ **Verständliche Ergebnisse** | Drei Ansichten: *Security Scan*, *Shop-Integrität*, *Handlungsempfehlungen*. Deutsch, mit konkreten nächsten Schritten. |
| ✅ **Fehlalarme im Griff** | Bekannte, harmlose Befunde markierst du einmal als unbedenklich – sie zählen dann nie wieder mit. |

> **Wichtig:** Der Scan ist eine schnelle Triage-Hilfe. Ein kritischer Befund ist ein klares
> Warnsignal; ein sauberes Ergebnis ist keine Garantie. Bei bestätigtem Verdacht gehört eine
> forensische Analyse dazu.

---

## 🚀 In 2 Minuten loslegen

**1. Programm holen**

Fertiges Binary aus den [Releases](../../releases) laden – oder selbst bauen (benötigt [Rust](https://rustup.rs)):

```bash
cargo build --release
# → target/release/ecomsec
```

**2. Scan starten** (JTL-Shop 5, Shopware 6, WooCommerce/WordPress und Magento 2 werden automatisch erkannt)

```bash
ecomsec scan --root /var/www/shop
```

**3. Ergebnis lesen**

```
■ Kritische Befunde – sofort handeln
Befunde: 3 kritisch · 2 Warnungen · 0 Hinweise · 0 als unbedenklich markiert
```

| Ampel | Bedeutung | Was tun? |
|---|---|---|
| 🔴 **Kritisch** | Webshell, Exploit-Spur, ungepatchte Lücke, neues Admin-Konto, geänderter Zahlungsempfänger | Befund prüfen (Tab *Handlungsempfehlungen* › *Zuerst prüfen*), dann Sofortmaßnahmen |
| 🟡 **Warnung** | Geänderte Dateien, offene Dateirechte, Backups im Webroot, Konten ohne 2FA | Zeitnah prüfen, bekannte Fälle als unbedenklich markieren |
| 🟢 **Keine kritischen Befunde** | Alles im grünen Bereich | Baseline anlegen, [täglich automatisch prüfen](#-täglich-automatisch-prüfen) |

**Mehr Komfort?** Das Dashboard im Browser starten:

```bash
ecomsec serve --root /var/www/shop
# → http://127.0.0.1:8787
```

---

## 📦 Installation & Updates

**Linux & macOS – ein Befehl** (erkennt System und Prozessor, prüft die SHA-256-Prüfsumme,
installiert nach `/usr/local/bin` bzw. `~/.local/bin`):

```bash
curl -fsSL https://raw.githubusercontent.com/liohtml/ecom-sec/main/install.sh | sh
# bestimmte Version / eigenes Verzeichnis:
curl -fsSL https://raw.githubusercontent.com/liohtml/ecom-sec/main/install.sh | sh -s -- --version v0.2.0 --dir ~/bin
```

**Mit Rust-Toolchain** (alle Plattformen, baut aus den Quellen von [crates.io](https://crates.io/crates/ecomsec)):

```bash
cargo install ecomsec --locked
```

**Windows:** ZIP-Paket `ecomsec-<version>-x86_64-pc-windows-msvc.zip` aus den [Releases](../../releases)
laden und `ecomsec.exe` entpacken. Jedes Release enthält `SHA256SUMS` zum Prüfen.

**Docker** (Image `ghcr.io/liohtml/ecom-sec`, 19 MB, für amd64 und arm64; Shop read-only eingehängt,
Zustand im Volume – Details und Compose-Beispiele in [docker/README.md](docker/README.md)):

```bash
# einmaliger Scan
docker run --rm -v /var/www/shop:/shop:ro -v ecomsec-state:/state ghcr.io/liohtml/ecom-sec scan --skip-remote

# oder mit Docker Compose (Scan, Dashboard, tägliche Überwachung) – docker-compose.yml liegt im Repository
docker compose run --rm scan
docker compose up -d dashboard
```

**Aktualisieren:**

```bash
ecomsec self-update --check   # nur nachsehen
ecomsec self-update           # neueste Version laden, Prüfsumme prüfen, Programm ersetzen
```

---

## 🧰 Das bekommst du

### 1 · Security Scan – findet, was nicht in deinen Shop gehört

- **Bekannte Webshell-Namen** aus den IOC-Listen von CISA, NSA und MITRE (c99, r57, WSO, b374k, Alfa …) sowie typische Tarnungen wie `bild.jpg.php` oder versteckte `.dateien.php`
- **Neue oder geänderte PHP-Dateien** seit dem Referenzdatum (Standard: 17.06.2026, Veröffentlichung von CVE-2026-54390) – inklusive Erkennung **zurückdatierter Zeitstempel**
- **PHP in Upload- und Bilderverzeichnissen** – dort hat ausführbarer Code nichts verloren
- **Manipulierte `.htaccess` / `.user.ini`**, die Bilder als PHP ausführen oder Code in jede Seite einschleusen
- **Verdächtige Code-Muster** mit YARA-ähnlichen Regeln: `eval(base64_decode(…))`, China Chopper, Hex-Verschleierung, Reverse Shells, Dropper, Spam-Mailer, Karten-Skimmer
- **CVE-2026-54390-Angriffsmuster** (`{capture}…{eval}`, gefährliche Smarty-Modifier) in Dateien, kompilierten Templates und Logs
- **WordPress-/WooCommerce-Hintertüren** (versteckte Admin-Anlage, Login-Bypass, Must-Use-Plugins, Schein-Plugins, `.ico`-Loader) und **Magecart-Skimmer** in WooCommerce- und Magento-Checkouts, RequireJS-Konfigurationen und CMS-Inhalten
- **Öffentlich erreichbare Backups, Datenbank-Dumps und Konfigurationskopien**
- **Angriffsspuren in Webserver-Logs:** `--access-log auto` (oder ein Pfad) durchsucht Apache-/nginx-Access-Logs inklusive `.gz`-Rotationen nach den Anfragemustern veröffentlichter Lücken – z. B. `/admin/logout?safemode=`, `rmaSummary` per GET oder eingeschleuste Consent-Namen – mit Zeitraum und Absender-IPs

### 2 · Shop-Integrität – ist dein Shop noch deiner?

- **Patch-Status** für CVE-2026-54390: zuerst anhand der Version (5.5.4 / 5.6.2 / 5.7.2 / ab 5.8), sonst anhand der geprüften Datei – das Ergebnis sagt immer, worauf es beruht
- **Alle JTL-Sicherheitsupdates bis 5.8.2** (Oktober 2026): gespeichertes XSS in der Consent-Statistik (CVE-2026-103904), Wartungsmodus per URL (CVE-2026-103905), Path Traversal, IDOR im Retouren-Modul, XSS in „Passwort vergessen“ und im Backend. Eingespielte Patch-Dateien werden **direkt im Code** erkannt, die Prüfmerkmale stammen aus dem öffentlichen JTL-Quellcode und sind gegen jedes Release von 5.0 bis 5.8.2 getestet
- **Eingeschleuste Consent-Namen** in der Datenbank (Spur von CVE-2026-103904) samt Bereinigungs-Hinweis
- **Patch-Status für WordPress, WooCommerce und Magento** inklusive Patch-Level (`2.4.6-p6`) – z. B. CosmicSting, SessionReaper, WP_Query-SQL-Injection, WooCommerce-Store-API
- **Zahlungs-, URL- und Script-Einstellungen in der Datenbank** (Head-/Footer-Scripts, `siteurl`, Basis-URLs, Webhooks, API-Schlüssel) mit Änderungserkennung zwischen zwei Scans
- **Admin-Konten** mit letztem Login und 2FA-Status; **neue Konten seit dem letzten Scan** werden kritisch gemeldet
- **PayPal-Empfängerkonto** (teilmaskiert) mit Änderungserkennung zwischen zwei Scans
- **E-Mail-Historie der letzten 90 Tage** auf eingeschleuste Angriffs-Payloads
- **E-Mail-Vorlagen, Kunden- und Kontaktdaten** mit Template-Syntax
- **Dateirechte** der Konfigurationsdatei, **Plugins und Cronjobs**, die nach dem Referenzdatum hinzukamen
- Optional eine **Baseline**: ein Fingerabdruck aller Kerndateien, gegen den spätere Scans vergleichen

### 3 · Handlungsempfehlungen – was jetzt zu tun ist

Eine priorisierte Checkliste in vier Gruppen: **Zuerst prüfen** (Fehlalarme ausschließen, bevor
der Shop abgeschaltet wird), **Sofortmaßnahmen**, **Kompromittierungs-Prüfung** und
**Langfristige Härtung** – jeder Punkt verweist auf die Befunde, die ihn ausgelöst haben.

### Außerdem

- **Risikoakzeptanz:** Befunde einzeln, pro Verzeichnis oder pro Regel als unbedenklich markieren, mit Begründung. Bleibt über alle künftigen Scans erhalten.
- **Berichte:** Terminal, JSON (für Monitoring), eine einzelne HTML-Datei zum Weitergeben sowie SARIF, JUnit und Markdown für CI und Security-Dashboards.
- **Shared-Hosting-tauglich:** Mit `--time-budget 45s` scannt `ecomsec` in Etappen und setzt beim nächsten Aufruf fort – kein Timeout, keine Last.
- **Hell und dunkel:** Dashboard und HTML-Bericht folgen deinem System oder per Klick.
- **Scan-Verlauf:** Jeder Lauf wird mit Ergebnis gespeichert, damit du Veränderungen siehst – `ecomsec diff` zeigt, was seit dem letzten Scan neu oder verschwunden ist.
- **Überwachung mit Benachrichtigung:** `ecomsec watch` per cron oder systemd meldet sich nur bei Änderungen – per E-Mail, Slack, Teams, Discord, Mattermost, ntfy, Telegram oder Webhook.
- **Aktuelle Schwachstellen:** Die Advisory-Datenbank liegt als Datei im Repository, wird wöchentlich von einem Agenten nachgepflegt und lässt sich ohne neues Release per `ecomsec advisories update` holen. Mit `--online` prüft der Scan zusätzlich alle Composer-Pakete (Shopware-Core, Plugins, Symfony, Smarty …) tagesaktuell gegen OSV.dev.

---

## 📸 Screenshots

<p align="center"><img src="docs/img/terminal.png" alt="Scan-Ergebnis im Terminal" width="92%"></p>
<p align="center"><i>Scan im Terminal: Kopfkarte mit Ampel, Sicherheitsniveau und Score-Treibern, danach die Befunde nach Schweregrad mit Kategorie, Fundort, ID und Beweiszeilen – am Ende die nächsten Befehle.</i></p>

<p align="center"><img src="docs/img/report.png" alt="HTML-Bericht – Zusammenfassung" width="92%"></p>
<p align="center"><i>HTML-Bericht (<code>ecomsec report --format html</code>): eine einzelne Datei zum Weitergeben und Drucken – Ergebnis, Sicherheitsniveau, Kennzahlen, Diagramme und die drei wichtigsten Maßnahmen auf einen Blick.</i></p>

<p align="center"><img src="docs/img/report_dark.png" alt="HTML-Bericht – Befunde, dunkles Design" width="92%"></p>
<p align="center"><i>Befunde im HTML-Bericht (dunkles Design): Filter, Gruppierung nach Verzeichnis und aufklappbare Details mit Beweisausschnitten.</i></p>

<p align="center"><img src="docs/img/dashboard.png" alt="Dashboard – Übersicht mit Ampel, Score und Änderungen seit dem letzten Scan" width="92%"></p>
<p align="center"><i>Dashboard, Übersicht: Ampel, Sicherheitsniveau mit Note und den größten Abzügen, Kennzahlen im Vergleich zum letzten Scan, Änderungen seit dem letzten Scan und die nächsten Schritte.</i></p>

<p align="center"><img src="docs/img/dashboard_dark.png" alt="Dashboard – Befunde mit Detailansicht, dunkles Design" width="92%"></p>
<p align="center"><i>Befunde im dunklen Design: Facettenfilter und Suche, Detailansicht mit Beweisen, KI-Bewertung und verknüpften Empfehlungen; einzeln, je Verzeichnis oder je Regel als unbedenklich markieren.</i></p>

<p align="center"><img src="docs/img/integrity.png" alt="Dashboard – Shop-Integrität" width="92%"></p>
<p align="center"><i>Shop-Integrität: Installation, bekannte Schwachstellen mit Begründung des Patch-Status und die Prüfungen nach Bereichen – Auffälliges zuerst.</i></p>

<p align="center"><img src="docs/img/integrity_accounts.png" alt="Shop-Integrität – Admin-Konten, Zahlung, E-Mail, Plugins" width="92%"></p>
<p align="center"><i>Admin-Konten mit 2FA-Status, PayPal-Empfänger, E-Mail-Historie, Dateirechte und Plugins (Beispieldaten).</i></p>

<p align="center"><img src="docs/img/recommendations.png" alt="Dashboard – Empfehlungen, dunkles Design" width="92%"></p>
<p align="center"><i>Empfehlungen im dunklen Design: priorisierte Checkliste zum Abhaken mit Verweisen auf die auslösenden Befunde.</i></p>

---

## 🛒 Unterstützte Shopsysteme

| Shopsystem | Zugriff | Erkennung | Datenbank-/API-Prüfungen |
|---|---|---|---|
| **JTL-Shop 5** (5.0 – 5.8+) | Shop-Verzeichnis, optional MySQL | automatisch | Admin-Konten, PayPal, E-Mail-Historie, Vorlagen, Kundendaten, Plugins, Cronjobs |
| **Shopware 6** (6.4+) | Projekt-Verzeichnis, optional MySQL | automatisch | Benutzer, API-Integrationen, Apps/Plugins, Zahlungsanbieter, Mail-Templates, Flows, Snippets/CMS |
| **WooCommerce / WordPress** (WordPress 4.x+, WooCommerce 3.x+) | Webroot, optional MySQL | automatisch | Administratoren & Sitzungen, Standardrolle, siteurl/home, aktive Plugins, Options-/Beitrags-Injection, WP-Cron, PayPal/Stripe/BACS, REST-API-Schlüssel, Webhooks |
| **Magento 2 / Adobe Commerce** (2.3+) | Projekt-Verzeichnis, optional MySQL | automatisch | Admin-Benutzer & Sitzungen, Integrationen/OAuth, Basis-URLs, Head-/Footer-Scripts, Zahlungskonfiguration, CMS-Blöcke/-Seiten, Template-Direktiven, Cron-Jobs |
| **Shopify** | Admin-API-Token (nur Lese-Rechte) | `--platform shopify` | Script-Tags, Webhooks, Apps & Berechtigungen, Mitarbeiter (Plus), Live-Theme |

Die Datenbank-Zugangsdaten liest `ecomsec` aus der Shop-Konfiguration (`config.JTL-Shop.ini.php`,
`.env`, `wp-config.php` – auch eine Ebene über dem Webroot – bzw. `app/etc/env.php`). Ist keine Datenbank erreichbar, läuft der Dateiscan trotzdem vollständig – die
fehlenden Prüfungen werden im Bericht genannt.

```bash
# Shopify-Beispiel
ecomsec scan --platform shopify --shop mein-shop.myshopify.com --token shpat_…
```

Weitere Shopsysteme lassen sich als Adapter ergänzen – siehe [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 🔔 Täglich automatisch prüfen

Einmal einrichten – danach meldet sich `ecomsec` **nur, wenn sich etwas ändert**: ein neuer
kritischer Befund, eine neu veröffentlichte Schwachstelle für deine Version, eine verwundbare
Bibliothek, ein neues Admin-Konto, ein geänderter Zahlungsempfänger. Ruhige Tage bleiben ruhig.

**1. Kanal eintragen** in `ecomsec.toml` – E-Mail, Slack, Microsoft Teams, Discord, Mattermost,
ntfy, Telegram, eigener Webhook oder Datei:

```toml
[target]
root = "/var/www/shop"

[notify]
on = "warning"                                 # critical | warning | any | always

[[notify.channel]]
kind = "email"
smtp_host = "smtp.example.de"
smtp_user = "shop@example.de"
smtp_password_env = "ECOMSEC_SMTP_PASSWORD"    # Geheimnisse immer aus der Umgebung
from = "ecomsec <shop@example.de>"
to = ["inhaber@example.de"]

[[notify.channel]]
kind = "slack"                                 # oder teams, discord, mattermost, ntfy, telegram, webhook
url_env = "ECOMSEC_SLACK_WEBHOOK"
on = "critical"
```

**2. Testen und Zeitplan holen** – `ecomsec` gibt die fertige systemd-Unit bzw. Crontab-Zeile aus
und schreibt selbst nichts:

```bash
ecomsec notify test                        # Testnachricht an alle Kanäle
ecomsec watch --install-systemd            # Service + Timer, täglich 04:17
ecomsec watch --install-cron               # oder: Zeile für crontab -e
```

```cron
17 4 * * * /usr/local/bin/ecomsec --state-dir /var/lib/ecomsec --root /var/www/shop watch --quiet
```

Jeder Lauf von `ecomsec watch` aktualisiert die Schwachstellen-Datenbank (ohne Netz geht es mit dem
vorhandenen Stand weiter), scannt mit allen Optionen von `scan` (auch `--online`), vergleicht mit
dem vorherigen Lauf und benachrichtigt nur bei Änderungen. Was sich geändert hat, zeigen auch
`ecomsec diff` und das Dashboard-Panel „Änderungen seit letztem Scan“. Ohne cron/systemd:
`ecomsec watch --interval 24h`.

Exit-Codes: `0` keine neuen Befunde · `1` neue Warnung · `2` neuer kritischer Befund · `10` Fehler.
Für `scan` gilt: `0` sauber · `1` Warnungen (mit `--fail-on warning`) · `2` kritisch · `10` Fehler.

Auf Shared Hosting mit knappen Laufzeiten scannt `ecomsec` in Etappen – verglichen und
benachrichtigt wird nach dem ersten vollständigen Durchlauf, den Cronjob also z. B. stündlich
einplanen:

```bash
ecomsec watch --root /var/www/shop --time-budget 45s --quiet   # beim nächsten Aufruf geht es weiter
```

Benachrichtigungen gehen ausschließlich an Kanäle, die du selbst einträgst. Alle Kanäle, Formate
und Beispiele: [docs/MONITORING.md](docs/MONITORING.md).
Jeder Bericht enthält ein **Sicherheitsniveau** von 0–100 mit Note A–F und den drei wichtigsten
Gründen für Punktabzüge – im Dashboard (Tab *Hilfe & Service*) als Verlauf der letzten 30 Scans.

---

## 🧩 Integrationen

| Format | Befehl | Wofür |
|---|---|---|
| SARIF 2.1.0 | `ecomsec scan --format sarif` | GitHub Code Scanning (`upload-sarif`), GitLab, DefectDojo |
| JUnit-XML | `ecomsec scan --format junit` | Test-Ansicht in GitLab, Jenkins, Azure DevOps – ein Testfall pro Befund-Kategorie |
| Markdown | `ecomsec scan --format markdown` | Kommentar im Pull/Merge Request, Chat-Nachricht |
| SBOM | `ecomsec sbom --format cyclonedx` / `spdx-json` | Software-Stückliste der Composer-Pakete für Dependency-Track & Co. |

Fertige Pipeline-Beispiele für GitHub Actions und GitLab CI, Exit-Codes und Docker: [docs/CI.md](docs/CI.md).

---

## 🧹 Fehlalarme ausräumen

Jeder Befund hat eine kurze ID. Was du kennst, markierst du einmal als unbedenklich:

```bash
ecomsec findings list   --root /var/www/shop
ecomsec findings accept --root /var/www/shop 5acb77c9c21963b4 --reason "Dump der Agentur, entfernt am 20.06."
ecomsec findings accept --root /var/www/shop --group templates_c --reason "kompilierte Templates"
ecomsec findings accept --root /var/www/shop --rule ctime_newer_than_mtime --reason "Deployment vom 01.10."
```

Im Dashboard geht das per Klick – einzeln, per Checkbox-Auswahl oder für ein ganzes Verzeichnis.

Nach einer verifizierten Prüfung lohnt sich eine Baseline. Spätere Scans melden dann jede
veränderte, fehlende oder neue Kerndatei:

```bash
ecomsec baseline create --root /var/www/shop
```

---

## 🤖 KI-Audit (optional)

Zu viele Befunde, zu wenig Zeit? Auf Wunsch schaut nach dem Scan ein Claude-Modell als
forensische Analystin drüber: Es liest gezielt die betroffenen Dateien und Datensätze, bewertet
jeden kritischen Befund und jede Warnung (**bestätigt**, **wahrscheinlich Fehlalarm** oder
**manuelle Prüfung nötig** – mit Konfidenz und Beleg) und schließt mit einer Gesamtbewertung und
priorisierten nächsten Schritten ab. Im Modus `hunt` prüft es zusätzlich eigene Plugins und
Templates auf SQL-Injection, XSS, SSTI, unsichere Uploads und fest einprogrammierte Zugangsdaten.

```bash
export ANTHROPIC_API_KEY="sk-ant-…"
ecomsec audit --root /var/www/shop                 # Triage, claude-sonnet-5-5
ecomsec audit --root /var/www/shop --mode hunt -v  # plus Code-Review, Werkzeugaufrufe anzeigen
```

```
GESAMTBEWERTUNG
wahrscheinlich kompromittiert (Konfidenz 85 %)
In mediafiles/Bilder/wso.php liegt eine Webshell (eval auf $_POST, ctime 02.07.) …

BEWERTUNGEN DER BEFUNDE (2)
Bestätigt (1)
  #5acb77c9c21963b4 mediafiles/Bilder/wso.php – Webshell-Muster eval($_POST) (95 %)
Wahrscheinlich Fehlalarm (1)
  #91e0d2a4b7c3f018 templates_c/a1b2.php – Neue PHP-Datei seit dem Referenzdatum (85 %)

Token-Verbrauch: 412380 Eingabe (361902 aus Cache) / 9850 Ausgabe · ca. 0,35 USD · 2 Bewertungen, 0 neue Befunde.
```

Im Dashboard erscheint die Bewertung als Badge am Befund („KI: wahrscheinlich Fehlalarm (85 %)“)
und als Panel „KI-Bewertung“ mit Zusammenfassung und nächsten Schritten.

| | |
|---|---|
| 🔒 **Datenschutz** | Das Modell hat **nur lesende Werkzeuge**, beschränkt auf das Shop-Verzeichnis, den Scan-Report und `SELECT`-Abfragen (max. 200 Zeilen). An die Anthropic-API gehen **nur redigierte Ausschnitte, die das Modell anfordert** – Passwörter, Schlüssel, Tokens, Hashes, PEM-Blöcke, lange Hex-/Base64-Werte und E-Mail-Adressen werden vorher maskiert, `config.JTL-Shop.ini.php` und `.env` nie im Klartext gesendet, Schlüsseldateien gar nicht. |
| 💶 **Kosten** | Über dein Anthropic-Konto, typisch wenige Cent bis ca. 1,50 USD je Triage; ein Token-Budget begrenzt jeden Lauf hart. |
| 🧭 **Entscheidung bleibt bei dir** | Die KI ändert weder Schweregrad noch Markierungen und empfiehlt nie, ungeprüft zu löschen. |

Ohne `ecomsec audit` und API-Schlüssel bleibt alles wie gehabt: nichts verlässt den Server.
Details zu Werkzeugen, Redaktion, Kosten und Grenzen: [docs/AUDIT.md](docs/AUDIT.md).

---

## ❓ Häufige Fragen

<details>
<summary><b>Verändert der Scan etwas an meinem Shop?</b></summary>
Nein. <code>ecomsec</code> liest ausschließlich – Dateien, Datenbank (nur SELECT) bzw. Shopify-API (nur GET). Es werden keine Dateien gelöscht, keine Einstellungen geändert und keine Daten an Dritte übertragen – außer an Benachrichtigungskanäle, die du selbst einträgst. Der einzige Schreibzugriff ist das eigene Zustandsverzeichnis (Akzeptanzen, Verlauf, Reports, Baseline), standardmäßig unter <code>~/.local/state/ecomsec</code>.
Nein. <code>ecomsec</code> liest ausschließlich – Dateien, Datenbank (nur SELECT) bzw. Shopify-API (nur GET). Es werden keine Dateien gelöscht, keine Einstellungen geändert und keine Daten an Dritte übertragen (einzige Ausnahme: das optionale <a href="#-ki-audit-optional">KI-Audit</a>, das du ausdrücklich mit eigenem API-Schlüssel startest). Der einzige Schreibzugriff ist das eigene Zustandsverzeichnis (Akzeptanzen, Verlauf, Baseline), standardmäßig unter <code>~/.local/state/ecomsec</code>.
</details>

<details>
<summary><b>Ich habe einen kritischen Befund. Soll ich den Shop sofort abschalten?</b></summary>
Erst prüfen, dann handeln. Die Gruppe „Zuerst prüfen“ in den Handlungsempfehlungen führt dich durch: Ist die Datei bekannt (Agentur, Plugin, eigene Anpassung)? Dann als unbedenklich markieren. Ist sie fremd: sichern, entfernen, alle Zugangsdaten rotieren, Patch einspielen. Bei Datenabfluss gilt die 72-Stunden-Meldepflicht nach DSGVO Art. 33.
</details>

<details>
<summary><b>Warum werden so viele „geänderte Dateien“ gemeldet?</b></summary>
Alles, was nach dem Referenzdatum verändert wurde, ist erst einmal verdächtig – auch Updates und Agentur-Arbeiten. Setze das Referenzdatum auf deinen letzten bekannten sauberen Stand (<code>--reference-date 2026-09-01</code>) oder markiere die bekannten Verzeichnisse einmal als unbedenklich. Massenhafte Zeitstempel-Abweichungen durch ein Deployment fasst <code>ecomsec</code> automatisch zu einem Hinweis zusammen.
</details>

<details>
<summary><b>Woher weiß ecomsec, ob der CVE-2026-54390-Patch drin ist?</b></summary>
Zuerst anhand der Shop-Version (5.5.4, 5.6.2, 5.7.2 und ab 5.8 gelten als gepatcht). Bei älteren Versionen, unbekannter Version oder eingespieltem Back-Patch prüft es die Datei, die der offizielle Fix ändert: Maskiert der Mail-Renderer Smarty-Klammern in Platzhaltern (<code>{ldelim}</code>), ist der Fix drin. Für abweichende Back-Patches gibt es eine Rückfallprüfung der Smarty-Mail-Klassen. Genauso arbeiten die Prüfungen für die Updates 5.6.3 bis 5.8.2. Das Ergebnis nennt immer, ob die Version oder die Datei die Grundlage war.
</details>

<details>
<summary><b>Findet das Tool auch neue CVEs für Shopsysteme und Plugins?</b></summary>
Ja, auf drei Wegen. <b>1.</b> Die eingebaute Advisory-Datenbank (<code>advisories/*.toml</code>) wird wöchentlich automatisch aktualisiert: ein Workflow sucht in NVD und OSV.dev nach neuen Einträgen, ein Claude-Agent recherchiert Versionsbereiche in den Primärquellen und öffnet einen Pull Request, den ein Mensch freigibt. <b>2.</b> <code>ecomsec advisories update</code> lädt den aktuellen Stand, ohne dass du ein neues Release brauchst. <b>3.</b> <code>ecomsec scan --online</code> prüft alle Composer-Pakete deiner Installation (bei Shopware und Magento Core und Erweiterungen, bei JTL die mitgelieferten Bibliotheken) tagesaktuell gegen OSV.dev – dabei verlassen nur Paketnamen und Versionen den Server. Bei WordPress werden die installierten Plugins mit dem WordPress.org-Verzeichnis verglichen (nur der Plugin-Name wird gesendet). Für JTL-Plugins aus dem Extension Store, WordPress-Plugins außerhalb von WooCommerce und Shopify-Apps gibt es keine frei nutzbare Schwachstellen-Datenbank; hier bleibt die Risikobewertung nach Installationsdatum, Herkunft und Berechtigungen. Details: <a href="docs/ADVISORIES.md">docs/ADVISORIES.md</a>.
</details>

<details>
<summary><b>Brauche ich Datenbank-Zugang?</b></summary>
Nicht zwingend. Ohne Datenbank läuft der komplette Dateiscan, der Patch-Status und die Rechteprüfung. Admin-Konten, PayPal, E-Mail-Historie und Plugins benötigen die Datenbank; <code>ecomsec</code> nutzt dafür die Zugangsdaten aus der Shop-Konfiguration. Mit <code>--skip-remote</code> schaltest du diese Prüfungen bewusst ab.
</details>

<details>
<summary><b>Läuft das auf Shared Hosting?</b></summary>
Ja. Keine Root-Rechte, keine Dienste, ein statisch gebautes Binary. Mit <code>--time-budget</code> arbeitet der Scan in Etappen innerhalb der erlaubten Laufzeit und setzt beim nächsten Aufruf fort.
</details>

<details>
<summary><b>Kann ich eigene Regeln ergänzen?</b></summary>
Ja, als kleine TOML-Dateien im YARA-ähnlichen Format: <code>ecomsec scan --rules ./meine-regeln</code>. Anleitung in <a href="docs/RULES.md">docs/RULES.md</a>.
</details>

<details>
<summary><b>Was ist der Unterschied zum JTL-Plugin „EcomSec Security Scan“?</b></summary>
Gleicher Prüfumfang und gleiche drei Ansichten – aber als eigenständiges Programm statt als Plugin: läuft auch, wenn das Backend bereits kompromittiert ist, unterstützt mehrere Shopsysteme, liefert maschinenlesbare Berichte und lässt sich per Cron automatisieren.
</details>

---

## 💻 Systemvoraussetzungen

- Linux, macOS oder Windows (64-bit); Lesezugriff auf das Shop-Verzeichnis
- Für Datenbank-Prüfungen: MySQL/MariaDB-Zugang wie in der Shop-Konfiguration hinterlegt
- Für Shopify: Admin-API-Token mit Lese-Scopes (`read_script_tags`, `read_themes`, `read_apps`, `read_users`)
- Zum Selbstbauen: Rust ab 1.80

---

## ⚙️ Alle Befehle auf einen Blick

```
ecomsec scan      [--root PFAD | --platform shopify --shop … --token …]
                  [--format text|json|html|sarif|junit|markdown] [--output DATEI] [--time-budget 45s]
                  [--reference-date YYYY-MM-DD] [--skip-remote] [--fail-on never|warning|critical]
                  [--online] [--advisories DIR] [--access-log auto|PFAD]
ecomsec advisories list | lint [PFAD…] | update [--url BASIS-URL]
ecomsec watch     [Scan-Optionen] [--notify-on critical|warning|any|always] [--no-notify]
                  [--no-update] [--interval 24h] [--quiet] [--install-systemd | --install-cron [--at HH:MM]]
ecomsec diff      [VORHER.json NACHHER.json] [--format text|json]
ecomsec notify    test | list
ecomsec serve     [--bind 127.0.0.1:8787] [--auth-token GEHEIM]
ecomsec findings  list | accept <ID…> [--group DIR] [--rule REGEL] [--reason TEXT] | unaccept <ID…> [--all]
ecomsec baseline  create [--core-only] | diff | show
ecomsec report    [--format text|json|html|sarif|junit|markdown] [--output DATEI]
ecomsec sbom      [--format cyclonedx|spdx-json] [--output DATEI] [--no-dev]
ecomsec self-update [--check] [--force]
ecomsec history
ecomsec platforms
ecomsec rules     [--tag cve-2026-54390]
ecomsec audit     [--mode triage|hunt] [--model claude-sonnet-5-5|claude-opus-5-5] [--max-turns N]
                  [--max-tokens-budget TOKENS] [--rescan] [--format text|json]   (optional, ANTHROPIC_API_KEY)
```

Optional per Konfigurationsdatei: [`ecomsec.example.toml`](ecomsec.example.toml).

---

## 🧑‍💻 Für Entwickler

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) – Aufbau, `Platform`-Trait, neue Shopsysteme anbinden
- [docs/RULES.md](docs/RULES.md) – Regelformat, Dateiklassen, Kategorien
- [docs/ADVISORIES.md](docs/ADVISORIES.md) – Schwachstellen-Datenbank, OSV-Abgleich, automatische Pflege per Agent
- [docs/MONITORING.md](docs/MONITORING.md) – tägliche Überwachung, Benachrichtigungskanäle, systemd/cron
- [docs/AUDIT.md](docs/AUDIT.md) – optionales KI-Audit: Werkzeuge, Redaktion, Kosten, Grenzen
- [docs/CI.md](docs/CI.md) – SARIF/JUnit/Markdown/SBOM, GitHub Actions, GitLab CI, Docker, `self-update`
- Workspace: `ecomsec-core` (Engine), `ecomsec-jtl5`, `ecomsec-shopware6`, `ecomsec-woocommerce`, `ecomsec-magento2`, `ecomsec-shopify`, `ecomsec-osv`, `ecomsec-notify` (Benachrichtigungen), `ecomsec-audit` (KI-Audit), `ecomsec-cli`
- `cargo test --workspace` · `cargo clippy --workspace --all-targets` · `cargo fmt --all`

## 📜 Lizenz und Hinweise

MIT-Lizenz. Signaturen und IOC-Listen stammen aus öffentlichen Quellen (CISA, NSA/ASD, MITRE ATT&CK,
Sansec-Analyse zu CVE-2026-54390) und erheben keinen Vollständigkeitsanspruch. Der dateibasierte
Patch-Nachweis ist eine Heuristik; Versionsbereiche der Advisories sind gegen die jeweiligen
Hersteller-Mitteilungen zu verifizieren; die Advisory-Datenbank unter `advisories/` wird automatisiert
aus NVD und OSV.dev gespeist und vor dem Merge geprüft. Dieses Projekt steht in keiner Verbindung zu JTL-Software,
Shopware AG, Shopify Inc., Automattic (WooCommerce), der WordPress Foundation oder Adobe (Magento).
