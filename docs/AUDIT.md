# KI-Audit (optional)

`ecomsec audit` lässt nach einem normalen Scan ein Claude-Modell von Anthropic als forensische
Analystin auf die Ergebnisse schauen. Das Modell bewertet jeden kritischen Befund und jede
Warnung, sortiert begründete Fehlalarme aus, sucht nach Spuren, die die Signaturen übersehen
haben, und schließt mit einer Gesamtbewertung und priorisierten nächsten Schritten ab – auf
Deutsch, mit Belegen (Pfad, Zeile, Ausschnitt).

Das KI-Audit ist **ausdrücklich optional**. Ohne API-Schlüssel und ohne den Befehl `ecomsec audit`
verlässt nichts den Server; Scan, Dashboard und Berichte funktionieren unverändert.

## Was es tut

1. Es lädt den letzten gespeicherten Report (oder scannt selbst, wenn keiner existiert bzw. mit
   `--rescan`).
2. Es startet eine Agenten-Schleife: Das Modell fordert über **nur lesende Werkzeuge** gezielt
   Informationen an, `ecomsec` führt sie lokal aus und schickt das (redigierte) Ergebnis zurück.
3. Bewertungen und neue Befunde werden gespeichert und in den Report übernommen.

| Werkzeug | Zweck | Grenzen |
|---|---|---|
| `list_dir`, `read_file`, `grep`, `file_info` | Dateien des Shops ansehen, durchsuchen, Metadaten (mtime/ctime, Modus, Besitzer, SHA-256) | nur innerhalb des Shop-Verzeichnisses (`..` und Symlinks nach außen werden abgelehnt), max. 64 KiB pro Aufruf, Binärdateien nur als Hexdump-Anfang, Schlüsseldateien gar nicht |
| `get_report_summary`, `list_findings`, `get_finding`, `get_integrity` | Scan-Report lesen | – |
| `db_query` | Shop-Datenbank lesen (nur JTL-Shop 5 / Shopware 6, nicht mit `--skip-remote`) | eine einzelne `SELECT`/`SHOW`/`DESCRIBE`-Anweisung, keine Kommentare, Sperrliste für Schreibzugriffe/Locks/`INTO OUTFILE`/`SLEEP`, `LIMIT` ≤ 200, READ-ONLY-Transaktion, 20 s Zeitlimit |
| `lookup_advisory` | lokale Schwachstellen-Datenbank | – |
| `osv_lookup` | OSV.dev für ein Composer-Paket | nur mit `--online`; sendet nur Paketname und Version |
| `record_verdict` | Bewertung eines Befunds: `confirmed`, `likely_false_positive`, `needs_human` mit Konfidenz und Begründung | nur für existierende Befund-IDs |
| `record_finding` | neues Problem (z. B. SQL-Injection in einem eigenen Plugin, übersehene Hintertür) | max. 50 pro Lauf, Regelname `agent_<kategorie>` |

Es gibt kein Werkzeug, das schreibt, löscht, Befehle ausführt oder ins Internet geht.

### Modi

| Modus | Inhalt |
|---|---|
| `--mode triage` (Standard) | Jeder offene kritische Befund und jede Warnung wird bewertet (gleichartige gesammelt). Günstig. |
| `--mode hunt` | Triage plus Code-Review eigener Erweiterungen: `plugins/`, `includes/plugins/`, `templates/` (JTL) bzw. `custom/plugins`, `custom/static-plugins`, `custom/apps`, `src/`, `templates/` (Shopware). Eine Heuristik (Superglobals, SQL-Verkettung, `eval`/`system`, `unserialize`, Uploads, `|raw`, fest einprogrammierte Geheimnisse, Verschleierung, Änderung nach dem Referenzdatum) wählt bis zu 40 Dateien / 800 KiB aus; das Modell prüft sie auf SQLi, XSS, SSTI, RCE, IDOR, unsichere Uploads, Zugangsdaten im Code und veraltete Bibliotheken. |

## Welche Daten den Server verlassen

**Nur redigierte Ausschnitte, die das Modell konkret anfordert**, gehen per HTTPS an die
Anthropic-API (`api.anthropic.com`): der Auftrag (Plattform, Version, Liste der offenen Befunde),
die Ergebnisse der oben genannten Werkzeugaufrufe und die Antworten des Modells. Es werden keine
Dateien hochgeladen und kein Verzeichnis als Ganzes übertragen.

Bevor eine Werkzeugausgabe gesendet wird, maskiert `ecomsec`:

- PHP-Konstanten wie `define('DB_PASS', …)`, `BLOWFISH_KEY`, alle Werte mit `PASS`, `SECRET`,
  `KEY`, `TOKEN`, `SALT`, `AUTH` im Namen, `APP_SECRET=` und andere Schlüssel-Zeilen,
- Zugangsdaten in URLs (`mysql://user:passwort@host`), Shopify-Tokens (`shpat_…`), Anthropic-,
  AWS-, GitHub-, Slack-, Stripe- und Google-Schlüssel, JWTs,
- Passwort-Hashes (bcrypt, argon2, crypt), PEM-Blöcke (private Schlüssel, Zertifikate),
- lange Hex- und Base64-Werte – bei Base64 steht im Platzhalter nur, ob der dekodierte Inhalt
  Code-Merkmale wie `eval` oder `<?php` enthält, nicht der Inhalt selbst,
- E-Mail-Adressen (`ma***@ex***.de`) sowie in Datenbankergebnissen alle Spalten, deren Name auf
  Passwörter, Tokens, Schlüssel, Sessions oder Zahlungsdaten hinweist.

Zugangsdaten-Dateien (`includes/config.JTL-Shop.ini.php`, `.env`, `.env.*`, `auth.json`,
`config/jwt/*` …) werden **streng** redigiert: jeder Wert außer harmlosen Schlüsseln wie
`URL_SHOP`, `DB_HOST`, `DB_NAME`, `APP_ENV`, `APP_URL` wird maskiert. Schlüsseldateien (`*.pem`,
`*.key`, `.htpasswd`, `id_rsa` …) werden nie ausgegeben. `grep` sucht in der redigierten Fassung,
damit maskierte Werte auch nicht über Treffer/Nicht-Treffer erraten werden können.

Wie viel übertragen wurde, steht in jedem Ergebnis unter „Übertragene Daten“ (Anzahl Aufrufe,
KiB, maskierte Werte, gelesene Dateien, DB-Abfragen). Der API-Schlüssel wird weder protokolliert
noch gespeichert; Logs enthalten nur den Token-Verbrauch.

Für die Verarbeitung bei Anthropic gelten die Bedingungen deines API-Kontos (kommerzielle
Bedingungen, Datenaufbewahrung). Prüfe vor dem Einsatz für Kundenshops, ob ein
Auftragsverarbeitungsvertrag (AVV) nötig ist – auch redigierte Logauszüge können
personenbezogene Daten enthalten (z. B. IP-Adressen, Namen).

## Einrichtung

API-Schlüssel in der [Anthropic Console](https://console.anthropic.com) anlegen und als
Umgebungsvariable setzen:

```bash
export ANTHROPIC_API_KEY="sk-ant-…"
ecomsec audit --root /var/www/shop
```

Der Schlüssel gehört nicht in die Konfigurationsdatei. Wer eine andere Variable nutzen will:

```toml
[audit]
api_key_env = "ECOMSEC_ANTHROPIC_KEY"
```

Alle Schlüssel des Abschnitts `[audit]` stehen in [`ecomsec.example.toml`](../ecomsec.example.toml).

## Aufruf

```
ecomsec audit [--root PFAD] [--mode triage|hunt] [--model MODELL] [--effort low|medium|high|xhigh|max]
              [--max-turns N] [--max-tokens-budget TOKENS] [--rescan] [--online] [--skip-remote]
              [--format text|json] [--output DATEI] [-v | -vv]
```

| Option | Standard | Bedeutung |
|---|---|---|
| `--mode` | `triage` | siehe oben |
| `--model` | `claude-sonnet-5-5` | `claude-opus-5-5` für besonders gründliche Audits (etwa doppelte Kosten) |
| `--effort` | `medium` | Denktiefe; `high` gründlicher und teurer |
| `--max-turns` | 40 (triage) / 80 (hunt) | maximale Anzahl Modellaufrufe |
| `--max-tokens-budget` | 1 500 000 / 4 000 000 | Abbruch, sobald Ein- und Ausgabe-Tokens zusammen das Budget überschreiten |
| `--rescan` | aus | vorher neu scannen |
| `--online` | aus | erlaubt `osv_lookup` |
| `--skip-remote` | aus | kein Datenbankzugriff für das Modell |
| `-v` / `-vv` | – | jeden Werkzeugaufruf und den Token-Stand pro Runde auf stderr ausgeben |

Exit-Codes: `0` abgeschlossen · `3` vorzeitig beendet (Budget, Rundenlimit oder Ablehnung durch
das Modell) – Teilergebnis gespeichert · `10` Fehler (z. B. kein API-Schlüssel, API nicht
erreichbar).

Kurz vor Erreichen des Budgets oder Rundenlimits bittet `ecomsec` das Modell, ausstehende
Bewertungen zu erfassen und abzuschließen. Bleiben Befunde ohne Bewertung, fordert es sie einmal
nach; was danach noch fehlt, steht im Ergebnis unter „Ohne Bewertung“.

## Ergebnisse

Im Zustandsverzeichnis des Ziels (siehe [ARCHITECTURE.md](ARCHITECTURE.md#zustand)):

| Datei | Inhalt |
|---|---|
| `audit-<Zeitstempel>.json` | vollständiges Audit: Modell, Zeitraum, Runden, Tokens, geschätzte Kosten, Bewertungen, neue Befunde, Gesamtbewertung, nächste Schritte, übertragene Datenmengen |
| `last-audit.json` | Kopie des letzten Audits (Dashboard, `GET /api/audit`) |
| `last-report.json` | jeder bewertete Befund erhält ein Feld `review` (`verdict`, `confidence`, `reasoning`, `model`); neue Befunde des Audits werden mit Regel `agent_…` angehängt |

Die Bewertung ändert **weder Schweregrad noch Risikoakzeptanz** eines Befunds. Ob ein Befund als
unbedenklich markiert wird, entscheidest weiterhin du (`ecomsec findings accept …`). Neue
KI-Befunde zählen in die Ampel und lassen sich wie alle anderen akzeptieren.

`ecomsec report` zeigt die Bewertung je Befund („KI: wahrscheinlich Fehlalarm (85 %)“), das
Dashboard zusätzlich ein aufklappbares Panel „KI-Bewertung“ mit Zusammenfassung und nächsten
Schritten sowie einen Filter nach KI-Bewertung. Ein neuer `ecomsec scan` ersetzt den Report;
die Bewertungen bleiben in `last-audit.json` erhalten, das Dashboard weist darauf hin, dass sie
sich auf einen älteren Scan beziehen. Danach `ecomsec audit` erneut ausführen.

## Kosten

Abgerechnet wird über dein Anthropic-Konto nach Tokens. `ecomsec` nutzt Prompt-Caching (der
wachsende Gesprächsverlauf wird überwiegend günstig aus dem Cache gelesen) und gibt am Ende
Verbrauch und geschätzte Kosten aus. Richtwerte mit `claude-sonnet-5-5` (2 USD / 10 USD je
Million Ein-/Ausgabe-Tokens, Cache-Lesen 0,20 USD):

| Modus | typischer Shop | praktische Obergrenze durch das Standard-Budget |
|---|---|---|
| `triage`, 5–30 offene Befunde | ca. 0,20 – 1,50 USD | ca. 3 – 5 USD |
| `hunt`, 20–40 Code-Dateien | ca. 1 – 5 USD | ca. 8 – 12 USD |

Mit `claude-opus-5-5` (4 USD / 20 USD) etwa das Doppelte. Die Werte hängen stark von Anzahl
und Art der Befunde ab; das Budget (`--max-tokens-budget`) begrenzt die Kosten hart. Die
Kostenschätzung im Ergebnis basiert auf Listenpreisen und ist ohne Gewähr.

## Grenzen

- Die KI-Bewertung ist eine **Entscheidungshilfe, keine forensische Analyse** und keine Garantie.
  Modelle können sich irren, Belege übersehen oder falsch gewichten – besonders bei
  `likely_false_positive` gilt: Begründung lesen und stichprobenartig nachprüfen.
- Das Modell sieht nur, was es anfordert, und nur redigiert. Verschleierter Code in Base64 ist
  nicht im Klartext sichtbar (nur der Hinweis auf Code-Merkmale).
- Hunt-Modus: Die Heuristik wählt Kandidaten aus; nicht ausgewählte Dateien werden nur geprüft,
  wenn das Modell sie selbst anfordert. Kein Ersatz für einen Penetrationstest oder ein Code-Audit.
- Inhalte aus dem Shop (Dateien, Datenbank, Logs) werden dem Modell als Daten übergeben. Das
  System-Prompt weist an, darin enthaltene „Anweisungen“ als Angriffsindiz zu behandeln; ganz
  ausschließen lässt sich eine Beeinflussung durch präparierte Inhalte (Prompt-Injection) nicht.
  Da alle Werkzeuge nur lesen, kann eine solche Beeinflussung den Shop nicht verändern.
- Für Shopify (gehostet) gibt es kein Dateisystem: Das Modell arbeitet nur mit Report und
  Integritätsdaten, der Hunt-Modus entfällt.
- Bei Ablehnung einer Anfrage durch die Sicherheitsfilter des Modells versucht die API
  (`fallback = true`, Standard) automatisch ein Ausweichmodell; gelingt das nicht, endet das
  Audit mit Exit-Code 3 und dem bis dahin erreichten Stand.
- Das Audit nutzt die Anthropic-API direkt (`api_base` ist für Proxys/Gateways konfigurierbar).
