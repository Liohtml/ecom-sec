# Täglich automatisch prüfen – Überwachung mit Benachrichtigung

Einmal einrichten, danach meldet sich `ecomsec` **nur, wenn sich etwas ändert**: ein neuer
kritischer Befund, eine neu veröffentlichte Schwachstelle, die deine Shop-Version betrifft, eine
verwundbare Bibliothek, ein neues Admin-Konto oder ein geänderter Zahlungsempfänger. Ruhige Tage
bleiben ruhig.

Der Shop wird dabei weiterhin **nur gelesen**. Netzwerkzugriffe gibt es nur dort, wo du sie
einrichtest: das Update der Schwachstellen-Datenbank (abschaltbar), der optionale OSV-Abgleich
(`--online`) und die Benachrichtigungskanäle, die du selbst einträgst.

---

## In 4 Schritten eingerichtet

**1. Benachrichtigung konfigurieren** – in `ecomsec.toml` (Vorlage: [`ecomsec.example.toml`](../ecomsec.example.toml)):

```toml
[target]
root = "/var/www/shop"

[notify]
on = "warning"            # critical | warning | any | always

[[notify.channel]]
kind = "email"
smtp_host = "smtp.example.de"
smtp_user = "shop@example.de"
smtp_password_env = "ECOMSEC_SMTP_PASSWORD"   # Passwort kommt aus der Umgebung
from = "ecomsec <shop@example.de>"
to = ["inhaber@example.de"]
```

**2. Geheimnisse hinterlegen** – nie in die Konfigurationsdatei schreiben, sondern als
Umgebungsvariable, z. B. in `/etc/ecomsec/ecomsec.env` (Dateirechte `0600`):

```bash
ECOMSEC_SMTP_PASSWORD=…
```

**3. Testen** – schickt eine Testnachricht an alle Kanäle:

```bash
ecomsec notify list   # was ist eingerichtet? (ohne Geheimnisse)
ecomsec notify test
```

**4. Zeitplan einrichten** – `ecomsec` gibt die passende Konfiguration fertig aus, schreibt aber
selbst nichts:

```bash
ecomsec watch --install-systemd            # systemd-Service + Timer (täglich 04:17)
ecomsec watch --install-cron --at 03:30    # oder eine Crontab-Zeile
```

Fertig. Einen Lauf von Hand startest du jederzeit mit `ecomsec watch`.

---

## Was passiert bei jedem Lauf?

`ecomsec watch` ist genau ein Überwachungslauf:

1. **Advisory-Update** – holt die aktuelle Schwachstellen-Datenbank (wie `ecomsec advisories
   update`). Ist das Netz weg, läuft der Scan mit dem vorhandenen Stand weiter.
   Abschalten: `--no-update` oder `[watch] update_advisories = false`.
2. **Scan** – mit allen Optionen von `ecomsec scan` (`--online`, `--skip-remote`,
   `--reference-date`, `--exclude`, `--time-budget` …).
3. **Vergleich** mit dem vorherigen vollständigen Lauf. Die letzten 10 Reports liegen im
   Zustandsverzeichnis unter `reports/`.
4. **Benachrichtigung** – nur, wenn die eingestellte Schwelle erreicht ist.
5. **Exit-Code** für systemd, cron oder dein Monitoring.

Der **erste Lauf** hat nichts zum Vergleichen und meldet deshalb den aktuellen Stand (alle aktiven
Befunde). Ab dem zweiten Lauf kommen nur noch Änderungen.

### Wann wird benachrichtigt?

| `on` / `--notify-on` | Nachricht bei … |
|---|---|
| `critical` | neuen **kritischen** Befunden (Webshell, neues Admin-Konto, geänderter Zahlungsempfänger, neu verwundbare kritische Schwachstelle …) |
| `warning` *(Standard)* | zusätzlich neuen **Warnungen** (geänderte Dateien, offene Dateirechte, verwundbare Bibliothek mit mittlerem Risiko …) |
| `any` | **jeder** Änderung – auch behobenen Befunden, Hinweisen, Versionswechseln |
| `always` | **jedem Lauf**, auch ohne Änderung (als „Lebenszeichen“) |

Als Änderung zählen:

| Änderung | Beispiel |
|---|---|
| Neuer Befund | `mediafiles/Bilder/wso.php` ist neu aufgetaucht |
| Schweregrad gestiegen | ein Hinweis ist jetzt eine Warnung |
| Neu verwundbar | eine heute veröffentlichte Advisory betrifft deine Version |
| Integrität verschlechtert | Admin-Konto neu, PayPal-Empfänger geändert, Dateirechte offen |
| Nicht mehr gefunden | ein Befund ist verschwunden (z. B. Datei entfernt) – nur bei `any` |

Befunde, die du als **unbedenklich** markiert hast (`ecomsec findings accept`), lösen nie eine
Nachricht aus. Reine Wertänderungen ohne Statuswechsel (z. B. „letzter Login“ eines Admins) werden
im Vergleich erwähnt, zählen aber nicht als Änderung.

Die Schwelle lässt sich pro Kanal überschreiben (`on = "critical"` im Kanal), `--notify-on` auf der
Kommandozeile gilt für alle Kanäle.

---

## Benachrichtigungskanäle

Jeder Kanal ist ein eigener `[[notify.channel]]`-Block. Gemeinsame Schlüssel: `kind`, `name`
(Anzeigename), `on` (eigene Schwelle), `enabled = false` (vorübergehend aus), `timeout_secs`.

Geheimnisse (Passwörter, Tokens, Webhook-URLs) liest `ecomsec` am besten aus Umgebungsvariablen:
Für jeden geheimen Schlüssel gibt es eine Variante mit `_env`, z. B. `url_env`, `token_env`,
`smtp_password_env`. Der direkte Eintrag (`url = "…"`) funktioniert auch, ist aber nicht
empfohlen. Geheimnisse erscheinen nie in Ausgaben oder Fehlermeldungen.

| `kind` | Pflichtangaben | Hinweise |
|---|---|---|
| `email` | `smtp_host`, `from`, `to` | `smtp_security = "starttls"` (Port 587, Standard), `"tls"` (465) oder `"none"` (25, nur lokales Relay); `smtp_user`/`smtp_user_env` + `smtp_password_env`. Text- und HTML-Teil. |
| `slack` | `url`/`url_env` | Incoming Webhook; optional `channel`, `username` |
| `teams` | `url`/`url_env` | Teams-Workflow („Beim Empfang einer Webhook-Anforderung“), Adaptive Card |
| `teams-legacy` | `url`/`url_env` | alter Office-365-Connector (MessageCard) |
| `discord` | `url`/`url_env` | Webhook eines Kanals; erwähnt niemanden (`@everyone` wird nie ausgelöst) |
| `mattermost` | `url`/`url_env` | Incoming Webhook; optional `channel`, `username` |
| `ntfy` | `topic` | `url` (Standard `https://ntfy.sh`), optional `token_env`; Priorität „dringend“ bei kritischen Befunden |
| `telegram` | `token`/`token_env`, `chat_id` | Bot über @BotFather anlegen, Bot in den Chat holen |
| `webhook` | `url`/`url_env` | JSON-POST mit Zusammenfassung und vollständigem Vergleich; `headers`, `header_env` |
| `file` | `path` | hängt jede Meldung an (`format = "text"` oder `"json"` = eine JSON-Zeile pro Meldung) |
| `stdout` | – | schreibt die Meldung auf die Standardausgabe |

### Beispiele

```toml
[[notify.channel]]
kind = "slack"
url_env = "ECOMSEC_SLACK_WEBHOOK"

[[notify.channel]]
kind = "teams"
url_env = "ECOMSEC_TEAMS_WEBHOOK"
on = "critical"

[[notify.channel]]
kind = "ntfy"
topic = "shop-7f3a9c2e"           # schwer zu erratender Name – wer ihn kennt, liest mit
# url = "https://ntfy.example.de" # eigener Server
# token_env = "ECOMSEC_NTFY_TOKEN"

[[notify.channel]]
kind = "telegram"
token_env = "ECOMSEC_TELEGRAM_TOKEN"
chat_id = "123456789"

[[notify.channel]]
kind = "webhook"
url_env = "ECOMSEC_WEBHOOK_URL"
header_env = { "Authorization" = "ECOMSEC_WEBHOOK_AUTH" }

[[notify.channel]]
kind = "file"
path = "/var/log/ecomsec/aenderungen.jsonl"
format = "json"
```

### Format des generischen Webhooks

```json
{
  "event": "ecomsec.changes",          // ecomsec.test | ecomsec.error
  "title": "[ecomsec] 1 neuer kritischer Befund – JTL-Shop 5 5.7.2 (/var/www/shop)",
  "level": "critical",                 // critical | warning | info | null
  "target": "JTL-Shop 5 (/var/www/shop)",
  "created_at": "2026-10-13T04:17:12Z",
  "summary": "… derselbe Text wie in der E-Mail …",
  "dashboard_url": null,
  "diff": { "new_findings": [ … ], "resolved_findings": [ … ], "changed_severity": [ … ],
            "new_advisories": [ … ], "integrity_changes": [ … ], "verdict_before": "warning",
            "verdict_after": "critical", "relevance": "critical", … }
}
```

`diff` ist identisch mit der Ausgabe von `ecomsec diff --format json`.

Scheitert der Scan selbst (z. B. Verzeichnis nicht lesbar), geht an alle Kanäle eine Meldung
„Prüfung fehlgeschlagen“ (`event = "ecomsec.error"`).

---

## Zeitplan

### systemd (empfohlen auf eigenen Servern)

```bash
ecomsec --root /var/www/shop watch --install-systemd
```

gibt zwei Dateien aus – `ecomsec-watch.service` und `ecomsec-watch.timer` – mit absoluten Pfaden
zu Programm, Konfiguration, Zustandsverzeichnis und Shop sowie allen angegebenen Scan-Optionen.
Speichere sie unter `/etc/systemd/system/` und aktiviere den Timer:

```bash
systemctl daemon-reload
systemctl enable --now ecomsec-watch.timer
systemctl start ecomsec-watch.service     # einmal sofort prüfen
journalctl -u ecomsec-watch.service       # Protokoll ansehen
```

Hinweise: Trage unter `User=` einen Benutzer ein, der den Shop lesen und das Zustandsverzeichnis
schreiben darf (oft der Webserver-Benutzer). Geheimnisse gehören in
`/etc/ecomsec/ecomsec.env`. Die Exit-Codes 1 und 2 („neue Warnung“/„neuer kritischer Befund“)
gelten für systemd nicht als Fehler (`SuccessExitStatus=1 2`).

### cron (auch auf Shared Hosting)

```bash
ecomsec --root /var/www/shop watch --install-cron --at 04:17
```

```cron
# ecomsec: täglich um 04:17 prüfen, nur bei Änderungen benachrichtigen.
17 4 * * * /usr/local/bin/ecomsec --state-dir /home/shop/.local/state/ecomsec --root /var/www/shop watch --quiet
```

`--quiet` sorgt dafür, dass cron nur bei Fehlern eine Mail schickt. Umgebungsvariablen für
Geheimnisse setzt du oben in der Crontab (`ECOMSEC_SMTP_PASSWORD=…`) oder in einem kleinen
Wrapper-Skript.

**Shared Hosting mit knapper Laufzeit:** Mit `--time-budget 45s` arbeitet der Scan in Etappen.
Verglichen und benachrichtigt wird erst nach einem vollständigen Durchlauf – plane den Cronjob
dann häufiger ein (z. B. stündlich), damit ein Durchlauf pro Tag sicher fertig wird.

### Dauerbetrieb ohne cron/systemd

```bash
ecomsec --root /var/www/shop watch --interval 24h
```

prüft sofort und dann alle 24 Stunden. `Strg+C` beendet nach dem laufenden Durchlauf, ein zweites
`Strg+C` sofort. Das Intervall lässt sich auch als `[watch] interval = "24h"` festlegen.

---

## Änderungen ansehen

```bash
ecomsec diff --root /var/www/shop                    # letzter Scan gegen den vorherigen
ecomsec diff --root /var/www/shop --format json      # maschinenlesbar
ecomsec diff vorher.json nachher.json                # zwei Reports aus `scan --format json`
ecomsec watch --no-notify                            # Probelauf: zeigt, wer benachrichtigt würde
```

Im **Dashboard** (`ecomsec serve`) zeigt der Tab *Security Scan* oben das Panel „Änderungen seit
letztem Scan“ mit neuen, nicht mehr gefundenen und geänderten Befunden.

### Exit-Codes von `watch` und `diff`

| Code | Bedeutung |
|---|---|
| `0` | keine neuen relevanten Befunde |
| `1` | neue Warnung |
| `2` | neuer kritischer Befund oder neu verwundbare kritische Schwachstelle |
| `10` | Fehler (Scan fehlgeschlagen oder – ohne neue Befunde – eine Benachrichtigung konnte nicht zugestellt werden) |

---

## Häufige Fragen

<details>
<summary><b>Ich bekomme keine Nachricht.</b></summary>
Das ist meist gut so: Ohne Änderung bleibt es still. Prüfe mit <code>ecomsec notify test</code>, ob
die Kanäle funktionieren, und mit <code>ecomsec notify list</code>, ob eine Umgebungsvariable fehlt.
Wer ein tägliches Lebenszeichen möchte, stellt einen Kanal auf <code>on = "always"</code>.
</details>

<details>
<summary><b>Ich bekomme zu viele Nachrichten.</b></summary>
Bekannte, harmlose Befunde einmal als unbedenklich markieren (<code>ecomsec findings accept …</code>
oder per Klick im Dashboard) – sie lösen nie wieder etwas aus. Für Chat-Kanäle hilft
<code>on = "critical"</code>, die E-Mail kann auf <code>warning</code> bleiben.
</details>

<details>
<summary><b>Was wird über das Netz gesendet?</b></summary>
Der Shop selbst wird nie verändert. Nach außen gehen nur: der Abruf der Advisory-Dateien von GitHub
(abschaltbar mit <code>--no-update</code>), bei <code>--online</code> Paketnamen und Versionen an
OSV.dev, und die Meldungen an die von dir eingetragenen Kanäle. Die Meldungen enthalten Befund-Titel,
Pfade relativ zum Shop und kurze Beweisausschnitte – wähle die Kanäle entsprechend.
</details>

<details>
<summary><b>Erkennt die Überwachung auch neue CVEs, ohne dass sich am Shop etwas ändert?</b></summary>
Ja. Weil jeder Lauf zuerst die Advisory-Datenbank aktualisiert, meldet <code>watch</code> eine neu
veröffentlichte Schwachstelle, sobald sie deine Version betrifft („Neu verwundbar“). Mit
<code>--online</code> gilt das auch für Composer-Bibliotheken über OSV.dev.
</details>
