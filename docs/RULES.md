# Eigene Regeln

`ecomsec` verwendet ein kompaktes, YARA-ähnliches Regelformat in TOML. Eingebaute Regeln liegen
unter `crates/ecomsec-core/signatures/` (plattformübergreifend) und
`crates/ecomsec-*/signatures/` (plattformspezifisch). Zusätzliche Regelverzeichnisse werden mit
`--rules DIR` (mehrfach möglich) oder `scan.rule_dirs` in `ecomsec.toml` geladen; alle `*.toml`
darin werden alphabetisch verarbeitet.

## Format

```toml
[[rule]]
name        = "php_eval_base64"                      # eindeutig, wird Teil der Befund-ID
description = "eval() mit base64-dekodierter Nutzlast"
severity    = "critical"                             # critical | warning | info
category    = "suspicious_pattern"                   # optional, Standard suspicious_pattern
condition   = "any"                                  # any | all | "2" (mindestens N Strings)
applies_to  = ["php"]                                # Dateiklassen, Standard ["php"]
tags        = ["webshell", "obfuscation"]
reference   = "https://…"                            # optional
strings = [
  { regex   = 'eval\s*\(\s*base64_decode\s*\(', nocase = true },
  { literal = "FilesMan" },
]
```

### Dateiklassen (`applies_to`)

| Klasse | Dateien |
|---|---|
| `php` | `.php .phtml .php3-8 .phar .inc .pht …` |
| `htaccess` | `.htaccess`, `.htpasswd`, `web.config` |
| `ini` | `.user.ini`, `php.ini` |
| `template` | Template-Endungen der Plattform (`tpl`, `twig`, `liquid`, Magento-Knockout-`html`) sowie DB-gespeicherte Inhalte (Templates, CMS-Blöcke, WordPress-Optionen und -Beiträge) |
| `js` | `.js .mjs .cjs` und Theme-JavaScript (Shopify) |
| `log` | Dateien in Log-Verzeichnissen der Plattform oder mit Endung `.log` (bei großen Dateien nur die letzten 64 MiB) |
| `image` | Bilder (nur die ersten 2 MiB; für Polyglot-Prüfungen) |
| `any` | alle Klassen |

### Kategorien (`category`)

`known_webshell`, `modified_since_reference`, `code_in_upload_dir`, `webserver_config_manipulation`,
`suspicious_pattern`, `exploit_payload`, `timestamp_anomaly`, `attack_trace`, `patch_status`,
`admin_account`, `payment_configuration`, `config_permissions`, `exposed_file`,
`integrity_deviation`, `third_party_injection`, `scan_limitation`, `informational`.

Die Kategorie steuert, welche Handlungsempfehlung ein Treffer auslöst.

### Regex-Dialekt

Rust-`regex` (Byte-Modus, kein Unicode): `\s`, `\w`, `\d` sind ASCII, `.` matcht kein `\n`.
Keine Lookarounds/Backreferences. Bei `nocase = true` wird case-insensitiv gesucht.
Literale werden automatisch escaped.

## IOC-Dateinamen

`crates/ecomsec-core/signatures/ioc_filenames.toml` enthält Einträge mit `exact`, `prefix` oder
`regex` (auf den Dateinamen, case-insensitiv) und einer `severity`. Treffer in
Upload-Verzeichnissen werden von `warning` auf `critical` angehoben.

## Testen

```bash
ecomsec rules                 # listet alle geladenen Regeln
ecomsec scan --root fixture --rules ./meine-regeln --format json | jq '.findings[] | select(.rule=="meine_regel")'
```
