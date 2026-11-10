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
within      = 1500                                   # optional: die Treffer liegen in einem Fenster von N Bytes
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
| `image` | Bilder (bis 2 MiB ganz, darüber Anfang und Ende; für Polyglot-Prüfungen) |
| `other` | alle übrigen Dateien außer Archiven und Dumps (`.txt`, `.dat`, ohne Endung …) |
| `any` | alle Dateiklassen (nicht `decoded`) |
| `decoded` | Nutzlasten, die erst durch die Entschleierung entstehen (siehe unten) |

Dateien über `--max-file-size` (Standard 8 MiB) werden nicht übersprungen: geprüft werden der
Anfang bis zur Grenze und die letzten 256 KiB.

### Näherung (`within`)

Ohne `within` genügt es, dass die geforderten Strings irgendwo in der Datei vorkommen. In
JavaScript-Bündeln mit einem Megabyte steht jedes Stichwort irgendwo; Schadcode verwendet die
Merkmale dagegen dicht beieinander. `within = N` verlangt, dass die nach `condition` nötigen
Strings in einem Fenster von `N` Bytes (gemessen zwischen den Trefferanfängen) liegen.

## Entschleierung

PHP- und JavaScript-Dateien werden zweimal geprüft: so, wie sie auf der Platte stehen, und nach
einer statischen Entschleierung (Modul `ecomsec_core::deobf`). Dabei wird nichts ausgeführt.

| Schritt | Beispiel | Ergebnis |
|---|---|---|
| Kommentare zwischen Tokens entfernen | `eval/**/($_POST['x'])` | `eval ($_POST['x'])` |
| Escapes dekodieren | `"\x73\x79stem"`, `"\163ystem"`, `"\u{73}ystem"` | `'system'` |
| Verkettungen falten | `'sys' . 'tem'`, `'at' + 'ob'` | `'system'`, `'atob'` |
| Zeichen-Aufrufe falten | `chr(115).chr(121)…`, `String.fromCharCode(101,118,97,108)` | `'sy…'`, `'eval'` |
| Dekodier-Aufrufe auf kurzen Literalen | `strrev('metsys')`, `str_rot13('flfgrz')`, `base64_decode('c3lzdGVt')` | `'system'` |
| Nutzlasten entpacken | `gzinflate(base64_decode('…'))`, auch ohne sichtbaren Aufruf | eigene Schicht |

Ein String, der erst durch Falten entsteht und dabei ein Wort zusammensetzt, erhält in der
entschleierten Schicht das Präfix `/*@hidden*/`. Regeln können damit `'system'` (harmlos, etwa
in einer Sperrliste) von `'sys'.'tem'` (versteckt) unterscheiden:

```toml
strings = [ { regex = '/\*@hidden\*/\x27(assert|system|passthru)\x27' } ]
```

Lange Literale (ab 40 Zeichen) werden entlang der Dekodierkette entpackt, die im Code steht.
Fehlt sie – der Dekodierer wird über eine Variable aufgerufen –, probiert `ecomsec` Base64
(auch rückwärts) und Hex und danach deflate, zlib und gzip. Entpackte Nutzlasten werden erneut
entschleiert, bis zu sechs Ebenen tief. Auf ihnen laufen die Regeln der Dateiklasse und
zusätzlich die Regeln mit `applies_to = ["decoded"]`.

Grenzen je Datei: 4 MiB Eingabe, 4 MiB je entpackter Nutzlast, 8 MiB und 24 Schichten insgesamt.
Eine Dekompressionsbombe endet an diesen Grenzen und erzeugt keine Schicht.

Ein Treffer, der nur in einer entschleierten Schicht liegt, behält den Regelnamen (und damit
die Befund-ID), nennt im Titel „erst nach Entschleierung sichtbar“ und in den Beweiszeilen die
Schritte, z. B. `[base64_decode → gzinflate] …`.

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

Einträge mit `weak = true` sind generische Namen (`shell.php`, `test.php`, `x.php`), die auch in
gewöhnlichen Plugins vorkommen. Sie werden nach Kontext bewertet:

| Kontext | Schweregrad |
|---|---|
| im Upload-Verzeichnis | kritisch |
| eine Inhaltsregel (ab Warnung) trifft dieselbe Datei | kritisch |
| direkt im Webroot, kein Inhaltstreffer | höchstens Warnung |
| tiefer im Verzeichnisbaum, kein Inhaltstreffer | Hinweis |

Namen einer bestimmten Shell-Familie (c99, r57, WSO, b374k), Doppelendungen und versteckte
PHP-Dateien bleiben unabhängig vom Inhalt kritisch.

## Testen

```bash
ecomsec rules                 # listet alle geladenen Regeln
ecomsec scan --root fixture --rules ./meine-regeln --format json | jq '.findings[] | select(.rule=="meine_regel")'
```

## Geschwindigkeit

Alle Strings der Regeln einer Dateiklasse werden zu einem Automaten zusammengefasst. Ein
Durchlauf pro Datei ergibt, welche Strings vorkommen; nur Regeln, deren Bedingung damit
erfüllbar ist, werden einzeln ausgewertet. Strings mit großen Wiederholungsgrenzen
(`.{0,300}`, ab 80) vergrößern diesen Automaten stark und bleiben deshalb außen vor – sie
zählen als „möglich“ und werden erst geprüft, wenn die übrigen Strings der Regel passen. Für
eigene Regeln heißt das: lieber `within` als lange `.{0,N}`-Brücken verwenden und jeder Regel
mindestens einen String ohne große Wiederholung geben.

## Qualitätssicherung

`crates/ecomsec-core/tests/detection_corpus.toml` enthält kurze Muster öffentlich dokumentierter
Techniken (zerlegte Funktionsnamen, mehrfach verpackte Nutzlasten, Callbacks mit Request-Daten,
PHP ohne Buchstaben, Skimmer-Loader …) und harmlose Doppelgänger (Sperrlisten mit
Funktionsnamen, eingebettete Bilder, gewöhnliche Callbacks, Kartenvalidierung). Der Test
`tests/detection.rs` schlägt fehl, wenn eine Technik nicht mehr erkannt oder ein Doppelgänger
gemeldet wird. Neue Regeln bekommen dort mindestens ein Muster und – wo eine Verwechslung
naheliegt – einen Doppelgänger.

Das Korpus belegt, dass die genannten Techniken erkannt werden; es ist keine Stichprobe echter
Schadsoftware und sagt nichts über Varianten, die darin fehlen. Fehlalarme werden zusätzlich an
unverändertem Herstellercode gemessen: WordPress 6.6.2 mit 14 verbreiteten Plugins (WooCommerce,
Elementor, Jetpack, Wordfence, UpdraftPlus …, 34.000 Dateien) ergibt ohne Datenbankprüfung
keinen kritischen Befund aus dem Dateiscan.
