# Sicherheit

## Schwachstelle melden

Bitte melde Sicherheitslücken in `ecomsec` **nicht** als öffentliches Issue, sondern vertraulich
über [GitHub Security Advisories](https://github.com/liohtml/ecom-sec/security/advisories/new)
(„Report a vulnerability“).

Hilfreich sind: betroffene Version (`ecomsec --version`), Betriebssystem, die Schritte zum
Nachstellen und – falls vorhanden – eine Beispieldatei. Schadcode-Proben bitte als
passwortgeschütztes Archiv anhängen.

Unterstützt wird jeweils das neueste Release. Behobene Lücken werden im Release-Text genannt.

Ebenfalls willkommen, aber als normales Issue: **Erkennungslücken** (eine Hintertür oder ein
Skimmer, den der Scan übersieht) und **Fehlalarme** in unverändertem Herstellercode. Ein
gekürztes Muster reicht; es wird Teil des Erkennungskorpus
(`crates/ecomsec-core/tests/detection_corpus.toml`).

## Was der Scanner selbst absichert

`ecomsec` liest Dateien, die ein Angreifer kontrolliert. Daraus folgen diese Eigenschaften:

| Eigenschaft | Umsetzung |
|---|---|
| Kein Code aus dem Shop wird ausgeführt | Entschleierung und Regeln arbeiten rein statisch; PHP und JavaScript werden nie interpretiert |
| Nur lesend | Dateien werden nicht verändert, die Datenbank nur mit `SELECT`/`SHOW`/`DESCRIBE` abgefragt; geschrieben wird ausschließlich ins eigene Zustandsverzeichnis |
| Begrenzter Speicher | Entpackte Nutzlasten sind auf 4 MiB je Stufe, 8 MiB je Datei und sechs Ebenen begrenzt; Dekompressionsbomben enden an dieser Grenze |
| Begrenzte Laufzeit je Datei | Reguläre Ausdrücke laufen in linearer Zeit (Rust `regex`, keine Backreferences); Dateien über der Größengrenze werden an Anfang und Ende geprüft |
| Kein Ausbruch über Links | Symbolische Links werden nicht verfolgt; Links, die aus dem Shop herausführen, werden gemeldet |
| Daten von Dritten werden geprüft | Pfade aus Prüfsummen-Manifesten müssen im Paketverzeichnis bleiben, Slugs und Versionen werden vor dem Einsetzen in eine Adresse geprüft |
| Nichts verlässt den Server ungefragt | Netzwerkzugriffe gibt es nur für `--online`, `advisories update`, `self-update`, eingetragene Benachrichtigungskanäle und das optionale KI-Audit |
| Geprüfte Updates | `install.sh` und `self-update` verlangen eine gültige minisign-Signatur der Prüfsummendatei; Releases tragen eine Build-Provenance |
| Geschütztes Dashboard | `ecomsec serve` verlangt ein Token, prüft `Host` und `Origin` und bindet ohne Token nur an Loopback |

## Grenzen

Der Scan ist eine Triage-Hilfe. Er erkennt dokumentierte Techniken und deren Verschleierung,
aber keine Hintertür, die wie gewöhnlicher Anwendungscode aussieht, und keinen Schadcode, der nur
im Arbeitsspeicher oder außerhalb des geprüften Verzeichnisses liegt. Die Herkunftsprüfung für
WordPress vertraut den Prüfsummen von WordPress.org: Ein dort veröffentlichtes, aber
kompromittiertes Plugin gilt als Original. Ein sauberes Ergebnis ersetzt bei konkretem Verdacht
keine forensische Analyse.
