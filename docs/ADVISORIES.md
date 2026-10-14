# Schwachstellen-Datenbank (Advisories)

ecomsec kennt drei Quellen für bekannte Schwachstellen:

| Quelle | Aktualität | Wo |
|---|---|---|
| **Eingebettete Dateien** `advisories/<platform>.toml` | Stand des Builds | im Binary, immer aktiv |
| **Heruntergeladene Dateien** (`ecomsec advisories update`) | Stand von `main` im Repository | `<State-Dir>/advisories/`, bei jedem Scan automatisch gemergt |
| **OSV.dev** (`ecomsec scan --online`) | tagesaktuell | prüft alle Composer-Pakete (Shopware- und Magento-Core, Erweiterungen, Symfony, Smarty …); sendet nur Paketname + Version |
| **WordPress.org** (`ecomsec scan --online`, nur WordPress) | tagesaktuell | vergleicht installierte Plugins und WordPress-Core mit der aktuellen Version im WordPress.org-Verzeichnis (veraltet = Warnung); sendet nur den Plugin-Slug |

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
platform = "jtl5"                  # jtl5 | shopware6 | woocommerce | magento2 | shopify
component = "WooCommerce"          # optional, siehe unten
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

Patch-Level wie bei Magento (`2.4.6-p6`) sind erlaubt und werden als zusätzliche Versionsstelle
verglichen: `2.4.6 < 2.4.6-p1 < 2.4.6-p13 < 2.4.7`. Beispiel: `affected = [">=2.4.6 <2.4.6-p6"]`.

### Komponenten (`component`)

Manche Plattformen bestehen aus mehreren unabhängig versionierten Teilen. Ein Eintrag mit
`component` wird nicht gegen die Shop-Version, sondern gegen die Version der Komponente geprüft,
die der Adapter über `Platform::component_version` liefert:

| Plattform | `component` | Version aus |
|---|---|---|
| `woocommerce` | (leer) | WordPress-Core, `wp-includes/version.php` |
| `woocommerce` | `"WooCommerce"` | Plugin-Header `wp-content/plugins/woocommerce/woocommerce.php` |
| `magento2` | `"Adobe Commerce"` | Shop-Version, aber nur bei der kommerziellen Edition (Open Source = nicht betroffen) |

Ist die Komponente nicht installiert, gilt der Eintrag als „nicht betroffen“.

Die Bewertung im Scan: Liegt die Shop-Version in keinem Bereich und ist mindestens so hoch wie
eine `fixed_in`-Version, gilt der Eintrag als gepatcht. Liegt sie in einem Bereich, fragt die
Engine den Plattform-Adapter nach einem dateibasierten Nachweis (z. B. Back-Patch), bevor sie
„verwundbar“ meldet.

## Patch-Nachweis im Code und Spuren in Logs

Die Versionsnummer allein reicht bei JTL-Shop nicht: JTL verteilt Fixes für ältere Zweige auch als
lose Patch-Dateien. Liegt die Version im betroffenen Bereich oder ist sie unbekannt, prüft der
JTL-Adapter deshalb die Dateien, die der offizielle Fix ändert. Die Merkmale stammen aus dem
öffentlichen Quellcode (`gitlab.com/jtl-software/jtl-shop/core`) und sind gegen jedes Release von
5.0.0 bis 5.8.2 getestet:

| Advisory | Geprüfte Datei(en) | Merkmal des Fixes |
|---|---|---|
| CVE-2026-54390 | `includes/src/Mail/Renderer/SmartyRenderer.php` | `{ldelim}`/`{rdelim}`-Maskierung von Platzhalterwerten |
| CVE-2026-103904 | `admin/templates/bootstrap/statistik.tpl`, `includes/src/Consent/Manager.php` | `escape` der Namen, `getActiveItemIDs()` |
| CVE-2026-103905 | `includes/src/Router/Middleware/AuthMiddleware.php` | Safe-Mode erst nach der Anmeldeprüfung |
| JTL-2026-PATH-TRAVERSAL | `dbeS/Sync/ImageUpload.php`, `ImageMap.php`, `BannerController.php` | `Path::hasTraversal`, `realpath`-Prüfung |
| JTL-SHOP-9886 | `includes/src/RMA/Services/RMAReturnAddressService.php` | Besitzprüfung über `$customerID` |
| JTL-2026-PWRESET-XSS | `includes/src/Router/Controller/ForgotPasswordController.php` | `Text::filterXSS($email)` |
| JTL-2026-ADMIN-XSS | `tpl_inc/bewertung_editieren.tpl`, `ActivationController.php` | `htmlentities` / `filterXSS` |

Ein nur teilweise eingespielter Patch zählt als verwundbar.

Zusätzlich sucht `ecomsec scan --access-log auto|PFAD` in Webserver-Access-Logs (auch `.gz`) nach
den Anfragemustern aus den Advisories, etwa `/admin/logout?safemode=` (CVE-2026-103905),
`rmaSummary` per GET (JTL-SHOP-9886) oder HTML in Anfragen an `/_updateconsent`
(CVE-2026-103904). Mit Datenbankzugang meldet der JTL-Adapter außerdem Namen in
`consent_statistics`, die zu keiner Einwilligung in `tconsent` passen. Solche mit HTML- oder
Skript-Zeichen sind kritisch.

## Automatische Pflege

Der Workflow `.github/workflows/advisories.yml` läuft wöchentlich (und per Hand):

1. **Sync** – `scripts/advisory_sync.py` fragt die NVD-API (Stichworte und CPEs für JTL-Shop,
   Shopware, Shopify-Apps, `cpe:2.3:a:wordpress:wordpress`, `cpe:2.3:a:woocommerce:woocommerce`,
   `cpe:2.3:a:adobe:magento`, `cpe:2.3:a:magento:magento`, `cpe:2.3:a:adobe:commerce`) und OSV.dev
   (Shopware-Composer-Pakete, `magento/product-community-edition`, `magento/magento2-base`,
   `magento/framework` – Framework-Versionen 103.0.N werden auf 2.4.N abgebildet) nach Einträgen
   ab, die in den letzten 30 Tagen angelegt oder geändert wurden. Treffer auf den WooCommerce-CPE
   erhalten im Entwurf `component = "WooCommerce"`. Bekannte IDs (`advisories/*.toml`, `aliases`)
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
- OSV kennt kein WordPress-Ökosystem. `advisories/woocommerce.toml` enthält nur WordPress-Core und
  WooCommerce; für alle anderen Plugins meldet `--online` lediglich „veraltet“ (Vergleich mit
  WordPress.org). Eine Anbindung von Schwachstellen-Feeds wie Wordfence Intelligence (öffentlich,
  Lizenzbedingungen beachten), WPScan oder Patchstack (API-Token nötig) ist als Erweiterung
  vorgesehen.
- Adobe verteilt zusätzlich isolierte Hotfixes (z. B. VULN-27015 für CosmicSting, VULN-32437 für
  SessionReaper), die die Versionsnummer nicht ändern. Installationen mit eingespieltem Hotfix
  werden weiterhin als verwundbar gemeldet und sind nach Prüfung als akzeptiert zu markieren.
