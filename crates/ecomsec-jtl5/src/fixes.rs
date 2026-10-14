//! File-based patch evidence for JTL security releases 5.5.4 – 5.8.2 and the
//! access-log indicators published with them.
//!
//! JTL ships the fixes both as releases and as loose patch files for older
//! branches, so the version number alone does not tell whether a shop is
//! protected.  Every check below looks at a file the official fix changes and
//! decides by markers taken from the public code diff
//! (gitlab.com/jtl-software/jtl-shop/core, tags v5.6.4 → v5.8.2).

use ecomsec_core::access_log::LogIndicator;
use ecomsec_core::finding::Severity;
use ecomsec_core::platform::PatchEvidence;
use regex::Regex;

/// One file touched by a fix.
struct FileCheck {
    rel: &'static str,
    /// Present only after the fix.
    fixed: &'static str,
    /// Present only before the fix.
    vulnerable: &'static str,
    /// What the file shows, for the report.
    what: &'static str,
}

/// File checks per advisory id.
fn checks(id: &str) -> &'static [FileCheck] {
    match id {
        // Official fix (5.5.4 / 5.6.2 / 5.7.2 and the back-patch): user values
        // in mail subjects get their Smarty delimiters escaped.
        "CVE-2026-54390" => &[FileCheck {
            rel: "includes/src/Mail/Renderer/SmartyRenderer.php",
            fixed: r"\{ldelim\}",
            vulnerable: r"\$replace\[\]\s*=\s*\$value\s*;",
            what: "Maskierung von Smarty-Syntax in Platzhaltern des Mail-Renderers",
        }],
        "CVE-2026-103904" => &[
            FileCheck {
                rel: "admin/templates/bootstrap/statistik.tpl",
                fixed: r"\$oStat->\$cMemberVar\s*\|\s*escape",
                vulnerable: r"\{\$oStat->\$cMemberVar\}",
                what: "Ausgabe der Consent-Namen in der Statistik",
            },
            FileCheck {
                rel: "includes/src/Consent/Manager.php",
                fixed: r"getActiveItemIDs",
                vulnerable: r"function\s+getConsentsFromData",
                what: "Prüfung der Einwilligungs-Namen beim Speichern",
            },
        ],
        "CVE-2026-103905" => &[], // order based, see `safemode_evidence`
        "JTL-2026-PATH-TRAVERSAL" => &[
            FileCheck {
                rel: "includes/src/dbeS/Sync/ImageUpload.php",
                fixed: r"hasTraversal",
                vulnerable: r"'cPfad'\s*=>\s*\(string\)\s*\$child->attributes\(\)->cHash",
                what: "Pfadprüfung im Wawi-Bildabgleich",
            },
            FileCheck {
                rel: "includes/src/ImageMap.php",
                fixed: r"realpath\(\s*\\?PFAD_ROOT\s*\.\s*\\?PFAD_BILDER_BANNER\s*\)",
                vulnerable: r"unlink\(\s*\\?PFAD_ROOT\s*\.\s*\\?PFAD_BILDER_BANNER\s*\.\s*\$bannerData",
                what: "Pfadprüfung beim Löschen von ImageMaps",
            },
            FileCheck {
                rel: "includes/src/Router/Controller/Backend/BannerController.php",
                fixed: r"deleteBannerFile",
                vulnerable: r"unlink\(\s*\\?PFAD_ROOT\s*\.\s*\\?PFAD_BILDER_BANNER\s*\.\s*\$bannerPath",
                what: "Pfadprüfung beim Ersetzen von Bannern",
            },
        ],
        "JTL-SHOP-9886" => &[FileCheck {
            rel: "includes/src/RMA/Services/RMAReturnAddressService.php",
            fixed: r"returnAddressFromDeliveryAddressTemplateID\s*\([^)]*\$customerID",
            vulnerable: r"returnAddressFromDeliveryAddressTemplateID\s*\(\s*int\s+\$deliveryAddressTemplateID\s*\)",
            what: "Besitzprüfung der Rücksendeadresse",
        }],
        "JTL-2026-PWRESET-XSS" => &[FileCheck {
            rel: "includes/src/Router/Controller/ForgotPasswordController.php",
            // 5.8.0 already filters the preset field, so only the message counts.
            fixed: r"(\$email\s*=\s*Text::filterXSS\(|filterXSS\(\$email\))",
            vulnerable: r"(\$email\s*=\s*\$requestData\['email'\]\s*;|'forgot password'\s*\)\s*,\s*\$email\s*\))",
            what: "Filterung der E-Mail-Adresse in der Meldung",
        }],
        "JTL-2026-ADMIN-XSS" => &[
            FileCheck {
                rel: "admin/templates/bootstrap/tpl_inc/bewertung_editieren.tpl",
                fixed: r"htmlentities\(\$review->getName\(\)",
                vulnerable: r#"value="\{\$review->getName\(\)\}""#,
                what: "Ausgabe von Bewertungen im Backend",
            },
            FileCheck {
                rel: "includes/src/Router/Controller/Backend/ActivationController.php",
                fixed: r"filterXSS\(\s*Request::verifyGPDataString\('cSuchTyp'\)",
                vulnerable: r"assign\('cSuchTyp',\s*Request::verifyGPDataString\('cSuchTyp'\)\)",
                what: "Suchparameter der Freischaltungen",
            },
        ],
        _ => &[],
    }
}

/// File that must exist for the advisory to apply at all (the vulnerable
/// feature is younger than the oldest affected file).
fn precondition(id: &str) -> Option<&'static str> {
    match id {
        // Consent statistics were introduced with 5.4.0.
        "CVE-2026-103904" => {
            Some("includes/src/Consent/Statistics/Repositories/ConsentStatisticsRepository.php")
        }
        _ => None,
    }
}

/// Whether this module knows the advisory.
pub fn handles(id: &str) -> bool {
    id == "CVE-2026-103905" || !checks(id).is_empty()
}

/// Evaluate the file evidence for `id`.  `read` returns the content of a file
/// relative to the shop root.
pub fn evidence(id: &str, read: &dyn Fn(&str) -> Option<String>) -> Option<PatchEvidence> {
    if id == "CVE-2026-103905" {
        return safemode_evidence(read);
    }
    if let Some(rel) = precondition(id) {
        read(rel)?;
    }
    let mut fixed = Vec::new();
    let mut vulnerable = Vec::new();
    for c in checks(id) {
        let Some(text) = read(c.rel) else { continue };
        let is_fixed = Regex::new(c.fixed).expect("fix marker").is_match(&text);
        let is_vuln = Regex::new(c.vulnerable)
            .expect("vuln marker")
            .is_match(&text);
        if is_vuln && !is_fixed {
            vulnerable.push(c);
        } else if is_fixed {
            fixed.push(c);
        }
    }
    let files = |list: &[&FileCheck]| list.iter().map(|c| c.rel).collect::<Vec<_>>().join(", ");
    if !vulnerable.is_empty() {
        return Some(PatchEvidence {
            patched: false,
            checked: files(&vulnerable),
            detail: format!(
                "Ungepatchter Code gefunden: {}",
                vulnerable
                    .iter()
                    .map(|c| c.what)
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        });
    }
    if !fixed.is_empty() {
        return Some(PatchEvidence {
            patched: true,
            checked: files(&fixed),
            detail: format!(
                "Fix im Code nachgewiesen ({})",
                fixed.iter().map(|c| c.what).collect::<Vec<_>>().join("; ")
            ),
        });
    }
    None
}

/// CVE-2026-103905: the vulnerable middleware toggles the safe-mode lock
/// *before* it checks the admin session, the fixed one only afterwards.
fn safemode_evidence(read: &dyn Fn(&str) -> Option<String>) -> Option<PatchEvidence> {
    const REL: &str = "includes/src/Router/Middleware/AuthMiddleware.php";
    let text = read(REL)?;
    let toggle = text.find("plgSafeMode")?;
    let auth = text.find("->isValid()")?;
    Some(if toggle > auth {
        PatchEvidence {
            patched: true,
            checked: REL.into(),
            detail: "Fix im Code nachgewiesen (Wartungsmodus wird erst nach der Anmeldeprüfung umgeschaltet)"
                .into(),
        }
    } else {
        PatchEvidence {
            patched: false,
            checked: REL.into(),
            detail:
                "Ungepatchter Code gefunden: Wartungsmodus wird vor der Anmeldeprüfung umgeschaltet"
                    .into(),
        }
    })
}

/// Request patterns from the JTL advisories, for `--access-log`.
pub fn log_indicators() -> Vec<LogIndicator> {
    vec![
        LogIndicator::new(
            "jtl5_log_safemode_toggle",
            Severity::Warning,
            "Wartungsmodus per URL umgeschaltet (/admin/logout?safemode=)",
            "Aufrufe von /admin/logout mit dem Parameter safemode= schalten auf ungepatchten Shops ohne Anmeldung \
             den Wartungsmodus um (CVE-2026-103905). Prüfen, ob die Aufrufe von eigenen Administratoren stammen; \
             fremde IP-Adressen, ungewöhnliche Uhrzeiten, häufige Wiederholung oder ein Referer einer fremden \
             Domain deuten auf Ausnutzung hin.",
            r#"(?i)"(?:GET|POST|HEAD) [^"]*/admin/logout[^"\s]*[?&]safemode="#,
            Some("CVE-2026-103905"),
        ),
        LogIndicator::new(
            "jtl5_log_consent_injection",
            Severity::Critical,
            "Eingeschleuste Einwilligungs-Namen über /_updateconsent",
            "Anfragen an /_updateconsent mit HTML- oder Skript-Zeichen sind Versuche, CVE-2026-103904 auszunutzen \
             (gespeichertes XSS in der Consent-Statistik). Tabelle consent_statistics prüfen, die Consent-Statistik \
             bis zur Bereinigung nicht öffnen, Admin-Konten, Rechte, Plugins und Templates im Zeitraum kontrollieren.",
            r#"(?i)"(?:GET|POST) [^"]*_updateconsent[^"\s]*(?:%3c|<|%3e|%22|%27|javascript|onerror|onload)"#,
            Some("CVE-2026-103904"),
        ),
        LogIndicator::new(
            "jtl5_log_consent_stats_view",
            Severity::Info,
            "Consent-Statistik im Backend geöffnet (/admin/stats/6)",
            "Zeitpunkte, zu denen ein Administrator die Consent-Statistik geöffnet hat. Auf ungepatchten Shops wurde \
             dabei eingeschleuster Code (CVE-2026-103904) ausgeführt; Änderungen an Konten, Rechten, Plugins und \
             Einstellungen in diesen Zeiträumen prüfen.",
            r#"(?i)"GET [^"]*/admin/stats/6(?:[/?\s"])"#,
            Some("CVE-2026-103904"),
        ),
        LogIndicator::new(
            "jtl5_log_rma_summary_get",
            Severity::Critical,
            "Direkter Aufruf der Retouren-Methode rmaSummary per GET",
            "Der Shop selbst ruft rmaSummary per POST auf. GET-Aufrufe mit rmaSummary im Log sind laut JTL ein Beweis \
             für manuelle Aufrufe, typisch für das Abgreifen fremder Lieferadressen (JTL-SHOP-9886). Anzahl und \
             Absender prüfen und eine Meldung nach DSGVO Art. 33 erwägen.",
            r#"(?i)"GET [^"]*rmaSummary"#,
            Some("JTL-SHOP-9886"),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn reader(files: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<&str, &str> = files.iter().cloned().collect();
        move |rel| map.get(rel).map(|s| s.to_string())
    }

    // Excerpts of JTL-Shop 5.8.1 (vulnerable) and 5.8.2 (fixed).
    const STATS_REPO: &str =
        "includes/src/Consent/Statistics/Repositories/ConsentStatisticsRepository.php";
    const TPL_581: &str = "{else}\n    {$oStat->$cMemberVar}\n{/if}";
    const TPL_582: &str = "{else}\n    {$oStat->$cMemberVar|escape:'html'}\n{/if}";
    const MGR_581: &str =
        "private function getConsentsFromData(array $data): array\n{ $consents = []; }";
    const MGR_582: &str = "private function getConsentsFromData(array $data): array\n{ $allowedKeys = $this->getActiveItemIDs(); }";
    const AUTH_581: &str = "if (isset($GLOBALS['plgSafeMode'])) { touch(SAFE_MODE_LOCK); }\nif (!$this->account->isValid()) { return; }";
    const AUTH_582: &str = "if (!$this->account->isValid()) { return; }\nif (isset($GLOBALS['plgSafeMode'])) { touch(SAFE_MODE_LOCK); }";

    #[test]
    fn consent_xss_vulnerable_and_fixed() {
        let ev = evidence(
            "CVE-2026-103904",
            &reader(&[
                ("admin/templates/bootstrap/statistik.tpl", TPL_581),
                ("includes/src/Consent/Manager.php", MGR_581),
                (STATS_REPO, "<?php"),
            ]),
        )
        .unwrap();
        assert!(!ev.patched);
        assert!(ev.checked.contains("statistik.tpl"));
        let ev = evidence(
            "CVE-2026-103904",
            &reader(&[
                ("admin/templates/bootstrap/statistik.tpl", TPL_582),
                ("includes/src/Consent/Manager.php", MGR_582),
                (STATS_REPO, "<?php"),
            ]),
        )
        .unwrap();
        assert!(ev.patched);
        // Half-applied patch counts as vulnerable.
        let ev = evidence(
            "CVE-2026-103904",
            &reader(&[
                ("admin/templates/bootstrap/statistik.tpl", TPL_582),
                ("includes/src/Consent/Manager.php", MGR_581),
                (STATS_REPO, "<?php"),
            ]),
        )
        .unwrap();
        assert!(!ev.patched);
        assert!(ev.detail.contains("Speichern"));
    }

    #[test]
    fn consent_xss_needs_consent_statistics() {
        // 5.0 – 5.3 have statistik.tpl but no consent statistics.
        assert!(evidence(
            "CVE-2026-103904",
            &reader(&[("admin/templates/bootstrap/statistik.tpl", TPL_581)])
        )
        .is_none());
    }

    #[test]
    fn password_reset_580_is_vulnerable() {
        let rel = "includes/src/Router/Controller/ForgotPasswordController.php";
        let v580 = "->assign('presetEmail', Text::filterXSS($requestData['email']))\n$email       = $requestData['email'];";
        let v581 = "$email       = Text::filterXSS((string)$requestData['email']);";
        assert!(
            !evidence("JTL-2026-PWRESET-XSS", &reader(&[(rel, v580)]))
                .unwrap()
                .patched
        );
        assert!(
            evidence("JTL-2026-PWRESET-XSS", &reader(&[(rel, v581)]))
                .unwrap()
                .patched
        );
    }

    #[test]
    fn safemode_order_decides() {
        let rel = "includes/src/Router/Middleware/AuthMiddleware.php";
        assert!(
            !evidence("CVE-2026-103905", &reader(&[(rel, AUTH_581)]))
                .unwrap()
                .patched
        );
        assert!(
            evidence("CVE-2026-103905", &reader(&[(rel, AUTH_582)]))
                .unwrap()
                .patched
        );
        assert!(evidence("CVE-2026-103905", &reader(&[])).is_none());
    }

    #[test]
    fn ssti_fix_marker() {
        let rel = "includes/src/Mail/Renderer/SmartyRenderer.php";
        let v561 = "foreach ($vars as $value) {\n    $replace[] = $value;\n}";
        let v562 = "$replace[] = \\is_string($value)\n    ? \\strtr($value, ['{' => '{ldelim}', '}' => '{rdelim}'])\n    : $value;";
        assert!(
            !evidence("CVE-2026-54390", &reader(&[(rel, v561)]))
                .unwrap()
                .patched
        );
        assert!(
            evidence("CVE-2026-54390", &reader(&[(rel, v562)]))
                .unwrap()
                .patched
        );
    }

    #[test]
    fn unknown_files_give_no_evidence() {
        assert!(evidence("JTL-SHOP-9886", &reader(&[])).is_none());
        assert!(!handles("CVE-2099-0001"));
        assert!(handles("CVE-2026-103905"));
    }

    #[test]
    fn log_indicators_match_advisory_examples() {
        let ind = log_indicators();
        let by = |id: &str| ind.iter().find(|i| i.id == id).unwrap();
        let line = r#"203.0.113.7 - - [14/Oct/2026:09:12:01 +0200] "GET /admin/logout?safemode=1 HTTP/1.1" 302 0 "https://evil.example/" "-""#;
        assert!(by("jtl5_log_safemode_toggle").pattern.is_match(line));
        assert!(!by("jtl5_log_safemode_toggle")
            .pattern
            .is_match(r#"1.2.3.4 - - [x] "GET /admin/logout HTTP/1.1" 302 0 "-" "-""#));
        assert!(by("jtl5_log_rma_summary_get").pattern.is_match(
            r#"1.2.3.4 - - [x] "GET /io?io={%22name%22:%22rmaSummary%22} HTTP/1.1" 200 1 "-" "-""#
        ));
        assert!(!by("jtl5_log_rma_summary_get")
            .pattern
            .is_match(r#"1.2.3.4 - - [x] "POST /io HTTP/1.1" 200 1 "-" "-""#));
        assert!(by("jtl5_log_consent_injection")
            .pattern
            .is_match(r#"1.2.3.4 - - [x] "GET /_updateconsent?data[%3Csvg/onload=alert(1)%3E]=true HTTP/1.1" 200 1 "-" "-""#));
        assert!(by("jtl5_log_consent_stats_view")
            .pattern
            .is_match(r#"1.2.3.4 - - [x] "GET /admin/stats/6 HTTP/1.1" 200 1 "-" "-""#));
        assert!(!by("jtl5_log_consent_stats_view")
            .pattern
            .is_match(r#"1.2.3.4 - - [x] "GET /admin/stats/60 HTTP/1.1" 200 1 "-" "-""#));
    }
}
