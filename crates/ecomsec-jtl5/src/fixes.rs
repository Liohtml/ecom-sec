//! File-based patch evidence for JTL security releases 5.5.4 – 5.8.5 and the
//! access-log indicators published with them.
//!
//! JTL ships the fixes both as releases and as loose patch files for older
//! branches, so the version number alone does not tell whether a shop is
//! protected.  Every check below looks at a file the official fix changes and
//! decides by markers taken from the public code diff
//! (gitlab.com/jtl-software/jtl-shop/core, tags v5.6.4 → v5.8.3) and – since
//! JTL no longer publishes patch releases there – from the official packages
//! (build.jtl-shop.de) and the hotfix diffs of 12.11. and 24.11.2026, which
//! cover every version from 5.0.0.

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
        // 5.8.3: no fixes for 5.6 / 5.7; markers checked against 5.2.0, 5.4.0,
        // 5.5.0, 5.6.5, 5.7.5, 5.8.2 (vulnerable) and 5.8.3 (fixed).
        "JTL-SHOP-10049" => &[FileCheck {
            rel: "includes/src/Backend/Notification.php",
            fixed: r"isValidHash",
            vulnerable: r#"notification_hash IN \('"\s*\.\s*\$hashes->implode"#,
            what: "Prüfung der Hashes ausgeblendeter Benachrichtigungen",
        }],
        "JTL-2026-BACKEND-PRIVESC" => &[
            FileCheck {
                rel: "includes/src/Router/Controller/Backend/AdminAccountController.php",
                fixed: r"errorNoPermissionAdminGroup",
                vulnerable: r"kAdminlogingruppe\s*=\s*Request::pInt\('kAdminlogingruppe'\)",
                what: "Schutz der Administratorgruppe in der Benutzerverwaltung",
            },
            FileCheck {
                rel: "includes/src/TwoFA/BackendTwoFA.php",
                fixed: r"assertCurrentAccountMayManage",
                vulnerable: r"BackendUserData::getByName\(\$userName,\s*\$db\)",
                what: "Rechteprüfung bei der 2FA-Verwaltung von Administratoren",
            },
        ],
        "JTL-2026-WAWI-SYNC" => &[
            FileCheck {
                rel: "includes/src/dbeS/Sync/ImageUpload.php",
                fixed: r"ALLOWED_MIME_TYPES",
                vulnerable: r"\\?copy\(\$tmpfile",
                what: "Typprüfung im Wawi-Bildabgleich",
            },
            FileCheck {
                rel: "includes/src/dbeS/Sync/AbstractSync.php",
                fixed: r"excludeParams",
                vulnerable: r"NOT IN \('\s*\.\s*\\?implode\(', ',\s*\$excludeValues\)",
                what: "Parameter beim Löschen im Wawi-Abgleich",
            },
        ],
        "JTL-2026-CHECKOUT-PAYMENT" => &[FileCheck {
            rel: "includes/src/Router/Controller/CheckoutController.php",
            fixed: r"customerGroupAllowedForPaymentMethod",
            vulnerable: r"function\s+paymentMethodIsValid",
            what: "Prüfung von Aktivierung und Kundengruppe der Zahlungsart",
        }],
        // 12.11.2026 (5.8.4 / 5.7.6 / 5.6.6 / 5.5.5).  Markers checked against
        // both sides of every hotfix diff 5.0.0 – 5.8.3 and the packages.
        "CVE-2026-22308" => &[FileCheck {
            rel: "includes/src/OPC/Service.php",
            fixed: r"PreviewToken::isValid",
            vulnerable: r"verifyGPDataString\('opcPreviewMode'\)\s*===\s*'yes'",
            what: "Vorschau nur mit Token aus dem OPC-Editor",
        }],
        "CVE-2026-22309" => &[FileCheck {
            rel: "includes/src/Crawler/Controller.php",
            fixed: r"sanitizeCrawlerText",
            vulnerable: r"\$botName\s*=\s*\$crawlerDetect->getMatches\(\)\s*;",
            what: "Bereinigung erkannter Crawler-User-Agents",
        }],
        "CVE-2026-22310" => &[FileCheck {
            rel: "includes/src/Redirect/Services/ValidationService.php",
            fixed: r"UNSAFE_404_SOURCE_PATTERN",
            vulnerable: r"function\s+add404Redirect\(string \$url,\s*\?string \$queryString\)",
            what: "Prüfung gespeicherter 404-URLs",
        }],
        "CVE-2026-22311" => &[FileCheck {
            rel: "includes/src/dbeS/FailedLoginLimiter.php",
            fixed: r"function\s+registerFailure",
            vulnerable: r"function\s+getLimit\(\):\s*int\s*\{\s*return 5;",
            what: "Fehlversuche am Wawi-Abgleich sperren nicht mehr",
        }],
        "CVE-2026-123058" => &[FileCheck {
            rel: "includes/src/Installation/VueInstaller.php",
            fixed: r"AlreadyInstalledException",
            vulnerable: r"'doinstall'\s*=>\s*\$this->doInstall\(\)|case 'doinstall':",
            what: "Sperre des Installers auf eingerichteten Shops",
        }],
        "CVE-2026-125060" => &[FileCheck {
            rel: "includes/src/Router/Controller/CheckoutController.php",
            fixed: r"DeliveryAddressOwnership|resolveSelectableDeliveryAddressID",
            vulnerable: r"kLieferadresse\s*=\s*\(int\)\(\$post\['kLieferadresse'\]\s*\?\?\s*-1\)",
            what: "Besitzprüfung der Lieferadresse im Bestellprozess",
        }],
        "JTL-2026-ADMIN-PWRESET" => &[FileCheck {
            rel: "includes/src/Router/Controller/Backend/PasswordController.php",
            fixed: r"getAdminIDByResetPasswordHash",
            vulnerable: r"update\('tadminlogin',\s*'cMail',\s*Request::pString\('fpm'\)",
            what: "Konto wird über den Reset-Link bestimmt",
        }],
        "JTL-2026-DBES-CATEGORY-SQLI" => &[FileCheck {
            rel: "includes/src/dbeS/Sync/Categories.php",
            fixed: r"buildIntList\('attribPK'",
            vulnerable: r"NOT IN \('\s*\.\s*\\?implode\(', ',\s*\$attribPKs\)",
            what: "Gebundene IDs im Kategorie-Abgleich",
        }],
        "JTL-2026-BACKEND-RIGHTS-584" => &[
            FileCheck {
                rel: "includes/src/Router/Controller/Backend/IOController.php",
                fixed: r"function\s+guardedRegister",
                vulnerable: r"->register\('getCustomers',\s*\$jsonApi->getCustomers\(\.\.\.\)\)",
                what: "Rechteprüfung der Backend-IO-Funktionen",
            },
            FileCheck {
                rel: "includes/src/Router/Controller/Backend/AdminAccountController.php",
                fixed: r"function\s+deleteAvatarFile",
                vulnerable: r"unlink\(\s*\\?PFAD_ROOT\s*\.\s*\$attribs\['useAvatarUpload'\]\s*\)",
                what: "Avatar-Löschung nur im Avatar-Verzeichnis",
            },
        ],
        // 24.11.2026 (5.8.5 / 5.7.7 / 5.6.7 / 5.5.6), checked against both
        // sides of every hotfix diff 5.0.0 – 5.8.4 and the packages.
        "CVE-2026-133938" => &[FileCheck {
            rel: "includes/src/Router/Controller/Backend/AdminAccountController.php",
            fixed: r"actionQuickChangeLanguage\(\)(:\s*void)?\s*\{\s*if\s*\(\s*Form::validateToken\(\)\s*===\s*false\s*\)",
            vulnerable: r"function\s+actionQuickChangeLanguage\(\)(:\s*void)?\s*\{\s*\$this->changeAdminUserLanguage",
            what: "Token-Prüfung der Backend-Sprachumschaltung",
        }],
        "CVE-2026-133939" => &[FileCheck {
            rel: "admin/opc/tpl/startmenu.tpl",
            fixed: r"\$opcStartUrl\|escape:'javascript'",
            vulnerable: r"url:\s*'\{\$opcStartUrl\}'",
            what: "Maskierung im OPC-Startmenü",
        }],
        // The file exists in every version; only the fixed one denies all files.
        "CVE-2026-133940" => &[FileCheck {
            rel: "export/backup/.htaccess",
            fixed: r#"<FilesMatch\s+"\.\*">"#,
            vulnerable: r"\A",
            what: "Sperre aller Dateien in export/backup (nur Apache)",
        }],
        "CVE-2026-133941" => &[FileCheck {
            rel: "includes/src/Country/Manager.php",
            fixed: r"function\s+getSortOrder\(\)",
            vulnerable: r"'activeSortOrder',\s*Request::pString\('activeSortOrder'\)",
            what: "Prüfung von activeSortOrder in der Länderverwaltung",
        }],
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
        LogIndicator::new(
            "jtl5_log_backup_download",
            Severity::Critical,
            "Sicherungsdatei aus export/backup erfolgreich abgerufen",
            "Antwort 200 oder 206 auf eine Datei in /export/backup/: Eine Datenbank- oder Dateisicherung wurde \
             heruntergeladen (CVE-2026-133940). Absender prüfen; stammt der Abruf nicht von euch, Zugangsdaten aus \
             der Konfiguration ändern und eine Meldung nach DSGVO Art. 33 prüfen. 404-Antworten auf .sql.gz- oder \
             .zip-Namen deuten auf Raten von Dateinamen hin.",
            r#"(?i)"(?:GET|HEAD) [^"]*/export/backup/[^"\s]*\.(?:gz|zip)[^"]*" (?:200|206) "#,
            Some("CVE-2026-133940"),
        ),
        LogIndicator::new(
            "jtl5_log_quick_change_language",
            Severity::Critical,
            "Backend-Sprachumschaltung mit Skript- oder Sonderzeichen",
            "action=quick_change_language mit einem Wert, der kein Sprachcode ist, ist ein Versuch, CVE-2026-133938 \
             auszunutzen. Fremder Referer oder GET-Aufruf ohne vorheriges Backend-Login sprechen für einen Angriff. \
             tadminlogin.language prüfen (Scan mit Datenbankzugang) und Admin-Sitzungen beenden.",
            r#"(?i)"(?:GET|POST) [^"]*quick_change_language[^"]*language=[^&"\s]*(?:%27|%22|%3b|%3c|<|')"#,
            Some("CVE-2026-133938"),
        ),
        LogIndicator::new(
            "jtl5_log_country_sort_injection",
            Severity::Warning,
            "Länderverwaltung mit manipuliertem activeSortOrder",
            "activeSortOrder darf nur ASC oder DESC sein. Sonderzeichen deuten auf einen Versuch hin, CVE-2026-133941 \
             auszunutzen; der Code lief im Browser des Backend-Nutzers, der den Link geöffnet hat.",
            r#"(?i)"GET [^"]*activeSortOrder=[^&"\s]*(?:%27|%22|%3c|%3e|%3b|<|')"#,
            Some("CVE-2026-133941"),
        ),
        LogIndicator::new(
            "jtl5_log_opc_preview_get",
            Severity::Warning,
            "OPC-Vorschaumodus per GET aufgerufen",
            "Der OPC-Editor sendet die Vorschau per POST. GET-Aufrufe mit opcPreviewMode stammen aus Links und sind auf \
             ungepatchten Shops ein Weg für reflektiertes XSS (CVE-2026-22308). Mit %3C oder %22 in den Parametern \
             ist ein Angriff wahrscheinlich.",
            r#"(?i)"GET [^"]*opcPreviewMode="#,
            Some("CVE-2026-22308"),
        ),
        LogIndicator::new(
            "jtl5_log_installer_access",
            Severity::Warning,
            "Zugriff auf den Web-Installer",
            "Aufrufe von /install/ nach der Installation sind verdächtig: Vor 5.8.4 / 5.7.6 / 5.6.6 / 5.5.5 ließ sich \
             der Shop darüber ohne Anmeldung neu einrichten (CVE-2026-123058). Konfiguration, Admin- und Sync-Konten \
             prüfen; das Verzeichnis install/ löschen.",
            r#"(?i)"POST [^"]*/install/(?:install\.php|index\.php)?[^"\s]*task=(?:doinstall|credentialscheck|installdemodata)"#,
            Some("CVE-2026-123058"),
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

    // Excerpts of JTL-Shop 5.8.2 (vulnerable) and 5.8.3 (fixed).
    const NOTIF_582: &str = r#"$this->db->query(
                "DELETE FROM tnotificationsignore
                    WHERE notification_hash IN ('" . $hashes->implode('notification_hash', "', '") . "')"
            );"#;
    const NOTIF_583: &str = r#"public static function isValidHash(string $hash): bool
                    AND notification_hash IN (' . \implode(', ', $placeholders) . ')',"#;
    const SYNC_582: &str =
        r#"AND ' . $excludeKey . ' NOT IN (' . \implode(', ', $excludeValues) . ')' : '');"#;
    const SYNC_583: &str = r#"$excludeParams = []; AND `' . $excludeKey . '` NOT IN (:'"#;
    const IMG_582: &str =
        r#"if (\copy($tmpfile, \PFAD_ROOT . \PFAD_MEDIA_IMAGE_STORAGE . $item->cPfad)) {"#;
    const IMG_583: &str = r#"private const array ALLOWED_MIME_TYPES = [ 'jpg' => 'image/jpeg' ];
            if (\copy($tmpfile, \PFAD_ROOT . \PFAD_MEDIA_IMAGE_STORAGE . $item->cPfad)) {"#;

    #[test]
    fn release_583_markers() {
        let notif = "includes/src/Backend/Notification.php";
        assert!(
            !evidence("JTL-SHOP-10049", &reader(&[(notif, NOTIF_582)]))
                .unwrap()
                .patched
        );
        assert!(
            evidence("JTL-SHOP-10049", &reader(&[(notif, NOTIF_583)]))
                .unwrap()
                .patched
        );

        let sync = "includes/src/dbeS/Sync/AbstractSync.php";
        let img = "includes/src/dbeS/Sync/ImageUpload.php";
        let fixed = reader(&[(sync, SYNC_583), (img, IMG_583)]);
        assert!(evidence("JTL-2026-WAWI-SYNC", &fixed).unwrap().patched);
        // Half of the patch is not enough.
        let partial = reader(&[(sync, SYNC_583), (img, IMG_582)]);
        let e = evidence("JTL-2026-WAWI-SYNC", &partial).unwrap();
        assert!(!e.patched && e.checked == img);
        assert!(
            !evidence("JTL-2026-WAWI-SYNC", &reader(&[(sync, SYNC_582)]))
                .unwrap()
                .patched
        );

        let ctl = "includes/src/Router/Controller/Backend/AdminAccountController.php";
        let tfa = "includes/src/TwoFA/BackendTwoFA.php";
        let old = reader(&[
            (
                ctl,
                "$tmpAcc->kAdminlogingruppe = Request::pInt('kAdminlogingruppe');",
            ),
            (
                tfa,
                "$twoFA = new self($db, BackendUserData::getByName($userName, $db));",
            ),
        ]);
        assert!(!evidence("JTL-2026-BACKEND-PRIVESC", &old).unwrap().patched);
        let new = reader(&[
            (ctl, "$tmpAcc->kAdminlogingruppe = Request::pInt('kAdminlogingruppe'); $this->addError(__('errorNoPermissionAdminGroup'));"),
            (tfa, "$twoFA = new self($db, BackendUserData::getByName($userName, $db)); self::assertCurrentAccountMayManage($twoFA->getUserData());"),
        ]);
        assert!(evidence("JTL-2026-BACKEND-PRIVESC", &new).unwrap().patched);

        let co = "includes/src/Router/Controller/CheckoutController.php";
        assert!(
            !evidence(
                "JTL-2026-CHECKOUT-PAYMENT",
                &reader(&[(co, "public function paymentMethodIsValid(")])
            )
            .unwrap()
            .patched
        );
        assert!(evidence("JTL-2026-CHECKOUT-PAYMENT", &reader(&[(co, "public function paymentMethodIsValid( Helper::customerGroupAllowedForPaymentMethod(")])).unwrap().patched);
    }

    /// Payloads of CVE-2026-54390 keep matching, stock JTL files do not.
    #[test]
    fn ssti_rules_spare_stock_templates() {
        let rules = ecomsec_core::rules::RuleSet::from_toml(
            "jtl5",
            include_str!("../signatures/rules_jtl5.toml"),
        )
        .unwrap();
        let names = |class: &str, data: &[u8]| {
            rules
                .scan(class, data)
                .iter()
                .map(|h| h.rule.name().to_string())
                .collect::<Vec<_>>()
        };
        for payload in [
            &b"vorname={capture name=a}x{/capture}{eval var=$smarty.capture.a}"[..],
            b"{eval var=\"{system('id')}\"}",
            b"{eval var=$oBoxContent}",
        ] {
            assert!(
                names("log", payload).contains(&"jtl_ssti_eval_tag_with_var".to_string()),
                "{}",
                String::from_utf8_lossy(payload)
            );
        }
        for payload in [
            &b"{$smarty.capture.a|unserialize}"[..],
            b"{\"/etc/passwd\"|file_get_contents}",
        ] {
            assert!(names("template", payload)
                .contains(&"jtl_smarty_dangerous_modifier_chain".to_string()));
        }
        // templates/NOVA/boxes/box_custom.tpl (5.0 – 5.8.3)
        let nova =
            b"<div class=\"box-content-wrapper\">\n    {eval var=$oBox->getContent()}\n</div>";
        assert!(
            names("template", nova).is_empty(),
            "{:?}",
            names("template", nova)
        );
        // includes/libs/tinymce/js/tinymce/plugins/codesample/plugin.min.js
        let tinymce = b"function(e){var t=/\\b(?:abstract|assert|boolean|break|byte|case)\\b/}";
        assert!(
            names("js", tinymce).is_empty(),
            "{:?}",
            names("js", tinymce)
        );
    }

    /// Excerpts of the official JTL code before and after the November fixes
    /// (hotfix diffs 12.11. / 24.11.2026, version 5.8.3 / 5.8.4).
    #[test]
    fn november_2026_markers() {
        let cases: &[(&str, &str, &str, &str)] = &[
            (
                "CVE-2026-22308",
                "includes/src/OPC/Service.php",
                "return Request::verifyGPDataString('opcPreviewMode') === 'yes';",
                "return \\is_string($token) && PreviewToken::isValid($token, (string)Shop::getAdminSessionToken(), \\time());",
            ),
            (
                "CVE-2026-22309",
                "includes/src/Crawler/Controller.php",
                "$botName            = $crawlerDetect->getMatches();",
                "$botName            = self::sanitizeCrawlerText($crawlerDetect->getMatches() ?? '');",
            ),
            (
                "CVE-2026-22310",
                "includes/src/Redirect/Services/ValidationService.php",
                "private function add404Redirect(string $url, ?string $queryString): ?stdClass",
                "private const string UNSAFE_404_SOURCE_PATTERN = '/[<>\"]/';",
            ),
            (
                "CVE-2026-22311",
                "includes/src/dbeS/FailedLoginLimiter.php",
                "public function getLimit(): int\n    {\n        return 5;\n    }",
                "public function registerFailure(): void",
            ),
            (
                "CVE-2026-123058",
                "includes/src/Installation/VueInstaller.php",
                "'doinstall'        => $this->doInstall(),",
                "} catch (AlreadyInstalledException $e) {",
            ),
            (
                "CVE-2026-125060",
                "includes/src/Router/Controller/CheckoutController.php",
                "$_SESSION['Bestellung']->kLieferadresse = (int)($post['kLieferadresse'] ?? -1);",
                "kLieferadresse = (new DeliveryAddressOwnership($this->db))->resolveSelectableID(",
            ),
            (
                "JTL-2026-ADMIN-PWRESET",
                "includes/src/Router/Controller/Backend/PasswordController.php",
                "if ($this->db->update('tadminlogin', 'cMail', Request::pString('fpm'), $upd) > 0) {",
                "$adminID = $this->account->getAdminIDByResetPasswordHash(",
            ),
            (
                "JTL-2026-DBES-CATEGORY-SQLI",
                "includes/src/dbeS/Sync/Categories.php",
                "AND tkategorieattribut.kKategorieAttribut NOT IN (' . \\implode(', ', $attribPKs) . ')' : ''),",
                "[$notIn, $notInParams] = $this->buildIntList('attribPK', $attribPKs);",
            ),
            (
                "CVE-2026-133938",
                "includes/src/Router/Controller/Backend/AdminAccountController.php",
                "public function actionQuickChangeLanguage(): void\n    {\n        $this->changeAdminUserLanguage(Request::verifyGPDataString('language'));",
                "public function actionQuickChangeLanguage(): void\n    {\n        if (Form::validateToken() === false) {\n            return;\n        }",
            ),
            (
                "CVE-2026-133939",
                "admin/opc/tpl/startmenu.tpl",
                "url: '{$opcStartUrl}',",
                "url: '{$opcStartUrl|escape:'javascript'}',",
            ),
            (
                "CVE-2026-133940",
                "export/backup/.htaccess",
                "<IfModule !mod_authz_core.c>\n    Order Deny,Allow\n    Deny from all\n</IfModule>",
                "</IfModule>\n\n<FilesMatch \".*\">\n    Require all denied\n</FilesMatch>",
            ),
            (
                "CVE-2026-133941",
                "includes/src/Country/Manager.php",
                "'activeSortOrder',\n                Request::pString('activeSortOrder') ?: Request::gString('activeSortOrder')",
                "private function getSortOrder(): string",
            ),
        ];
        for (id, rel, old, new) in cases {
            assert!(handles(id), "{id}");
            let before =
                evidence(id, &reader(&[(rel, old)])).unwrap_or_else(|| panic!("{id}: no evidence"));
            assert!(!before.patched, "{id}: old code must be vulnerable");
            let after =
                evidence(id, &reader(&[(rel, new)])).unwrap_or_else(|| panic!("{id}: no evidence"));
            assert!(after.patched, "{id}: new code must be patched");
        }
    }

    #[test]
    fn november_2026_log_indicators() {
        let ids = |line: &str| {
            log_indicators()
                .into_iter()
                .filter(|i| i.pattern.is_match(line))
                .map(|i| i.id)
                .collect::<Vec<_>>()
        };
        let line = |req: &str, status: u16| {
            format!("203.0.113.7 - - [20/Nov/2026:03:12:44 +0100] \"{req} HTTP/1.1\" {status} 1234 \"-\" \"curl/8\"")
        };
        assert_eq!(
            ids(&line(
                "GET /export/backup/20261101_sql_9f1c2a_backup.sql.gz",
                200
            )),
            ["jtl5_log_backup_download"]
        );
        assert!(ids(&line(
            "GET /export/backup/20261101_sql_9f1c2a_backup.sql.gz",
            404
        ))
        .is_empty());
        assert_eq!(
            ids(&line(
                "GET /admin/?action=quick_change_language&language=de-DE%27%3Balert(1)%2F%2F",
                302
            )),
            ["jtl5_log_quick_change_language"]
        );
        assert!(ids(&line(
            "GET /admin/?action=quick_change_language&language=en-GB&jtl_token=abc",
            302
        ))
        .is_empty());
        assert_eq!(
            ids(&line(
                "GET /admin/countries?activeSortOrder=ASC%27%3E%3Cscript%3E",
                200
            )),
            ["jtl5_log_country_sort_injection"]
        );
        assert!(ids(&line("GET /admin/countries?activeSortOrder=DESC", 200)).is_empty());
        assert_eq!(
            ids(&line("GET /?opcPreviewMode=yes&pageData=%3Cimg", 200)),
            ["jtl5_log_opc_preview_get"]
        );
        assert_eq!(
            ids(&line("POST /install/install.php?task=doinstall", 200)),
            ["jtl5_log_installer_access"]
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
