//! JTL-Shop 5 adapter.
//!
//! Reads `includes/config.JTL-Shop.ini.php` (database credentials), detects
//! the shop version from `includes/defines.php` and implements the checks of
//! the original backend plugin:
//!
//! * file scan profile (upload dirs, compiled templates, logs, plugin dir),
//! * CVE-2026-54390 patch status (version first, then an inspection of the
//!   Smarty mail renderer / registered modifiers),
//! * admin accounts with last login and 2FA status (`tadminlogin`),
//! * PayPal recipient / merchant settings with change detection,
//! * permissions of the configuration file,
//! * e-mail history (`temailhistory`, 90 days) and stored e-mail templates
//!   searched for the SSTI payload,
//! * customer / contact records containing template syntax,
//! * plugins and cron jobs added after the reference date,
//! * file evidence for the security releases 5.6.3 – 5.8.2 (consent XSS,
//!   safe-mode toggle, path traversal, RMA IDOR …), injected consent names in
//!   `consent_statistics` and the matching access-log indicators.

mod config;
mod db_checks;
mod fixes;

pub use config::JtlConfig;

use ecomsec_core::finding::{Category, Finding, Severity, Source};
use ecomsec_core::platform::{
    Advisory, ConfigFileSpec, FileScanProfile, IntegrityItem, IntegrityReport, IntegrityStatus,
    PatchEvidence, Platform, PlatformContext, PlatformInfo, PlatformKind,
};
use ecomsec_core::recommendations::{Recommendation, RecommendationGroupKind};
use ecomsec_core::report::Report;
use ecomsec_core::rules::RuleSet;
use ecomsec_core::version::Version;
use regex::Regex;
use std::path::{Path, PathBuf};

pub const PLATFORM_ID: &str = "jtl5";
pub const RULES_TOML: &str = include_str!("../signatures/rules_jtl5.toml");

/// Composer inventories shipped with JTL-Shop 5 (vendor libraries such as
/// Smarty, Symfony components, Guzzle).
pub const COMPOSER_INVENTORY: &[&str] = &[
    "includes/vendor/composer/installed.json",
    "vendor/composer/installed.json",
    "composer.lock",
];

/// Candidate locations of the Smarty mail renderer whose patch state is
/// inspected when the version number alone is not conclusive.
pub const RENDERER_CANDIDATES: &[&str] = &[
    "includes/src/Mail/Renderer/SmartyRenderer.php",
    "includes/src/Mail/SmartyRenderer.php",
    "includes/src/Smarty/MailSmarty.php",
    "includes/src/Mail/Mailer.php",
];

/// Files where the dangerous Smarty modifiers are registered.
pub const MODIFIER_REGISTRATION_CANDIDATES: &[&str] = &[
    "includes/src/Smarty/MailSmarty.php",
    "includes/src/Smarty/JTLSmarty.php",
    "includes/src/Mail/Renderer/SmartyRenderer.php",
    "includes/src/Smarty/SmartyRegistry.php",
];

/// Markers whose presence in the renderer indicates that the vendor patch or
/// the official back-patch was applied.  This is a heuristic: JTL did not
/// publish a byte-exact description of the fix, so every marker that a
/// hardened renderer would plausibly contain is accepted.
pub const PATCH_MARKERS: &[&str] = &[
    r"CVE-2026-54390",
    r"setSecurityPolicy|security_policy|Smarty_Security|SmartySecurity|SecurityPolicy",
    r"disabled_tags|disabled_modifiers|allowed_modifiers|allowed_tags|disabled_special_smarty_vars",
    r"unregisterPlugin\s*\(\s*['\x22]modifier['\x22]\s*,\s*['\x22](unserialize|file_get_contents)",
    r"(escapeSmarty|sanitizeTemplate|escapeTemplateSyntax|stripSmartyTags|removeSmartyTags|literal)\s*\(",
    r"str_replace\s*\(\s*\[?\s*['\x22]\{['\x22]",
    r"preg_replace\s*\([^)]{0,80}\\\{",
];

pub struct Jtl5 {
    root: PathBuf,
    config: JtlConfig,
    version: Option<Version>,
    version_source: String,
}

impl Jtl5 {
    /// Does `root` look like a JTL-Shop 5 installation?
    pub fn detect(root: &Path) -> bool {
        root.join("includes/config.JTL-Shop.ini.php").is_file()
            || (root.join("includes/defines.php").is_file() && root.join("admin").is_dir())
            || root.join("includes/src/Shop.php").is_file()
    }

    pub fn open(root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        let root = root.canonicalize().unwrap_or(root);
        let config = JtlConfig::load(&root);
        let (version, version_source) = detect_version(&root);
        Ok(Jtl5 {
            root,
            config,
            version,
            version_source,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config(&self) -> &JtlConfig {
        &self.config
    }

    pub fn version(&self) -> Option<&Version> {
        self.version.as_ref()
    }

    /// Override the version (e.g. from the database).
    pub fn set_version(&mut self, v: Version, source: &str) {
        self.version = Some(v);
        self.version_source = source.to_string();
    }

    fn read_rel(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.root.join(rel)).ok()
    }
}

/// Detect the shop version from `includes/defines.php` (constant
/// `APPLICATION_VERSION`), falling back to `includes/config.JTL-Shop.ini.php`.
pub fn detect_version(root: &Path) -> (Option<Version>, String) {
    let re = Regex::new(r#"APPLICATION_VERSION['"]?\s*[,=]\s*['"]v?([0-9]+(?:\.[0-9]+)+)['"]"#)
        .expect("regex");
    for rel in [
        "includes/defines.php",
        "includes/defines_inc.php",
        "includes/config.JTL-Shop.ini.php",
    ] {
        if let Ok(text) = std::fs::read_to_string(root.join(rel)) {
            if let Some(c) = re.captures(&text) {
                if let Some(v) = Version::parse(&c[1]) {
                    return (Some(v), rel.to_string());
                }
            }
        }
    }
    (None, "nicht gefunden".into())
}

/// Embedded advisory file (`advisories/jtl5.toml` in the repository).
pub const ADVISORIES_TOML: &str = include_str!("../advisories.toml");

fn embedded_advisories() -> Vec<Advisory> {
    let mut db = ecomsec_core::AdvisoryDb::new();
    db.merge_toml("builtin:advisories/jtl5.toml", ADVISORIES_TOML)
        .expect("embedded JTL advisories are valid");
    db.for_platform(PLATFORM_ID)
}

/// OSV.dev lookup of the bundled Composer packages (only with `--online`).
fn dependency_check(root: &Path, ctx: &PlatformContext, report: &mut IntegrityReport) {
    if !ctx.online {
        report
            .items
            .push(ecomsec_osv::offline_item(root, COMPOSER_INVENTORY));
        return;
    }
    match ecomsec_osv::check_root(root, COMPOSER_INVENTORY, &ecomsec_osv::OsvClient::default()) {
        None => report
            .items
            .push(ecomsec_osv::offline_item(root, COMPOSER_INVENTORY)),
        Some(Ok(out)) => {
            report.findings.extend(out.findings);
            report.items.push(out.item);
            report.limitations.extend(out.limitations);
        }
        Some(Err(e)) => {
            report
                .limitations
                .push(format!("OSV-Abgleich fehlgeschlagen: {e}"));
            report
                .items
                .push(ecomsec_osv::offline_item(root, COMPOSER_INVENTORY));
        }
    }
}

impl Platform for Jtl5 {
    fn info(&self) -> PlatformInfo {
        let mut details = vec![("Versionsquelle".to_string(), self.version_source.clone())];
        if let Some(url) = &self.config.shop_url {
            details.push(("Shop-URL".into(), url.clone()));
        }
        if let Some(db) = &self.config.db {
            details.push(("Datenbank".into(), db.display()));
        }
        PlatformInfo {
            id: PLATFORM_ID.into(),
            name: "JTL-Shop 5".into(),
            kind: PlatformKind::SelfHosted,
            version: self.version.clone(),
            root: Some(self.root.clone()),
            target: self.config.shop_url.clone(),
            details,
        }
    }

    fn file_scan_profile(&self) -> Option<FileScanProfile> {
        let mut p = FileScanProfile::new(&self.root);
        p.generated_dirs = vec![
            "templates_c".into(),
            "admin/templates_c".into(),
            "includes/vendor/smarty/smarty/libs/sysplugins".into(),
        ];
        p.upload_dirs = vec![
            "mediafiles".into(),
            "bilder".into(),
            "uploads".into(),
            "export".into(),
            "gfx".into(),
            "media".into(),
            "downloads".into(),
            "dbeS/tmp".into(),
            "admin/export".into(),
            "admin/gfx".into(),
            "admin/uploads".into(),
            "templates/Evo/themes".into(),
        ];
        p.log_dirs = vec!["jtllogs".into(), "admin/jtllogs".into(), "dbeS/logs".into()];
        p.core_dirs = vec!["admin".into(), "includes".into()];
        p.config_files = vec![
            ConfigFileSpec {
                path: "includes/config.JTL-Shop.ini.php".into(),
                description: "Shop-Konfiguration (DB-Zugang, Blowfish-Key)".into(),
                secret: true,
            },
            ConfigFileSpec {
                path: ".htaccess".into(),
                description: "Webserver-Konfiguration im Shop-Root".into(),
                secret: false,
            },
            ConfigFileSpec {
                path: "admin/.htaccess".into(),
                description: "Webserver-Konfiguration des Admin-Backends".into(),
                secret: false,
            },
        ];
        p.template_extensions = vec!["tpl".into()];
        Some(p)
    }

    fn rules(&self) -> RuleSet {
        RuleSet::from_toml("builtin:rules_jtl5", RULES_TOML).expect("embedded JTL rules compile")
    }

    fn advisories(&self) -> Vec<Advisory> {
        embedded_advisories()
    }

    fn db_credentials(&self) -> Option<ecomsec_core::db::DbCredentials> {
        self.config.db.clone()
    }

    fn access_log_indicators(&self) -> Vec<ecomsec_core::access_log::LogIndicator> {
        fixes::log_indicators()
    }

    fn patch_evidence(&self, advisory: &Advisory, _ctx: &PlatformContext) -> Option<PatchEvidence> {
        if fixes::handles(&advisory.id) {
            let ev = fixes::evidence(&advisory.id, &|rel| self.read_rel(rel));
            // CVE-2026-54390: fall back to the heuristic below for back-patches
            // that do not touch the renderer the way the official fix does.
            if ev.is_some() || advisory.id != "CVE-2026-54390" {
                return ev;
            }
        }
        if advisory.id != "CVE-2026-54390" {
            return None;
        }
        // 1. Are the dangerous modifiers still registered?  (RCE chain, 5.4.0+)
        let reg = Regex::new(
            r#"(?m)^[^/#*\n]*registerPlugin\s*\(\s*['"]modifier['"]\s*,\s*['"](unserialize|file_get_contents)['"]"#,
        )
        .expect("regex");
        for rel in MODIFIER_REGISTRATION_CANDIDATES {
            if let Some(text) = self.read_rel(rel) {
                if let Some(c) = reg.captures(&text) {
                    return Some(PatchEvidence {
                        patched: false,
                        checked: rel.to_string(),
                        detail: format!(
                            "Der gefährliche Smarty-Modifier `{}` ist weiterhin registriert – die RCE-Kette von \
                             CVE-2026-54390 steht zur Verfügung",
                            &c[1]
                        ),
                    });
                }
            }
        }
        // 2. Does the mail renderer carry a hardening marker?
        let markers: Vec<Regex> = PATCH_MARKERS
            .iter()
            .map(|m| Regex::new(m).expect("marker regex"))
            .collect();
        for rel in RENDERER_CANDIDATES {
            if let Some(text) = self.read_rel(rel) {
                let hits: Vec<&str> = markers
                    .iter()
                    .zip(PATCH_MARKERS.iter())
                    .filter(|(re, _)| re.is_match(&text))
                    .map(|(_, raw)| *raw)
                    .collect();
                if !hits.is_empty() {
                    return Some(PatchEvidence {
                        patched: true,
                        checked: rel.to_string(),
                        detail: format!(
                            "Smarty-Mail-Renderer enthält Härtungsmarker ({}); Patch bzw. Back-Patch eingespielt (heuristische Bewertung)",
                            hits.len()
                        ),
                    });
                }
                return Some(PatchEvidence {
                    patched: false,
                    checked: rel.to_string(),
                    detail: "Smarty-Mail-Renderer ohne Härtungsmarker – kein Patch-Nachweis".into(),
                });
            }
        }
        None
    }

    fn integrity(&self, ctx: &PlatformContext) -> anyhow::Result<IntegrityReport> {
        let mut report = IntegrityReport::default();
        report.items.push(
            IntegrityItem::new(
                "shop.version",
                "Shop",
                "JTL-Shop Version",
                if self.version.is_some() {
                    IntegrityStatus::Ok
                } else {
                    IntegrityStatus::Warning
                },
                self.version
                    .as_ref()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unbekannt".into()),
            )
            .with_detail(format!("Quelle: {}", self.version_source)),
        );
        config::permission_checks(&self.root, &mut report);
        dependency_check(&self.root, ctx, &mut report);
        if ctx.skip_remote {
            report
                .limitations
                .push("Datenbankprüfungen übersprungen (--skip-remote).".into());
            return Ok(report);
        }
        match &self.config.db {
            None => {
                report.limitations.push(
                    "Keine Datenbank-Zugangsdaten gefunden (includes/config.JTL-Shop.ini.php) – Admin-Konten, \
                     PayPal und E-Mail-Historie nicht geprüft."
                        .into(),
                );
                report.findings.push(
                    Finding::new(
                        Severity::Info,
                        Category::ScanLimitation,
                        Source::Scanner,
                        "jtl_db_config_missing",
                        "includes/config.JTL-Shop.ini.php",
                        "Datenbankprüfungen nicht möglich: Konfiguration nicht lesbar",
                    )
                    .with_description(
                        "Die Datei includes/config.JTL-Shop.ini.php konnte nicht gelesen oder geparst werden.",
                    ),
                );
            }
            Some(creds) => match creds.connect() {
                Ok(mut conn) => db_checks::run(self, &mut conn, ctx, &mut report),
                Err(e) => {
                    report
                        .limitations
                        .push(format!("Datenbank nicht erreichbar: {e}"));
                    report.findings.push(
                        Finding::new(
                            Severity::Info,
                            Category::ScanLimitation,
                            Source::Database,
                            "jtl_db_unreachable",
                            creds.display(),
                            "Datenbank nicht erreichbar – DB-Prüfungen übersprungen",
                        )
                        .with_description(e.to_string()),
                    );
                }
            },
        }
        Ok(report)
    }

    fn recommendations(&self, report: &Report) -> Vec<Recommendation> {
        let mut recs = Vec::new();
        let vulnerable = report.advisories.iter().any(|a| {
            matches!(
                a.state,
                ecomsec_core::platform::PatchState::Vulnerable
                    | ecomsec_core::platform::PatchState::Unknown
            )
        });
        if vulnerable {
            recs.push(Recommendation::new(
                RecommendationGroupKind::Immediate,
                1,
                "JTL-Shop auf 5.5.4 / 5.6.2 / 5.7.2 (oder neuer) aktualisieren bzw. Back-Patch einspielen",
                "Download über das JTL-Kundencenter bzw. die JTL-Forum-Ankündigung zu CVE-2026-54390. Danach \
                 Blowfish-Key in includes/config.JTL-Shop.ini.php, Datenbank-Passwort, dbeS-Synchronisations-\
                 Passwort, SMTP-/Newsletter-Zugänge, FTP/SFTP, Redis, OAuth-Secrets rotieren – alle Werte waren \
                 vor dem Patch durch die Lücke auslesbar.",
            ));
        }
        recs.push(Recommendation::new(
            RecommendationGroupKind::Hardening,
            3,
            "Admin-Backend zusätzlich absichern",
            "Admin-Verzeichnis umbenennen oder per HTTP-Auth/IP-Allowlist schützen, 2FA für alle Admin-Konten \
             (JTL-Backend › Benutzerverwaltung) erzwingen und Login-Versuche im Backend überwachen.",
        ));
        recs.push(Recommendation::new(
            RecommendationGroupKind::Hardening,
            3,
            "Plugins und Templates nur aus vertrauenswürdigen Quellen",
            "Nur Plugins aus dem JTL Extension Store oder von bekannten Agenturen installieren; nicht genutzte \
             Plugins deinstallieren (nicht nur deaktivieren). Nach jedem Plugin-Update erneut scannen.",
        ));
        recs
    }
}
