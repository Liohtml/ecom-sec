//! Shopware 6 adapter.
//!
//! * Detects a Shopware 6 project root (composer.json with `shopware/core`
//!   or `shopware/production`, `public/index.php`).
//! * Reads `.env` / `.env.local` for `DATABASE_URL` and `APP_ENV`.
//! * Determines the version from `composer.lock` or
//!   `vendor/composer/installed.json`.
//! * File scan profile: `public/` as public root, `public/media`,
//!   `public/thumbnail` and `files/` as upload dirs, `var/cache` as
//!   generated, `var/log` as logs, Twig templates.
//! * Database checks: admin users and API integrations with change detection,
//!   apps/plugins installed after the reference date, payment provider
//!   configuration (PayPal, Mollie, Stripe …) with change detection, mail
//!   templates / flows / snippets / CMS slots searched for Twig SSTI payloads
//!   and foreign script tags.

mod db_checks;

use ecomsec_core::db::DbCredentials;
use ecomsec_core::finding::{Category, Finding, Severity, Source};
use ecomsec_core::platform::{
    Advisory, ConfigFileSpec, FileScanProfile, IntegrityItem, IntegrityReport, IntegrityStatus,
    Platform, PlatformContext, PlatformInfo, PlatformKind,
};
use ecomsec_core::recommendations::{Recommendation, RecommendationGroupKind};
use ecomsec_core::report::Report;
use ecomsec_core::rules::RuleSet;
use ecomsec_core::version::Version;
use regex::Regex;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const PLATFORM_ID: &str = "shopware6";
pub const RULES_TOML: &str = include_str!("../signatures/rules_shopware6.toml");

/// Composer inventories of a Shopware project (core, plugins, libraries).
pub const COMPOSER_INVENTORY: &[&str] = &["composer.lock", "vendor/composer/installed.json"];

#[derive(Debug, Clone, Default)]
pub struct ShopwareEnv {
    pub values: BTreeMap<String, String>,
    pub db: Option<DbCredentials>,
    pub app_env: Option<String>,
    pub app_url: Option<String>,
}

impl ShopwareEnv {
    pub fn load(root: &Path) -> Self {
        let mut values = BTreeMap::new();
        for name in [".env", ".env.local", ".env.prod", ".env.prod.local"] {
            if let Ok(text) = std::fs::read_to_string(root.join(name)) {
                for (k, v) in parse_dotenv(&text) {
                    values.insert(k, v);
                }
            }
        }
        // Environment variables of the current process win (container setups).
        for key in ["DATABASE_URL", "APP_ENV", "APP_URL"] {
            if let Ok(v) = std::env::var(key) {
                if !v.is_empty() && !values.contains_key(key) {
                    values.insert(key.to_string(), v);
                }
            }
        }
        let db = values
            .get("DATABASE_URL")
            .and_then(|u| DbCredentials::from_url(u));
        ShopwareEnv {
            app_env: values.get("APP_ENV").cloned(),
            app_url: values.get("APP_URL").cloned(),
            db,
            values,
        }
    }
}

/// Minimal dotenv parser (KEY=value, quotes, comments, `export`).
pub fn parse_dotenv(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let mut v = v.trim().to_string();
        if (v.starts_with('"') && v.ends_with('"') && v.len() >= 2)
            || (v.starts_with('\'') && v.ends_with('\'') && v.len() >= 2)
        {
            v = v[1..v.len() - 1].to_string();
        } else if let Some(idx) = v.find(" #") {
            v = v[..idx].trim().to_string();
        }
        if !k.is_empty() {
            out.push((k.to_string(), v));
        }
    }
    out
}

pub struct Shopware6 {
    root: PathBuf,
    env: ShopwareEnv,
    version: Option<Version>,
    version_source: String,
}

impl Shopware6 {
    pub fn detect(root: &Path) -> bool {
        let composer = root.join("composer.json");
        let is_sw_composer = std::fs::read_to_string(&composer)
            .map(|t| {
                t.contains("shopware/core")
                    || t.contains("shopware/production")
                    || t.contains("shopware/platform")
            })
            .unwrap_or(false);
        is_sw_composer
            || root.join("vendor/shopware/core").is_dir()
            || (root.join("public/index.php").is_file()
                && root.join("bin/console").is_file()
                && root.join("custom/plugins").is_dir())
    }

    pub fn open(root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        let root = root.canonicalize().unwrap_or(root);
        let env = ShopwareEnv::load(&root);
        let (version, version_source) = detect_version(&root);
        Ok(Shopware6 {
            root,
            env,
            version,
            version_source,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn env(&self) -> &ShopwareEnv {
        &self.env
    }
}

/// Version from `composer.lock` (package `shopware/core`), falling back to
/// `vendor/composer/installed.json`.
pub fn detect_version(root: &Path) -> (Option<Version>, String) {
    for rel in ["composer.lock", "vendor/composer/installed.json"] {
        if let Ok(text) = std::fs::read_to_string(root.join(rel)) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                let packages = json
                    .get("packages")
                    .and_then(|p| p.as_array())
                    .cloned()
                    .or_else(|| json.as_array().cloned())
                    .unwrap_or_default();
                for name in ["shopware/core", "shopware/platform"] {
                    if let Some(pkg) = packages
                        .iter()
                        .find(|p| p.get("name").and_then(|n| n.as_str()) == Some(name))
                    {
                        if let Some(v) = pkg
                            .get("version")
                            .and_then(|v| v.as_str())
                            .and_then(Version::parse)
                        {
                            return (Some(v), format!("{rel} ({name})"));
                        }
                    }
                }
            }
        }
    }
    // Last resort: the Kernel constant in vendor.
    if let Ok(text) = std::fs::read_to_string(root.join("vendor/shopware/core/Kernel.php")) {
        let re = Regex::new(r#"SHOPWARE_FALLBACK_VERSION\s*=\s*['"]v?([0-9]+(?:\.[0-9]+)+)"#)
            .expect("regex");
        if let Some(c) = re.captures(&text) {
            if let Some(v) = Version::parse(&c[1]) {
                return (Some(v), "vendor/shopware/core/Kernel.php".into());
            }
        }
    }
    (None, "nicht gefunden".into())
}

/// Embedded advisory file (`advisories/shopware6.toml` in the repository).
pub const ADVISORIES_TOML: &str = include_str!("../../../advisories/shopware6.toml");

fn advisories() -> Vec<Advisory> {
    let mut db = ecomsec_core::AdvisoryDb::new();
    db.merge_toml("builtin:advisories/shopware6.toml", ADVISORIES_TOML)
        .expect("embedded Shopware advisories are valid");
    db.for_platform(PLATFORM_ID)
}

impl Platform for Shopware6 {
    fn info(&self) -> PlatformInfo {
        let mut details = vec![("Versionsquelle".to_string(), self.version_source.clone())];
        if let Some(e) = &self.env.app_env {
            details.push(("APP_ENV".into(), e.clone()));
        }
        if let Some(db) = &self.env.db {
            details.push(("Datenbank".into(), db.display()));
        }
        PlatformInfo {
            id: PLATFORM_ID.into(),
            name: "Shopware 6".into(),
            kind: PlatformKind::SelfHosted,
            version: self.version.clone(),
            root: Some(self.root.clone()),
            target: self.env.app_url.clone(),
            details,
        }
    }

    fn file_scan_profile(&self) -> Option<FileScanProfile> {
        let mut p = FileScanProfile::new(&self.root);
        p.public_root = Some(self.root.join("public"));
        p.generated_dirs = vec!["var/cache".into(), "var/queue".into()];
        p.upload_dirs = vec![
            "public/media".into(),
            "public/thumbnail".into(),
            "public/sitemap".into(),
            "files".into(),
            "public/documents".into(),
            "var/sessions".into(),
            "public/bundles".into(),
            "public/theme".into(),
        ];
        p.log_dirs = vec!["var/log".into()];
        p.core_dirs = vec![
            "vendor/shopware".into(),
            "src".into(),
            "bin".into(),
            "config".into(),
        ];
        p.config_files = vec![
            ConfigFileSpec {
                path: ".env".into(),
                description: "Umgebungskonfiguration (DATABASE_URL, APP_SECRET)".into(),
                secret: true,
            },
            ConfigFileSpec {
                path: ".env.local".into(),
                description: "Lokale Umgebungskonfiguration".into(),
                secret: true,
            },
            ConfigFileSpec {
                path: "config/jwt/private.pem".into(),
                description: "JWT-Signaturschlüssel".into(),
                secret: true,
            },
            ConfigFileSpec {
                path: "public/.htaccess".into(),
                description: "Webserver-Konfiguration".into(),
                secret: false,
            },
        ];
        p.template_extensions = vec!["twig".into()];
        Some(p)
    }

    fn rules(&self) -> RuleSet {
        RuleSet::from_toml("builtin:rules_shopware6", RULES_TOML)
            .expect("embedded Shopware rules compile")
    }

    fn advisories(&self) -> Vec<Advisory> {
        advisories()
    }

    fn integrity(&self, ctx: &PlatformContext) -> anyhow::Result<IntegrityReport> {
        let mut report = IntegrityReport::default();
        report.items.push(
            IntegrityItem::new(
                "shop.version",
                "Shop",
                "Shopware Version",
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
        match self.env.app_env.as_deref() {
            Some("prod") => report.items.push(IntegrityItem::new(
                "shop.app_env",
                "Shop",
                "APP_ENV",
                IntegrityStatus::Ok,
                "prod",
            )),
            Some(other) => {
                report.items.push(IntegrityItem::new(
                    "shop.app_env",
                    "Shop",
                    "APP_ENV",
                    IntegrityStatus::Warning,
                    other,
                ));
                report.findings.push(
                    Finding::new(Severity::Warning, Category::ExposedFile, Source::Configuration, "app_env_not_prod", ".env", format!("APP_ENV={other} – Debug-Modus aktiv"))
                        .with_description("Im Dev-Modus liefert Symfony detaillierte Fehlerseiten mit Pfaden, Stacktraces und Konfigurationswerten aus. Für Produktivsysteme APP_ENV=prod setzen."),
                );
            }
            None => report.items.push(IntegrityItem::new(
                "shop.app_env",
                "Shop",
                "APP_ENV",
                IntegrityStatus::Unknown,
                "nicht gesetzt",
            )),
        }
        permission_checks(&self.root, &mut report);
        dependency_check(&self.root, ctx, &mut report);
        if ctx.skip_remote {
            report
                .limitations
                .push("Datenbankprüfungen übersprungen (--skip-remote).".into());
            return Ok(report);
        }
        match &self.env.db {
            None => {
                report.limitations.push("Keine DATABASE_URL in .env gefunden – Admin-/App-/Zahlungsprüfungen übersprungen.".into());
                report.findings.push(
                    Finding::new(Severity::Info, Category::ScanLimitation, Source::Scanner, "sw_db_config_missing", ".env", "Datenbankprüfungen nicht möglich: DATABASE_URL fehlt")
                        .with_description("DATABASE_URL weder in .env/.env.local noch in der Prozessumgebung gefunden."),
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
                            "sw_db_unreachable",
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
        if report.advisories.iter().any(|a| {
            matches!(
                a.state,
                ecomsec_core::platform::PatchState::Vulnerable
                    | ecomsec_core::platform::PatchState::Unknown
            )
        }) {
            recs.push(Recommendation::new(
                RecommendationGroupKind::Immediate,
                1,
                "Shopware aktualisieren oder Security-Plugin installieren",
                "`composer update shopware/*` auf die behobene Version, alternativ `composer require shopware/security-plugin` (swag/security) für Hotfixes. Danach APP_SECRET, JWT-Schlüssel (config/jwt), Datenbank-Passwort und Admin-API-Integrationen rotieren.",
            ));
        }
        recs.push(Recommendation::new(
            RecommendationGroupKind::Hardening,
            3,
            "Admin-API-Integrationen und Apps regelmäßig prüfen",
            "Unter Einstellungen › System › Integrationen alle Access-Keys zuordnen; nicht genutzte löschen. Apps mit weitreichenden Berechtigungen (z. B. Bestellungen schreiben, Zahlungen) nur von vertrauenswürdigen Herstellern.",
        ));
        recs.push(Recommendation::new(
            RecommendationGroupKind::Hardening,
            3,
            "Webroot auf public/ beschränken",
            "Der Document Root muss auf `public/` zeigen; `.env`, `var/`, `config/` und `vendor/` dürfen nie per HTTP erreichbar sein. `APP_ENV=prod` und Deploy mit `bin/console cache:clear` statt manueller Änderungen in var/cache.",
        ));
        recs
    }
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

fn permission_checks(root: &Path, report: &mut IntegrityReport) {
    let targets: [(&str, bool); 5] = [
        (".env", true),
        (".env.local", true),
        ("config/jwt/private.pem", true),
        ("config/jwt/public.pem", false),
        ("public/.htaccess", false),
    ];
    for (rel, secret) in targets {
        let path = root.join(rel);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        let mode = mode_of(&meta);
        let perm = mode & 0o777;
        let (status, detail, finding): (IntegrityStatus, Option<&str>, Option<Severity>) =
            if perm & 0o002 != 0 {
                (
                    IntegrityStatus::Critical,
                    Some("für alle Benutzer schreibbar"),
                    Some(Severity::Critical),
                )
            } else if secret && perm & 0o004 != 0 {
                (
                    IntegrityStatus::Warning,
                    Some("für alle Benutzer lesbar"),
                    Some(Severity::Warning),
                )
            } else if perm & 0o020 != 0 {
                (
                    IntegrityStatus::Warning,
                    Some("gruppenschreibbar"),
                    Some(Severity::Warning),
                )
            } else {
                (IntegrityStatus::Ok, None, None)
            };
        let mut item = IntegrityItem::new(
            format!("perm.{rel}"),
            "Dateirechte",
            rel,
            status,
            format!("{perm:04o}"),
        );
        if let Some(d) = detail {
            item = item.with_detail(d);
        }
        report.items.push(item);
        if let Some(sev) = finding {
            report.findings.push(
                Finding::file(sev, Category::ConfigPermissions, "config_permissions", root, &path, format!("{rel}: {}", detail.unwrap_or("")))
                    .with_description("Dateien mit Zugangsdaten/Schlüsseln sollten nur für den Anwendungsbenutzer lesbar sein (0600/0640).")
                    .with_evidence(format!("mode={perm:04o}")),
            );
        }
    }
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn mode_of(_meta: &std::fs::Metadata) -> u32 {
    0o600
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_parsing() {
        let text = "# comment\nAPP_ENV=prod\nDATABASE_URL=\"mysql://u:p@localhost:3306/sw\"\nexport APP_URL='https://x' \nFOO=bar # trailing\n";
        let vars: BTreeMap<_, _> = parse_dotenv(text).into_iter().collect();
        assert_eq!(vars["APP_ENV"], "prod");
        assert_eq!(vars["DATABASE_URL"], "mysql://u:p@localhost:3306/sw");
        assert_eq!(vars["APP_URL"], "https://x");
        assert_eq!(vars["FOO"], "bar");
    }

    #[test]
    fn version_from_composer_lock() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("composer.lock"),
            r#"{"packages":[{"name":"symfony/console","version":"v6.3.0"},{"name":"shopware/core","version":"v6.5.7.4"}]}"#,
        )
        .unwrap();
        let (v, src) = detect_version(tmp.path());
        assert_eq!(v.unwrap().to_string(), "v6.5.7.4");
        assert!(src.starts_with("composer.lock"));
    }

    #[test]
    fn advisory_evaluation() {
        let advs = advisories();
        let sqli = advs.iter().find(|a| a.id == "CVE-2024-22406").unwrap();
        assert!(sqli.affects(&Version::parse("6.5.7.3").unwrap()));
        assert!(!sqli.affects(&Version::parse("6.5.7.4").unwrap()));
        assert!(!sqli.affects(&Version::parse("6.6.0.0").unwrap()));
    }
}
