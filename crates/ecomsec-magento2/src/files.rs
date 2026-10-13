//! File-system based Magento checks: entry points, `env.php`, admin route
//! hijacks, RequireJS configurations, module list, crontab inventory and
//! permissions.

use crate::config::EnvConfig;
use ecomsec_core::finding::{Category, Finding, Severity, Source};
use ecomsec_core::hosts::{classify_host, host_of, HostClass};
use ecomsec_core::platform::{IntegrityItem, IntegrityReport, IntegrityStatus, PlatformContext};
use ecomsec_core::util::{excerpt, relative_display, sha256_hex, strip_php_comments};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Domains of the Magento / Adobe ecosystem and common Magento payment SDKs.
pub const MAGENTO_PLATFORM_HOSTS: &[&str] = &[
    "magento.com",
    "magentocommerce.com",
    "adobe.com",
    "adobe.io",
    "adobedtm.com",
    "magento-opensource.com",
    "braintreegateway.com",
    "braintree-api.com",
    "paypal.com",
    "paypalobjects.com",
    "klarna.com",
    "klarnacdn.net",
    "googleapis.com",
    "gstatic.com",
];

fn backdoor_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(eval|assert|create_function|system|shell_exec|passthru|proc_open|popen)\s*\(|\b(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)\s*\(|(include|require)(_once)?\s*\(?\s*['"](https?|ftp|php|data)://|file_get_contents\s*\(\s*['"]https?://|file_put_contents\s*\(|\$_(GET|POST|REQUEST|COOKIE|FILES)\s*\[|\\x[0-9a-f]{2}\\x[0-9a-f]{2}"#,
        )
        .expect("regex")
    })
}

fn include_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)\b(include|require)(_once)?\b[^;]{0,200}"#).expect("regex"))
}

/// Entry points shipped by Magento and the includes they legitimately use.
const ENTRY_POINTS: &[(&str, &[&str])] = &[
    ("pub/index.php", &["app/bootstrap.php"]),
    ("index.php", &["app/bootstrap.php"]),
    (
        "pub/get.php",
        &[
            "app/bootstrap.php",
            "app/autoload.php",
            "bootstrap.php",
            "'errors/404.php'",
        ],
    ),
    ("pub/static.php", &["app/bootstrap.php"]),
    ("pub/cron.php", &["app/bootstrap.php"]),
    (
        "pub/health_check.php",
        &["app/bootstrap.php", "autoload.php", "vendor/autoload.php"],
    ),
    (
        "app/bootstrap.php",
        &[
            "autoload.php",
            "functions.php",
            "Magento/Framework",
            "vendor_path.php",
            "app/etc",
        ],
    ),
];

/// Entry points must not carry extra includes or code-execution primitives.
pub fn entry_point_checks(root: &Path, report: &mut IntegrityReport) {
    let mut deviations = 0usize;
    let mut critical = false;
    let mut checked = 0usize;
    for (rel, allowed) in ENTRY_POINTS {
        let path = root.join(rel);
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        checked += 1;
        let code = strip_php_comments(&String::from_utf8_lossy(&bytes));
        let foreign: Vec<String> = include_regex()
            .find_iter(&code)
            .map(|m| m.as_str().trim().to_string())
            .filter(|s| !allowed.iter().any(|a| s.contains(a)))
            .collect();
        let suspicious: Vec<String> = backdoor_regex()
            .find_iter(&code)
            .map(|m| m.as_str().to_string())
            // pub/get.php and bootstrap legitimately read $_SERVER only.
            .filter(|m| !m.starts_with("$_SERVER"))
            .take(3)
            .collect();
        if foreign.is_empty() && suspicious.is_empty() {
            continue;
        }
        deviations += 1;
        if !suspicious.is_empty() {
            critical = true;
        }
        let mut f = Finding::file(
            if suspicious.is_empty() {
                Severity::Warning
            } else {
                Severity::Critical
            },
            Category::IntegrityDeviation,
            "magento_entry_point_modified",
            root,
            &path,
            format!("{rel} enthält zusätzlichen Code oder Includes"),
        )
        .with_description(
            "Die Magento-Einstiegspunkte (pub/index.php, pub/get.php, pub/static.php, app/bootstrap.php) \
             laden nur den Bootstrap. Zusätzliche Includes oder eval/base64/Request-Zugriffe laufen bei jedem \
             Request – typisch für Skimmer-Loader und Webshells. Datei aus dem Original-Release \
             wiederherstellen (composer install / git checkout).",
        );
        for x in foreign.iter().chain(suspicious.iter()).take(4) {
            f = f.with_evidence(excerpt(x, 160));
        }
        report.findings.push(f);
    }
    report.items.push(IntegrityItem::new(
        "magento.entry_points",
        "Integrität",
        "Einstiegspunkte (pub/index.php, get.php, static.php, bootstrap.php)",
        if critical {
            IntegrityStatus::Critical
        } else if deviations > 0 {
            IntegrityStatus::Warning
        } else if checked == 0 {
            IntegrityStatus::Unknown
        } else {
            IntegrityStatus::Ok
        },
        format!("{checked} geprüft, {deviations} abweichend"),
    ));
}

/// `app/etc/env.php` is a plain `return [...]` array.
pub fn env_php_checks(root: &Path, env: &EnvConfig, report: &mut IntegrityReport) {
    let path = root.join("app/etc/env.php");
    let Ok(text) = std::fs::read_to_string(&path) else {
        report.items.push(IntegrityItem::new(
            "magento.env_php",
            "Konfiguration",
            "app/etc/env.php",
            IntegrityStatus::Warning,
            "nicht lesbar",
        ));
        return;
    };
    let code = strip_php_comments(&text);
    let mut hits: Vec<String> = include_regex()
        .find_iter(&code)
        .map(|m| m.as_str().to_string())
        .collect();
    hits.extend(
        backdoor_regex()
            .find_iter(&code)
            .map(|m| m.as_str().to_string()),
    );
    if !hits.is_empty() {
        let mut f = Finding::file(
            Severity::Critical,
            Category::SuspiciousPattern,
            "magento_env_php_code",
            root,
            &path,
            "app/etc/env.php enthält ausführbaren Code oder Includes",
        )
        .with_description(
            "env.php wird bei jedem Request geladen und enthält normalerweise nur ein Konfigurations-Array. \
             Includes, eval oder Request-Zugriffe sind ein Persistenzmuster. Datei bereinigen, \
             Datenbank-Passwort und Crypt-Key rotieren.",
        );
        for h in hits.iter().take(3) {
            f = f.with_evidence(excerpt(h, 160));
        }
        report.findings.push(f);
    }
    report.items.push(IntegrityItem::new(
        "magento.env_php",
        "Konfiguration",
        "app/etc/env.php",
        if hits.is_empty() {
            IntegrityStatus::Ok
        } else {
            IntegrityStatus::Critical
        },
        if hits.is_empty() {
            "reines Konfigurations-Array".to_string()
        } else {
            format!("{} verdächtige Anweisungen", hits.len())
        },
    ));
    // MAGE_MODE
    let mode = env.mage_mode.clone().unwrap_or_else(|| "default".into());
    report.items.push(IntegrityItem::new(
        "magento.mage_mode",
        "Konfiguration",
        "MAGE_MODE",
        if mode == "production" {
            IntegrityStatus::Ok
        } else {
            IntegrityStatus::Warning
        },
        &mode,
    ));
    if mode != "production" {
        report.findings.push(
            Finding::new(
                Severity::Warning,
                Category::ExposedFile,
                Source::Configuration,
                "magento_mode_not_production",
                "app/etc/env.php:MAGE_MODE",
                format!("MAGE_MODE={mode} – Shop läuft nicht im Production-Modus"),
            )
            .with_description(
                "Im developer/default-Modus zeigt Magento Fehlermeldungen mit Pfaden und Stacktraces und \
                 generiert Dateien zur Laufzeit. `bin/magento deploy:mode:set production` verwenden.",
            ),
        );
    }
    // Admin URL
    let front = env.admin_front_name.clone().unwrap_or_default();
    let default_admin = front.is_empty()
        || front.eq_ignore_ascii_case("admin")
        || front.eq_ignore_ascii_case("backend");
    report.items.push(IntegrityItem::new(
        "magento.admin_url",
        "Konfiguration",
        "Admin-Pfad (backend/frontName)",
        if default_admin {
            IntegrityStatus::Warning
        } else {
            IntegrityStatus::Ok
        },
        if default_admin {
            format!(
                "Standard ({})",
                if front.is_empty() { "admin" } else { &front }
            )
        } else {
            "individuell".to_string()
        },
    ));
    if default_admin {
        report.findings.push(
            Finding::new(
                Severity::Info,
                Category::Informational,
                Source::Configuration,
                "magento_default_admin_url",
                "app/etc/env.php:backend.frontName",
                "Magento-Admin unter dem Standardpfad /admin erreichbar",
            )
            .with_description(
                "Automatisierte Brute-Force- und Credential-Stuffing-Angriffe zielen auf /admin. Einen \
                 individuellen Admin-Pfad setzen (`bin/magento setup:config:set --backend-frontname=…`) und \
                 zusätzlich per IP-Allowlist schützen.",
            ),
        );
    }
    report.items.push(
        IntegrityItem::new(
            "magento.crypt_key",
            "Konfiguration",
            "Crypt-Key (crypt/key)",
            if env.crypt_key_present {
                IntegrityStatus::Ok
            } else {
                IntegrityStatus::Warning
            },
            if env.crypt_key_present {
                format!("vorhanden ({} Schlüssel)", env.crypt_keys)
            } else {
                "fehlt".to_string()
            },
        )
        .with_detail(
            "Nach CosmicSting (CVE-2024-34102) und jeder Kompromittierung rotieren – ausgelesene Keys \
             erlauben das Fälschen von Admin-API-Tokens.",
        ),
    );
    if env.document_root_is_pub == Some(false) {
        report.findings.push(
            Finding::new(
                Severity::Warning,
                Category::ExposedFile,
                Source::Configuration,
                "magento_docroot_not_pub",
                "app/etc/env.php:directories.document_root_is_pub",
                "Document Root zeigt nicht auf pub/",
            )
            .with_description(
                "Wenn der Webserver das Projektverzeichnis ausliefert, sind app/etc, var/ und vendor/ nur \
                 durch .htaccess-Regeln geschützt (wirkungslos unter nginx ohne passende Konfiguration). \
                 Document Root auf pub/ setzen.",
            ),
        );
    }
}

/// Frontend routes that claim the admin front name (phishing of admin
/// credentials) in custom modules.
pub fn admin_route_checks(root: &Path, env: &EnvConfig, report: &mut IntegrityReport) {
    let front = env
        .admin_front_name
        .clone()
        .unwrap_or_else(|| "admin".into())
        .to_ascii_lowercase();
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r#"(?i)<route\b[^>]*\bfrontName\s*=\s*["']([^"']+)["']"#).expect("regex")
    });
    let mut hits = 0usize;
    for base in ["app/code", "app/design"] {
        for entry in walkdir::WalkDir::new(root.join(base))
            .max_depth(6)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file() && e.file_name() == "routes.xml")
        {
            let path = entry.path();
            // Only storefront routes are a hijack; adminhtml routes are normal.
            let rel = relative_display(root, path);
            if rel.contains("/adminhtml/") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            for c in re.captures_iter(&text) {
                let name = c[1].to_ascii_lowercase();
                if name == front || name == "admin" || name == "backend" {
                    hits += 1;
                    report.findings.push(
                        Finding::file(
                            Severity::Critical,
                            Category::SuspiciousPattern,
                            "magento_admin_route_hijack",
                            root,
                            path,
                            format!("Storefront-Route beansprucht den Admin-Pfad „{name}“"),
                        )
                        .with_description(
                            "Ein Modul registriert eine Frontend-Route mit dem Namen des Admin-Pfads. So \
                             lassen sich gefälschte Admin-Logins einblenden und Zugangsdaten abgreifen. \
                             Modul prüfen und entfernen.",
                        )
                        .with_evidence(excerpt(&c[0], 160)),
                    );
                }
            }
        }
    }
    report.items.push(IntegrityItem::new(
        "magento.admin_route",
        "Integrität",
        "Frontend-Routen mit Admin-Pfad",
        if hits > 0 {
            IntegrityStatus::Critical
        } else {
            IntegrityStatus::Ok
        },
        hits.to_string(),
    ));
}

/// URLs referenced in RequireJS configurations (custom modules, themes and
/// the deployed `pub/static/_requirejs` bundles).
pub fn requirejs_checks(root: &Path, allow: &[String], report: &mut IntegrityReport) {
    static URL: OnceLock<Regex> = OnceLock::new();
    let url = URL.get_or_init(|| {
        Regex::new(r#"["'`]((?:https?:)?//[a-z0-9.\-]+\.[a-z]{2,}[^"'`\s]*)"#).expect("regex")
    });
    let mut files = 0usize;
    let mut foreign = 0usize;
    let mut seen = BTreeSet::new();
    for (base, depth) in [
        ("app/code", 8),
        ("app/design", 8),
        ("vendor", 6),
        ("pub/static/_requirejs", 8),
        ("pub/static/frontend", 8),
    ] {
        for entry in walkdir::WalkDir::new(root.join(base))
            .max_depth(depth)
            .into_iter()
            .filter_entry(|e| {
                let n = e.file_name().to_string_lossy();
                !(e.file_type().is_dir()
                    && (n == "Test" || n == "tests" || n == "node_modules" || n == "dev"))
            })
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_type().is_file()
                    && e.file_name()
                        .to_string_lossy()
                        .starts_with("requirejs-config")
            })
            .take(2000)
        {
            files += 1;
            let path = entry.path();
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            for c in url.captures_iter(&text) {
                let u = c[1].to_string();
                let host = host_of(&u).unwrap_or_default();
                let class = classify_host(&host, MAGENTO_PLATFORM_HOSTS, allow);
                let severity = match class {
                    HostClass::Suspicious => Severity::Critical,
                    HostClass::Unknown => Severity::Warning,
                    _ => continue,
                };
                let rel = relative_display(root, path);
                if !seen.insert((rel.clone(), host.clone())) {
                    continue;
                }
                foreign += 1;
                report.findings.push(
                    Finding::new(
                        severity,
                        Category::ThirdPartyInjection,
                        Source::FileSystem,
                        "magento_requirejs_foreign_url",
                        format!("{rel}:{host}"),
                        format!("RequireJS-Konfiguration lädt Code von {} ({host})", class.label()),
                    )
                    .with_description(
                        "Über requirejs-config.js eingebundene Module werden auf jeder Storefront-Seite – \
                         auch im Checkout – geladen. Magecart-Angreifer tragen dort ihre Skimmer-URL ein. \
                         Host zuordnen, sonst Konfiguration bereinigen und `setup:static-content:deploy` \
                         ausführen. Bekannte Anbieter per `--allow-host` freigeben.",
                    )
                    .with_evidence(excerpt(&u, 200)),
                );
            }
        }
    }
    report.items.push(IntegrityItem::new(
        "magento.requirejs",
        "Storefront",
        "RequireJS-Konfigurationen mit fremden URLs",
        if foreign > 0 {
            IntegrityStatus::Warning
        } else {
            IntegrityStatus::Ok
        },
        format!("{foreign} in {files} Dateien"),
    ));
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Snapshot {
    entries: BTreeMap<String, String>,
}

/// Module list from `app/etc/config.php` with change detection.
pub fn module_checks(
    root: &Path,
    modules: Option<&[(String, bool)]>,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) {
    let Some(modules) = modules else {
        report.items.push(IntegrityItem::new(
            "magento.modules",
            "Module",
            "Module (app/etc/config.php)",
            IntegrityStatus::Unknown,
            "nicht lesbar",
        ));
        return;
    };
    let enabled: Vec<&str> = modules
        .iter()
        .filter(|(_, e)| *e)
        .map(|(n, _)| n.as_str())
        .collect();
    let previous: Snapshot = ctx.state.snapshot("m2-modules").unwrap_or_default();
    let mut current = Snapshot::default();
    for (name, on) in modules {
        current
            .entries
            .insert(name.clone(), if *on { "1" } else { "0" }.into());
        let was = previous.entries.get(name);
        let newly_enabled =
            *on && !previous.entries.is_empty() && was.map(|w| w != "1").unwrap_or(true);
        if newly_enabled {
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    Category::ThirdPartyInjection,
                    Source::Configuration,
                    "magento_module_enabled",
                    format!("module:{name}"),
                    format!("Modul seit dem letzten Scan aktiviert: {name}"),
                )
                .with_description(
                    "Neue Module können Frontend-Code (Skimmer), Routen oder Cronjobs einbringen. \
                     Herkunft (Composer-Paket, app/code) und Änderung zuordnen.",
                ),
            );
        }
    }
    let third_party: Vec<&str> = enabled
        .iter()
        .copied()
        .filter(|n| {
            !n.starts_with("Magento_") && !n.starts_with("PayPal_") && !n.starts_with("Vertex")
        })
        .collect();
    let two_fa = enabled.contains(&"Magento_TwoFactorAuth");
    report.items.push(
        IntegrityItem::new(
            "magento.modules",
            "Module",
            "Module aktiv / Drittanbieter",
            IntegrityStatus::Ok,
            format!("{} / {}", enabled.len(), third_party.len()),
        )
        .with_detail(excerpt(&third_party.join(", "), 1500)),
    );
    report.items.push(IntegrityItem::new(
        "magento.2fa",
        "Admin-Konten",
        "Zwei-Faktor-Authentifizierung (Magento_TwoFactorAuth)",
        if two_fa {
            IntegrityStatus::Ok
        } else {
            IntegrityStatus::Warning
        },
        if two_fa { "aktiv" } else { "deaktiviert" },
    ));
    if !two_fa && modules.iter().any(|(n, _)| n == "Magento_TwoFactorAuth") {
        report.findings.push(
            Finding::new(
                Severity::Warning,
                Category::AdminAccount,
                Source::Configuration,
                "magento_2fa_disabled",
                "app/etc/config.php:Magento_TwoFactorAuth",
                "Zwei-Faktor-Authentifizierung für den Admin ist deaktiviert",
            )
            .with_description(
                "Magento 2.4 erzwingt 2FA standardmäßig; das Modul wurde abgeschaltet. Gestohlene \
                 Admin-Passwörter reichen damit für den Vollzugriff. Modul wieder aktivieren.",
            ),
        );
    }
    let _ = root;
    if let Err(e) = ctx.state.save_snapshot("m2-modules", &current) {
        report
            .limitations
            .push(format!("Modul-Snapshot nicht gespeichert: {e}"));
    }
}

/// Job codes declared in `crontab.xml` files of installed modules.
pub fn known_cron_jobs(root: &Path) -> BTreeSet<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE
        .get_or_init(|| Regex::new(r#"<job\b[^>]*\bname\s*=\s*["']([^"']+)["']"#).expect("regex"));
    let mut out = BTreeSet::new();
    for (base, depth) in [("vendor", 6), ("app/code", 5)] {
        for entry in walkdir::WalkDir::new(root.join(base))
            .max_depth(depth)
            .into_iter()
            .filter_entry(|e| {
                let n = e.file_name().to_string_lossy();
                !(e.file_type().is_dir()
                    && (n == "Test" || n == "tests" || n == "node_modules" || n == "dev"))
            })
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file() && e.file_name() == "crontab.xml")
        {
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                out.extend(re.captures_iter(&text).map(|c| c[1].to_string()));
            }
        }
    }
    out
}

/// Permission checks of `env.php` and web server config files.
pub fn permission_checks(root: &Path, report: &mut IntegrityReport) {
    let targets: [(&str, bool); 4] = [
        ("app/etc/env.php", true),
        ("app/etc/config.php", false),
        ("pub/.htaccess", false),
        (".htaccess", false),
    ];
    for (rel, secret) in targets {
        let path: PathBuf = root.join(rel);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        let perm = mode_of(&meta) & 0o777;
        let (status, detail, sev) = if perm & 0o002 != 0 {
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
        } else if perm & 0o020 != 0 && secret {
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
        if let Some(sev) = sev {
            report.findings.push(
                Finding::file(sev, Category::ConfigPermissions, "config_permissions", root, &path, format!("{rel}: {}", detail.unwrap_or("")))
                    .with_description("app/etc/env.php enthält DB-Zugangsdaten und den Crypt-Key und sollte nur für den Anwendungsbenutzer lesbar sein (0640/0600, Magento empfiehlt 0440 im Production-Modus).")
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

/// Fingerprint helper for snapshots.
pub fn fp(parts: &[&str]) -> String {
    sha256_hex(parts.join("|").as_bytes())
}
