//! File-system based WordPress checks: plugin/theme inventory, must-use
//! plugins, fake plugin folders, the bootstrap files `index.php` and
//! `wp-config.php`, file permissions and the optional WordPress.org version
//! check.

use crate::config::{file_headers, parse_headers, WpConfig};
use chrono::{DateTime, Utc};
use ecomsec_core::finding::{Category, Finding, Severity, Source};
use ecomsec_core::platform::{IntegrityItem, IntegrityReport, IntegrityStatus, PlatformContext};
use ecomsec_core::util::{excerpt, sha256_hex};
use ecomsec_core::version::Version;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

pub const CONTENT_DIR: &str = "wp-content";

/// One installed plugin or theme.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extension {
    /// Directory name (= wordpress.org slug for directory plugins).
    pub slug: String,
    /// `plugins/woocommerce/woocommerce.php` style main file, relative to
    /// the web root.
    pub main_file: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub author: Option<String>,
    /// Newest modification time of the PHP files in the extension.
    pub newest_mtime: Option<DateTime<Utc>>,
    pub php_files: usize,
    /// `Update URI:` header (`false` disables wordpress.org updates).
    pub update_uri: Option<String>,
}

/// Inventory of plugins (`wp-content/plugins`) or themes (`wp-content/themes`).
pub fn plugins(root: &Path) -> Vec<Extension> {
    let dir = root.join(CONTENT_DIR).join("plugins");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let path = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            out.push(scan_plugin_dir(root, &path, &name));
        } else if name.ends_with(".php") && name != "index.php" {
            // Single-file plugin directly in plugins/ (hello.php).
            let h = file_headers(&path);
            if let Some(pname) = h.get("plugin name") {
                out.push(Extension {
                    slug: name.trim_end_matches(".php").to_string(),
                    main_file: Some(rel(root, &path)),
                    name: Some(pname.clone()),
                    version: h.get("version").cloned(),
                    author: h.get("author").cloned(),
                    newest_mtime: mtime(&path),
                    php_files: 1,
                    update_uri: h.get("update uri").cloned(),
                });
            }
        }
    }
    out
}

fn scan_plugin_dir(root: &Path, dir: &Path, slug: &str) -> Extension {
    let mut ext = Extension {
        slug: slug.to_string(),
        main_file: None,
        name: None,
        version: None,
        author: None,
        newest_mtime: None,
        php_files: 0,
        update_uri: None,
    };
    // Main file: a top-level PHP file carrying a `Plugin Name:` header.
    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut files: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().map(|x| x == "php").unwrap_or(false))
            .collect();
        files.sort();
        // Prefer `<slug>.php`.
        files.sort_by_key(|p| p.file_stem().map(|s| s != slug).unwrap_or(true));
        for f in files {
            let h = file_headers(&f);
            if let Some(n) = h.get("plugin name") {
                ext.main_file = Some(rel(root, &f));
                ext.name = Some(n.clone());
                ext.version = h.get("version").cloned();
                ext.author = h.get("author").cloned();
                ext.update_uri = h.get("update uri").cloned();
                break;
            }
        }
    }
    for entry in walkdir::WalkDir::new(dir)
        .follow_links(false)
        .max_depth(12)
        .into_iter()
        .filter_map(Result::ok)
        .take(20_000)
    {
        if entry.file_type().is_file()
            && entry
                .path()
                .extension()
                .map(|x| x == "php" || x == "phtml" || x == "inc")
                .unwrap_or(false)
        {
            ext.php_files += 1;
            if let Some(m) = mtime(entry.path()) {
                if ext.newest_mtime.map(|n| m > n).unwrap_or(true) {
                    ext.newest_mtime = Some(m);
                }
            }
        }
    }
    ext
}

pub fn themes(root: &Path) -> Vec<Extension> {
    let dir = root.join(CONTENT_DIR).join("themes");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let path = e.path();
        if !path.is_dir() {
            continue;
        }
        let slug = e.file_name().to_string_lossy().to_string();
        let style = path.join("style.css");
        let h = std::fs::read(&style)
            .map(|b| parse_headers(&String::from_utf8_lossy(&b[..b.len().min(8192)])))
            .unwrap_or_default();
        let mut newest = None;
        let mut php_files = 0;
        for entry in walkdir::WalkDir::new(&path)
            .max_depth(8)
            .into_iter()
            .filter_map(Result::ok)
            .take(20_000)
        {
            if entry.file_type().is_file()
                && entry
                    .path()
                    .extension()
                    .map(|x| x == "php")
                    .unwrap_or(false)
            {
                php_files += 1;
                if let Some(m) = mtime(entry.path()) {
                    if newest.map(|n| m > n).unwrap_or(true) {
                        newest = Some(m);
                    }
                }
            }
        }
        out.push(Extension {
            slug,
            main_file: style.is_file().then(|| rel(root, &style)),
            name: h.get("theme name").cloned(),
            version: h.get("version").cloned(),
            author: h.get("author").cloned(),
            newest_mtime: newest,
            php_files,
            update_uri: h.get("update uri").cloned(),
        });
    }
    out
}

fn mtime(path: &Path) -> Option<DateTime<Utc>> {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .map(DateTime::<Utc>::from)
}

fn rel(root: &Path, path: &Path) -> String {
    ecomsec_core::util::relative_display(root, path)
}

fn after_reference(t: Option<DateTime<Utc>>, ctx: &PlatformContext) -> bool {
    t.map(|t| t.date_naive() >= ctx.reference_date)
        .unwrap_or(false)
}

/// A directory name that looks machine-generated (`xkqzwpvb`, `a3f9c1e7d2`).
pub fn random_looking(slug: &str) -> bool {
    let s = slug.to_ascii_lowercase();
    if s.len() < 6 || s.contains(['-', '_', '.']) {
        return false;
    }
    let letters: Vec<char> = s.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    let digits = s.chars().filter(|c| c.is_ascii_digit()).count();
    let vowels = letters.iter().filter(|c| "aeiouy".contains(**c)).count();
    let hex_like = s.chars().all(|c| c.is_ascii_hexdigit()) && digits >= 2;
    let no_vowels = letters.len() >= 5 && vowels == 0;
    let mixed = digits >= 2 && letters.len() >= 3;
    hex_like || no_vowels || mixed
}

/// Plugin and theme inventory as integrity items, plus findings for
/// extensions changed after the reference date and fake plugin folders.
pub fn inventory_checks(
    root: &Path,
    plugins: &[Extension],
    themes: &[Extension],
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) {
    for p in plugins {
        let changed = after_reference(p.newest_mtime, ctx);
        let label = p.name.clone().unwrap_or_else(|| p.slug.clone());
        let mut status = if changed {
            IntegrityStatus::Warning
        } else {
            IntegrityStatus::Ok
        };
        if p.main_file.is_none() && p.php_files > 0 {
            // A folder with PHP code but no plugin header is not shown in the
            // backend – a favourite hiding place for backdoors.
            let random = random_looking(&p.slug);
            status = IntegrityStatus::Critical;
            report.findings.push(
                Finding::new(
                    if random { Severity::Critical } else { Severity::Warning },
                    Category::SuspiciousPattern,
                    Source::FileSystem,
                    "wp_plugin_without_header",
                    format!("{CONTENT_DIR}/plugins/{}", p.slug),
                    format!("Plugin-Ordner ohne Plugin-Header: {}", p.slug),
                )
                .with_description(
                    "Der Ordner enthält PHP-Dateien, aber keine Datei mit `Plugin Name:`-Header. WordPress zeigt \
                     ihn daher nicht in der Plugin-Liste an – Angreifer legen Backdoors gern in solchen \
                     Schein-Plugins ab (oft mit zufälligem Namen). Inhalt prüfen und unbekannte Ordner entfernen.",
                )
                .with_evidence(format!(
                    "{} PHP-Dateien{}",
                    p.php_files,
                    if random { " · Name wirkt zufällig generiert" } else { "" }
                )),
            );
        }
        let mut item = IntegrityItem::new(
            format!("plugin.{}", p.slug),
            "Plugins & Themes",
            format!("Plugin: {label}"),
            status,
            p.version
                .clone()
                .unwrap_or_else(|| "Version unbekannt".into()),
        );
        item = item.with_detail(format!(
            "{}{} PHP-Dateien · zuletzt geändert {}",
            p.author
                .as_ref()
                .map(|a| format!("Autor {} · ", excerpt(a, 60)))
                .unwrap_or_default(),
            p.php_files,
            p.newest_mtime
                .map(|t| t.format("%d.%m.%Y").to_string())
                .unwrap_or_else(|| "unbekannt".into())
        ));
        report.items.push(item);
        if changed && p.main_file.is_some() {
            report.findings.push(
                Finding::new(
                    Severity::Info,
                    Category::ModifiedSinceReference,
                    Source::FileSystem,
                    "wp_plugin_modified_after_reference",
                    format!("{CONTENT_DIR}/plugins/{}", p.slug),
                    format!("Plugin nach dem Referenzdatum installiert/aktualisiert: {label}"),
                )
                .with_description(
                    "Mindestens eine PHP-Datei des Plugins wurde nach dem Referenzdatum geändert. Mit dem \
                     Update-Verlauf abgleichen (Dashboard › Aktualisierungen, Hosting-Logs).",
                )
                .with_evidence(format!(
                    "Version {} · neueste Änderung {}",
                    p.version.as_deref().unwrap_or("?"),
                    p.newest_mtime
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_default()
                )),
            );
        }
    }
    for t in themes {
        let changed = after_reference(t.newest_mtime, ctx);
        report.items.push(
            IntegrityItem::new(
                format!("theme.{}", t.slug),
                "Plugins & Themes",
                format!(
                    "Theme: {}",
                    t.name.clone().unwrap_or_else(|| t.slug.clone())
                ),
                if (t.main_file.is_none() && t.php_files > 0) || changed {
                    IntegrityStatus::Warning
                } else {
                    IntegrityStatus::Ok
                },
                t.version
                    .clone()
                    .unwrap_or_else(|| "Version unbekannt".into()),
            )
            .with_detail(format!(
                "{} PHP-Dateien · zuletzt geändert {}{}",
                t.php_files,
                t.newest_mtime
                    .map(|x| x.format("%d.%m.%Y").to_string())
                    .unwrap_or_else(|| "unbekannt".into()),
                if t.main_file.is_none() {
                    " · keine style.css – kein gültiges Theme"
                } else {
                    ""
                }
            )),
        );
    }
    report.items.push(IntegrityItem::new(
        "extensions.summary",
        "Plugins & Themes",
        "Plugins / Themes im Dateisystem",
        IntegrityStatus::Ok,
        format!("{} / {}", plugins.len(), themes.len()),
    ));
    let _ = root;
}

fn backdoor_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(eval|assert|create_function)\s*\(|\b(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)\s*\(|(include|require)(_once)?\s*\(?\s*['"](https?|ftp|php|data)://|file_get_contents\s*\(\s*['"]https?://|wp_remote_(get|post|retrieve_body)\s*\(|\$_(GET|POST|REQUEST|COOKIE)\s*\[|\\x[0-9a-f]{2}\\x[0-9a-f]{2}"#,
        )
        .expect("regex")
    })
}

#[derive(Serialize, Deserialize, Default)]
struct FileSnapshot {
    entries: BTreeMap<String, String>,
}

/// Must-use plugins are loaded automatically and are not listed among the
/// regular plugins – a classic persistence location.
pub fn mu_plugin_checks(root: &Path, ctx: &PlatformContext, report: &mut IntegrityReport) {
    let dir = root.join(CONTENT_DIR).join("mu-plugins");
    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(&dir)
        .max_depth(3)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| {
            p.extension()
                .map(|x| x == "php" || x == "phtml" || x == "inc")
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    let previous: FileSnapshot = ctx.state.snapshot("wp-mu-plugins").unwrap_or_default();
    let mut current = FileSnapshot::default();
    let mut suspicious = 0usize;
    for f in &files {
        let r = rel(root, f);
        let text = std::fs::read(f)
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default();
        current
            .entries
            .insert(r.clone(), sha256_hex(text.as_bytes()));
        let hits: Vec<String> = backdoor_regex()
            .find_iter(&text)
            .take(3)
            .map(|m| excerpt(m.as_str(), 60))
            .collect();
        if !hits.is_empty() {
            suspicious += 1;
            let severity = if hits.len() >= 2 {
                Severity::Critical
            } else {
                Severity::Warning
            };
            let mut finding = Finding::file(
                severity,
                Category::SuspiciousPattern,
                "wp_mu_plugin_suspicious",
                root,
                f,
                "Must-Use-Plugin mit Code-Ausführung, Dekodierung oder Fernabruf",
            )
            .with_description(
                "Dateien in wp-content/mu-plugins werden bei jedem Request automatisch geladen und erscheinen \
                 nicht in der Plugin-Liste. eval/base64/gzinflate, Request-Parameter oder das Nachladen \
                 von Code aus dem Internet sind dort ein starkes Backdoor-Indiz. Herkunft klären (Hoster? \
                 Agentur?), sonst entfernen.",
            );
            for h in hits {
                finding = finding.with_evidence(h);
            }
            report.findings.push(finding);
        }
        if !previous.entries.is_empty() && !previous.entries.contains_key(&r) {
            report.findings.push(
                Finding::file(
                    Severity::Warning,
                    Category::ModifiedSinceReference,
                    "wp_mu_plugin_new",
                    root,
                    f,
                    "Neues Must-Use-Plugin seit dem letzten Scan",
                )
                .with_description(
                    "Must-Use-Plugins werden ohne Aktivierung geladen. Jede neue Datei muss zugeordnet werden.",
                ),
            );
        } else if after_reference(mtime(f), ctx) {
            report.findings.push(
                Finding::file(
                    Severity::Warning,
                    Category::ModifiedSinceReference,
                    "wp_mu_plugin_modified",
                    root,
                    f,
                    "Must-Use-Plugin nach dem Referenzdatum geändert",
                )
                .with_evidence(
                    mtime(f)
                        .map(|t| format!("mtime={}", t.to_rfc3339()))
                        .unwrap_or_default(),
                ),
            );
        }
    }
    report.items.push(
        IntegrityItem::new(
            "wp.mu_plugins",
            "Plugins & Themes",
            "Must-Use-Plugins (wp-content/mu-plugins)",
            if suspicious > 0 {
                IntegrityStatus::Critical
            } else if files.is_empty() {
                IntegrityStatus::Ok
            } else {
                IntegrityStatus::Warning
            },
            format!("{} Dateien, {suspicious} verdächtig", files.len()),
        )
        .with_detail(if files.is_empty() {
            "keine".to_string()
        } else {
            files
                .iter()
                .map(|f| rel(root, f))
                .collect::<Vec<_>>()
                .join(", ")
        }),
    );
    if let Err(e) = ctx.state.save_snapshot("wp-mu-plugins", &current) {
        report
            .limitations
            .push(format!("Snapshot mu-plugins nicht gespeichert: {e}"));
    }
}

/// The root `index.php` of WordPress only defines `WP_USE_THEMES` and
/// requires `wp-blog-header.php`.  Anything else was added.
pub fn index_php_check(root: &Path, report: &mut IntegrityReport) {
    let path = root.join("index.php");
    let Ok(bytes) = std::fs::read(&path) else {
        return;
    };
    let text = String::from_utf8_lossy(&bytes).to_string();
    let code = ecomsec_core::util::strip_php_comments(&text);
    static INCLUDE: OnceLock<Regex> = OnceLock::new();
    let include = INCLUDE.get_or_init(|| {
        Regex::new(r#"(?i)\b(include|require)(_once)?\b[^;]{0,200}"#).expect("regex")
    });
    let foreign: Vec<String> = include
        .find_iter(&code)
        .map(|m| m.as_str().trim().to_string())
        .filter(|s| !s.contains("wp-blog-header.php"))
        .collect();
    let has_header = code.contains("wp-blog-header.php");
    let suspicious_code = backdoor_regex().is_match(&code);
    let ok = has_header && foreign.is_empty() && !suspicious_code && bytes.len() < 2048;
    report.items.push(IntegrityItem::new(
        "wp.index_php",
        "Integrität",
        "index.php (Front-Controller)",
        if ok {
            IntegrityStatus::Ok
        } else {
            IntegrityStatus::Critical
        },
        if ok {
            "unverändert (Standardinhalt)".to_string()
        } else {
            format!("{} Bytes, abweichender Inhalt", bytes.len())
        },
    ));
    if !ok {
        let mut f = Finding::file(
            if suspicious_code || !foreign.is_empty() {
                Severity::Critical
            } else {
                Severity::Warning
            },
            Category::IntegrityDeviation,
            "wp_index_php_modified",
            root,
            &path,
            "index.php enthält zusätzlichen Code (vorangestelltes Include / Injection)",
        )
        .with_description(
            "Die index.php von WordPress besteht nur aus `define('WP_USE_THEMES', true)` und \
             `require __DIR__ . '/wp-blog-header.php'`. Zusätzliche Includes oder Code laufen bei jedem \
             Seitenaufruf – typisch für SEO-Spam-Weichen und Skimmer-Loader. Datei aus dem offiziellen \
             WordPress-Paket wiederherstellen.",
        );
        for inc in foreign.iter().take(3) {
            f = f.with_evidence(excerpt(inc, 160));
        }
        if !has_header {
            f = f.with_evidence("wp-blog-header.php wird nicht geladen");
        }
        report.findings.push(f);
    }
}

/// Checks on `wp-config.php`: extra includes, file editor, debug output,
/// salts, location.
pub fn wp_config_checks(root: &Path, cfg: &WpConfig, report: &mut IntegrityReport) {
    let Some(path) = &cfg.path else {
        report.items.push(IntegrityItem::new(
            "wp.config",
            "Konfiguration",
            "wp-config.php",
            IntegrityStatus::Warning,
            "nicht gefunden",
        ));
        return;
    };
    report.items.push(
        IntegrityItem::new(
            "wp.config",
            "Konfiguration",
            "wp-config.php",
            IntegrityStatus::Ok,
            if cfg.outside_webroot {
                "oberhalb des Webroots (gehärtet)"
            } else {
                "im Webroot"
            },
        )
        .with_detail(format!("Tabellenpräfix {}", cfg.table_prefix)),
    );
    let odd_ext =
        Regex::new(r#"\.(ico|png|jpe?g|gif|txt|css|js|tmp|svg|bak|log)['"]"#).expect("regex");
    for inc in &cfg.extra_includes {
        let lower = inc.to_ascii_lowercase();
        let critical = lower.contains("\\x")
            || lower.contains("://")
            || odd_ext.is_match(&lower)
            || lower.contains("uploads/")
            || lower.contains("/tmp/");
        report.findings.push(
            Finding::new(
                if critical {
                    Severity::Critical
                } else {
                    Severity::Warning
                },
                Category::SuspiciousPattern,
                Source::Configuration,
                "wp_config_extra_include",
                format!("{}:{}", rel(root, path), sha256_hex(inc.as_bytes()).get(..12).unwrap_or("")),
                "wp-config.php bindet zusätzliche Datei ein",
            )
            .with_description(
                "wp-config.php wird bei jedem Request geladen. Zusätzliche include/require-Anweisungen – \
                 besonders auf Bild-, Text- oder versteckte Dateien, hex-kodierte Pfade oder URLs – sind \
                 ein bekanntes Persistenzmuster. Eingebundene Datei prüfen und Anweisung entfernen, \
                 sofern sie nicht bewusst gesetzt wurde.",
            )
            .with_evidence(excerpt(inc, 200)),
        );
    }
    let file_edit = cfg.flag("DISALLOW_FILE_EDIT").unwrap_or(false)
        || cfg.flag("DISALLOW_FILE_MODS").unwrap_or(false);
    report.items.push(IntegrityItem::new(
        "wp.disallow_file_edit",
        "Konfiguration",
        "Theme-/Plugin-Editor im Backend",
        if file_edit {
            IntegrityStatus::Ok
        } else {
            IntegrityStatus::Warning
        },
        if file_edit {
            "deaktiviert (DISALLOW_FILE_EDIT)"
        } else {
            "aktiv – Admins können PHP-Code bearbeiten"
        },
    ));
    if !file_edit {
        report.findings.push(
            Finding::new(
                Severity::Info,
                Category::Informational,
                Source::Configuration,
                "wp_file_edit_enabled",
                "wp-config.php:DISALLOW_FILE_EDIT",
                "Datei-Editor im WordPress-Backend ist aktiv",
            )
            .with_description(
                "Mit einem übernommenen Admin-Konto lässt sich über Design › Theme-Datei-Editor sofort \
                 PHP-Code ausführen. `define('DISALLOW_FILE_EDIT', true);` in wp-config.php setzen.",
            ),
        );
    }
    let debug_display =
        cfg.flag("WP_DEBUG").unwrap_or(false) && cfg.flag("WP_DEBUG_DISPLAY").unwrap_or(true);
    if debug_display {
        report.findings.push(
            Finding::new(
                Severity::Warning,
                Category::ExposedFile,
                Source::Configuration,
                "wp_debug_display",
                "wp-config.php:WP_DEBUG",
                "WP_DEBUG ist aktiv und Fehler werden im Frontend ausgegeben",
            )
            .with_description(
                "Fehlermeldungen verraten Pfade, Plugin-Versionen und SQL-Details. Auf Produktivsystemen \
                 WP_DEBUG=false oder zumindest WP_DEBUG_DISPLAY=false setzen.",
            ),
        );
    }
    if cfg.flag("WP_DEBUG_LOG").unwrap_or(false)
        || cfg.get("WP_DEBUG_LOG").is_some_and(|v| v.contains('/'))
    {
        let log = root.join(crate::inventory::CONTENT_DIR).join("debug.log");
        if log.is_file() {
            report.findings.push(
                Finding::file(
                    Severity::Warning,
                    Category::ExposedFile,
                    "wp_debug_log_public",
                    root,
                    &log,
                    "wp-content/debug.log ist vorhanden und ggf. öffentlich abrufbar",
                )
                .with_description(
                    "Das Debug-Log liegt standardmäßig im öffentlich erreichbaren wp-content. Es enthält \
                     Pfade, Fehlermeldungen und mitunter personenbezogene Daten. Log außerhalb des Webroots \
                     schreiben (`WP_DEBUG_LOG` auf einen Pfad setzen) oder Zugriff sperren.",
                ),
            );
        }
    }
    let weak = cfg.weak_salts();
    report.items.push(
        IntegrityItem::new(
            "wp.salts",
            "Konfiguration",
            "Authentifizierungs-Schlüssel und Salts",
            if weak.is_empty() {
                IntegrityStatus::Ok
            } else {
                IntegrityStatus::Critical
            },
            if weak.is_empty() {
                "alle 8 gesetzt".to_string()
            } else {
                format!("{} fehlen oder Platzhalter", weak.len())
            },
        )
        .with_detail("Nach einer Kompromittierung neu erzeugen (https://api.wordpress.org/secret-key/1.1/salt/) – das meldet alle Sitzungen ab."),
    );
    if !weak.is_empty() {
        report.findings.push(
            Finding::new(
                Severity::Warning,
                Category::ConfigPermissions,
                Source::Configuration,
                "wp_weak_salts",
                "wp-config.php:salts",
                "Schlüssel/Salts in wp-config.php fehlen oder sind Platzhalter",
            )
            .with_description(
                "Ohne individuelle Salts lassen sich Login-Cookies leichter fälschen. Neue Werte über den \
                 WordPress.org-Generator erzeugen und eintragen.",
            )
            .with_evidence(weak.join(", ")),
        );
    }
}

/// Permission checks of `wp-config.php` and the web server config files.
pub fn permission_checks(root: &Path, cfg: &WpConfig, report: &mut IntegrityReport) {
    let mut targets: Vec<(PathBuf, String, bool)> = Vec::new();
    if let Some(p) = &cfg.path {
        let label = if cfg.outside_webroot {
            "../wp-config.php".to_string()
        } else {
            "wp-config.php".to_string()
        };
        targets.push((p.clone(), label, true));
    }
    for (relp, secret) in [
        (".htaccess", false),
        (".user.ini", false),
        ("wp-content/.htaccess", false),
    ] {
        targets.push((root.join(relp), relp.to_string(), secret));
    }
    for (path, label, secret) in targets {
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
            format!("perm.{label}"),
            "Dateirechte",
            &label,
            status,
            format!("{perm:04o}"),
        );
        if let Some(d) = detail {
            item = item.with_detail(d);
        }
        report.items.push(item);
        if let Some(sev) = sev {
            report.findings.push(
                Finding::new(sev, Category::ConfigPermissions, Source::FileSystem, "config_permissions", label.clone(), format!("{label}: {}", detail.unwrap_or("")))
                    .with_description("wp-config.php enthält DB-Zugangsdaten und Salts und sollte nur für den Webserver-/FTP-Benutzer lesbar sein (0600/0640); .htaccess/.user.ini nicht für andere schreibbar (0644).")
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

// ---------------------------------------------------------------- online

/// Minimal client for the public WordPress.org APIs (plugin directory and
/// core version check).  Only the plugin slug / nothing at all is sent.
pub struct WpOrgClient {
    agent: ureq::Agent,
    base: String,
    /// Upper bound of plugin lookups per scan.
    pub max_plugins: usize,
}

impl Default for WpOrgClient {
    fn default() -> Self {
        WpOrgClient::new("https://api.wordpress.org")
    }
}

impl WpOrgClient {
    pub fn new(base: &str) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(15)))
            .http_status_as_error(false)
            .build();
        WpOrgClient {
            agent: config.into(),
            base: base.trim_end_matches('/').to_string(),
            max_plugins: 150,
        }
    }

    fn get_json(&self, url: &str) -> anyhow::Result<serde_json::Value> {
        let mut resp = self
            .agent
            .get(url)
            .header(
                "User-Agent",
                "ecomsec (+https://github.com/liohtml/ecom-sec)",
            )
            .call()?;
        let status = resp.status().as_u16();
        let text = resp.body_mut().read_to_string()?;
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("HTTP {status}: ungültige Antwort ({e})"))?;
        Ok(json)
    }

    /// Latest version of a plugin in the wordpress.org directory; `Ok(None)`
    /// when the plugin is not listed there (premium/custom plugin).
    pub fn plugin_latest(&self, slug: &str) -> anyhow::Result<Option<String>> {
        if !slug
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Ok(None);
        }
        // The bundled single-file plugin `hello.php` is listed as hello-dolly.
        let slug = if slug == "hello" { "hello-dolly" } else { slug };
        let url = format!(
            "{}/plugins/info/1.2/?action=plugin_information&request[slug]={slug}&request[fields][sections]=0&request[fields][description]=0",
            self.base
        );
        let json = self.get_json(&url)?;
        if json.get("error").is_some() {
            return Ok(None);
        }
        Ok(json
            .get("version")
            .and_then(|v| v.as_str())
            .map(str::to_string))
    }

    /// Latest WordPress release according to the core version-check API.
    pub fn core_latest(&self) -> anyhow::Result<Option<String>> {
        let json = self.get_json(&format!("{}/core/version-check/1.7/", self.base))?;
        Ok(json
            .get("offers")
            .and_then(|o| o.as_array())
            .and_then(|o| o.first())
            .and_then(|o| o.get("current").or_else(|| o.get("version")))
            .and_then(|v| v.as_str())
            .map(str::to_string))
    }
}

/// Compare installed plugins with the wordpress.org directory (only with
/// `--online`).  OSV.dev has no WordPress ecosystem, so this is the
/// "outdated" signal; vulnerability feeds (Wordfence, WPScan, Patchstack)
/// are future work.
pub fn online_checks(
    plugins: &[Extension],
    wp_version: Option<&Version>,
    client: &WpOrgClient,
    report: &mut IntegrityReport,
) {
    if let Some(installed) = wp_version {
        match client.core_latest() {
            Ok(Some(latest)) => {
                let outdated = Version::parse(&latest).is_some_and(|l| &l > installed);
                report.items.push(IntegrityItem::new(
                    "wp.core_latest",
                    "Shop",
                    "WordPress-Version laut WordPress.org",
                    if outdated {
                        IntegrityStatus::Warning
                    } else {
                        IntegrityStatus::Ok
                    },
                    format!("installiert {installed} · aktuell {latest}"),
                ));
                if outdated {
                    report.findings.push(
                        Finding::new(
                            Severity::Warning,
                            Category::PatchStatus,
                            Source::Api,
                            "wp_core_outdated",
                            format!("wordpress {installed}"),
                            format!("WordPress {installed} ist veraltet (aktuell {latest})"),
                        )
                        .with_description(
                            "WordPress-Sicherheitsupdates erscheinen als Minor-Releases. Automatische \
                             Hintergrund-Updates aktiviert lassen und zeitnah aktualisieren.",
                        ),
                    );
                }
            }
            Ok(None) => {}
            Err(e) => report
                .limitations
                .push(format!("WordPress.org-Versionsabfrage fehlgeschlagen: {e}")),
        }
    }
    let mut checked = 0usize;
    let mut outdated = 0usize;
    let mut not_listed = Vec::new();
    for p in plugins.iter().filter(|p| p.main_file.is_some()) {
        if checked >= client.max_plugins {
            report.limitations.push(format!(
                "WordPress.org-Abgleich auf {} Plugins begrenzt.",
                client.max_plugins
            ));
            break;
        }
        if p.update_uri.as_deref().is_some_and(|u| {
            let u = u.to_ascii_lowercase();
            u == "false" || !(u.contains("wordpress.org") || u.contains("w.org"))
        }) {
            not_listed.push(p.slug.clone());
            continue;
        }
        checked += 1;
        match client.plugin_latest(&p.slug) {
            Ok(Some(latest)) => {
                let installed = p.version.as_deref().and_then(Version::parse);
                let newer = Version::parse(&latest);
                if let (Some(i), Some(l)) = (installed, newer) {
                    if l > i {
                        outdated += 1;
                        report.findings.push(
                            Finding::new(
                                Severity::Warning,
                                Category::PatchStatus,
                                Source::Api,
                                "wp_plugin_outdated",
                                format!("plugin:{}", p.slug),
                                format!(
                                    "Plugin veraltet: {} {} (aktuell {latest})",
                                    p.name.as_deref().unwrap_or(&p.slug),
                                    p.version.as_deref().unwrap_or("?")
                                ),
                            )
                            .with_description(
                                "Veraltete Plugins sind der häufigste Einstiegspunkt bei WordPress-Shops. \
                                 Changelog auf Sicherheitsfixes prüfen und aktualisieren; nicht genutzte \
                                 Plugins löschen.",
                            )
                            .with_evidence(format!("https://wordpress.org/plugins/{}/", p.slug)),
                        );
                    }
                }
            }
            Ok(None) => not_listed.push(p.slug.clone()),
            Err(e) => {
                report.limitations.push(format!(
                    "WordPress.org-Abfrage für {} fehlgeschlagen: {e}",
                    p.slug
                ));
                break;
            }
        }
    }
    report.items.push(
        IntegrityItem::new(
            "dependencies.wporg",
            "Abhängigkeiten",
            "Plugins gegen WordPress.org-Verzeichnis geprüft",
            if outdated > 0 {
                IntegrityStatus::Warning
            } else {
                IntegrityStatus::Ok
            },
            format!("{checked} geprüft, {outdated} veraltet"),
        )
        .with_detail(if not_listed.is_empty() {
            "Alle Plugins im WordPress.org-Verzeichnis gefunden.".to_string()
        } else {
            format!(
                "Nicht im WordPress.org-Verzeichnis (Premium/Eigenentwicklung – manuell prüfen): {}",
                not_listed.join(", ")
            )
        }),
    );
}

/// Placeholder item when the online check is disabled.
pub fn offline_item(plugins: &[Extension]) -> IntegrityItem {
    IntegrityItem::new(
        "dependencies.wporg",
        "Abhängigkeiten",
        "Plugins gegen WordPress.org-Verzeichnis geprüft",
        IntegrityStatus::Unknown,
        "nicht geprüft",
    )
    .with_detail(format!(
        "{} Plugins im Dateisystem. Mit `--online` werden installierte Versionen mit dem \
         WordPress.org-Verzeichnis verglichen (es wird nur der Plugin-Slug gesendet).",
        plugins.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_names() {
        assert!(random_looking("xkqzwpvb"));
        assert!(random_looking("a3f9c1e7d2"));
        assert!(random_looking("wpx7k2q9"));
        assert!(!random_looking("woocommerce"));
        assert!(!random_looking("akismet"));
        assert!(!random_looking("wordpress-seo"));
        assert!(!random_looking("jetpack"));
        assert!(!random_looking("elementor"));
    }
}
