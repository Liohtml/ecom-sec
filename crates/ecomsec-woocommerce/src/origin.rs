//! Origin check: installed files against the checksums WordPress.org
//! publishes for every core release and every plugin version (`--online`).
//!
//! This answers two questions that pattern rules cannot:
//!
//! * Is a file of the core or of a directory plugin still the original?
//!   A changed `wp-includes/…php` or a PHP file that is not part of the
//!   release is the most direct trace of an intrusion.
//! * Is a rule hit part of the official package?  Security and backup
//!   plugins legitimately contain code that looks like a backdoor.  When the
//!   checksum matches, the engine rates such hits as informational.
//!
//! Sent to WordPress.org: the core version and locale, and for each plugin
//! its slug and version.  Premium and custom plugins have no published
//! checksums and stay with the pattern rules.

use crate::inventory::{Extension, WpOrgClient, CONTENT_DIR};
use ecomsec_core::engine::file_scan::PHP_EXTENSIONS;
use ecomsec_core::finding::{Category, Finding, Severity};
use ecomsec_core::platform::{IntegrityItem, IntegrityReport, IntegrityStatus};
use md5::Md5;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Checksums of one file; several values when a release was re-tagged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileSums {
    pub sha256: Vec<String>,
    pub md5: Vec<String>,
}

/// Path inside the package → checksums.
pub type Manifest = BTreeMap<String, FileSums>;

/// Findings per package before a summary replaces the single entries.
const MAX_FINDINGS_PER_PACKAGE: usize = 25;

/// Share of differing files above which the manifest evidently describes
/// another release than the one on disk (half-finished update, wrong
/// version header).
const MISMATCH_SHARE_LIMIT: f64 = 0.4;

fn string_list(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::String(s)) => vec![s.to_ascii_lowercase()],
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str())
            .map(str::to_ascii_lowercase)
            .collect(),
        _ => Vec::new(),
    }
}

/// A manifest path must stay inside the package directory.
fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

impl WpOrgClient {
    /// Checksums of a core release; `Ok(None)` when WordPress.org has none
    /// for this version and locale (nightly builds, unknown locale).
    pub fn core_checksums(&self, version: &str, locale: &str) -> anyhow::Result<Option<Manifest>> {
        let url = format!(
            "{}/core/checksums/1.0/?version={version}&locale={locale}",
            self.api_base()
        );
        let (status, text) = self.get_text(&url)?;
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("HTTP {status}: ungültige Antwort ({e})"))?;
        let Some(map) = json.get("checksums").and_then(|c| c.as_object()) else {
            return Ok(None);
        };
        Ok(Some(
            map.iter()
                .filter(|(path, _)| safe_relative(path))
                .map(|(path, sum)| {
                    (
                        path.clone(),
                        FileSums {
                            sha256: Vec::new(),
                            md5: string_list(Some(sum)),
                        },
                    )
                })
                .collect(),
        ))
    }

    /// Checksums of one plugin version; `Ok(None)` when the plugin or the
    /// version is not in the WordPress.org directory.
    pub fn plugin_checksums(&self, slug: &str, version: &str) -> anyhow::Result<Option<Manifest>> {
        let url = format!(
            "{}/plugin-checksums/{slug}/{version}.json",
            self.downloads_base()
        );
        let (status, text) = self.get_text(&url)?;
        if status == 404 {
            return Ok(None);
        }
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("HTTP {status}: ungültige Antwort ({e})"))?;
        let Some(files) = json.get("files").and_then(|f| f.as_object()) else {
            return Ok(None);
        };
        Ok(Some(
            files
                .iter()
                .filter(|(path, _)| safe_relative(path))
                .map(|(path, sums)| {
                    (
                        path.clone(),
                        FileSums {
                            sha256: string_list(sums.get("sha256")),
                            md5: string_list(sums.get("md5")),
                        },
                    )
                })
                .collect(),
        ))
    }
}

/// Characters allowed in a slug or version that goes into a request URL.
fn url_safe(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
        && !value.contains("..")
}

fn digests(path: &Path, want_md5: bool) -> std::io::Result<(String, Option<String>)> {
    let mut file = std::fs::File::open(path)?;
    let mut sha = Sha256::new();
    let mut md5 = want_md5.then(Md5::new);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sha.update(&buf[..n]);
        if let Some(m) = md5.as_mut() {
            m.update(&buf[..n]);
        }
    }
    Ok((
        hex::encode(sha.finalize()),
        md5.map(|m| hex::encode(m.finalize())),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileState {
    Verified,
    Modified,
    Missing,
    Unreadable,
}

fn check_file(path: &Path, sums: &FileSums) -> FileState {
    if !path.is_file() {
        return FileState::Missing;
    }
    let use_md5 = sums.sha256.is_empty();
    match digests(path, use_md5) {
        Ok((sha, md5)) => {
            let matches = if use_md5 {
                md5.is_some_and(|m| sums.md5.contains(&m))
            } else {
                sums.sha256.contains(&sha)
            };
            if matches {
                FileState::Verified
            } else {
                FileState::Modified
            }
        }
        Err(_) => FileState::Unreadable,
    }
}

/// Files in which a change or an addition can run code.
fn is_code(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    if matches!(name.as_str(), ".htaccess" | ".user.ini" | "php.ini") {
        return true;
    }
    let ext = name.rsplit('.').next().unwrap_or("");
    PHP_EXTENSIONS.contains(&ext) || matches!(ext, "js" | "mjs")
}

/// Result of comparing one package directory with its manifest.
#[derive(Debug, Default)]
struct PackageResult {
    verified: Vec<String>,
    modified: Vec<String>,
    unknown: Vec<String>,
    missing: usize,
    total: usize,
}

impl PackageResult {
    /// The manifest does not describe the files on disk.
    fn mismatched_release(&self) -> bool {
        let present = self.total - self.missing;
        // A handful of changed files is reported file by file, whatever
        // the size of the package.
        present == 0
            || (self.modified.len() >= 5
                && self.modified.len() as f64 > MISMATCH_SHARE_LIMIT * present as f64)
    }
}

/// Compare `dir` with `manifest`.  Paths in the result are relative to
/// `root`.  `walk` lists the directories searched for executable files that
/// are not in the manifest.
fn compare(
    root: &Path,
    dir: &Path,
    manifest: &Manifest,
    skip: impl Fn(&str) -> bool + Sync,
    walk: &[PathBuf],
) -> PackageResult {
    let entries: Vec<(&String, &FileSums)> =
        manifest.iter().filter(|(path, _)| !skip(path)).collect();
    let states: Vec<(String, FileState)> = entries
        .par_iter()
        .map(|(path, sums)| {
            let full = dir.join(path);
            (
                ecomsec_core::util::relative_display(root, &full),
                check_file(&full, sums),
            )
        })
        .collect();
    let mut result = PackageResult {
        total: states.len(),
        ..Default::default()
    };
    for (rel, state) in states {
        match state {
            FileState::Verified => result.verified.push(rel),
            FileState::Modified => result.modified.push(rel),
            FileState::Missing => result.missing += 1,
            FileState::Unreadable => {}
        }
    }
    for base in walk {
        for entry in WalkDir::new(base)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            .flatten()
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let Ok(inside) = entry.path().strip_prefix(dir) else {
                continue;
            };
            let inside = inside.to_string_lossy().replace('\\', "/");
            if !manifest.contains_key(&inside) && !skip(&inside) && is_code(&inside) {
                result
                    .unknown
                    .push(ecomsec_core::util::relative_display(root, entry.path()));
            }
        }
    }
    result
}

/// Locale of the installed core package (`$wp_local_package`), `en_US`
/// when the international package is installed.
pub fn core_locale(root: &Path) -> String {
    let text = std::fs::read_to_string(root.join("wp-includes/version.php")).unwrap_or_default();
    let re = regex::Regex::new(r#"\$wp_local_package\s*=\s*['"]([A-Za-z_]{2,12})['"]"#)
        .expect("valid regex");
    re.captures(&text)
        .map(|c| c[1].to_string())
        .unwrap_or_else(|| "en_US".to_string())
}

fn file_finding(
    root: &Path,
    rel: &str,
    severity: Severity,
    rule: &str,
    title: String,
    description: &str,
) -> Finding {
    Finding::file(
        severity,
        Category::IntegrityDeviation,
        rule,
        root,
        &root.join(rel),
        title,
    )
    .with_description(description)
}

/// Verify the core and all directory plugins.  Findings, integrity rows and
/// the set of verified files are added to `report`.
pub fn verify(
    root: &Path,
    wp_version: Option<&str>,
    plugins: &[Extension],
    client: &WpOrgClient,
    report: &mut IntegrityReport,
) {
    verify_core(root, wp_version, client, report);
    verify_plugins(root, plugins, client, report);
}

fn verify_core(
    root: &Path,
    wp_version: Option<&str>,
    client: &WpOrgClient,
    report: &mut IntegrityReport,
) {
    const KEY: &str = "integrity.wporg_core";
    const LABEL: &str = "WordPress-Kern gegen offizielle Prüfsummen";
    let Some(version) = wp_version.filter(|v| url_safe(v)) else {
        report.items.push(IntegrityItem::new(
            KEY,
            "Integrität",
            LABEL,
            IntegrityStatus::Unknown,
            "WordPress-Version nicht ermittelbar",
        ));
        return;
    };
    let locale = core_locale(root);
    let manifest = match client.core_checksums(version, &locale) {
        Ok(Some(m)) => m,
        Ok(None) => {
            report.items.push(
                IntegrityItem::new(
                    KEY,
                    "Integrität",
                    LABEL,
                    IntegrityStatus::Unknown,
                    "keine Prüfsummen veröffentlicht",
                )
                .with_detail(format!("WordPress {version} ({locale})")),
            );
            return;
        }
        Err(e) => {
            report.limitations.push(format!(
                "Prüfsummen des WordPress-Kerns nicht abrufbar: {e}"
            ));
            return;
        }
    };
    // Bundled themes and plugins are replaced and removed independently of
    // the core; they are checked as plugins or not at all.
    let skip = |path: &str| path.starts_with("wp-content/");
    let result = compare(
        root,
        root,
        &manifest,
        skip,
        &[root.join("wp-admin"), root.join("wp-includes")],
    );
    if result.mismatched_release() {
        report.items.push(
            IntegrityItem::new(
                KEY,
                "Integrität",
                LABEL,
                IntegrityStatus::Warning,
                format!(
                    "{} von {} Dateien weichen ab",
                    result.modified.len(),
                    result.total - result.missing
                ),
            )
            .with_detail(format!(
                "Die Dateien passen nicht zu WordPress {version} ({locale}) – vermutlich ein \
                 unvollständiges Update. Kern neu installieren (`wp core download --force`)."
            )),
        );
        return;
    }

    // PHP files directly in the web root that the release does not contain.
    let mut root_unknown = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .filter(|e| e.path().is_file())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        for name in names {
            let lower = name.to_ascii_lowercase();
            let is_php = lower
                .rsplit('.')
                .next()
                .is_some_and(|ext| PHP_EXTENSIONS.contains(&ext));
            if is_php && !manifest.contains_key(&name) && lower != "wp-config.php" {
                root_unknown.push(name);
            }
        }
    }

    for rel in result.modified.iter().take(MAX_FINDINGS_PER_PACKAGE) {
        let code = is_code(rel);
        report.findings.push(file_finding(
            root,
            rel,
            if code {
                Severity::Critical
            } else {
                Severity::Warning
            },
            "wp_core_file_modified",
            format!("WordPress-Kerndatei weicht vom Original ab ({version})"),
            "Der Inhalt stimmt nicht mit der Prüfsumme überein, die WordPress.org für diese Version \
             veröffentlicht. Kerndateien werden nie von Hand geändert; eingeschleuster Code in \
             Kerndateien ist ein häufiges Versteck. Datei mit dem Original vergleichen und den Kern \
             neu installieren (`wp core download --force`).",
        ));
    }
    for rel in result.unknown.iter().take(MAX_FINDINGS_PER_PACKAGE) {
        let php = !rel.to_ascii_lowercase().ends_with(".js");
        report.findings.push(file_finding(
            root,
            rel,
            if php {
                Severity::Critical
            } else {
                Severity::Warning
            },
            "wp_core_unknown_file",
            "Datei im WordPress-Kern gehört nicht zur offiziellen Version".to_string(),
            "wp-admin und wp-includes enthalten ausschließlich Dateien der WordPress-Version. Eine \
             zusätzliche ausführbare Datei dort ist typisch für eine abgelegte Hintertür mit \
             unauffälligem Namen. Inhalt prüfen, Datei sichern und entfernen.",
        ));
    }
    for name in root_unknown.iter().take(MAX_FINDINGS_PER_PACKAGE) {
        report.findings.push(file_finding(
            root,
            name,
            Severity::Warning,
            "wp_root_unknown_file",
            "PHP-Datei im Webroot gehört nicht zu WordPress".to_string(),
            "WordPress liefert diese Datei nicht aus. Eigene Skripte im Webroot sind möglich \
             (Verifizierungsdateien, Wartungsskripte), ebenso abgelegte Dropper. Herkunft klären.",
        ));
    }
    let deviations = result.modified.len() + result.unknown.len();
    report.items.push(
        IntegrityItem::new(
            KEY,
            "Integrität",
            LABEL,
            if deviations > 0 {
                IntegrityStatus::Critical
            } else if !root_unknown.is_empty() {
                IntegrityStatus::Warning
            } else {
                IntegrityStatus::Ok
            },
            format!(
                "{} Dateien original · {} geändert · {} fremd",
                result.verified.len(),
                result.modified.len(),
                result.unknown.len() + root_unknown.len()
            ),
        )
        .with_detail(format!(
            "WordPress {version} ({locale}), Quelle: api.wordpress.org{}",
            if result.missing > 0 {
                format!(" · {} Dateien der Version fehlen", result.missing)
            } else {
                String::new()
            }
        )),
    );
    report.verified_files.extend(result.verified);
}

fn verify_plugins(
    root: &Path,
    plugins: &[Extension],
    client: &WpOrgClient,
    report: &mut IntegrityReport,
) {
    let mut verified_plugins = 0usize;
    let mut deviating = Vec::new();
    let mut unverifiable = Vec::new();
    let mut other_release = Vec::new();
    let mut requests = 0usize;
    for plugin in plugins {
        let dir = root.join(CONTENT_DIR).join("plugins").join(&plugin.slug);
        // Single-file plugins and plugins without a version have no manifest.
        let Some(version) = plugin.version.as_deref().filter(|_| dir.is_dir()) else {
            unverifiable.push(plugin.slug.clone());
            continue;
        };
        if !url_safe(&plugin.slug) || !url_safe(version) {
            unverifiable.push(plugin.slug.clone());
            continue;
        }
        if requests >= client.max_plugins {
            report.limitations.push(format!(
                "Prüfsummen-Abgleich auf {} Plugins begrenzt.",
                client.max_plugins
            ));
            break;
        }
        requests += 1;
        let manifest = match client.plugin_checksums(&plugin.slug, version) {
            Ok(Some(m)) if !m.is_empty() => m,
            Ok(_) => {
                unverifiable.push(plugin.slug.clone());
                continue;
            }
            Err(e) => {
                report.limitations.push(format!(
                    "Prüfsummen für Plugin {} nicht abrufbar: {e}",
                    plugin.slug
                ));
                break;
            }
        };
        let result = compare(root, &dir, &manifest, |_| false, std::slice::from_ref(&dir));
        if result.mismatched_release() {
            other_release.push(format!("{} {version}", plugin.slug));
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    Category::IntegrityDeviation,
                    ecomsec_core::finding::Source::FileSystem,
                    "wp_plugin_release_mismatch",
                    format!("plugin:{}", plugin.slug),
                    format!(
                        "Plugin {} passt nicht zur angegebenen Version {version}",
                        plugin.slug
                    ),
                )
                .with_description(
                    "Ein großer Teil der Dateien stimmt nicht mit den Prüfsummen dieser Version überein. \
                     Meist ist ein Update unvollständig durchgelaufen oder die Versionsangabe wurde \
                     geändert. Plugin aus dem offiziellen Paket neu installieren \
                     (`wp plugin install <slug> --force`).",
                )
                .with_evidence(format!(
                    "{} von {} Dateien weichen ab",
                    result.modified.len(),
                    result.total - result.missing
                )),
            );
            continue;
        }
        let modified_code: Vec<&String> = result.modified.iter().filter(|r| is_code(r)).collect();
        for rel in modified_code.iter().take(MAX_FINDINGS_PER_PACKAGE) {
            report.findings.push(file_finding(
                root,
                rel,
                Severity::Warning,
                "wp_plugin_file_modified",
                format!(
                    "Plugin-Datei weicht vom Original ab ({} {version})",
                    plugin.slug
                ),
                "Der Inhalt stimmt nicht mit der Prüfsumme überein, die WordPress.org für diese \
                 Plugin-Version veröffentlicht. Entweder wurde das Plugin von Hand angepasst oder es \
                 wurde Code eingeschleust. Mit dem Original vergleichen \
                 (`wp plugin verify-checksums <slug>`) und bei Zweifel neu installieren.",
            ));
        }
        for rel in result.unknown.iter().take(MAX_FINDINGS_PER_PACKAGE) {
            report.findings.push(file_finding(
                root,
                rel,
                Severity::Warning,
                "wp_plugin_unknown_file",
                format!(
                    "Datei gehört nicht zum offiziellen Plugin-Paket ({} {version})",
                    plugin.slug
                ),
                "Das Paket von WordPress.org enthält diese ausführbare Datei nicht. Plugins legen \
                 selten eigenen Code in ihrem Verzeichnis ab; Angreifer verstecken Hintertüren gern \
                 zwischen Plugin-Dateien. Inhalt und Herkunft prüfen.",
            ));
        }
        if modified_code.is_empty() && result.unknown.is_empty() {
            verified_plugins += 1;
        } else {
            deviating.push(plugin.slug.clone());
        }
        report.verified_files.extend(result.verified);
    }
    let mut detail = Vec::new();
    if !deviating.is_empty() {
        detail.push(format!("Abweichungen: {}", deviating.join(", ")));
    }
    if !other_release.is_empty() {
        detail.push(format!(
            "anderer Versionsstand: {}",
            other_release.join(", ")
        ));
    }
    if !unverifiable.is_empty() {
        detail.push(format!(
            "ohne veröffentlichte Prüfsummen (Premium/Eigenentwicklung – nur Musterprüfung): {}",
            unverifiable.join(", ")
        ));
    }
    report.items.push(
        IntegrityItem::new(
            "integrity.wporg_plugins",
            "Integrität",
            "Plugins gegen offizielle Prüfsummen",
            if !deviating.is_empty() || !other_release.is_empty() {
                IntegrityStatus::Warning
            } else if verified_plugins > 0 {
                IntegrityStatus::Ok
            } else {
                IntegrityStatus::Unknown
            },
            format!(
                "{verified_plugins} original · {} mit Abweichungen · {} nicht prüfbar",
                deviating.len() + other_release.len(),
                unverifiable.len()
            ),
        )
        .with_detail(if detail.is_empty() {
            "Alle Plugins stimmen mit den Paketen von WordPress.org überein.".to_string()
        } else {
            detail.join(" · ")
        }),
    );
}

/// Rows shown when the online check is off.
pub fn offline_items() -> Vec<IntegrityItem> {
    vec![IntegrityItem::new(
        "integrity.wporg_core",
        "Integrität",
        "WordPress-Kern und Plugins gegen offizielle Prüfsummen",
        IntegrityStatus::Unknown,
        "nicht geprüft",
    )
    .with_detail(
        "Mit `--online` werden Kern- und Plugin-Dateien mit den Prüfsummen von WordPress.org \
         verglichen (gesendet werden Version, Sprache sowie Slug und Version der Plugins).",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    fn write(root: &Path, rel: &str, content: &[u8]) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn sha256(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    fn md5(data: &[u8]) -> String {
        hex::encode(Md5::digest(data))
    }

    /// Serve canned JSON by request path; unknown paths answer 404.
    fn serve(routes: Vec<(&'static str, String)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut line = String::new();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                reader.read_line(&mut line).ok();
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).unwrap_or(0) == 0 || header == "\r\n" {
                        break;
                    }
                }
                let hit = routes.iter().find(|(prefix, _)| path.starts_with(prefix));
                let (status, body) = match hit {
                    Some((_, body)) => ("200 OK", body.clone()),
                    None => ("404 Not Found", "Not found".to_string()),
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        base
    }

    fn plugin(slug: &str, version: &str) -> Extension {
        Extension {
            slug: slug.to_string(),
            main_file: Some(format!("wp-content/plugins/{slug}/{slug}.php")),
            name: Some(slug.to_string()),
            version: Some(version.to_string()),
            author: None,
            newest_mtime: None,
            php_files: 1,
            update_uri: None,
        }
    }

    #[test]
    fn core_and_plugins_are_compared_with_published_checksums() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let original = b"<?php // original core file\n";
        write(
            root,
            "wp-includes/version.php",
            b"<?php\n$wp_version = '6.6.2';\n$wp_local_package = 'de_DE';\n",
        );
        write(root, "wp-includes/load.php", original);
        write(
            root,
            "wp-admin/admin.php",
            b"<?php // tampered\n@eval($_POST['x']);",
        );
        write(
            root,
            "wp-includes/class-wp-cache-helper.php",
            b"<?php // dropped\n",
        );
        write(root, "index.php", original);
        write(root, "wp-config.php", b"<?php // config\n");
        write(root, "lock360.php", b"<?php // dropper\n");
        // Plugin: one original file, one changed, one added.
        write(
            root,
            "wp-content/plugins/shop-tools/shop-tools.php",
            b"<?php // plugin main\n",
        );
        write(
            root,
            "wp-content/plugins/shop-tools/inc/api.php",
            b"<?php // changed\n",
        );
        write(
            root,
            "wp-content/plugins/shop-tools/inc/.cache.php",
            b"<?php // added\n",
        );
        write(
            root,
            "wp-content/plugins/shop-tools/readme.txt",
            b"changed readme",
        );
        // Premium plugin without checksums.
        write(
            root,
            "wp-content/plugins/premium-suite/premium-suite.php",
            b"<?php\n",
        );

        let core = serde_json::json!({ "checksums": {
            "wp-includes/version.php": md5(b"<?php\n$wp_version = '6.6.2';\n$wp_local_package = 'de_DE';\n"),
            "wp-includes/load.php": md5(original),
            "wp-admin/admin.php": md5(b"<?php // original admin\n"),
            "index.php": md5(original),
            "wp-content/plugins/akismet/akismet.php": md5(b"not installed"),
            "../outside.php": md5(b"x"),
        }});
        let shop_tools = serde_json::json!({ "files": {
            "shop-tools.php": { "md5": md5(b"<?php // plugin main\n"), "sha256": sha256(b"<?php // plugin main\n") },
            "inc/api.php": { "md5": "0", "sha256": [sha256(b"<?php // original api\n"), sha256(b"<?php // retagged\n")] },
            "readme.txt": { "md5": "0", "sha256": sha256(b"original readme") },
        }});
        let base = serve(vec![
            (
                "/core/checksums/1.0/?version=6.6.2&locale=de_DE",
                core.to_string(),
            ),
            (
                "/plugin-checksums/shop-tools/1.4.0.json",
                shop_tools.to_string(),
            ),
        ]);
        let client = WpOrgClient::with_bases(&base, &base);
        let mut report = IntegrityReport::default();
        verify(
            root,
            Some("6.6.2"),
            &[
                plugin("shop-tools", "1.4.0"),
                plugin("premium-suite", "2.0"),
            ],
            &client,
            &mut report,
        );

        let has = |rule: &str, subject: &str, severity: Severity| {
            report
                .findings
                .iter()
                .any(|f| f.rule == rule && f.subject == subject && f.severity == severity)
        };
        assert!(has(
            "wp_core_file_modified",
            "wp-admin/admin.php",
            Severity::Critical
        ));
        assert!(has(
            "wp_core_unknown_file",
            "wp-includes/class-wp-cache-helper.php",
            Severity::Critical
        ));
        assert!(has(
            "wp_root_unknown_file",
            "lock360.php",
            Severity::Warning
        ));
        assert!(has(
            "wp_plugin_file_modified",
            "wp-content/plugins/shop-tools/inc/api.php",
            Severity::Warning
        ));
        assert!(has(
            "wp_plugin_unknown_file",
            "wp-content/plugins/shop-tools/inc/.cache.php",
            Severity::Warning
        ));
        // A changed readme cannot run code and wp-config.php is expected.
        assert!(!report
            .findings
            .iter()
            .any(|f| f.subject.ends_with("readme.txt")));
        assert!(!report.findings.iter().any(|f| f.subject == "wp-config.php"));
        assert_eq!(report.findings.len(), 5, "{:#?}", report.findings);

        let verified = &report.verified_files;
        assert!(verified.contains("wp-includes/load.php"));
        assert!(verified.contains("index.php"));
        assert!(verified.contains("wp-content/plugins/shop-tools/shop-tools.php"));
        assert!(!verified.contains("wp-admin/admin.php"));
        assert!(!verified.contains("wp-content/plugins/shop-tools/inc/api.php"));

        let item = |key: &str| report.items.iter().find(|i| i.key == key).unwrap();
        assert_eq!(
            item("integrity.wporg_core").status,
            IntegrityStatus::Critical
        );
        let plugins = item("integrity.wporg_plugins");
        assert_eq!(plugins.status, IntegrityStatus::Warning);
        assert!(plugins
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("premium-suite"));
    }

    #[test]
    fn another_release_on_disk_is_one_finding_and_verifies_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut files = serde_json::Map::new();
        for i in 0..10 {
            let rel = format!("inc/file{i}.php");
            write(
                root,
                &format!("wp-content/plugins/half-updated/{rel}"),
                b"<?php // new release\n",
            );
            files.insert(
                rel,
                serde_json::json!({ "sha256": sha256(b"<?php // old release\n") }),
            );
        }
        let base = serve(vec![(
            "/plugin-checksums/half-updated/3.0.json",
            serde_json::json!({ "files": files }).to_string(),
        )]);
        let client = WpOrgClient::with_bases(&base, &base);
        let mut report = IntegrityReport::default();
        verify_plugins(root, &[plugin("half-updated", "3.0")], &client, &mut report);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule, "wp_plugin_release_mismatch");
        assert!(report.verified_files.is_empty());
    }

    #[test]
    fn request_values_and_manifest_paths_are_validated() {
        assert!(url_safe("woocommerce") && url_safe("9.3.3") && url_safe("1.0.0-beta.1"));
        assert!(
            !url_safe("../../etc") && !url_safe("a/b") && !url_safe("1.0?x=1") && !url_safe("")
        );
        assert!(safe_relative("inc/api.php"));
        assert!(!safe_relative("../wp-config.php") && !safe_relative("/etc/passwd"));
        assert!(!safe_relative("a//b") && !safe_relative("a\\..\\b"));
        assert!(is_code("a/b.php") && is_code("x/.htaccess") && is_code("a.js"));
        assert!(!is_code("readme.txt") && !is_code("logo.png"));
    }
}
