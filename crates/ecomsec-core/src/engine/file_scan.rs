//! Resumable, time-budgeted file scanner.
//!
//! For every file below the profile root the scanner performs, depending on
//! the file class:
//!
//! * IOC file-name lookup (known webshell names, double extensions …),
//! * "executable code in upload directory" check,
//! * modified-since-reference-date check with timestamp-manipulation
//!   heuristics (ctime newer than mtime, future dates),
//! * content rule matching (YARA-lite) with the class-specific rule subset,
//! * exposed backup / dump / config-copy detection below the public root.
//!
//! When a time budget is set, the scanner persists a checkpoint (position in
//! the sorted file list plus findings so far) and the next run continues
//! where it stopped.  This mirrors the staged scanning of the original plugin
//! that keeps shared-hosting PHP requests below the gateway timeout.

use super::ScanOptions;
use crate::finding::{Category, Finding, Severity};
use crate::platform::FileScanProfile;
use crate::rules::RuleSet;
use crate::signatures::IocList;
use crate::state::StateStore;
use chrono::{DateTime, Duration as ChronoDuration, NaiveDate, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Instant, SystemTime};
use walkdir::WalkDir;

/// Progress callback: (files done, files total).
pub type ProgressFn = Box<dyn Fn(usize, usize) + Send + Sync>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Checkpoint {
    root: String,
    reference_date: NaiveDate,
    started_at: DateTime<Utc>,
    next_index: usize,
    total: usize,
    files_scanned: u64,
    bytes_scanned: u64,
    findings: Vec<Finding>,
    limitations: Vec<String>,
}

#[derive(Debug, Default)]
pub struct FileScanResult {
    pub findings: Vec<Finding>,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub complete: bool,
    pub remaining: usize,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileClass {
    Php,
    Htaccess,
    Ini,
    Template,
    Js,
    Log,
    Image,
    Archive,
    Other,
}

impl FileClass {
    pub fn as_str(self) -> &'static str {
        match self {
            FileClass::Php => "php",
            FileClass::Htaccess => "htaccess",
            FileClass::Ini => "ini",
            FileClass::Template => "template",
            FileClass::Js => "js",
            FileClass::Log => "log",
            FileClass::Image => "image",
            FileClass::Archive => "archive",
            FileClass::Other => "other",
        }
    }
}

pub const PHP_EXTENSIONS: &[&str] = &[
    "php", "phtml", "php3", "php4", "php5", "php7", "php8", "phps", "phar", "inc", "pht", "phtm",
    "pgif",
];

const IMAGE_EXTENSIONS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "webp", "svg", "bmp", "ico", "avif",
];
const ARCHIVE_EXTENSIONS: &[&str] = &[
    "sql", "zip", "tar", "gz", "tgz", "bz2", "xz", "rar", "7z", "bak", "old", "orig", "dump",
    "sql.gz", "sql.zip", "tar.gz",
];

/// Classify a file by name / extension / location.
pub fn classify(path: &Path, rel: &str, profile: &FileScanProfile) -> FileClass {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name == ".htaccess" || name == ".htpasswd" || name == "web.config" {
        return FileClass::Htaccess;
    }
    if name == ".user.ini" || name == "php.ini" || name == ".htaccess.ini" {
        return FileClass::Ini;
    }
    let ext = name.rsplit('.').next().unwrap_or("").to_string();
    if under_any(rel, &profile.log_dirs) || ext == "log" {
        return FileClass::Log;
    }
    if PHP_EXTENSIONS.contains(&ext.as_str()) {
        return FileClass::Php;
    }
    if profile
        .template_extensions
        .iter()
        .any(|t| t.eq_ignore_ascii_case(&ext))
    {
        return FileClass::Template;
    }
    if ext == "js" || ext == "mjs" || ext == "cjs" {
        return FileClass::Js;
    }
    if IMAGE_EXTENSIONS.contains(&ext.as_str()) {
        return FileClass::Image;
    }
    if ARCHIVE_EXTENSIONS.contains(&ext.as_str()) {
        return FileClass::Archive;
    }
    FileClass::Other
}

fn under_any(rel: &str, dirs: &[String]) -> bool {
    dirs.iter().any(|d| {
        let d = d.trim_end_matches('/').trim_start_matches("./");
        !d.is_empty() && (rel == d || rel.starts_with(&format!("{d}/")))
    })
}

fn exposed_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(\.(sql|sql\.gz|sql\.zip|sql\.bz2|dump|mysql)$|^(backup|bak|sicherung|dump|db|database|export)[\w.-]*\.(zip|tar|tar\.gz|tgz|gz|7z|rar)$|\.(zip|tar\.gz|tgz|rar|7z)$|^(config|configuration|settings|\.env|wp-config|local)[\w.-]*\.(bak|old|orig|save|txt|copy|dist|~|[0-9]+)$|\.(php|phtml|inc)\.(bak|old|orig|save|txt|copy|~|[0-9]+)$|^\.env(\..+)?$|\.(pem|key|p12|pfx|ppk)$)",
        )
        .expect("valid regex")
    })
}

pub struct FileScanner<'a> {
    profile: &'a FileScanProfile,
    rules: &'a RuleSet,
    iocs: &'a IocList,
    options: &'a ScanOptions,
}

impl<'a> FileScanner<'a> {
    pub fn new(
        profile: &'a FileScanProfile,
        rules: &'a RuleSet,
        iocs: &'a IocList,
        options: &'a ScanOptions,
    ) -> Self {
        FileScanner {
            profile,
            rules,
            iocs,
            options,
        }
    }

    /// Enumerate all files in deterministic order.
    fn enumerate(&self) -> (Vec<PathBuf>, Vec<String>) {
        let root = &self.profile.root;
        let mut files = Vec::new();
        let mut limitations = Vec::new();
        let walker = WalkDir::new(root)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|e| {
                if e.depth() == 0 || !e.file_type().is_dir() {
                    return true;
                }
                let rel = crate::util::relative_display(root, e.path());
                !under_any(&rel, &self.profile.excluded_dirs)
            });
        for entry in walker {
            match entry {
                Ok(e) if e.file_type().is_file() => files.push(e.path().to_path_buf()),
                Ok(_) => {}
                Err(e) => {
                    let msg = format!("nicht lesbar: {e}");
                    if limitations.len() < 20 {
                        limitations.push(msg);
                    }
                }
            }
        }
        (files, limitations)
    }

    pub fn run(
        &self,
        state: &StateStore,
        progress: Option<ProgressFn>,
    ) -> anyhow::Result<FileScanResult> {
        let started = Instant::now();
        let root_key = self.profile.root.to_string_lossy().to_string();
        let (files, enum_limitations) = self.enumerate();
        let total = files.len();

        let mut cp = match state.checkpoint::<Checkpoint>() {
            Some(cp)
                if self.options.resume
                    && cp.root == root_key
                    && cp.reference_date == self.options.reference_date
                    && cp.next_index <= total
                    && Utc::now() - cp.started_at < ChronoDuration::hours(24) =>
            {
                log::info!("resuming file scan at {}/{}", cp.next_index, total);
                cp
            }
            _ => Checkpoint {
                root: root_key,
                reference_date: self.options.reference_date,
                started_at: Utc::now(),
                next_index: 0,
                total,
                files_scanned: 0,
                bytes_scanned: 0,
                findings: Vec::new(),
                limitations: enum_limitations,
            },
        };
        cp.total = total;

        let reference: DateTime<Utc> = self
            .options
            .reference_date
            .and_hms_opt(0, 0, 0)
            .expect("midnight")
            .and_utc();
        let now = Utc::now();
        let mut complete = true;

        while cp.next_index < total {
            if let Some(budget) = self.options.time_budget {
                if started.elapsed() >= budget {
                    complete = false;
                    break;
                }
            }
            let path = &files[cp.next_index];
            cp.next_index += 1;
            cp.files_scanned += 1;
            if let Some(p) = &progress {
                if cp.next_index % 250 == 0 || cp.next_index == total {
                    p(cp.next_index, total);
                }
            }
            match self.scan_file(path, reference, now) {
                Ok((bytes, mut findings)) => {
                    cp.bytes_scanned += bytes;
                    cp.findings.append(&mut findings);
                }
                Err(e) => {
                    if cp.limitations.len() < 50 {
                        cp.limitations.push(format!("{}: {e}", path.display()));
                    }
                }
            }
        }

        if complete {
            state.clear_checkpoint()?;
            collapse_deployment_noise(&mut cp.findings, cp.files_scanned);
        } else {
            state.save_checkpoint(&cp)?;
        }
        Ok(FileScanResult {
            findings: cp.findings,
            files_scanned: cp.files_scanned,
            bytes_scanned: cp.bytes_scanned,
            complete,
            remaining: total.saturating_sub(cp.next_index),
            limitations: cp.limitations,
        })
    }

    /// Scan one file; returns bytes read and findings.
    fn scan_file(
        &self,
        path: &Path,
        reference: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> anyhow::Result<(u64, Vec<Finding>)> {
        let root = &self.profile.root;
        let rel = crate::util::relative_display(root, path);
        let class = classify(path, &rel, self.profile);
        let meta = fs::symlink_metadata(path)?;
        let size = meta.len();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let in_upload = under_any(&rel, &self.profile.upload_dirs);
        let in_generated = under_any(&rel, &self.profile.generated_dirs);
        let mut findings = Vec::new();
        let mut bytes_read = 0u64;

        // ----------------------------------------------------------- IOC names
        if matches!(
            class,
            FileClass::Php | FileClass::Other | FileClass::Image | FileClass::Archive
        ) {
            if let Some(ioc) = self.iocs.lookup(name) {
                let severity = if in_upload && ioc.spec.severity == Severity::Warning {
                    Severity::Critical
                } else {
                    ioc.spec.severity
                };
                let mut f = Finding::file(
                    severity,
                    Category::KnownWebshell,
                    "ioc_filename",
                    root,
                    path,
                    format!("Dateiname entspricht bekanntem IOC: {}", ioc.spec.name),
                )
                .with_description(
                    "Der Dateiname steht auf einer Liste bekannter Webshell-/Backdoor-Namen (CISA, NSA, \
                     MITRE ATT&CK T1505.003) bzw. nutzt ein typisches Tarnmuster. Inhalt prüfen; nicht \
                     erklärbare Dateien sichern und entfernen.",
                )
                .with_evidence(format!("{} ({})", name, crate::util::human_size(size)));
                if let Some(r) = &ioc.spec.reference {
                    f = f.with_evidence(r.clone());
                }
                findings.push(f);
            }
        }

        // ----------------------------------------------------------- uploads
        if class == FileClass::Php && in_upload {
            findings.push(
                Finding::file(
                    Severity::Critical,
                    Category::CodeInUploadDir,
                    "php_in_upload_dir",
                    root,
                    path,
                    "PHP-Datei in Upload-/Medienverzeichnis",
                )
                .with_description(
                    "Upload- und Medienverzeichnisse dürfen keine ausführbaren Dateien enthalten. Ein PHP-\
                     Script an dieser Stelle ist ein klassisches Muster für eine über einen Upload-Bug \
                     abgelegte Webshell.",
                )
                .with_evidence(format!("{} ({})", rel, crate::util::human_size(size))),
            );
        }

        // ----------------------------------------------------------- timestamps
        if matches!(class, FileClass::Php | FileClass::Htaccess | FileClass::Ini) {
            let mtime: Option<DateTime<Utc>> = meta.modified().ok().map(DateTime::<Utc>::from);
            let ctime: Option<DateTime<Utc>> = ctime_of(&meta);
            if let Some(m) = mtime {
                if m >= reference {
                    let severity = if in_generated {
                        Severity::Info
                    } else {
                        Severity::Warning
                    };
                    findings.push(
                        Finding::file(
                            severity,
                            Category::ModifiedSinceReference,
                            "modified_since_reference",
                            root,
                            path,
                            if in_generated {
                                "Generierte Datei seit Referenzdatum geändert"
                            } else {
                                "Datei seit Referenzdatum neu oder geändert"
                            },
                        )
                        .with_description(format!(
                            "Änderungszeit {} liegt nach dem Referenzdatum {}. Jede unbekannte Änderung an \
                             ausführbaren Dateien seit Bekanntwerden der Schwachstelle ist zu verifizieren \
                             (Update? Agentur? Plugin?).",
                            m.format("%d.%m.%Y %H:%M:%S UTC"),
                            self.options.reference_date.format("%d.%m.%Y")
                        ))
                        .with_evidence(format!("mtime={}", m.to_rfc3339())),
                    );
                }
                if m > now + ChronoDuration::days(1) {
                    findings.push(
                        Finding::file(
                            Severity::Warning,
                            Category::TimestampAnomaly,
                            "mtime_in_future",
                            root,
                            path,
                            "Änderungszeit liegt in der Zukunft",
                        )
                        .with_description("Zeitstempel wurden offenbar manipuliert (touch).")
                        .with_evidence(format!("mtime={}", m.to_rfc3339())),
                    );
                }
                if let Some(c) = ctime {
                    // ctime cannot be set from user space: if the inode changed
                    // after the reference date while the content claims to be
                    // older, the mtime was most likely back-dated.
                    if c >= reference && m < reference && c - m > ChronoDuration::hours(6) {
                        findings.push(
                            Finding::file(
                                Severity::Warning,
                                Category::TimestampAnomaly,
                                "ctime_newer_than_mtime",
                                root,
                                path,
                                "Mögliche Zeitstempel-Manipulation (ctime nach Referenzdatum, mtime davor)",
                            )
                            .with_description(
                                "Die Inode-Änderungszeit (ctime) liegt nach dem Referenzdatum, die \
                                 Änderungszeit (mtime) davor. ctime lässt sich nicht zurückdatieren – \
                                 typisch für `touch -r`-Tarnung nach dem Ablegen einer Datei. Kann auch \
                                 durch Deployment-Tools (rsync -t, Archive entpacken, chmod) entstehen.",
                            )
                            .with_evidence(format!("mtime={} ctime={}", m.to_rfc3339(), c.to_rfc3339())),
                        );
                    }
                }
            }
        }

        // ----------------------------------------------------------- exposed files
        if let Ok(pub_rel) = path.strip_prefix(self.profile.public_root()) {
            let pub_rel = pub_rel.to_string_lossy().replace('\\', "/");
            let in_excluded_public = under_any(&pub_rel, &self.profile.generated_dirs);
            if !in_excluded_public && exposed_regex().is_match(name) && class != FileClass::Php {
                let lower = name.to_ascii_lowercase();
                let severity = if lower.contains(".sql")
                    || lower.contains("dump")
                    || lower.starts_with(".env")
                    || lower.ends_with(".pem")
                    || lower.ends_with(".key")
                    || lower.ends_with(".ppk")
                {
                    Severity::Critical
                } else if size < 1024 && lower.ends_with(".zip") {
                    Severity::Info
                } else {
                    Severity::Warning
                };
                findings.push(
                    Finding::file(
                        severity,
                        Category::ExposedFile,
                        "exposed_file",
                        root,
                        path,
                        "Backup-, Dump-, Schlüssel- oder Konfigurationskopie im Webroot",
                    )
                    .with_description(
                        "Die Datei liegt unterhalb des öffentlich erreichbaren Verzeichnisses und kann je \
                         nach Webserver-Konfiguration direkt heruntergeladen werden. Dumps und \
                         Konfigurationskopien enthalten häufig Zugangsdaten.",
                    )
                    .with_evidence(format!("{} ({})", pub_rel, crate::util::human_size(size))),
                );
            }
        }

        // ----------------------------------------------------------- content
        let content_class = match class {
            FileClass::Php => Some("php"),
            FileClass::Htaccess => Some("htaccess"),
            FileClass::Ini => Some("ini"),
            FileClass::Template => Some("template"),
            FileClass::Js => Some("js"),
            FileClass::Log => Some("log"),
            FileClass::Image => Some("image"),
            FileClass::Archive | FileClass::Other => None,
        };
        if let Some(cls) = content_class {
            let limit = match class {
                FileClass::Image => (2 * 1024 * 1024).min(self.options.max_file_size),
                FileClass::Log => 64 * 1024 * 1024,
                _ => self.options.max_file_size,
            };
            if size > limit && class != FileClass::Log {
                if class == FileClass::Php {
                    findings.push(
                        Finding::file(
                            Severity::Info,
                            Category::ScanLimitation,
                            "file_too_large",
                            root,
                            path,
                            "Datei zu groß für die Inhaltsprüfung",
                        )
                        .with_evidence(crate::util::human_size(size)),
                    );
                }
            } else {
                let data = read_limited(path, size, limit)?;
                bytes_read = data.len() as u64;
                for hit in self.rules.scan(cls, &data) {
                    let spec = &hit.rule.spec;
                    let mut severity = spec.severity;
                    if in_generated
                        && severity == Severity::Warning
                        && spec.category == Category::SuspiciousPattern
                    {
                        // Compiled templates legitimately contain odd PHP.
                        severity = Severity::Info;
                    }
                    let mut f = Finding::file(
                        severity,
                        spec.category,
                        spec.name.clone(),
                        root,
                        path,
                        spec.description.to_string(),
                    )
                    .with_description(format!(
                        "Regel `{}`{}: {}",
                        spec.name,
                        if spec.tags.is_empty() {
                            String::new()
                        } else {
                            format!(" [{}]", spec.tags.join(", "))
                        },
                        spec.description
                    ));
                    let mut seen = std::collections::HashSet::new();
                    for ex in hit
                        .excerpts
                        .iter()
                        .filter(|e| seen.insert((*e).clone()))
                        .take(3)
                    {
                        f = f.with_evidence(ex.clone());
                    }
                    if let Some(r) = &spec.reference {
                        f = f.with_evidence(r.clone());
                    }
                    findings.push(f);
                }
            }
        }

        Ok((bytes_read, findings))
    }
}

/// A fresh deployment (rsync -t, unpacking a release archive) after the
/// reference date gives *every* file a new ctime while keeping old mtimes.
/// Reporting thousands of per-file anomalies would bury real findings, so a
/// mass occurrence is collapsed into one informational finding.
fn collapse_deployment_noise(findings: &mut Vec<Finding>, files_scanned: u64) {
    let anomalies = findings
        .iter()
        .filter(|f| f.rule == "ctime_newer_than_mtime")
        .count();
    // Fewer than ten files are always listed individually; above that a
    // share of 30 % or more of all scanned files is a deployment pattern.
    if anomalies < 10 || (anomalies as f64) < 0.3 * files_scanned.max(1) as f64 {
        return;
    }
    let sample: Vec<String> = findings
        .iter()
        .filter(|f| f.rule == "ctime_newer_than_mtime")
        .take(5)
        .map(|f| f.subject.clone())
        .collect();
    findings.retain(|f| f.rule != "ctime_newer_than_mtime");
    findings.push(
        Finding::new(
            Severity::Info,
            Category::TimestampAnomaly,
            crate::finding::Source::FileSystem,
            "ctime_mass_anomaly",
            "deployment",
            format!(
                "{anomalies} Dateien mit ctime nach dem Referenzdatum bei älterer mtime (vermutlich Deployment)"
            ),
        )
        .with_description(
            "Ein Großteil der Dateien wurde nach dem Referenzdatum auf dem Server abgelegt, trägt aber \
             ältere Änderungszeiten. Das ist typisch für ein Deployment mit erhaltenen Zeitstempeln und \
             kein Hinweis auf eine Manipulation einzelner Dateien. Einzelne Dateien mit diesem Muster \
             würden separat gemeldet.",
        )
        .with_evidence(sample.join(", ")),
    );
}

/// Read a file fully, or – for oversized logs – only its tail.
fn read_limited(path: &Path, size: u64, limit: u64) -> std::io::Result<Vec<u8>> {
    if size <= limit {
        return fs::read(path);
    }
    let mut f = fs::File::open(path)?;
    f.seek(SeekFrom::Start(size - limit))?;
    let mut buf = Vec::with_capacity(limit as usize);
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(unix)]
fn ctime_of(meta: &fs::Metadata) -> Option<DateTime<Utc>> {
    use std::os::unix::fs::MetadataExt;
    let secs = meta.ctime();
    let nanos = meta.ctime_nsec() as u32;
    DateTime::<Utc>::from_timestamp(secs, nanos)
}

#[cfg(not(unix))]
fn ctime_of(meta: &fs::Metadata) -> Option<DateTime<Utc>> {
    meta.created().ok().map(DateTime::<Utc>::from)
}

#[allow(dead_code)]
fn system_time_to_utc(t: SystemTime) -> DateTime<Utc> {
    DateTime::<Utc>::from(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures;
    use filetime::{set_file_mtime, FileTime};

    fn profile(root: &Path) -> FileScanProfile {
        let mut p = FileScanProfile::new(root);
        p.upload_dirs = vec!["mediafiles".into(), "uploads".into()];
        p.generated_dirs = vec!["templates_c".into()];
        p.log_dirs = vec!["jtllogs".into()];
        p.template_extensions = vec!["tpl".into()];
        p
    }

    fn write(root: &Path, rel: &str, content: &[u8]) -> PathBuf {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, content).unwrap();
        p
    }

    fn old(path: &Path) {
        // 2024-01-01
        set_file_mtime(path, FileTime::from_unix_time(1_704_067_200, 0)).unwrap();
    }

    #[test]
    fn detects_typical_compromise_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("shop");
        fs::create_dir_all(&root).unwrap();
        let clean = write(&root, "includes/src/Product.php", b"<?php class Product {}");
        old(&clean);
        let shell = write(
            &root,
            "mediafiles/Bilder/wso.php",
            b"<?php eval($_POST['x']);",
        );
        old(&shell);
        let ht = write(
            &root,
            "mediafiles/.htaccess",
            b"AddHandler application/x-httpd-php .jpg\n",
        );
        old(&ht);
        let dump = write(&root, "backup.sql", b"CREATE TABLE x;");
        old(&dump);
        let fresh = write(&root, "admin/new.php", b"<?php echo 1;");
        let _ = fresh; // mtime = now -> modified since reference
        let gen = write(
            &root,
            "templates_c/abc.php",
            b"<?php /* compiled */ echo 'x';",
        );
        let _ = gen;

        let rules = signatures::builtin_rules().unwrap();
        let iocs = IocList::builtin().unwrap();
        let opts = ScanOptions {
            no_persist: true,
            ..Default::default()
        };
        let profile = profile(&root);
        let state = StateStore::new(tmp.path().join("state"));
        let scanner = FileScanner::new(&profile, &rules, &iocs, &opts);
        let res = scanner.run(&state, None).unwrap();
        assert!(res.complete);
        assert_eq!(res.files_scanned, 6);

        let has = |rule: &str, subject: &str| {
            res.findings
                .iter()
                .any(|f| f.rule == rule && f.subject == subject)
        };
        assert!(has("ioc_filename", "mediafiles/Bilder/wso.php"));
        assert!(has("php_in_upload_dir", "mediafiles/Bilder/wso.php"));
        assert!(has("php_china_chopper", "mediafiles/Bilder/wso.php"));
        assert!(has(
            "htaccess_php_handler_for_non_php",
            "mediafiles/.htaccess"
        ));
        assert!(has("exposed_file", "backup.sql"));
        assert!(has("modified_since_reference", "admin/new.php"));
        let gen_finding = res
            .findings
            .iter()
            .find(|f| f.rule == "modified_since_reference" && f.subject == "templates_c/abc.php")
            .unwrap();
        assert_eq!(gen_finding.severity, Severity::Info);
        // The clean file only triggers the ctime heuristic (test fixture was
        // created just now with a back-dated mtime) – never a content finding.
        assert!(res
            .findings
            .iter()
            .filter(|f| f.subject == "includes/src/Product.php")
            .all(|f| f.rule == "ctime_newer_than_mtime"));
    }

    #[test]
    fn time_budget_checkpoints_and_resumes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("shop");
        for i in 0..40 {
            let p = write(&root, &format!("includes/f{i:03}.php"), b"<?php echo 1;");
            old(&p);
        }
        let rules = signatures::builtin_rules().unwrap();
        let iocs = IocList::builtin().unwrap();
        let state = StateStore::new(tmp.path().join("state"));
        let profile = profile(&root);
        let opts = ScanOptions {
            time_budget: Some(std::time::Duration::from_nanos(1)),
            no_persist: true,
            ..Default::default()
        };
        let scanner = FileScanner::new(&profile, &rules, &iocs, &opts);
        let first = scanner.run(&state, None).unwrap();
        assert!(!first.complete);
        assert!(first.remaining > 0);
        assert!(state.checkpoint::<Checkpoint>().is_some());

        let opts = ScanOptions {
            no_persist: true,
            ..Default::default()
        };
        let scanner = FileScanner::new(&profile, &rules, &iocs, &opts);
        let second = scanner.run(&state, None).unwrap();
        assert!(second.complete);
        assert_eq!(second.files_scanned, 40);
        assert!(state.checkpoint::<Checkpoint>().is_none());
    }

    #[test]
    fn classification() {
        let tmp = tempfile::tempdir().unwrap();
        let p = profile(tmp.path());
        let c = |rel: &str| classify(&tmp.path().join(rel), rel, &p);
        assert_eq!(c("a/b.php"), FileClass::Php);
        assert_eq!(c("a/x.phtml"), FileClass::Php);
        assert_eq!(c("a/.htaccess"), FileClass::Htaccess);
        assert_eq!(c("a/.user.ini"), FileClass::Ini);
        assert_eq!(c("jtllogs/x.txt"), FileClass::Log);
        assert_eq!(c("templates/x.tpl"), FileClass::Template);
        assert_eq!(c("js/app.js"), FileClass::Js);
        assert_eq!(c("bilder/a.jpg"), FileClass::Image);
        assert_eq!(c("dump.sql"), FileClass::Archive);
        assert_eq!(c("readme.md"), FileClass::Other);
    }
}
