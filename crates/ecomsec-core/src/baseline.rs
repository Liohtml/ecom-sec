//! Integrity baseline: SHA-256 manifest of the code files of an installation
//! that later scans are compared against (changed / missing / new).

use crate::finding::{Category, Finding, Severity};
use crate::platform::FileScanProfile;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub created_at: DateTime<Utc>,
    pub root: String,
    pub platform_id: String,
    pub version: Option<String>,
    pub files: BTreeMap<String, FileRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineDiff {
    pub changed: Vec<String>,
    pub missing: Vec<String>,
    pub added: Vec<String>,
}

/// Extensions that are part of a baseline.
pub const CODE_EXTENSIONS: &[&str] = &[
    "php", "phtml", "inc", "phar", "tpl", "twig", "js", "htaccess", "ini", "json", "xml", "yaml",
    "yml", "env",
];

fn is_code_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name == ".htaccess" || name == ".user.ini" || name == ".env" {
        return true;
    }
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| CODE_EXTENSIONS.iter().any(|c| c.eq_ignore_ascii_case(e)))
        .unwrap_or(false)
}

fn is_excluded(rel: &str, profile: &FileScanProfile) -> bool {
    let under = |dirs: &[String]| {
        dirs.iter().any(|d| {
            let d = d.trim_end_matches('/');
            rel == d || rel.starts_with(&format!("{d}/"))
        })
    };
    under(&profile.excluded_dirs) || under(&profile.generated_dirs) || under(&profile.log_dirs)
}

impl Baseline {
    /// Walk the installation and record hashes of all code files that are
    /// neither excluded, generated nor logs.  When `core_only` is set, only
    /// the profile's `core_dirs` are recorded.
    pub fn create(
        profile: &FileScanProfile,
        platform_id: &str,
        version: Option<String>,
        core_only: bool,
    ) -> std::io::Result<Self> {
        let mut files = BTreeMap::new();
        for entry in WalkDir::new(&profile.root)
            .follow_links(false)
            .sort_by_file_name()
        {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    log::warn!("baseline: {e}");
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let rel = crate::util::relative_display(&profile.root, path);
            if is_excluded(&rel, profile) || !is_code_file(path) {
                continue;
            }
            if core_only
                && !profile.core_dirs.is_empty()
                && !profile.core_dirs.iter().any(|d| {
                    let d = d.trim_end_matches('/');
                    rel == d || rel.starts_with(&format!("{d}/"))
                })
            {
                continue;
            }
            match std::fs::read(path) {
                Ok(bytes) => {
                    files.insert(
                        rel,
                        FileRecord {
                            sha256: crate::util::sha256_hex(&bytes),
                            size: bytes.len() as u64,
                        },
                    );
                }
                Err(e) => log::warn!("baseline: cannot read {}: {e}", path.display()),
            }
        }
        Ok(Baseline {
            created_at: Utc::now(),
            root: profile.root.to_string_lossy().to_string(),
            platform_id: platform_id.to_string(),
            version,
            files,
        })
    }

    /// Compare the baseline against the current state of the installation.
    pub fn diff(&self, profile: &FileScanProfile) -> std::io::Result<BaselineDiff> {
        let current = Baseline::create(profile, &self.platform_id, self.version.clone(), false)?;
        let mut diff = BaselineDiff::default();
        for (rel, rec) in &self.files {
            match current.files.get(rel) {
                None => diff.missing.push(rel.clone()),
                Some(cur) if cur.sha256 != rec.sha256 => diff.changed.push(rel.clone()),
                _ => {}
            }
        }
        for rel in current.files.keys() {
            if !self.files.contains_key(rel) {
                diff.added.push(rel.clone());
            }
        }
        Ok(diff)
    }

    /// Turn a diff into findings.
    pub fn findings(profile: &FileScanProfile, diff: &BaselineDiff) -> Vec<Finding> {
        let mut out = Vec::new();
        let root = &profile.root;
        for rel in &diff.changed {
            out.push(
                Finding::file(
                    Severity::Warning,
                    Category::IntegrityDeviation,
                    "baseline_changed",
                    root,
                    &root.join(rel),
                    "Datei weicht von der Baseline ab",
                )
                .with_description(
                    "Der Hash der Datei unterscheidet sich von der zuletzt aufgezeichneten Baseline. \
                     Entweder wurde die Datei legitim aktualisiert (Update, Anpassung) oder manipuliert.",
                ),
            );
        }
        for rel in &diff.missing {
            out.push(
                Finding::file(
                    Severity::Warning,
                    Category::IntegrityDeviation,
                    "baseline_missing",
                    root,
                    &root.join(rel),
                    "Datei aus der Baseline fehlt",
                )
                .with_description(
                    "Die Datei war in der Baseline enthalten, existiert aber nicht mehr. Fehlgeschlagenes \
                     Update oder Löschung durch einen Angreifer.",
                ),
            );
        }
        for rel in &diff.added {
            out.push(
                Finding::file(
                    Severity::Info,
                    Category::IntegrityDeviation,
                    "baseline_added",
                    root,
                    &root.join(rel),
                    "Neue Datei seit der Baseline",
                )
                .with_description(
                    "Die Datei ist seit der Baseline hinzugekommen (Plugin, Update – oder Fremdcode).",
                ),
            );
        }
        out
    }
}
