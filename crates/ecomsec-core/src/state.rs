//! Persistent, per-installation state: accepted findings, snapshots used for
//! change detection (payment recipient, admin list), scan history, the
//! file-scan checkpoint and the integrity baseline.
//!
//! Everything is plain JSON inside one directory so it can be inspected,
//! backed up or deleted by hand.

use crate::finding::FindingId;
use crate::report::HistoryEntry;
use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Acceptance {
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub accepted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AcceptedFindings {
    #[serde(default)]
    pub findings: BTreeMap<FindingId, Acceptance>,
}

#[derive(Debug, Clone)]
pub struct StateStore {
    dir: PathBuf,
}

const MAX_HISTORY: usize = 200;
/// Number of complete reports kept in `reports/` for change detection.
pub const MAX_ARCHIVED_REPORTS: usize = 10;
const REPORTS_DIR: &str = "reports";
const ARCHIVE_TS_FORMAT: &str = "%Y%m%dT%H%M%S%.3fZ";

impl StateStore {
    /// Use `dir` directly.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        StateStore { dir: dir.into() }
    }

    /// Per-target sub directory below `base`, keyed by platform id and a hash
    /// of the target (web root or shop domain).
    pub fn for_target(base: &Path, platform_id: &str, target: &str) -> Self {
        let digest = crate::util::sha256_hex(target.as_bytes());
        StateStore {
            dir: base.join(format!("{platform_id}-{}", &digest[..12])),
        }
    }

    /// Default base directory: `$ECOMSEC_STATE_DIR`, else
    /// `$XDG_STATE_HOME/ecomsec`, else `~/.local/state/ecomsec`.
    pub fn default_base() -> PathBuf {
        if let Ok(p) = std::env::var("ECOMSEC_STATE_DIR") {
            return PathBuf::from(p);
        }
        if let Ok(p) = std::env::var("XDG_STATE_HOME") {
            return PathBuf::from(p).join("ecomsec");
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("ecomsec");
        }
        PathBuf::from(".ecomsec-state")
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn ensure_dir(&self) -> io::Result<()> {
        fs::create_dir_all(&self.dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn read_json<T: DeserializeOwned + Default>(&self, name: &str) -> T {
        let p = self.path(name);
        match fs::read(&p) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                log::warn!("state file {} is corrupt ({e}); ignoring", p.display());
                T::default()
            }),
            Err(_) => T::default(),
        }
    }

    fn read_json_opt<T: DeserializeOwned>(&self, name: &str) -> Option<T> {
        let bytes = fs::read(self.path(name)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    fn write_json<T: Serialize>(&self, name: &str, value: &T) -> io::Result<()> {
        self.ensure_dir()?;
        let p = self.path(name);
        let tmp = p.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
        fs::rename(tmp, p)
    }

    // ------------------------------------------------------------ acceptance

    pub fn accepted(&self) -> AcceptedFindings {
        self.read_json("accepted.json")
    }

    pub fn accept(&self, id: FindingId, subject: &str, reason: Option<String>) -> io::Result<()> {
        let mut acc = self.accepted();
        acc.findings.insert(
            id,
            Acceptance {
                subject: subject.to_string(),
                reason,
                accepted_at: Utc::now(),
            },
        );
        self.write_json("accepted.json", &acc)
    }

    pub fn unaccept(&self, id: &FindingId) -> io::Result<bool> {
        let mut acc = self.accepted();
        let removed = acc.findings.remove(id).is_some();
        if removed {
            self.write_json("accepted.json", &acc)?;
        }
        Ok(removed)
    }

    pub fn clear_accepted(&self) -> io::Result<()> {
        self.write_json("accepted.json", &AcceptedFindings::default())
    }

    // ------------------------------------------------------------ snapshots

    /// Generic snapshot slot used for change detection between scans.
    pub fn snapshot<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.read_json_opt(&format!("snapshot-{key}.json"))
    }

    pub fn save_snapshot<T: Serialize>(&self, key: &str, value: &T) -> io::Result<()> {
        self.write_json(&format!("snapshot-{key}.json"), value)
    }

    // ------------------------------------------------------------ history

    pub fn history(&self) -> Vec<HistoryEntry> {
        self.read_json::<Vec<HistoryEntry>>("history.json")
    }

    pub fn push_history(&self, entry: HistoryEntry) -> io::Result<()> {
        let mut h = self.history();
        h.push(entry);
        if h.len() > MAX_HISTORY {
            let drop = h.len() - MAX_HISTORY;
            h.drain(..drop);
        }
        self.write_json("history.json", &h)
    }

    // ------------------------------------------------------------ last report

    pub fn save_last_report(&self, report: &crate::report::Report) -> io::Result<()> {
        self.write_json("last-report.json", report)
    }

    pub fn last_report(&self) -> Option<crate::report::Report> {
        self.read_json_opt("last-report.json")
    }

    // ------------------------------------------------------------ report archive

    /// Keep a copy of a complete report as `reports/<timestamp>.json` (used
    /// by `ecomsec diff` / `watch`).  Only the newest
    /// [`MAX_ARCHIVED_REPORTS`] files are kept.
    pub fn archive_report(&self, report: &crate::report::Report) -> io::Result<PathBuf> {
        let dir = self.dir.join(REPORTS_DIR);
        fs::create_dir_all(&dir)?;
        let name = format!("{}.json", report.generated_at.format(ARCHIVE_TS_FORMAT));
        let path = dir.join(&name);
        let tmp = dir.join(format!("{name}.tmp"));
        fs::write(&tmp, serde_json::to_vec_pretty(report)?)?;
        fs::rename(&tmp, &path)?;
        let files = self.archived_reports();
        if files.len() > MAX_ARCHIVED_REPORTS {
            for old in &files[..files.len() - MAX_ARCHIVED_REPORTS] {
                if let Err(e) = fs::remove_file(old) {
                    log::warn!("cannot prune {}: {e}", old.display());
                }
            }
        }
        Ok(path)
    }

    /// Archived report files, oldest first.
    pub fn archived_reports(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = match fs::read_dir(self.dir.join(REPORTS_DIR)) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| archive_timestamp(p).is_some())
                .collect(),
            Err(_) => Vec::new(),
        };
        files.sort();
        files
    }

    /// Read a report JSON file (archived or exported with `--format json`).
    pub fn load_report(path: &Path) -> io::Result<crate::report::Report> {
        let bytes = fs::read(path)?;
        serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// The newest archived report.
    pub fn latest_archived_report(&self) -> Option<crate::report::Report> {
        let files = self.archived_reports();
        files.iter().rev().find_map(|p| Self::load_report(p).ok())
    }

    /// Time stamps (`20261013T041700.123Z`) of the archived reports, oldest
    /// first.  The stamp is the report's `generated_at` truncated to
    /// milliseconds.
    pub fn archived_stamps(&self) -> Vec<String> {
        self.archived_reports()
            .iter()
            .filter_map(|p| archive_timestamp(p).map(str::to_string))
            .collect()
    }

    /// The archived report with the given stamp (see
    /// [`StateStore::archived_stamps`]).  Invalid stamps yield `None`.
    pub fn archived_report(&self, stamp: &str) -> Option<crate::report::Report> {
        let valid = stamp.len() == 20
            && stamp.as_bytes()[8] == b'T'
            && stamp.ends_with('Z')
            && stamp
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, 'T' | '.' | 'Z'));
        if !valid {
            return None;
        }
        Self::load_report(&self.dir.join(REPORTS_DIR).join(format!("{stamp}.json"))).ok()
    }

    /// The newest archived report generated strictly before `before`.
    pub fn previous_report(&self, before: DateTime<Utc>) -> Option<crate::report::Report> {
        let cutoff = before.format(ARCHIVE_TS_FORMAT).to_string();
        self.archived_reports()
            .iter()
            .rev()
            .filter(|p| archive_timestamp(p).is_some_and(|ts| ts < cutoff.as_str()))
            .find_map(|p| Self::load_report(p).ok())
    }

    // ------------------------------------------------------------ checkpoint

    pub fn checkpoint<T: DeserializeOwned>(&self) -> Option<T> {
        self.read_json_opt("checkpoint.json")
    }

    pub fn save_checkpoint<T: Serialize>(&self, value: &T) -> io::Result<()> {
        self.write_json("checkpoint.json", value)
    }

    pub fn clear_checkpoint(&self) -> io::Result<()> {
        match fs::remove_file(self.path("checkpoint.json")) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    // ------------------------------------------------------------ documents

    /// Store an additional JSON document (e.g. `last-audit.json`) in the
    /// state directory.  `name` must be a plain file name ending in `.json`.
    pub fn save_document<T: Serialize>(&self, name: &str, value: &T) -> io::Result<PathBuf> {
        if !valid_document_name(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid state document name {name:?}"),
            ));
        }
        self.write_json(name, value)?;
        Ok(self.path(name))
    }

    /// Load a JSON document stored with [`StateStore::save_document`].
    pub fn document<T: DeserializeOwned>(&self, name: &str) -> Option<T> {
        if !valid_document_name(name) {
            return None;
        }
        self.read_json_opt(name)
    }

    // ------------------------------------------------------------ baseline

    pub fn baseline(&self) -> Option<crate::baseline::Baseline> {
        self.read_json_opt("baseline.json")
    }

    pub fn save_baseline(&self, b: &crate::baseline::Baseline) -> io::Result<()> {
        self.write_json("baseline.json", b)
    }
}

/// Timestamp part of an archived report file name (`20261013T041700.123Z`).
fn archive_timestamp(path: &Path) -> Option<&str> {
    let name = path.file_name()?.to_str()?;
    let ts = name.strip_suffix(".json")?;
    (ts.len() == 20 && ts.ends_with('Z') && ts.as_bytes()[8] == b'T').then_some(ts)
}

fn valid_document_name(name: &str) -> bool {
    name.ends_with(".json")
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Category;

    #[test]
    fn documents_roundtrip_and_reject_bad_names() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path());
        store
            .save_document("last-audit.json", &vec![1, 2, 3])
            .unwrap();
        assert_eq!(
            store.document::<Vec<i32>>("last-audit.json"),
            Some(vec![1, 2, 3])
        );
        assert!(store.save_document("../x.json", &1).is_err());
        assert!(store.save_document("x.txt", &1).is_err());
        assert!(store.document::<i32>("../x.json").is_none());
    }

    #[test]
    fn accept_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path().join("s"));
        let id = FindingId::derive(Category::KnownWebshell, "x", "a.php");
        store
            .accept(id.clone(), "a.php", Some("ok".into()))
            .unwrap();
        assert!(store.accepted().findings.contains_key(&id));
        assert!(store.unaccept(&id).unwrap());
        assert!(!store.unaccept(&id).unwrap());
        assert!(store.accepted().findings.is_empty());
    }

    #[test]
    fn snapshots_and_history() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path());
        assert!(store.snapshot::<String>("x").is_none());
        store.save_snapshot("x", &"hello".to_string()).unwrap();
        assert_eq!(store.snapshot::<String>("x").as_deref(), Some("hello"));
        assert!(store.history().is_empty());
    }

    fn dummy_report(at: DateTime<Utc>) -> crate::report::Report {
        use crate::platform::{PlatformInfo, PlatformKind};
        crate::report::Report {
            schema_version: 1,
            generated_at: at,
            platform: PlatformInfo {
                id: "jtl5".into(),
                name: "JTL-Shop 5".into(),
                kind: PlatformKind::SelfHosted,
                version: None,
                root: None,
                target: None,
                details: vec![],
            },
            reference_date: chrono::NaiveDate::from_ymd_opt(2026, 6, 17).unwrap(),
            verdict: crate::report::Verdict::Clean,
            summary: Default::default(),
            findings: vec![],
            integrity: vec![],
            advisories: vec![],
            recommendations: vec![],
            limitations: vec![],
            score: None,
            grade: None,
            score_drivers: Vec::new(),
        }
    }

    #[test]
    fn report_archive_is_pruned_and_ordered() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path());
        assert!(store.latest_archived_report().is_none());
        let start = Utc::now() - chrono::Duration::days(30);
        for i in 0..(MAX_ARCHIVED_REPORTS + 3) {
            store
                .archive_report(&dummy_report(start + chrono::Duration::days(i as i64)))
                .unwrap();
        }
        // Unrelated files are ignored.
        fs::write(tmp.path().join("reports").join("notes.txt"), "x").unwrap();
        let files = store.archived_reports();
        assert_eq!(files.len(), MAX_ARCHIVED_REPORTS);
        let latest = store.latest_archived_report().unwrap();
        let expected_latest = start + chrono::Duration::days(MAX_ARCHIVED_REPORTS as i64 + 2);
        assert_eq!(latest.generated_at, expected_latest);
        let prev = store.previous_report(latest.generated_at).unwrap();
        assert_eq!(
            prev.generated_at,
            expected_latest - chrono::Duration::days(1)
        );
        let oldest_kept = start + chrono::Duration::days(3);
        assert!(store.previous_report(oldest_kept).is_none());
    }

    #[test]
    fn archived_report_by_stamp() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path());
        let at = Utc::now();
        store.archive_report(&dummy_report(at)).unwrap();
        let stamps = store.archived_stamps();
        assert_eq!(stamps.len(), 1);
        assert_eq!(stamps[0], at.format(ARCHIVE_TS_FORMAT).to_string());
        let r = store.archived_report(&stamps[0]).unwrap();
        assert_eq!(r.generated_at, at);
        assert!(store.archived_report("../last-report").is_none());
        assert!(store.archived_report("20260101T000000.000Z").is_none());
    }
}
