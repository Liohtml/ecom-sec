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

    // ------------------------------------------------------------ baseline

    pub fn baseline(&self) -> Option<crate::baseline::Baseline> {
        self.read_json_opt("baseline.json")
    }

    pub fn save_baseline(&self, b: &crate::baseline::Baseline) -> io::Result<()> {
        self.write_json("baseline.json", b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Category;

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
}
