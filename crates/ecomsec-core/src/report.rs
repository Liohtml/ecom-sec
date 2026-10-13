//! The scan report: findings, integrity view, advisories and
//! recommendations in one serialisable structure.

use crate::finding::{Finding, Severity};
use crate::platform::{AdvisoryStatus, IntegrityItem, PlatformInfo};
use crate::recommendations::RecommendationGroup;
use crate::score::{Grade, PostureScore, ScoreDriver};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

/// Overall verdict, derived from the non-accepted findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Clean,
    Warning,
    Critical,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Clean => "Keine kritischen Befunde",
            Verdict::Warning => "Warnungen – zeitnah prüfen",
            Verdict::Critical => "Kritische Befunde – sofort handeln",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    pub critical: usize,
    pub warning: usize,
    pub info: usize,
    /// Findings marked as harmless (not counted above).
    pub accepted: usize,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub duration_ms: u128,
    /// `false` when the time budget ran out and the scan must be resumed.
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    pub platform: PlatformInfo,
    pub reference_date: NaiveDate,
    pub verdict: Verdict,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub integrity: Vec<IntegrityItem>,
    pub advisories: Vec<AdvisoryStatus>,
    pub recommendations: Vec<RecommendationGroup>,
    /// Checks that were skipped or incomplete.
    pub limitations: Vec<String>,
    /// Security posture score 0–100 (see [`crate::score`]).  Missing in
    /// reports written by older versions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grade: Option<Grade>,
    /// Factors that lowered the score, largest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub score_drivers: Vec<ScoreDriver>,
}

impl Report {
    pub fn compute_summary(findings: &[Finding]) -> (Verdict, Summary) {
        let mut s = Summary {
            complete: true,
            ..Default::default()
        };
        for f in findings {
            match f.effective_severity() {
                None => s.accepted += 1,
                Some(Severity::Critical) => s.critical += 1,
                Some(Severity::Warning) => s.warning += 1,
                Some(Severity::Info) => s.info += 1,
            }
        }
        let verdict = if s.critical > 0 {
            Verdict::Critical
        } else if s.warning > 0 {
            Verdict::Warning
        } else {
            Verdict::Clean
        };
        (verdict, s)
    }

    /// Findings sorted by severity (critical first), accepted last.
    pub fn sorted_findings(&self) -> Vec<&Finding> {
        let mut v: Vec<&Finding> = self.findings.iter().collect();
        v.sort_by(|a, b| {
            a.accepted
                .cmp(&b.accepted)
                .then(b.severity.cmp(&a.severity))
                .then(a.subject.cmp(&b.subject))
        });
        v
    }

    /// (Re-)compute the posture score and store it in the report.
    pub fn apply_score(&mut self) {
        let s = crate::score::compute(self);
        self.score = Some(s.score);
        self.grade = Some(s.grade);
        self.score_drivers = s.drivers;
    }

    /// Stored posture score, or a freshly computed one for reports written
    /// by older versions.
    pub fn posture(&self) -> PostureScore {
        match (self.score, self.grade) {
            (Some(score), Some(grade)) => PostureScore {
                score,
                grade,
                drivers: self.score_drivers.clone(),
            },
            _ => crate::score::compute(self),
        }
    }

    pub fn find(&self, id: &str) -> Option<&Finding> {
        self.findings.iter().find(|f| f.id.as_str() == id)
    }

    /// Re-apply risk acceptance (after `accept`/`unaccept`) without a rescan:
    /// updates the findings, the summary/verdict and prunes references to
    /// accepted findings from the recommendations.
    pub fn reapply_acceptance(&mut self, accepted: &crate::state::AcceptedFindings) {
        for f in &mut self.findings {
            match accepted.findings.get(&f.id) {
                Some(a) => {
                    f.accepted = true;
                    f.accepted_reason = a.reason.clone();
                }
                None => {
                    f.accepted = false;
                    f.accepted_reason = None;
                }
            }
        }
        let (verdict, summary) = Report::compute_summary(&self.findings);
        self.verdict = verdict;
        self.summary = Summary {
            files_scanned: self.summary.files_scanned,
            bytes_scanned: self.summary.bytes_scanned,
            duration_ms: self.summary.duration_ms,
            complete: self.summary.complete,
            ..summary
        };
        let active: std::collections::HashSet<crate::finding::FindingId> = self
            .findings
            .iter()
            .filter(|f| !f.accepted)
            .map(|f| f.id.clone())
            .collect();
        for g in &mut self.recommendations {
            for r in &mut g.items {
                r.related.retain(|id| active.contains(id));
            }
        }
        self.apply_score();
    }
}

/// Compact entry kept in the scan history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub generated_at: DateTime<Utc>,
    pub platform_id: String,
    pub version: Option<String>,
    pub verdict: Verdict,
    pub critical: usize,
    pub warning: usize,
    pub info: usize,
    pub accepted: usize,
    pub files_scanned: u64,
    pub complete: bool,
    /// Posture score (missing in entries written by older versions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grade: Option<Grade>,
}

impl From<&Report> for HistoryEntry {
    fn from(r: &Report) -> Self {
        HistoryEntry {
            generated_at: r.generated_at,
            platform_id: r.platform.id.clone(),
            version: r.platform.version.as_ref().map(|v| v.to_string()),
            verdict: r.verdict,
            critical: r.summary.critical,
            warning: r.summary.warning,
            info: r.summary.info,
            accepted: r.summary.accepted,
            files_scanned: r.summary.files_scanned,
            complete: r.summary.complete,
            score: r.score,
            grade: r.grade,
        }
    }
}
