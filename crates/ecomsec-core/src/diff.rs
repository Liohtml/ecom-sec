//! Change detection between two scan reports: what is new, what is gone,
//! which advisories newly affect the installation and which integrity values
//! changed.  This is the basis of `ecomsec diff`, `ecomsec watch`, the
//! dashboard panel "Änderungen seit letztem Scan" and all notifications.
//!
//! Findings are matched by their stable [`FindingId`]; integrity rows by
//! their `key`; advisories by their id.

use crate::finding::{Finding, FindingId, Severity};
use crate::platform::{IntegrityItem, IntegrityStatus, PatchState};
use crate::report::{Report, Verdict};
use crate::state::StateStore;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;

pub const DIFF_SCHEMA_VERSION: u32 = 1;

/// Maximum number of lines per section in the rendered summaries.
pub const MAX_SECTION_LINES: usize = 20;

/// Finding counts of the newer report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffCounts {
    pub critical: usize,
    pub warning: usize,
    pub info: usize,
    pub accepted: usize,
}

/// A finding present in both reports whose severity changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityChange {
    pub before: Severity,
    pub after: Severity,
    /// The finding as it appears in the newer report.
    pub finding: Finding,
}

impl SeverityChange {
    pub fn escalated(&self) -> bool {
        self.after > self.before
    }
}

/// An advisory whose evaluation changed between the reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryChange {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    /// `None` when the advisory was not known at the time of the older report
    /// (e.g. newly published and fetched with `advisories update`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_before: Option<PatchState>,
    pub state_after: PatchState,
    pub basis: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixed_in: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    pub published: NaiveDate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityChangeKind {
    Added,
    Removed,
    Changed,
}

/// A row of the integrity view that appeared, disappeared or changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityChange {
    pub key: String,
    pub section: String,
    pub label: String,
    pub change: IntegrityChangeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_before: Option<IntegrityStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_after: Option<IntegrityStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// `true` when the row was added/removed or its status changed.  Pure
    /// value changes with the same status (e.g. "letzter Login") are kept in
    /// the diff but do not count as a change worth notifying about.
    pub significant: bool,
}

fn status_rank(s: IntegrityStatus) -> u8 {
    match s {
        IntegrityStatus::Ok | IntegrityStatus::Unknown => 0,
        IntegrityStatus::Warning => 1,
        IntegrityStatus::Critical => 2,
    }
}

fn status_label(s: IntegrityStatus) -> &'static str {
    match s {
        IntegrityStatus::Ok => "OK",
        IntegrityStatus::Warning => "Prüfen",
        IntegrityStatus::Critical => "Kritisch",
        IntegrityStatus::Unknown => "unbekannt",
    }
}

impl IntegrityChange {
    /// Severity of a deterioration (status got worse), if any.
    pub fn worsened(&self) -> Option<Severity> {
        let before = self.status_before.map(status_rank).unwrap_or(0);
        let after = self.status_after.map(status_rank)?;
        if after > before {
            Some(if after == 2 {
                Severity::Critical
            } else {
                Severity::Warning
            })
        } else {
            None
        }
    }
}

/// Difference between an older and a newer report of the same installation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportDiff {
    pub schema_version: u32,
    pub platform_id: String,
    pub platform_name: String,
    /// Web root or shop domain.
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_generated_at: Option<DateTime<Utc>>,
    pub after_generated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_before: Option<Verdict>,
    pub verdict_after: Verdict,
    pub summary_after: DiffCounts,
    /// No older report was available: every active finding counts as new.
    pub first_run: bool,
    /// Highest severity among the relevant changes (`None`: nothing relevant).
    pub relevance: Option<Severity>,
    /// Active (not accepted) findings that did not exist before.
    pub new_findings: Vec<Finding>,
    /// Findings of the older report (not accepted then) that are gone.
    pub resolved_findings: Vec<Finding>,
    pub changed_severity: Vec<SeverityChange>,
    /// Advisories that now report the installation as vulnerable.
    pub new_advisories: Vec<AdvisoryChange>,
    /// Advisories that were vulnerable before and no longer are.
    #[serde(default)]
    pub fixed_advisories: Vec<AdvisoryChange>,
    pub integrity_changes: Vec<IntegrityChange>,
}

impl ReportDiff {
    /// Compare `before` (older, optional) with `after` (newer).
    pub fn compute(before: Option<&Report>, after: &Report) -> ReportDiff {
        let mut diff = ReportDiff {
            schema_version: DIFF_SCHEMA_VERSION,
            platform_id: after.platform.id.clone(),
            platform_name: after.platform.name.clone(),
            target: after.platform.target_key(),
            before_generated_at: before.map(|b| b.generated_at),
            after_generated_at: after.generated_at,
            version_before: before.and_then(|b| b.platform.version.as_ref().map(|v| v.to_string())),
            version_after: after.platform.version.as_ref().map(|v| v.to_string()),
            verdict_before: before.map(|b| b.verdict),
            verdict_after: after.verdict,
            summary_after: DiffCounts {
                critical: after.summary.critical,
                warning: after.summary.warning,
                info: after.summary.info,
                accepted: after.summary.accepted,
            },
            first_run: before.is_none(),
            relevance: None,
            new_findings: Vec::new(),
            resolved_findings: Vec::new(),
            changed_severity: Vec::new(),
            new_advisories: Vec::new(),
            fixed_advisories: Vec::new(),
            integrity_changes: Vec::new(),
        };

        // ------------------------------------------------------------ findings
        let old: HashMap<&FindingId, &Finding> = before
            .map(|b| b.findings.iter().map(|f| (&f.id, f)).collect())
            .unwrap_or_default();
        let new: HashMap<&FindingId, &Finding> =
            after.findings.iter().map(|f| (&f.id, f)).collect();
        for f in &after.findings {
            match old.get(&f.id) {
                None if !f.accepted => diff.new_findings.push(f.clone()),
                Some(prev) if prev.severity != f.severity && !f.accepted => {
                    diff.changed_severity.push(SeverityChange {
                        before: prev.severity,
                        after: f.severity,
                        finding: f.clone(),
                    })
                }
                _ => {}
            }
        }
        if let Some(b) = before {
            for f in &b.findings {
                if !f.accepted && !new.contains_key(&f.id) {
                    diff.resolved_findings.push(f.clone());
                }
            }
        }
        let by_severity = |a: &Finding, b: &Finding| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.subject.cmp(&b.subject))
        };
        diff.new_findings.sort_by(by_severity);
        diff.resolved_findings.sort_by(by_severity);
        diff.changed_severity.sort_by(|a, b| {
            b.after
                .cmp(&a.after)
                .then(a.finding.subject.cmp(&b.finding.subject))
        });

        // ---------------------------------------------------------- advisories
        let old_adv: HashMap<&str, PatchState> = before
            .map(|b| {
                b.advisories
                    .iter()
                    .map(|a| (a.advisory.id.as_str(), a.state))
                    .collect()
            })
            .unwrap_or_default();
        for status in &after.advisories {
            let prev = old_adv.get(status.advisory.id.as_str()).copied();
            let change = || AdvisoryChange {
                id: status.advisory.id.clone(),
                title: status.advisory.title.clone(),
                severity: status.advisory.severity,
                score: status.advisory.score,
                state_before: prev,
                state_after: status.state,
                basis: status.basis.clone(),
                fixed_in: status
                    .advisory
                    .fixed_in
                    .iter()
                    .map(|v| v.to_string())
                    .collect(),
                reference: status.advisory.reference.clone(),
                published: status.advisory.published,
            };
            let now_vulnerable = status.state == PatchState::Vulnerable;
            let was_vulnerable = prev == Some(PatchState::Vulnerable);
            if now_vulnerable && !was_vulnerable {
                diff.new_advisories.push(change());
            } else if was_vulnerable && !now_vulnerable {
                diff.fixed_advisories.push(change());
            }
        }
        if let Some(b) = before {
            // Advisories that were vulnerable and disappeared (withdrawn).
            let current: std::collections::HashSet<&str> = after
                .advisories
                .iter()
                .map(|a| a.advisory.id.as_str())
                .collect();
            for status in &b.advisories {
                if status.state == PatchState::Vulnerable
                    && !current.contains(status.advisory.id.as_str())
                {
                    diff.fixed_advisories.push(AdvisoryChange {
                        id: status.advisory.id.clone(),
                        title: status.advisory.title.clone(),
                        severity: status.advisory.severity,
                        score: status.advisory.score,
                        state_before: Some(status.state),
                        state_after: PatchState::NotAffected,
                        basis: "Advisory nicht mehr in der Datenbank".into(),
                        fixed_in: Vec::new(),
                        reference: status.advisory.reference.clone(),
                        published: status.advisory.published,
                    });
                }
            }
        }
        diff.new_advisories
            .sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));

        // ----------------------------------------------------------- integrity
        if let Some(b) = before {
            diff.integrity_changes = integrity_changes(&b.integrity, &after.integrity);
        }

        diff.relevance = diff.compute_relevance();
        diff
    }

    fn compute_relevance(&self) -> Option<Severity> {
        let findings = self.new_findings.iter().map(|f| f.severity);
        let escalations = self
            .changed_severity
            .iter()
            .filter(|c| c.escalated())
            .map(|c| c.after);
        let advisories = self.new_advisories.iter().map(|a| a.severity);
        let integrity = self.integrity_changes.iter().filter_map(|c| c.worsened());
        let mut max = findings
            .chain(escalations)
            .chain(advisories)
            .chain(integrity)
            .max();
        if max.is_none() && self.has_changes() {
            max = Some(Severity::Info);
        }
        max
    }

    /// Anything worth mentioning changed (new/resolved findings, severity,
    /// advisories, significant integrity changes, version, verdict).
    pub fn has_changes(&self) -> bool {
        !self.new_findings.is_empty()
            || !self.resolved_findings.is_empty()
            || !self.changed_severity.is_empty()
            || !self.new_advisories.is_empty()
            || !self.fixed_advisories.is_empty()
            || self.integrity_changes.iter().any(|c| c.significant)
            || (!self.first_run && self.version_before != self.version_after)
            || (!self.first_run && self.verdict_before != Some(self.verdict_after))
    }

    /// Number of new findings with the given severity.
    pub fn new_count(&self, severity: Severity) -> usize {
        self.new_findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }

    /// One-line German headline, e.g. for an e-mail subject.
    pub fn headline(&self) -> String {
        let shop = self.shop_label();
        let crit = self.new_count(Severity::Critical)
            + self
                .new_advisories
                .iter()
                .filter(|a| a.severity == Severity::Critical)
                .count();
        let warn = self.new_count(Severity::Warning);
        if self.first_run {
            return format!("Erste Prüfung: {} – {shop}", self.verdict_after.label());
        }
        if crit > 0 {
            return format!(
                "{crit} neue{} kritische{} Befund{} – {shop}",
                if crit == 1 { "r" } else { "" },
                if crit == 1 { "r" } else { "" },
                if crit == 1 { "" } else { "e" }
            );
        }
        if !self.new_advisories.is_empty() {
            return format!(
                "{} neue Schwachstelle(n) betreffen den Shop – {shop}",
                self.new_advisories.len()
            );
        }
        if warn > 0 {
            return format!(
                "{warn} neue Warnung{} – {shop}",
                if warn == 1 { "" } else { "en" }
            );
        }
        if self.relevance.is_some() && self.has_changes() {
            if self.new_findings.is_empty()
                && self.changed_severity.is_empty()
                && !self.resolved_findings.is_empty()
            {
                return format!(
                    "{} Befund(e) nicht mehr vorhanden – {shop}",
                    self.resolved_findings.len()
                );
            }
            return format!("Änderungen seit dem letzten Scan – {shop}");
        }
        format!("Keine Änderungen seit dem letzten Scan – {shop}")
    }

    fn shop_label(&self) -> String {
        match &self.version_after {
            Some(v) => format!("{} {v} ({})", self.platform_name, self.target),
            None => format!("{} ({})", self.platform_name, self.target),
        }
    }

    /// Key facts as label/value pairs (German), for headers and card fields.
    pub fn facts(&self) -> Vec<(String, String)> {
        let mut v = vec![("Shop".to_string(), self.shop_label())];
        if !self.first_run && self.version_before != self.version_after {
            v.push((
                "Version".into(),
                format!(
                    "{} → {}",
                    self.version_before.as_deref().unwrap_or("unbekannt"),
                    self.version_after.as_deref().unwrap_or("unbekannt")
                ),
            ));
        }
        v.push((
            "Vergleich".into(),
            match self.before_generated_at {
                Some(b) => format!(
                    "{} → {}",
                    b.format("%d.%m.%Y %H:%M UTC"),
                    self.after_generated_at.format("%d.%m.%Y %H:%M UTC")
                ),
                None => format!(
                    "erster Scan ({})",
                    self.after_generated_at.format("%d.%m.%Y %H:%M UTC")
                ),
            },
        ));
        v.push((
            "Ergebnis".into(),
            match self.verdict_before {
                Some(b) if b != self.verdict_after => {
                    format!("{} → {}", b.label(), self.verdict_after.label())
                }
                _ => self.verdict_after.label().to_string(),
            },
        ));
        let s = &self.summary_after;
        v.push((
            "Befunde jetzt".into(),
            format!(
                "{} kritisch · {} Warnungen · {} Hinweise · {} unbedenklich",
                s.critical, s.warning, s.info, s.accepted
            ),
        ));
        v
    }

    /// The changes grouped into titled sections (German), most important
    /// first.  Empty sections are omitted; each section holds at most
    /// [`MAX_SECTION_LINES`] lines, `total` says how many there are.
    pub fn sections(&self) -> Vec<DiffSection> {
        let mut out = Vec::new();
        let finding_line = |f: &Finding| DiffLine {
            severity: Some(f.severity),
            text: format!("{}: {}", f.title, f.subject),
            detail: f.evidence.first().cloned(),
            id: Some(f.id.to_string()),
        };
        push_section(
            &mut out,
            if self.first_run {
                "Aktuelle Befunde"
            } else {
                "Neue Befunde"
            },
            self.new_findings.iter().map(finding_line).collect(),
        );
        push_section(
            &mut out,
            "Neu verwundbar (Advisories)",
            self.new_advisories
                .iter()
                .map(|a| DiffLine {
                    severity: Some(a.severity),
                    text: format!(
                        "{} – {}{}",
                        a.id,
                        a.title,
                        if a.fixed_in.is_empty() {
                            String::new()
                        } else {
                            format!(" (behoben in {})", a.fixed_in.join(", "))
                        }
                    ),
                    detail: a.reference.clone(),
                    id: None,
                })
                .collect(),
        );
        push_section(
            &mut out,
            "Schweregrad geändert",
            self.changed_severity
                .iter()
                .map(|c| DiffLine {
                    severity: Some(c.after),
                    text: format!(
                        "{} → {}: {}: {}",
                        c.before.label(),
                        c.after.label(),
                        c.finding.title,
                        c.finding.subject
                    ),
                    detail: None,
                    id: Some(c.finding.id.to_string()),
                })
                .collect(),
        );
        push_section(
            &mut out,
            "Shop-Integrität geändert",
            self.integrity_changes
                .iter()
                .filter(|c| c.significant)
                .map(|c| {
                    let text = match c.change {
                        IntegrityChangeKind::Added => format!(
                            "NEU {} · {}: {}",
                            c.section,
                            c.label,
                            c.value_after.as_deref().unwrap_or("")
                        ),
                        IntegrityChangeKind::Removed => format!(
                            "ENTFERNT {} · {} (war: {})",
                            c.section,
                            c.label,
                            c.value_before.as_deref().unwrap_or("")
                        ),
                        IntegrityChangeKind::Changed => {
                            let mut t = format!("{} · {}", c.section, c.label);
                            if c.value_before != c.value_after {
                                let _ = write!(
                                    t,
                                    ": {} → {}",
                                    c.value_before.as_deref().unwrap_or(""),
                                    c.value_after.as_deref().unwrap_or("")
                                );
                            }
                            if let (Some(b), Some(a)) = (c.status_before, c.status_after) {
                                if b != a {
                                    let _ =
                                        write!(t, " ({} → {})", status_label(b), status_label(a));
                                }
                            }
                            t
                        }
                    };
                    DiffLine {
                        severity: c.worsened(),
                        text,
                        detail: c.detail.clone(),
                        id: None,
                    }
                })
                .collect(),
        );
        push_section(
            &mut out,
            "Behobene Schwachstellen",
            self.fixed_advisories
                .iter()
                .map(|a| DiffLine {
                    severity: None,
                    text: format!("{} – {}", a.id, a.title),
                    detail: None,
                    id: None,
                })
                .collect(),
        );
        push_section(
            &mut out,
            "Nicht mehr gefunden",
            self.resolved_findings
                .iter()
                .map(|f| DiffLine {
                    severity: Some(f.severity),
                    text: format!("{}: {}", f.title, f.subject),
                    detail: None,
                    id: Some(f.id.to_string()),
                })
                .collect(),
        );
        out
    }

    /// Number of integrity rows whose value changed without a status change.
    pub fn minor_integrity_changes(&self) -> usize {
        self.integrity_changes
            .iter()
            .filter(|c| !c.significant)
            .count()
    }

    /// Plain-text summary (German).  Used by the CLI, e-mail and chat
    /// notifications.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "ecomsec – {}", self.headline());
        let _ = writeln!(out);
        for (k, v) in self.facts() {
            let _ = writeln!(out, "{:<14} {v}", format!("{k}:"));
        }
        let sections = self.sections();
        if sections.is_empty() {
            let _ = writeln!(out);
            if self.first_run {
                let _ = writeln!(out, "Keine aktiven Befunde.");
            } else {
                let _ = writeln!(out, "Keine Änderungen seit dem letzten Scan.");
            }
        }
        for s in &sections {
            let _ = writeln!(out);
            let _ = writeln!(out, "{} ({}):", s.title, s.total);
            for l in &s.lines {
                let badge = l
                    .severity
                    .map(|s| format!("[{}] ", s.label()))
                    .unwrap_or_default();
                let id =
                    l.id.as_deref()
                        .map(|i| format!("  #{i}"))
                        .unwrap_or_default();
                let _ = writeln!(out, "  {badge}{}{id}", l.text);
                if let Some(d) = &l.detail {
                    let _ = writeln!(out, "      {}", one_line(d, 160));
                }
            }
            if s.total > s.lines.len() {
                let _ = writeln!(out, "  … und {} weitere", s.total - s.lines.len());
            }
        }
        let minor = self.minor_integrity_changes();
        if minor > 0 {
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "{minor} weitere Integritätswerte ohne Statusänderung aktualisiert (z. B. letzter Login)."
            );
        }
        out
    }
}

/// A titled group of change lines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSection {
    pub title: String,
    pub total: usize,
    pub lines: Vec<DiffLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffLine {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

fn push_section(out: &mut Vec<DiffSection>, title: &str, lines: Vec<DiffLine>) {
    if lines.is_empty() {
        return;
    }
    let total = lines.len();
    out.push(DiffSection {
        title: title.to_string(),
        total,
        lines: lines.into_iter().take(MAX_SECTION_LINES).collect(),
    });
}

/// Collapse whitespace and cap the length (for evidence excerpts).
fn one_line(s: &str, max: usize) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        flat
    } else {
        let mut t: String = flat.chars().take(max - 1).collect();
        t.push('…');
        t
    }
}

fn integrity_changes(before: &[IntegrityItem], after: &[IntegrityItem]) -> Vec<IntegrityChange> {
    let old: BTreeMap<&str, &IntegrityItem> = before.iter().map(|i| (i.key.as_str(), i)).collect();
    let new: BTreeMap<&str, &IntegrityItem> = after.iter().map(|i| (i.key.as_str(), i)).collect();
    let mut out = Vec::new();
    for item in after {
        match old.get(item.key.as_str()) {
            None => out.push(IntegrityChange {
                key: item.key.clone(),
                section: item.section.clone(),
                label: item.label.clone(),
                change: IntegrityChangeKind::Added,
                status_before: None,
                status_after: Some(item.status),
                value_before: None,
                value_after: Some(item.value.clone()),
                detail: item.detail.clone(),
                significant: true,
            }),
            Some(prev) if prev.status != item.status || prev.value != item.value => {
                out.push(IntegrityChange {
                    key: item.key.clone(),
                    section: item.section.clone(),
                    label: item.label.clone(),
                    change: IntegrityChangeKind::Changed,
                    status_before: Some(prev.status),
                    status_after: Some(item.status),
                    value_before: Some(prev.value.clone()),
                    value_after: Some(item.value.clone()),
                    detail: item.detail.clone(),
                    significant: prev.status != item.status,
                })
            }
            _ => {}
        }
    }
    for item in before {
        if !new.contains_key(item.key.as_str()) {
            out.push(IntegrityChange {
                key: item.key.clone(),
                section: item.section.clone(),
                label: item.label.clone(),
                change: IntegrityChangeKind::Removed,
                status_before: Some(item.status),
                status_after: None,
                value_before: Some(item.value.clone()),
                value_after: None,
                detail: item.detail.clone(),
                significant: true,
            });
        }
    }
    out
}

/// Diff of the most recent report in `store` against the one before.
///
/// The newer side is the last saved report (with the current risk
/// acceptance applied); if that report is incomplete (time budget), the most
/// recent complete archived report is used instead.  Returns `None` when no
/// report exists at all; `first_run` is set when there is nothing to compare
/// with.
pub fn latest_from_store(store: &StateStore) -> Option<ReportDiff> {
    let last = store.last_report();
    let mut after = match last {
        Some(r) if r.summary.complete => r,
        other => store.latest_archived_report().or(other)?,
    };
    after.reapply_acceptance(&store.accepted());
    let before = store.previous_report(after.generated_at);
    Some(ReportDiff::compute(before.as_ref(), &after))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Category, Source};
    use crate::platform::{Advisory, AdvisoryStatus, PlatformInfo, PlatformKind};
    use crate::version::{Version, VersionRange};

    fn report(findings: Vec<Finding>) -> Report {
        let (verdict, summary) = Report::compute_summary(&findings);
        Report {
            schema_version: 1,
            generated_at: Utc::now(),
            platform: PlatformInfo {
                id: "jtl5".into(),
                name: "JTL-Shop 5".into(),
                kind: PlatformKind::SelfHosted,
                version: Some(Version::parse("5.3.1").unwrap()),
                root: Some("/var/www/shop".into()),
                target: None,
                details: vec![],
            },
            reference_date: NaiveDate::from_ymd_opt(2026, 6, 17).unwrap(),
            verdict,
            summary,
            findings,
            integrity: vec![],
            advisories: vec![],
            recommendations: vec![],
            limitations: vec![],
            score: None,
            grade: None,
            score_drivers: Vec::new(),
        }
    }

    fn finding(sev: Severity, subject: &str) -> Finding {
        Finding::new(
            sev,
            Category::SuspiciousPattern,
            Source::FileSystem,
            "rule_x",
            subject,
            format!("Befund {subject}"),
        )
    }

    fn advisory(id: &str, state: PatchState) -> AdvisoryStatus {
        AdvisoryStatus {
            advisory: Advisory {
                id: id.into(),
                title: "Test".into(),
                severity: Severity::Critical,
                score: Some(9.8),
                affected: vec![VersionRange::new(None, Some("9.0"))],
                fixed_in: vec![Version::parse("9.0").unwrap()],
                backpatch_note: None,
                reference: Some("https://example.org".into()),
                published: NaiveDate::from_ymd_opt(2026, 10, 1).unwrap(),
                tags: vec![],
                component: None,
            },
            state,
            basis: "Version 5.3.1".into(),
        }
    }

    #[test]
    fn identical_reports_have_no_changes() {
        let a = report(vec![finding(Severity::Warning, "a.php")]);
        let d = ReportDiff::compute(Some(&a), &a);
        assert!(!d.has_changes());
        assert_eq!(d.relevance, None);
        assert!(d.sections().is_empty());
        assert!(d.to_text().contains("Keine Änderungen"));
        assert!(d.headline().starts_with("Keine Änderungen"));
    }

    #[test]
    fn new_resolved_and_changed_findings() {
        let before = report(vec![
            finding(Severity::Warning, "a.php"),
            finding(Severity::Info, "b.php"),
        ]);
        let after = report(vec![
            finding(Severity::Critical, "b.php"),
            finding(Severity::Critical, "shell.php"),
            finding(Severity::Info, "c.php"),
        ]);
        let d = ReportDiff::compute(Some(&before), &after);
        let subjects: Vec<&str> = d.new_findings.iter().map(|f| f.subject.as_str()).collect();
        assert_eq!(subjects, vec!["shell.php", "c.php"]);
        assert_eq!(d.resolved_findings.len(), 1);
        assert_eq!(d.resolved_findings[0].subject, "a.php");
        assert_eq!(d.changed_severity.len(), 1);
        assert!(d.changed_severity[0].escalated());
        assert_eq!(d.relevance, Some(Severity::Critical));
        assert_eq!(d.verdict_before, Some(Verdict::Warning));
        assert_eq!(d.verdict_after, Verdict::Critical);
        let text = d.to_text();
        assert!(text.contains("Neue Befunde (2)"));
        assert!(text.contains("Nicht mehr gefunden (1)"));
        assert!(text.contains("INFO → KRITISCH"));
        assert!(d.headline().contains("neuer kritischer Befund"));
        // Serialisable round trip.
        let json = serde_json::to_string(&d).unwrap();
        let back: ReportDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(back.new_findings.len(), 2);
    }

    #[test]
    fn accepted_findings_are_not_new() {
        let before = report(vec![]);
        let mut f = finding(Severity::Critical, "x.php");
        f.accepted = true;
        let after = report(vec![f]);
        let d = ReportDiff::compute(Some(&before), &after);
        assert!(d.new_findings.is_empty());
        assert_eq!(d.relevance, None);
    }

    #[test]
    fn only_info_changes_have_info_relevance() {
        let before = report(vec![finding(Severity::Warning, "old.php")]);
        let after = report(vec![]);
        let d = ReportDiff::compute(Some(&before), &after);
        assert_eq!(d.relevance, Some(Severity::Info));
        assert!(d.headline().contains("nicht mehr vorhanden"));
    }

    #[test]
    fn newly_vulnerable_and_fixed_advisories() {
        let mut before = report(vec![]);
        before.advisories = vec![advisory("CVE-1", PatchState::Vulnerable)];
        let mut after = report(vec![]);
        after.advisories = vec![
            advisory("CVE-1", PatchState::Patched),
            advisory("CVE-2", PatchState::Vulnerable),
        ];
        let d = ReportDiff::compute(Some(&before), &after);
        assert_eq!(d.new_advisories.len(), 1);
        assert_eq!(d.new_advisories[0].id, "CVE-2");
        assert_eq!(d.new_advisories[0].state_before, None);
        assert_eq!(d.fixed_advisories.len(), 1);
        assert_eq!(d.relevance, Some(Severity::Critical));
        assert!(d.to_text().contains("CVE-2 – Test (behoben in 9.0)"));
    }

    #[test]
    fn integrity_changes_detect_status_value_added_removed() {
        let mut before = report(vec![]);
        before.integrity = vec![
            IntegrityItem::new(
                "payment.paypal.email",
                "Zahlung",
                "PayPal",
                IntegrityStatus::Ok,
                "a***@x.de",
            ),
            IntegrityItem::new(
                "admin.account.admin",
                "Admin-Konten",
                "admin",
                IntegrityStatus::Ok,
                "letzter Login: gestern",
            ),
            IntegrityItem::new("old", "Shop", "Alt", IntegrityStatus::Ok, "x"),
        ];
        let mut after = report(vec![]);
        after.integrity = vec![
            IntegrityItem::new(
                "payment.paypal.email",
                "Zahlung",
                "PayPal",
                IntegrityStatus::Critical,
                "e***@evil.example",
            ),
            IntegrityItem::new(
                "admin.account.admin",
                "Admin-Konten",
                "admin",
                IntegrityStatus::Ok,
                "letzter Login: heute",
            ),
            IntegrityItem::new(
                "admin.account.hacker",
                "Admin-Konten",
                "hacker",
                IntegrityStatus::Warning,
                "aktiv",
            ),
        ];
        let d = ReportDiff::compute(Some(&before), &after);
        assert_eq!(d.integrity_changes.len(), 4);
        let get = |k: &str| d.integrity_changes.iter().find(|c| c.key == k).unwrap();
        assert_eq!(
            get("payment.paypal.email").worsened(),
            Some(Severity::Critical)
        );
        assert!(!get("admin.account.admin").significant);
        assert_eq!(
            get("admin.account.hacker").change,
            IntegrityChangeKind::Added
        );
        assert_eq!(get("old").change, IntegrityChangeKind::Removed);
        assert_eq!(d.relevance, Some(Severity::Critical));
        assert_eq!(d.minor_integrity_changes(), 1);
        let text = d.to_text();
        assert!(text.contains("a***@x.de → e***@evil.example (OK → Kritisch)"));
        assert!(text.contains("NEU Admin-Konten · hacker"));
    }

    #[test]
    fn value_only_integrity_change_is_not_a_change() {
        let mut before = report(vec![]);
        before.integrity = vec![IntegrityItem::new(
            "admin.account.admin",
            "Admin-Konten",
            "admin",
            IntegrityStatus::Ok,
            "letzter Login: gestern",
        )];
        let mut after = before.clone();
        after.integrity[0].value = "letzter Login: heute".into();
        let d = ReportDiff::compute(Some(&before), &after);
        assert_eq!(d.integrity_changes.len(), 1);
        assert!(!d.has_changes());
        assert_eq!(d.relevance, None);
    }

    #[test]
    fn first_run_lists_active_findings() {
        let after = report(vec![finding(Severity::Warning, "a.php")]);
        let d = ReportDiff::compute(None, &after);
        assert!(d.first_run);
        assert_eq!(d.new_findings.len(), 1);
        assert_eq!(d.relevance, Some(Severity::Warning));
        assert!(d.headline().starts_with("Erste Prüfung"));
        assert!(d.to_text().contains("Aktuelle Befunde (1)"));
    }

    #[test]
    fn sections_are_capped() {
        let before = report(vec![]);
        let after = report(
            (0..30)
                .map(|i| finding(Severity::Warning, &format!("f{i:02}.php")))
                .collect(),
        );
        let d = ReportDiff::compute(Some(&before), &after);
        let s = &d.sections()[0];
        assert_eq!(s.total, 30);
        assert_eq!(s.lines.len(), MAX_SECTION_LINES);
        assert!(d.to_text().contains("… und 10 weitere"));
    }

    #[test]
    fn latest_from_store_uses_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path());
        assert!(latest_from_store(&store).is_none());
        let mut a = report(vec![finding(Severity::Warning, "a.php")]);
        a.generated_at = Utc::now() - chrono::Duration::hours(24);
        store.archive_report(&a).unwrap();
        store.save_last_report(&a).unwrap();
        let d = latest_from_store(&store).unwrap();
        assert!(d.first_run);
        let b = report(vec![
            finding(Severity::Warning, "a.php"),
            finding(Severity::Critical, "b.php"),
        ]);
        store.archive_report(&b).unwrap();
        store.save_last_report(&b).unwrap();
        let d = latest_from_store(&store).unwrap();
        assert!(!d.first_run);
        assert_eq!(d.new_findings.len(), 1);
        assert_eq!(d.new_findings[0].subject, "b.php");
        // Accepting the finding afterwards removes it from the diff.
        store
            .accept(d.new_findings[0].id.clone(), "b.php", None)
            .unwrap();
        let d = latest_from_store(&store).unwrap();
        assert!(d.new_findings.is_empty());
    }
}
