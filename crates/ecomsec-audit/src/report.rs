//! Audit result, merging into the scan report and the German text output.

use crate::client::Usage;
use crate::tools::{DataStats, VerdictRecord};
use chrono::{DateTime, Utc};
use ecomsec_core::finding::{Finding, Review, ReviewVerdict};
use ecomsec_core::report::Report;
use ecomsec_core::state::AcceptedFindings;
use serde::{Deserialize, Serialize};
use std::fmt::Write;

pub const AUDIT_SCHEMA_VERSION: u32 = 1;
/// File name of the most recent audit in the state directory.
pub const LAST_AUDIT_FILE: &str = "last-audit.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditMode {
    /// Review every critical/warning finding.
    Triage,
    /// Triage plus a review of custom code for vulnerabilities.
    Hunt,
}

impl AuditMode {
    pub fn label(self) -> &'static str {
        match self {
            AuditMode::Triage => "Triage",
            AuditMode::Hunt => "Hunt (Triage + Code-Review)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Completed,
    BudgetExceeded,
    MaxTurns,
    Refused,
    ApiError,
}

impl AuditStatus {
    pub fn label(self) -> &'static str {
        match self {
            AuditStatus::Completed => "abgeschlossen",
            AuditStatus::BudgetExceeded => "abgebrochen: Token-Budget erschöpft",
            AuditStatus::MaxTurns => "abgebrochen: maximale Rundenzahl erreicht",
            AuditStatus::Refused => "abgebrochen: Anfrage vom Modell abgelehnt",
            AuditStatus::ApiError => "abgebrochen: API-Fehler",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextStep {
    pub priority: u8,
    pub action: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub schema_version: u32,
    pub model: String,
    pub mode: AuditMode,
    pub started: DateTime<Utc>,
    pub finished: DateTime<Utc>,
    /// Scan report the audit was based on.
    pub report_generated_at: DateTime<Utc>,
    pub platform: String,
    pub status: AuditStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abort_reason: Option<String>,
    pub turns: u32,
    /// All input tokens processed (uncached + cache write + cache read).
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub usage: Usage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_cost_usd: Option<f64>,
    pub verdicts: Vec<VerdictRecord>,
    pub new_findings: Vec<Finding>,
    /// Critical/warning findings the model did not assess.
    #[serde(default)]
    pub unreviewed: Vec<String>,
    /// `kompromittiert`, `wahrscheinlich_kompromittiert`, `unklar`,
    /// `wahrscheinlich_sauber`, `sauber` (as stated by the model).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overall_assessment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    pub summary: String,
    pub next_steps: Vec<NextStep>,
    /// Transparency: what was sent to the API.
    pub data: DataStats,
}

impl AuditReport {
    /// `audit-<timestamp>.json`
    pub fn file_name(&self) -> String {
        format!("audit-{}.json", self.started.format("%Y%m%dT%H%M%SZ"))
    }

    pub fn is_complete(&self) -> bool {
        self.status == AuditStatus::Completed
    }
}

/// Merge verdicts (as `Finding::review`) and new findings into the scan
/// report.  Risk acceptance is re-applied so that summary and verdict stay
/// consistent.  Returns the number of findings that received a review.
pub fn merge_into_report(
    audit: &AuditReport,
    report: &mut Report,
    accepted: &AcceptedFindings,
) -> usize {
    let mut merged = 0;
    for v in &audit.verdicts {
        if let Some(f) = report
            .findings
            .iter_mut()
            .find(|f| f.id.as_str() == v.finding_id)
        {
            f.review = Some(Review {
                verdict: v.verdict,
                confidence: v.confidence,
                reasoning: v.reasoning.clone(),
                model: audit.model.clone(),
                reviewed_at: Some(audit.finished),
            });
            merged += 1;
        }
    }
    for nf in &audit.new_findings {
        match report.findings.iter_mut().find(|f| f.id == nf.id) {
            Some(existing) => *existing = nf.clone(),
            None => report.findings.push(nf.clone()),
        }
    }
    report.reapply_acceptance(accepted);
    merged
}

fn percent(c: f32) -> String {
    format!("{:.0} %", c * 100.0)
}

/// Amount with German decimal comma (`0,35`).
pub fn format_usd(amount: f64) -> String {
    format!("{amount:.2}").replace('.', ",")
}

/// German text rendering.
pub fn render_text(a: &AuditReport) -> String {
    let mut out = String::new();
    let line = "─".repeat(78);
    let _ = writeln!(out, "{line}\nKI-AUDIT – {}\n{line}", a.mode.label());
    let _ = writeln!(out, "Plattform:       {}", a.platform);
    let _ = writeln!(out, "Modell:          {}", a.model);
    let _ = writeln!(
        out,
        "Zeitraum:        {} – {} ({} Runden, {} Werkzeugaufrufe)",
        a.started.format("%d.%m.%Y %H:%M:%S"),
        a.finished.format("%H:%M:%S UTC"),
        a.turns,
        a.data.tool_calls
    );
    let _ = writeln!(
        out,
        "Bezug:           Scan-Report vom {}",
        a.report_generated_at.format("%d.%m.%Y %H:%M UTC")
    );
    let _ = writeln!(
        out,
        "Tokens:          {} Eingabe (davon {} aus Cache) · {} Ausgabe{}",
        a.tokens_in,
        a.usage.cache_read_input_tokens,
        a.tokens_out,
        a.estimated_cost_usd
            .map(|c| format!(" · geschätzte Kosten ca. {} USD", format_usd(c)))
            .unwrap_or_else(|| " · Kostenschätzung für dieses Modell nicht verfügbar".into())
    );
    let _ = writeln!(out, "Status:          {}", a.status.label());
    if let Some(r) = &a.abort_reason {
        let _ = writeln!(out, "                 {r}");
    }

    let _ = writeln!(out, "\n{line}\nGESAMTBEWERTUNG\n{line}");
    if let Some(o) = &a.overall_assessment {
        let _ = writeln!(
            out,
            "{}{}",
            o.replace('_', " "),
            a.confidence
                .map(|c| format!(" (Konfidenz {})", percent(c)))
                .unwrap_or_default()
        );
    }
    if a.summary.trim().is_empty() {
        let _ = writeln!(out, "(keine Zusammenfassung)");
    } else {
        for l in a.summary.lines() {
            let _ = writeln!(out, "{l}");
        }
    }

    if !a.next_steps.is_empty() {
        let _ = writeln!(out, "\n{line}\nNÄCHSTE SCHRITTE\n{line}");
        let mut steps = a.next_steps.clone();
        steps.sort_by_key(|s| s.priority);
        for (i, s) in steps.iter().enumerate() {
            let _ = writeln!(out, "{}. [P{}] {}", i + 1, s.priority, s.action);
            if !s.rationale.is_empty() {
                let _ = writeln!(out, "      {}", s.rationale);
            }
        }
    }

    let _ = writeln!(
        out,
        "\n{line}\nBEWERTUNGEN DER BEFUNDE ({})\n{line}",
        a.verdicts.len()
    );
    for (verdict, title) in [
        (ReviewVerdict::Confirmed, "Bestätigt"),
        (ReviewVerdict::NeedsHuman, "Manuelle Prüfung nötig"),
        (
            ReviewVerdict::LikelyFalsePositive,
            "Wahrscheinlich Fehlalarm",
        ),
    ] {
        let list: Vec<&VerdictRecord> =
            a.verdicts.iter().filter(|v| v.verdict == verdict).collect();
        if list.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n{title} ({})", list.len());
        for v in list {
            let _ = writeln!(
                out,
                "  #{} {} – {} ({})",
                v.finding_id,
                v.subject,
                v.title,
                percent(v.confidence)
            );
            for l in v.reasoning.lines() {
                let _ = writeln!(out, "      {l}");
            }
        }
    }
    if !a.unreviewed.is_empty() {
        let _ = writeln!(
            out,
            "\nOhne Bewertung ({}): {}",
            a.unreviewed.len(),
            a.unreviewed
                .iter()
                .take(30)
                .map(|s| format!("#{s}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    if !a.new_findings.is_empty() {
        let _ = writeln!(
            out,
            "\n{line}\nNEUE BEFUNDE DES KI-AUDITS ({})\n{line}",
            a.new_findings.len()
        );
        for f in &a.new_findings {
            let _ = writeln!(
                out,
                "\n[{}] {} #{}\n    {} · {}",
                f.severity.label(),
                f.title,
                f.id,
                f.category,
                f.subject
            );
            for l in f.description.lines() {
                let _ = writeln!(out, "    {l}");
            }
            for e in &f.evidence {
                let _ = writeln!(out, "    › {e}");
            }
        }
    }

    let _ = writeln!(out, "\n{line}\nÜBERTRAGENE DATEN\n{line}");
    let _ = writeln!(
        out,
        "{} Werkzeugausgaben ({:.1} KiB, redigiert; {} Werte maskiert) · {} Dateien gelesen · {} Suchen · {} DB-Abfragen · {} OSV-Abfragen",
        a.data.tool_calls,
        a.data.bytes_sent as f64 / 1024.0,
        a.data.redactions,
        a.data.files_read.len(),
        a.data.greps,
        a.data.db_queries,
        a.data.osv_lookups
    );
    let _ = writeln!(
        out,
        "\nHinweis: Die KI-Bewertung ist eine Entscheidungshilfe und ersetzt keine forensische Analyse. Nichts löschen, bevor ein Befund verifiziert und gesichert ist."
    );
    out
}
