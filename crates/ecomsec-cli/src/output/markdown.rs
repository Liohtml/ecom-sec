//! Compact Markdown report for pull-request / merge-request comments and
//! chat notifications.

use ecomsec_core::platform::PatchState;
use ecomsec_core::{Report, Severity, Verdict};
use std::fmt::Write;

/// Maximum number of finding rows; the rest is summarised.
pub const MAX_ROWS: usize = 50;

/// Escape text for a Markdown table cell.
pub fn cell(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\r', "")
        .replace('\n', " ")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn code(s: &str) -> String {
    format!("`{}`", cell(s).replace('`', "'"))
}

pub fn render(report: &Report, show_all: bool) -> String {
    let mut out = String::new();
    let posture = report.posture();
    let icon = match report.verdict {
        Verdict::Critical => "🔴",
        Verdict::Warning => "🟡",
        Verdict::Clean => "🟢",
    };
    let _ = writeln!(out, "## {icon} ecomsec: {}\n", report.verdict.label());
    let _ = writeln!(
        out,
        "**{}{}** · Sicherheitsniveau **{}/100 (Note {})** · Scan {}{}\n",
        report.platform.name,
        report
            .platform
            .version
            .as_ref()
            .map(|v| format!(" {v}"))
            .unwrap_or_default(),
        posture.score,
        posture.grade,
        report.generated_at.format("%d.%m.%Y %H:%M UTC"),
        if report.summary.complete {
            ""
        } else {
            " · ⚠️ unvollständig"
        }
    );
    let _ = writeln!(
        out,
        "| kritisch | Warnungen | Hinweise | unbedenklich | Dateien |\n|---:|---:|---:|---:|---:|\n| {} | {} | {} | {} | {} |\n",
        report.summary.critical,
        report.summary.warning,
        report.summary.info,
        report.summary.accepted,
        report.summary.files_scanned
    );

    // ------------------------------------------------------------ findings
    let findings: Vec<_> = report
        .sorted_findings()
        .into_iter()
        .filter(|f| show_all || (!f.accepted && f.severity != Severity::Info))
        .collect();
    if findings.is_empty() {
        let _ = writeln!(out, "Keine offenen Befunde.\n");
    } else {
        let _ = writeln!(out, "### Befunde\n");
        let _ = writeln!(
            out,
            "| | Befund | Ort | Regel | ID |\n|---|---|---|---|---|"
        );
        for f in findings.iter().take(MAX_ROWS) {
            let sev = match f.severity {
                Severity::Critical => "🔴 kritisch",
                Severity::Warning => "🟡 Warnung",
                Severity::Info => "🔵 Hinweis",
            };
            let _ = writeln!(
                out,
                "| {}{} | {} | {} | {} | {} |",
                sev,
                if f.accepted { " (unbedenklich)" } else { "" },
                cell(&f.title),
                code(&f.subject),
                code(&f.rule),
                code(f.id.as_str())
            );
        }
        if findings.len() > MAX_ROWS {
            let _ = writeln!(
                out,
                "\n… und {} weitere Befunde (vollständig: `ecomsec report --format html`).",
                findings.len() - MAX_ROWS
            );
        }
        out.push('\n');
    }

    // ------------------------------------------------------------ advisories
    let relevant: Vec<_> = report
        .advisories
        .iter()
        .filter(|a| matches!(a.state, PatchState::Vulnerable | PatchState::Unknown))
        .collect();
    if !relevant.is_empty() {
        let _ = writeln!(
            out,
            "### Bekannte Schwachstellen\n\n| Advisory | Status | Bewertung |\n|---|---|---|"
        );
        for a in relevant {
            let _ = writeln!(
                out,
                "| {} | {} | {} |",
                cell(&a.advisory.id),
                match a.state {
                    PatchState::Vulnerable => "🔴 verwundbar",
                    _ => "🟡 unbekannt",
                },
                cell(&a.basis)
            );
        }
        out.push('\n');
    }

    // ------------------------------------------------------------ drivers
    if !posture.drivers.is_empty() {
        let _ = writeln!(
            out,
            "<details><summary>Score-Treiber</summary>\n\n| Faktor | Punkte |\n|---|---:|"
        );
        for d in &posture.drivers {
            let _ = writeln!(out, "| {} | −{} |", cell(&d.label), d.points);
        }
        let _ = writeln!(out, "\n</details>\n");
    }
    if !report.limitations.is_empty() {
        let _ = writeln!(out, "<details><summary>Einschränkungen</summary>\n");
        for l in &report.limitations {
            let _ = writeln!(out, "- {}", cell(l));
        }
        let _ = writeln!(out, "\n</details>\n");
    }
    let _ = writeln!(
        out,
        "<sub>ecomsec {} · read-only Kompromittierungs-Check · Triage-Hilfe, ersetzt keine forensische Analyse</sub>",
        env!("CARGO_PKG_VERSION")
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_support::sample_report;

    #[test]
    fn renders_summary_tables_and_escapes() {
        let mut report = sample_report();
        report.findings[0].title = "a|b\nc".into();
        let md = render(&report, false);
        assert!(md.starts_with("## 🔴 ecomsec: Kritische Befunde"));
        assert!(md.contains("| kritisch | Warnungen | Hinweise | unbedenklich | Dateien |"));
        assert!(md.contains("Sicherheitsniveau **"));
        assert!(md.contains("a\\|b c"));
        assert!(md.contains("`mediafiles/wso.php`"));
        // Accepted and info findings are hidden by default …
        assert!(!md.contains("`exposed_file`"));
        assert!(!md.contains("`admin_without_2fa`"));
        // … and shown with --all.
        let all = render(&report, true);
        assert!(all.contains("`exposed_file`"));
        assert!(all.contains("(unbedenklich)"));
        assert!(md.contains("### Bekannte Schwachstellen"));
        assert!(md.contains("Score-Treiber"));
        // Every table row has the same number of unescaped pipes as its header.
        for l in md
            .lines()
            .filter(|l| l.starts_with("| ") && l.contains("`"))
        {
            let pipes = l.replace("\\|", "").matches('|').count();
            assert_eq!(pipes, 6, "{l}");
        }
    }

    #[test]
    fn clean_report() {
        let mut report = sample_report();
        report.findings.clear();
        report.advisories.clear();
        let (v, s) = Report::compute_summary(&report.findings);
        report.verdict = v;
        report.summary = s;
        report.apply_score();
        let md = render(&report, false);
        assert!(md.starts_with("## 🟢"));
        assert!(md.contains("Keine offenen Befunde."));
    }
}
