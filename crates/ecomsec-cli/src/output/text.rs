//! Terminal report renderer (German, ANSI colours).

use ecomsec_core::platform::{IntegrityStatus, PatchState};
use ecomsec_core::{Report, Severity, Verdict};
use std::fmt::Write;

struct Style {
    color: bool,
}

impl Style {
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    fn red(&self, s: &str) -> String {
        self.wrap("31;1", s)
    }
    fn yellow(&self, s: &str) -> String {
        self.wrap("33;1", s)
    }
    fn green(&self, s: &str) -> String {
        self.wrap("32;1", s)
    }
    fn blue(&self, s: &str) -> String {
        self.wrap("34", s)
    }
    fn severity(&self, sev: Severity) -> String {
        match sev {
            Severity::Critical => self.red("KRITISCH"),
            Severity::Warning => self.yellow("WARNUNG "),
            Severity::Info => self.blue("INFO    "),
        }
    }
    fn status(&self, st: IntegrityStatus) -> String {
        match st {
            IntegrityStatus::Ok => self.green("✔"),
            IntegrityStatus::Warning => self.yellow("!"),
            IntegrityStatus::Critical => self.red("✖"),
            IntegrityStatus::Unknown => self.dim("?"),
        }
    }
}

pub fn render(report: &Report, show_all: bool, color: bool) -> String {
    let st = Style { color };
    let mut out = String::new();
    let line = "─".repeat(78);

    // ---------------------------------------------------------------- banner
    let banner = match report.verdict {
        Verdict::Critical => st.red(&format!("■ {}", report.verdict.label())),
        Verdict::Warning => st.yellow(&format!("■ {}", report.verdict.label())),
        Verdict::Clean => st.green(&format!("■ {}", report.verdict.label())),
    };
    let _ = writeln!(out, "{line}");
    let _ = writeln!(
        out,
        "{} – ecomsec Security Scan",
        st.bold(&report.platform.name)
    );
    let _ = writeln!(out, "{line}");
    let _ = writeln!(out, "{banner}");
    if !report.summary.complete {
        let _ = writeln!(
            out,
            "{}",
            st.yellow("   (Scan unvollständig – Zeitbudget erschöpft, bitte erneut starten)")
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Ziel:            {}",
        report
            .platform
            .root
            .as_ref()
            .map(|p| p.display().to_string())
            .or_else(|| report.platform.target.clone())
            .unwrap_or_default()
    );
    let _ = writeln!(
        out,
        "Version:         {}",
        report
            .platform
            .version
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unbekannt".into())
    );
    for (k, v) in &report.platform.details {
        let _ = writeln!(out, "{:<17}{}", format!("{k}:"), v);
    }
    let _ = writeln!(
        out,
        "Referenzdatum:   {}",
        report.reference_date.format("%d.%m.%Y")
    );
    let _ = writeln!(
        out,
        "Scan-Zeitpunkt:  {}",
        report.generated_at.format("%d.%m.%Y %H:%M:%S UTC")
    );
    let _ = writeln!(
        out,
        "Umfang:          {} Dateien, {} gelesen, {:.1}s",
        report.summary.files_scanned,
        ecomsec_core::util::human_size(report.summary.bytes_scanned),
        report.summary.duration_ms as f64 / 1000.0
    );
    let _ = writeln!(
        out,
        "Befunde:         {} kritisch · {} Warnungen · {} Hinweise · {} als unbedenklich markiert",
        st.red(&report.summary.critical.to_string()),
        st.yellow(&report.summary.warning.to_string()),
        report.summary.info,
        report.summary.accepted
    );

    // ---------------------------------------------------------------- findings
    let _ = writeln!(
        out,
        "\n{line}\n{}\n{line}",
        st.bold("SECURITY SCAN – BEFUNDE")
    );
    let findings = report.sorted_findings();
    let visible: Vec<_> = findings
        .iter()
        .filter(|f| show_all || (!f.accepted && f.severity != Severity::Info))
        .collect();
    if visible.is_empty() {
        let _ = writeln!(out, "{}", st.green("Keine Befunde."));
    }
    for f in &visible {
        let _ = writeln!(
            out,
            "\n[{}] {} {}{}",
            st.severity(f.severity),
            st.bold(&f.title),
            st.dim(&format!("#{}", f.id)),
            if f.accepted {
                st.dim("  (unbedenklich)")
            } else {
                String::new()
            }
        );
        let _ = writeln!(out, "    {} · {}", f.category, f.subject);
        if !f.description.is_empty() {
            for l in wrap(&f.description, 90) {
                let _ = writeln!(out, "    {}", st.dim(&l));
            }
        }
        for e in &f.evidence {
            let _ = writeln!(out, "    › {e}");
        }
        if let Some(r) = &f.accepted_reason {
            let _ = writeln!(out, "    Begründung: {r}");
        }
        if let Some(rv) = &f.review {
            let _ = writeln!(
                out,
                "    {} {}",
                st.blue(&format!(
                    "KI: {} ({:.0} %)",
                    rv.verdict.label(),
                    rv.confidence * 100.0
                )),
                st.dim(&ecomsec_core::util::excerpt(&rv.reasoning, 160))
            );
        }
    }
    let hidden = findings.len() - visible.len();
    if hidden > 0 {
        let _ = writeln!(
            out,
            "\n{}",
            st.dim(&format!(
                "({hidden} Hinweise/unbedenkliche Befunde ausgeblendet – mit --all anzeigen)"
            ))
        );
    }

    // ---------------------------------------------------------------- integrity
    let _ = writeln!(out, "\n{line}\n{}\n{line}", st.bold("SHOP-INTEGRITÄT"));
    let mut sections: Vec<&str> = Vec::new();
    for item in &report.integrity {
        if !sections.contains(&item.section.as_str()) {
            sections.push(&item.section);
        }
    }
    for section in sections {
        let _ = writeln!(out, "\n{}", st.bold(section));
        for item in report.integrity.iter().filter(|i| i.section == section) {
            let _ = writeln!(
                out,
                "  {} {:<44} {}",
                st.status(item.status),
                truncate(&item.label, 44),
                item.value
            );
            if let Some(d) = &item.detail {
                let _ = writeln!(out, "      {}", st.dim(d));
            }
        }
    }
    if !report.advisories.is_empty() {
        let _ = writeln!(out, "\n{}", st.bold("Bekannte Schwachstellen"));
        for a in &report.advisories {
            let state = match a.state {
                PatchState::Patched => st.green("gepatcht"),
                PatchState::NotAffected => st.green("nicht betroffen"),
                PatchState::Vulnerable => st.red("VERWUNDBAR"),
                PatchState::Unknown => st.yellow("unbekannt"),
            };
            let _ = writeln!(
                out,
                "  {:<16} {} – {}",
                a.advisory.id, state, a.advisory.title
            );
            let _ = writeln!(out, "      {}", st.dim(&a.basis));
        }
    }

    // ---------------------------------------------------------------- recommendations
    let _ = writeln!(
        out,
        "\n{line}\n{}\n{line}",
        st.bold("HANDLUNGSEMPFEHLUNGEN")
    );
    for group in &report.recommendations {
        let _ = writeln!(out, "\n{}", st.bold(&group.label));
        for (i, r) in group.items.iter().enumerate() {
            let _ = writeln!(
                out,
                "  {}. {} {}",
                i + 1,
                st.bold(&r.title),
                st.dim(&format!("(Priorität {})", r.priority))
            );
            for l in wrap(&r.detail, 88) {
                let _ = writeln!(out, "     {l}");
            }
            if !r.related.is_empty() {
                let ids: Vec<String> = r.related.iter().take(8).map(|i| format!("#{i}")).collect();
                let _ = writeln!(
                    out,
                    "     {}",
                    st.dim(&format!(
                        "Befunde: {}{}",
                        ids.join(" "),
                        if r.related.len() > 8 { " …" } else { "" }
                    ))
                );
            }
        }
    }

    // ---------------------------------------------------------------- limitations
    if !report.limitations.is_empty() {
        let _ = writeln!(out, "\n{line}\n{}\n{line}", st.bold("EINSCHRÄNKUNGEN"));
        for l in &report.limitations {
            let _ = writeln!(out, "  • {l}");
        }
    }
    let _ = writeln!(
        out,
        "\n{}",
        st.dim("Hinweis: Dieser Scan ist eine Triage-Hilfe und ersetzt keine forensische Analyse. Ein sauberes Ergebnis ist keine Garantie.")
    );
    out
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n - 1).collect();
        t.push('…');
        t
    }
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if cur.chars().count() + word.chars().count() + 1 > width && !cur.is_empty() {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}
