//! JUnit XML export for CI dashboards (GitLab, Jenkins, Azure DevOps …).
//!
//! One test case per finding category.  A category fails when it has open
//! (non-accepted) critical or warning findings; info-only and accepted
//! findings pass and are listed in `system-out`.

use super::sarif::category_key;
use ecomsec_core::finding::{Category, Finding, Severity};
use ecomsec_core::Report;
use std::fmt::Write;

/// All categories in display order – every one becomes a test case, so CI
/// dashboards also show what passed.
pub const CATEGORIES: &[Category] = &[
    Category::KnownWebshell,
    Category::ExploitPayload,
    Category::CodeInUploadDir,
    Category::WebserverConfigManipulation,
    Category::SuspiciousPattern,
    Category::ModifiedSinceReference,
    Category::TimestampAnomaly,
    Category::AttackTrace,
    Category::PatchStatus,
    Category::AdminAccount,
    Category::PaymentConfiguration,
    Category::ConfigPermissions,
    Category::ExposedFile,
    Category::IntegrityDeviation,
    Category::ThirdPartyInjection,
    Category::ScanLimitation,
    Category::Informational,
];

pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Control characters are not allowed in XML 1.0.
            c if (c as u32) < 0x20 && !matches!(c, '\n' | '\r' | '\t') => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

fn line(f: &Finding) -> String {
    format!(
        "[{}] {} – {} (#{}{})",
        f.severity.label(),
        f.subject,
        f.title,
        f.id,
        if f.accepted { ", unbedenklich" } else { "" }
    )
}

pub fn render(report: &Report) -> String {
    let mut categories: Vec<Category> = CATEGORIES.to_vec();
    for f in &report.findings {
        if !categories.contains(&f.category) {
            categories.push(f.category);
        }
    }
    let suite = format!("ecomsec.{}", report.platform.id);
    let time = report.summary.duration_ms as f64 / 1000.0;
    let mut cases = String::new();
    let mut failures = 0usize;
    for cat in &categories {
        let all: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.category == *cat)
            .collect();
        let failing: Vec<&&Finding> = all
            .iter()
            .filter(|f| !f.accepted && f.severity >= Severity::Warning)
            .collect();
        let _ = writeln!(
            cases,
            "    <testcase classname=\"{}\" name=\"{}\" time=\"0\">",
            xml_escape(&format!("{suite}.{}", category_key(*cat))),
            xml_escape(cat.label())
        );
        if !failing.is_empty() {
            failures += 1;
            let crit = failing
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .count();
            let warn = failing.len() - crit;
            let kind = if crit > 0 { "critical" } else { "warning" };
            let message = format!("{crit} kritisch, {warn} Warnungen");
            let body: Vec<String> = failing.iter().map(|f| line(f)).collect();
            let _ = writeln!(
                cases,
                "      <failure type=\"{kind}\" message=\"{}\">{}</failure>",
                xml_escape(&message),
                xml_escape(&body.join("\n"))
            );
        }
        let rest: Vec<String> = all
            .iter()
            .filter(|f| f.accepted || f.severity == Severity::Info)
            .map(|f| line(f))
            .collect();
        if !rest.is_empty() {
            let _ = writeln!(
                cases,
                "      <system-out>{}</system-out>",
                xml_escape(&rest.join("\n"))
            );
        }
        cases.push_str("    </testcase>\n");
    }
    let posture = report.posture();
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = write!(
        out,
        "<testsuites name=\"ecomsec\" tests=\"{n}\" failures=\"{failures}\" errors=\"0\" time=\"{time:.3}\">\n  <testsuite name=\"{}\" tests=\"{n}\" failures=\"{failures}\" errors=\"0\" skipped=\"0\" time=\"{time:.3}\" timestamp=\"{}\">\n",
        xml_escape(&suite),
        report.generated_at.format("%Y-%m-%dT%H:%M:%S"),
        n = categories.len(),
    );
    let _ = write!(
        out,
        "    <properties>\n      <property name=\"verdict\" value=\"{}\"/>\n      <property name=\"score\" value=\"{}\"/>\n      <property name=\"grade\" value=\"{}\"/>\n      <property name=\"platform\" value=\"{}\"/>\n      <property name=\"version\" value=\"{}\"/>\n    </properties>\n",
        xml_escape(report.verdict.label()),
        posture.score,
        posture.grade,
        xml_escape(&report.platform.name),
        xml_escape(
            &report
                .platform
                .version
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or_default()
        ),
    );
    out.push_str(&cases);
    out.push_str("  </testsuite>\n</testsuites>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_support::sample_report;

    fn testcase<'a>(xml: &'a str, name: &str) -> &'a str {
        let start = xml
            .find(&format!("name=\"{name}\""))
            .unwrap_or_else(|| panic!("testcase {name}"));
        let end = start + xml[start..].find("</testcase>").unwrap();
        &xml[start..end]
    }

    #[test]
    fn one_testcase_per_category_with_failures() {
        let report = sample_report();
        let xml = render(&report);
        assert!(xml.starts_with("<?xml"));
        assert_eq!(xml.matches("<testcase ").count(), CATEGORIES.len());
        assert_eq!(
            xml.matches("<testcase ").count(),
            xml.matches("</testcase>").count()
        );
        // Webshell (critical) and patch status (critical advisory) fail.
        assert!(testcase(&xml, "Bekannte Webshell").contains("<failure type=\"critical\""));
        assert!(testcase(&xml, "Patch-Status").contains("<failure"));
        // Accepted dump → passes, but is listed.
        let exposed = testcase(&xml, "Öffentlich erreichbare Datei");
        assert!(!exposed.contains("<failure"));
        assert!(exposed.contains("unbedenklich"));
        // Info only → passes.
        assert!(!testcase(&xml, "Admin-Konto").contains("<failure"));
        let failures = xml.matches("<failure ").count();
        assert!(xml.contains(&format!("failures=\"{failures}\"")));
        assert!(xml.contains("<property name=\"grade\""));
    }

    #[test]
    fn escapes_xml() {
        assert_eq!(xml_escape("a<b>&\"'\u{1}"), "a&lt;b&gt;&amp;&quot;&apos; ");
    }
}
