pub mod html;
pub mod junit;
pub mod markdown;
pub mod sarif;
pub mod sbom;
pub mod text;

use ecomsec_core::Report;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
    Html,
    /// SARIF 2.1.0 (GitHub Code Scanning, GitLab, DefectDojo …)
    Sarif,
    /// JUnit-XML (ein Testfall pro Befund-Kategorie)
    Junit,
    /// Kompakter Markdown-Bericht (PR-/MR-Kommentar)
    Markdown,
}

pub fn render(
    report: &Report,
    format: Format,
    show_all: bool,
    color: bool,
) -> anyhow::Result<String> {
    Ok(match format {
        Format::Text => text::render(report, show_all, color),
        Format::Json => serde_json::to_string_pretty(report)?,
        Format::Html => html::render_static(report)?,
        Format::Sarif => sarif::render(report)?,
        Format::Junit => junit::render(report),
        Format::Markdown => markdown::render(report, show_all),
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    use chrono::{NaiveDate, TimeZone, Utc};
    use ecomsec_core::finding::{Category, Finding, Severity, Source};
    use ecomsec_core::platform::{
        Advisory, AdvisoryStatus, IntegrityItem, IntegrityStatus, PatchState, PlatformInfo,
        PlatformKind,
    };
    use ecomsec_core::report::SCHEMA_VERSION;
    use ecomsec_core::{Report, Version};
    use std::path::Path;

    /// A small, deterministic report covering file, database, advisory,
    /// dependency and accepted findings.
    pub fn sample_report() -> Report {
        let root = Path::new("/var/www/shop");
        let mut dump = Finding::file(
            Severity::Warning,
            Category::ExposedFile,
            "exposed_file",
            root,
            &root.join("backup.sql"),
            "Datenbank-Dump im Webroot",
        );
        dump.accepted = true;
        dump.accepted_reason = Some("Testdump".into());
        let findings = vec![
            Finding::file(
                Severity::Critical,
                Category::KnownWebshell,
                "ioc_filename",
                root,
                &root.join("mediafiles/wso.php"),
                "Bekannter Webshell-Dateiname: wso.php",
            )
            .with_description("Dateiname steht auf der IOC-Liste.")
            .with_evidence("WSO"),
            Finding::new(
                Severity::Critical,
                Category::PatchStatus,
                Source::Configuration,
                "advisory_cve-2026-54390",
                "5.3.1",
                "Shop ist verwundbar: CVE-2026-54390",
            ),
            Finding::new(
                Severity::Info,
                Category::AdminAccount,
                Source::Database,
                "admin_without_2fa",
                "tadminlogin:admin",
                "Admin-Konto ohne Zwei-Faktor-Authentifizierung: admin",
            ),
            Finding::new(
                Severity::Warning,
                Category::PatchStatus,
                Source::Configuration,
                "osv_ghsa-xxxx",
                "composer:smarty/smarty@4.3.0",
                "Verwundbare Abhängigkeit: smarty/smarty 4.3.0",
            ),
            dump,
        ];
        let (verdict, mut summary) = Report::compute_summary(&findings);
        summary.files_scanned = 42;
        summary.duration_ms = 1234;
        let advisory = Advisory {
            id: "CVE-2026-54390".into(),
            title: "Smarty-SSTI in Mailvorlagen".into(),
            severity: Severity::Critical,
            score: None,
            affected: vec![],
            fixed_in: vec![],
            backpatch_note: None,
            reference: None,
            published: NaiveDate::from_ymd_opt(2026, 6, 17).unwrap(),
            tags: vec![],
        };
        let mut report = Report {
            schema_version: SCHEMA_VERSION,
            generated_at: Utc.with_ymd_and_hms(2026, 10, 13, 12, 0, 0).unwrap(),
            platform: PlatformInfo {
                id: "jtl5".into(),
                name: "JTL-Shop 5".into(),
                kind: PlatformKind::SelfHosted,
                version: Version::parse("5.3.1"),
                root: Some(root.to_path_buf()),
                target: None,
                details: vec![],
            },
            reference_date: NaiveDate::from_ymd_opt(2026, 6, 17).unwrap(),
            verdict,
            summary,
            findings,
            integrity: vec![IntegrityItem::new(
                "admin.account.admin",
                "Admin-Konten",
                "admin",
                IntegrityStatus::Warning,
                "aktiv · 2FA: nein · letzter Login: nie",
            )],
            advisories: vec![AdvisoryStatus {
                advisory,
                state: PatchState::Vulnerable,
                basis: "Version 5.3.1 liegt im betroffenen Bereich.".into(),
            }],
            recommendations: vec![],
            limitations: vec!["Datenbank-Prüfungen übersprungen (--skip-remote).".into()],
            score: None,
            grade: None,
            score_drivers: vec![],
        };
        report.apply_score();
        report
    }
}
