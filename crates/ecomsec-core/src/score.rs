//! Security posture score: a deterministic 0–100 rating of a report plus a
//! letter grade (A–F) and the three largest score drivers.
//!
//! The score starts at 100 and every factor subtracts a capped number of
//! points.  All weights are constants below so the rating is reproducible
//! and documented in one place:
//!
//! | Factor | Penalty | Cap |
//! |---|---|---|
//! | open critical findings (except patch status / permissions) | 12 each | 48 |
//! | open warnings (except patch status / permissions) | 2 each | 16 |
//! | vulnerable shop version (advisory) | 15 each | 30 |
//! | advisory with unknown patch status | 4 each | 8 |
//! | vulnerable Composer dependency (OSV) | 3 critical / 1 other | 12 |
//! | admin accounts without 2FA | 10 × share without 2FA | 10 |
//! | config files with open permissions | 6 critical / 3 warning | 9 |
//! | no integrity baseline | 5 | 5 |
//! | scan incomplete (time budget) | 8 | 8 |
//! | skipped / limited checks | 1 each | 4 |
//!
//! Afterwards the verdict caps the score: with open critical findings it is
//! at most 49 (grade D or worse), with open warnings at most 89 (grade B or
//! worse).  Accepted findings never count.
//!
//! Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40.

use crate::finding::{Category, Severity};
use crate::platform::IntegrityStatus;
use crate::report::{Report, Verdict};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const CRITICAL_EACH: u32 = 12;
pub const CRITICAL_CAP: u32 = 48;
pub const WARNING_EACH: u32 = 2;
pub const WARNING_CAP: u32 = 16;
pub const ADVISORY_VULNERABLE_EACH: u32 = 15;
pub const ADVISORY_VULNERABLE_CAP: u32 = 30;
pub const ADVISORY_UNKNOWN_EACH: u32 = 4;
pub const ADVISORY_UNKNOWN_CAP: u32 = 8;
pub const DEPENDENCY_CRITICAL_EACH: u32 = 3;
pub const DEPENDENCY_OTHER_EACH: u32 = 1;
pub const DEPENDENCY_CAP: u32 = 12;
pub const TWO_FA_MAX: u32 = 10;
pub const PERMISSION_CRITICAL_EACH: u32 = 6;
pub const PERMISSION_WARNING_EACH: u32 = 3;
pub const PERMISSION_CAP: u32 = 9;
pub const NO_BASELINE: u32 = 5;
pub const INCOMPLETE: u32 = 8;
pub const LIMITATION_EACH: u32 = 1;
pub const LIMITATION_CAP: u32 = 4;
/// Highest possible score while critical findings are open.
pub const CRITICAL_CEILING: u32 = 49;
/// Highest possible score while warnings are open.
pub const WARNING_CEILING: u32 = 89;

/// Letter grade derived from the score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

impl Grade {
    pub fn from_score(score: u8) -> Grade {
        match score {
            90..=u8::MAX => Grade::A,
            75..=89 => Grade::B,
            60..=74 => Grade::C,
            40..=59 => Grade::D,
            _ => Grade::F,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Grade::A => "A",
            Grade::B => "B",
            Grade::C => "C",
            Grade::D => "D",
            Grade::F => "F",
        }
    }

    /// Short German description of the grade.
    pub fn label(self) -> &'static str {
        match self {
            Grade::A => "sehr gut",
            Grade::B => "gut",
            Grade::C => "befriedigend",
            Grade::D => "mangelhaft",
            Grade::F => "ungenügend",
        }
    }
}

impl fmt::Display for Grade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One factor that lowered the score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreDriver {
    /// Stable machine key (`critical_findings`, `admin_2fa`, …).
    pub key: String,
    /// German explanation, e.g. "2 kritische Befunde".
    pub label: String,
    /// Points subtracted from 100.
    pub points: u32,
}

/// Result of [`compute`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostureScore {
    pub score: u8,
    pub grade: Grade,
    /// All factors with a penalty, largest first.
    pub drivers: Vec<ScoreDriver>,
}

impl PostureScore {
    /// The three largest drivers.
    pub fn top_drivers(&self) -> &[ScoreDriver] {
        &self.drivers[..self.drivers.len().min(3)]
    }
}

fn capped(n: usize, each: u32, cap: u32) -> u32 {
    (n as u32).saturating_mul(each).min(cap)
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Parse the 2FA state out of an admin-account integrity value
/// (`aktiv · 2FA: ja · …`).  Inactive accounts and unknown states are skipped.
fn two_fa_state(value: &str) -> Option<bool> {
    if value.starts_with("inaktiv") {
        return None;
    }
    let rest = value.split("2FA:").nth(1)?.trim_start();
    if rest.starts_with("ja") {
        Some(true)
    } else if rest.starts_with("nein") {
        Some(false)
    } else {
        None
    }
}

/// Compute the posture score of a report.
pub fn compute(report: &Report) -> PostureScore {
    let mut drivers: Vec<ScoreDriver> = Vec::new();
    let mut push = |key: &str, label: String, points: u32| {
        if points > 0 {
            drivers.push(ScoreDriver {
                key: key.to_string(),
                label,
                points,
            });
        }
    };

    // ------------------------------------------------------------ findings
    let open = || report.findings.iter().filter(|f| !f.accepted);
    let is_dependency = |rule: &str| rule.starts_with("osv_");
    let is_advisory = |rule: &str| rule.starts_with("advisory_");
    let generic = || {
        open().filter(|f| {
            // Patch status and file permissions have their own factors.
            !matches!(
                f.category,
                Category::PatchStatus | Category::ConfigPermissions
            ) && !is_dependency(&f.rule)
                && !is_advisory(&f.rule)
        })
    };
    let critical = generic()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let warnings = generic()
        .filter(|f| f.severity == Severity::Warning)
        .count();
    push(
        "critical_findings",
        plural(critical, "kritischer Befund", "kritische Befunde"),
        capped(critical, CRITICAL_EACH, CRITICAL_CAP),
    );
    push(
        "warnings",
        plural(warnings, "Warnung", "Warnungen"),
        capped(warnings, WARNING_EACH, WARNING_CAP),
    );

    // ------------------------------------------------------------ advisories
    let (mut vulnerable, mut unknown) = (Vec::new(), 0usize);
    for f in open().filter(|f| is_advisory(&f.rule)) {
        if f.rule.ends_with("_unknown") {
            unknown += 1;
        } else {
            vulnerable.push(
                f.rule
                    .trim_start_matches("advisory_")
                    .to_ascii_uppercase()
                    .to_string(),
            );
        }
    }
    push(
        "advisories_vulnerable",
        format!(
            "Shop-Version verwundbar ({})",
            vulnerable
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ),
        capped(
            vulnerable.len(),
            ADVISORY_VULNERABLE_EACH,
            ADVISORY_VULNERABLE_CAP,
        ),
    );
    push(
        "advisories_unknown",
        format!(
            "Patch-Status für {} nicht ermittelbar",
            plural(unknown, "Schwachstelle", "Schwachstellen")
        ),
        capped(unknown, ADVISORY_UNKNOWN_EACH, ADVISORY_UNKNOWN_CAP),
    );

    // ------------------------------------------------------------ dependencies
    let (mut dep_points, mut dep_count) = (0u32, 0usize);
    for f in open().filter(|f| is_dependency(&f.rule)) {
        dep_count += 1;
        dep_points += if f.severity == Severity::Critical {
            DEPENDENCY_CRITICAL_EACH
        } else {
            DEPENDENCY_OTHER_EACH
        };
    }
    push(
        "dependencies",
        format!(
            "{} in Composer-Abhängigkeiten",
            plural(
                dep_count,
                "bekannte Schwachstelle",
                "bekannte Schwachstellen"
            )
        ),
        dep_points.min(DEPENDENCY_CAP),
    );

    // ------------------------------------------------------------ integrity
    let (mut with_2fa, mut without_2fa) = (0usize, 0usize);
    let (mut perm_points, mut perm_count) = (0u32, 0usize);
    let mut baseline_missing = false;
    for item in &report.integrity {
        if item.key.starts_with("admin.account.") {
            match two_fa_state(&item.value) {
                Some(true) => with_2fa += 1,
                Some(false) => without_2fa += 1,
                None => {}
            }
        } else if item.key.starts_with("perm.") {
            let p = match item.status {
                IntegrityStatus::Critical => PERMISSION_CRITICAL_EACH,
                IntegrityStatus::Warning => PERMISSION_WARNING_EACH,
                _ => 0,
            };
            if p > 0 {
                perm_count += 1;
                perm_points += p;
            }
        } else if item.key == "integrity.baseline" && item.status == IntegrityStatus::Unknown {
            baseline_missing = true;
        }
    }
    let known = with_2fa + without_2fa;
    if known > 0 {
        let share = without_2fa as f64 / known as f64;
        push(
            "admin_2fa",
            format!("{without_2fa} von {known} aktiven Admin-Konten ohne 2FA"),
            (share * TWO_FA_MAX as f64).round() as u32,
        );
    }
    push(
        "config_permissions",
        format!(
            "{} mit zu offenen Dateirechten",
            plural(perm_count, "Konfigurationsdatei", "Konfigurationsdateien")
        ),
        perm_points.min(PERMISSION_CAP),
    );
    push(
        "baseline_missing",
        "Keine Integritäts-Baseline angelegt".to_string(),
        if baseline_missing { NO_BASELINE } else { 0 },
    );

    // ------------------------------------------------------------ completeness
    push(
        "scan_incomplete",
        "Scan unvollständig (Zeitbudget erschöpft)".to_string(),
        if report.summary.complete {
            0
        } else {
            INCOMPLETE
        },
    );
    let limitations = report.limitations.len();
    push(
        "limitations",
        format!(
            "{} übersprungen oder eingeschränkt",
            plural(limitations, "Prüfung", "Prüfungen")
        ),
        capped(limitations, LIMITATION_EACH, LIMITATION_CAP),
    );

    // ------------------------------------------------------------ total
    let penalty: u32 = drivers.iter().map(|d| d.points).sum();
    let mut score = 100u32.saturating_sub(penalty);
    match report.verdict {
        Verdict::Critical => score = score.min(CRITICAL_CEILING),
        Verdict::Warning => score = score.min(WARNING_CEILING),
        Verdict::Clean => {}
    }
    drivers.sort_by(|a, b| b.points.cmp(&a.points).then(a.key.cmp(&b.key)));
    let score = score as u8;
    PostureScore {
        score,
        grade: Grade::from_score(score),
        drivers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Source};
    use crate::platform::{IntegrityItem, PlatformInfo, PlatformKind};
    use crate::report::SCHEMA_VERSION;
    use chrono::{NaiveDate, Utc};

    fn report(findings: Vec<Finding>, integrity: Vec<IntegrityItem>) -> Report {
        let (verdict, summary) = Report::compute_summary(&findings);
        Report {
            schema_version: SCHEMA_VERSION,
            generated_at: Utc::now(),
            platform: PlatformInfo {
                id: "jtl5".into(),
                name: "JTL-Shop 5".into(),
                kind: PlatformKind::SelfHosted,
                version: None,
                root: None,
                target: None,
                details: vec![],
            },
            reference_date: NaiveDate::from_ymd_opt(2026, 6, 17).unwrap(),
            verdict,
            summary,
            findings,
            integrity,
            advisories: vec![],
            recommendations: vec![],
            limitations: vec![],
            score: None,
            grade: None,
            score_drivers: vec![],
        }
    }

    fn finding(sev: Severity, cat: Category, rule: &str, subject: &str) -> Finding {
        Finding::new(sev, cat, Source::FileSystem, rule, subject, "t")
    }

    fn admin(name: &str, value: &str) -> IntegrityItem {
        IntegrityItem::new(
            format!("admin.account.{name}"),
            "Admin-Konten",
            name,
            IntegrityStatus::Ok,
            value,
        )
    }

    #[test]
    fn clean_report_scores_100() {
        let s = compute(&report(vec![], vec![]));
        assert_eq!(s.score, 100);
        assert_eq!(s.grade, Grade::A);
        assert!(s.drivers.is_empty());
    }

    #[test]
    fn critical_findings_cap_the_grade() {
        let r = report(
            vec![finding(
                Severity::Critical,
                Category::KnownWebshell,
                "ioc_filename",
                "a.php",
            )],
            vec![],
        );
        let s = compute(&r);
        // 100 - 12 = 88, capped to 49 because of the critical verdict.
        assert_eq!(s.score, 49);
        assert_eq!(s.grade, Grade::D);
        assert_eq!(s.drivers[0].key, "critical_findings");
        assert_eq!(s.drivers[0].label, "1 kritischer Befund");
    }

    #[test]
    fn many_findings_saturate_at_zero_and_caps_apply() {
        let mut f = Vec::new();
        for i in 0..50 {
            f.push(finding(
                Severity::Critical,
                Category::SuspiciousPattern,
                "r",
                &format!("c{i}"),
            ));
            f.push(finding(
                Severity::Warning,
                Category::ModifiedSinceReference,
                "w",
                &format!("w{i}"),
            ));
        }
        for i in 0..5 {
            f.push(finding(
                Severity::Critical,
                Category::PatchStatus,
                &format!("advisory_cve-2026-{i}"),
                "5.3.1",
            ));
            f.push(finding(
                Severity::Critical,
                Category::PatchStatus,
                &format!("osv_ghsa-{i}"),
                "composer:a/b@1",
            ));
        }
        let mut r = report(f, vec![]);
        r.summary.complete = false;
        r.limitations = (0..10).map(|i| format!("l{i}")).collect();
        let s = compute(&r);
        let points = |k: &str| s.drivers.iter().find(|d| d.key == k).unwrap().points;
        assert_eq!(points("critical_findings"), CRITICAL_CAP);
        assert_eq!(points("warnings"), WARNING_CAP);
        assert_eq!(points("advisories_vulnerable"), ADVISORY_VULNERABLE_CAP);
        assert_eq!(points("dependencies"), DEPENDENCY_CAP);
        assert_eq!(points("limitations"), LIMITATION_CAP);
        assert_eq!(points("scan_incomplete"), INCOMPLETE);
        assert_eq!(s.score, 0);
        assert_eq!(s.grade, Grade::F);
        assert_eq!(s.top_drivers().len(), 3);
        assert_eq!(s.top_drivers()[0].key, "critical_findings");
    }

    #[test]
    fn accepted_findings_do_not_count() {
        let mut f = finding(
            Severity::Critical,
            Category::ExposedFile,
            "exposed_file",
            "backup.sql",
        );
        f.accepted = true;
        let s = compute(&report(vec![f], vec![]));
        assert_eq!(s.score, 100);
    }

    #[test]
    fn warnings_cap_at_b() {
        let s = compute(&report(
            vec![finding(
                Severity::Warning,
                Category::ModifiedSinceReference,
                "modified",
                "x.php",
            )],
            vec![],
        ));
        assert_eq!(s.score, 89);
        assert_eq!(s.grade, Grade::B);
    }

    #[test]
    fn two_fa_permissions_and_baseline() {
        let integrity = vec![
            admin("a", "aktiv · 2FA: ja · letzter Login: nie"),
            admin("b", "aktiv · 2FA: nein · letzter Login: nie"),
            admin("c", "inaktiv · 2FA: nein · letzter Login: nie"),
            admin("d", "Inhaber · 3 Berechtigungen · 2FA: unbekannt"),
            IntegrityItem::new(
                "perm.includes/config.JTL-Shop.ini.php",
                "Dateirechte",
                "x",
                IntegrityStatus::Critical,
                "0666",
            ),
            IntegrityItem::new(
                "integrity.baseline",
                "Integrität",
                "Baseline",
                IntegrityStatus::Unknown,
                "keine Baseline vorhanden",
            ),
        ];
        let s = compute(&report(vec![], integrity));
        let get = |k: &str| s.drivers.iter().find(|d| d.key == k).cloned().unwrap();
        // 1 of 2 active accounts without 2FA → 5 points.
        assert_eq!(get("admin_2fa").points, 5);
        assert_eq!(
            get("admin_2fa").label,
            "1 von 2 aktiven Admin-Konten ohne 2FA"
        );
        assert_eq!(get("config_permissions").points, PERMISSION_CRITICAL_EACH);
        assert_eq!(get("baseline_missing").points, NO_BASELINE);
        assert_eq!(s.score, 100 - 5 - 6 - 5);
        assert_eq!(s.grade, Grade::B);
        // Deterministic ordering: largest first, ties by key.
        assert_eq!(s.drivers[0].key, "config_permissions");
        assert_eq!(s.drivers[1].key, "admin_2fa");
        assert_eq!(s.drivers[2].key, "baseline_missing");
    }

    #[test]
    fn grade_boundaries() {
        assert_eq!(Grade::from_score(100), Grade::A);
        assert_eq!(Grade::from_score(90), Grade::A);
        assert_eq!(Grade::from_score(89), Grade::B);
        assert_eq!(Grade::from_score(75), Grade::B);
        assert_eq!(Grade::from_score(74), Grade::C);
        assert_eq!(Grade::from_score(60), Grade::C);
        assert_eq!(Grade::from_score(59), Grade::D);
        assert_eq!(Grade::from_score(40), Grade::D);
        assert_eq!(Grade::from_score(39), Grade::F);
        assert_eq!(Grade::from_score(0), Grade::F);
    }

    #[test]
    fn two_fa_parser() {
        assert_eq!(two_fa_state("aktiv · 2FA: ja"), Some(true));
        assert_eq!(
            two_fa_state("Inhaber · 2 Berechtigungen · 2FA: nein"),
            Some(false)
        );
        assert_eq!(two_fa_state("inaktiv · 2FA: nein"), None);
        assert_eq!(two_fa_state("aktiv · Administrator"), None);
    }

    #[test]
    fn report_without_score_fields_still_loads() {
        let mut v = serde_json::to_value(report(vec![], vec![])).unwrap();
        let obj = v.as_object_mut().unwrap();
        obj.remove("score");
        obj.remove("grade");
        obj.remove("score_drivers");
        let r: Report = serde_json::from_value(v).unwrap();
        assert!(r.score.is_none());
        assert_eq!(r.posture().score, 100);
    }
}
