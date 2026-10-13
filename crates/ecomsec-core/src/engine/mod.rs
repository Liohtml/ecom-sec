//! Scan orchestration: file scan, advisories, integrity checks, additional
//! checks, risk acceptance, recommendations and persistence.

pub mod file_scan;

use crate::advisories::{merge_by_id, AdvisoryDb};
use crate::baseline::Baseline;
use crate::finding::{Category, Finding, Severity, Source};
use crate::platform::{
    evaluate_advisories, IntegrityItem, IntegrityStatus, PatchState, Platform, PlatformContext,
};
use crate::recommendations;
use crate::report::{HistoryEntry, Report, SCHEMA_VERSION};
use crate::rules::RuleSet;
use crate::signatures::{self, IocList};
use crate::state::StateStore;
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Default reference date: publication of the CVE-2026-54390 advisory in the
/// JTL partner newsletter (17 June 2026).  Files changed on or after this day
/// are reported.
pub fn default_reference_date() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 6, 17).expect("valid date")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub reference_date: NaiveDate,
    /// Stop the file scan after this long and persist a checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_budget: Option<Duration>,
    /// Continue from a persisted checkpoint if one matches.
    #[serde(default)]
    pub resume: bool,
    #[serde(default)]
    pub skip_files: bool,
    /// Skip database / API based checks.
    #[serde(default)]
    pub skip_remote: bool,
    #[serde(default)]
    pub skip_baseline: bool,
    /// Additional rule directories (`*.toml`).
    #[serde(default)]
    pub extra_rule_dirs: Vec<PathBuf>,
    /// Additional relative directories to exclude from the file scan.
    #[serde(default)]
    pub extra_excludes: Vec<String>,
    /// Files larger than this are not content-scanned (metadata checks still apply).
    pub max_file_size: u64,
    /// Do not persist the report / history (dry run).
    #[serde(default)]
    pub no_persist: bool,
    /// Additional advisory directories (`*.toml`), merged over the embedded ones.
    #[serde(default)]
    pub advisory_dirs: Vec<PathBuf>,
    /// Allow online lookups (OSV.dev) – sends package names and versions.
    #[serde(default)]
    pub online: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            reference_date: default_reference_date(),
            time_budget: None,
            resume: true,
            skip_files: false,
            skip_remote: false,
            skip_baseline: false,
            extra_rule_dirs: Vec::new(),
            extra_excludes: Vec::new(),
            max_file_size: 8 * 1024 * 1024,
            no_persist: false,
            advisory_dirs: Vec::new(),
            online: false,
        }
    }
}

/// The engine holds compiled signatures and runs scans.
pub struct Engine {
    rules: RuleSet,
    iocs: IocList,
    advisories: AdvisoryDb,
}

/// What a scan returns.
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub report: Report,
    /// `false` when the file scan hit the time budget; run again with
    /// `resume` to continue.
    pub complete: bool,
    /// Files still to be scanned (when incomplete).
    pub remaining_files: usize,
}

impl Engine {
    pub fn new(options: &ScanOptions) -> anyhow::Result<Self> {
        let mut rules = signatures::builtin_rules()?;
        for dir in &options.extra_rule_dirs {
            let extra = RuleSet::from_dir(dir)?;
            log::info!("loaded {} extra rules from {}", extra.len(), dir.display());
            rules.extend(extra);
        }
        let iocs = IocList::builtin()?;
        let mut advisories = AdvisoryDb::new();
        for dir in &options.advisory_dirs {
            if dir.is_dir() {
                let n = advisories.merge_dir(dir)?;
                log::info!("loaded {n} advisories from {}", dir.display());
            }
        }
        Ok(Engine {
            rules,
            iocs,
            advisories,
        })
    }

    /// Advisories loaded from extra directories (not the embedded ones).
    pub fn extra_advisories(&self) -> &AdvisoryDb {
        &self.advisories
    }

    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    pub fn iocs(&self) -> &IocList {
        &self.iocs
    }

    /// Run a full scan.
    pub fn scan(
        &self,
        platform: &dyn Platform,
        state: &StateStore,
        options: &ScanOptions,
    ) -> anyhow::Result<ScanOutcome> {
        self.scan_with_progress(platform, state, options, None)
    }

    pub fn scan_with_progress(
        &self,
        platform: &dyn Platform,
        state: &StateStore,
        options: &ScanOptions,
        progress: Option<file_scan::ProgressFn>,
    ) -> anyhow::Result<ScanOutcome> {
        let started = Instant::now();
        let info = platform.info();
        let ctx = PlatformContext {
            reference_date: options.reference_date,
            skip_remote: options.skip_remote,
            online: options.online,
            state: state.clone(),
        };
        let mut findings: Vec<Finding> = Vec::new();
        let mut limitations: Vec<String> = Vec::new();
        let mut integrity: Vec<IntegrityItem> = Vec::new();
        let mut complete = true;
        let mut remaining_files = 0usize;
        let mut files_scanned = 0u64;
        let mut bytes_scanned = 0u64;

        // ---------------------------------------------------------- files
        let profile = platform.file_scan_profile().map(|mut p| {
            p.excluded_dirs
                .extend(options.extra_excludes.iter().cloned());
            p
        });
        if let Some(profile) = &profile {
            if options.skip_files {
                limitations.push("Dateiscan übersprungen (--skip-files).".into());
            } else {
                let mut rules = self.rules.clone();
                rules.extend(platform.rules());
                let scanner = file_scan::FileScanner::new(profile, &rules, &self.iocs, options);
                let result = scanner.run(state, progress)?;
                files_scanned = result.files_scanned;
                bytes_scanned = result.bytes_scanned;
                complete = result.complete;
                remaining_files = result.remaining;
                findings.extend(result.findings);
                limitations.extend(result.limitations);
                if !complete {
                    limitations.push(format!(
                        "Zeitbudget erschöpft: {} Dateien noch nicht geprüft. Scan erneut starten, um fortzusetzen.",
                        remaining_files
                    ));
                }
            }

            // ------------------------------------------------------ baseline
            if complete && !options.skip_baseline {
                if let Some(baseline) = state.baseline() {
                    match baseline.diff(profile) {
                        Ok(diff) => {
                            let n = diff.changed.len() + diff.missing.len() + diff.added.len();
                            integrity.push(
                                IntegrityItem::new(
                                    "integrity.baseline",
                                    "Integrität",
                                    "Abweichungen von der Baseline",
                                    if diff.changed.is_empty() && diff.missing.is_empty() {
                                        IntegrityStatus::Ok
                                    } else {
                                        IntegrityStatus::Warning
                                    },
                                    format!(
                                        "{} geändert, {} fehlend, {} neu",
                                        diff.changed.len(),
                                        diff.missing.len(),
                                        diff.added.len()
                                    ),
                                )
                                .with_detail(format!(
                                    "Baseline vom {} ({} Dateien)",
                                    baseline.created_at.format("%d.%m.%Y %H:%M UTC"),
                                    baseline.files.len()
                                )),
                            );
                            if n > 0 {
                                findings.extend(Baseline::findings(profile, &diff));
                            }
                        }
                        Err(e) => {
                            limitations.push(format!("Baseline-Vergleich fehlgeschlagen: {e}"))
                        }
                    }
                } else {
                    integrity.push(
                        IntegrityItem::new(
                            "integrity.baseline",
                            "Integrität",
                            "Baseline",
                            IntegrityStatus::Unknown,
                            "keine Baseline vorhanden",
                        )
                        .with_detail("Mit `ecomsec baseline create` nach einer verifizierten Prüfung anlegen."),
                    );
                }
            }
        }

        // ---------------------------------------------------------- advisories
        let merged = merge_by_id(
            platform.advisories(),
            self.advisories.for_platform(&info.id),
        );
        let advisories = evaluate_advisories(platform, &ctx, info.version.as_ref(), merged);
        for status in &advisories {
            let adv = &status.advisory;
            let (istatus, label) = match status.state {
                PatchState::Patched => (IntegrityStatus::Ok, "gepatcht"),
                PatchState::NotAffected => (IntegrityStatus::Ok, "nicht betroffen"),
                PatchState::Vulnerable => (IntegrityStatus::Critical, "VERWUNDBAR"),
                PatchState::Unknown => (IntegrityStatus::Warning, "unbekannt"),
            };
            integrity.push(
                IntegrityItem::new(
                    format!("patch.{}", adv.id.to_ascii_lowercase()),
                    "Patch-Status",
                    format!("{} – {}", adv.id, adv.title),
                    istatus,
                    label,
                )
                .with_detail(status.basis.clone()),
            );
            match status.state {
                PatchState::Vulnerable => findings.push(
                    Finding::new(
                        adv.severity,
                        Category::PatchStatus,
                        Source::Configuration,
                        format!("advisory_{}", adv.id.to_ascii_lowercase()),
                        info.version
                            .as_ref()
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "unbekannte Version".into()),
                        format!("Shop ist verwundbar: {} ({})", adv.id, adv.title),
                    )
                    .with_description(status.basis.clone())
                    .with_evidence(
                        adv.reference
                            .clone()
                            .unwrap_or_else(|| "keine Referenz hinterlegt".into()),
                    ),
                ),
                PatchState::Unknown => findings.push(
                    Finding::new(
                        Severity::Warning,
                        Category::PatchStatus,
                        Source::Configuration,
                        format!("advisory_{}_unknown", adv.id.to_ascii_lowercase()),
                        "unbekannte Version",
                        format!("Patch-Status für {} nicht ermittelbar", adv.id),
                    )
                    .with_description(status.basis.clone()),
                ),
                _ => {}
            }
        }

        // ---------------------------------------------------------- integrity
        match platform.integrity(&ctx) {
            Ok(rep) => {
                integrity.extend(rep.items);
                findings.extend(rep.findings);
                limitations.extend(rep.limitations);
            }
            Err(e) => {
                limitations.push(format!("Integritätsprüfung fehlgeschlagen: {e}"));
                findings.push(
                    Finding::new(
                        Severity::Info,
                        Category::ScanLimitation,
                        Source::Scanner,
                        "integrity_failed",
                        "integrity",
                        "Integritätsprüfung konnte nicht ausgeführt werden",
                    )
                    .with_description(e.to_string()),
                );
            }
        }

        // ---------------------------------------------------------- additional
        match platform.additional_checks(&ctx) {
            Ok(more) => findings.extend(more),
            Err(e) => limitations.push(format!("Zusätzliche Prüfungen fehlgeschlagen: {e}")),
        }

        // Stable section order: Shop, Patch-Status, Integrität, then the rest.
        let rank = |section: &str| match section {
            "Shop" => 0,
            "Patch-Status" => 1,
            "Integrität" => 2,
            _ => 3,
        };
        integrity.sort_by_key(|i| rank(&i.section));

        // ---------------------------------------------------------- acceptance
        let accepted = state.accepted();
        for f in &mut findings {
            if let Some(a) = accepted.findings.get(&f.id) {
                f.accepted = true;
                f.accepted_reason = a.reason.clone();
            }
        }
        dedupe(&mut findings);

        let (verdict, mut summary) = Report::compute_summary(&findings);
        summary.files_scanned = files_scanned;
        summary.bytes_scanned = bytes_scanned;
        summary.duration_ms = started.elapsed().as_millis();
        summary.complete = complete;

        let mut report = Report {
            schema_version: SCHEMA_VERSION,
            generated_at: Utc::now(),
            platform: info,
            reference_date: options.reference_date,
            verdict,
            summary,
            findings,
            integrity,
            advisories,
            recommendations: Vec::new(),
            limitations,
        };
        let extra = platform.recommendations(&report);
        report.recommendations = recommendations::build(&report, extra);

        if !options.no_persist {
            if let Err(e) = state.push_history(HistoryEntry::from(&report)) {
                log::warn!("cannot write history: {e}");
            }
            if let Err(e) = state.save_last_report(&report) {
                log::warn!("cannot write last report: {e}");
            }
            // Only complete reports are archived for change detection – a
            // partial file scan would show findings as "resolved".
            if report.summary.complete {
                if let Err(e) = state.archive_report(&report) {
                    log::warn!("cannot archive report: {e}");
                }
            }
        }

        Ok(ScanOutcome {
            report,
            complete,
            remaining_files,
        })
    }
}

/// Remove exact duplicates (same id), keeping the most severe.
fn dedupe(findings: &mut Vec<Finding>) {
    findings.sort_by(|a, b| a.id.cmp(&b.id).then(b.severity.cmp(&a.severity)));
    findings.dedup_by(|a, b| a.id == b.id);
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.subject.cmp(&b.subject)));
}

/// Parse a human time budget such as `30s`, `2m`, `500ms`.
pub fn parse_duration(input: &str) -> Option<Duration> {
    let s = input.trim();
    if let Some(ms) = s.strip_suffix("ms") {
        return ms.trim().parse().ok().map(Duration::from_millis);
    }
    if let Some(v) = s.strip_suffix('s') {
        return v.trim().parse::<f64>().ok().map(Duration::from_secs_f64);
    }
    if let Some(v) = s.strip_suffix('m') {
        return v
            .trim()
            .parse::<f64>()
            .ok()
            .map(|m| Duration::from_secs_f64(m * 60.0));
    }
    if let Some(v) = s.strip_suffix('h') {
        return v
            .trim()
            .parse::<f64>()
            .ok()
            .map(|h| Duration::from_secs_f64(h * 3600.0));
    }
    s.parse::<u64>().ok().map(Duration::from_secs)
}
