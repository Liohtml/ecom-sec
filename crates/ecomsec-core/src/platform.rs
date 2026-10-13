//! The [`Platform`] trait implemented by every shop-system adapter plus the
//! data structures adapters use to describe themselves.

use crate::finding::Finding;
use crate::report::Report;
use crate::rules::RuleSet;
use crate::state::StateStore;
use crate::version::{Version, VersionRange};
use crate::Recommendation;
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Coarse platform family.  Adapters are identified by their string id
/// (`jtl5`, `shopware6`, `shopify`, …); the kind only says how the adapter
/// reaches the installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformKind {
    /// Self-hosted: web root on disk, optionally a database.
    SelfHosted,
    /// SaaS: no file system, everything goes through an API.
    Hosted,
}

/// Static description of the platform an adapter targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub id: String,
    pub name: String,
    pub kind: PlatformKind,
    /// Detected version of the shop software.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<Version>,
    /// Web root (self-hosted) …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<PathBuf>,
    /// … or remote identifier (shop domain) for hosted platforms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Free-form details (edition, PHP version, …).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<(String, String)>,
}

impl PlatformInfo {
    pub fn target_key(&self) -> String {
        self.root
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .or_else(|| self.target.clone())
            .unwrap_or_else(|| self.id.clone())
    }
}

/// A sensitive configuration file whose permissions are checked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFileSpec {
    /// Path relative to the web root.
    pub path: String,
    pub description: String,
    /// `true` if the file holds secrets (DB credentials, keys).
    #[serde(default = "default_true")]
    pub secret: bool,
}

fn default_true() -> bool {
    true
}

/// Tells the file scanner how an installation is laid out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileScanProfile {
    /// Directory that is walked.
    pub root: PathBuf,
    /// Directory that is reachable through HTTP (for the exposed-file check).
    /// Defaults to `root`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_root: Option<PathBuf>,
    /// Relative directories that are skipped entirely (`.git`, `node_modules`).
    #[serde(default)]
    pub excluded_dirs: Vec<String>,
    /// Relative directories where generated PHP is normal (compiled templates,
    /// caches).  New files there are reported as info instead of warning,
    /// content rules still apply.
    #[serde(default)]
    pub generated_dirs: Vec<String>,
    /// Relative directories that must never contain executable code.
    #[serde(default)]
    pub upload_dirs: Vec<String>,
    /// Relative directories holding log files, scanned for attack traces.
    #[serde(default)]
    pub log_dirs: Vec<String>,
    /// Relative directories that make up the vendor-supplied core (used by the
    /// baseline / integrity comparison).
    #[serde(default)]
    pub core_dirs: Vec<String>,
    /// Sensitive configuration files.
    #[serde(default)]
    pub config_files: Vec<ConfigFileSpec>,
    /// Template file extensions (`tpl`, `twig`, `liquid`), scanned with the
    /// `template` rule class.
    #[serde(default)]
    pub template_extensions: Vec<String>,
}

impl FileScanProfile {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        FileScanProfile {
            root: root.into(),
            public_root: None,
            excluded_dirs: vec![
                ".git".into(),
                ".svn".into(),
                ".hg".into(),
                "node_modules".into(),
            ],
            generated_dirs: Vec::new(),
            upload_dirs: Vec::new(),
            log_dirs: Vec::new(),
            core_dirs: Vec::new(),
            config_files: Vec::new(),
            template_extensions: Vec::new(),
        }
    }

    pub fn public_root(&self) -> &PathBuf {
        self.public_root.as_ref().unwrap_or(&self.root)
    }
}

/// A known vulnerability with the affected version ranges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    /// `CVE-2026-54390`, `GHSA-…`.
    pub id: String,
    pub title: String,
    pub severity: crate::Severity,
    /// CVSS or similar score, for display only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    pub affected: Vec<VersionRange>,
    pub fixed_in: Vec<Version>,
    /// Note about back-patches for older branches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backpatch_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    pub published: NaiveDate,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Component the version ranges refer to when it is not the shop core
    /// itself (e.g. `WooCommerce` on top of WordPress).  The adapter
    /// resolves its version through [`Platform::component_version`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
}

impl Advisory {
    /// Vulnerable according to the version alone?
    pub fn affects(&self, v: &Version) -> bool {
        self.affected.iter().any(|r| r.contains(v))
    }

    /// Fixed release for the branch of `v`, if the advisory knows one.
    pub fn fix_for_branch(&self, v: &Version) -> Option<&Version> {
        self.fixed_in
            .iter()
            .find(|f| f.same_branch(v))
            .or_else(|| self.fixed_in.iter().max())
    }
}

/// Evidence an adapter can provide about an advisory beyond the version
/// number (e.g. the patched source file was inspected, a back-patch marker
/// exists).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchEvidence {
    pub patched: bool,
    /// What was checked (`includes/src/.../SmartyRenderer.php`).
    pub checked: String,
    pub detail: String,
}

/// Outcome of evaluating one advisory against the installation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryStatus {
    pub advisory: Advisory,
    pub state: PatchState,
    /// Human readable explanation of how the state was derived.
    pub basis: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchState {
    Patched,
    Vulnerable,
    Unknown,
    NotAffected,
}

/// Status of a single integrity item shown in the "Shop-Integrität" view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityStatus {
    Ok,
    Warning,
    Critical,
    Unknown,
}

/// A row in the integrity view (admin account, PayPal recipient, patch
/// status, config permissions …).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityItem {
    /// Stable key, e.g. `admin.account.jdoe`, `payment.paypal.recipient`.
    pub key: String,
    /// Section, e.g. `Patch-Status`, `Admin-Konten`, `Zahlung`, `Dateirechte`.
    pub section: String,
    pub label: String,
    pub status: IntegrityStatus,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl IntegrityItem {
    pub fn new(
        key: impl Into<String>,
        section: impl Into<String>,
        label: impl Into<String>,
        status: IntegrityStatus,
        value: impl Into<String>,
    ) -> Self {
        IntegrityItem {
            key: key.into(),
            section: section.into(),
            label: label.into(),
            status,
            value: value.into(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// What an adapter's integrity checks return.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub items: Vec<IntegrityItem>,
    pub findings: Vec<Finding>,
    /// Checks that could not be executed (and why).
    pub limitations: Vec<String>,
}

impl IntegrityReport {
    pub fn merge(&mut self, other: IntegrityReport) {
        self.items.extend(other.items);
        self.findings.extend(other.findings);
        self.limitations.extend(other.limitations);
    }
}

/// What an adapter knows about a component referenced by an advisory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentVersion {
    /// The component is not part of the installation.
    NotInstalled,
    /// Installed (or possibly installed), version not determinable.
    Unknown,
    Installed(Version),
}

/// Runtime context handed to adapters.
#[derive(Debug, Clone)]
pub struct PlatformContext {
    pub reference_date: NaiveDate,
    /// Database / API checks disabled by the user.
    pub skip_remote: bool,
    /// Online lookups (OSV.dev) explicitly enabled by the user.
    pub online: bool,
    pub state: StateStore,
}

/// The adapter interface.  Everything is synchronous and read-only.
pub trait Platform: Send + Sync {
    /// Identity and detected version of the installation.
    fn info(&self) -> PlatformInfo;

    /// Layout for the file scanner.  `None` for hosted platforms.
    fn file_scan_profile(&self) -> Option<FileScanProfile> {
        None
    }

    /// Platform-specific content rules (CVE payloads, template engines …).
    fn rules(&self) -> RuleSet {
        RuleSet::empty()
    }

    /// Known vulnerabilities of this platform.
    fn advisories(&self) -> Vec<Advisory> {
        Vec::new()
    }

    /// Installed version of a component other than the shop core (for
    /// advisories with `component = "…"`).  Adapters compare the name
    /// case-insensitively.
    fn component_version(&self, _component: &str) -> ComponentVersion {
        ComponentVersion::Unknown
    }

    /// Additional evidence for an advisory beyond the version number.
    fn patch_evidence(
        &self,
        _advisory: &Advisory,
        _ctx: &PlatformContext,
    ) -> Option<PatchEvidence> {
        None
    }

    /// Integrity checks: admin accounts, payment configuration, config file
    /// permissions, …
    fn integrity(&self, _ctx: &PlatformContext) -> anyhow::Result<IntegrityReport> {
        Ok(IntegrityReport::default())
    }

    /// Any further checks (e-mail history, API-based scans, …).
    fn additional_checks(&self, _ctx: &PlatformContext) -> anyhow::Result<Vec<Finding>> {
        Ok(Vec::new())
    }

    /// Platform-specific recommendations appended to the generic ones.
    fn recommendations(&self, _report: &Report) -> Vec<Recommendation> {
        Vec::new()
    }
}

/// Version an advisory is evaluated against: the shop version, or the
/// version of the advisory's `component` as reported by the adapter.
/// `Err` carries the status for a component that is not installed.
fn subject_version(
    platform: &dyn Platform,
    version: Option<&Version>,
    adv: &Advisory,
) -> Result<(Option<Version>, String), String> {
    match &adv.component {
        None => Ok((version.cloned(), "Shop-Version".to_string())),
        Some(c) => match platform.component_version(c) {
            ComponentVersion::NotInstalled => Err(format!(
                "{c} ist nicht installiert – {} betrifft diese Installation nicht.",
                adv.id
            )),
            ComponentVersion::Unknown => Ok((None, format!("{c}-Version"))),
            ComponentVersion::Installed(v) => Ok((Some(v), format!("{c}-Version"))),
        },
    }
}

/// Version actually evaluated for an advisory (shop or component version).
pub fn evaluated_version(
    platform: &dyn Platform,
    version: Option<&Version>,
    adv: &Advisory,
) -> Option<Version> {
    subject_version(platform, version, adv)
        .ok()
        .and_then(|(v, _)| v)
}

/// Evaluate advisories against a version.  Adapters may refine the result via
/// [`Platform::patch_evidence`]; the engine calls this helper.  Advisories
/// with a `component` are evaluated against
/// [`Platform::component_version`] instead of the shop version.
pub fn evaluate_advisories(
    platform: &dyn Platform,
    ctx: &PlatformContext,
    version: Option<&Version>,
    advisories: Vec<Advisory>,
) -> Vec<AdvisoryStatus> {
    advisories
        .into_iter()
        .map(|adv| {
            let (version, label) = match subject_version(platform, version, &adv) {
                Ok(pair) => pair,
                Err(basis) => {
                    return AdvisoryStatus {
                        advisory: adv,
                        state: PatchState::NotAffected,
                        basis,
                    }
                }
            };
            let (state, basis) = match version.as_ref() {
                Some(v) if !adv.affects(v) => {
                    let fixed = adv.fixed_in.iter().any(|f| f <= v && f.same_branch(v))
                        || adv.fixed_in.iter().all(|f| f <= v);
                    if fixed {
                        (
                            PatchState::Patched,
                            format!("{label} {v} enthält den Fix (Bewertung anhand der Versionsnummer)."),
                        )
                    } else {
                        (
                            PatchState::NotAffected,
                            format!("{label} {v} ist von {} nicht betroffen.", adv.id),
                        )
                    }
                }
                other => {
                    // Version unknown or vulnerable: ask the adapter for file evidence.
                    match platform.patch_evidence(&adv, ctx) {
                        Some(ev) if ev.patched => (
                            PatchState::Patched,
                            format!(
                                "{} (Bewertung anhand der geprüften Datei {}; Version {}).",
                                ev.detail,
                                ev.checked,
                                other.map(|v| v.to_string()).unwrap_or_else(|| "unbekannt".into())
                            ),
                        ),
                        Some(ev) => (
                            PatchState::Vulnerable,
                            format!("{} (geprüfte Datei: {}).", ev.detail, ev.checked),
                        ),
                        None => match other {
                            Some(v) => (
                                PatchState::Vulnerable,
                                format!(
                                    "{label} {v} liegt im betroffenen Bereich ({}); kein Patch-Nachweis gefunden.",
                                    adv.affected
                                        .iter()
                                        .map(|r| r.to_string())
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ),
                            ),
                            None => (
                                PatchState::Unknown,
                                format!("{label} konnte nicht ermittelt werden und kein Patch-Nachweis gefunden."),
                            ),
                        },
                    }
                }
            };
            AdvisoryStatus {
                advisory: adv,
                state,
                basis,
            }
        })
        .collect()
}
