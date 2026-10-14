//! Finding model shared by all scanners and platform adapters.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::{Path, PathBuf};

/// Severity of a finding.  Mirrors the three-colour traffic light of the
/// original backend plugin: red (critical), yellow (warning), neutral (info).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info = 0,
    Warning = 1,
    Critical = 2,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "KRITISCH",
            Severity::Warning => "WARNUNG",
            Severity::Info => "INFO",
        }
    }

    pub fn label_en(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label_en())
    }
}

/// Classification of a finding.  Platform adapters reuse these categories so
/// that reports, recommendations and risk acceptance work identically for
/// every shop system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// File name matches a known webshell / backdoor IOC list.
    KnownWebshell,
    /// PHP (or other executable) file created or modified after the reference date.
    ModifiedSinceReference,
    /// Executable code inside an upload/media directory.
    CodeInUploadDir,
    /// `.htaccess` / `.user.ini` / web server config manipulated to execute code.
    WebserverConfigManipulation,
    /// Content matches a malware / obfuscation rule.
    SuspiciousPattern,
    /// Content matches a CVE-specific exploitation payload (e.g. SSTI).
    ExploitPayload,
    /// File metadata looks manipulated (mtime older than ctime, future dates …).
    TimestampAnomaly,
    /// Trace of an attack found in stored e-mails / logs.
    AttackTrace,
    /// Patch status of the installation against known vulnerabilities.
    PatchStatus,
    /// Administrative accounts (last login, 2FA, stale accounts …).
    AdminAccount,
    /// Payment recipient / merchant configuration changed or suspicious.
    PaymentConfiguration,
    /// Permissions of sensitive configuration files.
    ConfigPermissions,
    /// Backup / dump / config files reachable through the web root.
    ExposedFile,
    /// Core file deviates from the recorded baseline.
    IntegrityDeviation,
    /// Third-party code injected into the storefront (script tags, apps, webhooks).
    ThirdPartyInjection,
    /// Scanner could not perform a check (DB unreachable, permissions …).
    ScanLimitation,
    /// Informational only.
    Informational,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::KnownWebshell => "Bekannte Webshell",
            Category::ModifiedSinceReference => "Neue/geänderte Datei",
            Category::CodeInUploadDir => "Code im Upload-Verzeichnis",
            Category::WebserverConfigManipulation => "Webserver-Konfiguration manipuliert",
            Category::SuspiciousPattern => "Verdächtiges Code-Muster",
            Category::ExploitPayload => "Exploit-Payload",
            Category::TimestampAnomaly => "Zeitstempel-Anomalie",
            Category::AttackTrace => "Angriffsspur",
            Category::PatchStatus => "Patch-Status",
            Category::AdminAccount => "Admin-Konto",
            Category::PaymentConfiguration => "Zahlungs-Konfiguration",
            Category::ConfigPermissions => "Dateirechte",
            Category::ExposedFile => "Öffentlich erreichbare Datei",
            Category::IntegrityDeviation => "Integritätsabweichung",
            Category::ThirdPartyInjection => "Fremdcode / Injection",
            Category::ScanLimitation => "Scan-Einschränkung",
            Category::Informational => "Information",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Stable identifier of a finding.  It is derived from the category, the
/// rule name and the subject (usually a path), so that the same finding keeps
/// its id across scans and risk acceptance survives rescans.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct FindingId(pub String);

impl FindingId {
    pub fn derive(category: Category, rule: &str, subject: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(format!("{category:?}\0{rule}\0{subject}").as_bytes());
        let digest = hasher.finalize();
        FindingId(hex::encode(&digest[..8]))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FindingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a finding comes from: the file system, the database, an API, …
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    FileSystem,
    Database,
    Api,
    Configuration,
    Scanner,
    /// Web server access logs (`--access-log`).
    AccessLog,
}

/// A single finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub severity: Severity,
    pub category: Category,
    pub source: Source,
    /// Short human readable title.
    pub title: String,
    /// Longer explanation including why this matters and what to verify.
    pub description: String,
    /// Subject of the finding: a path relative to the web root, a DB record,
    /// an account name, a URL …
    pub subject: String,
    /// Absolute path on disk, when the subject is a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// Name of the rule or check that produced the finding.
    pub rule: String,
    /// Optional evidence excerpt (matched snippet, timestamps, …).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// Risk-acceptance state, filled in by the engine from the state store.
    #[serde(default)]
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_reason: Option<String>,
    /// Optional grouping key (e.g. directory) used by bulk triage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Assessment by the optional AI audit (`ecomsec audit`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<Review>,
}

/// Verdict of a reviewer (the optional AI audit) on a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdict {
    /// The finding is a real indicator of compromise / vulnerability.
    Confirmed,
    /// Most likely harmless (known plugin, deployment, generated file …).
    LikelyFalsePositive,
    /// Evidence is inconclusive; a human has to decide.
    NeedsHuman,
}

impl ReviewVerdict {
    pub fn label(self) -> &'static str {
        match self {
            ReviewVerdict::Confirmed => "bestätigt",
            ReviewVerdict::LikelyFalsePositive => "wahrscheinlich Fehlalarm",
            ReviewVerdict::NeedsHuman => "manuelle Prüfung nötig",
        }
    }

    /// Parse the wire names (`confirmed`, `likely_false_positive`, `needs_human`).
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "confirmed" => Some(ReviewVerdict::Confirmed),
            "likely_false_positive" | "false_positive" => Some(ReviewVerdict::LikelyFalsePositive),
            "needs_human" => Some(ReviewVerdict::NeedsHuman),
            _ => None,
        }
    }
}

impl fmt::Display for ReviewVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Review attached to a finding.  Purely informational: it never changes the
/// severity or the risk acceptance of a finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Review {
    pub verdict: ReviewVerdict,
    /// Confidence between 0.0 and 1.0.
    pub confidence: f32,
    pub reasoning: String,
    /// Model (or reviewer) that produced the assessment.
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Finding {
    pub fn new(
        severity: Severity,
        category: Category,
        source: Source,
        rule: impl Into<String>,
        subject: impl Into<String>,
        title: impl Into<String>,
    ) -> Self {
        let rule = rule.into();
        let subject = subject.into();
        Finding {
            id: FindingId::derive(category, &rule, &subject),
            severity,
            category,
            source,
            title: title.into(),
            description: String::new(),
            subject,
            path: None,
            rule,
            evidence: Vec::new(),
            accepted: false,
            accepted_reason: None,
            group: None,
            review: None,
        }
    }

    pub fn file(
        severity: Severity,
        category: Category,
        rule: impl Into<String>,
        root: &Path,
        path: &Path,
        title: impl Into<String>,
    ) -> Self {
        let rel = crate::util::relative_display(root, path);
        let group = path
            .parent()
            .map(|p| crate::util::relative_display(root, p))
            .filter(|g| !g.is_empty());
        let mut f = Finding::new(severity, category, Source::FileSystem, rule, rel, title);
        f.path = Some(path.to_path_buf());
        f.group = group;
        f
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence.push(evidence.into());
        self
    }

    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }

    /// Severity that counts towards the verdict (accepted findings do not).
    pub fn effective_severity(&self) -> Option<Severity> {
        if self.accepted {
            None
        } else {
            Some(self.severity)
        }
    }
}
