//! # ecomsec-core
//!
//! Platform-agnostic compromise-check engine ("Kompromittierungs-Check") for
//! e-commerce installations.  The engine is deliberately read-only: it never
//! modifies a shop, never contacts external services and works without SSH or
//! root access as long as the web root (and optionally the database) is
//! readable.
//!
//! The crate provides:
//!
//! * a [`Finding`] model with severities, categories and stable identifiers,
//! * a YARA-like rule engine ([`rules`]) driven by embedded signature files,
//! * a resumable, time-budgeted file scanner ([`engine::file_scan`]),
//! * the [`Platform`] trait that shop adapters (JTL-Shop 5, Shopware 6,
//!   Shopify, …) implement to contribute paths, version/CVE knowledge and
//!   integrity checks,
//! * persistent state for risk acceptance, baselines and scan history
//!   ([`state`]),
//! * change detection between two reports ([`diff`]),
//! * prioritised recommendations ([`recommendations`]),
//! * a deterministic security posture score with grade ([`score`]),
//! * a read-only search for attack traces in web server logs ([`access_log`]).

pub mod access_log;
pub mod advisories;
pub mod baseline;
pub mod db;
pub mod diff;
pub mod engine;
pub mod finding;
pub mod hosts;
pub mod platform;
pub mod recommendations;
pub mod report;
pub mod rules;
pub mod score;
pub mod signatures;
pub mod state;
pub mod util;
pub mod version;

pub use advisories::{AdvisoryDb, AdvisorySpec};
pub use diff::ReportDiff;
pub use engine::{Engine, ScanOptions, ScanOutcome};
pub use finding::{Category, Finding, FindingId, Review, ReviewVerdict, Severity};
pub use platform::{
    Advisory, ComponentVersion, FileScanProfile, IntegrityItem, IntegrityStatus, Platform,
    PlatformContext, PlatformInfo, PlatformKind,
};
pub use recommendations::{Recommendation, RecommendationGroup};
pub use report::{Report, Summary, Verdict};
pub use rules::{Rule, RuleSet};
pub use score::{Grade, PostureScore, ScoreDriver};
pub use state::StateStore;
pub use version::Version;
