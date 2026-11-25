//! `last-audit.json` / `audit-<ts>.json` written by ecomsec 0.2.0 (time
//! types from `chrono`) still load and are written back unchanged.

use ecomsec_audit::AuditReport;

#[test]
fn audit_report_from_older_version_round_trips() {
    let old = include_str!("fixtures/chrono-0.2.0/last-audit.json");
    let audit: AuditReport = serde_json::from_str(old).expect("old audit report loads");
    assert_eq!(audit.file_name(), "audit-20261125T082539Z.json");
    assert!(audit.started <= audit.finished);
    assert_eq!(
        serde_json::to_string_pretty(&audit).unwrap(),
        old.trim_end()
    );
}
