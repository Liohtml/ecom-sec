//! Compatibility with JSON written by older versions.
//!
//! The files below `fixtures/chrono-0.2.0/` were produced by ecomsec 0.2.0
//! (time types from `chrono`): a real state directory from a JTL-Shop scan
//! (`state/`), the JSON output of `ecomsec diff`, a file-scan checkpoint and
//! hand-picked instants with every fractional-second width (`edge/`).
//!
//! Every file must still load, and writing it again must give the same bytes:
//! the report JSON is a stable interface (docs/ARCHITECTURE.md, Report-Schema).

use ecomsec_core::baseline::Baseline;
use ecomsec_core::report::HistoryEntry;
use ecomsec_core::state::AcceptedFindings;
use ecomsec_core::{Report, ReportDiff, StateStore};
use serde::{de::DeserializeOwned, Serialize};
use std::path::{Path, PathBuf};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chrono-0.2.0")
}

fn read(rel: &str) -> String {
    let p = fixtures().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// Parse `rel` as `T`, write it back with `to_string_pretty` (as the state
/// store and `--format json` do) and require identical text.
fn assert_round_trip<T: Serialize + DeserializeOwned>(rel: &str) -> T {
    let original = read(rel);
    let value: T =
        serde_json::from_str(&original).unwrap_or_else(|e| panic!("{rel} does not load: {e}"));
    let written = serde_json::to_string_pretty(&value).unwrap();
    if written != original.trim_end_matches('\n') {
        let line = written
            .lines()
            .zip(original.lines())
            .position(|(a, b)| a != b)
            .unwrap_or(0);
        panic!(
            "{rel} changed on round trip, first difference in line {}:\n  old: {}\n  new: {}",
            line + 1,
            original.lines().nth(line).unwrap_or(""),
            written.lines().nth(line).unwrap_or("")
        );
    }
    value
}

#[test]
fn last_report_round_trips_unchanged() {
    let r: Report = assert_round_trip("state/last-report.json");
    assert_eq!(r.reference_date.to_string(), "2026-06-17");
    assert!(r.findings.iter().any(|f| f.review.is_some()));
}

#[test]
fn archived_reports_round_trip_unchanged() {
    assert_round_trip::<Report>("state/reports/20261125T082539.222Z.json");
    assert_round_trip::<Report>("state/reports/20261125T082539.643Z.json");
}

#[test]
fn history_accepted_and_baseline_round_trip_unchanged() {
    let h: Vec<HistoryEntry> = assert_round_trip("state/history.json");
    assert_eq!(h.len(), 4);
    let a: AcceptedFindings = assert_round_trip("state/accepted.json");
    assert_eq!(a.findings.len(), 1);
    assert_round_trip::<Baseline>("state/baseline.json");
}

#[test]
fn diff_output_round_trips_unchanged() {
    let d: ReportDiff = assert_round_trip("diff.json");
    assert!(d.before_generated_at.is_some());
}

#[test]
fn every_fractional_second_width_round_trips_unchanged() {
    let h: Vec<HistoryEntry> = assert_round_trip("edge/history.json");
    assert_eq!(h.len(), 12);
    assert_round_trip::<AcceptedFindings>("edge/accepted.json");
}

#[test]
fn state_store_reads_old_state_directory() {
    let store = StateStore::new(fixtures().join("state"));
    let last = store.last_report().expect("last-report.json");
    assert_eq!(store.history().len(), 4);
    assert_eq!(store.accepted().findings.len(), 1);
    assert!(store.baseline().is_some());

    let stamps = store.archived_stamps();
    assert_eq!(stamps, ["20261125T082539.222Z", "20261125T082539.643Z"]);
    let newest = store.latest_archived_report().expect("archived report");
    assert_eq!(newest.generated_at, last.generated_at);
    assert!(store.archived_report(&stamps[0]).is_some());

    let previous = store
        .previous_report(last.generated_at)
        .expect("previous report");
    let first = store.archived_report(&stamps[0]).unwrap();
    assert_eq!(previous.generated_at, first.generated_at);
    assert!(first.generated_at < last.generated_at);
}
