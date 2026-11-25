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
    assert_round_trip::<AcceptedFindings>("edge/accepted.json");
    // The last history entry, 9999-12-31T23:59:59Z, lies beyond the range of
    // jiff (up to 9999-12-30T22:00:00Z): it still loads, saturated at the
    // maximum.  Everything else is written back unchanged.
    let original = read("edge/history.json");
    let h: Vec<HistoryEntry> = serde_json::from_str(&original).unwrap();
    assert_eq!(h.len(), 12);
    assert_eq!(h[11].generated_at, ecomsec_core::time::Timestamp::MAX);
    let written = serde_json::to_string_pretty(&h).unwrap();
    let expected = original.replace(
        "\"9999-12-31T23:59:59Z\"",
        "\"9999-12-30T22:00:00.999999999Z\"",
    );
    assert_eq!(written, expected.trim_end());
}

/// Replace every RFC 3339 time stamp string in `v` with `to`.
fn set_timestamps(v: &mut serde_json::Value, to: &str) -> usize {
    match v {
        serde_json::Value::String(s) => {
            let b = s.as_bytes();
            let looks_like_ts = b.len() >= 20
                && b[4] == b'-'
                && b[10] == b'T'
                && b[13] == b':'
                && s.ends_with('Z')
                && s[..4].bytes().all(|c| c.is_ascii_digit());
            if looks_like_ts {
                *s = to.to_string();
                1
            } else {
                0
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().map(|x| set_timestamps(x, to)).sum(),
        serde_json::Value::Object(o) => o.values_mut().map(|x| set_timestamps(x, to)).sum(),
        _ => 0,
    }
}

/// Every time stamp field keeps the 0/3/6/9-digit form, whatever its value:
/// with all of them set to `.500` (which a plain jiff serialiser would
/// shorten to `.5`), the files still round-trip unchanged.
#[test]
fn every_time_stamp_field_uses_the_report_format() {
    fn check<T: Serialize + DeserializeOwned>(rel: &str, at_least: usize) {
        let mut v: serde_json::Value = serde_json::from_str(&read(rel)).unwrap();
        let n = set_timestamps(&mut v, "2026-11-25T08:25:39.500Z");
        assert!(n >= at_least, "{rel}: only {n} time stamps");
        let typed: T = serde_json::from_value(v.clone()).unwrap();
        // Compare via text: `to_value` would widen f32 fields (0.6 → 0.6000000238…).
        let written: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&typed).unwrap()).unwrap();
        assert!(written == v, "{rel} changed");
    }
    check::<Report>("state/last-report.json", 2);
    check::<Vec<HistoryEntry>>("state/history.json", 4);
    check::<AcceptedFindings>("state/accepted.json", 1);
    check::<Baseline>("state/baseline.json", 1);
    check::<ReportDiff>("diff.json", 2);
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
