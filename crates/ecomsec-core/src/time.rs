//! Points in time and calendar dates, and their text form in reports.
//!
//! Time stamps are [`jiff::Timestamp`] (always UTC), calendar dates
//! [`jiff::civil::Date`].  Up to version 0.2 the types came from `chrono`; the
//! JSON written since then is a stable interface (docs/ARCHITECTURE.md,
//! Report-Schema), so every `Timestamp` that is serialised goes through
//! [`serde_rfc3339`] (or [`serde_rfc3339::option`]):
//!
//! * written as RFC 3339 in UTC with `Z`, fractional seconds with 0, 3, 6 or 9
//!   digits, exactly as before (`2026-10-13T04:17:00Z`,
//!   `2026-10-13T04:17:00.500Z`, `2026-10-13T04:17:00.123456789Z`);
//! * read in that form and in every form the old `chrono` reader accepted
//!   (space instead of `T`, `UTC` suffix, `+01:00`/`+0100`/`+01` offsets, more
//!   than nine fractional digits), so older and hand-edited state files
//!   (history.json, accepted.json, baseline.json, reports/, checkpoint.json)
//!   keep loading.
//!
//! jiff covers the years -9999 to 9999 (up to `9999-12-30T22:00:00Z`).
//! Instants beyond that, which `chrono` could represent, saturate at
//! [`Timestamp::MIN`] / [`Timestamp::MAX`] when read or converted from file
//! times, so a state file with such a value stays readable and a file with an
//! absurd mtime is still reported as dated in the future.
//!
//! Dates serialise with jiff's own format (`2026-06-17`), which is the same as
//! before.

pub use jiff::civil::Date;
pub use jiff::{SignedDuration, Timestamp};

use jiff::tz::Offset;
use std::fmt::Write as _;

/// The current point in time.
pub fn now() -> Timestamp {
    Timestamp::now()
}

/// RFC 3339 in UTC with `Z` and 0, 3, 6 or 9 fractional digits (the report
/// format; `chrono`'s serde format before 0.3).
pub fn rfc3339(ts: Timestamp) -> String {
    let mut s = String::with_capacity(30);
    write_rfc3339(&mut s, ts, true);
    s
}

/// RFC 3339 in UTC with `+00:00` instead of `Z` (used in evidence strings such
/// as `mtime=…`; `chrono`'s `to_rfc3339()` before 0.3).
pub fn rfc3339_offset(ts: Timestamp) -> String {
    let mut s = String::with_capacity(35);
    write_rfc3339(&mut s, ts, false);
    s
}

/// RFC 3339 in UTC with whole seconds and `Z` (SARIF, SBOM).
pub fn rfc3339_seconds(ts: Timestamp) -> String {
    let dt = Offset::UTC.to_datetime(ts);
    let mut s = String::with_capacity(20);
    write_year(&mut s, dt.year());
    let _ = write!(
        s,
        "-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    );
    s
}

fn write_rfc3339(s: &mut String, ts: Timestamp, use_z: bool) {
    let dt = Offset::UTC.to_datetime(ts);
    write_year(s, dt.year());
    let _ = write!(
        s,
        "-{:02}-{:02}T{:02}:{:02}:{:02}",
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    );
    // Shortest of 0, 3, 6 or 9 digits without losing precision.
    let ns = dt.subsec_nanosecond();
    if ns == 0 {
    } else if ns % 1_000_000 == 0 {
        let _ = write!(s, ".{:03}", ns / 1_000_000);
    } else if ns % 1_000 == 0 {
        let _ = write!(s, ".{:06}", ns / 1_000);
    } else {
        let _ = write!(s, ".{ns:09}");
    }
    s.push_str(if use_z { "Z" } else { "+00:00" });
}

fn write_year(s: &mut String, year: i16) {
    if (0..=9999).contains(&year) {
        let _ = write!(s, "{year:04}");
    } else {
        let _ = write!(s, "{year:+05}");
    }
}

/// Parse an RFC 3339 time stamp with any offset.  Besides the strict form
/// this accepts what `chrono` accepted when reading state files: a space as
/// date/time separator, whitespace before the offset, `UTC` instead of `Z`,
/// offsets without colon or minutes and more than nine fractional digits.
pub fn parse_rfc3339(s: &str) -> Result<Timestamp, jiff::Error> {
    let err = match s.parse::<Timestamp>() {
        Ok(ts) => return Ok(ts),
        Err(err) => err,
    };
    let relaxed = relaxed(s);
    let found = [Some(s), relaxed.as_deref()]
        .into_iter()
        .flatten()
        .find_map(saturating);
    found.ok_or(err)
}

/// Parse date, time and offset separately; an instant outside jiff's range
/// saturates.
fn saturating(s: &str) -> Option<Timestamp> {
    let pieces = jiff::fmt::temporal::Pieces::parse(s).ok()?;
    let offset = pieces.to_numeric_offset()?;
    let dt = pieces.date().to_datetime(pieces.time()?);
    Some(offset.to_timestamp(dt).unwrap_or(if dt.year() > 0 {
        Timestamp::MAX
    } else {
        Timestamp::MIN
    }))
}

/// Bring the variants accepted by `chrono` into the form jiff parses.
fn relaxed(s: &str) -> Option<String> {
    let s = s.trim();
    // Date `Y-M-D`, then `T`/`t`/` `, then the rest.
    let sep = s.char_indices().find_map(|(i, c)| {
        (matches!(c, 'T' | 't' | ' ') && s[..i].matches('-').count() >= 2).then_some(i)
    })?;
    let (date, rest) = (&s[..sep], &s[sep + 1..]);
    let date: String = date.chars().filter(|c| !c.is_whitespace()).collect();
    // chrono writes signed years with four digits (`-0001`), jiff wants six.
    let date = match date.strip_prefix(['+', '-']) {
        Some(rest) => {
            let (year, month_day) = rest.split_once('-')?;
            format!("{}{year:0>6}-{month_day}", &date[..1])
        }
        None => date,
    };
    // Time `H:M:S[.fff]`, then an optional offset.
    let rest = rest.trim_start();
    let time_end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == ':' || c == '.' || c.is_whitespace()))
        .unwrap_or(rest.len());
    let (time, offset) = rest.split_at(time_end);
    let time: String = time.chars().filter(|c| !c.is_whitespace()).collect();
    let time = match time.split_once('.') {
        Some((hms, frac)) if frac.len() > 9 => format!("{hms}.{}", &frac[..9]),
        _ => time,
    };
    let offset = offset.trim();
    let offset = if offset.eq_ignore_ascii_case("utc") {
        "Z"
    } else {
        offset
    };
    if offset.is_empty() {
        return None;
    }
    Some(format!("{date}T{time}{offset}"))
}

/// A calendar date as `YYYY-MM-DD` (command line, dashboard API).
pub fn parse_date(s: &str) -> Result<Date, jiff::Error> {
    Date::strptime("%Y-%m-%d", s.trim())
}

/// A MySQL `DATETIME` / `TIMESTAMP` column as text (`2026-06-17 08:15:00`,
/// no time zone).  `None` for anything else, including zero dates.
pub fn parse_sql_datetime(s: &str) -> Option<jiff::civil::DateTime> {
    jiff::civil::DateTime::strptime("%Y-%m-%d %H:%M:%S", s).ok()
}

/// Calendar date of `ts` in UTC.
pub fn utc_date(ts: Timestamp) -> Date {
    Offset::UTC.to_datetime(ts).date()
}

/// Midnight UTC at the start of `date`.
pub fn utc_midnight(date: Date) -> Timestamp {
    Offset::UTC
        .to_timestamp(date.to_datetime(jiff::civil::Time::midnight()))
        .unwrap_or(Timestamp::MIN)
}

/// Time stamp from a file time, saturating outside jiff's range.
pub fn from_system_time(t: std::time::SystemTime) -> Timestamp {
    Timestamp::try_from(t).unwrap_or(if t > std::time::SystemTime::UNIX_EPOCH {
        Timestamp::MAX
    } else {
        Timestamp::MIN
    })
}

/// Time stamp from Unix seconds and nanoseconds, saturating outside jiff's
/// range.  `None` only when `nanos` is not in `0..1_000_000_000`.
pub fn from_unix(seconds: i64, nanos: i32) -> Option<Timestamp> {
    if !(0..1_000_000_000).contains(&nanos) {
        return None;
    }
    Some(Timestamp::new(seconds, nanos).unwrap_or(if seconds > 0 {
        Timestamp::MAX
    } else {
        Timestamp::MIN
    }))
}

/// `#[serde(with = "crate::time::serde_rfc3339")]` for [`Timestamp`] fields
/// (format see the module documentation).
pub mod serde_rfc3339 {
    use super::{parse_rfc3339, rfc3339, Timestamp};
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(ts: &Timestamp, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&rfc3339(*ts))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Timestamp, D::Error> {
        d.deserialize_str(Visitor)
    }

    struct Visitor;

    impl de::Visitor<'_> for Visitor {
        type Value = Timestamp;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("an RFC 3339 time stamp")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Timestamp, E> {
            parse_rfc3339(v).map_err(E::custom)
        }
    }

    /// The same for `Option<Timestamp>` (`null` / missing is `None`; combine
    /// with `#[serde(default)]`).
    pub mod option {
        use super::Timestamp;
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(ts: &Option<Timestamp>, s: S) -> Result<S::Ok, S::Error> {
            match ts {
                Some(ts) => super::serialize(ts, s),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Timestamp>, D::Error> {
            #[derive(Deserialize)]
            struct Wrap(#[serde(with = "super")] Timestamp);
            Ok(Option::<Wrap>::deserialize(d)?.map(|w| w.0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Formats of the same instants as written by ecomsec 0.2.0 (chrono).
    #[test]
    fn formats_match_chrono() {
        let fixture: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../tests/fixtures/chrono-0.2.0/edge/formats.json"
        ))
        .unwrap();
        assert_eq!(fixture.len(), 12);
        // The last one, 9999-12-31T23:59:59Z, is beyond jiff's range.
        let (beyond, fixture) = fixture.split_last().unwrap();
        assert_eq!(
            parse_rfc3339(beyond["serde"].as_str().unwrap()).unwrap(),
            Timestamp::MAX
        );
        for f in fixture {
            let ts = parse_rfc3339(f["serde"].as_str().unwrap()).unwrap();
            let s = |k: &str| f[k].as_str().unwrap().to_string();
            assert_eq!(rfc3339(ts), s("serde"));
            assert_eq!(rfc3339_offset(ts), s("rfc3339"));
            assert_eq!(rfc3339_seconds(ts), s("rfc3339_secs_z"));
            assert_eq!(ts.as_second(), f["unix"].as_i64().unwrap());
            assert_eq!(parse_rfc3339(&s("rfc3339")).unwrap(), ts);
            for (key, fmt) in [
                ("archive", crate::state::ARCHIVE_TS_FORMAT),
                ("de_minute", "%d.%m.%Y %H:%M UTC"),
                ("de_second", "%d.%m.%Y %H:%M:%S UTC"),
                ("iso_space", "%Y-%m-%d %H:%M:%S UTC"),
                ("compact_min", "%Y%m%d-%H%M"),
                ("compact_sec", "%Y%m%dT%H%M%SZ"),
                ("junit", "%Y-%m-%dT%H:%M:%S"),
            ] {
                assert_eq!(ts.strftime(fmt).to_string(), s(key), "{key}");
            }
            let date = utc_date(ts);
            assert_eq!(serde_json::to_value(date).unwrap(), f["date"]);
            assert_eq!(date.strftime("%d.%m.%Y").to_string(), s("date_de"));
            assert!(utc_midnight(date) <= ts);
        }
    }

    #[test]
    fn reads_what_chrono_read() {
        let t = parse_rfc3339("2026-10-13T04:17:00.5Z").unwrap();
        for s in [
            "2026-10-13T04:17:00.500Z",
            "2026-10-13t04:17:00.5z",
            "2026-10-13 04:17:00.5Z",
            "2026-10-13 04:17:00.5 UTC",
            "2026-10-13T04:17:00.5utc",
            "2026-10-13T06:17:00.5+02:00",
            "2026-10-13T06:17:00.5+0200",
            "2026-10-13T06:17:00.5+02",
            "2026-10-13T06:17:00.5 +02:00",
            "2026-10-13T02:17:00.5-02:00",
            "2026-10-13T04:17:00.500000000123Z",
            " 2026-10-13T04:17:00.5Z ",
        ] {
            assert_eq!(parse_rfc3339(s).ok(), Some(t), "{s}");
        }
        for bad in [
            "",
            "2026-10-13",
            "2026-10-13T04:17:00",
            "gestern",
            "1760329020",
        ] {
            assert!(parse_rfc3339(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn dates() {
        assert_eq!(
            parse_date("2026-06-17").unwrap(),
            jiff::civil::date(2026, 6, 17)
        );
        assert_eq!(
            parse_date(" 2026-6-7 ").unwrap(),
            jiff::civil::date(2026, 6, 7)
        );
        for bad in [
            "",
            "17.06.2026",
            "2026-02-30",
            "2026-06-17T00:00",
            "20260617x",
        ] {
            assert!(parse_date(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn sql_datetimes() {
        let d = parse_sql_datetime("2026-06-17 08:15:00").unwrap();
        assert_eq!(d.date(), jiff::civil::date(2026, 6, 17));
        assert_eq!((d.hour(), d.minute(), d.second()), (8, 15, 0));
        assert_eq!(
            parse_sql_datetime("2026-6-7 8:5:3").map(|d| d.date()),
            Some(jiff::civil::date(2026, 6, 7))
        );
        for bad in [
            "",
            "0000-00-00 00:00:00",
            "2026-02-30 00:00:00",
            "2026-06-17",
            "2026-06-17 08:15:00.123456",
            "2026-06-17T08:15:00Z",
        ] {
            assert_eq!(parse_sql_datetime(bad), None, "{bad}");
        }
    }

    #[test]
    fn out_of_range_saturates() {
        assert_eq!(
            parse_rfc3339("9999-12-31T23:59:59Z").unwrap(),
            Timestamp::MAX
        );
        assert_eq!(
            parse_rfc3339("9999-12-31 23:59:59 UTC").unwrap(),
            Timestamp::MAX
        );
        assert_eq!(
            parse_rfc3339("-9999-01-01T00:00:00+01:00").unwrap(),
            Timestamp::MIN
        );
        assert_eq!(from_unix(i64::MAX, 0), Some(Timestamp::MAX));
        assert_eq!(from_unix(i64::MIN, 0), Some(Timestamp::MIN));
        assert_eq!(from_unix(0, 1_000_000_000), None);
        let far =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(300_000_000_000);
        assert_eq!(from_system_time(far), Timestamp::MAX);
        assert_eq!(rfc3339(Timestamp::MAX), "9999-12-30T22:00:00.999999999Z");
        assert_eq!(rfc3339(Timestamp::MIN), "-9999-01-02T01:59:59Z");
        for ts in [Timestamp::MIN, Timestamp::MAX] {
            assert_eq!(parse_rfc3339(&rfc3339(ts)).unwrap(), ts);
            assert_eq!(parse_rfc3339(&rfc3339_offset(ts)).unwrap(), ts);
        }
        assert_eq!(
            rfc3339(parse_rfc3339("-0001-06-01T00:00:00Z").unwrap()),
            "-0001-06-01T00:00:00Z"
        );
    }

    #[test]
    fn serde_helpers() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct S {
            #[serde(with = "serde_rfc3339")]
            at: Timestamp,
            #[serde(
                default,
                with = "serde_rfc3339::option",
                skip_serializing_if = "Option::is_none"
            )]
            maybe: Option<Timestamp>,
        }
        let at = from_unix(1_791_865_020, 120_000_000).unwrap();
        let v = S {
            at,
            maybe: Some(at),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(
            json,
            r#"{"at":"2026-10-13T04:17:00.120Z","maybe":"2026-10-13T04:17:00.120Z"}"#
        );
        assert_eq!(serde_json::from_str::<S>(&json).unwrap(), v);
        let none: S = serde_json::from_str(r#"{"at":"2026-10-13T04:17:00.12Z"}"#).unwrap();
        assert_eq!(none.maybe, None);
        let null: S =
            serde_json::from_str(r#"{"at":"2026-10-13T04:17:00Z","maybe":null}"#).unwrap();
        assert_eq!(null.maybe, None);
        assert!(serde_json::from_str::<S>(r#"{"at":1760329020}"#).is_err());
    }
}
