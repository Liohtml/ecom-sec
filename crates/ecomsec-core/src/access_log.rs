//! Read-only search for attack traces in web server access logs.
//!
//! Adapters describe what to look for ([`LogIndicator`], e.g. the request
//! pattern of a published exploit); the engine streams the configured log
//! files (plain or gzip-compressed, Apache/nginx "combined" format or anything
//! line based) and aggregates the hits per indicator into one finding.

use crate::finding::{Category, Finding, Severity, Source};
use regex::Regex;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

/// Well-known log directories checked by `--access-log auto`.
pub const AUTO_LOG_DIRS: &[&str] = &[
    "/var/log/apache2",
    "/var/log/httpd",
    "/var/log/nginx",
    "/var/log/lighttpd",
    "/var/www/logs",
];

/// Maximum number of example lines and source addresses kept per indicator.
const MAX_SAMPLES: usize = 3;
const MAX_IPS: usize = 10;
/// Lines longer than this are cut before matching (protects against binary junk).
const MAX_LINE: usize = 16 * 1024;

/// One thing to look for in access logs.
#[derive(Debug, Clone)]
pub struct LogIndicator {
    /// Stable rule id, e.g. `jtl5_log_safemode_toggle`.
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    /// Matched against the whole log line.
    pub pattern: Regex,
    /// Related advisory (CVE id …), shown in the evidence.
    pub advisory: Option<String>,
}

impl LogIndicator {
    pub fn new(
        id: &str,
        severity: Severity,
        title: &str,
        description: &str,
        pattern: &str,
        advisory: Option<&str>,
    ) -> Self {
        LogIndicator {
            id: id.to_string(),
            severity,
            title: title.to_string(),
            description: description.to_string(),
            pattern: Regex::new(pattern).expect("log indicator regex"),
            advisory: advisory.map(str::to_string),
        }
    }
}

/// Result of a log scan.
#[derive(Debug, Default)]
pub struct LogScan {
    pub findings: Vec<Finding>,
    pub files: Vec<PathBuf>,
    pub lines: u64,
    pub limitations: Vec<String>,
}

#[derive(Default)]
struct Hits {
    count: u64,
    files: BTreeSet<String>,
    ips: BTreeSet<String>,
    first: Option<String>,
    last: Option<String>,
    samples: Vec<String>,
}

/// Expand the configured locations into log files.  `auto` stands for the
/// usual system log directories; directories contribute every file whose name
/// contains `access` (incl. rotated `.1` / `.gz` files).
pub fn expand(locations: &[PathBuf]) -> (Vec<PathBuf>, Vec<String>) {
    let mut files = BTreeSet::new();
    let mut notes = Vec::new();
    for loc in locations {
        if loc.as_os_str() == "auto" {
            let mut found = false;
            for dir in AUTO_LOG_DIRS {
                let n = collect_dir(Path::new(dir), &mut files);
                found |= n > 0;
            }
            if !found {
                notes.push(format!(
                    "Keine lesbaren Access-Logs in den üblichen Verzeichnissen gefunden ({}); Pfad mit --access-log angeben.",
                    AUTO_LOG_DIRS.join(", ")
                ));
            }
        } else if loc.is_dir() {
            if collect_dir(loc, &mut files) == 0 {
                notes.push(format!(
                    "Im Verzeichnis {} wurden keine Access-Logs (*access*) gefunden.",
                    loc.display()
                ));
            }
        } else if loc.is_file() {
            files.insert(loc.clone());
        } else {
            notes.push(format!("Access-Log {} nicht gefunden.", loc.display()));
        }
    }
    (files.into_iter().collect(), notes)
}

fn collect_dir(dir: &Path, out: &mut BTreeSet<PathBuf>) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut n = 0;
    for entry in rd.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if path.is_file() && name.contains("access") {
            out.insert(path);
            n += 1;
        }
    }
    n
}

fn open(path: &Path) -> std::io::Result<Box<dyn BufRead>> {
    let file = File::open(path)?;
    let gz = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("gz"))
        .unwrap_or(false);
    Ok(if gz {
        Box::new(BufReader::new(flate2::read::MultiGzDecoder::new(file)))
    } else {
        Box::new(BufReader::new(file))
    })
}

/// Client address: first token of the common/combined log format.
fn client_ip(line: &str) -> Option<&str> {
    let tok = line.split_whitespace().next()?;
    let looks_like_ip = tok.len() <= 45
        && tok
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
        && (tok.contains('.') || tok.contains(':'));
    looks_like_ip.then_some(tok)
}

/// Timestamp in `[...]` (common/combined log format).
fn timestamp(line: &str) -> Option<&str> {
    let start = line.find('[')? + 1;
    let end = start + line[start..].find(']')?;
    Some(&line[start..end])
}

fn shorten(line: &str) -> String {
    const MAX: usize = 300;
    if line.chars().count() <= MAX {
        line.to_string()
    } else {
        format!("{}…", line.chars().take(MAX).collect::<String>())
    }
}

/// Scan `files` for `indicators`.
pub fn scan(files: &[PathBuf], indicators: &[LogIndicator]) -> LogScan {
    let mut result = LogScan::default();
    if indicators.is_empty() {
        return result;
    }
    let mut hits: Vec<Hits> = indicators.iter().map(|_| Hits::default()).collect();
    for path in files {
        let reader = match open(path) {
            Ok(r) => r,
            Err(e) => {
                result
                    .limitations
                    .push(format!("Access-Log {} nicht lesbar: {e}", path.display()));
                continue;
            }
        };
        result.files.push(path.clone());
        let label = path.display().to_string();
        let mut buf = Vec::new();
        let mut reader = reader;
        loop {
            buf.clear();
            match reader
                .by_ref()
                .take(MAX_LINE as u64 * 64)
                .read_until(b'\n', &mut buf)
            {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => {
                    result.limitations.push(format!(
                        "Access-Log {} nur teilweise gelesen: {e}",
                        path.display()
                    ));
                    break;
                }
            }
            result.lines += 1;
            buf.truncate(MAX_LINE);
            let line = String::from_utf8_lossy(&buf);
            let line = line.trim_end();
            for (ind, h) in indicators.iter().zip(hits.iter_mut()) {
                if !ind.pattern.is_match(line) {
                    continue;
                }
                h.count += 1;
                h.files.insert(label.clone());
                if let Some(ip) = client_ip(line) {
                    if h.ips.len() < MAX_IPS {
                        h.ips.insert(ip.to_string());
                    }
                }
                if let Some(ts) = timestamp(line) {
                    if h.first.is_none() {
                        h.first = Some(ts.to_string());
                    }
                    h.last = Some(ts.to_string());
                }
                if h.samples.len() < MAX_SAMPLES {
                    h.samples.push(shorten(line));
                }
            }
        }
    }
    for (ind, h) in indicators.iter().zip(hits) {
        if h.count == 0 {
            continue;
        }
        let mut summary = format!("{} Treffer in {} Datei(en)", h.count, h.files.len());
        if let Some(a) = &ind.advisory {
            summary.push_str(&format!(" · {a}"));
        }
        if let (Some(first), Some(last)) = (&h.first, &h.last) {
            summary.push_str(&format!(" · Zeitraum {first} – {last}"));
        }
        if !h.ips.is_empty() {
            summary.push_str(&format!(
                " · Absender: {}",
                h.ips.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
        let mut f = Finding::new(
            ind.severity,
            Category::AttackTrace,
            Source::AccessLog,
            ind.id.clone(),
            format!("access-log:{}", ind.id),
            ind.title.clone(),
        )
        .with_description(ind.description.clone())
        .with_evidence(summary);
        for s in h.samples {
            f = f.with_evidence(s);
        }
        result.findings.push(f);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn indicator() -> LogIndicator {
        LogIndicator::new(
            "test_safemode",
            Severity::Warning,
            "Safe-Mode umgeschaltet",
            "Beschreibung",
            r#"(?i)"(?:GET|POST|HEAD) [^"]*/admin/logout[^"\s]*[?&]safemode="#,
            Some("CVE-2026-103905"),
        )
    }

    const HIT: &str = r#"203.0.113.7 - - [14/Oct/2026:09:12:01 +0200] "GET /admin/logout?safemode=1 HTTP/1.1" 302 0 "https://evil.example/" "Mozilla/5.0""#;
    const MISS: &str = r#"198.51.100.2 - - [14/Oct/2026:09:13:00 +0200] "GET /admin/logout HTTP/1.1" 302 0 "-" "Mozilla/5.0""#;

    #[test]
    fn finds_hits_in_plain_and_gzip_logs() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("access.log");
        std::fs::write(&plain, format!("{MISS}\n{HIT}\n")).unwrap();
        let gz = dir.path().join("access.log.2.gz");
        let mut enc = flate2::write::GzEncoder::new(
            File::create(&gz).unwrap(),
            flate2::Compression::default(),
        );
        writeln!(enc, "{HIT}").unwrap();
        enc.finish().unwrap();
        std::fs::write(dir.path().join("error.log"), HIT).unwrap();

        let (files, notes) = expand(&[dir.path().to_path_buf()]);
        assert!(notes.is_empty());
        assert_eq!(files.len(), 2, "error.log must be ignored");
        let scan = scan(&files, &[indicator()]);
        assert_eq!(scan.lines, 3);
        assert_eq!(scan.findings.len(), 1);
        let f = &scan.findings[0];
        assert_eq!(f.source, Source::AccessLog);
        assert_eq!(f.category, Category::AttackTrace);
        assert!(f.evidence[0].starts_with("2 Treffer in 2 Datei(en) · CVE-2026-103905"));
        assert!(f.evidence[0].contains("203.0.113.7"));
        assert!(!f.evidence[0].contains("198.51.100.2"));
    }

    #[test]
    fn no_finding_without_hits_and_missing_paths_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("shop-access.log");
        std::fs::write(&log, format!("{MISS}\n")).unwrap();
        let (files, notes) = expand(&[log, dir.path().join("fehlt.log")]);
        assert_eq!(files.len(), 1);
        assert_eq!(notes.len(), 1);
        assert!(scan(&files, &[indicator()]).findings.is_empty());
    }

    #[test]
    fn parses_ip_and_timestamp() {
        assert_eq!(client_ip(HIT), Some("203.0.113.7"));
        assert_eq!(client_ip("- - foo"), None);
        assert_eq!(timestamp(HIT), Some("14/Oct/2026:09:12:01 +0200"));
    }
}
