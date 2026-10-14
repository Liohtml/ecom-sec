//! HTML output.
//!
//! * [`render_static`] produces the stand-alone report (`--format html`):
//!   a single self-contained file (inline CSS/JS/SVG, no external requests)
//!   meant for sharing and printing.  The report JSON is embedded and
//!   rendered client-side.
//! * [`render_web`] serves the interactive dashboard of `ecomsec serve`.

use ecomsec_core::finding::Category;
use ecomsec_core::Report;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};

/// Dashboard shell, stylesheet and script (served by `ecomsec serve`).
pub const WEB_INDEX_HTML: &str = include_str!("../../assets/app/index.html");
pub const WEB_APP_CSS: &str = include_str!("../../assets/app/app.css");
pub const WEB_APP_JS: &str = include_str!("../../assets/app/app.js");

/// Template of the stand-alone report.
pub const REPORT_HTML: &str = include_str!("../../assets/report.html");

const PLACEHOLDER: &str = "__REPORT_JSON__";

/// Finding fields whose (often repeated) values are interned into a string
/// table to keep reports with many findings small.
const INTERNED: [&str; 4] = ["title", "description", "rule", "group"];

/// Render the stand-alone report with the report embedded (no server
/// interaction, no external requests).
pub fn render_static(report: &Report) -> anyhow::Result<String> {
    let json = embed_json(&pack(report)?)?;
    Ok(REPORT_HTML.replacen(PLACEHOLDER, &json, 1))
}

/// Render the dashboard shell (data is fetched from `/api/*`).
pub fn render_web() -> String {
    WEB_INDEX_HTML.replace("__VERSION__", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod web_tests {
    use super::*;

    #[test]
    fn web_shell_references_assets_and_version() {
        let html = render_web();
        assert!(html.contains("app.css"));
        assert!(html.contains("app.js"));
        assert!(!html.contains("__VERSION__"));
        assert!(html.contains(env!("CARGO_PKG_VERSION")));
        // No external resources: the dashboard must work offline.
        for asset in [html.as_str(), WEB_APP_CSS, WEB_APP_JS] {
            assert!(!asset.contains("http://"), "external http reference");
            assert!(!asset.contains("src=\"https://"), "external script");
            assert!(!asset.contains("@import"), "css import");
        }
    }
}

/// Serialise a value for embedding inside a `<script>` element: every `<`
/// is written as `\u003c`, so neither `</script>` (in any letter case) nor
/// `<!--` can terminate or alter the script block.  The result is still
/// valid JSON and a valid JavaScript expression.
fn embed_json(value: &Value) -> anyhow::Result<String> {
    Ok(serde_json::to_string(value)?.replace('<', "\\u003c"))
}

/// Build the data object embedded into the report:
/// `{ report, strings, meta }`.  `report` is the regular report JSON with
/// interned finding strings (indices into `strings`) and file paths that
/// equal `<root>/<subject>` replaced by the flag `_p`.
fn pack(report: &Report) -> anyhow::Result<Value> {
    let mut value = serde_json::to_value(report)?;
    let root = report.platform.root.as_ref().map(|p| {
        p.to_string_lossy()
            .trim_end_matches(['/', '\\'])
            .to_string()
    });
    let mut strings: Vec<String> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    if let Some(findings) = value.get_mut("findings").and_then(Value::as_array_mut) {
        for finding in findings {
            let Some(obj) = finding.as_object_mut() else {
                continue;
            };
            for key in INTERNED {
                if let Some(Value::String(s)) = obj.get(key) {
                    let next = strings.len();
                    let i = *index.entry(s.clone()).or_insert(next);
                    if i == next {
                        strings.push(s.clone());
                    }
                    obj.insert(key.to_string(), json!(i));
                }
            }
            compact_path(obj, root.as_deref());
            // `accepted` defaults to false; only keep it when set.
            if obj.get("accepted") == Some(&Value::Bool(false)) {
                obj.remove("accepted");
            }
        }
    }
    let posture = report.posture();
    let mut categories: BTreeMap<String, &'static str> = BTreeMap::new();
    for f in &report.findings {
        categories.insert(category_key(f.category), f.category.label());
    }
    Ok(json!({
        "report": value,
        "strings": strings,
        "meta": {
            "generator": format!("ecomsec {}", env!("CARGO_PKG_VERSION")),
            "posture": posture,
            "grade_label": posture.grade.label(),
            "categories": categories,
        },
    }))
}

/// Drop `path` when it is exactly `<root>/<subject>`; the report script
/// reconstructs it.
fn compact_path(obj: &mut Map<String, Value>, root: Option<&str>) {
    let Some(root) = root else { return };
    let (Some(Value::String(path)), Some(Value::String(subject))) =
        (obj.get("path"), obj.get("subject"))
    else {
        return;
    };
    if *path == format!("{root}/{subject}") {
        obj.remove("path");
        obj.insert("_p".into(), json!(1));
    }
}

fn category_key(c: Category) -> String {
    serde_json::to_value(c)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{c:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_support::sample_report;

    #[test]
    fn static_report_embeds_data_without_placeholder() {
        let report = sample_report();
        let html = render_static(&report).unwrap();
        assert!(!html.contains(PLACEHOLDER));
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("Bekannter Webshell-Dateiname: wso.php"));
        assert!(html.contains("ioc_filename"));
        assert!(html.contains("\"score\":"));
        assert!(html.contains("\"verdict\":\"critical\""));
        assert!(html.contains("Bekannte Webshell"), "category labels");
        // No external resources.
        assert!(!html.contains("src=\"http"));
        assert!(!html.contains("<link "));
    }

    #[test]
    fn embedded_json_cannot_break_out_of_the_script() {
        let mut report = sample_report();
        report.findings[0].evidence = vec!["</SCRIPT><script>alert(1)</script><!--".into()];
        let html = render_static(&report).unwrap();
        let start = html.find("var PACK = ").unwrap();
        let end = html[start..].find("</script>").unwrap() + start;
        let script = &html[start..end];
        assert!(!script.to_ascii_lowercase().contains("<script"));
        assert!(!script.contains("<!--"));
        assert!(script.contains("\\u003c/SCRIPT>"));
    }

    #[test]
    fn pack_interns_strings_and_compacts_paths() {
        let report = sample_report();
        let packed = pack(&report).unwrap();
        let strings = packed["strings"].as_array().unwrap();
        let f0 = &packed["report"]["findings"][0];
        let title = f0["title"].as_u64().unwrap() as usize;
        assert_eq!(strings[title], report.findings[0].title.as_str());
        assert!(f0.get("path").is_none());
        assert_eq!(f0["_p"], 1);
        // Database findings keep their (absent) path and plain subject.
        let db = &packed["report"]["findings"][2];
        assert!(db.get("_p").is_none());
        assert_eq!(db["subject"], "tadminlogin:admin");
        // Identical strings are stored once.
        let mut sorted: Vec<&str> = strings.iter().map(|s| s.as_str().unwrap()).collect();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), strings.len());
        assert_eq!(
            packed["meta"]["categories"]["known_webshell"],
            "Bekannte Webshell"
        );
    }

    #[test]
    fn report_with_500_findings_stays_below_300_kb() {
        use ecomsec_core::finding::{Finding, Severity};
        let mut report = sample_report();
        let root = std::path::Path::new("/var/www/shop");
        let rules = [
            (
                "php_eval_base64",
                Category::SuspiciousPattern,
                Severity::Critical,
            ),
            (
                "modified_since_reference",
                Category::ModifiedSinceReference,
                Severity::Warning,
            ),
            (
                "php_in_upload_dir",
                Category::CodeInUploadDir,
                Severity::Critical,
            ),
            (
                "ctime_newer_than_mtime",
                Category::TimestampAnomaly,
                Severity::Info,
            ),
        ];
        for i in 0..500 {
            let (rule, cat, sev) = rules[i % rules.len()];
            let path = root.join(format!("includes/src/Module{}/Sub/Klasse{i}.php", i % 17));
            report.findings.push(
                Finding::file(
                    sev,
                    cat,
                    rule,
                    root,
                    &path,
                    format!("Auffällige Datei Klasse{i}.php"),
                )
                .with_description(
                    "Jede unbekannte Änderung an ausführbaren Dateien seit Bekanntwerden der \
                         Schwachstelle ist zu verifizieren (Update? Agentur? Plugin?). Unbekannte \
                         Dateien gelten bis zum Beweis des Gegenteils als Fremdcode.",
                )
                .with_evidence(format!("mtime=2026-07-{:02}T03:12:44+00:00", i % 28 + 1))
                .with_evidence("<?php eval(gzinflate(base64_decode(\"eJxLy8lPLy4p\")));"),
            );
        }
        let html = render_static(&report).unwrap();
        assert!(html.len() < 300 * 1024, "report has {} bytes", html.len());
    }
}
