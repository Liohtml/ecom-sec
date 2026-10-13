//! Candidate selection for `--mode hunt`: custom code (plugins, templates,
//! theme scripts) ranked by risk heuristics within a file and size budget.

use chrono::{DateTime, NaiveDate, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::OnceLock;
use walkdir::WalkDir;

/// A file suggested to the model for a code review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntCandidate {
    pub path: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<DateTime<Utc>>,
    /// Heuristic hits (`name`, count).
    pub hits: Vec<(String, usize)>,
    pub score: u32,
}

/// Directories with custom (non-vendor) code per platform.
pub fn custom_code_dirs(platform_id: &str) -> &'static [&'static str] {
    match platform_id {
        "jtl5" => &["plugins", "includes/plugins", "templates", "includes/ext"],
        "shopware6" => &[
            "custom/plugins",
            "custom/static-plugins",
            "custom/apps",
            "src",
            "templates",
        ],
        _ => &["."],
    }
}

const SKIP_DIRS: &[&str] = &[
    "vendor",
    "node_modules",
    ".git",
    "tests",
    "Test",
    "Tests",
    "dist",
    "build",
    "templates_c",
    "cache",
];

const EXTENSIONS: &[&str] = &["php", "phtml", "inc", "tpl", "twig", "js", "mjs", "ts"];

struct Heuristic {
    name: &'static str,
    weight: u32,
    re: Regex,
}

fn heuristics() -> &'static [Heuristic] {
    static H: OnceLock<Vec<Heuristic>> = OnceLock::new();
    H.get_or_init(|| {
        let h = |name, weight, re: &str| Heuristic {
            name,
            weight,
            re: Regex::new(re).expect("valid heuristic"),
        };
        vec![
            h("superglobal", 2, r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b"),
            h(
                "sql_concat",
                5,
                r#"(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b[^;\n]{0,160}["']\s*\.\s*\$"#,
            ),
            h(
                "raw_query",
                2,
                r"->(query|executeQuery|executeStatement|exec|getRow|getObjects|queryPrepared|fetchAll|fetchAssociative)\s*\(",
            ),
            h("mysqli", 4, r"(?i)\b(mysqli_query|mysql_query)\s*\("),
            h(
                "code_exec",
                5,
                r"\b(eval|assert|system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(",
            ),
            h("unserialize", 4, r"\bunserialize\s*\("),
            h(
                "file_op_var",
                3,
                r"\b(move_uploaded_file|file_put_contents|fopen|copy|rename|unlink|include|require|include_once|require_once)\s*\(?\s*\$",
            ),
            h(
                "raw_output",
                2,
                r"\|raw\b|nofilter|\{\{\{|innerHTML\s*=|document\.write\(|\.html\(\s*[A-Za-z_$]",
            ),
            h("echo_input", 4, r"\becho\s+\$_(GET|POST|REQUEST)"),
            h(
                "ssrf",
                3,
                r"\b(curl_exec|file_get_contents|fsockopen)\s*\(\s*\$",
            ),
            h(
                "hardcoded_secret",
                3,
                r#"(?i)(api[_-]?key|secret|password|passwort|token)\s*(=>|=|:)\s*['"][^'"$]{8,}['"]"#,
            ),
            h(
                "obfuscation",
                4,
                r"base64_decode|gzinflate|gzuncompress|str_rot13|(\\x[0-9a-fA-F]{2}){4,}",
            ),
            h(
                "template_eval",
                4,
                r"\{eval\b|\{php\}|\{include\s+file=\$|registerPlugin\s*\(|template_from_string|createTemplate\s*\(\s*\$",
            ),
        ]
    })
}

/// Collect and rank candidate files below the platform's custom code
/// directories.  At most `max_files` files and `max_bytes` bytes in total.
pub fn hunt_candidates(
    root: &Path,
    platform_id: &str,
    reference_date: NaiveDate,
    max_files: usize,
    max_bytes: u64,
) -> Vec<HuntCandidate> {
    let reference = reference_date
        .and_hms_opt(0, 0, 0)
        .map(|d| d.and_utc())
        .unwrap_or_else(Utc::now);
    let mut all: Vec<HuntCandidate> = Vec::new();
    let mut visited = 0usize;
    for dir in custom_code_dirs(platform_id) {
        let base = root.join(dir);
        if !base.is_dir() {
            continue;
        }
        let walker = WalkDir::new(&base)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                !(e.file_type().is_dir()
                    && SKIP_DIRS.contains(&e.file_name().to_string_lossy().as_ref()))
            });
        for entry in walker.flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            visited += 1;
            if visited > 50_000 {
                break;
            }
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            let ext = name.rsplit('.').next().unwrap_or("");
            if !EXTENSIONS.contains(&ext) || name.ends_with(".min.js") {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            let size = meta.len();
            if size == 0 || size > 512 * 1024 {
                continue;
            }
            let Ok(bytes) = std::fs::read(path) else {
                continue;
            };
            let text = String::from_utf8_lossy(&bytes);
            let mut hits = Vec::new();
            let mut score = 0u32;
            for h in heuristics() {
                let n = h.re.find_iter(&text).count();
                if n > 0 {
                    score += h.weight * (n.min(5) as u32);
                    hits.push((h.name.to_string(), n));
                }
            }
            if score == 0 {
                continue;
            }
            let modified: Option<DateTime<Utc>> = meta.modified().ok().map(DateTime::from);
            if modified.map(|m| m >= reference).unwrap_or(false) {
                score += 6;
            }
            let rel = ecomsec_core::util::relative_display(root, path);
            all.push(HuntCandidate {
                path: rel,
                size,
                modified,
                hits,
                score,
            });
        }
    }
    // Highest risk first; prefer smaller files on ties (cheaper to review).
    all.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then(a.size.cmp(&b.size))
            .then(a.path.cmp(&b.path))
    });
    let mut out = Vec::new();
    let mut total = 0u64;
    for c in all {
        if out.len() >= max_files {
            break;
        }
        if total + c.size > max_bytes {
            continue;
        }
        total += c.size;
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranks_risky_custom_code_first() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let write = |rel: &str, body: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        write(
            "plugins/acme/Frontend.php",
            "<?php $db->query(\"SELECT * FROM tkunde WHERE kKunde = \" . $_GET['id']);",
        );
        write("plugins/acme/harmless.php", "<?php return 1;");
        write("plugins/acme/vendor/lib.php", "<?php eval($_POST['x']);");
        write("templates/x/app.min.js", "document.write(x)");
        let c = hunt_candidates(
            root,
            "jtl5",
            NaiveDate::from_ymd_opt(2000, 1, 1).unwrap(),
            10,
            1_000_000,
        );
        assert_eq!(c.len(), 1, "{c:?}");
        assert_eq!(c[0].path, "plugins/acme/Frontend.php");
        assert!(c[0].hits.iter().any(|(n, _)| n == "sql_concat"));
    }
}
