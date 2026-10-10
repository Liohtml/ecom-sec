//! Composer dependency inventory and OSV.dev lookup.
//!
//! Self-hosted shops ship their PHP dependencies as Composer packages
//! (`composer.lock`, `vendor/composer/installed.json`).  With `--online` the
//! package names and exact versions are sent to <https://api.osv.dev>, which
//! aggregates the GitHub Advisory Database, FriendsOfPHP security advisories
//! and vendor advisories for the Packagist ecosystem.  That covers Shopware
//! core and Composer-distributed plugins as well as the libraries bundled
//! with JTL-Shop (Smarty, Symfony, Guzzle, …) – always up to date, without a
//! release of this tool.
//!
//! Nothing but package name and version leaves the machine.

use ecomsec_core::finding::{Category, Finding, Severity, Source};
use ecomsec_core::platform::{IntegrityItem, IntegrityStatus};
use ecomsec_core::version::Version;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

pub const OSV_API: &str = "https://api.osv.dev/v1";

#[derive(Debug, Error)]
pub enum OsvError {
    #[error("OSV-Anfrage fehlgeschlagen: {0}")]
    Http(String),
    #[error("OSV-Antwort ungültig: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposerPackage {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub dev: bool,
}

/// Normalise Composer version strings (`v6.5.7.4`, `6.5.7.4.0`, `dev-main`).
fn clean_version(v: &str) -> Option<String> {
    let v = v.trim().trim_start_matches(['v', 'V']);
    if v.starts_with("dev-") || v.ends_with("-dev") || v.is_empty() {
        return None;
    }
    Some(v.to_string())
}

/// Parse `composer.lock`.
pub fn read_composer_lock(text: &str) -> Vec<ComposerPackage> {
    let json: Value = match serde_json::from_str(text) {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for (key, dev) in [("packages", false), ("packages-dev", true)] {
        if let Some(arr) = json.get(key).and_then(|v| v.as_array()) {
            for p in arr {
                if let (Some(name), Some(version)) = (
                    p.get("name").and_then(|n| n.as_str()),
                    p.get("version")
                        .and_then(|v| v.as_str())
                        .and_then(clean_version),
                ) {
                    out.push(ComposerPackage {
                        name: name.to_string(),
                        version,
                        dev,
                    });
                }
            }
        }
    }
    out
}

/// Parse `vendor/composer/installed.json` (Composer 1: array, Composer 2:
/// `{"packages": [...], "dev-package-names": [...]}`).
pub fn read_installed_json(text: &str) -> Vec<ComposerPackage> {
    let json: Value = match serde_json::from_str(text) {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };
    let dev_names: BTreeSet<String> = json
        .get("dev-package-names")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let arr = json
        .get("packages")
        .and_then(|v| v.as_array())
        .cloned()
        .or_else(|| json.as_array().cloned())
        .unwrap_or_default();
    arr.iter()
        .filter_map(|p| {
            let name = p.get("name")?.as_str()?;
            let version = p.get("version")?.as_str().and_then(clean_version)?;
            Some(ComposerPackage {
                name: name.to_string(),
                version,
                dev: dev_names.contains(name),
            })
        })
        .collect()
}

/// Load the dependency inventory of an installation from the first existing
/// candidate (relative to `root`).  Returns packages and the source file.
pub fn load_inventory(root: &Path, candidates: &[&str]) -> Option<(Vec<ComposerPackage>, String)> {
    for rel in candidates {
        let path = root.join(rel);
        if let Ok(text) = std::fs::read_to_string(&path) {
            let packages = if rel.ends_with("composer.lock") {
                read_composer_lock(&text)
            } else {
                read_installed_json(&text)
            };
            if !packages.is_empty() {
                return Some((packages, rel.to_string()));
            }
        }
    }
    None
}

/// A vulnerability affecting one installed package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub summary: String,
    /// `CRITICAL`, `HIGH`, `MODERATE`, `LOW` or `UNKNOWN`.
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<String>,
    /// Fixed versions for the affected package (first fix on/after the
    /// installed version first).
    #[serde(default)]
    pub fixed_in: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageResult {
    pub package: ComposerPackage,
    pub vulns: Vec<Vulnerability>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LookupResult {
    pub results: Vec<PackageResult>,
    pub packages_checked: usize,
    pub vulnerable_packages: usize,
    pub limitations: Vec<String>,
}

pub struct OsvClient {
    agent: ureq::Agent,
    base: String,
    /// Upper bound of detail requests (one per distinct vulnerability).
    pub max_details: usize,
}

impl Default for OsvClient {
    fn default() -> Self {
        OsvClient::new(OSV_API)
    }
}

impl OsvClient {
    pub fn new(base: &str) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(40)))
            .http_status_as_error(false)
            .build();
        OsvClient {
            agent: config.into(),
            base: base.trim_end_matches('/').to_string(),
            max_details: 150,
        }
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value, OsvError> {
        let mut resp = self
            .agent
            .post(format!("{}{}", self.base, path))
            .header("Content-Type", "application/json")
            .header("User-Agent", concat!("ecomsec/", env!("CARGO_PKG_VERSION")))
            .send_json(body)
            .map_err(|e| OsvError::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| OsvError::Http(e.to_string()))?;
        if !(200..300).contains(&status) {
            return Err(OsvError::Http(format!(
                "HTTP {status} für {path}: {}",
                text.chars().take(200).collect::<String>()
            )));
        }
        serde_json::from_str(&text).map_err(|e| OsvError::Invalid(e.to_string()))
    }

    fn get(&self, path: &str) -> Result<Value, OsvError> {
        let mut resp = self
            .agent
            .get(format!("{}{}", self.base, path))
            .header("User-Agent", concat!("ecomsec/", env!("CARGO_PKG_VERSION")))
            .call()
            .map_err(|e| OsvError::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| OsvError::Http(e.to_string()))?;
        if !(200..300).contains(&status) {
            return Err(OsvError::Http(format!("HTTP {status} für {path}")));
        }
        serde_json::from_str(&text).map_err(|e| OsvError::Invalid(e.to_string()))
    }

    /// Query OSV for every package (batched) and fetch details for each
    /// distinct vulnerability.
    pub fn lookup(&self, packages: &[ComposerPackage]) -> Result<LookupResult, OsvError> {
        let mut result = LookupResult {
            packages_checked: packages.len(),
            ..Default::default()
        };
        // ---- batch queries: which package has which vulnerability ids?
        let mut ids_per_package: Vec<Vec<String>> = vec![Vec::new(); packages.len()];
        for (chunk_idx, chunk) in packages.chunks(500).enumerate() {
            let queries: Vec<Value> = chunk
                .iter()
                .map(|p| json!({"package": {"name": p.name, "ecosystem": "Packagist"}, "version": p.version}))
                .collect();
            let resp = self.post("/querybatch", &json!({"queries": queries}))?;
            let results = resp
                .get("results")
                .and_then(|r| r.as_array())
                .ok_or_else(|| OsvError::Invalid("results fehlt".into()))?;
            for (i, r) in results.iter().enumerate() {
                let idx = chunk_idx * 500 + i;
                if let Some(vulns) = r.get("vulns").and_then(|v| v.as_array()) {
                    ids_per_package[idx] = vulns
                        .iter()
                        .filter_map(|v| v.get("id").and_then(|i| i.as_str()).map(str::to_string))
                        .collect();
                }
                if r.get("next_page_token").is_some() {
                    result.limitations.push(format!(
                        "OSV: Ergebnisliste für {} abgeschnitten (mehr als 1000 Einträge).",
                        packages[idx].name
                    ));
                }
            }
        }
        // ---- details
        let distinct: BTreeSet<&String> = ids_per_package.iter().flatten().collect();
        let mut details: BTreeMap<String, Value> = BTreeMap::new();
        for (n, id) in distinct.iter().enumerate() {
            if n >= self.max_details {
                result.limitations.push(format!(
                    "OSV: Details nur für die ersten {} von {} Schwachstellen geladen.",
                    self.max_details,
                    distinct.len()
                ));
                break;
            }
            match self.get(&format!("/vulns/{id}")) {
                Ok(v) => {
                    details.insert((*id).clone(), v);
                }
                Err(e) => result.limitations.push(format!("OSV: {id}: {e}")),
            }
        }
        for (idx, ids) in ids_per_package.iter().enumerate() {
            if ids.is_empty() {
                continue;
            }
            let pkg = &packages[idx];
            let vulns: Vec<Vulnerability> = ids
                .iter()
                .map(|id| match details.get(id) {
                    Some(v) => vulnerability_from_json(v, pkg),
                    None => Vulnerability {
                        id: id.clone(),
                        aliases: vec![],
                        summary: "(Details nicht geladen)".into(),
                        severity: "UNKNOWN".into(),
                        cvss: None,
                        fixed_in: vec![],
                        reference: Some(format!("https://osv.dev/vulnerability/{id}")),
                        published: None,
                    },
                })
                .collect();
            result.vulnerable_packages += 1;
            result.results.push(PackageResult {
                package: pkg.clone(),
                vulns,
            });
        }
        Ok(result)
    }
}

/// Build a [`Vulnerability`] for `pkg` from an OSV record.
pub fn vulnerability_from_json(v: &Value, pkg: &ComposerPackage) -> Vulnerability {
    let id = v
        .get("id")
        .and_then(|i| i.as_str())
        .unwrap_or("?")
        .to_string();
    let aliases = v
        .get("aliases")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let summary = v
        .get("summary")
        .and_then(|s| s.as_str())
        .map(str::to_string)
        .or_else(|| {
            v.get("details")
                .and_then(|d| d.as_str())
                .map(|d| d.lines().next().unwrap_or("").to_string())
        })
        .unwrap_or_default();
    let severity = v
        .pointer("/database_specific/severity")
        .and_then(|s| s.as_str())
        .map(|s| s.to_ascii_uppercase())
        .or_else(|| {
            v.get("severity")
                .and_then(|s| s.as_array())
                .and_then(|a| a.first())
                .and_then(|s| s.get("score"))
                .and_then(|s| s.as_str())
                .and_then(severity_from_cvss_vector)
        })
        .unwrap_or_else(|| "UNKNOWN".into());
    let cvss = v
        .get("severity")
        .and_then(|s| s.as_array())
        .and_then(|a| a.first())
        .and_then(|s| s.get("score"))
        .and_then(|s| s.as_str())
        .map(str::to_string);
    let installed = Version::parse(&pkg.version);
    let mut fixed_in: Vec<String> = Vec::new();
    if let Some(affected) = v.get("affected").and_then(|a| a.as_array()) {
        for a in affected {
            let same = a
                .pointer("/package/name")
                .and_then(|n| n.as_str())
                .map(|n| n.eq_ignore_ascii_case(&pkg.name))
                .unwrap_or(false);
            if !same {
                continue;
            }
            for range in a
                .get("ranges")
                .and_then(|r| r.as_array())
                .into_iter()
                .flatten()
            {
                let mut introduced: Option<Version> = None;
                for ev in range
                    .get("events")
                    .and_then(|e| e.as_array())
                    .into_iter()
                    .flatten()
                {
                    if let Some(i) = ev.get("introduced").and_then(|x| x.as_str()) {
                        introduced = Version::parse(i).or_else(|| Version::parse("0"));
                    }
                    if let Some(f) = ev.get("fixed").and_then(|x| x.as_str()) {
                        let in_range = match (&installed, &introduced, Version::parse(f)) {
                            (Some(inst), Some(intro), Some(fix)) => inst >= intro && *inst < fix,
                            _ => true,
                        };
                        if in_range && !fixed_in.contains(&f.to_string()) {
                            fixed_in.push(f.to_string());
                        }
                    }
                }
            }
        }
    }
    let reference = v
        .get("references")
        .and_then(|r| r.as_array())
        .and_then(|a| {
            a.iter()
                .find(|r| r.get("type").and_then(|t| t.as_str()) == Some("ADVISORY"))
                .or_else(|| a.first())
        })
        .and_then(|r| r.get("url"))
        .and_then(|u| u.as_str())
        .map(str::to_string)
        .or_else(|| Some(format!("https://osv.dev/vulnerability/{id}")));
    Vulnerability {
        id,
        aliases,
        summary,
        severity,
        cvss,
        fixed_in,
        reference,
        published: v
            .get("published")
            .and_then(|p| p.as_str())
            .map(str::to_string),
    }
}

fn severity_from_cvss_vector(vector: &str) -> Option<String> {
    // Rough mapping without a full CVSS calculator: network + no privileges +
    // high impact → HIGH/CRITICAL, else MODERATE.
    let v = vector.to_ascii_uppercase();
    if !v.starts_with("CVSS:") {
        return None;
    }
    let network = v.contains("AV:N");
    let no_priv = v.contains("PR:N");
    let high_impact = v.contains("C:H")
        || v.contains("I:H")
        || v.contains("A:H")
        || v.contains("VC:H")
        || v.contains("VI:H");
    Some(
        if network && no_priv && high_impact {
            "CRITICAL"
        } else if high_impact {
            "HIGH"
        } else {
            "MODERATE"
        }
        .into(),
    )
}

/// Map OSV severity labels to finding severities.
pub fn finding_severity(label: &str) -> Severity {
    match label {
        "CRITICAL" | "HIGH" => Severity::Critical,
        "MODERATE" | "MEDIUM" => Severity::Warning,
        _ => Severity::Info,
    }
}

/// Convert a lookup result into findings plus an integrity row.
pub fn to_findings(result: &LookupResult, source_file: &str) -> (Vec<Finding>, IntegrityItem) {
    let mut findings = Vec::new();
    let mut critical = 0usize;
    for pr in &result.results {
        for v in &pr.vulns {
            let sev = finding_severity(&v.severity);
            if sev == Severity::Critical {
                critical += 1;
            }
            let subject = format!("composer:{}@{}", pr.package.name, pr.package.version);
            let mut f = Finding::new(
                sev,
                Category::PatchStatus,
                Source::Configuration,
                format!("osv_{}", v.id.to_ascii_lowercase()),
                subject,
                format!(
                    "Verwundbare Abhängigkeit: {} {} – {}",
                    pr.package.name,
                    pr.package.version,
                    if v.summary.is_empty() {
                        v.id.clone()
                    } else {
                        v.summary.clone()
                    }
                ),
            )
            .with_description(format!(
                "OSV.dev meldet {}{} (Schweregrad {}) für die installierte Version. {}{}",
                v.id,
                if v.aliases.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", v.aliases.join(", "))
                },
                v.severity,
                if v.fixed_in.is_empty() {
                    "Keine behobene Version angegeben – Hersteller-Advisory prüfen.".to_string()
                } else {
                    format!("Behoben in: {}.", v.fixed_in.join(", "))
                },
                if pr.package.dev {
                    " (Entwicklungsabhängigkeit)"
                } else {
                    ""
                }
            ))
            .with_group("composer".to_string());
            if let Some(r) = &v.reference {
                f = f.with_evidence(r.clone());
            }
            if let Some(c) = &v.cvss {
                f = f.with_evidence(c.clone());
            }
            findings.push(f);
        }
    }
    let total_vulns: usize = result.results.iter().map(|r| r.vulns.len()).sum();
    let item = IntegrityItem::new(
        "dependencies.osv",
        "Abhängigkeiten",
        "Composer-Pakete gegen OSV.dev geprüft",
        if critical > 0 {
            IntegrityStatus::Critical
        } else if total_vulns > 0 {
            IntegrityStatus::Warning
        } else {
            IntegrityStatus::Ok
        },
        format!(
            "{} Pakete · {} verwundbar · {} Schwachstellen ({} kritisch/hoch)",
            result.packages_checked, result.vulnerable_packages, total_vulns, critical
        ),
    )
    .with_detail(format!(
        "Quelle: {source_file} · api.osv.dev (GitHub Advisory Database, FriendsOfPHP)"
    ));
    (findings, item)
}

/// Outcome of [`check_root`].
#[derive(Debug, Clone)]
pub struct CheckOutcome {
    pub findings: Vec<Finding>,
    pub item: IntegrityItem,
    pub limitations: Vec<String>,
}

/// Convenience: inventory + lookup + findings for a root directory.  Returns
/// `None` when no inventory file exists.
pub fn check_root(
    root: &Path,
    candidates: &[&str],
    client: &OsvClient,
) -> Option<Result<CheckOutcome, OsvError>> {
    let (packages, source) = load_inventory(root, candidates)?;
    Some(client.lookup(&packages).map(|res| {
        let (findings, item) = to_findings(&res, &source);
        CheckOutcome {
            findings,
            item,
            limitations: res.limitations,
        }
    }))
}

/// Integrity row shown when online checks are disabled.
pub fn offline_item(root: &Path, candidates: &[&str]) -> IntegrityItem {
    match load_inventory(root, candidates) {
        Some((pkgs, src)) => IntegrityItem::new(
            "dependencies.osv",
            "Abhängigkeiten",
            "Composer-Pakete gegen OSV.dev geprüft",
            IntegrityStatus::Unknown,
            format!("nicht geprüft ({} Pakete in {src})", pkgs.len()),
        )
        .with_detail("Mit `ecomsec scan --online` werden Paketnamen und Versionen an api.osv.dev gesendet und tagesaktuell abgeglichen."),
        None => IntegrityItem::new(
            "dependencies.osv",
            "Abhängigkeiten",
            "Composer-Pakete",
            IntegrityStatus::Unknown,
            "keine composer.lock / installed.json gefunden",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_inventories() {
        let lock = r#"{"packages":[{"name":"shopware/core","version":"v6.5.7.3"},{"name":"x/dev","version":"dev-main"}],"packages-dev":[{"name":"phpunit/phpunit","version":"10.1.0"}]}"#;
        let p = read_composer_lock(lock);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].version, "6.5.7.3");
        assert!(p[1].dev);
        let installed =
            r#"{"packages":[{"name":"smarty/smarty","version":"v4.3.0"}],"dev-package-names":[]}"#;
        assert_eq!(read_installed_json(installed)[0].name, "smarty/smarty");
        let legacy = r#"[{"name":"a/b","version":"1.0.0"}]"#;
        assert_eq!(read_installed_json(legacy).len(), 1);
    }

    #[test]
    fn extracts_fixed_version_for_installed_range() {
        let pkg = ComposerPackage {
            name: "shopware/core".into(),
            version: "6.5.7.3".into(),
            dev: false,
        };
        let v = json!({
            "id":"GHSA-test","aliases":["CVE-2024-0001"],"summary":"SQLi",
            "database_specific":{"severity":"HIGH"},
            "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected":[
              {"package":{"name":"shopware/core","ecosystem":"Packagist"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"6.4.0.0"},{"fixed":"6.4.20.2"}]}]},
              {"package":{"name":"shopware/core","ecosystem":"Packagist"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"6.5.0.0"},{"fixed":"6.5.7.4"}]}]},
              {"package":{"name":"shopware/platform","ecosystem":"Packagist"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.9"}]}]}
            ],
            "references":[{"type":"WEB","url":"https://x"},{"type":"ADVISORY","url":"https://ghsa"}]
        });
        let vuln = vulnerability_from_json(&v, &pkg);
        assert_eq!(vuln.fixed_in, vec!["6.5.7.4".to_string()]);
        assert_eq!(vuln.severity, "HIGH");
        assert_eq!(vuln.reference.as_deref(), Some("https://ghsa"));
        assert_eq!(finding_severity(&vuln.severity), Severity::Critical);
        let res = LookupResult {
            results: vec![PackageResult {
                package: pkg,
                vulns: vec![vuln],
            }],
            packages_checked: 1,
            vulnerable_packages: 1,
            limitations: vec![],
        };
        let (f, item) = to_findings(&res, "composer.lock");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "osv_ghsa-test");
        assert_eq!(item.status, IntegrityStatus::Critical);
    }

    #[test]
    fn cvss_fallback() {
        assert_eq!(
            severity_from_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").as_deref(),
            Some("CRITICAL")
        );
        assert_eq!(
            severity_from_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N").as_deref(),
            Some("MODERATE")
        );
        assert!(severity_from_cvss_vector("nope").is_none());
    }
}
