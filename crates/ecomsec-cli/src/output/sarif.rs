//! SARIF 2.1.0 export for code-scanning dashboards (GitHub Code Scanning,
//! GitLab, Azure DevOps, DefectDojo …).
//!
//! * one rule per finding rule name, with German help text,
//! * levels: critical → `error`, warning → `warning`, info → `note`,
//! * file findings carry a `physicalLocation` relative to the scanned root
//!   (`%SRCROOT%`), all others a `logicalLocation`,
//! * `partialFingerprints` use the stable finding id, so dashboards keep
//!   track of a finding across scans,
//! * accepted findings are emitted with an external suppression.

use ecomsec_core::finding::{Category, Finding, Severity};
use ecomsec_core::Report;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
pub const SARIF_VERSION: &str = "2.1.0";
/// Key used in `partialFingerprints`.
pub const FINGERPRINT_KEY: &str = "ecomsecFindingId/v1";

pub fn level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

/// `security-severity` property understood by GitHub (CVSS-like 0–10).
fn security_severity(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "9.0",
        Severity::Warning => "5.5",
        Severity::Info => "2.0",
    }
}

/// snake_case key of a category (same spelling as in the JSON report).
pub fn category_key(c: Category) -> String {
    serde_json::to_value(c)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{c:?}"))
}

/// Generic German guidance per category, used as rule help.
pub fn category_help(c: Category) -> &'static str {
    match c {
        Category::KnownWebshell => "Der Dateiname steht auf einer IOC-Liste bekannter Webshells. Datei sichern (Forensik), Herkunft klären, entfernen und alle Zugangsdaten rotieren.",
        Category::ModifiedSinceReference => "Ausführbare Datei wurde nach dem Referenzdatum angelegt oder geändert. Mit Deployment-/Update-Historie abgleichen; unbekannte Änderungen wie eine Kompromittierung behandeln.",
        Category::CodeInUploadDir => "In Upload- und Medienverzeichnissen hat ausführbarer Code nichts verloren. Datei prüfen und entfernen, PHP-Ausführung im Verzeichnis per Webserver-Konfiguration unterbinden.",
        Category::WebserverConfigManipulation => "Die Webserver-Konfiguration (.htaccess/.user.ini) führt Code aus oder schwächt Schutzmechanismen. Mit dem Auslieferungszustand vergleichen und Manipulationen entfernen.",
        Category::SuspiciousPattern => "Der Inhalt entspricht einem Malware- oder Verschleierungsmuster. Code-Stelle prüfen; legitime Bibliotheken als unbedenklich markieren.",
        Category::ExploitPayload => "Spuren eines konkreten Exploits (z. B. Template-Injection). Betroffene Datensätze/Dateien bereinigen, Patch einspielen, Zugangsdaten rotieren.",
        Category::TimestampAnomaly => "Zeitstempel wirken manipuliert (zurückdatiert oder in der Zukunft). Inhalt der Datei gezielt prüfen.",
        Category::AttackTrace => "In Logs oder gespeicherten E-Mails wurden Angriffsversuche gefunden. Zeitraum eingrenzen und auf erfolgreiche Ausnutzung prüfen.",
        Category::PatchStatus => "Die installierte Version ist von einer bekannten Schwachstelle betroffen. Update bzw. Hersteller-Patch einspielen.",
        Category::AdminAccount => "Auffälligkeit bei Administratorkonten (neu, geändert, ohne 2FA). Konten zuordnen, unbekannte deaktivieren, 2FA erzwingen.",
        Category::PaymentConfiguration => "Zahlungsempfänger oder Zahlungsanbieter-Konfiguration wurde geändert. Sofort mit dem Händlerkonto abgleichen.",
        Category::ConfigPermissions => "Konfigurationsdatei mit Zugangsdaten hat zu offene Dateirechte. Rechte auf 0640/0600 einschränken.",
        Category::ExposedFile => "Backup, Dump oder Konfigurationskopie ist über den Webserver abrufbar. Aus dem Webroot entfernen.",
        Category::IntegrityDeviation => "Datei weicht von der Integritäts-Baseline ab. Änderung einem Update/Deployment zuordnen oder wiederherstellen.",
        Category::ThirdPartyInjection => "Fremdcode im Storefront (Script-Tags, Apps, Webhooks, Theme). Herkunft und Zielhosts prüfen.",
        Category::ScanLimitation => "Eine Prüfung konnte nicht vollständig ausgeführt werden. Ursache beheben und Scan wiederholen.",
        Category::Informational => "Information ohne unmittelbaren Handlungsbedarf.",
    }
}

fn file_uri(path: &std::path::Path) -> String {
    let mut s = path.to_string_lossy().replace('\\', "/");
    if !s.ends_with('/') {
        s.push('/');
    }
    if !s.starts_with('/') {
        // Windows drive letter (`C:/…`).
        s.insert(0, '/');
    }
    format!("file://{}", s.replace(' ', "%20"))
}

fn rule_object(rule: &str, first: &Finding) -> Value {
    let help = category_help(first.category);
    let mut full = first.description.clone();
    if full.is_empty() {
        full = help.to_string();
    }
    json!({
        "id": rule,
        "name": rule,
        "shortDescription": {"text": first.title},
        "fullDescription": {"text": full},
        "help": {
            "text": format!("{} – {help}", first.category.label()),
            "markdown": format!("**{}**\n\n{help}\n\nBefund-Regel `{rule}` von ecomsec.", first.category.label()),
        },
        "defaultConfiguration": {"level": level(first.severity)},
        "properties": {
            "tags": ["security", category_key(first.category)],
            "security-severity": security_severity(first.severity),
            "precision": "medium",
        }
    })
}

/// Render the report as a SARIF 2.1.0 log.
pub fn render(report: &Report) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(&to_value(report))?)
}

pub fn to_value(report: &Report) -> Value {
    // Rules: one per rule name, ordered by name for stable indices.  The most
    // severe finding of a rule defines its default level.
    let mut by_rule: BTreeMap<&str, &Finding> = BTreeMap::new();
    for f in &report.findings {
        by_rule
            .entry(f.rule.as_str())
            .and_modify(|cur| {
                if f.severity > cur.severity {
                    *cur = f;
                }
            })
            .or_insert(f);
    }
    let index: BTreeMap<&str, usize> = by_rule.keys().enumerate().map(|(i, r)| (*r, i)).collect();
    let rules: Vec<Value> = by_rule.iter().map(|(r, f)| rule_object(r, f)).collect();

    let has_root = report.platform.root.is_some();
    let results: Vec<Value> = report
        .sorted_findings()
        .into_iter()
        .map(|f| {
            let mut text = f.title.clone();
            if !f.description.is_empty() {
                text.push_str(" – ");
                text.push_str(&f.description);
            }
            let mut r = Map::new();
            r.insert("ruleId".into(), json!(f.rule));
            r.insert("ruleIndex".into(), json!(index[f.rule.as_str()]));
            r.insert("level".into(), json!(level(f.severity)));
            r.insert("message".into(), json!({"text": text}));
            let location = if f.path.is_some() && has_root {
                json!({
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.subject.replace('\\', "/"), "uriBaseId": "SRCROOT"}
                    },
                    "logicalLocations": [{"fullyQualifiedName": f.subject, "kind": "resource"}]
                })
            } else {
                json!({
                    "logicalLocations": [{"fullyQualifiedName": f.subject, "kind": "resource"}]
                })
            };
            r.insert("locations".into(), json!([location]));
            r.insert(
                "partialFingerprints".into(),
                json!({ FINGERPRINT_KEY: f.id.as_str() }),
            );
            if f.accepted {
                let mut s = json!({"kind": "external", "status": "accepted"});
                if let Some(reason) = &f.accepted_reason {
                    s["justification"] = json!(reason);
                }
                r.insert("suppressions".into(), json!([s]));
            }
            let mut props = json!({
                "ecomsecId": f.id.as_str(),
                "category": category_key(f.category),
                "severity": f.severity.label_en(),
                "subject": f.subject,
            });
            if !f.evidence.is_empty() {
                props["evidence"] = json!(f.evidence);
            }
            r.insert("properties".into(), props);
            Value::Object(r)
        })
        .collect();

    let posture = report.posture();
    let mut run = json!({
        "tool": {
            "driver": {
                "name": "ecomsec",
                "fullName": "ecomsec Security Scan – Kompromittierungs-Check",
                "version": env!("CARGO_PKG_VERSION"),
                "semanticVersion": env!("CARGO_PKG_VERSION"),
                "informationUri": env!("CARGO_PKG_REPOSITORY"),
                "rules": rules,
            }
        },
        "automationDetails": {"id": format!("ecomsec/{}/", report.platform.id)},
        "invocations": [{
            "executionSuccessful": true,
            "endTimeUtc": report.generated_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "toolExecutionNotifications": report.limitations.iter().map(|l| json!({
                "level": "note",
                "message": {"text": l},
            })).collect::<Vec<_>>(),
        }],
        "results": results,
        "properties": {
            "platform": report.platform.id,
            "platformVersion": report.platform.version.as_ref().map(|v| v.to_string()),
            "verdict": report.verdict,
            "score": posture.score,
            "grade": posture.grade,
        }
    });
    if let Some(root) = &report.platform.root {
        run["originalUriBaseIds"] = json!({"SRCROOT": {"uri": file_uri(root)}});
    }
    json!({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_support::sample_report;

    /// Hand-check of the properties the SARIF 2.1.0 schema marks as required
    /// (plus what GitHub Code Scanning relies on).
    #[test]
    fn sarif_has_required_structure() {
        let report = sample_report();
        let v = to_value(&report);
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["$schema"], SARIF_SCHEMA);
        let runs = v["runs"].as_array().expect("runs array");
        assert_eq!(runs.len(), 1);
        let run = &runs[0];
        let driver = &run["tool"]["driver"];
        assert_eq!(driver["name"], "ecomsec");
        let rules = driver["rules"].as_array().unwrap();
        // One rule per distinct rule name.
        let mut names: Vec<&str> = report.findings.iter().map(|f| f.rule.as_str()).collect();
        names.sort();
        names.dedup();
        assert_eq!(rules.len(), names.len());
        for r in rules {
            assert!(r["id"].is_string());
            assert!(r["shortDescription"]["text"].is_string());
            assert!(!r["help"]["text"].as_str().unwrap().is_empty());
        }
        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), report.findings.len());
        for res in results {
            // `message` with `text` is required for every result.
            assert!(res["message"]["text"].is_string());
            let idx = res["ruleIndex"].as_u64().unwrap() as usize;
            assert_eq!(rules[idx]["id"], res["ruleId"]);
            assert!(["error", "warning", "note"].contains(&res["level"].as_str().unwrap()));
            assert!(res["partialFingerprints"][FINGERPRINT_KEY].is_string());
            assert!(!res["locations"].as_array().unwrap().is_empty());
        }
        assert!(run["originalUriBaseIds"]["SRCROOT"]["uri"]
            .as_str()
            .unwrap()
            .starts_with("file:///"));
    }

    #[test]
    fn levels_locations_and_suppressions() {
        let report = sample_report();
        let v = to_value(&report);
        let results = v["runs"][0]["results"].as_array().unwrap();
        let by_rule = |r: &str| {
            results
                .iter()
                .find(|x| x["ruleId"] == r)
                .unwrap_or_else(|| panic!("result {r}"))
        };
        let shell = by_rule("ioc_filename");
        assert_eq!(shell["level"], "error");
        let loc = &shell["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(loc["uri"], "mediafiles/wso.php");
        assert_eq!(loc["uriBaseId"], "SRCROOT");
        let fp = report
            .findings
            .iter()
            .find(|f| f.rule == "ioc_filename")
            .unwrap()
            .id
            .to_string();
        assert_eq!(shell["partialFingerprints"][FINGERPRINT_KEY], fp.as_str());

        let admin = by_rule("admin_without_2fa");
        assert_eq!(admin["level"], "note");
        assert!(admin["locations"][0].get("physicalLocation").is_none());
        assert!(admin["locations"][0]["logicalLocations"][0]["fullyQualifiedName"].is_string());

        let accepted = by_rule("exposed_file");
        assert_eq!(accepted["level"], "warning");
        assert_eq!(accepted["suppressions"][0]["kind"], "external");
        assert_eq!(accepted["suppressions"][0]["justification"], "Testdump");
    }
}
