//! Parsing of `includes/config.JTL-Shop.ini.php` and permission checks of
//! sensitive files.

use ecomsec_core::db::DbCredentials;
use ecomsec_core::finding::{Category, Finding, Severity};
use ecomsec_core::platform::{IntegrityItem, IntegrityReport, IntegrityStatus};
use regex::Regex;
use std::collections::BTreeMap;
use std::path::Path;

/// Values from `includes/config.JTL-Shop.ini.php`.
#[derive(Debug, Clone, Default)]
pub struct JtlConfig {
    pub defines: BTreeMap<String, String>,
    pub db: Option<DbCredentials>,
    pub shop_url: Option<String>,
    pub blowfish_key_set: bool,
}

impl JtlConfig {
    pub fn load(root: &Path) -> Self {
        let path = root.join("includes/config.JTL-Shop.ini.php");
        match std::fs::read_to_string(&path) {
            Ok(text) => JtlConfig::parse(&text),
            Err(e) => {
                log::warn!("cannot read {}: {e}", path.display());
                JtlConfig::default()
            }
        }
    }

    pub fn parse(text: &str) -> Self {
        let re = Regex::new(
            r#"(?m)^\s*define\s*\(\s*(?:'([A-Za-z0-9_]+)'|"([A-Za-z0-9_]+)")\s*,\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"|([0-9]+|true|false))\s*\)"#,
        )
        .expect("regex");
        let mut defines = BTreeMap::new();
        for c in re.captures_iter(text) {
            let key = c
                .get(1)
                .or_else(|| c.get(2))
                .map(|m| m.as_str())
                .unwrap_or("");
            let value = c
                .get(3)
                .or_else(|| c.get(4))
                .or_else(|| c.get(5))
                .map(|m| unescape(m.as_str()))
                .unwrap_or_default();
            if !key.is_empty() {
                defines.insert(key.to_string(), value);
            }
        }
        let get = |k: &str| defines.get(k).cloned().filter(|v| !v.is_empty());
        let db = match (get("DB_HOST"), get("DB_NAME"), get("DB_USER")) {
            (Some(host), Some(database), Some(user)) => {
                let (host, port) = split_host_port(&host);
                Some(DbCredentials {
                    host,
                    port,
                    user,
                    password: get("DB_PASS").unwrap_or_default(),
                    database,
                    socket: get("DB_SOCKET"),
                })
            }
            _ => None,
        };
        JtlConfig {
            shop_url: get("URL_SHOP"),
            blowfish_key_set: get("BLOWFISH_KEY").is_some(),
            db,
            defines,
        }
    }
}

fn split_host_port(host: &str) -> (String, Option<u16>) {
    match host.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse().ok())
        }
        _ => (host.to_string(), None),
    }
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some(o) => out.push(o),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Permission checks on the configuration file and the `.htaccess` files.
pub fn permission_checks(root: &Path, report: &mut IntegrityReport) {
    let targets: [(&str, bool); 4] = [
        ("includes/config.JTL-Shop.ini.php", true),
        (".htaccess", false),
        ("admin/.htaccess", false),
        ("includes/defines.php", false),
    ];
    for (rel, secret) in targets {
        let path = root.join(rel);
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => {
                if secret {
                    report.items.push(IntegrityItem::new(
                        format!("perm.{rel}"),
                        "Dateirechte",
                        rel,
                        IntegrityStatus::Warning,
                        "nicht gefunden",
                    ));
                }
                continue;
            }
        };
        let (status, value, detail, finding) = evaluate_mode(rel, secret, mode_of(&meta));
        let mut item = IntegrityItem::new(format!("perm.{rel}"), "Dateirechte", rel, status, value);
        if let Some(d) = detail {
            item = item.with_detail(d);
        }
        report.items.push(item);
        if let Some((sev, title, desc)) = finding {
            report.findings.push(
                Finding::file(
                    sev,
                    Category::ConfigPermissions,
                    "config_permissions",
                    root,
                    &path,
                    title,
                )
                .with_description(desc)
                .with_evidence(format!("mode={:04o}", mode_of(&meta) & 0o7777)),
            );
        }
    }
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    if meta.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

type ModeVerdict = (
    IntegrityStatus,
    String,
    Option<String>,
    Option<(Severity, String, String)>,
);

/// Translate a unix mode into an integrity status and optional finding.
pub fn evaluate_mode(rel: &str, secret: bool, mode: u32) -> ModeVerdict {
    let perm = mode & 0o777;
    let value = format!("{perm:04o}");
    if perm & 0o002 != 0 {
        return (
            IntegrityStatus::Critical,
            value,
            Some("für alle Benutzer schreibbar".into()),
            Some((
                Severity::Critical,
                format!("{rel} ist für alle Benutzer schreibbar"),
                "Jeder Prozess auf dem Server kann die Datei verändern – z. B. Zugangsdaten austauschen oder \
                 Code injizieren. Rechte auf 0640/0600 (Konfiguration) bzw. 0644 (.htaccess) setzen."
                    .into(),
            )),
        );
    }
    if secret && perm & 0o004 != 0 {
        return (
            IntegrityStatus::Warning,
            value,
            Some("für alle Benutzer lesbar – DB-Zugangsdaten und Blowfish-Key einsehbar".into()),
            Some((
                Severity::Warning,
                format!("{rel} ist für alle Benutzer lesbar"),
                "Auf Shared Hosting können andere Kunden desselben Servers die Datei lesen. Rechte auf 0640 \
                 oder 0600 setzen (Besitzer = Webserver-/FTP-Benutzer)."
                    .into(),
            )),
        );
    }
    if perm & 0o020 != 0 {
        return (
            IntegrityStatus::Warning,
            value,
            Some("gruppenschreibbar".into()),
            Some((
                Severity::Warning,
                format!("{rel} ist gruppenschreibbar"),
                "Schreibrechte für die Gruppe sind selten nötig; auf 0640/0644 reduzieren.".into(),
            )),
        );
    }
    (IntegrityStatus::Ok, value, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_config() {
        let text = r#"<?php
define('PFAD_ROOT', '/var/www/shop/');
define('URL_SHOP', 'https://shop.example');
define("DB_HOST", "localhost:3307");
define('DB_NAME','jtl');
define('DB_USER','jtluser');
define('DB_PASS','se\'cret');
define('BLOWFISH_KEY', 'abc');
define('ES_DB_HOST', 'x');
"#;
        let c = JtlConfig::parse(text);
        let db = c.db.unwrap();
        assert_eq!(db.host, "localhost");
        assert_eq!(db.port, Some(3307));
        assert_eq!(db.password, "se'cret");
        assert_eq!(db.database, "jtl");
        assert_eq!(c.shop_url.as_deref(), Some("https://shop.example"));
        assert!(c.blowfish_key_set);
    }

    #[test]
    fn mode_evaluation() {
        assert_eq!(evaluate_mode("x", true, 0o100600).0, IntegrityStatus::Ok);
        assert_eq!(
            evaluate_mode("x", true, 0o100644).0,
            IntegrityStatus::Warning
        );
        assert_eq!(evaluate_mode("x", false, 0o100644).0, IntegrityStatus::Ok);
        assert_eq!(
            evaluate_mode("x", false, 0o100666).0,
            IntegrityStatus::Critical
        );
        assert_eq!(
            evaluate_mode("x", false, 0o100664).0,
            IntegrityStatus::Warning
        );
    }
}
