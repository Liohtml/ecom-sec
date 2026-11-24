//! Files that a JTL-Shop serves although it should not.
//!
//! * `export/backup/` holds database and file backups.  Up to the hotfix of
//!   24.11.2026 the `FilesMatch` rule in `export/.htaccess` allowed `.gz` and
//!   `.zip` below `export/` – including the backup folder (CVE-2026-133940).
//!   On nginx no `.htaccess` applies at all, so backups there are reachable
//!   unless the server configuration blocks the folder.
//! * `install/` contains the web installer.  It must be removed after the
//!   installation; before 5.8.4 / 5.7.6 / 5.6.6 / 5.5.5 the installer did not
//!   lock itself on an installed shop (CVE-2026-123058).

use ecomsec_core::engine::file_scan::htaccess_denies;
use ecomsec_core::finding::{Category, Finding, Severity};
use ecomsec_core::platform::{IntegrityItem, IntegrityReport, IntegrityStatus};
use std::path::Path;

const BACKUP_DIR: &str = "export/backup";
const INSTALLER: &str = "install/install.php";
const INSTALLER_OLD: &str = "install/index.php";
const SHOP_CONFIG: &str = "includes/config.JTL-Shop.ini.php";

/// Whether Apache serves files from `export/backup`, evaluated with the
/// same `.htaccess` merge order as the file scanner: up to the hotfix the
/// `FilesMatch` in `export/.htaccess` opens `.gz` and `.zip` there.
fn backup_dir_protected(root: &Path, files: &[(String, u64)]) -> bool {
    let dir = root.join(BACKUP_DIR);
    let probes: Vec<std::path::PathBuf> = if files.is_empty() {
        vec![
            dir.join("probe_sql_backup.sql.gz"),
            dir.join("probe_file_backup.zip"),
        ]
    } else {
        files.iter().map(|(name, _)| dir.join(name)).collect()
    };
    probes.iter().all(|p| htaccess_denies(p, root).is_some())
}

pub fn checks(root: &Path, report: &mut IntegrityReport) {
    backups(root, report);
    installer(root, report);
}

fn backups(root: &Path, report: &mut IntegrityReport) {
    let dir = root.join(BACKUP_DIR);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    let mut files: Vec<(String, u64)> = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| {
            (
                e.file_name().to_string_lossy().to_string(),
                e.metadata().map(|m| m.len()).unwrap_or(0),
            )
        })
        .filter(|(name, _)| !name.starts_with('.'))
        .collect();
    files.sort();
    let protected = backup_dir_protected(root, &files);
    if !files.is_empty() {
        let total: u64 = files.iter().map(|(_, n)| n).sum();
        report.findings.push(
            Finding::file(
                if protected {
                    Severity::Warning
                } else {
                    Severity::Critical
                },
                Category::ExposedFile,
                "jtl5_backup_files_exposed",
                root,
                &dir,
                format!(
                    "{} Sicherungsdatei(en) in export/backup{}",
                    files.len(),
                    if protected {
                        " (nur unter Apache geschützt)"
                    } else {
                        " – ohne Anmeldung abrufbar"
                    }
                ),
            )
            .with_description(if protected {
                "Die .htaccess sperrt das Verzeichnis, aber nur unter Apache. Läuft der Shop unter nginx oder hinter \
                 nginx, muss der Server das Verzeichnis selbst sperren (location ^~ /export/backup/ { return 403; }), \
                 sonst sind Datenbank- und Dateisicherungen weiter abrufbar (CVE-2026-133940). Nicht mehr \
                 benötigte Sicherungen löschen oder außerhalb des Webroots aufbewahren."
                    .to_string()
            } else {
                "Bis zum Hotfix vom 24.11.2026 erlaubt export/.htaccess den Abruf von .gz- und .zip-Dateien auch in \
                 export/backup (CVE-2026-133940). Datenbanksicherungen enthalten Kundendaten, Dateisicherungen \
                 auch die Shop-Konfiguration mit Zugangsdaten. Sofort: Sicherungen aus dem Webroot entfernen, \
                 auf 5.8.5 / 5.7.7 / 5.6.7 / 5.5.6 aktualisieren oder den Patch einspielen, unter nginx das \
                 Verzeichnis sperren. Access-Logs auf erfolgreiche Abrufe (200/206) prüfen; bei Abrufen \
                 Zugangsdaten ändern und eine Meldung nach DSGVO Art. 33 prüfen."
                    .to_string()
            })
            .with_evidence(
                files
                    .iter()
                    .take(10)
                    .map(|(n, size)| format!("{n} ({})", ecomsec_core::util::human_size(*size)))
                    .collect::<Vec<_>>()
                    .join(", "),
            )
            .with_evidence(format!(
                "zusammen {}",
                ecomsec_core::util::human_size(total)
            )),
        );
    }
    report.items.push(
        IntegrityItem::new(
            "files.export_backup",
            "Integrität",
            "Sicherungsdateien in export/backup (CVE-2026-133940)",
            match (files.is_empty(), protected) {
                (true, true) => IntegrityStatus::Ok,
                (true, false) => IntegrityStatus::Warning,
                (false, true) => IntegrityStatus::Warning,
                (false, false) => IntegrityStatus::Critical,
            },
            format!(
                "{} Dateien · .htaccess {}",
                files.len(),
                if protected { "gesperrt" } else { "ohne Sperre" }
            ),
        )
        .with_detail("Die .htaccess wirkt nur unter Apache; nginx braucht eine eigene Sperre."),
    );
}

fn installer(root: &Path, report: &mut IntegrityReport) {
    if !root.join(SHOP_CONFIG).is_file() {
        return;
    }
    let present: Vec<&str> = [INSTALLER, INSTALLER_OLD]
        .into_iter()
        .filter(|rel| root.join(rel).is_file())
        .collect();
    if present.is_empty() {
        return;
    }
    report.findings.push(
        Finding::file(
            Severity::Warning,
            Category::ExposedFile,
            "jtl5_installer_present",
            root,
            &root.join("install"),
            "Web-Installer nach der Installation noch vorhanden",
        )
        .with_description(
            "Das Verzeichnis install/ gehört nach der Installation gelöscht. Vor 5.8.4 / 5.7.6 / 5.6.6 / 5.5.5 \
             sperrte sich der Installer auf einem eingerichteten Shop nicht (CVE-2026-123058); auch danach ist er \
             unnötige Angriffsfläche. Verzeichnis löschen und im Access-Log nach Aufrufen von /install/ suchen.",
        )
        .with_evidence(present.join(", ")),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, content: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn rule_severity(report: &IntegrityReport, rule: &str) -> Option<Severity> {
        report
            .findings
            .iter()
            .find(|f| f.rule == rule)
            .map(|f| f.severity)
    }

    const EXPORT_HTACCESS: &str = "Require all denied\n<FilesMatch \"\\.(txt|csv|xml|gz|zip)$\">\n    Require all granted\n</FilesMatch>";
    const OLD_HTACCESS: &str = "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>";
    const NEW_HTACCESS: &str = "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n\n<FilesMatch \".*\">\n    Require all denied\n</FilesMatch>";

    #[test]
    fn backups_are_critical_without_the_hotfix() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "export/.htaccess", EXPORT_HTACCESS);
        write(root, "export/backup/.htaccess", OLD_HTACCESS);
        write(root, "export/backup/20261101_sql_a1b2c3_backup.sql.gz", "x");
        let mut report = IntegrityReport::default();
        checks(root, &mut report);
        assert_eq!(
            rule_severity(&report, "jtl5_backup_files_exposed"),
            Some(Severity::Critical)
        );

        write(root, "export/backup/.htaccess", NEW_HTACCESS);
        let mut report = IntegrityReport::default();
        checks(root, &mut report);
        assert_eq!(
            rule_severity(&report, "jtl5_backup_files_exposed"),
            Some(Severity::Warning)
        );
    }

    #[test]
    fn empty_protected_backup_dir_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "export/.htaccess", EXPORT_HTACCESS);
        write(tmp.path(), "export/backup/.htaccess", NEW_HTACCESS);
        let mut report = IntegrityReport::default();
        checks(tmp.path(), &mut report);
        assert!(report.findings.is_empty());
        assert_eq!(report.items[0].status, IntegrityStatus::Ok);
    }

    #[test]
    fn installer_only_counts_on_an_installed_shop() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "install/install.php", "<?php");
        let mut report = IntegrityReport::default();
        checks(tmp.path(), &mut report);
        assert!(rule_severity(&report, "jtl5_installer_present").is_none());
        write(tmp.path(), SHOP_CONFIG, "<?php");
        let mut report = IntegrityReport::default();
        checks(tmp.path(), &mut report);
        assert_eq!(
            rule_severity(&report, "jtl5_installer_present"),
            Some(Severity::Warning)
        );
    }
}
