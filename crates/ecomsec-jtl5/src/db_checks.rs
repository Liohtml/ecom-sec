//! Database based checks for JTL-Shop 5 (read-only).

use crate::Jtl5;
use chrono::NaiveDateTime;
use ecomsec_core::db::{col, columns, query_rows, table_exists};
use ecomsec_core::finding::{Category, Finding, Severity, Source};
use ecomsec_core::platform::{IntegrityItem, IntegrityReport, IntegrityStatus, PlatformContext};
use ecomsec_core::rules::RuleSet;
use ecomsec_core::util::{excerpt, mask, mask_email, sha256_hex};
use mysql::Conn;
use std::collections::BTreeMap;

fn parse_dt(s: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").ok()
}

fn after_reference(s: &str, ctx: &PlatformContext) -> bool {
    parse_dt(s)
        .map(|d| d.date() >= ctx.reference_date)
        .unwrap_or(false)
}

type Step = fn(&Jtl5, &mut Conn, &PlatformContext, &mut IntegrityReport) -> anyhow::Result<()>;

pub fn run(jtl: &Jtl5, conn: &mut Conn, ctx: &PlatformContext, report: &mut IntegrityReport) {
    let steps: Vec<(&str, Step)> = vec![
        ("Version (DB)", db_version),
        ("Admin-Konten", admin_accounts),
        ("PayPal", paypal),
        ("Plugins", plugins),
        ("Cronjobs", cron),
        ("E-Mail-Vorlagen", mail_templates),
        ("E-Mail-Historie", mail_history),
        ("Kundendaten", customer_records),
    ];
    for (name, step) in steps {
        if let Err(e) = step(jtl, conn, ctx, report) {
            report.limitations.push(format!("{name}: {e}"));
        }
    }
}

fn db_version(
    jtl: &Jtl5,
    conn: &mut Conn,
    _ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !table_exists(conn, "tversion")? {
        return Ok(());
    }
    let cols = columns(conn, "tversion")?;
    let rows = query_rows(conn, "SELECT * FROM tversion LIMIT 1")?;
    let Some(row) = rows.first() else {
        return Ok(());
    };
    let db_version = if cols.contains(&"cversion".to_string()) {
        col(row, "cVersion").to_string()
    } else {
        let n = col(row, "nVersion");
        if n.len() == 3 {
            format!("{}.{}.{}", &n[0..1], &n[1..2], &n[2..3])
        } else {
            n.to_string()
        }
    };
    if db_version.is_empty() {
        return Ok(());
    }
    let status = match (&jtl.version(), ecomsec_core::Version::parse(&db_version)) {
        (Some(file_v), Some(db_v)) if **file_v != db_v => IntegrityStatus::Warning,
        _ => IntegrityStatus::Ok,
    };
    let mut item = IntegrityItem::new(
        "shop.version.db",
        "Shop",
        "Version laut Datenbank (tversion)",
        status,
        &db_version,
    );
    if status == IntegrityStatus::Warning {
        item = item.with_detail("Weicht von der Version in includes/defines.php ab – unvollständiges Update oder manipulierte Dateien.");
    }
    report.items.push(item);
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct AdminSnapshot {
    accounts: BTreeMap<String, String>,
}

fn admin_accounts(
    _jtl: &Jtl5,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !table_exists(conn, "tadminlogin")? {
        report
            .limitations
            .push("Tabelle tadminlogin nicht vorhanden.".into());
        return Ok(());
    }
    let cols = columns(conn, "tadminlogin")?;
    let has = |c: &str| cols.contains(&c.to_ascii_lowercase());
    let mut select = vec!["kAdminlogin", "cLogin"];
    for c in [
        "cName",
        "cMail",
        "dLetzterLogin",
        "b2FAauth",
        "bAktiv",
        "kAdminlogingruppe",
        "nLoginVersuch",
        "dGueltigBis",
        "dErstellt",
    ] {
        if has(c) {
            select.push(c);
        }
    }
    let sql = format!(
        "SELECT {} FROM tadminlogin ORDER BY kAdminlogin",
        select.join(", ")
    );
    let rows = query_rows(conn, &sql)?;
    let previous: AdminSnapshot = ctx.state.snapshot("jtl-admins").unwrap_or_default();
    let mut current = AdminSnapshot::default();
    let mut without_2fa = 0usize;
    for row in &rows {
        let login = col(row, "cLogin").to_string();
        let mail = col(row, "cMail").to_string();
        let last_login = col(row, "dLetzterLogin").to_string();
        let tfa = has("b2FAauth") && col(row, "b2FAauth") == "1";
        let active = !has("bAktiv") || col(row, "bAktiv") == "1";
        let group = col(row, "kAdminlogingruppe");
        let is_admin = group.is_empty() || group == "1";
        let fingerprint = sha256_hex(format!("{login}|{mail}|{tfa}|{group}").as_bytes());
        current.accounts.insert(login.clone(), fingerprint.clone());

        let status = if !active {
            IntegrityStatus::Unknown
        } else if tfa {
            IntegrityStatus::Ok
        } else {
            without_2fa += 1;
            IntegrityStatus::Warning
        };
        let value = format!(
            "{} · 2FA: {} · letzter Login: {}{}",
            if active { "aktiv" } else { "inaktiv" },
            if has("b2FAauth") {
                if tfa {
                    "ja"
                } else {
                    "nein"
                }
            } else {
                "unbekannt"
            },
            if last_login.is_empty() {
                "nie".to_string()
            } else {
                last_login.clone()
            },
            if is_admin { " · Administrator" } else { "" }
        );
        report.items.push(
            IntegrityItem::new(
                format!("admin.account.{login}"),
                "Admin-Konten",
                &login,
                status,
                value,
            )
            .with_detail(format!("E-Mail: {}", mask_email(&mail))),
        );

        match previous.accounts.get(&login) {
            None if !previous.accounts.is_empty() => {
                report.findings.push(
                    Finding::new(
                        Severity::Critical,
                        Category::AdminAccount,
                        Source::Database,
                        "admin_account_new",
                        format!("tadminlogin:{login}"),
                        format!("Neues Admin-Konto seit dem letzten Scan: {login}"),
                    )
                    .with_description(
                        "Das Konto existierte beim letzten Scan nicht. Angreifer legen nach einer Kompromittierung \
                         häufig zusätzliche Administratoren an. Konto zuordnen oder sofort deaktivieren.",
                    )
                    .with_evidence(format!("E-Mail {} · letzter Login {}", mask_email(&mail), last_login)),
                );
            }
            Some(prev) if *prev != fingerprint => {
                report.findings.push(
                    Finding::new(
                        Severity::Warning,
                        Category::AdminAccount,
                        Source::Database,
                        "admin_account_changed",
                        format!("tadminlogin:{login}"),
                        format!("Admin-Konto geändert (E-Mail/2FA/Gruppe): {login}"),
                    )
                    .with_description("E-Mail-Adresse, 2FA-Status oder Rechtegruppe des Kontos haben sich seit dem letzten Scan geändert.")
                    .with_evidence(format!("E-Mail {} · 2FA {}", mask_email(&mail), tfa)),
                );
            }
            _ => {}
        }
        if active && !tfa && has("b2FAauth") {
            report.findings.push(
                Finding::new(
                    Severity::Info,
                    Category::AdminAccount,
                    Source::Database,
                    "admin_without_2fa",
                    format!("tadminlogin:{login}"),
                    format!("Admin-Konto ohne Zwei-Faktor-Authentifizierung: {login}"),
                )
                .with_description("2FA im Backend unter Benutzerverwaltung aktivieren."),
            );
        }
        if has("dErstellt") && after_reference(col(row, "dErstellt"), ctx) {
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    Category::AdminAccount,
                    Source::Database,
                    "admin_created_after_reference",
                    format!("tadminlogin:{login}"),
                    format!("Admin-Konto nach dem Referenzdatum angelegt: {login}"),
                )
                .with_evidence(format!("erstellt {}", col(row, "dErstellt"))),
            );
        }
    }
    report.items.push(IntegrityItem::new(
        "admin.summary",
        "Admin-Konten",
        "Konten gesamt / ohne 2FA",
        if without_2fa > 0 {
            IntegrityStatus::Warning
        } else {
            IntegrityStatus::Ok
        },
        format!("{} / {}", rows.len(), without_2fa),
    ));
    ctx.state.save_snapshot("jtl-admins", &current)?;
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct PaymentSnapshot {
    values: BTreeMap<String, String>,
}

fn paypal(
    _jtl: &Jtl5,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    let mut found: BTreeMap<String, String> = BTreeMap::new();
    if table_exists(conn, "tplugineinstellungen")? && table_exists(conn, "tplugin")? {
        let sql = "SELECT p.cPluginID AS plugin, e.cName AS name, e.cWert AS value \
                   FROM tplugineinstellungen e JOIN tplugin p ON p.kPlugin = e.kPlugin \
                   WHERE (LOWER(p.cPluginID) LIKE '%paypal%' OR LOWER(e.cName) LIKE '%paypal%') \
                     AND (LOWER(e.cName) LIKE '%merchant%' OR LOWER(e.cName) LIKE '%email%' OR LOWER(e.cName) LIKE '%mail%' \
                          OR LOWER(e.cName) LIKE '%payer%' OR LOWER(e.cName) LIKE '%client_id%' OR LOWER(e.cName) LIKE '%clientid%' \
                          OR LOWER(e.cName) LIKE '%account%' OR LOWER(e.cName) LIKE '%receiver%' OR LOWER(e.cName) LIKE '%empf%')";
        for row in query_rows(conn, sql)? {
            let key = format!("{}:{}", col(&row, "plugin"), col(&row, "name"));
            found.insert(key, col(&row, "value").to_string());
        }
    }
    if table_exists(conn, "tzahlungsarteinstellungen")? {
        let sql = "SELECT cModulId AS plugin, cName AS name, cWert AS value FROM tzahlungsarteinstellungen \
                   WHERE LOWER(cModulId) LIKE '%paypal%' AND (LOWER(cName) LIKE '%mail%' OR LOWER(cName) LIKE '%account%' OR LOWER(cName) LIKE '%merchant%' OR LOWER(cName) LIKE '%empf%')";
        for row in query_rows(conn, sql)? {
            let key = format!("{}:{}", col(&row, "plugin"), col(&row, "name"));
            found.insert(key, col(&row, "value").to_string());
        }
    }
    if table_exists(conn, "teinstellungen")? {
        let sql = "SELECT cName AS name, cWert AS value FROM teinstellungen WHERE LOWER(cName) LIKE '%paypal%' AND (LOWER(cName) LIKE '%mail%' OR LOWER(cName) LIKE '%account%' OR LOWER(cName) LIKE '%merchant%')";
        for row in query_rows(conn, sql)? {
            found.insert(
                format!("teinstellungen:{}", col(&row, "name")),
                col(&row, "value").to_string(),
            );
        }
    }
    if found.is_empty() {
        report.items.push(
            IntegrityItem::new(
                "payment.paypal",
                "Zahlung",
                "PayPal-Empfängerkonto",
                IntegrityStatus::Unknown,
                "nicht konfiguriert / nicht gefunden",
            )
            .with_detail(
                "Weder PayPal-Checkout-Plugin-Einstellungen noch Legacy-Einstellungen gefunden.",
            ),
        );
        return Ok(());
    }
    let previous: PaymentSnapshot = ctx.state.snapshot("jtl-paypal").unwrap_or_default();
    let mut current = PaymentSnapshot::default();
    for (key, value) in &found {
        let digest = sha256_hex(value.as_bytes());
        current.values.insert(key.clone(), digest.clone());
        let masked = if value.contains('@') {
            mask_email(value)
        } else {
            mask(value)
        };
        let changed = matches!(previous.values.get(key), Some(prev) if *prev != digest);
        let status = if changed {
            IntegrityStatus::Critical
        } else {
            IntegrityStatus::Ok
        };
        let mut item = IntegrityItem::new(
            format!("payment.paypal.{key}"),
            "Zahlung",
            key,
            status,
            if value.is_empty() {
                "(leer)".to_string()
            } else {
                masked.clone()
            },
        );
        if changed {
            item = item.with_detail("Wert hat sich seit dem letzten Scan geändert!");
            report.findings.push(
                Finding::new(
                    Severity::Critical,
                    Category::PaymentConfiguration,
                    Source::Database,
                    "paypal_recipient_changed",
                    key.clone(),
                    "PayPal-Empfänger-/Händlerkennung hat sich geändert",
                )
                .with_description(
                    "Die PayPal-Konfiguration unterscheidet sich vom Stand des letzten Scans. Wenn die Änderung nicht \
                     selbst vorgenommen wurde, leitet ein Angreifer möglicherweise Zahlungen um.",
                )
                .with_evidence(format!("neuer Wert: {masked}")),
            );
        }
        report.items.push(item);
    }
    ctx.state.save_snapshot("jtl-paypal", &current)?;
    Ok(())
}

fn plugins(
    _jtl: &Jtl5,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !table_exists(conn, "tplugin")? {
        return Ok(());
    }
    let cols = columns(conn, "tplugin")?;
    let has = |c: &str| cols.contains(&c.to_ascii_lowercase());
    let mut select = vec!["kPlugin", "cName", "cPluginID", "nStatus"];
    for c in [
        "nVersion",
        "dInstalliert",
        "dZuletztAktualisiert",
        "bExtension",
    ] {
        if has(c) {
            select.push(c);
        }
    }
    let rows = query_rows(
        conn,
        &format!("SELECT {} FROM tplugin ORDER BY cName", select.join(", ")),
    )?;
    let mut active = 0usize;
    for row in &rows {
        let name = col(row, "cName");
        let id = col(row, "cPluginID");
        let status = col(row, "nStatus");
        if status == "2" {
            active += 1;
        }
        let installed = col(row, "dInstalliert");
        let updated = col(row, "dZuletztAktualisiert");
        if after_reference(installed, ctx) {
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    Category::Informational,
                    Source::Database,
                    "plugin_installed_after_reference",
                    format!("tplugin:{id}"),
                    format!("Plugin nach dem Referenzdatum installiert: {name}"),
                )
                .with_description("Prüfen, ob die Installation bekannt und gewollt ist. Unbekannte Plugins können Fremdcode enthalten.")
                .with_evidence(format!("{id} · installiert {installed} · Status {status}")),
            );
        } else if after_reference(updated, ctx) {
            report.findings.push(
                Finding::new(
                    Severity::Info,
                    Category::Informational,
                    Source::Database,
                    "plugin_updated_after_reference",
                    format!("tplugin:{id}"),
                    format!("Plugin nach dem Referenzdatum aktualisiert: {name}"),
                )
                .with_evidence(format!("{id} · aktualisiert {updated}")),
            );
        }
    }
    report.items.push(
        IntegrityItem::new(
            "plugins.summary",
            "Plugins",
            "Plugins installiert / aktiv",
            IntegrityStatus::Ok,
            format!("{} / {}", rows.len(), active),
        )
        .with_detail(
            rows.iter()
                .map(|r| col(r, "cPluginID").to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ),
    );
    Ok(())
}

fn cron(
    _jtl: &Jtl5,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !table_exists(conn, "tcron")? {
        return Ok(());
    }
    let cols = columns(conn, "tcron")?;
    let has = |c: &str| cols.contains(&c.to_ascii_lowercase());
    let mut select = vec!["cronID"];
    for c in [
        "name",
        "jobType",
        "frequency",
        "startDate",
        "lastStart",
        "nextStart",
        "foreignKey",
        "tableName",
    ] {
        if has(c) {
            select.push(c);
        }
    }
    let rows = query_rows(conn, &format!("SELECT {} FROM tcron", select.join(", ")))?;
    let known = [
        "statusemail",
        "export",
        "newsletter",
        "imagecache",
        "xselling",
        "topseller",
        "bestseller",
        "sitemap",
        "mailqueue",
        "licensecheck",
        "upgrade",
        "dataexport",
        "dbes",
        "wishlist",
        "dbcheck",
    ];
    for row in &rows {
        let job = col(row, "jobType").to_string();
        let name = col(row, "name").to_string();
        let start = col(row, "startDate").to_string();
        let suspicious = !known.iter().any(|k| job.to_ascii_lowercase().contains(k));
        if suspicious || after_reference(&start, ctx) {
            report.findings.push(
                Finding::new(
                    if suspicious { Severity::Warning } else { Severity::Info },
                    Category::Informational,
                    Source::Database,
                    "cron_job",
                    format!("tcron:{}:{}", col(row, "cronID"), job),
                    format!("Cronjob prüfen: {} ({})", if name.is_empty() { &job } else { &name }, job),
                )
                .with_description("Cronjobs führen regelmäßig Code aus. Unbekannte Job-Typen oder nach dem Referenzdatum angelegte Jobs zuordnen.")
                .with_evidence(format!("Start {} · letzter Lauf {}", start, col(row, "lastStart"))),
            );
        }
    }
    report.items.push(IntegrityItem::new(
        "cron.summary",
        "Cronjobs",
        "Cronjobs in tcron",
        IntegrityStatus::Ok,
        rows.len().to_string(),
    ));
    Ok(())
}

fn template_rules(jtl: &Jtl5) -> RuleSet {
    let mut set = ecomsec_core::signatures::builtin_rules().unwrap_or_default();
    set.extend(ecomsec_core::platform::Platform::rules(jtl));
    set
}

fn mail_templates(
    jtl: &Jtl5,
    conn: &mut Conn,
    _ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !table_exists(conn, "temailvorlagesprache")? {
        return Ok(());
    }
    let cols = columns(conn, "temailvorlagesprache")?;
    let has = |c: &str| cols.contains(&c.to_ascii_lowercase());
    let mut select = vec!["kEmailvorlage", "kSprache"];
    for c in ["cBetreff", "cContentHtml", "cContentText"] {
        if has(c) {
            select.push(c);
        }
    }
    let rows = query_rows(
        conn,
        &format!("SELECT {} FROM temailvorlagesprache", select.join(", ")),
    )?;
    let rules = template_rules(jtl);
    let mut hits = 0usize;
    for row in &rows {
        let id = format!(
            "temailvorlagesprache:{}:{}",
            col(row, "kEmailvorlage"),
            col(row, "kSprache")
        );
        for field in ["cBetreff", "cContentHtml", "cContentText"] {
            let text = col(row, field);
            if text.is_empty() {
                continue;
            }
            for hit in rules.scan("template", text.as_bytes()) {
                if hit.rule.spec.category != Category::ExploitPayload
                    && hit.rule.spec.severity != Severity::Critical
                {
                    continue;
                }
                hits += 1;
                let mut f = Finding::new(
                    Severity::Critical,
                    Category::ExploitPayload,
                    Source::Database,
                    hit.rule.name().to_string(),
                    format!("{id}:{field}"),
                    format!("E-Mail-Vorlage enthält verdächtigen Template-Code ({})", hit.rule.spec.description),
                )
                .with_description("Gespeicherte E-Mail-Vorlagen werden bei jedem Versand durch Smarty ausgeführt – ein idealer Persistenzort für Angreifer. Vorlage im Backend prüfen und aus einem sauberen Stand wiederherstellen.");
                for ex in hit.excerpts.iter().take(2) {
                    f = f.with_evidence(ex.clone());
                }
                report.findings.push(f);
            }
        }
    }
    report.items.push(IntegrityItem::new(
        "mail.templates",
        "E-Mail",
        "E-Mail-Vorlagen mit verdächtigem Code",
        if hits > 0 {
            IntegrityStatus::Critical
        } else {
            IntegrityStatus::Ok
        },
        format!("{hits} von {} Vorlagen", rows.len()),
    ));
    Ok(())
}

/// Smarty payload fragments searched in e-mail subjects / names.
const PAYLOAD_LIKE: &[&str] = &[
    "{capture",
    "{eval",
    "{php",
    "{literal",
    "{include",
    "{$smarty",
    "|unserialize",
    "file_get_contents",
    "{$",
    "{if",
    "{assign",
    "{function",
    "system(",
    "base64_decode",
];

fn like_clause(column: &str) -> String {
    PAYLOAD_LIKE
        .iter()
        .map(|p| {
            format!(
                "{column} LIKE '%{}%'",
                p.replace('\'', "''").replace('%', "\\%")
            )
        })
        .collect::<Vec<_>>()
        .join(" OR ")
}

fn mail_history(
    _jtl: &Jtl5,
    conn: &mut Conn,
    _ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !table_exists(conn, "temailhistory")? {
        report
            .limitations
            .push("Tabelle temailhistory nicht vorhanden – E-Mail-Historie nicht geprüft.".into());
        return Ok(());
    }
    let cols = columns(conn, "temailhistory")?;
    let has = |c: &str| cols.contains(&c.to_ascii_lowercase());
    let mut select = vec!["kEmailhistory"];
    let mut searched = Vec::new();
    for c in [
        "cSubject",
        "cFromName",
        "cFromEmail",
        "cToName",
        "cToEmail",
        "dSent",
    ] {
        if has(c) {
            select.push(c);
            if c != "dSent" && c != "cFromEmail" {
                searched.push(c);
            }
        }
    }
    if searched.is_empty() {
        return Ok(());
    }
    let where_clause = searched
        .iter()
        .map(|c| format!("({})", like_clause(c)))
        .collect::<Vec<_>>()
        .join(" OR ");
    let date_filter = if has("dSent") {
        "dSent >= DATE_SUB(NOW(), INTERVAL 90 DAY) AND "
    } else {
        ""
    };
    let sql = format!(
        "SELECT {} FROM temailhistory WHERE {date_filter}({where_clause}) ORDER BY kEmailhistory DESC LIMIT 200",
        select.join(", ")
    );
    let rows = query_rows(conn, &sql)?;
    let total: Option<u64> = {
        use mysql::prelude::Queryable;
        conn.query_first(format!(
            "SELECT COUNT(*) FROM temailhistory WHERE {}1=1",
            date_filter
        ))
        .unwrap_or(None)
    };
    for row in &rows {
        let subject = col(row, "cSubject");
        let evidence_field = searched
            .iter()
            .map(|c| (c, col(row, c)))
            .find(|(_, v)| PAYLOAD_LIKE.iter().any(|p| v.contains(p)))
            .map(|(c, v)| format!("{c}: {}", excerpt(v, 160)))
            .unwrap_or_else(|| format!("Betreff: {}", excerpt(subject, 160)));
        let strong = subject.contains("{capture")
            || subject.contains("{eval")
            || subject.contains("|unserialize")
            || evidence_field.contains("{eval")
            || evidence_field.contains("{capture");
        report.findings.push(
            Finding::new(
                if strong { Severity::Critical } else { Severity::Warning },
                Category::AttackTrace,
                Source::Database,
                "mail_history_ssti",
                format!("temailhistory:{}", col(row, "kEmailhistory")),
                "Angriffs-Payload in versendeter E-Mail (temailhistory)",
            )
            .with_description(
                "Eine versendete E-Mail enthält Smarty-Template-Syntax in Betreff oder Namen. Das ist die typische Spur \
                 eines Angriffs auf CVE-2026-54390 (Payload über Registrierung/Kontakt/Passwort-Reset). War der Shop zum \
                 Zeitpunkt des Versands ungepatcht, ist von einer erfolgreichen Ausnutzung auszugehen.",
            )
            .with_evidence(evidence_field)
            .with_evidence(format!("gesendet {} an {}", col(row, "dSent"), mask_email(col(row, "cToEmail")))),
        );
    }
    report.items.push(IntegrityItem::new(
        "mail.history",
        "E-Mail",
        "E-Mail-Historie (90 Tage) mit Angriffsmustern",
        if rows.is_empty() {
            IntegrityStatus::Ok
        } else {
            IntegrityStatus::Critical
        },
        format!(
            "{} Treffer{}",
            rows.len(),
            total
                .map(|t| format!(" in {t} E-Mails"))
                .unwrap_or_default()
        ),
    ));
    Ok(())
}

fn customer_records(
    _jtl: &Jtl5,
    conn: &mut Conn,
    _ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    let probes: &[(&str, &[&str], &str, &str)] = &[
        (
            "tkunde",
            &[
                "cVorname",
                "cNachname",
                "cFirma",
                "cStrasse",
                "cOrt",
                "cMail",
            ],
            "kKunde",
            "dErstellt",
        ),
        (
            "tkontakthistory",
            &["cNachricht", "cBetreff", "cVorname", "cNachname", "cMail"],
            "kKontaktHistory",
            "dErstellt",
        ),
        (
            "tnewsletterempfaenger",
            &["cVorname", "cNachname", "cEmail"],
            "kNewsletterEmpfaenger",
            "dEingetragen",
        ),
        ("tbestellung", &["cKommentar"], "kBestellung", "dErstellt"),
        (
            "tlieferadresse",
            &["cVorname", "cNachname", "cFirma"],
            "kLieferadresse",
            "",
        ),
        (
            "trechnungsadresse",
            &["cVorname", "cNachname", "cFirma"],
            "kRechnungsadresse",
            "",
        ),
    ];
    let mut total_hits = 0usize;
    for (table, fields, key, date) in probes {
        if !table_exists(conn, table)? {
            continue;
        }
        let cols = columns(conn, table)?;
        let present: Vec<&str> = fields
            .iter()
            .copied()
            .filter(|f| cols.contains(&f.to_ascii_lowercase()))
            .collect();
        if present.is_empty() || !cols.contains(&key.to_ascii_lowercase()) {
            continue;
        }
        let smarty_like = present
            .iter()
            .map(|c| format!("({c} LIKE '%{{%}}%' OR {c} LIKE '%{{$%' OR {c} LIKE '%{{eval%' OR {c} LIKE '%{{capture%' OR {c} LIKE '%|unserialize%')"))
            .collect::<Vec<_>>()
            .join(" OR ");
        let mut select: Vec<String> = vec![key.to_string()];
        select.extend(present.iter().map(|s| s.to_string()));
        if !date.is_empty() && cols.contains(&date.to_ascii_lowercase()) {
            select.push(date.to_string());
        }
        let sql = format!(
            "SELECT {} FROM {table} WHERE {smarty_like} ORDER BY {key} DESC LIMIT 100",
            select.join(", ")
        );
        let rows = query_rows(conn, &sql)?;
        for row in &rows {
            total_hits += 1;
            let (field, value) = present
                .iter()
                .map(|c| (*c, col(row, c)))
                .find(|(_, v)| v.contains('{'))
                .unwrap_or((present[0], ""));
            let strong = value.contains("{eval")
                || value.contains("{capture")
                || value.contains("|unserialize")
                || value.contains("file_get_contents");
            report.findings.push(
                Finding::new(
                    if strong { Severity::Critical } else { Severity::Warning },
                    Category::AttackTrace,
                    Source::Database,
                    "record_with_template_syntax",
                    format!("{table}:{}", col(row, key)),
                    format!("Datensatz mit Smarty-Syntax in {table}.{field}"),
                )
                .with_description(
                    "Kunden-, Kontakt- oder Bestelldaten enthalten Template-Syntax. Solche Werte landen in E-Mails und \
                     werden dort von Smarty ausgeführt (CVE-2026-54390). Datensatz prüfen, Eingabe bereinigen und \
                     Zeitpunkt mit dem Patch-Stand abgleichen.",
                )
                .with_evidence(excerpt(value, 160))
                .with_evidence(format!("angelegt {}", if date.is_empty() { "?" } else { col(row, date) })),
            );
        }
    }
    report.items.push(IntegrityItem::new(
        "records.template_syntax",
        "E-Mail",
        "Datensätze mit Template-Syntax (Kunden, Kontakt, Newsletter, Bestellungen)",
        if total_hits > 0 {
            IntegrityStatus::Critical
        } else {
            IntegrityStatus::Ok
        },
        total_hits.to_string(),
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_clause_escapes() {
        let c = like_clause("cSubject");
        assert!(c.contains("cSubject LIKE '%{capture%'"));
        assert!(!c.contains("''%"));
    }

    #[test]
    fn row_helpers() {
        let row: Vec<(String, String)> = vec![("cLogin".into(), "admin".into())];
        assert_eq!(col(&row, "clogin"), "admin");
        assert!(after_reference(
            "2026-07-01 10:00:00",
            &PlatformContext {
                reference_date: chrono::NaiveDate::from_ymd_opt(2026, 6, 17).unwrap(),
                skip_remote: true,
                state: ecomsec_core::StateStore::new("/nonexistent"),
            }
        ));
    }
}
