//! Database based checks for Shopware 6 (read-only).

use crate::Shopware6;
use chrono::NaiveDateTime;
use ecomsec_core::db::{col, columns, query_rows, table_exists};
use ecomsec_core::finding::{Category, Finding, Severity, Source};
use ecomsec_core::platform::{
    IntegrityItem, IntegrityReport, IntegrityStatus, Platform, PlatformContext,
};
use ecomsec_core::rules::RuleSet;
use ecomsec_core::util::{excerpt, mask, mask_email, sha256_hex};
use mysql::Conn;
use std::collections::BTreeMap;

fn after_reference(s: &str, ctx: &PlatformContext) -> bool {
    let s = s.get(..19).unwrap_or(s);
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .map(|d| d.date() >= ctx.reference_date)
        .unwrap_or(false)
}

type Step = fn(&Shopware6, &mut Conn, &PlatformContext, &mut IntegrityReport) -> anyhow::Result<()>;

pub fn run(sw: &Shopware6, conn: &mut Conn, ctx: &PlatformContext, report: &mut IntegrityReport) {
    let steps: Vec<(&str, Step)> = vec![
        ("Admin-Benutzer", users),
        ("Integrationen", integrations),
        ("Apps", apps),
        ("Plugins", plugins),
        ("Zahlungsanbieter", payment_config),
        ("Mail-Templates", mail_templates),
        ("Flows", flows),
        ("Snippets / CMS", storefront_injection),
    ];
    for (name, step) in steps {
        if let Err(e) = step(sw, conn, ctx, report) {
            report.limitations.push(format!("{name}: {e}"));
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Snapshot {
    entries: BTreeMap<String, String>,
}

fn users(
    _sw: &Shopware6,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !table_exists(conn, "user")? {
        report
            .limitations
            .push("Tabelle `user` nicht vorhanden.".into());
        return Ok(());
    }
    let cols = columns(conn, "user")?;
    let has = |c: &str| cols.contains(&c.to_string());
    let mut select = vec![
        "LOWER(HEX(id)) AS id",
        "username",
        "email",
        "active",
        "admin",
        "created_at",
    ];
    for c in ["last_updated_password_at", "updated_at", "time_zone"] {
        if has(c) {
            select.push(c);
        }
    }
    let rows = query_rows(
        conn,
        &format!(
            "SELECT {} FROM `user` ORDER BY created_at",
            select.join(", ")
        ),
    )?;
    let previous: Snapshot = ctx.state.snapshot("sw-users").unwrap_or_default();
    let mut current = Snapshot::default();
    let mut admins = 0usize;
    for row in &rows {
        let username = col(row, "username").to_string();
        let email = col(row, "email").to_string();
        let admin = col(row, "admin") == "1";
        let active = col(row, "active") == "1";
        let created = col(row, "created_at").to_string();
        let pw_changed = col(row, "last_updated_password_at").to_string();
        if admin && active {
            admins += 1;
        }
        let fp = sha256_hex(format!("{username}|{email}|{admin}|{active}").as_bytes());
        current.entries.insert(username.clone(), fp.clone());
        report.items.push(
            IntegrityItem::new(
                format!("admin.account.{username}"),
                "Admin-Konten",
                &username,
                if !active {
                    IntegrityStatus::Unknown
                } else if admin {
                    IntegrityStatus::Warning
                } else {
                    IntegrityStatus::Ok
                },
                format!(
                    "{} · {} · angelegt {} · Passwort geändert {}",
                    if active { "aktiv" } else { "inaktiv" },
                    if admin {
                        "Administrator"
                    } else {
                        "eingeschränkte Rolle"
                    },
                    created.get(..10).unwrap_or(&created),
                    if pw_changed.is_empty() {
                        "nie"
                    } else {
                        pw_changed.get(..10).unwrap_or(&pw_changed)
                    }
                ),
            )
            .with_detail(format!(
                "E-Mail: {} · 2FA: nicht im Shopware-Core verfügbar",
                mask_email(&email)
            )),
        );
        match previous.entries.get(&username) {
            None if !previous.entries.is_empty() => report.findings.push(
                Finding::new(Severity::Critical, Category::AdminAccount, Source::Database, "admin_account_new", format!("user:{username}"), format!("Neuer Backend-Benutzer seit dem letzten Scan: {username}"))
                    .with_description("Der Benutzer existierte beim letzten Scan nicht. Zuordnen oder sofort deaktivieren und Passwort-/Token-Rotation durchführen.")
                    .with_evidence(format!("E-Mail {} · admin={admin} · angelegt {created}", mask_email(&email))),
            ),
            Some(prev) if *prev != fp => report.findings.push(
                Finding::new(Severity::Warning, Category::AdminAccount, Source::Database, "admin_account_changed", format!("user:{username}"), format!("Backend-Benutzer geändert (E-Mail/Rolle/Status): {username}"))
                    .with_evidence(format!("E-Mail {} · admin={admin} · aktiv={active}", mask_email(&email))),
            ),
            _ => {}
        }
        if after_reference(&created, ctx) {
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    Category::AdminAccount,
                    Source::Database,
                    "admin_created_after_reference",
                    format!("user:{username}"),
                    format!("Backend-Benutzer nach dem Referenzdatum angelegt: {username}"),
                )
                .with_evidence(format!("angelegt {created} · admin={admin}")),
            );
        }
    }
    report.items.push(IntegrityItem::new(
        "admin.summary",
        "Admin-Konten",
        "Benutzer gesamt / aktive Administratoren",
        IntegrityStatus::Ok,
        format!("{} / {admins}", rows.len()),
    ));
    ctx.state.save_snapshot("sw-users", &current)?;
    Ok(())
}

fn integrations(
    _sw: &Shopware6,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !table_exists(conn, "integration")? {
        return Ok(());
    }
    let cols = columns(conn, "integration")?;
    let has = |c: &str| cols.contains(&c.to_string());
    let mut select = vec!["LOWER(HEX(id)) AS id", "label", "access_key", "created_at"];
    for c in ["admin", "last_usage_at", "write_access", "updated_at"] {
        if has(c) {
            select.push(c);
        }
    }
    let rows = query_rows(
        conn,
        &format!(
            "SELECT {} FROM integration ORDER BY created_at",
            select.join(", ")
        ),
    )?;
    let previous: Snapshot = ctx.state.snapshot("sw-integrations").unwrap_or_default();
    let mut current = Snapshot::default();
    for row in &rows {
        let id = col(row, "id").to_string();
        let label = col(row, "label").to_string();
        let admin = col(row, "admin") == "1" || col(row, "write_access") == "1";
        let created = col(row, "created_at").to_string();
        let key = mask(col(row, "access_key"));
        current.entries.insert(
            id.clone(),
            sha256_hex(format!("{label}|{admin}").as_bytes()),
        );
        report.items.push(
            IntegrityItem::new(
                format!("integration.{id}"),
                "API-Integrationen",
                if label.is_empty() { &id } else { &label },
                if admin {
                    IntegrityStatus::Warning
                } else {
                    IntegrityStatus::Ok
                },
                format!(
                    "{} · Key {key} · angelegt {}",
                    if admin {
                        "Admin-Rechte"
                    } else {
                        "eingeschränkt"
                    },
                    created.get(..10).unwrap_or(&created)
                ),
            )
            .with_detail(format!("letzte Nutzung: {}", {
                let u = col(row, "last_usage_at");
                if u.is_empty() {
                    "nie"
                } else {
                    u
                }
            })),
        );
        if !previous.entries.is_empty() && !previous.entries.contains_key(&id) {
            report.findings.push(
                Finding::new(Severity::Critical, Category::AdminAccount, Source::Database, "integration_new", format!("integration:{id}"), format!("Neue Admin-API-Integration seit dem letzten Scan: {label}"))
                    .with_description("API-Integrationen sind vollwertige Zugänge zur Admin-API. Unbekannte Integrationen sofort löschen.")
                    .with_evidence(format!("admin={admin} · angelegt {created}")),
            );
        } else if after_reference(&created, ctx) {
            report.findings.push(
                Finding::new(
                    if admin {
                        Severity::Warning
                    } else {
                        Severity::Info
                    },
                    Category::AdminAccount,
                    Source::Database,
                    "integration_created_after_reference",
                    format!("integration:{id}"),
                    format!("API-Integration nach dem Referenzdatum angelegt: {label}"),
                )
                .with_evidence(format!("admin={admin} · angelegt {created}")),
            );
        }
    }
    ctx.state.save_snapshot("sw-integrations", &current)?;
    Ok(())
}

fn apps(
    _sw: &Shopware6,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !table_exists(conn, "app")? {
        return Ok(());
    }
    let rows = query_rows(conn, "SELECT LOWER(HEX(id)) AS id, name, active, version, author, created_at, updated_at FROM app ORDER BY name")?;
    let previous: Snapshot = ctx.state.snapshot("sw-apps").unwrap_or_default();
    let mut current = Snapshot::default();
    let mut active = 0usize;
    for row in &rows {
        let name = col(row, "name").to_string();
        let created = col(row, "created_at").to_string();
        if col(row, "active") == "1" {
            active += 1;
        }
        current
            .entries
            .insert(name.clone(), col(row, "version").to_string());
        if !previous.entries.is_empty() && !previous.entries.contains_key(&name) {
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    Category::ThirdPartyInjection,
                    Source::Database,
                    "app_new",
                    format!("app:{name}"),
                    format!("Neue App seit dem letzten Scan: {name}"),
                )
                .with_evidence(format!(
                    "Version {} · Autor {} · installiert {created}",
                    col(row, "version"),
                    col(row, "author")
                )),
            );
        } else if after_reference(&created, ctx) {
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    Category::Informational,
                    Source::Database,
                    "app_installed_after_reference",
                    format!("app:{name}"),
                    format!("App nach dem Referenzdatum installiert: {name}"),
                )
                .with_evidence(format!(
                    "Version {} · Autor {} · installiert {created}",
                    col(row, "version"),
                    col(row, "author")
                )),
            );
        }
    }
    report.items.push(
        IntegrityItem::new(
            "apps.summary",
            "Apps & Plugins",
            "Apps installiert / aktiv",
            IntegrityStatus::Ok,
            format!("{} / {active}", rows.len()),
        )
        .with_detail(
            rows.iter()
                .map(|r| col(r, "name").to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ),
    );
    ctx.state.save_snapshot("sw-apps", &current)?;
    Ok(())
}

fn plugins(
    _sw: &Shopware6,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !table_exists(conn, "plugin")? {
        return Ok(());
    }
    let rows = query_rows(conn, "SELECT name, active, version, author, installed_at, upgraded_at, managed_by_composer FROM plugin ORDER BY name")?;
    let mut active = 0usize;
    for row in &rows {
        let name = col(row, "name");
        if col(row, "active") == "1" {
            active += 1;
        }
        if after_reference(col(row, "installed_at"), ctx) {
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    Category::Informational,
                    Source::Database,
                    "plugin_installed_after_reference",
                    format!("plugin:{name}"),
                    format!("Plugin nach dem Referenzdatum installiert: {name}"),
                )
                .with_evidence(format!(
                    "Version {} · Autor {} · installiert {}",
                    col(row, "version"),
                    col(row, "author"),
                    col(row, "installed_at")
                )),
            );
        }
    }
    report.items.push(
        IntegrityItem::new(
            "plugins.summary",
            "Apps & Plugins",
            "Plugins installiert / aktiv",
            IntegrityStatus::Ok,
            format!("{} / {active}", rows.len()),
        )
        .with_detail(
            rows.iter()
                .map(|r| col(r, "name").to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ),
    );
    Ok(())
}

/// Extract `_value` from Shopware's system_config JSON wrapper.
fn config_value(raw: &str) -> String {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| v.get("_value").cloned())
        .map(|v| match v {
            serde_json::Value::String(s) => s,
            other => other.to_string(),
        })
        .unwrap_or_else(|| raw.to_string())
}

fn payment_config(
    _sw: &Shopware6,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !table_exists(conn, "system_config")? {
        return Ok(());
    }
    let sql = "SELECT configuration_key AS k, configuration_value AS v, LOWER(HEX(sales_channel_id)) AS sc FROM system_config \
               WHERE (configuration_key LIKE 'SwagPayPal.settings.%' OR configuration_key LIKE 'MolliePayments.config.%' OR configuration_key LIKE 'StripeShopware.%' OR configuration_key LIKE '%Payment%.%' OR configuration_key LIKE '%Pay%.settings.%') \
                 AND (configuration_key LIKE '%merchant%' OR configuration_key LIKE '%Merchant%' OR configuration_key LIKE '%clientId%' OR configuration_key LIKE '%ClientId%' OR configuration_key LIKE '%PayerId%' OR configuration_key LIKE '%apiKey%' OR configuration_key LIKE '%ApiKey%' OR configuration_key LIKE '%account%' OR configuration_key LIKE '%Account%' OR configuration_key LIKE '%email%' OR configuration_key LIKE '%Email%' OR configuration_key LIKE '%webhook%' OR configuration_key LIKE '%Webhook%') \
               ORDER BY configuration_key";
    let rows = query_rows(conn, sql)?;
    if rows.is_empty() {
        report.items.push(IntegrityItem::new(
            "payment.summary",
            "Zahlung",
            "Zahlungsanbieter-Konfiguration",
            IntegrityStatus::Unknown,
            "keine PayPal/Mollie/Stripe-Schlüssel in system_config",
        ));
        return Ok(());
    }
    let previous: Snapshot = ctx.state.snapshot("sw-payment").unwrap_or_default();
    let mut current = Snapshot::default();
    for row in &rows {
        let key = format!(
            "{}{}",
            col(row, "k"),
            if col(row, "sc").is_empty() {
                String::new()
            } else {
                format!("@{}", &col(row, "sc")[..8.min(col(row, "sc").len())])
            }
        );
        let value = config_value(col(row, "v"));
        let digest = sha256_hex(value.as_bytes());
        current.entries.insert(key.clone(), digest.clone());
        let masked = if value.contains('@') {
            mask_email(&value)
        } else {
            mask(&value)
        };
        let changed = matches!(previous.entries.get(&key), Some(p) if *p != digest);
        let mut item = IntegrityItem::new(
            format!("payment.{key}"),
            "Zahlung",
            &key,
            if changed {
                IntegrityStatus::Critical
            } else {
                IntegrityStatus::Ok
            },
            if value.is_empty() {
                "(leer)".into()
            } else {
                masked.clone()
            },
        );
        if changed {
            item = item.with_detail("Wert hat sich seit dem letzten Scan geändert!");
            report.findings.push(
                Finding::new(Severity::Critical, Category::PaymentConfiguration, Source::Database, "payment_config_changed", key.clone(), "Zahlungsanbieter-Konfiguration hat sich geändert")
                    .with_description("Händler-ID, Client-ID, API-Key oder Webhook-Ziel eines Zahlungsanbieters unterscheiden sich vom letzten Scan. Nicht selbst vorgenommene Änderungen deuten auf Zahlungsumleitung hin.")
                    .with_evidence(format!("neuer Wert: {masked}")),
            );
        }
        report.items.push(item);
    }
    ctx.state.save_snapshot("sw-payment", &current)?;
    Ok(())
}

fn template_rules(sw: &Shopware6) -> RuleSet {
    let mut set = ecomsec_core::signatures::builtin_rules().unwrap_or_default();
    set.extend(sw.rules());
    set
}

fn scan_text_rows(
    rules: &RuleSet,
    rows: &[Vec<(String, String)>],
    key: &str,
    fields: &[&str],
    subject_prefix: &str,
    title: &str,
    report: &mut IntegrityReport,
) -> usize {
    let mut hits = 0usize;
    for row in rows {
        let id = col(row, key);
        for field in fields {
            let text = col(row, field);
            if text.is_empty() {
                continue;
            }
            for hit in rules.scan("template", text.as_bytes()) {
                let spec = &hit.rule.spec;
                if spec.severity == Severity::Info {
                    continue;
                }
                hits += 1;
                let mut f = Finding::new(
                    spec.severity,
                    if spec.category == Category::SuspiciousPattern { Category::ExploitPayload } else { spec.category },
                    Source::Database,
                    spec.name.clone(),
                    format!("{subject_prefix}:{id}:{field}"),
                    format!("{title}: {}", spec.description),
                )
                .with_description("Datenbankgespeicherte Templates werden bei jeder Verwendung durch Twig ausgeführt – ein beliebter Persistenzort nach einer Kompromittierung. Inhalt im Backend prüfen und aus einem sauberen Stand wiederherstellen.");
                for ex in hit.excerpts.iter().take(2) {
                    f = f.with_evidence(ex.clone());
                }
                report.findings.push(f);
            }
        }
    }
    hits
}

fn mail_templates(
    sw: &Shopware6,
    conn: &mut Conn,
    _ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !table_exists(conn, "mail_template_translation")? {
        return Ok(());
    }
    let rows = query_rows(conn, "SELECT LOWER(HEX(mail_template_id)) AS id, subject, content_html, content_plain, sender_name FROM mail_template_translation")?;
    let rules = template_rules(sw);
    let hits = scan_text_rows(
        &rules,
        &rows,
        "id",
        &["subject", "content_html", "content_plain", "sender_name"],
        "mail_template",
        "Mail-Template mit verdächtigem Twig-Code",
        report,
    );
    report.items.push(IntegrityItem::new(
        "mail.templates",
        "E-Mail",
        "Mail-Templates mit verdächtigem Code",
        if hits > 0 {
            IntegrityStatus::Critical
        } else {
            IntegrityStatus::Ok
        },
        format!("{hits} Treffer in {} Übersetzungen", rows.len()),
    ));
    Ok(())
}

fn flows(
    sw: &Shopware6,
    conn: &mut Conn,
    _ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !table_exists(conn, "flow_sequence")? {
        return Ok(());
    }
    let rows = query_rows(conn, "SELECT LOWER(HEX(id)) AS id, action_name, config FROM flow_sequence WHERE config IS NOT NULL AND config LIKE '%{%'")?;
    let rules = template_rules(sw);
    let hits = scan_text_rows(
        &rules,
        &rows,
        "id",
        &["config"],
        "flow_sequence",
        "Flow-Builder-Aktion mit verdächtigem Twig-Code",
        report,
    );
    report.items.push(IntegrityItem::new(
        "flows",
        "E-Mail",
        "Flow-Sequenzen mit verdächtigem Code",
        if hits > 0 {
            IntegrityStatus::Critical
        } else {
            IntegrityStatus::Ok
        },
        format!(
            "{hits} Treffer in {} Sequenzen mit Template-Syntax",
            rows.len()
        ),
    ));
    Ok(())
}

fn storefront_injection(
    sw: &Shopware6,
    conn: &mut Conn,
    _ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    let rules = template_rules(sw);
    let mut total = 0usize;
    if table_exists(conn, "snippet")? {
        let rows = query_rows(conn, "SELECT LOWER(HEX(id)) AS id, translation_key, value FROM snippet WHERE value LIKE '%<script%' OR value LIKE '%javascript:%' OR value LIKE '%onerror=%' OR value LIKE '%onload=%' LIMIT 200")?;
        for row in &rows {
            total += 1;
            let value = col(row, "value");
            let sev = if rules
                .scan("template", value.as_bytes())
                .iter()
                .any(|h| h.rule.spec.severity == Severity::Critical)
                || value.contains("http")
            {
                Severity::Critical
            } else {
                Severity::Warning
            };
            report.findings.push(
                Finding::new(sev, Category::ThirdPartyInjection, Source::Database, "snippet_script", format!("snippet:{}", col(row, "id")), format!("Snippet enthält Script/JS-Handler: {}", col(row, "translation_key")))
                    .with_description("Übersetzungs-Snippets werden ungefiltert im Storefront ausgegeben – ein klassischer Weg, Skimmer-JavaScript einzuschleusen.")
                    .with_evidence(excerpt(value, 200)),
            );
        }
    }
    if table_exists(conn, "cms_slot_translation")? {
        let rows = query_rows(conn, "SELECT LOWER(HEX(cms_slot_id)) AS id, config FROM cms_slot_translation WHERE config LIKE '%<script%' OR config LIKE '%javascript:%' OR config LIKE '%onerror=%' LIMIT 200")?;
        for row in &rows {
            total += 1;
            let value = col(row, "config");
            report.findings.push(
                Finding::new(Severity::Warning, Category::ThirdPartyInjection, Source::Database, "cms_slot_script", format!("cms_slot:{}", col(row, "id")), "CMS-Element enthält <script> oder JS-Event-Handler")
                    .with_description("Erlebniswelten-Inhalte mit Script-Tags prüfen: nur bekannte Einbindungen (z. B. Tracking) sind legitim.")
                    .with_evidence(excerpt(value, 200)),
            );
        }
    }
    if table_exists(conn, "theme_translation")? {
        let rows = query_rows(conn, "SELECT LOWER(HEX(theme_id)) AS id, custom_fields FROM theme_translation WHERE custom_fields LIKE '%<script%' LIMIT 50")?;
        for row in &rows {
            total += 1;
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    Category::ThirdPartyInjection,
                    Source::Database,
                    "theme_script",
                    format!("theme:{}", col(row, "id")),
                    "Theme-Konfiguration enthält <script>",
                )
                .with_evidence(excerpt(col(row, "custom_fields"), 200)),
            );
        }
    }
    report.items.push(IntegrityItem::new(
        "storefront.injection",
        "Storefront",
        "Snippets/CMS/Theme mit Script-Einbettungen",
        if total > 0 {
            IntegrityStatus::Warning
        } else {
            IntegrityStatus::Ok
        },
        total.to_string(),
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_config_value() {
        assert_eq!(
            config_value(r#"{"_value":"merchant@example.com"}"#),
            "merchant@example.com"
        );
        assert_eq!(config_value(r#"{"_value":true}"#), "true");
        assert_eq!(config_value("plain"), "plain");
    }
}
