//! Database based checks for Magento 2 / Adobe Commerce (read-only, SELECT
//! only).  Table names carry the optional `db/table_prefix` of env.php.

use crate::files::{fp, MAGENTO_PLATFORM_HOSTS};
use crate::Magento2;
use chrono::NaiveDateTime;
use ecomsec_core::db::{col, columns, query_rows, table_exists};
use ecomsec_core::finding::{Category, Finding, Severity, Source};
use ecomsec_core::hosts::{classify_host, host_of, script_sources, HostClass};
use ecomsec_core::platform::{
    IntegrityItem, IntegrityReport, IntegrityStatus, Platform, PlatformContext,
};
use ecomsec_core::rules::RuleSet;
use ecomsec_core::util::{excerpt, mask, mask_email, sha256_hex};
use mysql::Conn;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

fn after_reference(s: &str, ctx: &PlatformContext) -> bool {
    let s = s.get(..19).unwrap_or(s);
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .map(|d| d.date() >= ctx.reference_date)
        .unwrap_or(false)
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Snapshot {
    entries: BTreeMap<String, String>,
}

pub struct Run<'a> {
    pub m2: &'a Magento2,
    pub prefix: String,
    pub own_hosts: Vec<String>,
    pub cron_jobs: &'a BTreeSet<String>,
    pub modules: Vec<String>,
    rules: RuleSet,
}

impl Run<'_> {
    fn t(&self, name: &str) -> String {
        format!("`{}{}`", self.prefix, name)
    }

    fn exists(&self, conn: &mut Conn, name: &str) -> anyhow::Result<bool> {
        Ok(table_exists(conn, &format!("{}{}", self.prefix, name))?)
    }

    fn cols(&self, conn: &mut Conn, name: &str) -> anyhow::Result<Vec<String>> {
        Ok(columns(conn, &format!("{}{}", self.prefix, name))?)
    }

    fn classify(&self, host: &str) -> HostClass {
        let mut platform: Vec<&str> = MAGENTO_PLATFORM_HOSTS.to_vec();
        platform.extend(self.own_hosts.iter().map(String::as_str));
        classify_host(host, &platform, &self.m2.allow_hosts)
    }
}

type Step = fn(&mut Run, &mut Conn, &PlatformContext, &mut IntegrityReport) -> anyhow::Result<()>;

pub fn run(
    m2: &Magento2,
    cron_jobs: &BTreeSet<String>,
    modules: Vec<String>,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) {
    let mut rules = ecomsec_core::signatures::builtin_rules().unwrap_or_default();
    rules.extend(m2.rules());
    let mut run = Run {
        m2,
        prefix: m2.env().table_prefix.clone(),
        own_hosts: Vec::new(),
        cron_jobs,
        modules,
        rules,
    };
    match run.exists(conn, "core_config_data") {
        Ok(true) => {}
        Ok(false) => {
            report.limitations.push(format!(
                "Tabelle {}core_config_data nicht gefunden – falsches Tabellenpräfix oder keine Magento-Datenbank; DB-Prüfungen übersprungen.",
                run.prefix
            ));
            return;
        }
        Err(e) => {
            report
                .limitations
                .push(format!("Datenbankabfrage fehlgeschlagen: {e}"));
            return;
        }
    }
    let steps: Vec<(&str, Step)> = vec![
        ("Basis-URLs", base_urls),
        ("Admin-Benutzer", admin_users),
        ("Integrationen", integrations),
        ("Head/Footer-Scripts", design_config),
        ("Zahlung", payment_config),
        ("CMS", cms_content),
        ("Template-Direktiven", template_directives),
        ("Cron", cron_schedule),
        ("Module", setup_modules),
    ];
    for (name, step) in steps {
        if let Err(e) = step(&mut run, conn, ctx, report) {
            report.limitations.push(format!("{name}: {e}"));
        }
    }
}

fn scope_label(row: &[(String, String)]) -> String {
    let scope = col(row, "scope");
    let id = col(row, "scope_id");
    if scope == "default" || scope.is_empty() {
        "default".into()
    } else {
        format!("{scope}:{id}")
    }
}

// ------------------------------------------------------------------ urls

const URL_PATHS: &[&str] = &[
    "web/unsecure/base_url",
    "web/secure/base_url",
    "web/unsecure/base_link_url",
    "web/secure/base_link_url",
    "web/unsecure/base_static_url",
    "web/secure/base_static_url",
    "web/unsecure/base_media_url",
    "web/secure/base_media_url",
    "admin/url/custom",
    "admin/url/use_custom",
    "admin/url/custom_path",
];

fn base_urls(
    run: &mut Run,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    let list = URL_PATHS
        .iter()
        .map(|p| format!("'{p}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let rows = query_rows(
        conn,
        &format!(
            "SELECT scope, scope_id, path, value FROM {} WHERE path IN ({list}) ORDER BY path, scope, scope_id",
            run.t("core_config_data")
        ),
    )?;
    for row in &rows {
        let path = col(row, "path");
        if path.ends_with("/base_url") {
            if let Some(h) = host_of(col(row, "value")) {
                if !run.own_hosts.contains(&h) {
                    run.own_hosts.push(h);
                }
            }
        }
    }
    let previous: Snapshot = ctx.state.snapshot("m2-urls").unwrap_or_default();
    let mut current = Snapshot::default();
    for row in &rows {
        let path = col(row, "path");
        let value = col(row, "value").to_string();
        let key = format!("{path}@{}", scope_label(row));
        current.entries.insert(key.clone(), value.clone());
        let changed = matches!(previous.entries.get(&key), Some(p) if *p != value);
        let host = host_of(&value).unwrap_or_default();
        let foreign_asset = (path.contains("static_url") || path.contains("media_url"))
            && value.contains("://")
            && matches!(
                run.classify(&host),
                HostClass::Suspicious | HostClass::Unknown
            );
        report.items.push(IntegrityItem::new(
            format!("magento.config.{key}"),
            "Shop",
            &key,
            if changed || foreign_asset {
                IntegrityStatus::Critical
            } else {
                IntegrityStatus::Ok
            },
            if value.is_empty() {
                "(leer)".into()
            } else {
                value.clone()
            },
        ));
        if changed {
            report.findings.push(
                Finding::new(
                    Severity::Critical,
                    Category::IntegrityDeviation,
                    Source::Database,
                    "magento_base_url_changed",
                    format!("core_config_data:{key}"),
                    format!("Basis-URL/Admin-URL geändert: {path}"),
                )
                .with_description(
                    "Basis-, Static- oder Media-URLs bzw. die Admin-URL unterscheiden sich vom letzten Scan. \
                     Angreifer lenken so Storefront-Assets auf eigene Server (Skimmer) oder Admins auf \
                     Phishing-Seiten. Nicht selbst vorgenommene Änderungen zurücksetzen.",
                )
                .with_evidence(format!(
                    "vorher {} · jetzt {value}",
                    previous.entries.get(&key).cloned().unwrap_or_default()
                )),
            );
        } else if foreign_asset {
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    Category::ThirdPartyInjection,
                    Source::Database,
                    "magento_asset_url_foreign",
                    format!("core_config_data:{key}"),
                    format!("Static-/Media-URL zeigt auf fremden Host {host}"),
                )
                .with_description(
                    "JavaScript der Storefront wird von dieser URL geladen. Ein CDN ist legitim – Host muss \
                     aber eindeutig zugeordnet sein (sonst `--allow-host`).",
                )
                .with_evidence(value.clone()),
            );
        }
    }
    ctx.state.save_snapshot("m2-urls", &current)?;
    Ok(())
}

// ------------------------------------------------------------------ admins

fn admin_users(
    run: &mut Run,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !run.exists(conn, "admin_user")? {
        report
            .limitations
            .push("Tabelle admin_user nicht vorhanden.".into());
        return Ok(());
    }
    let cols = run.cols(conn, "admin_user")?;
    let has = |c: &str| cols.iter().any(|x| x == c);
    let mut select = vec![
        "a.user_id AS user_id",
        "a.username AS username",
        "a.email AS email",
    ];
    for c in [
        "is_active",
        "created",
        "modified",
        "logdate",
        "lognum",
        "failures_num",
        "lock_expires",
    ] {
        if has(c) {
            select.push(match c {
                "is_active" => "a.is_active AS is_active",
                "created" => "a.created AS created",
                "modified" => "a.modified AS modified",
                "logdate" => "a.logdate AS logdate",
                "lognum" => "a.lognum AS lognum",
                "failures_num" => "a.failures_num AS failures_num",
                _ => "a.lock_expires AS lock_expires",
            });
        }
    }
    let role_join = if run.exists(conn, "authorization_role")? {
        select.push("(SELECT p.role_name FROM {roles} r JOIN {roles} p ON p.role_id = r.parent_id WHERE r.user_id = a.user_id AND r.role_type = 'U' AND r.user_type = '2' LIMIT 1) AS role_name");
        true
    } else {
        false
    };
    let sql = format!(
        "SELECT {} FROM {} a ORDER BY a.user_id",
        select.join(", "),
        run.t("admin_user")
    )
    .replace("{roles}", &run.t("authorization_role"));
    let rows = query_rows(conn, &sql)?;
    let mut sessions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if run.exists(conn, "admin_user_session")? {
        for r in query_rows(
            conn,
            &format!(
                "SELECT user_id, ip, updated_at FROM {} WHERE status = 1 ORDER BY updated_at DESC LIMIT 200",
                run.t("admin_user_session")
            ),
        )? {
            sessions
                .entry(col(&r, "user_id").to_string())
                .or_default()
                .push(format!("{} ({})", col(&r, "ip"), col(&r, "updated_at")));
        }
    }
    let previous: Snapshot = ctx.state.snapshot("m2-admins").unwrap_or_default();
    let mut current = Snapshot::default();
    let mut active = 0usize;
    for row in &rows {
        let user = col(row, "username").to_string();
        let email = col(row, "email").to_string();
        let is_active = col(row, "is_active") != "0";
        let created = col(row, "created").to_string();
        let role = col(row, "role_name").to_string();
        if is_active {
            active += 1;
        }
        let f = fp(&[&email, if is_active { "1" } else { "0" }, &role]);
        current.entries.insert(user.clone(), f.clone());
        let sess = sessions
            .get(col(row, "user_id"))
            .cloned()
            .unwrap_or_default();
        report.items.push(
            IntegrityItem::new(
                format!("admin.account.{user}"),
                "Admin-Konten",
                &user,
                if !is_active {
                    IntegrityStatus::Unknown
                } else {
                    IntegrityStatus::Ok
                },
                format!(
                    "{} · {} · angelegt {} · letzte Anmeldung {} ({}×)",
                    if is_active { "aktiv" } else { "inaktiv" },
                    if role.is_empty() { "Rolle ?" } else { &role },
                    created.get(..10).unwrap_or(&created),
                    {
                        let l = col(row, "logdate");
                        if l.is_empty() {
                            "nie"
                        } else {
                            l
                        }
                    },
                    {
                        let n = col(row, "lognum");
                        if n.is_empty() {
                            "0"
                        } else {
                            n
                        }
                    }
                ),
            )
            .with_detail(format!(
                "E-Mail: {} · Fehlversuche {}{}",
                mask_email(&email),
                {
                    let n = col(row, "failures_num");
                    if n.is_empty() {
                        "0"
                    } else {
                        n
                    }
                },
                if sess.is_empty() {
                    String::new()
                } else {
                    format!(
                        " · aktive Sitzungen: {}",
                        sess.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                    )
                }
            )),
        );
        let subject = format!("admin_user:{user}");
        match previous.entries.get(&user) {
            None if !previous.entries.is_empty() => report.findings.push(
                Finding::new(
                    Severity::Critical,
                    Category::AdminAccount,
                    Source::Database,
                    "admin_account_new",
                    subject.clone(),
                    format!("Neuer Magento-Admin seit dem letzten Scan: {user}"),
                )
                .with_description(
                    "Nach CosmicSting/SessionReaper-Angriffen legen Täter eigene Admin-Konten an. Unbekannte \
                     Konten sofort sperren, Crypt-Key und Passwörter rotieren.",
                )
                .with_evidence(format!(
                    "E-Mail {} · Rolle {role} · angelegt {created}",
                    mask_email(&email)
                )),
            ),
            Some(prev) if *prev != f => report.findings.push(
                Finding::new(
                    Severity::Warning,
                    Category::AdminAccount,
                    Source::Database,
                    "admin_account_changed",
                    subject.clone(),
                    format!("Magento-Admin geändert (E-Mail/Status/Rolle): {user}"),
                )
                .with_evidence(format!("E-Mail {} · aktiv={is_active} · Rolle {role}", mask_email(&email))),
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
                    subject,
                    format!("Magento-Admin nach dem Referenzdatum angelegt: {user}"),
                )
                .with_evidence(format!("angelegt {created} · Rolle {role}")),
            );
        }
    }
    let _ = role_join;
    report.items.push(IntegrityItem::new(
        "admin.summary",
        "Admin-Konten",
        "Admin-Benutzer gesamt / aktiv",
        IntegrityStatus::Ok,
        format!("{} / {active}", rows.len()),
    ));
    ctx.state.save_snapshot("m2-admins", &current)?;
    Ok(())
}

// ------------------------------------------------------------------ integrations

fn integrations(
    run: &mut Run,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    let previous: Snapshot = ctx.state.snapshot("m2-integrations").unwrap_or_default();
    let mut current = Snapshot::default();
    if run.exists(conn, "integration")? {
        let cols = run.cols(conn, "integration")?;
        let mut select = vec!["integration_id", "name", "email", "status"];
        for c in [
            "endpoint",
            "identity_link_url",
            "setup_type",
            "created_at",
            "updated_at",
        ] {
            if cols.iter().any(|x| x == c) {
                select.push(c);
            }
        }
        let rows = query_rows(
            conn,
            &format!(
                "SELECT {} FROM {} ORDER BY integration_id",
                select.join(", "),
                run.t("integration")
            ),
        )?;
        for row in &rows {
            let id = col(row, "integration_id").to_string();
            let name = col(row, "name").to_string();
            let endpoint = col(row, "endpoint").to_string();
            let key = format!("integration:{id}");
            current.entries.insert(key.clone(), fp(&[&name, &endpoint]));
            let host = host_of(&endpoint).unwrap_or_default();
            let class = if host.is_empty() {
                HostClass::Platform
            } else {
                run.classify(&host)
            };
            let new = !previous.entries.is_empty() && !previous.entries.contains_key(&key);
            report.items.push(
                IntegrityItem::new(
                    format!("integration.{id}"),
                    "API-Integrationen",
                    if name.is_empty() { &id } else { &name },
                    if new || class == HostClass::Suspicious {
                        IntegrityStatus::Critical
                    } else if col(row, "status") == "1" {
                        IntegrityStatus::Warning
                    } else {
                        IntegrityStatus::Ok
                    },
                    format!(
                        "Status {} · angelegt {}{}",
                        col(row, "status"),
                        col(row, "created_at"),
                        if endpoint.is_empty() {
                            String::new()
                        } else {
                            format!(" · Endpoint {host} ({})", class.label())
                        }
                    ),
                )
                .with_detail(format!("E-Mail {}", mask_email(col(row, "email")))),
            );
            if new {
                report.findings.push(
                    Finding::new(
                        Severity::Critical,
                        Category::AdminAccount,
                        Source::Database,
                        "integration_new",
                        key.clone(),
                        format!("Neue API-Integration seit dem letzten Scan: {name}"),
                    )
                    .with_description(
                        "Integrationen erhalten OAuth-Zugriff auf die Admin-REST-API (Bestellungen, Kunden, \
                         Konfiguration). Unbekannte Integrationen unter System › Integrationen löschen.",
                    )
                    .with_evidence(format!("Endpoint {endpoint} · angelegt {}", col(row, "created_at"))),
                );
            } else if after_reference(col(row, "created_at"), ctx) {
                report.findings.push(
                    Finding::new(
                        Severity::Warning,
                        Category::AdminAccount,
                        Source::Database,
                        "integration_created_after_reference",
                        key.clone(),
                        format!("API-Integration nach dem Referenzdatum angelegt: {name}"),
                    )
                    .with_evidence(format!("angelegt {}", col(row, "created_at"))),
                );
            }
        }
    }
    if run.exists(conn, "oauth_token")? {
        let cols = run.cols(conn, "oauth_token")?;
        if cols.iter().any(|c| c == "admin_id") {
            let rows = query_rows(
                conn,
                &format!(
                    "SELECT entity_id, consumer_id, admin_id, type, created_at FROM {} \
                     WHERE type = 'access' AND revoked = 0 AND (admin_id IS NOT NULL OR consumer_id IS NOT NULL) \
                     ORDER BY entity_id DESC LIMIT 200",
                    run.t("oauth_token")
                ),
            )?;
            for row in &rows {
                let key = format!("oauth_token:{}", col(row, "entity_id"));
                current.entries.insert(key.clone(), String::new());
                if !previous.entries.is_empty() && !previous.entries.contains_key(&key) {
                    let admin = !col(row, "admin_id").is_empty();
                    report.findings.push(
                        Finding::new(
                            if admin {
                                Severity::Critical
                            } else {
                                Severity::Warning
                            },
                            Category::AdminAccount,
                            Source::Database,
                            "oauth_token_new",
                            key,
                            if admin {
                                "Neuer Admin-Access-Token seit dem letzten Scan"
                            } else {
                                "Neuer Integrations-Access-Token seit dem letzten Scan"
                            },
                        )
                        .with_description(
                            "Neue, nicht widerrufene OAuth-Access-Tokens erlauben API-Zugriff ohne Passwort. \
                             Herkunft klären; bei Verdacht Tokens widerrufen und Crypt-Key rotieren.",
                        )
                        .with_evidence(format!(
                            "admin_id={} consumer_id={} angelegt {}",
                            col(row, "admin_id"),
                            col(row, "consumer_id"),
                            col(row, "created_at")
                        )),
                    );
                }
            }
            report.items.push(IntegrityItem::new(
                "oauth.tokens",
                "API-Integrationen",
                "Aktive OAuth-Access-Tokens",
                IntegrityStatus::Ok,
                rows.len().to_string(),
            ));
        }
    }
    ctx.state.save_snapshot("m2-integrations", &current)?;
    Ok(())
}

// ------------------------------------------------------------------ design / head

/// Configuration paths that are rendered verbatim into every storefront page.
const DESIGN_PATHS: &[&str] = &[
    "design/head/includes",
    "design/footer/absolute_footer",
    "design/head/demonotice",
    "design/head/default_title",
    "design/head/default_description",
    "design/header/welcome",
    "design/footer/copyright",
];

fn inspect_content(
    run: &Run,
    content: &str,
    rule_prefix: &str,
    subject: &str,
    title: &str,
    report: &mut IntegrityReport,
) -> usize {
    let mut hits = 0usize;
    for src in script_sources(content) {
        let host = host_of(&src).unwrap_or_default();
        let class = run.classify(&host);
        let severity = match class {
            HostClass::Suspicious => Severity::Critical,
            HostClass::Unknown => Severity::Warning,
            _ => continue,
        };
        hits += 1;
        report.findings.push(
            Finding::new(
                severity,
                Category::ThirdPartyInjection,
                Source::Database,
                format!("{rule_prefix}_foreign_script"),
                format!("{subject}:{host}"),
                format!("{title}: externes Script von {} ({host})", class.label()),
            )
            .with_description(
                "Magecart-Skimmer werden bevorzugt in „HTML Head › Scripts and Style Sheets“, im Footer oder \
                 in CMS-Blöcken eingebettet und laufen dann auf jeder Seite inklusive Checkout. Host \
                 zuordnen; unbekannte Einbindungen entfernen und den Cache leeren.",
            )
            .with_evidence(excerpt(&src, 200)),
        );
    }
    for hit in run.rules.scan("template", content.as_bytes()) {
        let spec = &hit.rule.spec;
        if spec.severity == Severity::Info {
            continue;
        }
        hits += 1;
        let mut f = Finding::new(
            spec.severity,
            if spec.category == Category::SuspiciousPattern {
                Category::ThirdPartyInjection
            } else {
                spec.category
            },
            Source::Database,
            spec.name.clone(),
            subject.to_string(),
            format!("{title}: {}", spec.description),
        )
        .with_description(format!(
            "Regel `{}` trifft auf in der Datenbank gespeicherten Inhalt.",
            spec.name
        ));
        for ex in hit.excerpts.iter().take(2) {
            f = f.with_evidence(ex.clone());
        }
        report.findings.push(f);
    }
    hits
}

fn design_config(
    run: &mut Run,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    let list = DESIGN_PATHS
        .iter()
        .map(|p| format!("'{p}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let rows = query_rows(
        conn,
        &format!(
            "SELECT scope, scope_id, path, value FROM {} WHERE path IN ({list}) \
                OR path LIKE 'general/store\\_information/%' ORDER BY path, scope, scope_id",
            run.t("core_config_data")
        ),
    )?;
    let previous: Snapshot = ctx.state.snapshot("m2-design").unwrap_or_default();
    let mut current = Snapshot::default();
    let mut flagged = 0usize;
    for row in &rows {
        let path = col(row, "path");
        let value = col(row, "value");
        let key = format!("{path}@{}", scope_label(row));
        if path.starts_with("general/store_information/") {
            if !value.is_empty() {
                report.items.push(IntegrityItem::new(
                    format!("magento.store_info.{key}"),
                    "Shop",
                    &key,
                    IntegrityStatus::Ok,
                    excerpt(value, 80),
                ));
            }
            continue;
        }
        let digest = sha256_hex(value.as_bytes());
        current.entries.insert(key.clone(), digest.clone());
        let n = inspect_content(
            run,
            value,
            "magento_design",
            &format!("core_config_data:{key}"),
            &format!("Konfiguration {key}"),
            report,
        );
        let changed = matches!(previous.entries.get(&key), Some(p) if *p != digest);
        if n > 0 {
            flagged += 1;
        }
        if changed && value.to_ascii_lowercase().contains("<script") {
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    Category::ThirdPartyInjection,
                    Source::Database,
                    "magento_design_script_changed",
                    format!("core_config_data:{key}"),
                    format!("Script-Einbindung in {path} hat sich seit dem letzten Scan geändert"),
                )
                .with_description(
                    "Änderungen an Head-/Footer-Scripts müssen zugeordnet werden (Marketing, Agentur). \
                     Unbekannte Änderungen sind ein typisches Magecart-Muster.",
                )
                .with_evidence(excerpt(value, 200)),
            );
        }
        if path == "design/head/includes" || path == "design/footer/absolute_footer" {
            report.items.push(IntegrityItem::new(
                format!("magento.design.{key}"),
                "Storefront",
                &key,
                if n > 0 || changed {
                    IntegrityStatus::Warning
                } else {
                    IntegrityStatus::Ok
                },
                format!(
                    "{} Script-Tags{}",
                    value.to_ascii_lowercase().matches("<script").count(),
                    if changed {
                        " · seit letztem Scan geändert"
                    } else {
                        ""
                    }
                ),
            ));
        }
    }
    report.items.push(IntegrityItem::new(
        "magento.design.summary",
        "Storefront",
        "Head-/Footer-Konfiguration mit fremden Scripts",
        if flagged > 0 {
            IntegrityStatus::Warning
        } else {
            IntegrityStatus::Ok
        },
        flagged.to_string(),
    ));
    ctx.state.save_snapshot("m2-design", &current)?;
    Ok(())
}

// ------------------------------------------------------------------ payment

fn encrypted_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\d+:\d+:").expect("regex"))
}

fn payment_key(path: &str) -> Option<bool> {
    static RE: OnceLock<Regex> = OnceLock::new();
    static SECRET: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(?i)(business_account|merchant|account|e-?mail|client_?id|publishable|payee|receiver|api_?(key|user|username|password|signature)|secret|private_key|public_key|webhook|partner|iban)")
            .expect("regex")
    });
    let secret = SECRET.get_or_init(|| {
        Regex::new(r"(?i)(secret|password|signature|private_key|api_key|token)").expect("regex")
    });
    let last = path.rsplit('/').next().unwrap_or(path);
    if !re.is_match(last)
        || last.contains("active")
        || last.ends_with("_title")
        || last.contains("debug")
    {
        return None;
    }
    Some(secret.is_match(last))
}

fn payment_config(
    run: &mut Run,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    let rows = query_rows(
        conn,
        &format!(
            "SELECT scope, scope_id, path, value FROM {} \
             WHERE (path LIKE 'payment/%' OR path LIKE 'paypal/%' OR path LIKE 'stripe/%' OR path LIKE 'adyen/%' OR path LIKE 'braintree/%' OR path LIKE 'mollie/%') \
               AND (path LIKE '%account%' OR path LIKE '%merchant%' OR path LIKE '%email%' OR path LIKE '%client\\_id%' OR path LIKE '%publishable%' \
                    OR path LIKE '%api\\_%' OR path LIKE '%secret%' OR path LIKE '%key%' OR path LIKE '%payee%' OR path LIKE '%webhook%') \
             ORDER BY path, scope, scope_id LIMIT 500",
            run.t("core_config_data")
        ),
    )?;
    let previous: Snapshot = ctx.state.snapshot("m2-payment").unwrap_or_default();
    let mut current = Snapshot::default();
    let mut changed_count = 0usize;
    for row in &rows {
        let path = col(row, "path");
        let Some(secret) = payment_key(path) else {
            continue;
        };
        let value = col(row, "value").to_string();
        let key = format!("{path}@{}", scope_label(row));
        let digest = sha256_hex(value.as_bytes());
        current.entries.insert(key.clone(), digest.clone());
        let changed = matches!(previous.entries.get(&key), Some(p) if *p != digest);
        // Magento stores sensitive values encrypted (`0:3:…` / `1:3:…`).
        let encrypted = encrypted_re().is_match(&value);
        let shown = if value.is_empty() {
            "(leer)".to_string()
        } else if encrypted {
            "verschlüsselt (Hash wird verglichen)".to_string()
        } else if secret {
            "gesetzt (Wert verborgen)".to_string()
        } else if value.contains('@') {
            mask_email(&value)
        } else {
            mask(&value)
        };
        let mut item = IntegrityItem::new(
            format!("payment.{key}"),
            "Zahlung",
            &key,
            if changed {
                IntegrityStatus::Critical
            } else {
                IntegrityStatus::Ok
            },
            shown.clone(),
        );
        if changed {
            changed_count += 1;
            item = item.with_detail("Wert hat sich seit dem letzten Scan geändert!");
            report.findings.push(
                Finding::new(
                    Severity::Critical,
                    Category::PaymentConfiguration,
                    Source::Database,
                    "payment_config_changed",
                    key.clone(),
                    "Zahlungsanbieter-Konfiguration hat sich geändert",
                )
                .with_description(
                    "PayPal-Empfängerkonto, Braintree-/Stripe-Händler-ID oder API-Schlüssel unterscheiden sich \
                     vom letzten Scan. Nicht selbst vorgenommene Änderungen deuten auf Zahlungsumleitung hin \
                     (Stores › Konfiguration › Verkäufe › Zahlungsmethoden).",
                )
                .with_evidence(format!("neuer Wert: {shown}")),
            );
        }
        report.items.push(item);
    }
    report.items.push(IntegrityItem::new(
        "payment.summary",
        "Zahlung",
        "Zahlungsanbieter-Einstellungen geprüft / geändert",
        if changed_count > 0 {
            IntegrityStatus::Critical
        } else if current.entries.is_empty() {
            IntegrityStatus::Unknown
        } else {
            IntegrityStatus::Ok
        },
        format!("{} / {changed_count}", current.entries.len()),
    ));
    ctx.state.save_snapshot("m2-payment", &current)?;
    Ok(())
}

// ------------------------------------------------------------------ cms

fn cms_content(
    run: &mut Run,
    conn: &mut Conn,
    _ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    let mut total = 0usize;
    let mut flagged = 0usize;
    for (table, id_col, store_table) in [
        ("cms_block", "block_id", "cms_block_store"),
        ("cms_page", "page_id", "cms_page_store"),
    ] {
        if !run.exists(conn, table)? {
            continue;
        }
        let cols = run.cols(conn, table)?;
        // Adobe Commerce (content staging) links stores via row_id.
        let link = if cols.iter().any(|c| c == "row_id") {
            "row_id"
        } else {
            id_col
        };
        let stores = if run.exists(conn, store_table)?
            && run.cols(conn, store_table)?.iter().any(|c| c == link)
        {
            format!(
                ", (SELECT GROUP_CONCAT(s.store_id) FROM {} s WHERE s.{link} = c.{link}) AS stores",
                run.t(store_table)
            )
        } else {
            String::new()
        };
        let rows = query_rows(
            conn,
            &format!(
                "SELECT c.{id_col} AS id, c.identifier, c.title, c.is_active, c.content{stores} FROM {} c \
                 WHERE c.content LIKE '%<script%' OR c.content LIKE '%<iframe%' OR c.content LIKE '%atob(%' \
                    OR c.content LIKE '%eval(%' \
                 LIMIT 500",
                run.t(table)
            ),
        )?;
        for row in &rows {
            total += 1;
            let ident = col(row, "identifier");
            let stores = col(row, "stores");
            let n = inspect_content(
                run,
                col(row, "content"),
                "magento_cms",
                &format!("{table}:{}", col(row, "id")),
                &format!(
                    "{} „{ident}“{}",
                    if table == "cms_block" {
                        "CMS-Block"
                    } else {
                        "CMS-Seite"
                    },
                    if stores.is_empty() {
                        String::new()
                    } else {
                        format!(" (Store {stores})")
                    }
                ),
                report,
            );
            if n > 0 {
                flagged += 1;
            }
        }
    }
    if run.exists(conn, "widget_instance")? {
        let rows = query_rows(
            conn,
            &format!(
                "SELECT instance_id, title, widget_parameters FROM {} WHERE widget_parameters LIKE '%<script%' OR widget_parameters LIKE '%atob(%' LIMIT 200",
                run.t("widget_instance")
            ),
        )?;
        for row in &rows {
            total += 1;
            if inspect_content(
                run,
                col(row, "widget_parameters"),
                "magento_widget",
                &format!("widget_instance:{}", col(row, "instance_id")),
                &format!("Widget „{}“", col(row, "title")),
                report,
            ) > 0
            {
                flagged += 1;
            }
        }
    }
    report.items.push(IntegrityItem::new(
        "magento.cms",
        "Storefront",
        "CMS-Blöcke/-Seiten/Widgets mit fremden Scripts",
        if flagged > 0 {
            IntegrityStatus::Warning
        } else {
            IntegrityStatus::Ok
        },
        format!("{flagged} auffällig von {total} mit Script/Direktiven"),
    ));
    Ok(())
}

/// CVE-2022-24086 and similar template-injection attacks put `{{…}}`
/// directives into customer and address fields that are later rendered by
/// the e-mail template filter.
fn template_directives(
    run: &mut Run,
    conn: &mut Conn,
    _ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    let mut hits = 0usize;
    for (table, fields) in [
        (
            "sales_order_address",
            &[
                "firstname",
                "lastname",
                "street",
                "city",
                "company",
                "email",
            ][..],
        ),
        (
            "quote_address",
            &[
                "firstname",
                "lastname",
                "street",
                "city",
                "company",
                "email",
            ][..],
        ),
        ("customer_entity", &["firstname", "lastname", "email"][..]),
    ] {
        if !run.exists(conn, table)? {
            continue;
        }
        let cols = run.cols(conn, table)?;
        let present: Vec<&str> = fields
            .iter()
            .copied()
            .filter(|f| cols.iter().any(|c| c == f))
            .collect();
        if present.is_empty() {
            continue;
        }
        let cond = present
            .iter()
            .map(|f| format!("{f} LIKE '%{{{{%'"))
            .collect::<Vec<_>>()
            .join(" OR ");
        let rows = query_rows(
            conn,
            &format!(
                "SELECT entity_id, CONCAT_WS(' | ', {}) AS v FROM {} WHERE {cond} ORDER BY entity_id DESC LIMIT 50",
                present.join(", "),
                run.t(table)
            ),
        )?;
        for row in &rows {
            hits += 1;
            report.findings.push(
                Finding::new(
                    Severity::Critical,
                    Category::AttackTrace,
                    Source::Database,
                    "magento_template_directive_in_customer_data",
                    format!("{table}:{}", col(row, "entity_id")),
                    format!("Template-Direktive {{{{…}}}} in Kunden-/Adressdaten ({table})"),
                )
                .with_description(
                    "Template-Injection-Angriffe (CVE-2022-24086, CVE-2022-24087 und Varianten) schleusen \
                     `{{var …}}`/`{{template …}}`-Direktiven über Checkout-Felder ein, die beim Rendern von \
                     Bestell-E-Mails ausgeführt werden. Der Datensatz zeigt einen Angriffsversuch; Patch-Stand \
                     prüfen und den Zeitraum in den Logs untersuchen.",
                )
                .with_evidence(excerpt(col(row, "v"), 200)),
            );
        }
    }
    report.items.push(IntegrityItem::new(
        "magento.template_directives",
        "Angriffsspuren",
        "Kunden-/Adressdaten mit {{…}}-Direktiven",
        if hits > 0 {
            IntegrityStatus::Critical
        } else {
            IntegrityStatus::Ok
        },
        hits.to_string(),
    ));
    Ok(())
}

// ------------------------------------------------------------------ cron

fn cron_schedule(
    run: &mut Run,
    conn: &mut Conn,
    _ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !run.exists(conn, "cron_schedule")? {
        return Ok(());
    }
    let rows = query_rows(
        conn,
        &format!(
            "SELECT job_code, COUNT(*) AS n, MIN(scheduled_at) AS first FROM {} WHERE status = 'pending' GROUP BY job_code ORDER BY job_code",
            run.t("cron_schedule")
        ),
    )?;
    if run.cron_jobs.is_empty() {
        report.limitations.push(
            "Keine crontab.xml-Dateien gefunden (vendor/ fehlt?) – cron_schedule nicht gegen bekannte Jobs abgeglichen."
                .into(),
        );
    }
    let mut unknown = Vec::new();
    for row in &rows {
        let job = col(row, "job_code");
        if run.cron_jobs.is_empty() || run.cron_jobs.contains(job) {
            continue;
        }
        unknown.push(job.to_string());
        report.findings.push(
            Finding::new(
                Severity::Warning,
                Category::SuspiciousPattern,
                Source::Database,
                "magento_cron_unknown_job",
                format!("cron_schedule:{job}"),
                format!("Geplanter Cron-Job ohne crontab.xml-Definition: {job}"),
            )
            .with_description(
                "Für den Job-Code existiert in keinem installierten Modul eine crontab.xml. Er kann von einem \
                 entfernten Modul stammen – oder von Malware, die sich per Datenbank einplant. Job-Code \
                 zuordnen, sonst Einträge löschen und Herkunft untersuchen.",
            )
            .with_evidence(format!("{} ausstehend, erster {}", col(row, "n"), col(row, "first"))),
        );
    }
    report.items.push(
        IntegrityItem::new(
            "magento.cron",
            "Cron",
            "Ausstehende Cron-Jobs / ohne Definition",
            if unknown.is_empty() {
                IntegrityStatus::Ok
            } else {
                IntegrityStatus::Warning
            },
            format!("{} / {}", rows.len(), unknown.len()),
        )
        .with_detail(if unknown.is_empty() {
            format!("{} Job-Codes aus crontab.xml bekannt", run.cron_jobs.len())
        } else {
            unknown.join(", ")
        }),
    );
    Ok(())
}

fn setup_modules(
    run: &mut Run,
    conn: &mut Conn,
    _ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !run.exists(conn, "setup_module")? || run.modules.is_empty() {
        return Ok(());
    }
    let rows = query_rows(
        conn,
        &format!(
            "SELECT module, schema_version, data_version FROM {}",
            run.t("setup_module")
        ),
    )?;
    let db: BTreeSet<String> = rows.iter().map(|r| col(r, "module").to_string()).collect();
    let cfg: BTreeSet<String> = run.modules.iter().cloned().collect();
    let only_db: Vec<&String> = db.difference(&cfg).collect();
    let only_cfg: Vec<&String> = cfg.difference(&db).collect();
    report.items.push(
        IntegrityItem::new(
            "magento.setup_module",
            "Module",
            "setup_module vs. app/etc/config.php",
            if only_db.is_empty() && only_cfg.is_empty() {
                IntegrityStatus::Ok
            } else {
                IntegrityStatus::Unknown
            },
            format!(
                "{} in DB, {} nur in DB, {} ohne DB-Eintrag",
                db.len(),
                only_db.len(),
                only_cfg.len()
            ),
        )
        .with_detail(excerpt(
            &format!(
                "nur in DB: {} · ohne DB-Eintrag: {}",
                only_db
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                only_cfg
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            1500,
        )),
    );
    if !only_db.is_empty() {
        report.findings.push(
            Finding::new(
                Severity::Info,
                Category::Informational,
                Source::Database,
                "magento_setup_module_orphans",
                "setup_module",
                format!("{} Module in setup_module ohne Eintrag in config.php", only_db.len()),
            )
            .with_description(
                "Reste entfernter Module oder manuell eingespielte Module. Abgleichen; unbekannte Module \
                 im Dateisystem (app/code, vendor) suchen.",
            )
            .with_evidence(excerpt(
                &only_db.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                400,
            )),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_paths() {
        assert_eq!(
            payment_key("payment/paypal_express/business_account"),
            Some(false)
        );
        assert_eq!(payment_key("payment/braintree/merchant_id"), Some(false));
        assert_eq!(payment_key("payment/braintree/private_key"), Some(true));
        assert_eq!(payment_key("payment/paypal_express/active"), None);
        assert_eq!(payment_key("payment/checkmo/title"), None);
    }
}
