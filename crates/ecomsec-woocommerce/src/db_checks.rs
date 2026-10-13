//! Database based checks for WordPress / WooCommerce (read-only, SELECT
//! only).  All table names carry the configured `$table_prefix`.

use crate::inventory::{random_looking, Extension};
use crate::php_serial::{unserialize, PhpValue};
use crate::WooCommerce;
use chrono::{DateTime, NaiveDateTime, Utc};
use ecomsec_core::db::{col, columns, query_rows, table_exists};
use ecomsec_core::finding::{Category, Finding, Severity, Source};
use ecomsec_core::hosts::{classify_host, host_of, script_sources, HostClass, SUSPICIOUS_TLDS};
use ecomsec_core::platform::{
    IntegrityItem, IntegrityReport, IntegrityStatus, Platform, PlatformContext,
};
use ecomsec_core::rules::RuleSet;
use ecomsec_core::util::{excerpt, mask, mask_email, sha256_hex};
use mysql::Conn;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// Domains belonging to the WordPress / WooCommerce ecosystem itself.
pub const WP_PLATFORM_HOSTS: &[&str] = &[
    "wordpress.org",
    "w.org",
    "wordpress.com",
    "wp.com",
    "gravatar.com",
    "woocommerce.com",
    "woo.com",
    "jetpack.com",
    "akismet.com",
];

/// Roles that can change the shop (code, payment settings, orders).
const PRIVILEGED_ROLES: &[&str] = &["administrator", "shop_manager", "editor"];

/// Cron hook prefixes of WordPress core, WooCommerce and widespread plugins.
const KNOWN_CRON_PREFIXES: &[&str] = &[
    "wp_",
    "wp-",
    "woocommerce",
    "wc_",
    "wc-",
    "action_scheduler",
    "delete_expired_transients",
    "recovery_mode_clean_expired_keys",
    "do_pings",
    "publish_future_post",
    "importer_scheduled_cleanup",
    "upgrader_scheduled_cleanup",
    "jetpack",
    "akismet",
    "wpseo",
    "yoast",
    "rank_math",
    "elementor",
    "wpforms",
    "updraft",
    "wordfence",
    "litespeed",
    "w3tc",
    "rocket_",
    "monsterinsights",
    "mailpoet",
    "sucuri",
    "itsec",
    "aioseo",
    "redirection",
    "cmplz",
    "complianz",
    "borlabs",
    "googlesitekit",
    "smush",
    "imagify",
    "ewww",
    "duplicator",
    "backwpup",
    "ai1wm",
    "gform",
    "gravityforms",
    "wpo_",
    "autoptimize",
    "breeze",
    "sg_",
    "mc4wp",
    "edd_",
    "tribe",
    "germanized",
    "woocommerce_germanized",
    "wpml",
    "icl_",
    "polylang",
    "pll_",
    "stripe",
    "ppcp",
    "mollie",
    "klarna",
];

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

/// Shared state of one DB check run.
pub struct Run<'a> {
    pub wc: &'a WooCommerce,
    pub prefix: String,
    pub plugins: &'a [Extension],
    /// Host names of `siteurl` / `home`.
    pub own_hosts: Vec<String>,
    rules: RuleSet,
}

impl Run<'_> {
    fn t(&self, name: &str) -> String {
        format!("`{}{}`", self.prefix, name)
    }

    fn exists(&self, conn: &mut Conn, name: &str) -> anyhow::Result<bool> {
        Ok(table_exists(conn, &format!("{}{}", self.prefix, name))?)
    }

    fn option(&self, conn: &mut Conn, name: &str) -> anyhow::Result<Option<String>> {
        let rows = query_rows(
            conn,
            &format!(
                "SELECT option_value FROM {} WHERE option_name = '{}' LIMIT 1",
                self.t("options"),
                name.replace(['\'', '\\'], "")
            ),
        )?;
        Ok(rows.first().map(|r| col(r, "option_value").to_string()))
    }

    fn classify(&self, host: &str) -> HostClass {
        let mut platform: Vec<&str> = WP_PLATFORM_HOSTS.to_vec();
        platform.extend(self.own_hosts.iter().map(String::as_str));
        classify_host(host, &platform, &self.wc.allow_hosts)
    }
}

type Step = fn(&mut Run, &mut Conn, &PlatformContext, &mut IntegrityReport) -> anyhow::Result<()>;

pub fn run(
    wc: &WooCommerce,
    plugins: &[Extension],
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) {
    let mut rules = ecomsec_core::signatures::builtin_rules().unwrap_or_default();
    rules.extend(wc.rules());
    let mut run = Run {
        wc,
        prefix: wc.config().table_prefix.clone(),
        plugins,
        own_hosts: Vec::new(),
        rules,
    };
    match run.exists(conn, "options") {
        Ok(true) => {}
        Ok(false) => {
            report.limitations.push(format!(
                "Tabelle {}options nicht gefunden – falsches Tabellenpräfix oder keine WordPress-Datenbank; DB-Prüfungen übersprungen.",
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
        ("Website-URLs", site_urls),
        ("Administratoren", admins),
        ("Registrierung", registration),
        ("Aktive Plugins", active_plugins),
        ("Optionen", option_injection),
        ("WP-Cron", cron),
        ("Zahlungsanbieter", payment_settings),
        ("Beiträge/Seiten", post_scripts),
        ("REST-API-Schlüssel", api_keys),
        ("Webhooks", webhooks),
        ("Benutzer-E-Mails", suspicious_user_emails),
    ];
    for (name, step) in steps {
        if let Err(e) = step(&mut run, conn, ctx, report) {
            report.limitations.push(format!("{name}: {e}"));
        }
    }
}

// ------------------------------------------------------------------ urls

fn site_urls(
    run: &mut Run,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    let previous: Snapshot = ctx.state.snapshot("wp-urls").unwrap_or_default();
    let mut current = Snapshot::default();
    for name in ["siteurl", "home"] {
        let value = run.option(conn, name)?.unwrap_or_default();
        if let Some(h) = host_of(&value) {
            if !run.own_hosts.contains(&h) {
                run.own_hosts.push(h);
            }
        }
        current.entries.insert(name.into(), value.clone());
        let changed = matches!(previous.entries.get(name), Some(p) if *p != value);
        report.items.push(IntegrityItem::new(
            format!("wp.option.{name}"),
            "Shop",
            format!("WordPress-Option {name}"),
            if changed {
                IntegrityStatus::Critical
            } else {
                IntegrityStatus::Ok
            },
            if value.is_empty() {
                "(leer)".to_string()
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
                    "wp_siteurl_changed",
                    format!("{}options:{name}", run.prefix),
                    format!("WordPress-Adresse ({name}) hat sich seit dem letzten Scan geändert"),
                )
                .with_description(
                    "Angreifer ändern siteurl/home, um Besucher und Admin-Logins auf eigene Server \
                     umzuleiten. Nicht selbst vorgenommene Änderungen sofort zurücksetzen \
                     (Einstellungen › Allgemein bzw. per SQL) und Admin-Zugänge prüfen.",
                )
                .with_evidence(format!(
                    "vorher {} · jetzt {value}",
                    previous.entries.get(name).cloned().unwrap_or_default()
                )),
            );
        }
    }
    ctx.state.save_snapshot("wp-urls", &current)?;
    Ok(())
}

// ------------------------------------------------------------------ admins

/// Role names granted in a `{prefix}capabilities` meta value.
pub fn roles_of(caps: &str) -> Vec<String> {
    match unserialize(caps) {
        Some(v) => v
            .entries()
            .iter()
            .filter(|(_, granted)| granted.truthy())
            .map(|(k, _)| k.as_string())
            .collect(),
        None => PRIVILEGED_ROLES
            .iter()
            .filter(|r| caps.contains(*r))
            .map(|r| r.to_string())
            .collect(),
    }
}

/// Last login time and IPs from the `session_tokens` user meta.
pub fn sessions_of(meta: &str) -> (Option<DateTime<Utc>>, Vec<String>) {
    let mut last = None;
    let mut ips = BTreeSet::new();
    if let Some(v) = unserialize(meta) {
        for (_, session) in v.entries() {
            if let Some(ts) = session.get("login").and_then(PhpValue::as_i64) {
                let t = DateTime::<Utc>::from_timestamp(ts, 0);
                if t > last {
                    last = t;
                }
            }
            if let Some(ip) = session.get("ip") {
                let ip = ip.as_string();
                if !ip.is_empty() {
                    ips.insert(ip);
                }
            }
        }
    }
    (last, ips.into_iter().collect())
}

fn suspicious_tld(email: &str) -> bool {
    let tld = email.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    SUSPICIOUS_TLDS.contains(&tld.as_str())
}

fn admins(
    run: &mut Run,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !run.exists(conn, "users")? || !run.exists(conn, "usermeta")? {
        report.limitations.push(format!(
            "Tabellen {0}users/{0}usermeta nicht vorhanden.",
            run.prefix
        ));
        return Ok(());
    }
    let sql = format!(
        "SELECT u.ID AS id, u.user_login AS login, u.user_email AS email, u.user_registered AS registered, \
                u.display_name AS display, m.meta_value AS caps \
         FROM {users} u JOIN {meta} m ON m.user_id = u.ID AND m.meta_key = '{p}capabilities' \
         WHERE m.meta_value LIKE '%administrator%' OR m.meta_value LIKE '%shop\\_manager%' OR m.meta_value LIKE '%editor%' \
         ORDER BY u.ID LIMIT 500",
        users = run.t("users"),
        meta = run.t("usermeta"),
        p = run.prefix
    );
    let rows = query_rows(conn, &sql)?;
    let ids: Vec<String> = rows
        .iter()
        .map(|r| col(r, "id").to_string())
        .filter(|i| i.chars().all(|c| c.is_ascii_digit()) && !i.is_empty())
        .collect();
    let mut sessions: BTreeMap<String, String> = BTreeMap::new();
    if !ids.is_empty() {
        for r in query_rows(
            conn,
            &format!(
                "SELECT user_id, meta_value FROM {} WHERE meta_key = 'session_tokens' AND user_id IN ({})",
                run.t("usermeta"),
                ids.join(",")
            ),
        )? {
            sessions.insert(col(&r, "user_id").to_string(), col(&r, "meta_value").to_string());
        }
    }
    let previous: Snapshot = ctx.state.snapshot("wp-admins").unwrap_or_default();
    let mut current = Snapshot::default();
    let mut admin_count = 0usize;
    let mut privileged = 0usize;
    for row in &rows {
        let login = col(row, "login").to_string();
        let email = col(row, "email").to_string();
        let registered = col(row, "registered").to_string();
        let roles: Vec<String> = roles_of(col(row, "caps"))
            .into_iter()
            .filter(|r| PRIVILEGED_ROLES.contains(&r.as_str()))
            .collect();
        if roles.is_empty() {
            continue;
        }
        privileged += 1;
        let is_admin = roles.iter().any(|r| r == "administrator");
        if is_admin {
            admin_count += 1;
        }
        let (last_login, ips) = sessions
            .get(col(row, "id"))
            .map(|m| sessions_of(m))
            .unwrap_or((None, Vec::new()));
        let fp = sha256_hex(format!("{email}|{}", roles.join(",")).as_bytes());
        current.entries.insert(login.clone(), fp.clone());
        let odd_email = suspicious_tld(&email);
        report.items.push(
            IntegrityItem::new(
                format!("admin.account.{login}"),
                "Admin-Konten",
                &login,
                if odd_email {
                    IntegrityStatus::Critical
                } else if is_admin {
                    IntegrityStatus::Warning
                } else {
                    IntegrityStatus::Ok
                },
                format!(
                    "{} · registriert {} · letzte Anmeldung {}",
                    roles.join(", "),
                    registered.get(..10).unwrap_or(&registered),
                    last_login
                        .map(|t| t.format("%d.%m.%Y %H:%M").to_string())
                        .unwrap_or_else(|| "keine aktive Sitzung".into())
                ),
            )
            .with_detail(format!(
                "E-Mail: {}{}{}",
                mask_email(&email),
                if ips.is_empty() {
                    String::new()
                } else {
                    format!(" · Sitzungs-IPs: {}", ips.join(", "))
                },
                if odd_email {
                    " · E-Mail-Domain mit auffälliger TLD"
                } else {
                    ""
                }
            )),
        );
        let subject = format!("{}users:{login}", run.prefix);
        match previous.entries.get(&login) {
            None if !previous.entries.is_empty() => report.findings.push(
                Finding::new(
                    Severity::Critical,
                    Category::AdminAccount,
                    Source::Database,
                    "admin_account_new",
                    subject.clone(),
                    format!("Neues privilegiertes Konto seit dem letzten Scan: {login}"),
                )
                .with_description(
                    "Das Konto mit Administrator-/Shop-Manager-/Redakteursrechten existierte beim letzten \
                     Scan nicht. Nicht zuordenbare Konten sofort sperren, Passwörter und Salts rotieren.",
                )
                .with_evidence(format!(
                    "Rollen {} · E-Mail {} · registriert {registered}",
                    roles.join(", "),
                    mask_email(&email)
                )),
            ),
            Some(prev) if *prev != fp => report.findings.push(
                Finding::new(
                    Severity::Warning,
                    Category::AdminAccount,
                    Source::Database,
                    "admin_account_changed",
                    subject.clone(),
                    format!("Privilegiertes Konto geändert (E-Mail/Rolle): {login}"),
                )
                .with_evidence(format!(
                    "Rollen {} · E-Mail {}",
                    roles.join(", "),
                    mask_email(&email)
                )),
            ),
            _ => {}
        }
        if after_reference(&registered, ctx) {
            report.findings.push(
                Finding::new(
                    if is_admin {
                        Severity::Warning
                    } else {
                        Severity::Info
                    },
                    Category::AdminAccount,
                    Source::Database,
                    "admin_created_after_reference",
                    subject.clone(),
                    format!("Privilegiertes Konto nach dem Referenzdatum registriert: {login}"),
                )
                .with_evidence(format!(
                    "Rollen {} · registriert {registered}",
                    roles.join(", ")
                )),
            );
        }
        if odd_email && is_admin {
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    Category::AdminAccount,
                    Source::Database,
                    "admin_suspicious_email",
                    subject,
                    format!("Administrator mit E-Mail-Adresse unter auffälliger TLD: {login}"),
                )
                .with_description(
                    "Von Angreifern angelegte Admin-Konten nutzen häufig Wegwerf-Domains unter .ru, .top, \
                     .xyz o. ä. Konto zuordnen.",
                )
                .with_evidence(mask_email(&email)),
            );
        }
    }
    let total = query_rows(
        conn,
        &format!("SELECT COUNT(*) AS n FROM {}", run.t("users")),
    )?
    .first()
    .map(|r| col(r, "n").to_string())
    .unwrap_or_default();
    report.items.push(IntegrityItem::new(
        "admin.summary",
        "Admin-Konten",
        "Benutzer gesamt / Administratoren / privilegiert",
        if admin_count > 3 {
            IntegrityStatus::Warning
        } else {
            IntegrityStatus::Ok
        },
        format!("{total} / {admin_count} / {privileged}"),
    ));
    ctx.state.save_snapshot("wp-admins", &current)?;
    Ok(())
}

fn registration(
    run: &mut Run,
    conn: &mut Conn,
    _ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    let open = run.option(conn, "users_can_register")?.unwrap_or_default() == "1";
    let role = run.option(conn, "default_role")?.unwrap_or_default();
    let privileged = PRIVILEGED_ROLES.contains(&role.as_str());
    report.items.push(IntegrityItem::new(
        "wp.registration",
        "Admin-Konten",
        "Registrierung / Standardrolle",
        if privileged {
            IntegrityStatus::Critical
        } else {
            IntegrityStatus::Ok
        },
        format!(
            "{} · Standardrolle {}",
            if open { "offen" } else { "geschlossen" },
            if role.is_empty() { "?" } else { &role }
        ),
    ));
    if privileged {
        report.findings.push(
            Finding::new(
                if open {
                    Severity::Critical
                } else {
                    Severity::Warning
                },
                Category::AdminAccount,
                Source::Database,
                "wp_default_role_privileged",
                format!("{}options:default_role", run.prefix),
                format!("Standardrolle für neue Benutzer ist „{role}“"),
            )
            .with_description(
                "Ein bekanntes Angriffsmuster setzt `default_role` auf administrator und öffnet die \
                 Registrierung – danach kann sich jeder selbst ein Admin-Konto anlegen. Auf `subscriber` \
                 bzw. `customer` zurücksetzen und neu registrierte Konten prüfen.",
            )
            .with_evidence(format!("users_can_register={}", if open { 1 } else { 0 })),
        );
    }
    Ok(())
}

// ------------------------------------------------------------------ plugins

fn active_plugins(
    run: &mut Run,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    let mut active: Vec<String> = run
        .option(conn, "active_plugins")?
        .and_then(|v| unserialize(&v))
        .map(|v| v.entries().iter().map(|(_, f)| f.as_string()).collect())
        .unwrap_or_default();
    if run.exists(conn, "sitemeta")? {
        let rows = query_rows(
            conn,
            &format!(
                "SELECT meta_value FROM {} WHERE meta_key = 'active_sitewide_plugins'",
                run.t("sitemeta")
            ),
        )?;
        for r in rows {
            if let Some(v) = unserialize(col(&r, "meta_value")) {
                active.extend(
                    v.entries()
                        .iter()
                        .map(|(k, _)| format!("network:{}", k.as_string())),
                );
            }
        }
    }
    let previous: Snapshot = ctx.state.snapshot("wp-active-plugins").unwrap_or_default();
    let mut current = Snapshot::default();
    let root = run.wc.root();
    let mut missing = Vec::new();
    for file in &active {
        current.entries.insert(file.clone(), String::new());
        let path = file.trim_start_matches("network:");
        if !root
            .join(crate::inventory::CONTENT_DIR)
            .join("plugins")
            .join(path)
            .is_file()
        {
            missing.push(path.to_string());
        }
        if !previous.entries.is_empty() && !previous.entries.contains_key(file) {
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    Category::ThirdPartyInjection,
                    Source::Database,
                    "wp_plugin_activated",
                    format!("plugin:{file}"),
                    format!("Plugin seit dem letzten Scan aktiviert: {path}"),
                )
                .with_description(
                    "Angreifer installieren nach einer Admin-Übernahme häufig eigene oder manipulierte \
                     Plugins (z. B. Datei-Manager, Skimmer-Loader). Aktivierung zuordnen.",
                ),
            );
        }
    }
    report.items.push(
        IntegrityItem::new(
            "wp.active_plugins",
            "Plugins & Themes",
            "Aktive Plugins (Datenbank)",
            if missing.is_empty() {
                IntegrityStatus::Ok
            } else {
                IntegrityStatus::Warning
            },
            active.len().to_string(),
        )
        .with_detail(if missing.is_empty() {
            active.join(", ")
        } else {
            format!(
                "{} · Datei fehlt im Dateisystem: {}",
                active.join(", "),
                missing.join(", ")
            )
        }),
    );
    ctx.state.save_snapshot("wp-active-plugins", &current)?;
    Ok(())
}

// ------------------------------------------------------------------ options

fn php_payload_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(eval|assert|create_function)\s*\(|\b(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\("#)
            .expect("regex")
    })
}

/// Evaluate an HTML/JS/PHP fragment stored in the database: foreign script
/// sources, skimmer/obfuscation rules and PHP payloads.
fn inspect_stored_content(
    run: &Run,
    content: &str,
    rule_prefix: &str,
    subject: &str,
    title: &str,
    autoload: bool,
    report: &mut IntegrityReport,
) -> usize {
    let mut hits = 0usize;
    for src in script_sources(content) {
        let host = host_of(&src).unwrap_or_default();
        let class = run.classify(&host);
        let severity = match class {
            HostClass::Suspicious => Severity::Critical,
            HostClass::Unknown => Severity::Warning,
            HostClass::Platform | HostClass::Allowlisted => continue,
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
                "In der Datenbank gespeicherte Inhalte binden JavaScript von einem fremden Host ein. \
                 Magecart-/WooCommerce-Skimmer werden genau so in Optionen, Widgets und Seiten versteckt. \
                 Host zuordnen; unbekannte Einbindungen entfernen. Bekannte Anbieter per \
                 `--allow-host` freigeben.",
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
            "Regel `{}` trifft auf in der Datenbank gespeicherten Inhalt. Inhalt im Backend prüfen und \
             bereinigen.",
            spec.name
        ));
        for ex in hit.excerpts.iter().take(2) {
            f = f.with_evidence(ex.clone());
        }
        report.findings.push(f);
    }
    let php: Vec<String> = php_payload_regex()
        .find_iter(content)
        .take(3)
        .map(|m| m.as_str().to_string())
        .collect();
    if !php.is_empty() {
        hits += 1;
        report.findings.push(
            Finding::new(
                if autoload && php.len() >= 2 {
                    Severity::Critical
                } else {
                    Severity::Warning
                },
                Category::SuspiciousPattern,
                Source::Database,
                format!("{rule_prefix}_php_payload"),
                subject.to_string(),
                format!("{title}: PHP-Ausführungs-/Dekodierfunktion in Datenbankwert"),
            )
            .with_description(
                "Backdoors legen ihre eigentliche Nutzlast gern in wp_options ab und laden sie über \
                 eval(base64_decode(get_option(…))). Wert und lesenden Code identifizieren.",
            )
            .with_evidence(php.join(", ")),
        );
    }
    hits
}

fn option_injection(
    run: &mut Run,
    conn: &mut Conn,
    _ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    let sql = format!(
        "SELECT option_id AS id, option_name AS name, autoload, SUBSTRING(option_value, 1, 500000) AS v FROM {} \
         WHERE option_name NOT LIKE '\\_transient%' AND option_name NOT LIKE '\\_site\\_transient%' \
           AND option_name NOT IN ('cron', 'active_plugins', 'rewrite_rules') \
           AND (option_value LIKE '%<script%' OR option_value LIKE '%eval(%' OR option_value LIKE '%base64\\_decode%' \
                OR option_value LIKE '%gzinflate%' OR option_value LIKE '%String.fromCharCode%' OR option_value LIKE '%atob(%' \
                OR option_value LIKE '%document.write(%') \
         LIMIT 300",
        run.t("options")
    );
    let rows = query_rows(conn, &sql)?;
    let mut flagged = 0usize;
    for row in &rows {
        let name = col(row, "name");
        let autoload = matches!(col(row, "autoload"), "yes" | "on" | "auto-on" | "auto");
        let value = col(row, "v");
        if inspect_stored_content(
            run,
            value,
            "wp_option",
            &format!("{}options:{name}", run.prefix),
            &format!("Option {name}{}", if autoload { " (autoload)" } else { "" }),
            autoload,
            report,
        ) > 0
        {
            flagged += 1;
        }
    }
    report.items.push(IntegrityItem::new(
        "wp.options.injection",
        "Storefront",
        "Optionen mit Script/Code-Inhalten",
        if flagged > 0 {
            IntegrityStatus::Warning
        } else {
            IntegrityStatus::Ok
        },
        format!("{flagged} auffällig von {} mit Script/Code", rows.len()),
    ));
    Ok(())
}

// ------------------------------------------------------------------ cron

/// Hooks (with their argument dumps) of the `cron` option.
pub fn cron_hooks(value: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Some(v) = unserialize(value) else {
        return out;
    };
    for (ts, hooks) in v.entries() {
        if ts.as_string() == "version" {
            continue;
        }
        for (hook, events) in hooks.entries() {
            let mut args = Vec::new();
            for (_, ev) in events.entries() {
                if let Some(a) = ev.get("args") {
                    collect_scalars(a, &mut args, 0);
                }
            }
            out.push((hook.as_string(), args.join(" ")));
        }
    }
    out
}

fn collect_scalars(v: &PhpValue, out: &mut Vec<String>, depth: usize) {
    if depth > 8 || out.len() > 50 {
        return;
    }
    match v {
        PhpValue::Array(e) | PhpValue::Object(_, e) => {
            for (_, x) in e {
                collect_scalars(x, out, depth + 1);
            }
        }
        other => {
            let s = other.as_string();
            if !s.is_empty() {
                out.push(s);
            }
        }
    }
}

fn known_hook(hook: &str, plugins: &[Extension]) -> bool {
    let h = hook.to_ascii_lowercase();
    KNOWN_CRON_PREFIXES.iter().any(|p| h.starts_with(p))
        || plugins.iter().any(|p| {
            let slug = p.slug.to_ascii_lowercase();
            let a = slug.replace('-', "_");
            let first = a.split('_').next().unwrap_or("");
            h.starts_with(&a) || h.starts_with(&slug) || (first.len() >= 4 && h.starts_with(first))
        })
}

fn cron(
    run: &mut Run,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    let Some(value) = run.option(conn, "cron")? else {
        return Ok(());
    };
    let hooks = cron_hooks(&value);
    let previous: Snapshot = ctx.state.snapshot("wp-cron").unwrap_or_default();
    let mut current = Snapshot::default();
    let mut unknown = BTreeSet::new();
    static URL: OnceLock<Regex> = OnceLock::new();
    let url = URL.get_or_init(|| {
        Regex::new(r"(?i)(https?|ftp|php|data)://|[A-Za-z0-9+/]{120,}={0,2}").expect("regex")
    });
    for (hook, args) in &hooks {
        current.entries.insert(hook.clone(), String::new());
        let is_known = known_hook(hook, run.plugins);
        if !is_known {
            unknown.insert(hook.clone());
        }
        let odd_args = url.find(args).map(|m| m.as_str().to_string());
        let random = random_looking(hook);
        if odd_args.is_some() || random {
            report.findings.push(
                Finding::new(
                    if odd_args.is_some() && !is_known {
                        Severity::Critical
                    } else {
                        Severity::Warning
                    },
                    Category::SuspiciousPattern,
                    Source::Database,
                    "wp_cron_suspicious_hook",
                    format!("{}options:cron:{hook}", run.prefix),
                    format!("WP-Cron-Ereignis mit auffälligem Namen/Argumenten: {hook}"),
                )
                .with_description(
                    "Malware registriert sich als wiederkehrendes WP-Cron-Ereignis, das Code von einem \
                     fremden Server lädt oder Backdoors nach dem Löschen neu anlegt. Zugehörigen Code \
                     (grep nach dem Hook-Namen) suchen und Ereignis entfernen.",
                )
                .with_evidence(excerpt(
                    &format!(
                        "{}{}",
                        if random { "Name wirkt zufällig; " } else { "" },
                        odd_args.unwrap_or_default()
                    ),
                    200,
                )),
            );
        } else if !is_known && !previous.entries.is_empty() && !previous.entries.contains_key(hook)
        {
            report.findings.push(
                Finding::new(
                    Severity::Warning,
                    Category::SuspiciousPattern,
                    Source::Database,
                    "wp_cron_new_unknown_hook",
                    format!("{}options:cron:{hook}", run.prefix),
                    format!("Neues unbekanntes WP-Cron-Ereignis seit dem letzten Scan: {hook}"),
                )
                .with_description(
                    "Der Hook gehört weder zu WordPress/WooCommerce noch erkennbar zu einem installierten \
                     Plugin. Zuordnen oder entfernen.",
                ),
            );
        }
    }
    report.items.push(
        IntegrityItem::new(
            "wp.cron",
            "WP-Cron",
            "Geplante Ereignisse / nicht zugeordnet",
            if unknown.is_empty() {
                IntegrityStatus::Ok
            } else {
                IntegrityStatus::Warning
            },
            format!("{} / {}", hooks.len(), unknown.len()),
        )
        .with_detail(if unknown.is_empty() {
            "alle Hooks WordPress, WooCommerce oder installierten Plugins zugeordnet".to_string()
        } else {
            format!(
                "nicht zugeordnet: {}",
                unknown.iter().cloned().collect::<Vec<_>>().join(", ")
            )
        }),
    );
    if !unknown.is_empty() {
        report.findings.push(
            Finding::new(
                Severity::Info,
                Category::Informational,
                Source::Database,
                "wp_cron_unknown_hooks",
                format!("{}options:cron", run.prefix),
                format!("{} WP-Cron-Hooks ohne erkennbare Zuordnung", unknown.len()),
            )
            .with_description(
                "Hooks, die keinem bekannten Präfix und keinem installierten Plugin zugeordnet werden \
                 konnten. Meist harmlos (Plugin mit abweichendem Präfix) – einmal prüfen und ggf. als \
                 unbedenklich markieren.",
            )
            .with_evidence(excerpt(
                &unknown.iter().cloned().collect::<Vec<_>>().join(", "),
                400,
            )),
        );
    }
    ctx.state.save_snapshot("wp-cron", &current)?;
    Ok(())
}

// ------------------------------------------------------------------ payment

/// Payment gateway options checked in full.
const PAYMENT_OPTIONS: &[&str] = &[
    "woocommerce_paypal_settings",
    "woocommerce_ppcp-gateway_settings",
    "woocommerce-ppcp-settings",
    "woocommerce-ppcp-data-common",
    "woocommerce_stripe_settings",
    "woocommerce_bacs_settings",
    "woocommerce_bacs_accounts",
    "woocommerce_mollie_settings",
    "woocommerce_klarna_payments_settings",
    "woocommerce_amazon_payments_advanced",
    "woocommerce_braintree_credit_card_settings",
    "woocommerce_square_credit_card_settings",
];

fn sensitive_key(path: &str) -> Option<bool> {
    static RE: OnceLock<Regex> = OnceLock::new();
    static SECRET: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(?i)(e-?mail|merchant|account|client_?id|publishable|receiver|payee|iban|bic|sort_?code|bank|webhook|api_?user|api_?key|secret|token|signature|password|profile_?id|partner)")
            .expect("regex")
    });
    let secret = SECRET.get_or_init(|| {
        Regex::new(r"(?i)(secret|token|signature|password|api_?key|private)").expect("regex")
    });
    let last = path.rsplit(['.', '[']).next().unwrap_or(path);
    if !re.is_match(last)
        || last.contains("enabled")
        || last.contains("debug")
        || last.ends_with("_title")
    {
        return None;
    }
    Some(secret.is_match(last))
}

/// Flatten a serialized settings array into `path → value`.
pub fn flatten(prefix: &str, v: &PhpValue, out: &mut Vec<(String, String)>, depth: usize) {
    if depth > 6 || out.len() > 500 {
        return;
    }
    match v {
        PhpValue::Array(e) | PhpValue::Object(_, e) => {
            for (k, x) in e {
                let key = k.as_string();
                let path = if prefix.is_empty() {
                    key
                } else if matches!(k, PhpValue::Int(_)) {
                    format!("{prefix}[{key}]")
                } else {
                    format!("{prefix}.{key}")
                };
                flatten(&path, x, out, depth + 1);
            }
        }
        other => out.push((prefix.to_string(), other.as_string())),
    }
}

fn payment_settings(
    run: &mut Run,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    let names = PAYMENT_OPTIONS
        .iter()
        .map(|n| format!("'{n}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT option_name AS name, option_value AS v FROM {} \
         WHERE option_name IN ({names}) \
            OR (option_name LIKE 'woocommerce\\_%\\_settings' AND (option_value LIKE '%merchant%' OR option_value LIKE '%receiver%' OR option_value LIKE '%account%' OR option_value LIKE '%client\\_id%' OR option_value LIKE '%publishable%' OR option_value LIKE '%iban%')) \
         ORDER BY option_name LIMIT 100",
        run.t("options")
    );
    let rows = query_rows(conn, &sql)?;
    let previous: Snapshot = ctx.state.snapshot("wc-payment").unwrap_or_default();
    let mut current = Snapshot::default();
    let mut changed_count = 0usize;
    for row in &rows {
        let name = col(row, "name");
        let raw = col(row, "v");
        let mut flat = Vec::new();
        match unserialize(raw) {
            Some(v) => flatten(name, &v, &mut flat, 0),
            None => flat.push((name.to_string(), raw.to_string())),
        }
        for (path, value) in flat {
            let Some(secret) = sensitive_key(&path) else {
                continue;
            };
            let digest = sha256_hex(value.as_bytes());
            current.entries.insert(path.clone(), digest.clone());
            let changed = matches!(previous.entries.get(&path), Some(p) if *p != digest);
            let added = !previous.entries.is_empty()
                && !previous.entries.contains_key(&path)
                && !value.is_empty();
            let shown = if value.is_empty() {
                "(leer)".to_string()
            } else if secret {
                "gesetzt (Wert verborgen, Hash wird verglichen)".to_string()
            } else if value.contains('@') {
                mask_email(&value)
            } else {
                mask(&value)
            };
            let mut item = IntegrityItem::new(
                format!("payment.{path}"),
                "Zahlung",
                &path,
                if changed {
                    IntegrityStatus::Critical
                } else if added {
                    IntegrityStatus::Warning
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
                        path.clone(),
                        "Zahlungsanbieter-Einstellung hat sich geändert",
                    )
                    .with_description(
                        "Händler-ID, Empfänger-E-Mail, Client-ID/API-Schlüssel oder Bankverbindung eines \
                         Zahlungsanbieters unterscheiden sich vom letzten Scan. Nicht selbst vorgenommene \
                         Änderungen deuten auf Zahlungsumleitung hin (WooCommerce › Einstellungen › Zahlungen).",
                    )
                    .with_evidence(format!("neuer Wert: {shown}")),
                );
            } else if added {
                report.findings.push(
                    Finding::new(
                        Severity::Warning,
                        Category::PaymentConfiguration,
                        Source::Database,
                        "payment_config_added",
                        path.clone(),
                        "Neue Zahlungsanbieter-Einstellung seit dem letzten Scan",
                    )
                    .with_evidence(format!("Wert: {shown}")),
                );
            }
            report.items.push(item);
        }
    }
    if current.entries.is_empty() {
        report.items.push(IntegrityItem::new(
            "payment.summary",
            "Zahlung",
            "Zahlungsanbieter-Einstellungen",
            IntegrityStatus::Unknown,
            "keine PayPal/Stripe/BACS-Einstellungen gefunden",
        ));
    } else {
        report.items.push(IntegrityItem::new(
            "payment.summary",
            "Zahlung",
            "Zahlungsanbieter-Einstellungen geprüft / geändert",
            if changed_count > 0 {
                IntegrityStatus::Critical
            } else {
                IntegrityStatus::Ok
            },
            format!("{} / {changed_count}", current.entries.len()),
        ));
    }
    ctx.state.save_snapshot("wc-payment", &current)?;
    Ok(())
}

// ------------------------------------------------------------------ posts

fn post_scripts(
    run: &mut Run,
    conn: &mut Conn,
    _ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !run.exists(conn, "posts")? {
        return Ok(());
    }
    let sql = format!(
        "SELECT ID AS id, post_type, post_status, post_title, post_modified, post_content FROM {} \
         WHERE post_type IN ('post','page','product','wp_block','wp_template','wp_template_part','wp_navigation') \
           AND post_status NOT IN ('trash','auto-draft','inherit') \
           AND (post_content LIKE '%<script%' OR post_content LIKE '%<iframe%' OR post_content LIKE '%atob(%' \
                OR post_content LIKE '%eval(%' OR post_content LIKE '%display:none%' OR post_content LIKE '%display: none%') \
         ORDER BY ID LIMIT 500",
        run.t("posts")
    );
    let rows = query_rows(conn, &sql)?;
    let mut flagged = 0usize;
    for row in &rows {
        let id = col(row, "id");
        let ptype = col(row, "post_type");
        let title = excerpt(col(row, "post_title"), 60);
        if inspect_stored_content(
            run,
            col(row, "post_content"),
            "wp_post",
            &format!("{}posts:{id}", run.prefix),
            &format!("{ptype} #{id} „{title}“"),
            false,
            report,
        ) > 0
        {
            flagged += 1;
        }
    }
    report.items.push(IntegrityItem::new(
        "wp.posts.injection",
        "Storefront",
        "Beiträge/Seiten/Produkte mit fremden Scripts oder Spam",
        if flagged > 0 {
            IntegrityStatus::Warning
        } else {
            IntegrityStatus::Ok
        },
        format!("{flagged} auffällig von {} mit Script/iframe", rows.len()),
    ));
    Ok(())
}

// ------------------------------------------------------------------ api keys

fn api_keys(
    run: &mut Run,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !run.exists(conn, "woocommerce_api_keys")? {
        return Ok(());
    }
    let cols = columns(conn, &format!("{}woocommerce_api_keys", run.prefix))?;
    let has = |c: &str| cols.iter().any(|x| x == c);
    let mut select = vec![
        "k.key_id AS key_id",
        "k.user_id AS user_id",
        "u.user_login AS login",
    ];
    for c in ["description", "permissions", "truncated_key", "last_access"] {
        if has(c) {
            select.push(match c {
                "description" => "k.description AS description",
                "permissions" => "k.permissions AS permissions",
                "truncated_key" => "k.truncated_key AS truncated_key",
                _ => "k.last_access AS last_access",
            });
        }
    }
    let rows = query_rows(
        conn,
        &format!(
            "SELECT {} FROM {} k LEFT JOIN {} u ON u.ID = k.user_id ORDER BY k.key_id",
            select.join(", "),
            run.t("woocommerce_api_keys"),
            run.t("users")
        ),
    )?;
    let previous: Snapshot = ctx.state.snapshot("wc-api-keys").unwrap_or_default();
    let mut current = Snapshot::default();
    for row in &rows {
        let id = col(row, "key_id").to_string();
        let desc = col(row, "description").to_string();
        let perms = col(row, "permissions").to_string();
        let login = col(row, "login").to_string();
        current.entries.insert(
            id.clone(),
            sha256_hex(format!("{desc}|{perms}|{}", col(row, "user_id")).as_bytes()),
        );
        let write = perms.contains("write");
        report.items.push(
            IntegrityItem::new(
                format!("wc.api_key.{id}"),
                "API-Integrationen",
                if desc.is_empty() {
                    format!("REST-Schlüssel #{id}")
                } else {
                    desc.clone()
                },
                if write {
                    IntegrityStatus::Warning
                } else {
                    IntegrityStatus::Ok
                },
                format!(
                    "{} · Benutzer {} · Key …{}",
                    if perms.is_empty() { "?" } else { &perms },
                    if login.is_empty() { "?" } else { &login },
                    col(row, "truncated_key")
                ),
            )
            .with_detail(format!("letzter Zugriff: {}", {
                let a = col(row, "last_access");
                if a.is_empty() {
                    "nie"
                } else {
                    a
                }
            })),
        );
        if !previous.entries.is_empty() && !previous.entries.contains_key(&id) {
            report.findings.push(
                Finding::new(
                    Severity::Critical,
                    Category::AdminAccount,
                    Source::Database,
                    "wc_api_key_new",
                    format!("{}woocommerce_api_keys:{id}", run.prefix),
                    format!("Neuer WooCommerce-REST-API-Schlüssel seit dem letzten Scan: {desc}"),
                )
                .with_description(
                    "REST-API-Schlüssel erlauben – je nach Berechtigung – Bestell- und Kundendaten zu lesen \
                     oder Einstellungen zu ändern. Unbekannte Schlüssel unter WooCommerce › Einstellungen › \
                     Erweitert › REST-API widerrufen.",
                )
                .with_evidence(format!("Berechtigung {perms} · Benutzer {login}")),
            );
        }
    }
    report.items.push(IntegrityItem::new(
        "wc.api_keys.summary",
        "API-Integrationen",
        "WooCommerce-REST-API-Schlüssel",
        IntegrityStatus::Ok,
        rows.len().to_string(),
    ));
    ctx.state.save_snapshot("wc-api-keys", &current)?;
    Ok(())
}

fn webhooks(
    run: &mut Run,
    conn: &mut Conn,
    ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    if !run.exists(conn, "wc_webhooks")? {
        return Ok(());
    }
    let rows = query_rows(
        conn,
        &format!(
            "SELECT webhook_id, status, name, delivery_url, topic, date_created FROM {} ORDER BY webhook_id",
            run.t("wc_webhooks")
        ),
    )?;
    let previous: Snapshot = ctx.state.snapshot("wc-webhooks").unwrap_or_default();
    let mut current = Snapshot::default();
    for row in &rows {
        let id = col(row, "webhook_id").to_string();
        let url = col(row, "delivery_url").to_string();
        let topic = col(row, "topic").to_string();
        let host = host_of(&url).unwrap_or_default();
        let class = run.classify(&host);
        current
            .entries
            .insert(id.clone(), sha256_hex(format!("{url}|{topic}").as_bytes()));
        let new = !previous.entries.is_empty() && !previous.entries.contains_key(&id);
        let changed = matches!(previous.entries.get(&id), Some(p) if *p != sha256_hex(format!("{url}|{topic}").as_bytes()));
        report.items.push(
            IntegrityItem::new(
                format!("wc.webhook.{id}"),
                "API-Integrationen",
                format!("Webhook {}", col(row, "name")),
                match class {
                    HostClass::Suspicious => IntegrityStatus::Critical,
                    _ if new || changed => IntegrityStatus::Critical,
                    HostClass::Unknown => IntegrityStatus::Warning,
                    _ => IntegrityStatus::Ok,
                },
                format!("{topic} → {host} ({})", class.label()),
            )
            .with_detail(format!(
                "Status {} · angelegt {}",
                col(row, "status"),
                col(row, "date_created")
            )),
        );
        if class == HostClass::Suspicious || new || changed {
            report.findings.push(
                Finding::new(
                    Severity::Critical,
                    Category::ThirdPartyInjection,
                    Source::Database,
                    if new { "wc_webhook_new" } else if changed { "wc_webhook_changed" } else { "wc_webhook_suspicious_host" },
                    format!("{}wc_webhooks:{id}", run.prefix),
                    format!("WooCommerce-Webhook {topic} an {host}"),
                )
                .with_description(
                    "Webhooks senden Bestell-/Kundendaten automatisch an die hinterlegte URL. Neue, geänderte \
                     oder auf verdächtige Hosts zeigende Webhooks sind ein Exfiltrationsweg. Unter \
                     WooCommerce › Einstellungen › Erweitert › Webhooks prüfen.",
                )
                .with_evidence(excerpt(&url, 200)),
            );
        }
    }
    ctx.state.save_snapshot("wc-webhooks", &current)?;
    Ok(())
}

fn suspicious_user_emails(
    run: &mut Run,
    conn: &mut Conn,
    _ctx: &PlatformContext,
    report: &mut IntegrityReport,
) -> anyhow::Result<()> {
    let cond = SUSPICIOUS_TLDS
        .iter()
        .map(|t| format!("user_email LIKE '%.{t}'"))
        .collect::<Vec<_>>()
        .join(" OR ");
    let rows = query_rows(
        conn,
        &format!(
            "SELECT ID AS id, user_login AS login, user_email AS email, user_registered AS registered FROM {} \
             WHERE {cond} ORDER BY ID DESC LIMIT 50",
            run.t("users")
        ),
    )?;
    if rows.is_empty() {
        return Ok(());
    }
    let sample: Vec<String> = rows
        .iter()
        .take(10)
        .map(|r| format!("{} ({})", col(r, "login"), mask_email(col(r, "email"))))
        .collect();
    report.findings.push(
        Finding::new(
            Severity::Info,
            Category::Informational,
            Source::Database,
            "wp_users_suspicious_tld",
            format!("{}users", run.prefix),
            format!(
                "{}{} Benutzerkonten mit E-Mail-Adressen unter auffälligen TLDs",
                rows.len(),
                if rows.len() >= 50 { "+" } else { "" }
            ),
        )
        .with_description(
            "Häufig Spam-Registrierungen; bei Häufung nach dem Referenzdatum auf automatisierte \
             Kontoanlage (Bot-Registrierung, Credential Stuffing) prüfen.",
        )
        .with_evidence(sample.join(", ")),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_and_sessions() {
        assert_eq!(
            roles_of(r#"a:1:{s:13:"administrator";b:1;}"#),
            vec!["administrator".to_string()]
        );
        assert!(roles_of(r#"a:1:{s:8:"customer";b:1;}"#)
            .iter()
            .all(|r| !PRIVILEGED_ROLES.contains(&r.as_str())));
        let (last, ips) = sessions_of(
            r#"a:2:{s:3:"abc";a:4:{s:10:"expiration";i:1760000000;s:2:"ip";s:9:"203.0.1.5";s:2:"ua";s:3:"cli";s:5:"login";i:1759000000;}s:3:"def";a:2:{s:2:"ip";s:9:"198.5.1.1";s:5:"login";i:1759500000;}}"#,
        );
        assert_eq!(last.unwrap().timestamp(), 1_759_500_000);
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn cron_parsing() {
        let value = r#"a:3:{i:1760000000;a:1:{s:16:"wp_version_check";a:1:{s:32:"40cd750bba9870f18aada2478b24840a";a:3:{s:8:"schedule";s:10:"twicedaily";s:4:"args";a:0:{}s:8:"interval";i:43200;}}}i:1760000100;a:1:{s:9:"xqzvkrtwp";a:1:{s:32:"40cd750bba9870f18aada2478b24840a";a:2:{s:8:"schedule";b:0;s:4:"args";a:1:{i:0;s:22:"https://evil.top/x.txt";}}}}s:7:"version";i:2;}"#;
        let hooks = cron_hooks(value);
        assert_eq!(hooks.len(), 2);
        assert_eq!(hooks[1].0, "xqzvkrtwp");
        assert!(hooks[1].1.contains("evil.top"));
        assert!(known_hook("wp_version_check", &[]));
        assert!(!known_hook("xqzvkrtwp", &[]));
    }

    #[test]
    fn payment_flattening() {
        let v = unserialize(r#"a:3:{s:7:"enabled";s:3:"yes";s:5:"email";s:16:"shop@example.com";s:13:"api_signature";s:6:"secret";}"#).unwrap();
        let mut flat = Vec::new();
        flatten("woocommerce_paypal_settings", &v, &mut flat, 0);
        let keys: Vec<_> = flat
            .iter()
            .filter_map(|(p, _)| sensitive_key(p).map(|s| (p.clone(), s)))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("woocommerce_paypal_settings.email".to_string(), false),
                (
                    "woocommerce_paypal_settings.api_signature".to_string(),
                    true
                )
            ]
        );
        let v = unserialize(r#"a:1:{i:0;a:2:{s:12:"account_name";s:4:"ACME";s:4:"iban";s:22:"DE89370400440532013000";}}"#).unwrap();
        let mut flat = Vec::new();
        flatten("woocommerce_bacs_accounts", &v, &mut flat, 0);
        assert!(flat
            .iter()
            .any(|(p, _)| p == "woocommerce_bacs_accounts[0].iban"));
        assert!(sensitive_key("woocommerce_bacs_accounts[0].iban").is_some());
    }
}
