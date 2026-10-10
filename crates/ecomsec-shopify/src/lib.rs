//! Shopify adapter (hosted platform, API only).
//!
//! Shopify stores have no file system to scan.  The relevant compromise
//! vectors are injected JavaScript (script tags, theme assets), data
//! exfiltration through webhooks to foreign hosts, rogue apps with broad
//! access scopes and unknown staff accounts.  All checks use the Admin API
//! with a read-only access token:
//!
//! * `shop.json` – identity,
//! * `script_tags.json` – foreign / suspicious script sources (Magecart),
//! * `webhooks.json` – subscriptions that send order/customer data elsewhere,
//! * `themes.json` + `assets.json` – layout, snippets and JavaScript of the
//!   live theme scanned with the skimmer/obfuscation rules and compared
//!   against the reference date,
//! * GraphQL `appInstallations` – apps and their access scopes,
//! * `users.json` – staff accounts (Shopify Plus only).
//!
//! Script tags, webhooks and apps are snapshotted so that additions since
//! the last scan are reported as critical findings.

mod client;
mod domains;

pub use client::{ShopifyClient, ShopifyConfig};
pub use domains::{classify_host, HostClass};

use chrono::{DateTime, Utc};
use ecomsec_core::finding::{Category, Finding, Severity, Source};
use ecomsec_core::platform::{
    IntegrityItem, IntegrityReport, IntegrityStatus, Platform, PlatformContext, PlatformInfo,
    PlatformKind,
};
use ecomsec_core::recommendations::{Recommendation, RecommendationGroupKind};
use ecomsec_core::report::Report;
use ecomsec_core::rules::RuleSet;
use ecomsec_core::util::{excerpt, mask_email};
use regex::Regex;
use serde_json::Value;
use std::collections::BTreeMap;

pub const PLATFORM_ID: &str = "shopify";

pub struct Shopify {
    client: ShopifyClient,
    shop: Value,
    allowlist: Vec<String>,
    max_assets: usize,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Snapshot {
    entries: BTreeMap<String, String>,
}

impl Shopify {
    /// Connect and fetch `shop.json` once to validate the token.
    pub fn open(config: ShopifyConfig) -> anyhow::Result<Self> {
        let allowlist = config.allowlist.clone();
        let max_assets = config.max_assets;
        let client = ShopifyClient::new(config)?;
        let shop = client
            .get_json("shop.json")?
            .get("shop")
            .cloned()
            .unwrap_or(Value::Null);
        Ok(Shopify {
            client,
            shop,
            allowlist,
            max_assets,
        })
    }

    fn shop_str(&self, key: &str) -> String {
        self.shop
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }

    fn classify(&self, url: &str) -> (HostClass, String) {
        let host = domains::host_of(url).unwrap_or_default();
        (classify_host(&host, &self.allowlist), host)
    }

    fn after_reference(&self, ts: &str, ctx: &PlatformContext) -> bool {
        DateTime::parse_from_rfc3339(ts)
            .map(|d| d.with_timezone(&Utc).date_naive() >= ctx.reference_date)
            .unwrap_or(false)
    }

    fn script_tags(
        &self,
        ctx: &PlatformContext,
        report: &mut IntegrityReport,
    ) -> anyhow::Result<()> {
        let tags = self.client.get_json("script_tags.json?limit=250")?;
        let list = tags
            .get("script_tags")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let previous: Snapshot = ctx
            .state
            .snapshot("shopify-script-tags")
            .unwrap_or_default();
        let mut current = Snapshot::default();
        let mut suspicious = 0usize;
        for tag in &list {
            let id = tag.get("id").map(|v| v.to_string()).unwrap_or_default();
            let src = tag
                .get("src")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let created = tag
                .get("created_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let scope = tag
                .get("display_scope")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            current.entries.insert(id.clone(), src.clone());
            let (class, host) = self.classify(&src);
            let is_new = !previous.entries.is_empty() && !previous.entries.contains_key(&id);
            let (status, severity) = match class {
                HostClass::Platform | HostClass::Allowlisted => (IntegrityStatus::Ok, None),
                HostClass::Unknown => (IntegrityStatus::Warning, Some(Severity::Warning)),
                HostClass::Suspicious => (IntegrityStatus::Critical, Some(Severity::Critical)),
            };
            report.items.push(
                IntegrityItem::new(
                    format!("script_tag.{id}"),
                    "Script-Tags",
                    &host,
                    status,
                    format!(
                        "{} · Scope {} · angelegt {}",
                        class.label(),
                        scope,
                        created.get(..10).unwrap_or(&created)
                    ),
                )
                .with_detail(src.clone()),
            );
            let severity = match (severity, is_new) {
                (Some(_), true) => Some(Severity::Critical),
                (s, _) => s,
            };
            if let Some(sev) = severity {
                suspicious += 1;
                report.findings.push(
                    Finding::new(sev, Category::ThirdPartyInjection, Source::Api, "script_tag_foreign", format!("script_tag:{id}"), format!("{}Script-Tag von {}: {host}", if is_new { "NEUES " } else { "" }, class.label()))
                        .with_description("Script-Tags werden auf jeder Storefront-Seite (und je nach Scope im Order-Status) geladen. Unbekannte Quellen sind der häufigste Weg für Kartendaten-Skimmer (Magecart). Jeden Eintrag einer installierten App zuordnen; unbekannte Tags löschen und die zugehörige App entfernen.")
                        .with_evidence(src.clone())
                        .with_evidence(format!("angelegt {created} · Scope {scope}")),
                );
            } else if self.after_reference(&created, ctx) {
                report.findings.push(
                    Finding::new(
                        Severity::Info,
                        Category::ThirdPartyInjection,
                        Source::Api,
                        "script_tag_recent",
                        format!("script_tag:{id}"),
                        format!("Script-Tag nach dem Referenzdatum angelegt: {host}"),
                    )
                    .with_evidence(src.clone()),
                );
            }
        }
        report.items.push(IntegrityItem::new(
            "script_tags.summary",
            "Script-Tags",
            "Script-Tags gesamt / auffällig",
            if suspicious > 0 {
                IntegrityStatus::Warning
            } else {
                IntegrityStatus::Ok
            },
            format!("{} / {suspicious}", list.len()),
        ));
        ctx.state.save_snapshot("shopify-script-tags", &current)?;
        Ok(())
    }

    fn webhooks(&self, ctx: &PlatformContext, report: &mut IntegrityReport) -> anyhow::Result<()> {
        let hooks = self.client.get_json("webhooks.json?limit=250")?;
        let list = hooks
            .get("webhooks")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let previous: Snapshot = ctx.state.snapshot("shopify-webhooks").unwrap_or_default();
        let mut current = Snapshot::default();
        let sensitive = [
            "orders",
            "customers",
            "checkouts",
            "draft_orders",
            "fulfillments",
            "payment",
        ];
        let mut flagged = 0usize;
        for hook in &list {
            let id = hook.get("id").map(|v| v.to_string()).unwrap_or_default();
            let address = hook
                .get("address")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let topic = hook
                .get("topic")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let created = hook
                .get("created_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            current
                .entries
                .insert(id.clone(), format!("{topic}|{address}"));
            let (class, host) = self.classify(&address);
            let is_sensitive = sensitive.iter().any(|s| topic.starts_with(s));
            let is_new = !previous.entries.is_empty() && !previous.entries.contains_key(&id);
            let severity = match class {
                HostClass::Platform | HostClass::Allowlisted => None,
                HostClass::Unknown if is_sensitive => Some(Severity::Warning),
                HostClass::Unknown => Some(Severity::Info),
                HostClass::Suspicious => Some(Severity::Critical),
            };
            let severity = if is_new && is_sensitive {
                Some(Severity::Critical)
            } else {
                severity
            };
            report.items.push(
                IntegrityItem::new(
                    format!("webhook.{id}"),
                    "Webhooks",
                    &topic,
                    match severity {
                        None => IntegrityStatus::Ok,
                        Some(Severity::Info) => IntegrityStatus::Ok,
                        Some(Severity::Warning) => IntegrityStatus::Warning,
                        Some(Severity::Critical) => IntegrityStatus::Critical,
                    },
                    format!("{host} · {}", class.label()),
                )
                .with_detail(address.clone()),
            );
            if let Some(sev) = severity {
                flagged += 1;
                report.findings.push(
                    Finding::new(sev, Category::ThirdPartyInjection, Source::Api, "webhook_foreign", format!("webhook:{id}"), format!("{}Webhook {topic} an {}: {host}", if is_new { "NEUER " } else { "" }, class.label()))
                        .with_description("Webhooks kopieren Bestell-, Kunden- oder Checkout-Daten in Echtzeit an die hinterlegte Adresse. Unbekannte Ziele sind ein Datenabfluss. Eintrag einer App zuordnen oder löschen; API-Zugänge der zugehörigen App widerrufen.")
                        .with_evidence(address.clone())
                        .with_evidence(format!("angelegt {created}")),
                );
            }
        }
        report.items.push(IntegrityItem::new(
            "webhooks.summary",
            "Webhooks",
            "Webhooks gesamt / auffällig",
            if flagged > 0 {
                IntegrityStatus::Warning
            } else {
                IntegrityStatus::Ok
            },
            format!("{} / {flagged}", list.len()),
        ));
        ctx.state.save_snapshot("shopify-webhooks", &current)?;
        Ok(())
    }

    fn apps(&self, ctx: &PlatformContext, report: &mut IntegrityReport) -> anyhow::Result<()> {
        let query = r#"{ appInstallations(first: 100) { edges { node { id app { title developerName appStoreAppUrl } accessScopes { handle } } } } }"#;
        let resp = self.client.graphql(query)?;
        let edges = resp
            .pointer("/data/appInstallations/edges")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let previous: Snapshot = ctx.state.snapshot("shopify-apps").unwrap_or_default();
        let mut current = Snapshot::default();
        let risky = [
            "write_orders",
            "read_customers",
            "write_customers",
            "write_script_tags",
            "write_themes",
            "read_all_orders",
            "write_payment_terms",
            "write_checkouts",
            "read_checkouts",
            "write_content",
        ];
        for edge in &edges {
            let node = edge.get("node").cloned().unwrap_or(Value::Null);
            let id = node
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let title = node
                .pointer("/app/title")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            let dev = node
                .pointer("/app/developerName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let store_url = node
                .pointer("/app/appStoreAppUrl")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let scopes: Vec<String> = node
                .get("accessScopes")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|s| {
                            s.get("handle").and_then(|h| h.as_str()).map(str::to_string)
                        })
                        .collect()
                })
                .unwrap_or_default();
            let risky_scopes: Vec<&String> = scopes
                .iter()
                .filter(|s| risky.contains(&s.as_str()))
                .collect();
            current.entries.insert(id.clone(), title.clone());
            let is_new = !previous.entries.is_empty() && !previous.entries.contains_key(&id);
            let unlisted = store_url.is_empty();
            let status = if is_new {
                IntegrityStatus::Critical
            } else if unlisted && !risky_scopes.is_empty() {
                IntegrityStatus::Warning
            } else {
                IntegrityStatus::Ok
            };
            report.items.push(
                IntegrityItem::new(
                    format!("app.{id}"),
                    "Apps",
                    &title,
                    status,
                    format!(
                        "{} · {} Scopes{}{}",
                        if dev.is_empty() {
                            "unbekannter Entwickler"
                        } else {
                            &dev
                        },
                        scopes.len(),
                        if risky_scopes.is_empty() {
                            String::new()
                        } else {
                            format!(" ({} sensibel)", risky_scopes.len())
                        },
                        if unlisted {
                            " · nicht im App Store (Custom/Private App)"
                        } else {
                            ""
                        }
                    ),
                )
                .with_detail(scopes.join(", ")),
            );
            if is_new {
                report.findings.push(
                    Finding::new(Severity::Critical, Category::ThirdPartyInjection, Source::Api, "app_new", format!("app:{id}"), format!("Neue App seit dem letzten Scan: {title}"))
                        .with_description("Apps erhalten dauerhaften API-Zugriff. Eine unbekannte Installation – insbesondere eine Custom App ohne App-Store-Eintrag – ist ein typischer Persistenzmechanismus nach gestohlenen Admin-Zugängen.")
                        .with_evidence(format!("Entwickler {dev} · Scopes {}", scopes.join(", "))),
                );
            } else if unlisted && !risky_scopes.is_empty() {
                report.findings.push(
                    Finding::new(Severity::Warning, Category::ThirdPartyInjection, Source::Api, "app_custom_risky", format!("app:{id}"), format!("Custom App mit sensiblen Berechtigungen: {title}"))
                        .with_description("Custom/Private Apps ohne App-Store-Eintrag mit Schreibrechten auf Bestellungen, Kunden, Themes oder Script-Tags müssen eindeutig zuzuordnen sein.")
                        .with_evidence(risky_scopes.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")),
                );
            }
        }
        report.items.push(IntegrityItem::new(
            "apps.summary",
            "Apps",
            "Installierte Apps",
            IntegrityStatus::Ok,
            edges.len().to_string(),
        ));
        ctx.state.save_snapshot("shopify-apps", &current)?;
        Ok(())
    }

    fn staff(&self, ctx: &PlatformContext, report: &mut IntegrityReport) -> anyhow::Result<()> {
        let users = match self.client.get_json("users.json") {
            Ok(v) => v,
            Err(e) => {
                report.limitations.push(format!("Mitarbeiterkonten nicht abrufbar (users.json ist nur auf Shopify Plus verfügbar): {e}"));
                report.items.push(IntegrityItem::new("admin.summary", "Admin-Konten", "Mitarbeiterkonten", IntegrityStatus::Unknown, "nur auf Shopify Plus per API abrufbar").with_detail("Manuell unter Einstellungen › Benutzer und Berechtigungen prüfen; 2FA für alle Mitarbeiter erzwingen."));
                return Ok(());
            }
        };
        let list = users
            .get("users")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let previous: Snapshot = ctx.state.snapshot("shopify-staff").unwrap_or_default();
        let mut current = Snapshot::default();
        for u in &list {
            let id = u.get("id").map(|v| v.to_string()).unwrap_or_default();
            let email = u
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name = format!(
                "{} {}",
                u.get("first_name").and_then(|v| v.as_str()).unwrap_or(""),
                u.get("last_name").and_then(|v| v.as_str()).unwrap_or("")
            )
            .trim()
            .to_string();
            let owner = u
                .get("account_owner")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let tfa = u.get("tfa_enabled").and_then(|v| v.as_bool());
            let perms = u
                .get("permissions")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            current.entries.insert(id.clone(), email.clone());
            let status = match tfa {
                Some(true) => IntegrityStatus::Ok,
                Some(false) => IntegrityStatus::Warning,
                None => IntegrityStatus::Unknown,
            };
            report.items.push(
                IntegrityItem::new(
                    format!("admin.account.{id}"),
                    "Admin-Konten",
                    if name.is_empty() {
                        mask_email(&email)
                    } else {
                        name.clone()
                    },
                    status,
                    format!(
                        "{}{} Berechtigungen · 2FA: {}",
                        if owner { "Inhaber · " } else { "" },
                        perms,
                        match tfa {
                            Some(true) => "ja",
                            Some(false) => "nein",
                            None => "unbekannt",
                        }
                    ),
                )
                .with_detail(format!("E-Mail: {}", mask_email(&email))),
            );
            if !previous.entries.is_empty() && !previous.entries.contains_key(&id) {
                report.findings.push(
                    Finding::new(Severity::Critical, Category::AdminAccount, Source::Api, "staff_new", format!("staff:{id}"), format!("Neues Mitarbeiterkonto seit dem letzten Scan: {}", mask_email(&email)))
                        .with_description("Unbekannte Mitarbeiterkonten sofort entfernen und Passwörter/2FA der verbleibenden Konten erneuern."),
                );
            }
            if tfa == Some(false) {
                report.findings.push(Finding::new(
                    Severity::Info,
                    Category::AdminAccount,
                    Source::Api,
                    "staff_without_2fa",
                    format!("staff:{id}"),
                    format!("Mitarbeiterkonto ohne 2FA: {}", mask_email(&email)),
                ));
            }
        }
        report.items.push(IntegrityItem::new(
            "admin.summary",
            "Admin-Konten",
            "Mitarbeiterkonten",
            IntegrityStatus::Ok,
            list.len().to_string(),
        ));
        ctx.state.save_snapshot("shopify-staff", &current)?;
        Ok(())
    }

    fn theme(&self, ctx: &PlatformContext, report: &mut IntegrityReport) -> anyhow::Result<()> {
        let themes = self.client.get_json("themes.json")?;
        let list = themes
            .get("themes")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let Some(main) = list
            .iter()
            .find(|t| t.get("role").and_then(|r| r.as_str()) == Some("main"))
        else {
            report
                .limitations
                .push("Kein Live-Theme (role=main) gefunden.".into());
            return Ok(());
        };
        let theme_id = main.get("id").map(|v| v.to_string()).unwrap_or_default();
        let theme_name = main
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let theme_updated = main
            .get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        report.items.push(IntegrityItem::new(
            "theme.main",
            "Theme",
            "Live-Theme",
            IntegrityStatus::Ok,
            format!(
                "{theme_name} (#{theme_id}) · zuletzt geändert {}",
                theme_updated.get(..10).unwrap_or(&theme_updated)
            ),
        ));

        let assets = self
            .client
            .get_json(&format!("themes/{theme_id}/assets.json"))?;
        let asset_list = assets
            .get("assets")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let interesting = |key: &str| {
            key.starts_with("layout/")
                || (key.starts_with("assets/")
                    && (key.ends_with(".js") || key.ends_with(".js.liquid")))
                || key.starts_with("snippets/")
                || key == "config/settings_data.json"
        };
        let mut rules = ecomsec_core::signatures::builtin_rules()?;
        rules.extend(RuleSet::empty());
        let script_re = Regex::new(r#"(?i)<script[^>]{0,300}?src\s*=\s*["']?([^"'\s>]+)"#)?;
        let import_re = Regex::new(
            r#"(?i)(?:fetch|import|XMLHttpRequest|sendBeacon|src\s*=|new\s+Image\(\)\.src\s*=)\s*\(?\s*["'`](https?://[^"'`\s]+)"#,
        )?;
        let mut scanned = 0usize;
        let mut modified = 0usize;
        let mut hits = 0usize;
        let mut external_hosts: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for asset in asset_list
            .iter()
            .filter(|a| {
                a.get("key")
                    .and_then(|k| k.as_str())
                    .map(interesting)
                    .unwrap_or(false)
            })
            .take(self.max_assets)
        {
            let key = asset
                .get("key")
                .and_then(|k| k.as_str())
                .unwrap_or("")
                .to_string();
            let updated = asset
                .get("updated_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if self.after_reference(&updated, ctx)
                && (key.starts_with("layout/") || key.starts_with("assets/"))
            {
                modified += 1;
                report.findings.push(
                    Finding::new(Severity::Warning, Category::ModifiedSinceReference, Source::Api, "theme_asset_modified", format!("theme:{theme_id}:{key}"), format!("Theme-Datei nach dem Referenzdatum geändert: {key}"))
                        .with_description("Layout- und JavaScript-Dateien des Live-Themes sind die bevorzugte Stelle für eingeschleuste Skimmer. Änderung mit dem Theme-Changelog/Agentur abgleichen.")
                        .with_evidence(format!("geändert {updated}")),
                );
            }
            let content = match self.client.get_json(&format!(
                "themes/{theme_id}/assets.json?asset[key]={}",
                urlencode(&key)
            )) {
                Ok(v) => v
                    .pointer("/asset/value")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_default(),
                Err(e) => {
                    report
                        .limitations
                        .push(format!("Theme-Asset {key} nicht lesbar: {e}"));
                    continue;
                }
            };
            if content.is_empty() {
                continue;
            }
            scanned += 1;
            let class = if key.ends_with(".js") {
                "js"
            } else {
                "template"
            };
            for hit in rules.scan(class, content.as_bytes()) {
                hits += 1;
                let mut f = Finding::new(hit.rule.spec.severity, hit.rule.spec.category, Source::Api, hit.rule.name().to_string(), format!("theme:{theme_id}:{key}"), format!("{key}: {}", hit.rule.spec.description))
                    .with_description(format!("Regel `{}` im Live-Theme. Code im Theme-Editor prüfen; bei unbekanntem Code Theme aus einem sauberen Backup wiederherstellen.", hit.rule.name()));
                for ex in hit.excerpts.iter().take(3) {
                    f = f.with_evidence(ex.clone());
                }
                report.findings.push(f);
            }
            for cap in script_re
                .captures_iter(&content)
                .chain(import_re.captures_iter(&content))
            {
                let url = cap[1].to_string();
                if url.starts_with("{{") || url.starts_with("{%") || url.starts_with('/') {
                    continue;
                }
                let (class, host) = self.classify(&url);
                if matches!(class, HostClass::Unknown | HostClass::Suspicious) && !host.is_empty() {
                    external_hosts
                        .entry(host)
                        .or_default()
                        .push(format!("{key}: {}", excerpt(&url, 120)));
                }
            }
        }
        for (host, refs) in &external_hosts {
            let class = classify_host(host, &self.allowlist);
            let sev = if class == HostClass::Suspicious {
                Severity::Critical
            } else {
                Severity::Warning
            };
            let mut f = Finding::new(sev, Category::ThirdPartyInjection, Source::Api, "theme_external_script", format!("theme:{theme_id}:host:{host}"), format!("Live-Theme lädt Code von {}: {host}", class.label()))
                .with_description("Externe Script-Quellen im Theme sind legitim für bekannte Dienste (Tracking, Reviews, Chat). Unbekannte oder verdächtige Hosts sind das Hauptmerkmal von Skimmer-Injektionen.");
            for r in refs.iter().take(4) {
                f = f.with_evidence(r.clone());
            }
            report.findings.push(f);
        }
        report.items.push(
            IntegrityItem::new(
                "theme.scan",
                "Theme",
                "Theme-Dateien geprüft / seit Referenzdatum geändert / Treffer",
                if hits > 0 {
                    IntegrityStatus::Critical
                } else if modified > 0 || !external_hosts.is_empty() {
                    IntegrityStatus::Warning
                } else {
                    IntegrityStatus::Ok
                },
                format!("{scanned} / {modified} / {hits}"),
            )
            .with_detail(format!(
                "externe Hosts (nicht allowlisted): {}",
                if external_hosts.is_empty() {
                    "keine".to_string()
                } else {
                    external_hosts
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            )),
        );
        Ok(())
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

impl Platform for Shopify {
    fn info(&self) -> PlatformInfo {
        let mut details = Vec::new();
        for (label, key) in [
            ("Shop", "name"),
            ("Plan", "plan_display_name"),
            ("Domain", "domain"),
            ("E-Mail", "email"),
            ("Land", "country_name"),
        ] {
            let v = self.shop_str(key);
            if !v.is_empty() {
                details.push((
                    label.to_string(),
                    if key == "email" { mask_email(&v) } else { v },
                ));
            }
        }
        details.push(("API-Version".into(), self.client.api_version().to_string()));
        PlatformInfo {
            id: PLATFORM_ID.into(),
            name: "Shopify".into(),
            kind: PlatformKind::Hosted,
            version: None,
            root: None,
            target: Some(self.client.shop_domain().to_string()),
            details,
        }
    }

    fn integrity(&self, ctx: &PlatformContext) -> anyhow::Result<IntegrityReport> {
        let mut report = IntegrityReport::default();
        if ctx.skip_remote {
            report
                .limitations
                .push("API-Prüfungen übersprungen (--skip-remote).".into());
            return Ok(report);
        }
        type Step = fn(&Shopify, &PlatformContext, &mut IntegrityReport) -> anyhow::Result<()>;
        let steps: Vec<(&str, Step)> = vec![
            ("Script-Tags", Shopify::script_tags),
            ("Webhooks", Shopify::webhooks),
            ("Apps", Shopify::apps),
            ("Mitarbeiter", Shopify::staff),
            ("Theme", Shopify::theme),
        ];
        for (name, step) in steps {
            if let Err(e) = step(self, ctx, &mut report) {
                report.limitations.push(format!("{name}: {e}"));
            }
        }
        report.items.push(
            IntegrityItem::new("payment.payouts", "Zahlung", "Auszahlungskonto (Shopify Payments)", IntegrityStatus::Unknown, "nicht per API prüfbar")
                .with_detail("Manuell unter Einstellungen › Zahlungen › Shopify Payments › Auszahlungen kontrollieren."),
        );
        Ok(report)
    }

    fn recommendations(&self, _report: &Report) -> Vec<Recommendation> {
        vec![
            Recommendation::new(RecommendationGroupKind::Hardening, 3, "Mitarbeiterzugänge und Apps absichern", "2FA für alle Mitarbeiter erzwingen (Einstellungen › Benutzer), Kollaborator-Zugänge befristen, Custom Apps mit minimalen Scopes anlegen und nicht genutzte Apps deinstallieren – deren Script-Tags und Webhooks verschwinden damit automatisch."),
            Recommendation::new(RecommendationGroupKind::Hardening, 3, "Theme-Änderungen nachvollziehbar halten", "Theme vor Änderungen duplizieren, Änderungen über Git/Shopify CLI deployen und nach jeder Agentur-Änderung erneut scannen. Checkout-Erweiterungen (Checkout Extensibility) statt checkout.liquid verwenden."),
        ]
    }
}
