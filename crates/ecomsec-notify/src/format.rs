//! Message formatting for every channel: plain text, e-mail HTML and the
//! JSON payloads of the chat services.  All functions are pure so the
//! payloads can be unit-tested without network access.

use crate::config::{ChannelKind, HttpTarget};
use crate::{HttpRequest, Notification, NotificationKind};
use ecomsec_core::Severity;
use serde_json::{json, Value};
use std::fmt::Write;

const FOOTER: &str = "ecomsec Security Scan · nur lesend · automatisch erstellt";
const TRUNCATED: &str = "… (gekürzt – vollständige Liste mit `ecomsec diff`)";

fn badge(sev: Option<Severity>) -> &'static str {
    match sev {
        Some(Severity::Critical) => "KRITISCH",
        Some(Severity::Warning) => "WARNUNG",
        Some(Severity::Info) => "INFO",
        None => "",
    }
}

fn emoji(sev: Option<Severity>) -> &'static str {
    match sev {
        Some(Severity::Critical) => "🔴",
        Some(Severity::Warning) => "🟡",
        Some(Severity::Info) => "🔵",
        None => "⚪",
    }
}

/// Colour of the message (hex without `#`).
pub fn color_hex(n: &Notification) -> &'static str {
    match (n.kind, n.level) {
        (NotificationKind::Test, _) => "2563EB",
        (_, Some(Severity::Critical)) => "C81E1E",
        (_, Some(Severity::Warning)) => "B45309",
        (_, Some(Severity::Info)) => "1D4ED8",
        (_, None) => "15803D",
    }
}

fn color_int(n: &Notification) -> u32 {
    u32::from_str_radix(color_hex(n), 16).unwrap_or(0)
}

fn cut(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Collects lines up to a byte budget and marks truncation.
struct Budget {
    out: String,
    max: usize,
    truncated: bool,
}

impl Budget {
    fn new(max: usize) -> Self {
        Budget {
            out: String::new(),
            max: max.saturating_sub(TRUNCATED.len() + 1),
            truncated: false,
        }
    }

    fn push(&mut self, line: &str) {
        if self.truncated {
            return;
        }
        if self.out.len() + line.len() + 1 > self.max {
            self.truncated = true;
            self.out.push_str(TRUNCATED);
            self.out.push('\n');
            return;
        }
        self.out.push_str(line);
        self.out.push('\n');
    }

    fn finish(self) -> String {
        self.out.trim_end().to_string()
    }
}

/// Markdown dialect used by a chat service.
struct Dialect {
    bold: fn(&str) -> String,
    esc: fn(&str) -> String,
    link: fn(&str, &str) -> String,
    code: fn(&str) -> String,
}

const SLACK: Dialect = Dialect {
    bold: |s| format!("*{s}*"),
    esc: |s| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    },
    link: |url, text| format!("<{url}|{text}>"),
    code: |s| format!("`{}`", s.replace('`', "'")),
};

const MARKDOWN: Dialect = Dialect {
    bold: |s| format!("**{s}**"),
    esc: |s| {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            if matches!(
                c,
                '\\' | '*' | '_' | '`' | '~' | '|' | '>' | '[' | ']' | '#' | '@'
            ) {
                out.push('\\');
            }
            out.push(c);
        }
        out
    },
    link: |url, text| format!("[{text}]({url})"),
    code: |s| format!("`{}`", s.replace('`', "'")),
};

const TELEGRAM: Dialect = Dialect {
    bold: |s| format!("<b>{s}</b>"),
    esc: html_escape,
    link: |url, text| format!("<a href=\"{}\">{text}</a>", html_escape(url)),
    code: |s| format!("<code>{}</code>", html_escape(s)),
};

pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Body lines in a markdown dialect: facts (optional), intro text for
/// test/error messages, change sections, dashboard link.
fn markdown_lines(n: &Notification, d: &Dialect, with_facts: bool) -> Vec<String> {
    let mut lines = Vec::new();
    if n.diff.is_none() {
        for l in n.text.lines() {
            lines.push((d.esc)(l));
        }
    } else if with_facts {
        for (k, v) in n.facts() {
            lines.push(format!("{}: {}", (d.bold)(&(d.esc)(&k)), (d.esc)(&v)));
        }
    }
    let sections = n.sections();
    if n.diff.is_some() && sections.is_empty() {
        lines.push(String::new());
        lines.push((d.esc)("Keine Änderungen seit dem letzten Scan."));
    }
    for s in &sections {
        lines.push(String::new());
        lines.push((d.bold)(&(d.esc)(&format!("{} ({})", s.title, s.total))));
        for l in &s.lines {
            let id =
                l.id.as_deref()
                    .map(|i| format!(" {}", (d.code)(&format!("#{i}"))))
                    .unwrap_or_default();
            lines.push(format!(
                "• {} {}{id}",
                if l.severity.is_some() {
                    emoji(l.severity)
                } else {
                    "▫️"
                },
                (d.esc)(&cut(&l.text, 300))
            ));
        }
        if s.total > s.lines.len() {
            lines.push((d.esc)(&format!(
                "… und {} weitere",
                s.total - s.lines.len()
            )));
        }
    }
    if let Some(url) = &n.dashboard_url {
        lines.push(String::new());
        lines.push((d.link)(url, "Dashboard öffnen"));
    }
    lines
}

fn budgeted(lines: &[String], max: usize) -> String {
    let mut b = Budget::new(max);
    for l in lines {
        b.push(l);
    }
    b.finish()
}

// ------------------------------------------------------------------ text

/// Plain-text body (e-mail text part, ntfy, file channel).
pub fn plain_text(n: &Notification) -> String {
    let mut out = n.text.trim_end().to_string();
    if let Some(url) = &n.dashboard_url {
        let _ = write!(out, "\n\nDashboard: {url}");
    }
    let _ = write!(out, "\n\n-- \n{FOOTER}\n");
    out
}

/// HTML e-mail body with inline styles.
pub fn email_html(n: &Notification) -> String {
    let color = color_hex(n);
    let mut h = String::new();
    let _ = write!(
        h,
        "<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\"><title>{title}</title></head>\
         <body style=\"margin:0;padding:24px;background:#f5f6f8;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1b1f24;font-size:14px;line-height:1.5\">\
         <div style=\"max-width:720px;margin:0 auto;background:#ffffff;border:1px solid #dde1e6;border-radius:10px;overflow:hidden\">\
         <div style=\"background:#{color};color:#ffffff;padding:16px 20px;font-size:18px;font-weight:600\">{title}</div>\
         <div style=\"padding:16px 20px\">",
        title = html_escape(&n.title)
    );
    if n.diff.is_none() {
        for p in n.text.split("\n\n") {
            let _ = write!(
                h,
                "<p style=\"margin:0 0 12px\">{}</p>",
                html_escape(p).replace('\n', "<br>")
            );
        }
    } else {
        h.push_str("<table style=\"border-collapse:collapse;width:100%;margin-bottom:8px\">");
        for (k, v) in n.facts() {
            let _ = write!(
                h,
                "<tr><td style=\"padding:4px 12px 4px 0;color:#5b6470;white-space:nowrap;vertical-align:top\">{}</td><td style=\"padding:4px 0\">{}</td></tr>",
                html_escape(&k),
                html_escape(&v)
            );
        }
        h.push_str("</table>");
        let sections = n.sections();
        if sections.is_empty() {
            h.push_str("<p>Keine Änderungen seit dem letzten Scan.</p>");
        }
        for s in &sections {
            let _ = write!(
                h,
                "<h3 style=\"font-size:15px;margin:18px 0 6px\">{} ({})</h3><ul style=\"padding-left:18px;margin:0\">",
                html_escape(&s.title),
                s.total
            );
            for l in &s.lines {
                let (fg, bg) = match l.severity {
                    Some(Severity::Critical) => ("#c81e1e", "#fde8e8"),
                    Some(Severity::Warning) => ("#b45309", "#fdf3e1"),
                    Some(Severity::Info) => ("#1d4ed8", "#e5edff"),
                    None => ("#5b6470", "#eef1f5"),
                };
                h.push_str("<li style=\"margin:4px 0\">");
                if l.severity.is_some() {
                    let _ = write!(
                        h,
                        "<span style=\"display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;font-weight:700;color:{fg};background:{bg}\">{}</span> ",
                        badge(l.severity)
                    );
                }
                h.push_str(&html_escape(&l.text));
                if let Some(id) = &l.id {
                    let _ = write!(
                        h,
                        " <span style=\"color:#5b6470;font-size:11px\">#{}</span>",
                        html_escape(id)
                    );
                }
                if let Some(d) = &l.detail {
                    let _ = write!(
                        h,
                        "<br><code style=\"font-size:12px;background:#eef1f5;padding:1px 4px;border-radius:3px;word-break:break-all\">{}</code>",
                        html_escape(&cut(d, 200))
                    );
                }
                h.push_str("</li>");
            }
            if s.total > s.lines.len() {
                let _ = write!(
                    h,
                    "<li style=\"color:#5b6470\">… und {} weitere</li>",
                    s.total - s.lines.len()
                );
            }
            h.push_str("</ul>");
        }
        if let Some(d) = &n.diff {
            let minor = d.minor_integrity_changes();
            if minor > 0 {
                let _ = write!(
                    h,
                    "<p style=\"color:#5b6470;font-size:12px\">{minor} weitere Integritätswerte ohne Statusänderung aktualisiert (z. B. letzter Login).</p>"
                );
            }
        }
    }
    if let Some(url) = &n.dashboard_url {
        let _ = write!(
            h,
            "<p style=\"margin-top:18px\"><a href=\"{}\" style=\"background:#2563eb;color:#ffffff;padding:8px 14px;border-radius:6px;text-decoration:none;font-weight:600\">Dashboard öffnen</a></p>",
            html_escape(url)
        );
    }
    let _ = write!(
        h,
        "</div><div style=\"padding:12px 20px;border-top:1px solid #dde1e6;color:#5b6470;font-size:12px\">{FOOTER}</div></div></body></html>"
    );
    h
}

// ------------------------------------------------------------------ JSON payloads

fn event(n: &Notification) -> &'static str {
    match n.kind {
        NotificationKind::Changes => "ecomsec.changes",
        NotificationKind::Test => "ecomsec.test",
        NotificationKind::Error => "ecomsec.error",
    }
}

/// Generic webhook: summary plus the complete diff.
pub fn webhook(n: &Notification) -> Value {
    json!({
        "event": event(n),
        "title": n.title,
        "level": n.level,
        "target": n.target,
        "created_at": n.created_at,
        "summary": n.text,
        "dashboard_url": n.dashboard_url,
        "diff": n.diff,
    })
}

/// Slack incoming webhook (Block Kit).
pub fn slack(n: &Notification, channel: Option<&str>, username: Option<&str>) -> Value {
    let mut blocks = vec![json!({
        "type": "header",
        "text": {"type": "plain_text", "text": cut(&format!("{} {}", emoji(n.level), n.title), 150), "emoji": true}
    })];
    if n.diff.is_some() {
        let fields: Vec<Value> = n
            .facts()
            .into_iter()
            .take(10)
            .map(|(k, v)| {
                json!({"type": "mrkdwn", "text": cut(&format!("*{}*\n{}", (SLACK.esc)(&k), (SLACK.esc)(&v)), 1900)})
            })
            .collect();
        blocks.push(json!({"type": "section", "fields": fields}));
        let sections = n.sections();
        if sections.is_empty() {
            blocks.push(json!({"type": "section", "text": {"type": "mrkdwn", "text": "Keine Änderungen seit dem letzten Scan."}}));
        }
        for s in sections.iter().take(10) {
            let mut lines = vec![(SLACK.bold)(&(SLACK.esc)(&format!(
                "{} ({})",
                s.title, s.total
            )))];
            for l in &s.lines {
                lines.push(format!(
                    "• {} {}",
                    emoji(l.severity),
                    (SLACK.esc)(&cut(&l.text, 300))
                ));
            }
            if s.total > s.lines.len() {
                lines.push(format!("… und {} weitere", s.total - s.lines.len()));
            }
            blocks.push(json!({"type": "section", "text": {"type": "mrkdwn", "text": budgeted(&lines, 2900)}}));
        }
    } else {
        blocks.push(json!({"type": "section", "text": {"type": "mrkdwn", "text": budgeted(&n.text.lines().map(|l| (SLACK.esc)(l)).collect::<Vec<_>>(), 2900)}}));
    }
    if let Some(url) = &n.dashboard_url {
        blocks.push(json!({"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text", "text": "Dashboard öffnen"}, "url": url}]}));
    }
    blocks.push(json!({"type": "context", "elements": [{"type": "mrkdwn", "text": format!("{FOOTER} · {}", n.created_at.format("%d.%m.%Y %H:%M UTC"))}]}));
    let mut v = json!({"text": n.title, "blocks": blocks});
    if let Some(c) = channel {
        v["channel"] = json!(c);
    }
    if let Some(u) = username {
        v["username"] = json!(u);
    }
    v
}

fn adaptive_color(n: &Notification) -> &'static str {
    match (n.kind, n.level) {
        (NotificationKind::Test, _) => "Accent",
        (_, Some(Severity::Critical)) => "Attention",
        (_, Some(Severity::Warning)) => "Warning",
        (_, Some(Severity::Info)) => "Accent",
        (_, None) => "Good",
    }
}

/// Microsoft Teams via Workflows / Power Automate: Adaptive Card 1.4.
pub fn teams(n: &Notification) -> Value {
    let mut body = vec![json!({
        "type": "TextBlock", "size": "Large", "weight": "Bolder", "wrap": true,
        "color": adaptive_color(n), "text": n.title
    })];
    if n.diff.is_some() {
        body.push(json!({
            "type": "FactSet",
            "facts": n.facts().into_iter().map(|(k, v)| json!({"title": k, "value": v})).collect::<Vec<_>>()
        }));
        let sections = n.sections();
        if sections.is_empty() {
            body.push(json!({"type": "TextBlock", "wrap": true, "text": "Keine Änderungen seit dem letzten Scan."}));
        }
        for s in &sections {
            body.push(
                json!({"type": "TextBlock", "weight": "Bolder", "spacing": "Medium", "wrap": true,
                "text": format!("{} ({})", s.title, s.total)}),
            );
            let mut items: Vec<String> = s
                .lines
                .iter()
                .map(|l| {
                    let b = badge(l.severity);
                    if b.is_empty() {
                        format!("- {}", cut(&l.text, 300))
                    } else {
                        format!("- **{b}** {}", cut(&l.text, 300))
                    }
                })
                .collect();
            if s.total > s.lines.len() {
                items.push(format!("- … und {} weitere", s.total - s.lines.len()));
            }
            body.push(json!({"type": "TextBlock", "wrap": true, "spacing": "Small", "text": items.join("\n")}));
        }
    } else {
        body.push(json!({"type": "TextBlock", "wrap": true, "text": n.text}));
    }
    body.push(json!({"type": "TextBlock", "isSubtle": true, "size": "Small", "wrap": true, "text": FOOTER}));
    let mut card = json!({
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "msteams": {"width": "Full"},
        "body": body,
    });
    if let Some(url) = &n.dashboard_url {
        card["actions"] =
            json!([{"type": "Action.OpenUrl", "title": "Dashboard öffnen", "url": url}]);
    }
    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": null,
            "content": card
        }]
    })
}

/// Microsoft Teams Office 365 connector (legacy MessageCard).
pub fn teams_legacy(n: &Notification) -> Value {
    let mut section = json!({
        "facts": n.facts().into_iter().map(|(k, v)| json!({"name": k, "value": v})).collect::<Vec<_>>(),
        "text": budgeted(&markdown_lines(n, &MARKDOWN, false), 18_000),
        "markdown": true,
    });
    if n.diff.is_none() {
        section["facts"] = json!([]);
    }
    let mut v = json!({
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": n.title,
        "themeColor": color_hex(n),
        "title": n.title,
        "sections": [section],
    });
    if let Some(url) = &n.dashboard_url {
        v["potentialAction"] = json!([{
            "@type": "OpenUri", "name": "Dashboard öffnen",
            "targets": [{"os": "default", "uri": url}]
        }]);
    }
    v
}

/// Discord webhook with one embed.
pub fn discord(n: &Notification, username: Option<&str>) -> Value {
    let fields: Vec<Value> = if n.diff.is_some() {
        n.facts()
            .into_iter()
            .take(25)
            .map(|(k, v)| json!({"name": cut(&k, 256), "value": cut(&v, 1024), "inline": false}))
            .collect()
    } else {
        Vec::new()
    };
    let lines = markdown_lines(n, &MARKDOWN, false);
    let mut embed = json!({
        "title": cut(&n.title, 256),
        "description": budgeted(&lines, 3500),
        "color": color_int(n),
        "fields": fields,
        "timestamp": n.created_at.to_rfc3339(),
        "footer": {"text": FOOTER},
    });
    if let Some(url) = &n.dashboard_url {
        embed["url"] = json!(url);
    }
    json!({
        "username": username.unwrap_or("ecomsec"),
        "embeds": [embed],
        // Never ping anyone, whatever ends up in file names.
        "allowed_mentions": {"parse": []},
    })
}

/// Mattermost incoming webhook (markdown text).
pub fn mattermost(n: &Notification, channel: Option<&str>, username: Option<&str>) -> Value {
    let mut lines = vec![format!(
        "#### {} {}",
        emoji(n.level),
        (MARKDOWN.esc)(&n.title)
    )];
    lines.extend(markdown_lines(n, &MARKDOWN, true));
    let mut v = json!({
        "text": budgeted(&lines, 15_000),
        "username": username.unwrap_or("ecomsec"),
    });
    if let Some(c) = channel {
        v["channel"] = json!(c);
    }
    v
}

/// ntfy JSON publish (posted to the server root).
pub fn ntfy(n: &Notification, topic: &str) -> Value {
    let (priority, tags) = match (n.kind, n.level) {
        (NotificationKind::Test, _) => (3, vec!["white_check_mark"]),
        (NotificationKind::Error, _) => (4, vec!["warning"]),
        (_, Some(Severity::Critical)) => (5, vec!["rotating_light"]),
        (_, Some(Severity::Warning)) => (4, vec!["warning"]),
        (_, Some(Severity::Info)) => (3, vec!["information_source"]),
        (_, None) => (2, vec!["white_check_mark"]),
    };
    let lines: Vec<String> = n.text.lines().map(str::to_string).collect();
    let mut v = json!({
        "topic": topic,
        "title": cut(&n.title, 250),
        "message": budgeted(&lines, 3900),
        "priority": priority,
        "tags": tags,
    });
    if let Some(url) = &n.dashboard_url {
        v["click"] = json!(url);
    }
    v
}

/// Telegram Bot API `sendMessage` (HTML parse mode).
pub fn telegram(n: &Notification, chat_id: &str) -> Value {
    let mut lines = vec![
        format!("{} <b>{}</b>", emoji(n.level), html_escape(&n.title)),
        String::new(),
    ];
    lines.extend(markdown_lines(n, &TELEGRAM, true));
    json!({
        "chat_id": chat_id,
        "text": budgeted(&lines, 3900),
        "parse_mode": "HTML",
        "disable_web_page_preview": true,
    })
}

pub(crate) fn http_request(kind: ChannelKind, h: &HttpTarget, n: &Notification) -> HttpRequest {
    let mut headers = h.headers.clone();
    let body = match kind {
        ChannelKind::Slack => slack(n, h.channel.as_deref(), h.username.as_deref()),
        ChannelKind::Teams => teams(n),
        ChannelKind::TeamsLegacy => teams_legacy(n),
        ChannelKind::Discord => discord(n, h.username.as_deref()),
        ChannelKind::Mattermost => mattermost(n, h.channel.as_deref(), h.username.as_deref()),
        ChannelKind::Ntfy => {
            if let Some(t) = &h.token {
                headers.push(("Authorization".into(), format!("Bearer {t}")));
            }
            ntfy(n, h.topic.as_deref().unwrap_or("ecomsec"))
        }
        ChannelKind::Telegram => telegram(n, h.chat_id.as_deref().unwrap_or_default()),
        _ => webhook(n),
    };
    HttpRequest {
        url: h.url.clone(),
        headers,
        body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Channel, ChannelConfig, MessageOptions};
    use chrono::{NaiveDate, Utc};
    use ecomsec_core::finding::{Category, Finding, Source};
    use ecomsec_core::platform::{PlatformInfo, PlatformKind};
    use ecomsec_core::{Report, ReportDiff};

    fn report(findings: Vec<Finding>) -> Report {
        let (verdict, summary) = Report::compute_summary(&findings);
        Report {
            schema_version: 1,
            generated_at: Utc::now(),
            platform: PlatformInfo {
                id: "jtl5".into(),
                name: "JTL-Shop 5".into(),
                kind: PlatformKind::SelfHosted,
                version: None,
                root: Some("/var/www/shop".into()),
                target: None,
                details: vec![],
            },
            reference_date: NaiveDate::from_ymd_opt(2026, 6, 17).unwrap(),
            verdict,
            summary,
            findings,
            integrity: vec![],
            advisories: vec![],
            recommendations: vec![],
            limitations: vec![],
            score: None,
            grade: None,
            score_drivers: Vec::new(),
        }
    }

    fn sample() -> Notification {
        let before = report(vec![]);
        let after = report(vec![
            Finding::new(
                Severity::Critical,
                Category::KnownWebshell,
                Source::FileSystem,
                "ioc_filename",
                "mediafiles/Bilder/wso_<x>&@everyone.php",
                "Bekannte Webshell",
            )
            .with_evidence("eval(base64_decode('…'))"),
            Finding::new(
                Severity::Warning,
                Category::ExposedFile,
                Source::FileSystem,
                "exposed_file",
                "backup.sql",
                "Öffentlich erreichbarer Dump",
            ),
        ]);
        let diff = ReportDiff::compute(Some(&before), &after);
        Notification::from_diff(
            &diff,
            &MessageOptions {
                subject_prefix: None,
                dashboard_url: Some("https://shop.example/ecomsec".into()),
            },
        )
    }

    fn channel(toml_text: &str) -> Channel {
        let c: ChannelConfig = toml::from_str(toml_text).unwrap();
        c.resolve(0, &|_| None).unwrap()
    }

    #[test]
    fn plain_text_and_html() {
        let n = sample();
        assert_eq!(n.level, Some(Severity::Critical));
        assert!(n.title.starts_with("[ecomsec] 1 neuer kritischer Befund"));
        let t = plain_text(&n);
        assert!(t.contains("Neue Befunde (2)"));
        assert!(t.contains("Dashboard: https://shop.example/ecomsec"));
        let h = email_html(&n);
        assert!(h.contains("wso_&lt;x&gt;&amp;@everyone.php"));
        assert!(!h.contains("wso_<x>"));
        assert!(h.contains("#C81E1E"));
        assert!(h.contains("KRITISCH"));
    }

    #[test]
    fn slack_block_kit() {
        let v = slack(&sample(), Some("#shop"), None);
        assert_eq!(v["channel"], "#shop");
        let blocks = v["blocks"].as_array().unwrap();
        assert_eq!(blocks[0]["type"], "header");
        assert!(blocks[0]["text"]["text"].as_str().unwrap().len() <= 150 * 4);
        let all = v.to_string();
        assert!(all.contains("wso_&lt;x&gt;&amp;@everyone.php"));
        assert!(all.contains("Dashboard öffnen"));
        assert!(blocks.iter().all(|b| b["text"]["text"]
            .as_str()
            .map(|t| t.len() <= 3000)
            .unwrap_or(true)));
    }

    #[test]
    fn teams_adaptive_and_legacy() {
        let v = teams(&sample());
        assert_eq!(v["type"], "message");
        let card = &v["attachments"][0]["content"];
        assert_eq!(card["type"], "AdaptiveCard");
        assert_eq!(card["body"][0]["color"], "Attention");
        assert_eq!(card["actions"][0]["type"], "Action.OpenUrl");
        let legacy = teams_legacy(&sample());
        assert_eq!(legacy["@type"], "MessageCard");
        assert_eq!(legacy["themeColor"], "C81E1E");
        assert!(legacy["sections"][0]["facts"].as_array().unwrap().len() >= 3);
    }

    #[test]
    fn discord_never_pings_and_respects_limits() {
        let v = discord(&sample(), None);
        assert_eq!(v["allowed_mentions"]["parse"], json!([]));
        let embed = &v["embeds"][0];
        assert_eq!(embed["color"], 0xC81E1E);
        let desc = embed["description"].as_str().unwrap();
        assert!(desc.contains("\\@everyone"));
        assert!(desc.chars().count() <= 4096);
    }

    #[test]
    fn mattermost_ntfy_telegram() {
        let n = sample();
        let m = mattermost(&n, None, Some("Shop-Bot"));
        assert!(m["text"].as_str().unwrap().starts_with("#### 🔴"));
        assert_eq!(m["username"], "Shop-Bot");
        let t = ntfy(&n, "mein-topic");
        assert_eq!(t["priority"], 5);
        assert_eq!(t["topic"], "mein-topic");
        assert_eq!(t["click"], "https://shop.example/ecomsec");
        let tg = telegram(&n, "-100");
        assert_eq!(tg["parse_mode"], "HTML");
        let text = tg["text"].as_str().unwrap();
        assert!(text.contains("<b>"));
        assert!(text.contains("wso_&lt;x&gt;"));
        assert!(text.chars().count() <= 4096);
    }

    #[test]
    fn long_messages_are_truncated_at_line_boundaries() {
        let before = report(vec![]);
        let after = report(
            (0..400)
                .map(|i| {
                    Finding::new(
                        Severity::Warning,
                        Category::ModifiedSinceReference,
                        Source::FileSystem,
                        format!("r{i}"),
                        format!("includes/{}/file{i}.php", "x".repeat(150)),
                        "Neue/geänderte Datei",
                    )
                })
                .collect(),
        );
        let n = Notification::from_diff(
            &ReportDiff::compute(Some(&before), &after),
            &Default::default(),
        );
        let tg = telegram(&n, "1");
        let text = tg["text"].as_str().unwrap();
        assert!(text.len() <= 3900, "{}", text.len());
        assert!(text.contains("gekürzt"));
        // Tags are balanced (no line was cut in half).
        assert_eq!(text.matches("<b>").count(), text.matches("</b>").count());
        let d = discord(&n, None);
        assert!(d["embeds"][0]["description"].as_str().unwrap().len() <= 3500);
    }

    #[test]
    fn http_requests_per_kind() {
        let n = sample();
        let tg = channel("kind = \"telegram\"\ntoken = \"123:ABC\"\nchat_id = \"42\"\n");
        let req = crate::http_request(&tg, &n).unwrap();
        assert_eq!(req.url, "https://api.telegram.org/bot123:ABC/sendMessage");
        assert_eq!(req.body["chat_id"], "42");

        let nt = channel("kind = \"ntfy\"\ntopic = \"t\"\ntoken = \"tk_secret\"\n");
        let req = crate::http_request(&nt, &n).unwrap();
        assert_eq!(req.url, "https://ntfy.sh");
        assert!(req
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer tk_secret"));

        let wh = channel(
            "kind = \"webhook\"\nurl = \"https://example.org/hook\"\nheaders = { \"X-Api-Key\" = \"k\" }\n",
        );
        let req = crate::http_request(&wh, &n).unwrap();
        assert_eq!(req.body["event"], "ecomsec.changes");
        assert_eq!(
            req.body["diff"]["new_findings"].as_array().unwrap().len(),
            2
        );
        assert_eq!(req.headers[0].0, "X-Api-Key");

        let file = channel("kind = \"stdout\"\n");
        assert!(crate::http_request(&file, &n).is_none());
    }

    #[test]
    fn test_and_error_messages() {
        let opts = MessageOptions {
            subject_prefix: Some("[Mein Shop]".into()),
            dashboard_url: None,
        };
        let t = Notification::test("jtl5 @ /srv", &opts);
        assert_eq!(t.title, "[Mein Shop] Testnachricht");
        assert_eq!(webhook(&t)["event"], "ecomsec.test");
        assert!(slack(&t, None, None).to_string().contains("Testnachricht"));
        let e = Notification::error("jtl5 @ /srv", "Verzeichnis fehlt", &opts);
        assert!(email_html(&e).contains("Verzeichnis fehlt"));
        assert_eq!(ntfy(&e, "x")["priority"], 4);
    }
}
