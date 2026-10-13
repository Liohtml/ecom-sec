//! # ecomsec-notify
//!
//! Delivers ecomsec change reports ([`ReportDiff`]) to the shop owner:
//! e-mail via SMTP, generic JSON webhooks, ready-made payloads for Slack,
//! Microsoft Teams, Discord, Mattermost, ntfy and Telegram, and a file /
//! stdout channel for custom integrations.
//!
//! Network access happens only for channels the user configured.  Secrets
//! come from environment variables (`*_env` keys) or the configuration file
//! and are redacted from every error message.

mod config;
mod email;
pub mod format;

pub use config::{
    Channel, ChannelConfig, ChannelKind, EnvLookup, FileFormat, NotifyConfig, NotifyOn, Secret,
};
pub use email::SmtpSecurity;

use chrono::{DateTime, Utc};
use config::Target;
use ecomsec_core::diff::DiffSection;
use ecomsec_core::{ReportDiff, Severity};
use serde::Serialize;
use std::io::Write;
use std::path::Path;

const USER_AGENT: &str = concat!("ecomsec/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, thiserror::Error)]
pub enum NotifyError {
    #[error("Konfiguration: {0}")]
    Config(String),
    #[error("HTTP: {0}")]
    Http(String),
    #[error("E-Mail: {0}")]
    Email(String),
    #[error("Datei: {0}")]
    Io(String),
}

/// What a notification is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    /// Result of a monitoring run.
    Changes,
    /// `ecomsec notify test`.
    Test,
    /// The monitoring run itself failed.
    Error,
}

/// Settings shared by all messages.
#[derive(Debug, Clone, Default)]
pub struct MessageOptions {
    /// Prefix of subjects/titles; `None` → `[ecomsec]`.
    pub subject_prefix: Option<String>,
    pub dashboard_url: Option<String>,
}

impl MessageOptions {
    fn prefix(&self) -> String {
        self.subject_prefix
            .clone()
            .unwrap_or_else(|| "[ecomsec]".into())
    }

    fn title(&self, text: &str) -> String {
        let p = self.prefix();
        if p.is_empty() {
            text.to_string()
        } else {
            format!("{p} {text}")
        }
    }
}

/// A rendered-independent message; every channel formats it its own way.
#[derive(Debug, Clone, Serialize)]
pub struct Notification {
    pub kind: NotificationKind,
    /// Subject / headline including the prefix.
    pub title: String,
    /// Highest relevance (drives colours and priorities).
    pub level: Option<Severity>,
    /// Plain-text body (German).
    pub text: String,
    /// Shop / target description.
    pub target: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<ReportDiff>,
}

impl Notification {
    pub fn from_diff(diff: &ReportDiff, opts: &MessageOptions) -> Self {
        Notification {
            kind: NotificationKind::Changes,
            title: opts.title(&diff.headline()),
            level: diff.relevance,
            text: diff.to_text(),
            target: format!("{} ({})", diff.platform_name, diff.target),
            created_at: Utc::now(),
            dashboard_url: opts.dashboard_url.clone(),
            diff: Some(diff.clone()),
        }
    }

    pub fn test(target: &str, opts: &MessageOptions) -> Self {
        Notification {
            kind: NotificationKind::Test,
            title: opts.title("Testnachricht"),
            level: None,
            text: format!(
                "Dies ist eine Testnachricht von ecomsec.\n\
                 Wenn Sie diese Nachricht lesen, ist der Benachrichtigungskanal richtig eingerichtet.\n\
                 Künftig melden wir uns nur, wenn sich am Prüfergebnis etwas ändert.\n\n\
                 Shop: {target}"
            ),
            target: target.to_string(),
            created_at: Utc::now(),
            dashboard_url: opts.dashboard_url.clone(),
            diff: None,
        }
    }

    pub fn error(target: &str, message: &str, opts: &MessageOptions) -> Self {
        Notification {
            kind: NotificationKind::Error,
            title: opts.title(&format!("Prüfung fehlgeschlagen – {target}")),
            level: Some(Severity::Warning),
            text: format!(
                "Der automatische Sicherheits-Scan konnte nicht ausgeführt werden.\n\n\
                 Shop: {target}\nFehler: {message}\n\n\
                 Bitte Konfiguration und Erreichbarkeit prüfen (z. B. `ecomsec watch` von Hand starten)."
            ),
            target: target.to_string(),
            created_at: Utc::now(),
            dashboard_url: opts.dashboard_url.clone(),
            diff: None,
        }
    }

    /// Key facts (label, value).
    pub fn facts(&self) -> Vec<(String, String)> {
        match &self.diff {
            Some(d) => d.facts(),
            None => vec![("Shop".into(), self.target.clone())],
        }
    }

    /// Change sections (empty for test/error messages).
    pub fn sections(&self) -> Vec<DiffSection> {
        self.diff.as_ref().map(|d| d.sections()).unwrap_or_default()
    }
}

/// Outcome of sending to one channel.
#[derive(Debug)]
pub struct Delivery {
    pub channel: String,
    pub kind: Option<ChannelKind>,
    pub result: Result<(), NotifyError>,
}

/// All configured channels plus message settings.
pub struct Notifier {
    pub channels: Vec<Channel>,
    /// Channels that could not be resolved (missing keys or env vars).
    pub invalid: Vec<(String, NotifyError)>,
    pub default_on: NotifyOn,
    pub options: MessageOptions,
}

impl Notifier {
    /// Resolve the configuration with the process environment.
    pub fn from_config(cfg: &NotifyConfig) -> Self {
        Self::from_config_with_env(cfg, &|k| std::env::var(k).ok())
    }

    pub fn from_config_with_env(cfg: &NotifyConfig, env: EnvLookup<'_>) -> Self {
        let mut channels = Vec::new();
        let mut invalid = Vec::new();
        for (i, c) in cfg.channels.iter().enumerate() {
            if !c.is_enabled() {
                continue;
            }
            match c.resolve(i, env) {
                Ok(ch) => channels.push(ch),
                Err(e) => invalid.push((c.display_name(i), e)),
            }
        }
        Notifier {
            channels,
            invalid,
            default_on: cfg.on.unwrap_or(NotifyOn::DEFAULT),
            options: MessageOptions {
                subject_prefix: cfg.subject_prefix.clone(),
                dashboard_url: cfg.dashboard_url.clone(),
            },
        }
    }

    pub fn is_empty(&self) -> bool {
        self.channels.is_empty() && self.invalid.is_empty()
    }

    /// Threshold of a channel: `override_on` (command line) wins, then the
    /// channel's own `on`, then `[notify] on`.
    pub fn threshold(&self, channel: &Channel, override_on: Option<NotifyOn>) -> NotifyOn {
        override_on.or(channel.on).unwrap_or(self.default_on)
    }

    /// Channels that want to hear about `diff`.
    pub fn recipients(&self, diff: &ReportDiff, override_on: Option<NotifyOn>) -> Vec<&Channel> {
        self.channels
            .iter()
            .filter(|c| self.threshold(c, override_on).matches(diff))
            .collect()
    }

    /// Notify every channel whose threshold matches.  Channels with a broken
    /// configuration are reported as failed deliveries whenever the default
    /// threshold matches.
    pub fn notify_diff(&self, diff: &ReportDiff, override_on: Option<NotifyOn>) -> Vec<Delivery> {
        let n = Notification::from_diff(diff, &self.options);
        let mut out: Vec<Delivery> = self
            .recipients(diff, override_on)
            .into_iter()
            .map(|c| deliver(c, &n))
            .collect();
        if override_on.unwrap_or(self.default_on).matches(diff) {
            out.extend(self.invalid_deliveries());
        }
        out
    }

    /// Send `n` to every channel regardless of thresholds (test, errors).
    pub fn send_all(&self, n: &Notification) -> Vec<Delivery> {
        let mut out: Vec<Delivery> = self.channels.iter().map(|c| deliver(c, n)).collect();
        out.extend(self.invalid_deliveries());
        out
    }

    fn invalid_deliveries(&self) -> Vec<Delivery> {
        self.invalid
            .iter()
            .map(|(name, e)| Delivery {
                channel: name.clone(),
                kind: None,
                result: Err(e.clone()),
            })
            .collect()
    }
}

fn deliver(channel: &Channel, n: &Notification) -> Delivery {
    let result = send(channel, n);
    if let Err(e) = &result {
        log::info!("notification via {} failed: {e}", channel.name);
    }
    Delivery {
        channel: channel.name.clone(),
        kind: Some(channel.kind),
        result,
    }
}

/// A prepared HTTP POST with JSON body.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: serde_json::Value,
}

/// The HTTP request a channel would send (`None` for e-mail/file).
pub fn http_request(channel: &Channel, n: &Notification) -> Option<HttpRequest> {
    match &channel.target {
        Target::Http(h) => Some(format::http_request(channel.kind, h, n)),
        _ => None,
    }
}

/// Send one notification through one channel.
pub fn send(channel: &Channel, n: &Notification) -> Result<(), NotifyError> {
    match &channel.target {
        Target::Http(_) => {
            let req = http_request(channel, n).expect("http target");
            post_json(channel, &req)
        }
        Target::Email(e) => email::send(e, n, channel.timeout)
            .map_err(|err| redact_error(err, |m| channel.redact(m))),
        Target::File { path, format } => write_file(path.as_deref(), *format, n),
    }
}

fn redact_error(e: NotifyError, f: impl Fn(&str) -> String) -> NotifyError {
    match e {
        NotifyError::Config(m) => NotifyError::Config(f(&m)),
        NotifyError::Http(m) => NotifyError::Http(f(&m)),
        NotifyError::Email(m) => NotifyError::Email(f(&m)),
        NotifyError::Io(m) => NotifyError::Io(f(&m)),
    }
}

fn post_json(channel: &Channel, req: &HttpRequest) -> Result<(), NotifyError> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(channel.timeout))
        .http_status_as_error(false)
        .build()
        .into();
    let mut builder = agent.post(&req.url).header("User-Agent", USER_AGENT);
    for (k, v) in &req.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let mut resp = builder
        .send_json(&req.body)
        .map_err(|e| NotifyError::Http(channel.redact(&e.to_string())))?;
    let status = resp.status().as_u16();
    if (200..300).contains(&status) {
        return Ok(());
    }
    let body = resp.body_mut().read_to_string().unwrap_or_default();
    let body: String = body.chars().take(300).collect();
    Err(NotifyError::Http(
        channel.redact(&format!("HTTP {status}: {}", body.trim())),
    ))
}

fn write_file(
    path: Option<&Path>,
    format: FileFormat,
    n: &Notification,
) -> Result<(), NotifyError> {
    let content = match format {
        FileFormat::Text => format!(
            "===== {} · {} =====\n{}\n",
            n.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
            n.title,
            format::plain_text(n).trim_end()
        ),
        FileFormat::Json => {
            let mut line = serde_json::to_string(&format::webhook(n))
                .map_err(|e| NotifyError::Io(e.to_string()))?;
            line.push('\n');
            line
        }
    };
    match path {
        Some(p) => {
            if let Some(parent) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)
                    .map_err(|e| NotifyError::Io(format!("{}: {e}", parent.display())))?;
            }
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .map_err(|e| NotifyError::Io(format!("{}: {e}", p.display())))?;
            f.write_all(content.as_bytes())
                .map_err(|e| NotifyError::Io(format!("{}: {e}", p.display())))
        }
        None => {
            let mut out = std::io::stdout().lock();
            out.write_all(content.as_bytes())
                .and_then(|_| out.flush())
                .map_err(|e| NotifyError::Io(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notifier(toml_text: &str) -> Notifier {
        #[derive(serde::Deserialize)]
        struct W {
            notify: NotifyConfig,
        }
        let cfg = toml::from_str::<W>(toml_text).unwrap().notify;
        Notifier::from_config_with_env(&cfg, &|k| {
            (k == "HOOK").then(|| "https://example.org/hook/abcdef".to_string())
        })
    }

    #[test]
    fn file_channel_appends_text_and_json() {
        let tmp = tempfile::tempdir().unwrap();
        let text_path = tmp.path().join("log/changes.log");
        let json_path = tmp.path().join("changes.jsonl");
        let n = notifier(&format!(
            "[notify]\n[[notify.channel]]\nkind = \"file\"\npath = {:?}\n[[notify.channel]]\nkind = \"file\"\npath = {:?}\nformat = \"json\"\n",
            text_path.display().to_string(),
            json_path.display().to_string()
        ));
        assert_eq!(n.channels.len(), 2);
        let msg = Notification::test("jtl5 @ /srv/shop", &n.options);
        for _ in 0..2 {
            for d in n.send_all(&msg) {
                d.result.unwrap();
            }
        }
        let text = std::fs::read_to_string(&text_path).unwrap();
        assert_eq!(text.matches("[ecomsec] Testnachricht").count(), 2);
        let json = std::fs::read_to_string(&json_path).unwrap();
        let lines: Vec<serde_json::Value> = json
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["event"], "ecomsec.test");
    }

    #[test]
    fn invalid_channels_are_reported_but_do_not_block_others() {
        let n = notifier(
            "[notify]\n[[notify.channel]]\nkind = \"slack\"\nurl_env = \"MISSING\"\n[[notify.channel]]\nkind = \"webhook\"\nurl_env = \"HOOK\"\n[[notify.channel]]\nkind = \"discord\"\nenabled = false\n",
        );
        assert_eq!(n.channels.len(), 1);
        assert_eq!(n.invalid.len(), 1);
        assert!(n.invalid[0].1.to_string().contains("MISSING"));
    }
}
