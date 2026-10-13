//! `[notify]` / `[[notify.channel]]` configuration and its resolution into
//! ready-to-use channels.  Secrets are preferably referenced through
//! `*_env` keys naming environment variables; resolved secrets never appear
//! in `Debug` output or error messages.

use crate::email::{EmailTarget, SmtpSecurity};
use crate::NotifyError;
use ecomsec_core::{ReportDiff, Severity};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

/// When a notification is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotifyOn {
    /// Only new critical findings / newly vulnerable critical advisories /
    /// critical integrity changes.
    Critical,
    /// New warnings or worse.
    Warning,
    /// Any change (including resolved findings and info).
    Any,
    /// Every run, even without changes.
    Always,
}

impl NotifyOn {
    pub const DEFAULT: NotifyOn = NotifyOn::Warning;

    /// Should a run with this diff be reported?
    pub fn matches(self, diff: &ReportDiff) -> bool {
        match self {
            NotifyOn::Always => true,
            NotifyOn::Any => diff.has_changes(),
            NotifyOn::Warning => diff.relevance.is_some_and(|s| s >= Severity::Warning),
            NotifyOn::Critical => diff.relevance == Some(Severity::Critical),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NotifyOn::Critical => "critical",
            NotifyOn::Warning => "warning",
            NotifyOn::Any => "any",
            NotifyOn::Always => "always",
        }
    }
}

impl FromStr for NotifyOn {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Ok(NotifyOn::Critical),
            "warning" => Ok(NotifyOn::Warning),
            "any" => Ok(NotifyOn::Any),
            "always" => Ok(NotifyOn::Always),
            other => Err(format!(
                "unbekannter Wert {other:?} (critical, warning, any, always)"
            )),
        }
    }
}

/// Channel type, selected with `kind = "…"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChannelKind {
    Email,
    /// Generic JSON POST with summary and full diff.
    Webhook,
    Slack,
    /// Microsoft Teams (Workflows / Power Automate): Adaptive Card.
    Teams,
    /// Microsoft Teams Office 365 connector: legacy MessageCard.
    #[serde(alias = "teams_legacy", alias = "messagecard")]
    TeamsLegacy,
    Discord,
    Mattermost,
    Ntfy,
    Telegram,
    /// Append to a file.
    File,
    /// Print to standard output.
    Stdout,
}

impl ChannelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChannelKind::Email => "email",
            ChannelKind::Webhook => "webhook",
            ChannelKind::Slack => "slack",
            ChannelKind::Teams => "teams",
            ChannelKind::TeamsLegacy => "teams-legacy",
            ChannelKind::Discord => "discord",
            ChannelKind::Mattermost => "mattermost",
            ChannelKind::Ntfy => "ntfy",
            ChannelKind::Telegram => "telegram",
            ChannelKind::File => "file",
            ChannelKind::Stdout => "stdout",
        }
    }

    fn is_http(self) -> bool {
        !matches!(
            self,
            ChannelKind::Email | ChannelKind::File | ChannelKind::Stdout
        )
    }
}

impl fmt::Display for ChannelKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A secret value written directly into the configuration (not
/// recommended – prefer the matching `*_env` key).  `Debug` never prints it.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Secret(pub String);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"***\"")
    }
}

/// Output format of the `file` / `stdout` channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileFormat {
    #[default]
    Text,
    /// One JSON object per line (JSON Lines).
    Json,
}

/// `[notify]`
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyConfig {
    /// Default threshold for all channels (`critical`, `warning`, `any`,
    /// `always`); default `warning`.
    pub on: Option<NotifyOn>,
    /// Prefix of e-mail subjects and chat titles (default `[ecomsec]`).
    pub subject_prefix: Option<String>,
    /// Link to the dashboard, added to messages.
    pub dashboard_url: Option<String>,
    #[serde(default, rename = "channel")]
    pub channels: Vec<ChannelConfig>,
}

/// `[[notify.channel]]` – one flat table for all kinds; which keys are
/// required depends on `kind`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelConfig {
    pub kind: ChannelKind,
    /// Display name (default `<kind>#<n>`).
    pub name: Option<String>,
    /// `false` disables the channel without removing it.
    pub enabled: Option<bool>,
    /// Channel-specific threshold, overrides `[notify] on`.
    pub on: Option<NotifyOn>,
    /// Network timeout in seconds (default 20).
    pub timeout_secs: Option<u64>,

    // ---- HTTP channels
    /// Webhook URL (Slack, Teams, Discord, Mattermost, webhook), ntfy server
    /// (default https://ntfy.sh) or Telegram API base.
    pub url: Option<Secret>,
    pub url_env: Option<String>,
    /// Additional HTTP headers (generic webhook).
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Additional HTTP headers whose values come from environment variables
    /// (header name → variable name).
    #[serde(default)]
    pub header_env: BTreeMap<String, String>,
    /// ntfy topic.
    pub topic: Option<String>,
    /// Telegram bot token or ntfy access token.
    pub token: Option<Secret>,
    pub token_env: Option<String>,
    /// Telegram chat id.
    pub chat_id: Option<String>,
    /// Slack/Mattermost channel override.
    pub channel: Option<String>,
    /// Display name of the bot (Slack, Discord, Mattermost).
    pub username: Option<String>,

    // ---- e-mail
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    /// `starttls` (default), `tls` or `none`.
    pub smtp_security: Option<SmtpSecurity>,
    pub smtp_user: Option<String>,
    pub smtp_user_env: Option<String>,
    pub smtp_password: Option<Secret>,
    pub smtp_password_env: Option<String>,
    pub from: Option<String>,
    #[serde(default)]
    pub to: Vec<String>,

    // ---- file
    pub path: Option<PathBuf>,
    pub format: Option<FileFormat>,
}

/// A resolved, ready-to-use channel.
pub struct Channel {
    pub name: String,
    pub kind: ChannelKind,
    pub on: Option<NotifyOn>,
    pub(crate) target: Target,
    pub(crate) timeout: Duration,
    /// Resolved secret values, redacted from every error message.
    pub(crate) secrets: Vec<String>,
}

pub(crate) enum Target {
    Http(HttpTarget),
    Email(EmailTarget),
    File {
        path: Option<PathBuf>,
        format: FileFormat,
    },
}

#[derive(Default)]
pub(crate) struct HttpTarget {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub topic: Option<String>,
    pub chat_id: Option<String>,
    pub channel: Option<String>,
    pub username: Option<String>,
    pub token: Option<String>,
}

impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Channel")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("target", &self.describe())
            .finish()
    }
}

impl Channel {
    /// Human readable destination without secrets (host only for URLs).
    pub fn describe(&self) -> String {
        match &self.target {
            Target::Http(h) => {
                let host = url_host(&h.url);
                match (&h.topic, &h.chat_id) {
                    (Some(t), _) => format!("{host} (Topic {t})"),
                    (_, Some(c)) => format!("{host} (Chat {c})"),
                    _ => host,
                }
            }
            Target::Email(e) => format!(
                "{}:{} ({}) → {}",
                e.host,
                e.port,
                e.security.as_str(),
                e.to.join(", ")
            ),
            Target::File { path: Some(p), .. } => p.display().to_string(),
            Target::File { path: None, .. } => "Standardausgabe".into(),
        }
    }

    /// Replace every resolved secret in `msg` by `***`.
    pub(crate) fn redact(&self, msg: &str) -> String {
        redact(msg, &self.secrets)
    }
}

pub(crate) fn redact(msg: &str, secrets: &[String]) -> String {
    let mut out = msg.to_string();
    for s in secrets {
        if s.len() >= 4 {
            out = out.replace(s.as_str(), "***");
        }
    }
    out
}

/// `https://hooks.slack.com/services/…` → `https://hooks.slack.com/…`
fn url_host(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    if scheme.is_empty() {
        host.to_string()
    } else {
        format!("{scheme}://{host}/…")
    }
}

/// Environment lookup, injectable for tests.
pub type EnvLookup<'a> = &'a dyn Fn(&str) -> Option<String>;

fn lookup_secret(
    direct: Option<&Secret>,
    env_key: Option<&String>,
    field: &str,
    env: EnvLookup<'_>,
) -> Result<Option<String>, String> {
    if let Some(var) = env_key {
        return match env(var).filter(|v| !v.trim().is_empty()) {
            Some(v) => Ok(Some(v.trim().to_string())),
            None => Err(format!(
                "Umgebungsvariable {var} (für {field}) ist nicht gesetzt"
            )),
        };
    }
    Ok(direct.map(|s| s.0.trim().to_string()))
}

fn lookup_plain(
    direct: Option<&String>,
    env_key: Option<&String>,
    field: &str,
    env: EnvLookup<'_>,
) -> Result<Option<String>, String> {
    lookup_secret(
        direct.map(|s| Secret(s.clone())).as_ref(),
        env_key,
        field,
        env,
    )
}

impl ChannelConfig {
    pub fn display_name(&self, index: usize) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("{}#{}", self.kind, index + 1))
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    /// Validate the keys required by `kind` and resolve secrets.
    pub fn resolve(&self, index: usize, env: EnvLookup<'_>) -> Result<Channel, NotifyError> {
        let name = self.display_name(index);
        let err = |msg: &str| NotifyError::Config(format!("Kanal {name}: {msg}"));
        let mut secrets = Vec::new();
        let url = lookup_secret(self.url.as_ref(), self.url_env.as_ref(), "url", env)
            .map_err(|e| err(&e))?;
        if let Some(u) = &url {
            secrets.push(u.clone());
        }
        let token = lookup_secret(self.token.as_ref(), self.token_env.as_ref(), "token", env)
            .map_err(|e| err(&e))?;
        if let Some(t) = &token {
            secrets.push(t.clone());
        }
        let target = match self.kind {
            ChannelKind::Email => {
                let host = self
                    .smtp_host
                    .clone()
                    .ok_or_else(|| err("smtp_host fehlt"))?;
                let from = self.from.clone().ok_or_else(|| err("from fehlt"))?;
                if self.to.is_empty() {
                    return Err(err("to (Empfängerliste) fehlt"));
                }
                let security = self.smtp_security.unwrap_or_default();
                let user = lookup_plain(
                    self.smtp_user.as_ref(),
                    self.smtp_user_env.as_ref(),
                    "smtp_user",
                    env,
                )
                .map_err(|e| err(&e))?;
                let password = lookup_secret(
                    self.smtp_password.as_ref(),
                    self.smtp_password_env.as_ref(),
                    "smtp_password",
                    env,
                )
                .map_err(|e| err(&e))?;
                if user.is_some() != password.is_some() {
                    return Err(err(
                        "smtp_user und smtp_password müssen gemeinsam gesetzt sein",
                    ));
                }
                if let Some(p) = &password {
                    secrets.push(p.clone());
                }
                Target::Email(EmailTarget {
                    port: self.smtp_port.unwrap_or(security.default_port()),
                    host,
                    security,
                    user,
                    password,
                    from,
                    to: self.to.clone(),
                })
            }
            ChannelKind::File | ChannelKind::Stdout => {
                let path = if self.kind == ChannelKind::File {
                    let p = self.path.clone().ok_or_else(|| err("path fehlt"))?;
                    (p.as_os_str() != "-").then_some(p)
                } else {
                    None
                };
                Target::File {
                    path,
                    format: self.format.unwrap_or_default(),
                }
            }
            kind => {
                debug_assert!(kind.is_http());
                let mut h = HttpTarget {
                    channel: self.channel.clone(),
                    username: self.username.clone(),
                    ..Default::default()
                };
                for (k, v) in &self.headers {
                    h.headers.push((k.clone(), v.clone()));
                }
                for (k, var) in &self.header_env {
                    let v = env(var).filter(|v| !v.is_empty()).ok_or_else(|| {
                        err(&format!(
                            "Umgebungsvariable {var} (Header {k}) ist nicht gesetzt"
                        ))
                    })?;
                    secrets.push(v.clone());
                    h.headers.push((k.clone(), v));
                }
                match kind {
                    ChannelKind::Ntfy => {
                        h.url = url.unwrap_or_else(|| "https://ntfy.sh".into());
                        h.topic = Some(
                            self.topic
                                .clone()
                                .filter(|t| !t.trim().is_empty())
                                .ok_or_else(|| err("topic fehlt"))?,
                        );
                        h.token = token;
                    }
                    ChannelKind::Telegram => {
                        let token =
                            token.ok_or_else(|| err("token bzw. token_env (Bot-Token) fehlt"))?;
                        let base = url.unwrap_or_else(|| "https://api.telegram.org".into());
                        h.url = format!("{}/bot{token}/sendMessage", base.trim_end_matches('/'));
                        h.chat_id = Some(self.chat_id.clone().ok_or_else(|| err("chat_id fehlt"))?);
                    }
                    _ => {
                        h.url = url.ok_or_else(|| err("url bzw. url_env fehlt"))?;
                    }
                }
                if !(h.url.starts_with("https://") || h.url.starts_with("http://")) {
                    return Err(err("url muss mit https:// oder http:// beginnen"));
                }
                Target::Http(h)
            }
        };
        Ok(Channel {
            name,
            kind: self.kind,
            on: self.on,
            target,
            timeout: Duration::from_secs(self.timeout_secs.unwrap_or(20).clamp(1, 300)),
            secrets,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> NotifyConfig {
        #[derive(Deserialize)]
        struct Wrapper {
            notify: NotifyConfig,
        }
        toml::from_str::<Wrapper>(text).unwrap().notify
    }

    fn env(var: &str) -> Option<String> {
        match var {
            "SLACK_URL" => Some("https://hooks.slack.com/services/T000/B000/SECRETSECRET".into()),
            "SMTP_PASS" => Some("hunter22".into()),
            "TG_TOKEN" => Some("123456:ABCDEF".into()),
            _ => None,
        }
    }

    const EXAMPLE: &str = r#"
[notify]
on = "critical"
subject_prefix = "[Shop]"
dashboard_url = "https://shop.example/ecomsec"

[[notify.channel]]
kind = "email"
name = "Admin"
smtp_host = "smtp.example.de"
smtp_user = "shop@example.de"
smtp_password_env = "SMTP_PASS"
from = "ecomsec <shop@example.de>"
to = ["admin@example.de"]

[[notify.channel]]
kind = "slack"
url_env = "SLACK_URL"
on = "any"

[[notify.channel]]
kind = "telegram"
token_env = "TG_TOKEN"
chat_id = "-100123"

[[notify.channel]]
kind = "ntfy"
topic = "mein-shop-a8f3"

[[notify.channel]]
kind = "teams-legacy"
url = "https://example.webhook.office.com/x"
enabled = false

[[notify.channel]]
kind = "file"
path = "/var/log/ecomsec/changes.log"
format = "json"
"#;

    #[test]
    fn parses_full_example() {
        let cfg = parse(EXAMPLE);
        assert_eq!(cfg.on, Some(NotifyOn::Critical));
        assert_eq!(cfg.channels.len(), 6);
        assert_eq!(cfg.channels[4].kind, ChannelKind::TeamsLegacy);
        assert!(!cfg.channels[4].is_enabled());
        assert_eq!(cfg.channels[1].display_name(1), "slack#2");
        let chans: Vec<Channel> = cfg
            .channels
            .iter()
            .enumerate()
            .map(|(i, c)| c.resolve(i, &env).unwrap())
            .collect();
        match &chans[0].target {
            Target::Email(e) => {
                assert_eq!(e.port, 587);
                assert_eq!(e.password.as_deref(), Some("hunter22"));
            }
            _ => panic!("email expected"),
        }
        assert_eq!(chans[1].on, Some(NotifyOn::Any));
        assert_eq!(chans[1].describe(), "https://hooks.slack.com/…");
        assert!(chans[2].describe().contains("api.telegram.org"));
        assert!(!chans[2].describe().contains("ABCDEF"));
        assert_eq!(
            chans[3].describe(),
            "https://ntfy.sh/… (Topic mein-shop-a8f3)"
        );
        // Debug output never contains secrets.
        let dbg = format!("{:?} {:?}", cfg, chans);
        assert!(!dbg.contains("hunter22"));
        assert!(!dbg.contains("SECRETSECRET"));
        assert!(!dbg.contains("ABCDEF"));
    }

    #[test]
    fn missing_env_and_keys_are_reported_without_values() {
        let cfg = parse(
            r#"
[notify]
[[notify.channel]]
kind = "discord"
url_env = "NOT_SET_ANYWHERE"
[[notify.channel]]
kind = "email"
smtp_host = "x"
from = "a@b.de"
[[notify.channel]]
kind = "ntfy"
"#,
        );
        let e = cfg.channels[0].resolve(0, &env).unwrap_err().to_string();
        assert!(e.contains("NOT_SET_ANYWHERE"), "{e}");
        let e = cfg.channels[1].resolve(1, &env).unwrap_err().to_string();
        assert!(e.contains("to"), "{e}");
        let e = cfg.channels[2].resolve(2, &env).unwrap_err().to_string();
        assert!(e.contains("topic"), "{e}");
    }

    #[test]
    fn unknown_keys_and_kinds_are_rejected() {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Wrapper {
            notify: NotifyConfig,
        }
        assert!(
            toml::from_str::<Wrapper>("[notify]\n[[notify.channel]]\nkind = \"pager\"\n").is_err()
        );
        assert!(toml::from_str::<Wrapper>(
            "[notify]\n[[notify.channel]]\nkind = \"slack\"\nwebhook = \"x\"\n"
        )
        .is_err());
    }

    #[test]
    fn redaction_and_notify_on_parsing() {
        let s = vec!["topsecret".to_string(), "ab".to_string()];
        assert_eq!(redact("url topsecret/x ab", &s), "url ***/x ab");
        assert_eq!("Always".parse::<NotifyOn>().unwrap(), NotifyOn::Always);
        assert!("sometimes".parse::<NotifyOn>().is_err());
    }
}
