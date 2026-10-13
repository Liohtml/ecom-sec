//! E-mail via SMTP (lettre, rustls).  The message is multipart/alternative
//! with a plain-text and an HTML body.

use crate::format;
use crate::{Notification, NotifyError};
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use serde::Deserialize;
use std::time::Duration;

/// Transport security of the SMTP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpSecurity {
    /// Plain connection upgraded with STARTTLS (port 587).  TLS is required.
    #[default]
    Starttls,
    /// Implicit TLS ("SMTPS", port 465).
    Tls,
    /// No encryption – only for a local relay (port 25).
    None,
}

impl SmtpSecurity {
    pub fn default_port(self) -> u16 {
        match self {
            SmtpSecurity::Starttls => 587,
            SmtpSecurity::Tls => 465,
            SmtpSecurity::None => 25,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SmtpSecurity::Starttls => "STARTTLS",
            SmtpSecurity::Tls => "TLS",
            SmtpSecurity::None => "unverschlüsselt",
        }
    }
}

pub(crate) struct EmailTarget {
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
    pub user: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub to: Vec<String>,
}

/// Build the MIME message (separate from sending for testability).
pub(crate) fn build_message(
    target: &EmailTarget,
    n: &Notification,
) -> Result<Message, NotifyError> {
    let from: Mailbox = target
        .from
        .parse()
        .map_err(|e| NotifyError::Config(format!("ungültiger Absender {:?}: {e}", target.from)))?;
    let mut builder = Message::builder().from(from).subject(n.title.clone());
    for to in &target.to {
        let mb: Mailbox = to
            .parse()
            .map_err(|e| NotifyError::Config(format!("ungültiger Empfänger {to:?}: {e}")))?;
        builder = builder.to(mb);
    }
    let text = format::plain_text(n);
    let html = format::email_html(n);
    builder
        .multipart(MultiPart::alternative_plain_html(text, html))
        .map_err(|e| NotifyError::Email(e.to_string()))
}

pub(crate) fn send(
    target: &EmailTarget,
    n: &Notification,
    timeout: Duration,
) -> Result<(), NotifyError> {
    let message = build_message(target, n)?;
    let builder = match target.security {
        SmtpSecurity::Starttls => SmtpTransport::starttls_relay(&target.host)
            .map_err(|e| NotifyError::Email(e.to_string()))?,
        SmtpSecurity::Tls => {
            SmtpTransport::relay(&target.host).map_err(|e| NotifyError::Email(e.to_string()))?
        }
        SmtpSecurity::None => SmtpTransport::builder_dangerous(&target.host),
    };
    let mut builder = builder.port(target.port).timeout(Some(timeout));
    if let (Some(user), Some(password)) = (&target.user, &target.password) {
        builder = builder.credentials(Credentials::new(user.clone(), password.clone()));
    }
    builder
        .build()
        .send(&message)
        .map(|_| ())
        .map_err(|e| NotifyError::Email(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_has_subject_and_both_bodies() {
        let target = EmailTarget {
            host: "smtp.example.de".into(),
            port: 587,
            security: SmtpSecurity::Starttls,
            user: None,
            password: None,
            from: "ecomsec <shop@example.de>".into(),
            to: vec!["admin@example.de".into(), "Technik <it@example.de>".into()],
        };
        let n = Notification::test("jtl5 @ /var/www/shop", &Default::default());
        let msg = build_message(&target, &n).unwrap();
        let raw = String::from_utf8(msg.formatted()).unwrap();
        assert!(raw.contains("Subject:"));
        assert!(raw.contains("multipart/alternative"));
        assert!(raw.contains("text/plain"));
        assert!(raw.contains("text/html"));
        assert!(raw.contains("it@example.de"));
    }

    #[test]
    fn invalid_addresses_are_config_errors() {
        let target = EmailTarget {
            host: "x".into(),
            port: 25,
            security: SmtpSecurity::None,
            user: None,
            password: None,
            from: "kein absender".into(),
            to: vec!["a@b.de".into()],
        };
        let n = Notification::test("x", &Default::default());
        assert!(matches!(
            build_message(&target, &n),
            Err(NotifyError::Config(_))
        ));
    }
}
