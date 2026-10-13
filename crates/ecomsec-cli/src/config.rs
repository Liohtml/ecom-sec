//! Optional TOML configuration file (`ecomsec.toml`).

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default)]
    pub scan: ScanSection,
    #[serde(default)]
    pub target: TargetSection,
    #[serde(default)]
    pub shopify: ShopifySection,
    #[serde(default)]
    pub state: StateSection,
    #[serde(default)]
    pub serve: ServeSection,
    /// `[notify]` with `[[notify.channel]]` entries (see docs/MONITORING.md).
    #[serde(default)]
    pub notify: ecomsec_notify::NotifyConfig,
    #[serde(default)]
    pub watch: WatchSection,
    #[serde(default)]
    pub audit: AuditSection,
}

/// `[watch]` – defaults for `ecomsec watch`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchSection {
    /// Run `advisories update` before each scan (default `true`).
    pub update_advisories: Option<bool>,
    /// Base URL for the advisory download.
    pub update_url: Option<String>,
    /// Loop interval for `watch` without `--interval` (e.g. `24h`).
    pub interval: Option<String>,
}

/// `[audit]` – optional AI audit.  The API key itself is never stored in the
/// configuration, only the name of the environment variable holding it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSection {
    pub api_key_env: Option<String>,
    pub model: Option<String>,
    pub mode: Option<String>,
    pub max_turns: Option<u32>,
    pub max_tokens_budget: Option<u64>,
    pub effort: Option<String>,
    pub api_base: Option<String>,
    pub fallback: Option<bool>,
    pub hunt_max_files: Option<usize>,
    pub hunt_max_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanSection {
    pub reference_date: Option<String>,
    pub time_budget: Option<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub rule_dirs: Vec<PathBuf>,
    pub max_file_size: Option<u64>,
    #[serde(default)]
    pub advisory_dirs: Vec<PathBuf>,
    #[serde(default)]
    pub online: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSection {
    pub platform: Option<String>,
    pub root: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShopifySection {
    pub shop: Option<String>,
    pub token: Option<String>,
    pub token_env: Option<String>,
    pub api_version: Option<String>,
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    pub max_assets: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateSection {
    pub dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServeSection {
    pub bind: Option<String>,
    pub token: Option<String>,
}

impl FileConfig {
    /// Load the explicit path, else `./ecomsec.toml`, else `$ECOMSEC_CONFIG`.
    pub fn load(explicit: Option<&Path>) -> anyhow::Result<Self> {
        let candidates: Vec<PathBuf> = match explicit {
            Some(p) => vec![p.to_path_buf()],
            None => {
                let mut v = Vec::new();
                if let Ok(p) = std::env::var("ECOMSEC_CONFIG") {
                    v.push(PathBuf::from(p));
                }
                v.push(PathBuf::from("ecomsec.toml"));
                v
            }
        };
        for path in candidates {
            if path.is_file() {
                let text = std::fs::read_to_string(&path)?;
                let cfg: FileConfig = toml::from_str(&text).map_err(|e| {
                    anyhow::anyhow!("Konfiguration {} ungültig: {e}", path.display())
                })?;
                log::info!("configuration loaded from {}", path.display());
                return Ok(cfg);
            } else if explicit.is_some() {
                anyhow::bail!("Konfigurationsdatei {} nicht gefunden", path.display());
            }
        }
        Ok(FileConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecomsec_notify::{ChannelKind, NotifyOn};

    #[test]
    fn example_config_parses() {
        let text = include_str!("../../../ecomsec.example.toml");
        let cfg: FileConfig = toml::from_str(text).expect("example config is valid");
        assert!(cfg.watch.update_advisories.unwrap_or(true));
        assert_eq!(cfg.notify.on, Some(NotifyOn::Warning));
    }

    #[test]
    fn notify_and_watch_sections() {
        let cfg: FileConfig = toml::from_str(
            r#"
[watch]
update_advisories = false
interval = "12h"

[notify]
on = "critical"
dashboard_url = "https://shop.example/ecomsec"

[[notify.channel]]
kind = "slack"
url_env = "ECOMSEC_SLACK_WEBHOOK"

[[notify.channel]]
kind = "email"
smtp_host = "smtp.example.de"
smtp_security = "tls"
from = "shop@example.de"
to = ["admin@example.de"]
"#,
        )
        .unwrap();
        assert_eq!(cfg.watch.update_advisories, Some(false));
        assert_eq!(cfg.watch.interval.as_deref(), Some("12h"));
        assert_eq!(cfg.notify.on, Some(NotifyOn::Critical));
        assert_eq!(cfg.notify.channels.len(), 2);
        assert_eq!(cfg.notify.channels[1].kind, ChannelKind::Email);
    }

    #[test]
    fn unknown_notify_keys_are_rejected() {
        assert!(toml::from_str::<FileConfig>("[notify]\nfoo = 1\n").is_err());
        assert!(toml::from_str::<FileConfig>("[watch]\nevery = \"1h\"\n").is_err());
    }
}
