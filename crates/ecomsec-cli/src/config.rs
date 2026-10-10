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
