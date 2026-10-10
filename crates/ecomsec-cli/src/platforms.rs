//! Platform registry: auto-detection and construction of adapters.

use crate::config::FileConfig;
use anyhow::{bail, Context};
use ecomsec_core::Platform;
use ecomsec_shopify::{Shopify, ShopifyConfig};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Everything needed to (re-)open a platform adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSpec {
    pub platform: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shop: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_assets: Option<usize>,
}

pub struct PlatformDescriptor {
    pub id: &'static str,
    pub name: &'static str,
    pub kind: &'static str,
    pub description: &'static str,
}

pub const PLATFORMS: &[PlatformDescriptor] = &[
    PlatformDescriptor {
        id: ecomsec_jtl5::PLATFORM_ID,
        name: "JTL-Shop 5",
        kind: "self-hosted (Webroot + MySQL)",
        description: "CVE-2026-54390 Patch-Status, Webshell-/SSTI-Scan, tadminlogin, PayPal-Einstellungen, temailhistory, E-Mail-Vorlagen, Plugins, Cronjobs",
    },
    PlatformDescriptor {
        id: ecomsec_shopware6::PLATFORM_ID,
        name: "Shopware 6",
        kind: "self-hosted (Projekt-Root + MySQL)",
        description: "CVE-Status (Twig-SSTI, SQLi), Webshell-Scan, Admin-User, API-Integrationen, Apps/Plugins, Zahlungsanbieter-Konfiguration, Mail-Templates/Flows, Snippet-/CMS-Injection",
    },
    PlatformDescriptor {
        id: ecomsec_shopify::PLATFORM_ID,
        name: "Shopify",
        kind: "hosted (Admin API)",
        description: "Script-Tags, Webhooks, Apps & Scopes, Mitarbeiter (Plus), Live-Theme-Scan auf Skimmer/Fremdcode",
    },
];

/// Detect the platform of a directory.
pub fn detect(root: &Path) -> Option<&'static str> {
    if ecomsec_jtl5::Jtl5::detect(root) {
        Some(ecomsec_jtl5::PLATFORM_ID)
    } else if ecomsec_shopware6::Shopware6::detect(root) {
        Some(ecomsec_shopware6::PLATFORM_ID)
    } else {
        None
    }
}

impl TargetSpec {
    /// Build a target from CLI arguments and the configuration file.
    pub fn resolve(
        platform: Option<&str>,
        root: Option<&Path>,
        shop: Option<&str>,
        token: Option<&str>,
        api_version: Option<&str>,
        allow_hosts: &[String],
        cfg: &FileConfig,
    ) -> anyhow::Result<Self> {
        let platform = platform
            .map(str::to_string)
            .or_else(|| cfg.target.platform.clone())
            .unwrap_or_else(|| "auto".into());
        let shop = shop
            .map(str::to_string)
            .or_else(|| cfg.shopify.shop.clone())
            .or_else(|| std::env::var("SHOPIFY_SHOP").ok());
        let token = token
            .map(str::to_string)
            .or_else(|| cfg.shopify.token.clone())
            .or_else(|| {
                cfg.shopify
                    .token_env
                    .as_ref()
                    .and_then(|e| std::env::var(e).ok())
            })
            .or_else(|| std::env::var("SHOPIFY_ACCESS_TOKEN").ok());
        let mut allow = cfg.shopify.allow_hosts.clone();
        allow.extend(allow_hosts.iter().cloned());

        let platform = if platform == "auto" {
            if shop.is_some() && root.is_none() && cfg.target.root.is_none() {
                ecomsec_shopify::PLATFORM_ID.to_string()
            } else {
                let dir = root
                    .map(Path::to_path_buf)
                    .or_else(|| cfg.target.root.clone())
                    .unwrap_or_else(|| PathBuf::from("."));
                detect(&dir)
                    .with_context(|| {
                        format!(
                            "Kein unterstütztes Shopsystem in {} erkannt (JTL-Shop 5: includes/config.JTL-Shop.ini.php, Shopware 6: composer.json mit shopware/core). Plattform mit --platform angeben.",
                            dir.display()
                        )
                    })?
                    .to_string()
            }
        } else {
            platform
        };
        if !PLATFORMS.iter().any(|p| p.id == platform) {
            bail!(
                "Unbekannte Plattform {platform:?}. Verfügbar: {}",
                PLATFORMS
                    .iter()
                    .map(|p| p.id)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let root = if platform == ecomsec_shopify::PLATFORM_ID {
            None
        } else {
            Some(
                root.map(Path::to_path_buf)
                    .or_else(|| cfg.target.root.clone())
                    .unwrap_or_else(|| PathBuf::from(".")),
            )
        };
        Ok(TargetSpec {
            platform,
            root,
            shop,
            token,
            api_version: api_version
                .map(str::to_string)
                .or_else(|| cfg.shopify.api_version.clone()),
            allow_hosts: allow,
            max_assets: cfg.shopify.max_assets,
        })
    }

    /// Key for the per-target state directory.
    pub fn state_key(&self) -> String {
        self.root
            .as_ref()
            .map(|r| {
                r.canonicalize()
                    .unwrap_or_else(|_| r.clone())
                    .to_string_lossy()
                    .to_string()
            })
            .or_else(|| self.shop.clone())
            .unwrap_or_else(|| self.platform.clone())
    }

    pub fn display(&self) -> String {
        match (&self.root, &self.shop) {
            (Some(r), _) => format!("{} @ {}", self.platform, r.display()),
            (None, Some(s)) => format!("{} @ {s}", self.platform),
            _ => self.platform.clone(),
        }
    }

    /// Instantiate the adapter.
    pub fn open(&self) -> anyhow::Result<Box<dyn Platform>> {
        match self.platform.as_str() {
            ecomsec_jtl5::PLATFORM_ID => {
                let root = self.root.clone().unwrap_or_else(|| PathBuf::from("."));
                if !root.is_dir() {
                    bail!("Verzeichnis {} existiert nicht", root.display());
                }
                Ok(Box::new(ecomsec_jtl5::Jtl5::open(root)?))
            }
            ecomsec_shopware6::PLATFORM_ID => {
                let root = self.root.clone().unwrap_or_else(|| PathBuf::from("."));
                if !root.is_dir() {
                    bail!("Verzeichnis {} existiert nicht", root.display());
                }
                Ok(Box::new(ecomsec_shopware6::Shopware6::open(root)?))
            }
            ecomsec_shopify::PLATFORM_ID => {
                let shop = self
                    .shop
                    .clone()
                    .context("Shopify: --shop my-store.myshopify.com (oder SHOPIFY_SHOP) fehlt")?;
                let token = self
                    .token
                    .clone()
                    .context("Shopify: --token shpat_… (oder SHOPIFY_ACCESS_TOKEN) fehlt")?;
                let mut cfg = ShopifyConfig::new(shop, token);
                if let Some(v) = &self.api_version {
                    cfg.api_version = v.clone();
                }
                cfg.allowlist = self.allow_hosts.clone();
                if let Some(m) = self.max_assets {
                    cfg.max_assets = m;
                }
                Ok(Box::new(Shopify::open(cfg)?))
            }
            other => bail!("Unbekannte Plattform {other}"),
        }
    }
}
