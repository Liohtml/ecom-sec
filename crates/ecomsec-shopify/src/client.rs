//! Minimal Shopify Admin API client (REST + GraphQL) with rate-limit handling.

use serde_json::Value;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShopifyError {
    #[error("Shopify API {status} für {path}: {body}")]
    Status {
        status: u16,
        path: String,
        body: String,
    },
    #[error("HTTP-Fehler: {0}")]
    Http(String),
    #[error("ungültige Konfiguration: {0}")]
    Config(String),
}

#[derive(Debug, Clone)]
pub struct ShopifyConfig {
    /// `my-store.myshopify.com` (scheme optional).
    pub shop_domain: String,
    /// Admin API access token (`shpat_…`) – needs read scopes only.
    pub access_token: String,
    pub api_version: String,
    /// Additional trusted hosts for script tags, webhooks and theme scripts.
    pub allowlist: Vec<String>,
    /// Upper bound of theme assets that are downloaded and scanned.
    pub max_assets: usize,
    pub timeout: Duration,
}

impl ShopifyConfig {
    pub fn new(shop_domain: impl Into<String>, access_token: impl Into<String>) -> Self {
        ShopifyConfig {
            shop_domain: shop_domain.into(),
            access_token: access_token.into(),
            api_version: "2025-07".into(),
            allowlist: Vec::new(),
            max_assets: 150,
            timeout: Duration::from_secs(30),
        }
    }
}

pub struct ShopifyClient {
    agent: ureq::Agent,
    base: String,
    domain: String,
    token: String,
    api_version: String,
}

impl ShopifyClient {
    pub fn new(config: ShopifyConfig) -> Result<Self, ShopifyError> {
        let domain = config
            .shop_domain
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();
        if domain.is_empty() || !domain.contains('.') {
            return Err(ShopifyError::Config(
                "Shop-Domain fehlt (z. B. my-store.myshopify.com)".into(),
            ));
        }
        if config.access_token.trim().is_empty() {
            return Err(ShopifyError::Config("Admin-API-Token fehlt".into()));
        }
        let agent_config = ureq::Agent::config_builder()
            .timeout_global(Some(config.timeout))
            .http_status_as_error(false)
            .build();
        Ok(ShopifyClient {
            agent: agent_config.into(),
            base: format!("https://{domain}/admin/api/{}/", config.api_version),
            domain,
            token: config.access_token,
            api_version: config.api_version,
        })
    }

    pub fn shop_domain(&self) -> &str {
        &self.domain
    }

    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// GET `<base>/<path>` and parse JSON, retrying on 429.
    pub fn get_json(&self, path: &str) -> Result<Value, ShopifyError> {
        let url = format!("{}{}", self.base, path);
        for attempt in 0..4 {
            let resp = self
                .agent
                .get(&url)
                .header("X-Shopify-Access-Token", &self.token)
                .header("Accept", "application/json")
                .call()
                .map_err(|e| ShopifyError::Http(e.to_string()))?;
            match self.handle(resp, path, attempt)? {
                Some(v) => return Ok(v),
                None => continue,
            }
        }
        Err(ShopifyError::Http(format!(
            "Rate-Limit für {path} nach mehreren Versuchen nicht aufgehoben"
        )))
    }

    /// POST a GraphQL query.
    pub fn graphql(&self, query: &str) -> Result<Value, ShopifyError> {
        let url = format!("{}graphql.json", self.base);
        let body = serde_json::json!({ "query": query });
        for attempt in 0..4 {
            let resp = self
                .agent
                .post(&url)
                .header("X-Shopify-Access-Token", &self.token)
                .header("Content-Type", "application/json")
                .send_json(&body)
                .map_err(|e| ShopifyError::Http(e.to_string()))?;
            match self.handle(resp, "graphql.json", attempt)? {
                Some(v) => {
                    if let Some(errors) = v.get("errors").and_then(|e| e.as_array()) {
                        if !errors.is_empty() {
                            return Err(ShopifyError::Status {
                                status: 200,
                                path: "graphql.json".into(),
                                body: errors
                                    .iter()
                                    .map(|e| {
                                        e.get("message")
                                            .and_then(|m| m.as_str())
                                            .unwrap_or("?")
                                            .to_string()
                                    })
                                    .collect::<Vec<_>>()
                                    .join("; "),
                            });
                        }
                    }
                    return Ok(v);
                }
                None => continue,
            }
        }
        Err(ShopifyError::Http(
            "GraphQL Rate-Limit nicht aufgehoben".into(),
        ))
    }

    fn handle(
        &self,
        mut resp: ureq::http::Response<ureq::Body>,
        path: &str,
        attempt: u32,
    ) -> Result<Option<Value>, ShopifyError> {
        let status = resp.status().as_u16();
        if status == 429 {
            let wait = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(2.0)
                .max(0.5);
            log::warn!("Shopify rate limit on {path}; waiting {wait:.1}s (attempt {attempt})");
            std::thread::sleep(Duration::from_secs_f64(wait));
            return Ok(None);
        }
        let body = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| ShopifyError::Http(e.to_string()))?;
        if !(200..300).contains(&status) {
            return Err(ShopifyError::Status {
                status,
                path: path.to_string(),
                body: body.chars().take(300).collect(),
            });
        }
        serde_json::from_str(&body)
            .map(Some)
            .map_err(|e| ShopifyError::Http(format!("ungültiges JSON von {path}: {e}")))
    }
}
