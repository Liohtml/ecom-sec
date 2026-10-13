//! Host classification for script sources found in shop content (CMS blocks,
//! posts, options, theme settings).  Platform-neutral copy of the classifier
//! used by the Shopify adapter: adapters pass their own platform suffixes
//! (e.g. `wordpress.org`, `magento.com`) and an optional allowlist.

use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostClass {
    /// The platform's own infrastructure or the shop's own domain.
    Platform,
    /// Well-known vendor or user-supplied allowlist.
    Allowlisted,
    /// Not known – needs attribution.
    Unknown,
    /// Lookalike, IP literal, abuse-prone TLD.
    Suspicious,
}

impl HostClass {
    pub fn label(self) -> &'static str {
        match self {
            HostClass::Platform => "eigene Domain / Plattform",
            HostClass::Allowlisted => "bekannter Anbieter",
            HostClass::Unknown => "unbekannter Host",
            HostClass::Suspicious => "VERDÄCHTIGER Host",
        }
    }
}

/// Widely used tag managers, analytics, payment, consent and CDN hosts.
pub const KNOWN_VENDORS: &[&str] = &[
    "googletagmanager.com",
    "google-analytics.com",
    "googleadservices.com",
    "googlesyndication.com",
    "googleapis.com",
    "gstatic.com",
    "google.com",
    "recaptcha.net",
    "doubleclick.net",
    "facebook.net",
    "facebook.com",
    "fbcdn.net",
    "klaviyo.com",
    "hotjar.com",
    "stripe.com",
    "stripe.network",
    "paypal.com",
    "paypalobjects.com",
    "braintreegateway.com",
    "braintree-api.com",
    "adyen.com",
    "mollie.com",
    "klarna.com",
    "klarnaservices.com",
    "amazonpay.com",
    "trustpilot.com",
    "cloudflare.com",
    "cloudflareinsights.com",
    "jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "jquery.com",
    "bootstrapcdn.com",
    "fontawesome.com",
    "tiktok.com",
    "pinterest.com",
    "pinimg.com",
    "bing.com",
    "clarity.ms",
    "zendesk.com",
    "zdassets.com",
    "intercom.io",
    "intercomcdn.com",
    "crisp.chat",
    "tidio.co",
    "mailchimp.com",
    "list-manage.com",
    "chimpstatic.com",
    "trustedshops.com",
    "trustedshops.de",
    "usercentrics.eu",
    "cookiebot.com",
    "onetrust.com",
    "cookielaw.org",
    "consentmanager.net",
    "algolia.net",
    "algolianet.com",
    "vimeo.com",
    "youtube.com",
    "ytimg.com",
    "fonts.googleapis.com",
    "typekit.net",
    "adobe.com",
    "adobedtm.com",
    "newrelic.com",
    "nr-data.net",
    "sentry.io",
    "sentry-cdn.com",
    "segment.com",
    "hubspot.com",
    "hs-scripts.com",
    "hsforms.net",
    "linkedin.com",
    "licdn.com",
    "criteo.com",
    "criteo.net",
    "awin1.com",
    "sendinblue.com",
    "brevo.com",
    "microsoft.com",
    "live.com",
    "azureedge.net",
    "amazonaws.com",
    "cloudfront.net",
];

/// Top-level domains that are disproportionately used for skimmer and
/// spam infrastructure.
pub const SUSPICIOUS_TLDS: &[&str] = &[
    "ru", "cn", "su", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "icu", "club", "work",
    "click", "link", "pw", "cam", "rest", "bar", "monster", "quest", "sbs", "cfd", "zip", "mov",
];

/// Brand terms abused in lookalike domains (`google-analytlcs.net`).
pub const LOOKALIKE_TERMS: &[&str] = &[
    "google",
    "jquery",
    "facebook",
    "cloudflare",
    "paypal",
    "stripe",
    "klarna",
    "analytics",
    "gstatic",
    "tagmanager",
    "bootstrap",
    "fontawesome",
    "magento",
    "woocommerce",
    "wordpress",
    "braintree",
    "adyen",
    "amazon",
    "apple",
    "microsoft",
];

/// Host part of a URL (`https://user@cdn.example.com:8443/x` → `cdn.example.com`).
pub fn host_of(url: &str) -> Option<String> {
    let s = url.trim();
    let s = s.strip_prefix("//").unwrap_or(s);
    let rest = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let host = rest.split(['/', '?', '#', '"', '\'', ' ', '>']).next()?;
    let host = host.rsplit('@').next()?;
    let host = host.split(':').next()?;
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn suffix_matches(host: &str, suffix: &str) -> bool {
    let suffix = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
    !suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}")))
}

/// Classify a host.  `platform` holds the platform's own domains plus the
/// shop's own domain(s); `allowlist` user-supplied vendor domains.
pub fn classify_host(host: &str, platform: &[&str], allowlist: &[String]) -> HostClass {
    let host = host.to_ascii_lowercase();
    if host.is_empty() {
        return HostClass::Unknown;
    }
    if platform.iter().any(|s| suffix_matches(&host, s)) {
        return HostClass::Platform;
    }
    if allowlist.iter().any(|a| suffix_matches(&host, a))
        || KNOWN_VENDORS.iter().any(|s| suffix_matches(&host, s))
    {
        return HostClass::Allowlisted;
    }
    if host.split('.').count() == 4 && host.split('.').all(|p| p.parse::<u8>().is_ok()) {
        return HostClass::Suspicious;
    }
    if host.starts_with('[') || host.ends_with(".onion") {
        return HostClass::Suspicious;
    }
    let tld = host.rsplit('.').next().unwrap_or("");
    if SUSPICIOUS_TLDS.contains(&tld) {
        return HostClass::Suspicious;
    }
    if LOOKALIKE_TERMS.iter().any(|t| host.contains(t)) {
        return HostClass::Suspicious;
    }
    HostClass::Unknown
}

/// All external script sources (`<script src="…">`) in an HTML fragment.
pub fn script_sources(html: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r#"(?is)<script\b[^>]{0,400}?\bsrc\s*=\s*["']?((?:https?:)?//[^"'\s>]+)"#)
            .expect("regex")
    });
    re.captures_iter(html).map(|c| c[1].to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_classes() {
        assert_eq!(
            host_of("https://user@evil.ru:8443/a").as_deref(),
            Some("evil.ru")
        );
        assert_eq!(
            host_of("//cdn.example.com/x.js").as_deref(),
            Some("cdn.example.com")
        );
        let own = ["shop.example.de", "wordpress.org"];
        assert_eq!(
            classify_host("shop.example.de", &own, &[]),
            HostClass::Platform
        );
        assert_eq!(
            classify_host("s.w.wordpress.org", &own, &[]),
            HostClass::Platform
        );
        assert_eq!(
            classify_host("www.googletagmanager.com", &own, &[]),
            HostClass::Allowlisted
        );
        assert_eq!(
            classify_host("cdn.agency.de", &own, &["agency.de".into()]),
            HostClass::Allowlisted
        );
        assert_eq!(
            classify_host("cdn.example.org", &own, &[]),
            HostClass::Unknown
        );
        assert_eq!(
            classify_host("jquery-cdn.top", &own, &[]),
            HostClass::Suspicious
        );
        assert_eq!(
            classify_host("magento-analytics.net", &own, &[]),
            HostClass::Suspicious
        );
        assert_eq!(
            classify_host("45.33.12.9", &own, &[]),
            HostClass::Suspicious
        );
    }

    #[test]
    fn extracts_script_sources() {
        let html = r#"<p>x</p><script async src="https://evil.top/a.js"></script><SCRIPT src='//cdn.x.org/b.js'></SCRIPT><script>var a=1</script>"#;
        assert_eq!(
            script_sources(html),
            vec![
                "https://evil.top/a.js".to_string(),
                "//cdn.x.org/b.js".to_string()
            ]
        );
    }
}
