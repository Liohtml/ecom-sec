//! Host classification for script tags, webhooks and theme scripts.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostClass {
    /// Shopify's own infrastructure.
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
            HostClass::Platform => "Shopify-Plattform",
            HostClass::Allowlisted => "bekannter Anbieter",
            HostClass::Unknown => "unbekannter Host",
            HostClass::Suspicious => "VERDÄCHTIGER Host",
        }
    }
}

const PLATFORM_SUFFIXES: &[&str] = &[
    "shopify.com",
    "shopifycdn.com",
    "shopifycloud.com",
    "myshopify.com",
    "shopifysvc.com",
    "shopifyapps.com",
    "shopifypreview.com",
    "shopify.dev",
    "shopifyinbox.com",
    "shop.app",
];

const KNOWN_VENDORS: &[&str] = &[
    "googletagmanager.com",
    "google-analytics.com",
    "googleadservices.com",
    "googleapis.com",
    "gstatic.com",
    "google.com",
    "doubleclick.net",
    "facebook.net",
    "facebook.com",
    "fbcdn.net",
    "klaviyo.com",
    "hotjar.com",
    "judge.me",
    "loox.io",
    "yotpo.com",
    "stripe.com",
    "paypal.com",
    "paypalobjects.com",
    "klarna.com",
    "trustpilot.com",
    "cloudflare.com",
    "cloudflareinsights.com",
    "jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "jquery.com",
    "tiktok.com",
    "pinterest.com",
    "pinimg.com",
    "bing.com",
    "clarity.ms",
    "privy.com",
    "gorgias.com",
    "gorgias.chat",
    "zendesk.com",
    "intercom.io",
    "intercomcdn.com",
    "crisp.chat",
    "tidio.co",
    "mailchimp.com",
    "list-manage.com",
    "omnisend.com",
    "recharge.com",
    "rechargepayments.com",
    "bold.com",
    "boldapps.net",
    "pagefly.io",
    "gempages.net",
    "shogun.page",
    "trustedshops.com",
    "trustedshops.de",
    "usercentrics.eu",
    "cookiebot.com",
    "onetrust.com",
    "consentmanager.net",
    "afterpay.com",
    "affirm.com",
    "sezzle.com",
    "aftership.com",
    "stamped.io",
    "okendo.io",
    "smile.io",
    "rebuyengine.com",
    "nosto.com",
    "algolia.net",
    "algolianet.com",
    "vimeo.com",
    "youtube.com",
    "ytimg.com",
    "wistia.com",
    "fonts.googleapis.com",
    "typekit.net",
    "adobe.com",
    "newrelic.com",
    "nr-data.net",
    "sentry.io",
    "sentry-cdn.com",
    "segment.com",
    "segment.io",
    "mixpanel.com",
    "amplitude.com",
    "hubspot.com",
    "hs-scripts.com",
    "hsforms.net",
    "linkedin.com",
    "licdn.com",
    "snapchat.com",
    "sc-static.net",
    "criteo.com",
    "criteo.net",
    "awin1.com",
    "zenloop.com",
    "sendinblue.com",
    "brevo.com",
    "reddit.com",
    "redditstatic.com",
    "microsoft.com",
    "live.com",
    "azureedge.net",
    "amazonaws.com",
    "cloudfront.net",
];

const SUSPICIOUS_TLDS: &[&str] = &[
    "ru", "cn", "su", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "icu", "club", "work",
    "click", "link", "pw", "cam", "rest", "bar", "monster", "quest", "sbs", "cfd", "zip", "mov",
];

const LOOKALIKE_TERMS: &[&str] = &[
    "google",
    "jquery",
    "shopify",
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
    "klaviyo",
    "magento",
    "amazon",
    "apple",
    "microsoft",
];

pub fn host_of(url: &str) -> Option<String> {
    let s = url.trim();
    let s = s.strip_prefix("//").unwrap_or(s);
    let rest = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit('@').next()?; // strip userinfo
    let host = host.split(':').next()?; // strip port
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn suffix_matches(host: &str, suffix: &str) -> bool {
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

pub fn classify_host(host: &str, allowlist: &[String]) -> HostClass {
    let host = host.to_ascii_lowercase();
    if host.is_empty() {
        return HostClass::Unknown;
    }
    if PLATFORM_SUFFIXES.iter().any(|s| suffix_matches(&host, s)) {
        return HostClass::Platform;
    }
    if allowlist
        .iter()
        .any(|a| suffix_matches(&host, &a.to_ascii_lowercase()))
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
        // Contains a brand term but is neither platform nor known vendor.
        return HostClass::Suspicious;
    }
    HostClass::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(
            host_of("https://cdn.shopify.com/s/files/x.js?v=1").as_deref(),
            Some("cdn.shopify.com")
        );
        assert_eq!(host_of("//example.com/x").as_deref(), Some("example.com"));
        assert_eq!(
            host_of("https://user@evil.ru:8443/a").as_deref(),
            Some("evil.ru")
        );
        assert!(host_of("").is_none());
    }

    #[test]
    fn classification() {
        let allow = vec!["my-agency.de".to_string()];
        assert_eq!(
            classify_host("cdn.shopify.com", &allow),
            HostClass::Platform
        );
        assert_eq!(
            classify_host("www.googletagmanager.com", &allow),
            HostClass::Allowlisted
        );
        assert_eq!(
            classify_host("static.my-agency.de", &allow),
            HostClass::Allowlisted
        );
        assert_eq!(classify_host("cdn.example.org", &allow), HostClass::Unknown);
        assert_eq!(
            classify_host("jquery-cdn.top", &allow),
            HostClass::Suspicious
        );
        assert_eq!(
            classify_host("google-analytlcs.net", &allow),
            HostClass::Suspicious
        );
        assert_eq!(classify_host("45.33.12.9", &allow), HostClass::Suspicious);
    }
}
