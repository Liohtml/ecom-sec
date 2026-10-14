//! HTML output.  The static export (`--format html`) embeds the report JSON
//! into the self-contained `app.html`; the web dashboard (`ecomsec serve`)
//! is a separate app in `assets/app/` that fetches its data from `/api/*`.

use ecomsec_core::Report;

pub const APP_HTML: &str = include_str!("../../assets/app.html");

/// Dashboard shell, stylesheet and script (served by `ecomsec serve`).
pub const WEB_INDEX_HTML: &str = include_str!("../../assets/app/index.html");
pub const WEB_APP_CSS: &str = include_str!("../../assets/app/app.css");
pub const WEB_APP_JS: &str = include_str!("../../assets/app/app.js");

/// Render the app with the report embedded (no server interaction).
pub fn render_static(report: &Report) -> anyhow::Result<String> {
    let json = serde_json::to_string(report)?
        .replace("</script", "<\\/script")
        .replace("<!--", "<\\!--");
    Ok(APP_HTML
        .replace("\"__MODE__\"", "\"static\"")
        .replace("__REPORT_JSON__", &json))
}

/// Render the dashboard shell (data is fetched from `/api/*`).
pub fn render_web() -> String {
    WEB_INDEX_HTML.replace("__VERSION__", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_shell_references_assets_and_version() {
        let html = render_web();
        assert!(html.contains("app.css"));
        assert!(html.contains("app.js"));
        assert!(!html.contains("__VERSION__"));
        assert!(html.contains(env!("CARGO_PKG_VERSION")));
        // No external resources: the dashboard must work offline.
        for asset in [html.as_str(), WEB_APP_CSS, WEB_APP_JS] {
            assert!(!asset.contains("http://"), "external http reference");
            assert!(!asset.contains("src=\"https://"), "external script");
            assert!(!asset.contains("@import"), "css import");
        }
    }
}
