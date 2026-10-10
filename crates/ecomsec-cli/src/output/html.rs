//! Self-contained HTML report.  The same single-page app is used by the web
//! dashboard; for static export the report JSON is embedded.

use ecomsec_core::Report;

pub const APP_HTML: &str = include_str!("../../assets/app.html");

/// Render the app with the report embedded (no server interaction).
pub fn render_static(report: &Report) -> anyhow::Result<String> {
    let json = serde_json::to_string(report)?
        .replace("</script", "<\\/script")
        .replace("<!--", "<\\!--");
    Ok(APP_HTML
        .replace("\"__MODE__\"", "\"static\"")
        .replace("__REPORT_JSON__", &json))
}

/// Render the app in web mode (report is fetched from `/api/report`).
pub fn render_web() -> String {
    APP_HTML
        .replace("\"__MODE__\"", "\"web\"")
        .replace("__REPORT_JSON__", "null")
}
