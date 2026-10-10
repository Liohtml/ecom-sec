pub mod html;
pub mod text;

use ecomsec_core::Report;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
    Html,
}

pub fn render(
    report: &Report,
    format: Format,
    show_all: bool,
    color: bool,
) -> anyhow::Result<String> {
    Ok(match format {
        Format::Text => text::render(report, show_all, color),
        Format::Json => serde_json::to_string_pretty(report)?,
        Format::Html => html::render_static(report)?,
    })
}
