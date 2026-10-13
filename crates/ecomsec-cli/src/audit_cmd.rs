//! `ecomsec audit` – optional AI audit of the last scan report.

use crate::{emit, scan_options, Context_, ScanOptionArgs};
use anyhow::{bail, Context};
use clap::{Args, ValueEnum};
use ecomsec_audit::agent::{describe_call, run_audit, AuditConfig, ProgressEvent};
use ecomsec_audit::client::{AnthropicClient, DEFAULT_KEY_ENV};
use ecomsec_audit::report::{
    format_usd, merge_into_report, render_text, AuditMode, AuditReport, AuditStatus,
    LAST_AUDIT_FILE,
};
use ecomsec_audit::tools::{MysqlExecutor, OsvOnline, ToolContext};
use ecomsec_core::advisories::merge_by_id;
use ecomsec_core::Engine;
use std::io::IsTerminal;
use std::path::PathBuf;

/// Audit ended early (budget, turn limit, refusal); partial results saved.
pub const EXIT_AUDIT_ABORTED: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ModeArg {
    /// Kritische Befunde und Warnungen bewerten (Standard, günstig)
    Triage,
    /// Zusätzlich eigenen Code (Plugins, Templates, Theme-JS) auf Schwachstellen prüfen
    Hunt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AuditFormat {
    Text,
    Json,
}

#[derive(Args)]
pub struct AuditArgs {
    #[command(flatten)]
    opts: ScanOptionArgs,
    /// Audit-Modus
    #[arg(long, value_enum)]
    mode: Option<ModeArg>,
    /// Modell (Standard: claude-sonnet-5-5; für tiefe Audits claude-opus-5-5)
    #[arg(long, value_name = "MODELL")]
    model: Option<String>,
    /// Maximale Anzahl Runden (Modellaufrufe)
    #[arg(long, value_name = "N")]
    max_turns: Option<u32>,
    /// Abbruch, sobald Ein- und Ausgabe-Tokens zusammen diese Zahl überschreiten
    #[arg(long, value_name = "TOKENS")]
    max_tokens_budget: Option<u64>,
    /// Denktiefe des Modells: low, medium, high, xhigh, max
    #[arg(long, value_name = "STUFE")]
    effort: Option<String>,
    /// Vor dem Audit neu scannen, statt den gespeicherten Report zu verwenden
    #[arg(long)]
    rescan: bool,
    /// Ausgabeformat
    #[arg(short, long, value_enum, default_value_t = AuditFormat::Text)]
    format: AuditFormat,
    /// Ausgabedatei (Standard: stdout)
    #[arg(short, long, value_name = "DATEI")]
    output: Option<PathBuf>,
}

fn api_key(ctx: &Context_) -> anyhow::Result<String> {
    let var = ctx
        .cfg
        .audit
        .api_key_env
        .clone()
        .unwrap_or_else(|| DEFAULT_KEY_ENV.to_string());
    match std::env::var(&var) {
        Ok(k) if !k.trim().is_empty() => Ok(k.trim().to_string()),
        _ => bail!(
            "Kein API-Schlüssel für das KI-Audit gefunden: Die Umgebungsvariable {var} ist nicht gesetzt.\n\
             Das KI-Audit ist optional und überträgt nur redigierte Ausschnitte an die Anthropic-API.\n\
             Schlüssel setzen mit `export {var}=…` oder in ecomsec.toml unter [audit] mit api_key_env eine andere Variable angeben."
        ),
    }
}

fn config(ctx: &Context_, args: &AuditArgs) -> anyhow::Result<AuditConfig> {
    let c = &ctx.cfg.audit;
    let mode = match args.mode {
        Some(ModeArg::Triage) => AuditMode::Triage,
        Some(ModeArg::Hunt) => AuditMode::Hunt,
        None => match c.mode.as_deref().map(str::to_ascii_lowercase).as_deref() {
            None | Some("triage") => AuditMode::Triage,
            Some("hunt") => AuditMode::Hunt,
            Some(other) => bail!("[audit] mode = {other:?} ist ungültig (triage oder hunt)"),
        },
    };
    let mut cfg = AuditConfig::new(mode);
    if let Some(m) = args.model.clone().or_else(|| c.model.clone()) {
        if !m.starts_with("claude-") {
            bail!("Unbekanntes Modell {m:?} (z. B. claude-sonnet-5-5 oder claude-opus-5-5)");
        }
        cfg.model = m;
    }
    if let Some(n) = args.max_turns.or(c.max_turns) {
        if n == 0 {
            bail!("--max-turns muss mindestens 1 sein");
        }
        cfg.max_turns = n;
    }
    if let Some(b) = args.max_tokens_budget.or(c.max_tokens_budget) {
        cfg.max_tokens_budget = b;
    }
    if let Some(e) = args.effort.clone().or_else(|| c.effort.clone()) {
        let e = e.to_ascii_lowercase();
        if !matches!(e.as_str(), "low" | "medium" | "high" | "xhigh" | "max") {
            bail!("--effort {e:?} ist ungültig (low, medium, high, xhigh, max)");
        }
        cfg.effort = Some(e);
    }
    // No server-side fallback exists for the Haiku line.
    cfg.fallback = c.fallback.unwrap_or(true) && !cfg.model.starts_with("claude-haiku");
    if let Some(n) = c.hunt_max_files {
        cfg.hunt_max_files = n;
    }
    if let Some(n) = c.hunt_max_bytes {
        cfg.hunt_max_bytes = n;
    }
    Ok(cfg)
}

pub fn run(ctx: &Context_, args: AuditArgs, verbose: u8) -> anyhow::Result<u8> {
    let key = api_key(ctx)?;
    let cfg = config(ctx, &args)?;
    let options = scan_options(&args.opts, &ctx.cfg, false, &ctx.state_base)?;
    let platform = ctx.spec.open()?;
    let engine = Engine::new(&options)?;

    let report = match ctx.store.last_report() {
        Some(r) if !args.rescan => r,
        existing => {
            eprintln!(
                "{} – Scan wird ausgeführt …",
                if existing.is_none() {
                    "Kein gespeicherter Report"
                } else {
                    "Neuer Scan angefordert"
                }
            );
            engine.scan(platform.as_ref(), &ctx.store, &options)?.report
        }
    };
    if !report.summary.complete {
        eprintln!(
            "Hinweis: Der zugrunde liegende Scan ist unvollständig (Zeitbudget) – das Audit sieht nicht alle Befunde."
        );
    }

    let info = platform.info();
    let root = platform
        .file_scan_profile()
        .map(|p| p.root)
        .or_else(|| report.platform.root.clone());
    let advisories = merge_by_id(
        platform.advisories(),
        engine.extra_advisories().for_platform(&info.id),
    );
    let mut tools = ToolContext::new(report.clone(), root, &cfg.model).with_advisories(advisories);
    let mut sources = vec!["Report"];
    if tools.root().is_some() {
        sources.push("Dateien");
    }
    if !options.skip_remote {
        if let Some(creds) = platform.db_credentials() {
            tools = tools.with_sql(Box::new(MysqlExecutor::new(creds)));
            sources.push("Datenbank (nur lesend)");
        }
    }
    if options.online {
        tools = tools.with_osv(Box::new(OsvOnline::default()));
        sources.push("OSV.dev");
    }

    eprintln!(
        "KI-Audit ({}) mit {} für {} · Quellen: {} · max. {} Runden / {} Tokens",
        match cfg.mode {
            AuditMode::Triage => "triage",
            AuditMode::Hunt => "hunt",
        },
        cfg.model,
        ctx.spec.display(),
        sources.join(", "),
        cfg.max_turns,
        cfg.max_tokens_budget
    );
    eprintln!("An die Anthropic-API gehen nur redigierte Ausschnitte, die das Modell anfordert.");

    let client = AnthropicClient::new(key, ctx.cfg.audit.api_base.as_deref());
    let tty = std::io::stderr().is_terminal();
    let mut current_turn = 0;
    let mut progress = |ev: ProgressEvent<'_>| match ev {
        ProgressEvent::Turn { turn, max_turns } => {
            current_turn = turn;
            if verbose == 0 && tty {
                eprint!("\r  Runde {turn}/{max_turns} …");
            }
        }
        ProgressEvent::ToolCall { name, input } if verbose > 0 => {
            eprintln!("  [{current_turn}] {}", describe_call(name, input));
        }
        ProgressEvent::ToolResult {
            name,
            bytes,
            is_error,
        } if verbose > 1 || (verbose > 0 && is_error) => {
            eprintln!(
                "      → {name}: {:.1} KiB{}",
                bytes as f64 / 1024.0,
                if is_error { " (Fehler)" } else { "" }
            );
        }
        ProgressEvent::Usage {
            turn,
            usage,
            budget,
        } if verbose > 0 => {
            eprintln!(
                "  Runde {turn}: {} Tokens verbraucht (Budget {budget}, davon {} aus Cache)",
                usage.total_input() + usage.output_tokens,
                usage.cache_read_input_tokens
            );
        }
        _ => {}
    };
    let audit = run_audit(&client, &cfg, &mut tools, &mut progress);
    if verbose == 0 && tty {
        eprint!("\r{}\r", " ".repeat(40));
    }
    log::info!(
        "audit token usage: input {} (cache read {}, cache write {}), output {}",
        audit.usage.input_tokens,
        audit.usage.cache_read_input_tokens,
        audit.usage.cache_creation_input_tokens,
        audit.usage.output_tokens
    );

    let nothing_done = audit.verdicts.is_empty() && audit.new_findings.is_empty();
    if audit.status == AuditStatus::ApiError && nothing_done {
        bail!(
            "{}",
            audit
                .abort_reason
                .clone()
                .unwrap_or_else(|| "API-Fehler".into())
        );
    }
    persist(ctx, &report, &audit)?;

    let text = match args.format {
        AuditFormat::Text => render_text(&audit),
        AuditFormat::Json => serde_json::to_string_pretty(&audit)?,
    };
    emit(&text, args.output.as_ref())?;
    eprintln!(
        "Token-Verbrauch: {} Eingabe ({} aus Cache) / {} Ausgabe{} · {} Bewertungen, {} neue Befunde.",
        audit.tokens_in,
        audit.usage.cache_read_input_tokens,
        audit.tokens_out,
        audit
            .estimated_cost_usd
            .map(|c| format!(" · ca. {} USD", format_usd(c)))
            .unwrap_or_default(),
        audit.verdicts.len(),
        audit.new_findings.len()
    );
    match audit.status {
        AuditStatus::Completed => Ok(0),
        AuditStatus::ApiError => {
            eprintln!(
                "Fehler: {} (Teilergebnis gespeichert)",
                audit.abort_reason.as_deref().unwrap_or("API-Fehler")
            );
            Ok(crate::EXIT_ERROR)
        }
        _ => {
            eprintln!(
                "Audit vorzeitig beendet: {}",
                audit
                    .abort_reason
                    .as_deref()
                    .unwrap_or(audit.status.label())
            );
            Ok(EXIT_AUDIT_ABORTED)
        }
    }
}

/// Store `audit-<ts>.json` + `last-audit.json` and merge the verdicts into
/// the last report.
fn persist(
    ctx: &Context_,
    report: &ecomsec_core::Report,
    audit: &AuditReport,
) -> anyhow::Result<()> {
    let path = ctx
        .store
        .save_document(&audit.file_name(), audit)
        .context("Audit-Ergebnis kann nicht gespeichert werden")?;
    ctx.store
        .save_document(LAST_AUDIT_FILE, audit)
        .context("last-audit.json kann nicht gespeichert werden")?;
    let mut merged = report.clone();
    let n = merge_into_report(audit, &mut merged, &ctx.store.accepted());
    ctx.store
        .save_last_report(&merged)
        .context("Report kann nicht aktualisiert werden")?;
    eprintln!(
        "Audit gespeichert: {} ({n} Bewertungen in den Report übernommen)",
        path.display()
    );
    Ok(())
}
