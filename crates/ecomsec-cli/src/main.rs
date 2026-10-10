//! `ecomsec` – compromise check for e-commerce installations.

mod config;
mod output;
mod platforms;
mod web;

use anyhow::Context;
use chrono::NaiveDate;
use clap::{Args, Parser, Subcommand, ValueEnum};
use config::FileConfig;
use ecomsec_core::baseline::Baseline;
use ecomsec_core::engine::parse_duration;
use ecomsec_core::finding::FindingId;
use ecomsec_core::{Engine, Report, ScanOptions, Severity, StateStore, Verdict};
use output::Format;
use platforms::TargetSpec;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

const EXIT_WARNING: u8 = 1;
const EXIT_CRITICAL: u8 = 2;
const EXIT_ERROR: u8 = 10;

#[derive(Parser)]
#[command(
    name = "ecomsec",
    version,
    about = "Kompromittierungs-Check für Shop-Systeme (JTL-Shop 5, Shopware 6, Shopify) – read-only, ohne externe Dienste",
    long_about = None,
    propagate_version = true
)]
struct Cli {
    #[command(flatten)]
    target: TargetArgs,
    /// Konfigurationsdatei (Standard: ./ecomsec.toml oder $ECOMSEC_CONFIG)
    #[arg(long, global = true, value_name = "DATEI")]
    config: Option<PathBuf>,
    /// Verzeichnis für Zustand (Akzeptanzen, Baseline, Verlauf). Standard: $ECOMSEC_STATE_DIR / ~/.local/state/ecomsec
    #[arg(long, global = true, value_name = "DIR")]
    state_dir: Option<PathBuf>,
    /// Ausführliche Protokollierung
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Clone)]
struct TargetArgs {
    /// Plattform: auto, jtl5, shopware6, shopify
    #[arg(short, long, global = true, value_name = "ID")]
    platform: Option<String>,
    /// Webroot / Projektverzeichnis (self-hosted)
    #[arg(short, long, global = true, value_name = "PFAD")]
    root: Option<PathBuf>,
    /// Shopify Shop-Domain (my-store.myshopify.com)
    #[arg(long, global = true, env = "SHOPIFY_SHOP")]
    shop: Option<String>,
    /// Shopify Admin-API-Token (nur Lese-Scopes nötig)
    #[arg(
        long,
        global = true,
        env = "SHOPIFY_ACCESS_TOKEN",
        hide_env_values = true
    )]
    token: Option<String>,
    /// Shopify API-Version
    #[arg(long, global = true, value_name = "YYYY-MM")]
    api_version: Option<String>,
    /// Zusätzlicher vertrauenswürdiger Host (Shopify Script-Tags/Webhooks/Theme), mehrfach möglich
    #[arg(long = "allow-host", global = true, value_name = "HOST")]
    allow_hosts: Vec<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Vollständigen Scan ausführen (Dateien, Integrität, Datenbank/API)
    Scan(ScanArgs),
    /// Befunde des letzten Scans anzeigen und triagieren
    Findings {
        #[command(subcommand)]
        command: FindingsCommand,
    },
    /// Integritäts-Baseline (Hash-Manifest der Kerndateien)
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    /// Letzten Report erneut ausgeben
    Report(ReportArgs),
    /// Scan-Verlauf anzeigen
    History,
    /// Unterstützte Plattformen auflisten
    Platforms,
    /// Eingebaute Signaturen und Regeln anzeigen
    Rules {
        /// Nur Regeln mit diesem Tag
        #[arg(long)]
        tag: Option<String>,
    },
    /// Lokales Web-Dashboard starten
    Serve(ServeArgs),
}

#[derive(Args, Clone)]
struct ScanOptionArgs {
    /// Referenzdatum (YYYY-MM-DD); Dateien ab diesem Datum gelten als neu/geändert. Standard: 2026-06-17
    #[arg(long, value_name = "DATUM")]
    reference_date: Option<NaiveDate>,
    /// Zeitbudget für den Dateiscan (z. B. 45s, 2m); bei Ablauf wird ein Checkpoint gespeichert
    #[arg(long, value_name = "DAUER")]
    time_budget: Option<String>,
    /// Nicht an einem Checkpoint fortsetzen, sondern neu beginnen
    #[arg(long)]
    no_resume: bool,
    /// Dateiscan überspringen
    #[arg(long)]
    skip_files: bool,
    /// Datenbank-/API-Prüfungen überspringen
    #[arg(long)]
    skip_remote: bool,
    /// Baseline-Vergleich überspringen
    #[arg(long)]
    skip_baseline: bool,
    /// Zusätzliches Regelverzeichnis (*.toml), mehrfach möglich
    #[arg(long = "rules", value_name = "DIR")]
    rule_dirs: Vec<PathBuf>,
    /// Relatives Verzeichnis vom Dateiscan ausschließen, mehrfach möglich
    #[arg(long = "exclude", value_name = "REL")]
    excludes: Vec<String>,
    /// Maximale Dateigröße für die Inhaltsprüfung in Bytes
    #[arg(long)]
    max_file_size: Option<u64>,
}

#[derive(Args)]
struct ScanArgs {
    #[command(flatten)]
    opts: ScanOptionArgs,
    /// Ausgabeformat
    #[arg(short, long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Ausgabedatei (Standard: stdout)
    #[arg(short, long, value_name = "DATEI")]
    output: Option<PathBuf>,
    /// Exit-Code ≠ 0 ab diesem Schweregrad (für CI/Cron)
    #[arg(long, value_enum, default_value_t = FailOn::Critical)]
    fail_on: FailOn,
    /// Auch Hinweise und unbedenkliche Befunde anzeigen (Textausgabe)
    #[arg(long)]
    all: bool,
    /// Keine Farben
    #[arg(long)]
    no_color: bool,
    /// Report/Verlauf nicht speichern
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args)]
struct ReportArgs {
    #[arg(short, long, value_enum, default_value_t = Format::Text)]
    format: Format,
    #[arg(short, long, value_name = "DATEI")]
    output: Option<PathBuf>,
    #[arg(long)]
    all: bool,
    #[arg(long)]
    no_color: bool,
}

#[derive(Args)]
struct ServeArgs {
    #[command(flatten)]
    opts: ScanOptionArgs,
    /// Adresse (Standard 127.0.0.1:8787)
    #[arg(long, value_name = "HOST:PORT")]
    bind: Option<String>,
    /// Zugriffstoken für Dashboard/API (Header X-Auth-Token oder ?token=)
    #[arg(long, value_name = "TOKEN")]
    auth_token: Option<String>,
}

#[derive(Subcommand)]
enum FindingsCommand {
    /// Befunde auflisten
    List {
        #[arg(long)]
        all: bool,
        /// Nur dieser Schweregrad
        #[arg(long, value_enum)]
        severity: Option<SeverityArg>,
    },
    /// Befunde als unbedenklich markieren (bleibt über Scans erhalten)
    Accept {
        /// Befund-IDs
        ids: Vec<String>,
        /// Alle Befunde in diesem Verzeichnis (relativ)
        #[arg(long, value_name = "DIR")]
        group: Option<String>,
        /// Alle Befunde dieser Regel
        #[arg(long, value_name = "REGEL")]
        rule: Option<String>,
        /// Begründung
        #[arg(long)]
        reason: Option<String>,
    },
    /// Markierung aufheben
    Unaccept {
        ids: Vec<String>,
        /// Alle Markierungen aufheben
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum BaselineCommand {
    /// Baseline erzeugen (nach verifiziertem Zustand)
    Create {
        /// Nur Kernverzeichnisse (ohne Plugins/Templates)
        #[arg(long)]
        core_only: bool,
    },
    /// Aktuellen Stand mit der Baseline vergleichen
    Diff,
    /// Baseline-Informationen anzeigen
    Show,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FailOn {
    Never,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SeverityArg {
    Critical,
    Warning,
    Info,
}

struct Context_ {
    cfg: FileConfig,
    spec: TargetSpec,
    store: StateStore,
}

fn main() -> ExitCode {
    // Behave like a normal unix tool when stdout is closed early (`| head`).
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = Cli::parse();
    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
        .format_timestamp(None)
        .init();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("Fehler: {e:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn build_context(cli: &Cli) -> anyhow::Result<Context_> {
    let cfg = FileConfig::load(cli.config.as_deref())?;
    let t = &cli.target;
    let spec = TargetSpec::resolve(
        t.platform.as_deref(),
        t.root.as_deref(),
        t.shop.as_deref(),
        t.token.as_deref(),
        t.api_version.as_deref(),
        &t.allow_hosts,
        &cfg,
    )?;
    let base = cli
        .state_dir
        .clone()
        .or_else(|| cfg.state.dir.clone())
        .unwrap_or_else(StateStore::default_base);
    let store = StateStore::for_target(&base, &spec.platform, &spec.state_key());
    Ok(Context_ { cfg, spec, store })
}

fn scan_options(
    args: &ScanOptionArgs,
    cfg: &FileConfig,
    dry_run: bool,
) -> anyhow::Result<ScanOptions> {
    let mut o = ScanOptions::default();
    if let Some(d) = args.reference_date.or_else(|| {
        cfg.scan
            .reference_date
            .as_deref()
            .and_then(|s| s.parse().ok())
    }) {
        o.reference_date = d;
    }
    if let Some(tb) = args
        .time_budget
        .as_deref()
        .or(cfg.scan.time_budget.as_deref())
    {
        o.time_budget = Some(
            parse_duration(tb)
                .with_context(|| format!("ungültiges Zeitbudget {tb:?} (z. B. 45s, 2m)"))?,
        );
    }
    o.resume = !args.no_resume;
    o.skip_files = args.skip_files;
    o.skip_remote = args.skip_remote;
    o.skip_baseline = args.skip_baseline;
    o.extra_rule_dirs = cfg
        .scan
        .rule_dirs
        .iter()
        .cloned()
        .chain(args.rule_dirs.iter().cloned())
        .collect();
    o.extra_excludes = cfg
        .scan
        .exclude
        .iter()
        .cloned()
        .chain(args.excludes.iter().cloned())
        .collect();
    if let Some(m) = args.max_file_size.or(cfg.scan.max_file_size) {
        o.max_file_size = m;
    }
    o.no_persist = dry_run;
    Ok(o)
}

fn use_color(no_color: bool) -> bool {
    !no_color && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

fn emit(text: &str, output: Option<&PathBuf>) -> anyhow::Result<()> {
    match output {
        Some(p) => {
            std::fs::write(p, text)
                .with_context(|| format!("kann {} nicht schreiben", p.display()))?;
            eprintln!("Report geschrieben: {}", p.display());
        }
        None => {
            let mut out = std::io::stdout().lock();
            out.write_all(text.as_bytes())?;
            if !text.ends_with('\n') {
                out.write_all(b"\n")?;
            }
        }
    }
    Ok(())
}

fn exit_code_for(report: &Report, fail_on: FailOn) -> u8 {
    match (report.verdict, fail_on) {
        (_, FailOn::Never) => 0,
        (Verdict::Critical, _) => EXIT_CRITICAL,
        (Verdict::Warning, FailOn::Warning) => EXIT_WARNING,
        _ => 0,
    }
}

fn last_report(ctx: &Context_) -> anyhow::Result<Report> {
    ctx.store.last_report().with_context(|| {
        format!(
            "Kein gespeicherter Report für {} – zuerst `ecomsec scan` ausführen.",
            ctx.spec.display()
        )
    })
}

fn run(cli: Cli) -> anyhow::Result<u8> {
    match &cli.command {
        Command::Platforms => {
            println!("{:<10} {:<12} {:<36} Prüfungen", "ID", "Name", "Art");
            for p in platforms::PLATFORMS {
                println!(
                    "{:<10} {:<12} {:<36} {}",
                    p.id, p.name, p.kind, p.description
                );
            }
            println!("\nErkennung: `ecomsec scan --root <PFAD>` erkennt JTL-Shop 5 und Shopware 6 automatisch; Shopify über --shop/--token.");
            return Ok(0);
        }
        Command::Rules { tag } => {
            let engine = Engine::new(&ScanOptions::default())?;
            let mut rules = engine.rules().clone();
            rules.extend(
                ecomsec_jtl5::Jtl5::open(".")
                    .map(|j| ecomsec_core::Platform::rules(&j))
                    .unwrap_or_default(),
            );
            rules.extend(ecomsec_core::RuleSet::from_toml(
                "jtl5",
                ecomsec_jtl5::RULES_TOML,
            )?);
            rules.extend(ecomsec_core::RuleSet::from_toml(
                "shopware6",
                ecomsec_shopware6::RULES_TOML,
            )?);
            println!("IOC-Dateinamen: {} Einträge", engine.iocs().len());
            for e in engine.iocs().iter() {
                println!("  [{}] {}", e.spec.severity.label_en(), e.spec.name);
            }
            println!("\nInhaltsregeln: {}", rules.len());
            let mut seen = std::collections::HashSet::new();
            for r in rules.iter() {
                if !seen.insert(r.name().to_string()) {
                    continue;
                }
                if let Some(t) = tag {
                    if !r.spec.tags.iter().any(|x| x == t) {
                        continue;
                    }
                }
                println!(
                    "  [{}] {:<42} {:<28} {}",
                    r.spec.severity.label_en(),
                    r.name(),
                    r.spec.tags.join(","),
                    r.spec.description
                );
            }
            return Ok(0);
        }
        _ => {}
    }

    let ctx = build_context(&cli)?;
    match cli.command {
        Command::Scan(args) => {
            let options = scan_options(&args.opts, &ctx.cfg, args.dry_run)?;
            let platform = ctx.spec.open()?;
            let engine = Engine::new(&options)?;
            let show_progress = args.format == Format::Text
                && args.output.is_none()
                && std::io::stderr().is_terminal();
            let progress: Option<ecomsec_core::engine::file_scan::ProgressFn> = if show_progress {
                Some(Box::new(|done, total| {
                    eprint!("\r  Dateiscan {done}/{total} …");
                    if done == total {
                        eprint!("\r{}\r", " ".repeat(40));
                    }
                }))
            } else {
                None
            };
            eprintln!(
                "Scan: {} (Zustand: {})",
                ctx.spec.display(),
                ctx.store.dir().display()
            );
            let outcome =
                engine.scan_with_progress(platform.as_ref(), &ctx.store, &options, progress)?;
            let text = output::render(
                &outcome.report,
                args.format,
                args.all,
                use_color(args.no_color),
            )?;
            emit(&text, args.output.as_ref())?;
            if !outcome.complete {
                eprintln!(
                    "Hinweis: Zeitbudget erschöpft – {} Dateien verbleiben. Erneut `ecomsec scan` ausführen, um fortzusetzen.",
                    outcome.remaining_files
                );
            }
            Ok(exit_code_for(&outcome.report, args.fail_on))
        }
        Command::Report(args) => {
            let report = last_report(&ctx)?;
            let text = output::render(&report, args.format, args.all, use_color(args.no_color))?;
            emit(&text, args.output.as_ref())?;
            Ok(0)
        }
        Command::Findings { command } => findings(&ctx, command),
        Command::Baseline { command } => baseline(&ctx, command),
        Command::History => {
            let h = ctx.store.history();
            if h.is_empty() {
                println!("Noch kein Scan-Verlauf für {}.", ctx.spec.display());
                return Ok(0);
            }
            println!(
                "{:<22} {:<12} {:<10} {:>8} {:>9} {:>8} {:>8}",
                "Zeitpunkt (UTC)",
                "Version",
                "Ergebnis",
                "kritisch",
                "Warnungen",
                "Hinweise",
                "Dateien"
            );
            for e in h.iter().rev().take(50) {
                println!(
                    "{:<22} {:<12} {:<10} {:>8} {:>9} {:>8} {:>8}{}",
                    e.generated_at.format("%Y-%m-%d %H:%M:%S"),
                    e.version.clone().unwrap_or_default(),
                    format!("{:?}", e.verdict).to_lowercase(),
                    e.critical,
                    e.warning,
                    e.info,
                    e.files_scanned,
                    if e.complete { "" } else { "  (unvollständig)" }
                );
            }
            Ok(0)
        }
        Command::Serve(args) => {
            let options = scan_options(&args.opts, &ctx.cfg, false)?;
            let bind: std::net::SocketAddr = args
                .bind
                .as_deref()
                .or(ctx.cfg.serve.bind.as_deref())
                .unwrap_or("127.0.0.1:8787")
                .parse()
                .context("ungültige --bind Adresse")?;
            let token = args.auth_token.or_else(|| ctx.cfg.serve.token.clone());
            if !bind.ip().is_loopback() && token.is_none() {
                eprintln!("WARNUNG: Dashboard ist ohne --auth-token auf {bind} erreichbar.");
            }
            // Validate the target once so configuration errors surface immediately.
            let _ = ctx.spec.open()?;
            web::serve(bind, token, ctx.spec, options, ctx.store)?;
            Ok(0)
        }
        Command::Platforms | Command::Rules { .. } => unreachable!(),
    }
}

fn findings(ctx: &Context_, command: FindingsCommand) -> anyhow::Result<u8> {
    match command {
        FindingsCommand::List { all, severity } => {
            let report = last_report(ctx)?;
            let sev = severity.map(|s| match s {
                SeverityArg::Critical => Severity::Critical,
                SeverityArg::Warning => Severity::Warning,
                SeverityArg::Info => Severity::Info,
            });
            let mut n = 0;
            for f in report.sorted_findings() {
                if !all && (f.accepted || f.severity == Severity::Info) {
                    continue;
                }
                if let Some(s) = sev {
                    if f.severity != s {
                        continue;
                    }
                }
                n += 1;
                println!(
                    "{:<16} {:<8} {:<30} {:<40} {}{}",
                    f.id,
                    f.severity.label_en(),
                    truncate(&f.rule, 30),
                    truncate(&f.subject, 40),
                    f.title,
                    if f.accepted { "  [unbedenklich]" } else { "" }
                );
            }
            println!(
                "\n{n} Befunde (Report vom {}).",
                report.generated_at.format("%d.%m.%Y %H:%M UTC")
            );
            Ok(0)
        }
        FindingsCommand::Accept {
            ids,
            group,
            rule,
            reason,
        } => {
            let report = ctx.store.last_report();
            let mut targets: Vec<(FindingId, String)> = Vec::new();
            for id in ids {
                let subject = report
                    .as_ref()
                    .and_then(|r| r.find(&id))
                    .map(|f| f.subject.clone())
                    .unwrap_or_default();
                targets.push((FindingId(id), subject));
            }
            if group.is_some() || rule.is_some() {
                let report = report.as_ref().context(
                    "Für --group/--rule wird ein gespeicherter Report benötigt (zuerst scannen).",
                )?;
                for f in &report.findings {
                    let g_ok = group
                        .as_ref()
                        .map(|g| f.group.as_deref() == Some(g.trim_end_matches('/')))
                        .unwrap_or(true);
                    let r_ok = rule.as_ref().map(|r| &f.rule == r).unwrap_or(true);
                    if g_ok && r_ok && !f.accepted {
                        targets.push((f.id.clone(), f.subject.clone()));
                    }
                }
            }
            if targets.is_empty() {
                anyhow::bail!("Keine Befunde angegeben (IDs, --group oder --rule).");
            }
            for (id, subject) in &targets {
                ctx.store.accept(id.clone(), subject, reason.clone())?;
            }
            if let Some(mut r) = report {
                r.reapply_acceptance(&ctx.store.accepted());
                ctx.store.save_last_report(&r)?;
            }
            println!("{} Befund(e) als unbedenklich markiert.", targets.len());
            Ok(0)
        }
        FindingsCommand::Unaccept { ids, all } => {
            let mut n = 0;
            if all {
                n = ctx.store.accepted().findings.len();
                ctx.store.clear_accepted()?;
            } else {
                for id in ids {
                    if ctx.store.unaccept(&FindingId(id))? {
                        n += 1;
                    }
                }
            }
            if let Some(mut r) = ctx.store.last_report() {
                r.reapply_acceptance(&ctx.store.accepted());
                ctx.store.save_last_report(&r)?;
            }
            println!("{n} Markierung(en) aufgehoben.");
            Ok(0)
        }
    }
}

fn baseline(ctx: &Context_, command: BaselineCommand) -> anyhow::Result<u8> {
    let platform = ctx.spec.open()?;
    let profile = platform
        .file_scan_profile()
        .context("Diese Plattform hat kein Dateisystem – keine Baseline möglich.")?;
    match command {
        BaselineCommand::Create { core_only } => {
            let info = platform.info();
            let b = Baseline::create(
                &profile,
                &info.id,
                info.version.map(|v| v.to_string()),
                core_only,
            )?;
            ctx.store.save_baseline(&b)?;
            println!(
                "Baseline mit {} Dateien gespeichert ({}).",
                b.files.len(),
                ctx.store.dir().display()
            );
            Ok(0)
        }
        BaselineCommand::Diff => {
            let b = ctx
                .store
                .baseline()
                .context("Keine Baseline vorhanden – `ecomsec baseline create`.")?;
            let d = b.diff(&profile)?;
            println!(
                "Baseline vom {} ({} Dateien)",
                b.created_at.format("%d.%m.%Y %H:%M UTC"),
                b.files.len()
            );
            for (label, list) in [
                ("GEÄNDERT", &d.changed),
                ("FEHLT", &d.missing),
                ("NEU", &d.added),
            ] {
                for p in list {
                    println!("  {label:<9} {p}");
                }
            }
            println!(
                "{} geändert, {} fehlend, {} neu",
                d.changed.len(),
                d.missing.len(),
                d.added.len()
            );
            Ok(if d.changed.is_empty() && d.missing.is_empty() {
                0
            } else {
                EXIT_WARNING
            })
        }
        BaselineCommand::Show => match ctx.store.baseline() {
            Some(b) => {
                println!(
                    "Baseline: {} Dateien, erstellt {}, Version {}, Root {}",
                    b.files.len(),
                    b.created_at.format("%d.%m.%Y %H:%M UTC"),
                    b.version.unwrap_or_default(),
                    b.root
                );
                Ok(0)
            }
            None => {
                println!("Keine Baseline vorhanden.");
                Ok(0)
            }
        },
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n - 1).collect();
        t.push('…');
        t
    }
}
