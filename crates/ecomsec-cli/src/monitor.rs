//! Continuous monitoring: `ecomsec diff`, `ecomsec watch` and
//! `ecomsec notify`.
//!
//! `watch` is one monitoring run meant for cron/systemd (advisory update →
//! scan → diff against the previous run → notifications → exit code) or,
//! with `--interval`, a simple long-running loop.

use crate::config::FileConfig;
use crate::{
    advisories_cmd, build_context, scan_options, state_base, Cli, Context_, ScanOptionArgs,
    EXIT_CRITICAL, EXIT_ERROR, EXIT_WARNING,
};
use anyhow::Context;
use clap::{Args, Subcommand, ValueEnum};
use ecomsec_core::engine::parse_duration;
use ecomsec_core::{diff, Engine, ReportDiff, Severity, StateStore};
use ecomsec_notify::{Notification, Notifier, NotifyOn};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DiffFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NotifyOnArg {
    /// nur neue kritische Befunde
    Critical,
    /// neue Warnungen oder kritische Befunde
    Warning,
    /// jede Änderung (auch behobene Befunde)
    Any,
    /// nach jedem Lauf, auch ohne Änderung
    Always,
}

impl From<NotifyOnArg> for NotifyOn {
    fn from(v: NotifyOnArg) -> Self {
        match v {
            NotifyOnArg::Critical => NotifyOn::Critical,
            NotifyOnArg::Warning => NotifyOn::Warning,
            NotifyOnArg::Any => NotifyOn::Any,
            NotifyOnArg::Always => NotifyOn::Always,
        }
    }
}

#[derive(Args)]
pub struct DiffArgs {
    /// Älterer Report (JSON aus `scan --format json`). Ohne Dateien: die letzten beiden Scans des Ziels
    #[arg(value_name = "VORHER.json")]
    before: Option<PathBuf>,
    /// Neuerer Report (JSON)
    #[arg(value_name = "NACHHER.json", requires = "before")]
    after: Option<PathBuf>,
    /// Ausgabeformat
    #[arg(short, long, value_enum, default_value_t = DiffFormat::Text)]
    format: DiffFormat,
    /// Ausgabedatei (Standard: stdout)
    #[arg(short, long, value_name = "DATEI")]
    output: Option<PathBuf>,
}

impl DiffArgs {
    pub fn uses_files(&self) -> bool {
        self.before.is_some()
    }
}

#[derive(Args)]
pub struct WatchArgs {
    #[command(flatten)]
    opts: ScanOptionArgs,
    /// Wann benachrichtigt wird (überschreibt [notify] on und kanalbezogene Werte)
    #[arg(long, value_enum, value_name = "STUFE")]
    notify_on: Option<NotifyOnArg>,
    /// Nichts senden – nur anzeigen, welche Kanäle benachrichtigt würden
    #[arg(long)]
    no_notify: bool,
    /// Advisory-Datenbank vor dem Scan nicht aktualisieren
    #[arg(long)]
    no_update: bool,
    /// Basis-URL für das Advisory-Update
    #[arg(long, value_name = "URL")]
    update_url: Option<String>,
    /// Dauerbetrieb: alle DAUER erneut prüfen (z. B. 24h, 12h, 30m); Strg+C beendet
    #[arg(long, value_name = "DAUER")]
    interval: Option<String>,
    /// Ausgabeformat der Änderungen
    #[arg(short, long, value_enum, default_value_t = DiffFormat::Text)]
    format: DiffFormat,
    /// Nur Fehler ausgeben (für cron)
    #[arg(short, long)]
    quiet: bool,
    /// systemd-Service und -Timer für tägliche Prüfung ausgeben (schreibt nichts)
    #[arg(long, conflicts_with = "install_cron")]
    install_systemd: bool,
    /// Crontab-Zeile für tägliche Prüfung ausgeben (schreibt nichts)
    #[arg(long)]
    install_cron: bool,
    /// Uhrzeit für --install-systemd/--install-cron
    #[arg(long, value_name = "HH:MM", default_value = "04:17")]
    at: String,
}

#[derive(Subcommand)]
pub enum NotifyCommand {
    /// Testnachricht an alle konfigurierten Kanäle senden
    Test,
    /// Konfigurierte Benachrichtigungskanäle anzeigen (ohne Geheimnisse)
    List,
}

/// Exit code for a diff: 2 new critical, 1 new warning, else 0.
pub fn exit_code_for_diff(diff: &ReportDiff) -> u8 {
    match diff.relevance {
        Some(Severity::Critical) => EXIT_CRITICAL,
        Some(Severity::Warning) => EXIT_WARNING,
        _ => 0,
    }
}

fn render(diff: &ReportDiff, format: DiffFormat) -> anyhow::Result<String> {
    Ok(match format {
        DiffFormat::Text => diff.to_text(),
        DiffFormat::Json => serde_json::to_string_pretty(diff)?,
    })
}

// ---------------------------------------------------------------- diff

/// `ecomsec diff A.json B.json` – no target needed.
pub fn diff_files(args: &DiffArgs) -> anyhow::Result<u8> {
    let (Some(before), Some(after)) = (&args.before, &args.after) else {
        anyhow::bail!(
            "Bitte zwei Report-Dateien angeben (vorher, nachher) oder keine, um die letzten beiden Scans zu vergleichen."
        );
    };
    let load = |p: &Path| {
        StateStore::load_report(p)
            .with_context(|| format!("{} ist kein gültiger ecomsec-Report (JSON)", p.display()))
    };
    let (b, a) = (load(before)?, load(after)?);
    if b.platform.target_key() != a.platform.target_key() {
        eprintln!(
            "Hinweis: Die Reports stammen von unterschiedlichen Zielen ({} / {}).",
            b.platform.target_key(),
            a.platform.target_key()
        );
    }
    let diff = ReportDiff::compute(Some(&b), &a);
    crate::emit(&render(&diff, args.format)?, args.output.as_ref())?;
    Ok(exit_code_for_diff(&diff))
}

/// `ecomsec diff` – last scan of the target against the one before.
pub fn diff_latest(ctx: &Context_, args: &DiffArgs) -> anyhow::Result<u8> {
    let diff = diff::latest_from_store(&ctx.store).with_context(|| {
        format!(
            "Kein gespeicherter Report für {} – zuerst `ecomsec scan` ausführen.",
            ctx.spec.display()
        )
    })?;
    if diff.first_run {
        eprintln!(
            "Hinweis: Nur ein Scan vorhanden – Vergleich ab dem zweiten Scan. Angezeigt werden alle aktiven Befunde."
        );
    }
    crate::emit(&render(&diff, args.format)?, args.output.as_ref())?;
    Ok(exit_code_for_diff(&diff))
}

// ---------------------------------------------------------------- notify

fn print_deliveries(deliveries: &[ecomsec_notify::Delivery], quiet: bool) -> usize {
    let mut failed = 0;
    for d in deliveries {
        match &d.result {
            Ok(()) => {
                if !quiet {
                    eprintln!("Benachrichtigung über {}: gesendet", d.channel);
                }
            }
            Err(e) => {
                failed += 1;
                eprintln!("Benachrichtigung über {}: FEHLGESCHLAGEN – {e}", d.channel);
            }
        }
    }
    failed
}

pub fn notify(cli: &Cli, cmd: &NotifyCommand) -> anyhow::Result<u8> {
    let cfg = FileConfig::load(cli.config.as_deref())?;
    let notifier = Notifier::from_config(&cfg.notify);
    if notifier.is_empty() {
        println!(
            "Keine Benachrichtigungskanäle konfiguriert – siehe [notify] in ecomsec.example.toml und docs/MONITORING.md."
        );
        return Ok(0);
    }
    match cmd {
        NotifyCommand::List => {
            println!(
                "Standard-Schwelle: {} · {} Kanal/Kanäle",
                notifier.default_on.as_str(),
                notifier.channels.len() + notifier.invalid.len()
            );
            for c in &notifier.channels {
                println!(
                    "  {:<20} {:<13} {:<9} {}",
                    c.name,
                    c.kind.as_str(),
                    c.on.unwrap_or(notifier.default_on).as_str(),
                    c.describe()
                );
            }
            for (name, e) in &notifier.invalid {
                println!("  {name:<20} FEHLER        {e}");
            }
            Ok(if notifier.invalid.is_empty() {
                0
            } else {
                EXIT_ERROR
            })
        }
        NotifyCommand::Test => {
            // The target is optional for a test message.
            let target = build_context(cli)
                .map(|c| c.spec.display())
                .unwrap_or_else(|_| "ecomsec".into());
            let n = Notification::test(&target, &notifier.options);
            let deliveries = notifier.send_all(&n);
            let failed = print_deliveries(&deliveries, false);
            if failed > 0 {
                eprintln!("{failed} von {} Kanälen fehlgeschlagen.", deliveries.len());
                Ok(EXIT_ERROR)
            } else {
                println!(
                    "Testnachricht an {} Kanal/Kanäle gesendet.",
                    deliveries.len()
                );
                Ok(0)
            }
        }
    }
}

// ---------------------------------------------------------------- watch

static STOP: AtomicBool = AtomicBool::new(false);

pub fn watch(cli: &Cli, ctx: &Context_, args: &WatchArgs) -> anyhow::Result<u8> {
    if args.install_systemd || args.install_cron {
        let (hour, minute) = parse_time(&args.at)?;
        let cmd = schedule_command(cli, ctx, args)?;
        let text = if args.install_systemd {
            systemd_units(&cmd, hour, minute, &ctx.state_base)
        } else {
            cron_line(&cmd, hour, minute)
        };
        print!("{text}");
        return Ok(0);
    }
    let interval = args
        .interval
        .as_deref()
        .or(ctx.cfg.watch.interval.as_deref());
    let Some(interval) = interval else {
        return watch_once(ctx, args);
    };
    let every = parse_duration(interval)
        .with_context(|| format!("ungültiges Intervall {interval:?} (z. B. 24h, 30m)"))?;
    if every < Duration::from_secs(60) {
        anyhow::bail!("Das Intervall muss mindestens 1 Minute betragen.");
    }
    if let Err(e) = ctrlc::set_handler(|| {
        if STOP.swap(true, Ordering::SeqCst) {
            eprintln!("\nAbbruch.");
            std::process::exit(130);
        }
        eprintln!("\nBeende nach dem laufenden Durchlauf … (erneut Strg+C für sofortigen Abbruch)");
    }) {
        log::warn!("cannot install signal handler: {e}");
    }
    loop {
        let started = Instant::now();
        if let Err(e) = watch_once(ctx, args) {
            eprintln!("Fehler: {e:#}");
        }
        if STOP.load(Ordering::SeqCst) {
            break;
        }
        let next = chrono::Local::now()
            + chrono::Duration::from_std(every.saturating_sub(started.elapsed()))
                .unwrap_or_default();
        if !args.quiet {
            eprintln!(
                "Nächste Prüfung: {} (Strg+C beendet)",
                next.format("%d.%m.%Y %H:%M")
            );
        }
        while started.elapsed() < every && !STOP.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(500));
        }
        if STOP.load(Ordering::SeqCst) {
            break;
        }
    }
    Ok(0)
}

/// One monitoring run.
fn watch_once(ctx: &Context_, args: &WatchArgs) -> anyhow::Result<u8> {
    let cfg = &ctx.cfg;
    let notifier = Notifier::from_config(&cfg.notify);
    let override_on = args.notify_on.map(NotifyOn::from);

    // 1. Advisory update – network failures must not stop the scan.
    let update = !args.no_update && cfg.watch.update_advisories.unwrap_or(true);
    if update {
        let url = args
            .update_url
            .as_deref()
            .or(cfg.watch.update_url.as_deref());
        match advisories_cmd::update(&ctx.state_base, url) {
            Ok(files) => {
                let n: usize = files.iter().map(|(_, n, _)| n).sum();
                if !args.quiet {
                    eprintln!("Advisory-Datenbank aktualisiert ({n} Einträge).");
                }
            }
            Err(e) => {
                if !args.quiet {
                    eprintln!(
                        "Hinweis: Advisory-Update fehlgeschlagen ({e:#}) – der Scan nutzt den vorhandenen Stand."
                    );
                }
                log::info!("advisory update failed: {e:#}");
            }
        }
    }

    // 2. Scan (persisted, so the next run can compare against it).
    if !args.quiet {
        eprintln!(
            "Scan: {} (Zustand: {})",
            ctx.spec.display(),
            ctx.store.dir().display()
        );
    }
    let outcome = (|| -> anyhow::Result<ecomsec_core::ScanOutcome> {
        let options = scan_options(&args.opts, cfg, false, &ctx.state_base)?;
        let platform = ctx.spec.open()?;
        let engine = Engine::new(&options)?;
        engine.scan(platform.as_ref(), &ctx.store, &options)
    })();
    let outcome = match outcome {
        Ok(o) => o,
        Err(e) => {
            if !args.no_notify && !notifier.is_empty() {
                let n =
                    Notification::error(&ctx.spec.display(), &format!("{e:#}"), &notifier.options);
                print_deliveries(&notifier.send_all(&n), args.quiet);
            }
            return Err(e);
        }
    };
    if !outcome.complete {
        eprintln!(
            "Hinweis: Zeitbudget erschöpft – {} Dateien verbleiben. Vergleich und Benachrichtigung erfolgen nach dem nächsten vollständigen Lauf.",
            outcome.remaining_files
        );
        return Ok(0);
    }

    // 3. Diff against the previous complete run.
    let report = outcome.report;
    let before = ctx.store.previous_report(report.generated_at);
    let diff = ReportDiff::compute(before.as_ref(), &report);
    if !args.quiet {
        let text = render(&diff, args.format)?;
        let mut out = std::io::stdout().lock();
        out.write_all(text.as_bytes())?;
        if !text.ends_with('\n') {
            out.write_all(b"\n")?;
        }
        out.flush()?;
    }

    // 4. Notifications.
    let mut code = exit_code_for_diff(&diff);
    if notifier.is_empty() {
        if !args.quiet && diff.has_changes() {
            eprintln!(
                "Hinweis: Keine Benachrichtigungskanäle konfiguriert ([notify] in ecomsec.toml) – Änderungen werden nur hier angezeigt."
            );
        }
    } else if args.no_notify {
        let names: Vec<String> = notifier
            .recipients(&diff, override_on)
            .iter()
            .map(|c| format!("{} ({})", c.name, c.kind))
            .collect();
        if names.is_empty() {
            eprintln!("--no-notify: keine Benachrichtigung fällig.");
        } else {
            eprintln!(
                "--no-notify: Benachrichtigung würde gesendet an: {}",
                names.join(", ")
            );
        }
    } else {
        let deliveries = notifier.notify_diff(&diff, override_on);
        if deliveries.is_empty() && !args.quiet {
            eprintln!("Keine Benachrichtigung fällig.");
        }
        let failed = print_deliveries(&deliveries, args.quiet);
        if failed > 0 && code == 0 {
            code = EXIT_ERROR;
        }
    }
    Ok(code)
}

// ---------------------------------------------------------------- scheduling helpers

fn parse_time(s: &str) -> anyhow::Result<(u32, u32)> {
    let (h, m) = s
        .split_once(':')
        .with_context(|| format!("ungültige Uhrzeit {s:?} (HH:MM)"))?;
    let h: u32 = h.trim().parse().context("ungültige Stunde")?;
    let m: u32 = m.trim().parse().context("ungültige Minute")?;
    if h > 23 || m > 59 {
        anyhow::bail!("ungültige Uhrzeit {s:?} (HH:MM)");
    }
    Ok((h, m))
}

fn absolute(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|d| d.join(p))
                .unwrap_or_else(|_| p.to_path_buf())
        }
    })
}

/// The command line a scheduler should run: absolute binary, explicit
/// state dir/config/target and the scan options given now.
fn schedule_command(cli: &Cli, ctx: &Context_, args: &WatchArgs) -> anyhow::Result<Vec<String>> {
    let exe = std::env::current_exe()
        .map(|p| absolute(&p))
        .unwrap_or_else(|_| PathBuf::from("/usr/local/bin/ecomsec"));
    let mut cmd = vec![exe.display().to_string()];
    let config = cli.config.clone().or_else(|| {
        std::env::var_os("ECOMSEC_CONFIG")
            .map(PathBuf::from)
            .or_else(|| Some(PathBuf::from("ecomsec.toml")))
            .filter(|p| p.is_file())
    });
    if let Some(c) = config {
        cmd.push("--config".into());
        cmd.push(absolute(&c).display().to_string());
    }
    cmd.push("--state-dir".into());
    cmd.push(absolute(&state_base(cli, &ctx.cfg)).display().to_string());
    let spec = &ctx.spec;
    match (&spec.root, &spec.shop) {
        (Some(root), _) => {
            if cli.target.platform.is_some() {
                cmd.push("--platform".into());
                cmd.push(spec.platform.clone());
            }
            cmd.push("--root".into());
            cmd.push(absolute(root).display().to_string());
        }
        (None, Some(shop)) => {
            cmd.extend([
                "--platform".into(),
                spec.platform.clone(),
                "--shop".into(),
                shop.clone(),
            ]);
        }
        _ => {}
    }
    for h in &cli.target.allow_hosts {
        cmd.extend(["--allow-host".into(), h.clone()]);
    }
    if let Some(v) = &cli.target.api_version {
        cmd.extend(["--api-version".into(), v.clone()]);
    }
    cmd.push("watch".into());
    let o = &args.opts;
    if let Some(d) = o.reference_date {
        cmd.extend(["--reference-date".into(), d.to_string()]);
    }
    if let Some(t) = &o.time_budget {
        cmd.extend(["--time-budget".into(), t.clone()]);
    }
    for (flag, on) in [
        ("--no-resume", o.no_resume),
        ("--skip-files", o.skip_files),
        ("--skip-remote", o.skip_remote),
        ("--skip-baseline", o.skip_baseline),
        ("--online", o.online),
        ("--no-update", args.no_update),
    ] {
        if on {
            cmd.push(flag.into());
        }
    }
    for d in &o.rule_dirs {
        cmd.extend(["--rules".into(), absolute(d).display().to_string()]);
    }
    for e in &o.excludes {
        cmd.extend(["--exclude".into(), e.clone()]);
    }
    if let Some(m) = o.max_file_size {
        cmd.extend(["--max-file-size".into(), m.to_string()]);
    }
    for d in &o.advisory_dirs {
        cmd.extend(["--advisories".into(), absolute(d).display().to_string()]);
    }
    if let Some(u) = &args.update_url {
        cmd.extend(["--update-url".into(), u.clone()]);
    }
    if let Some(n) = args.notify_on {
        let v: NotifyOn = n.into();
        cmd.extend(["--notify-on".into(), v.as_str().into()]);
    }
    cmd.push("--quiet".into());
    Ok(cmd)
}

fn systemd_quote(arg: &str) -> String {
    let escaped = arg.replace('%', "%%");
    if !escaped.is_empty()
        && escaped
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-:=+,@".contains(c))
    {
        escaped
    } else {
        format!("\"{}\"", escaped.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn shell_quote(arg: &str) -> String {
    let quoted = if !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-:=+,@".contains(c))
    {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    };
    // `%` starts a new line in crontab entries.
    quoted.replace('%', "\\%")
}

pub fn systemd_units(cmd: &[String], hour: u32, minute: u32, state_base: &Path) -> String {
    let exec: Vec<String> = cmd.iter().map(|a| systemd_quote(a)).collect();
    let user = std::env::var("SUDO_USER")
        .ok()
        .or_else(|| std::env::var("USER").ok())
        .filter(|u| !u.is_empty() && u != "root");
    let user_line = match user {
        Some(u) => format!("User={u}"),
        None => "# User=www-data".to_string(),
    };
    format!(
        "# ---- /etc/systemd/system/ecomsec-watch.service ----\n\
[Unit]\n\
Description=ecomsec Sicherheits-Check mit Änderungsmeldung\n\
Documentation=https://github.com/liohtml/ecom-sec/blob/main/docs/MONITORING.md\n\
Wants=network-online.target\n\
After=network-online.target\n\
\n\
[Service]\n\
Type=oneshot\n\
# Benutzer mit Lesezugriff auf den Shop und Schreibzugriff auf {state}\n\
{user_line}\n\
# Geheimnisse (SMTP-Passwort, Webhook-URLs, Shopify-Token) als VAR=wert, Dateirechte 0600\n\
EnvironmentFile=-/etc/ecomsec/ecomsec.env\n\
ExecStart={exec}\n\
# Exit-Code 1/2 = neue Warnung bzw. neuer kritischer Befund – kein Fehler der Unit\n\
SuccessExitStatus=1 2\n\
Nice=10\n\
IOSchedulingClass=idle\n\
NoNewPrivileges=true\n\
PrivateTmp=true\n\
ProtectSystem=full\n\
\n\
# ---- /etc/systemd/system/ecomsec-watch.timer ----\n\
[Unit]\n\
Description=ecomsec Sicherheits-Check täglich um {hour:02}:{minute:02}\n\
\n\
[Timer]\n\
OnCalendar=*-*-* {hour:02}:{minute:02}:00\n\
RandomizedDelaySec=15min\n\
Persistent=true\n\
\n\
[Install]\n\
WantedBy=timers.target\n\
\n\
# Einrichten (als root):\n\
#   systemctl daemon-reload\n\
#   systemctl enable --now ecomsec-watch.timer\n\
#   systemctl start ecomsec-watch.service   # einmal sofort prüfen\n\
#   journalctl -u ecomsec-watch.service     # Protokoll\n",
        state = state_base.display(),
        exec = exec.join(" "),
    )
}

pub fn cron_line(cmd: &[String], hour: u32, minute: u32) -> String {
    let line: Vec<String> = cmd.iter().map(|a| shell_quote(a)).collect();
    format!(
        "# ecomsec: täglich um {hour:02}:{minute:02} prüfen, nur bei Änderungen benachrichtigen.\n\
# Mit `crontab -e` eintragen. Fehler gibt cron per Mail an MAILTO weiter.\n\
# Geheimnisse (z. B. ECOMSEC_SMTP_PASSWORD) vorher in der Crontab oder per Wrapper-Skript setzen.\n\
{minute} {hour} * * * {}\n",
        line.join(" ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_parsing() {
        assert_eq!(parse_time("04:17").unwrap(), (4, 17));
        assert_eq!(parse_time("23:59").unwrap(), (23, 59));
        assert!(parse_time("24:00").is_err());
        assert!(parse_time("4").is_err());
    }

    #[test]
    fn quoting() {
        assert_eq!(systemd_quote("/var/www/shop"), "/var/www/shop");
        assert_eq!(systemd_quote("/srv/mein shop"), "\"/srv/mein shop\"");
        assert_eq!(systemd_quote("50%"), "\"50%%\"");
        assert_eq!(shell_quote("/var/www/shop"), "/var/www/shop");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("a%b"), "'a\\%b'");
    }

    #[test]
    fn units_and_cron() {
        let cmd: Vec<String> = [
            "/usr/local/bin/ecomsec",
            "--root",
            "/srv/mein shop",
            "watch",
            "--quiet",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let units = systemd_units(&cmd, 4, 7, Path::new("/var/lib/ecomsec"));
        assert!(units
            .contains("ExecStart=/usr/local/bin/ecomsec --root \"/srv/mein shop\" watch --quiet"));
        assert!(units.contains("OnCalendar=*-*-* 04:07:00"));
        assert!(units.contains("SuccessExitStatus=1 2"));
        let cron = cron_line(&cmd, 4, 7);
        assert!(
            cron.contains("7 4 * * * /usr/local/bin/ecomsec --root '/srv/mein shop' watch --quiet")
        );
    }
}
