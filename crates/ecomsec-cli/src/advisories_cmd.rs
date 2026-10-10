//! `ecomsec advisories …`: list, lint and update the vulnerability database.

use anyhow::Context;
use clap::Subcommand;
use ecomsec_core::AdvisoryDb;
use std::path::{Path, PathBuf};

/// Raw URL of the curated advisory files in the repository.
pub const DEFAULT_UPDATE_URL: &str =
    "https://raw.githubusercontent.com/liohtml/ecom-sec/main/advisories";
pub const FILES: &[&str] = &["jtl5.toml", "shopware6.toml", "shopify.toml"];

#[derive(Subcommand)]
pub enum AdvisoriesCommand {
    /// Alle geladenen Advisories anzeigen (eingebettet + heruntergeladen + --advisories)
    List {
        /// Nur diese Plattform
        #[arg(long)]
        platform: Option<String>,
        /// Zusätzliches Verzeichnis
        #[arg(long = "advisories", value_name = "DIR")]
        dirs: Vec<PathBuf>,
    },
    /// Advisory-Dateien syntaktisch und semantisch prüfen (für CI)
    Lint {
        /// Verzeichnis oder Datei(en); Standard: eingebettete Dateien
        paths: Vec<PathBuf>,
    },
    /// Aktuelle Advisory-Dateien aus dem Repository herunterladen
    Update {
        /// Basis-URL (Standard: GitHub-Repository, Branch main)
        #[arg(long, value_name = "URL")]
        url: Option<String>,
    },
}

/// Directory where `advisories update` stores files.
pub fn download_dir(state_base: &Path) -> PathBuf {
    state_base.join("advisories")
}

fn embedded() -> anyhow::Result<AdvisoryDb> {
    let mut db = AdvisoryDb::new();
    db.merge_toml("builtin:jtl5", ecomsec_jtl5::ADVISORIES_TOML)?;
    db.merge_toml("builtin:shopware6", ecomsec_shopware6::ADVISORIES_TOML)?;
    Ok(db)
}

pub fn run(cmd: AdvisoriesCommand, state_base: &Path, cfg_dirs: &[PathBuf]) -> anyhow::Result<u8> {
    match cmd {
        AdvisoriesCommand::List { platform, dirs } => {
            let mut db = embedded()?;
            let dl = download_dir(state_base);
            let mut sources = vec!["eingebettet".to_string()];
            for d in std::iter::once(&dl)
                .chain(cfg_dirs.iter())
                .chain(dirs.iter())
            {
                if d.is_dir() {
                    let n = db.merge_dir(d)?;
                    sources.push(format!("{} ({n})", d.display()));
                }
            }
            println!("Quellen: {}", sources.join(", "));
            println!(
                "{:<18} {:<10} {:<9} {:<11} {:<34} Behoben in",
                "ID", "Plattform", "Schwere", "Datum", "Betroffen"
            );
            for spec in db.specs() {
                if let Some(p) = &platform {
                    if &spec.platform != p {
                        continue;
                    }
                }
                let flag = if spec.withdrawn {
                    " [zurückgezogen]"
                } else if spec.draft {
                    " [Entwurf – inaktiv]"
                } else {
                    ""
                };
                println!(
                    "{:<18} {:<10} {:<9} {:<11} {:<34} {}{}",
                    spec.id,
                    spec.platform,
                    spec.severity.label_en(),
                    spec.published,
                    truncate(&spec.affected.join(", "), 34),
                    spec.fixed_in.join(", "),
                    flag
                );
                println!("{:<18} {}", "", spec.title);
            }
            println!("\n{} Advisories.", db.len());
            Ok(0)
        }
        AdvisoriesCommand::Lint { paths } => {
            let mut db = AdvisoryDb::new();
            let mut errors = 0;
            if paths.is_empty() {
                db = embedded()?;
                println!("eingebettete Dateien: {} Advisories OK", db.len());
            }
            for p in &paths {
                let result = if p.is_dir() {
                    db.merge_dir(p)
                        .map(|n| format!("{}: {n} Advisories OK", p.display()))
                } else {
                    std::fs::read_to_string(p)
                        .map_err(ecomsec_core::advisories::AdvisoryError::Io)
                        .and_then(|t| db.merge_toml(&p.display().to_string(), &t))
                        .map(|n| format!("{}: {n} Advisories OK", p.display()))
                };
                match result {
                    Ok(msg) => println!("{msg}"),
                    Err(e) => {
                        errors += 1;
                        eprintln!("FEHLER {e}");
                    }
                }
            }
            // Semantic checks: fixed_in must lie outside affected ranges.
            for spec in db.specs() {
                if let Ok(adv) = spec.to_advisory() {
                    for f in &adv.fixed_in {
                        if adv.affects(f) {
                            errors += 1;
                            eprintln!(
                                "FEHLER {}: fixed_in {f} liegt im betroffenen Bereich",
                                spec.id
                            );
                        }
                    }
                    if adv.affected.is_empty() && !spec.draft && !spec.withdrawn {
                        errors += 1;
                        eprintln!("FEHLER {}: kein betroffener Versionsbereich", spec.id);
                    }
                }
            }
            if errors > 0 {
                eprintln!("{errors} Fehler.");
                Ok(1)
            } else {
                println!("Keine Fehler.");
                Ok(0)
            }
        }
        AdvisoriesCommand::Update { url } => {
            let base = url.unwrap_or_else(|| DEFAULT_UPDATE_URL.to_string());
            let base = base.trim_end_matches('/');
            let dir = download_dir(state_base);
            std::fs::create_dir_all(&dir)?;
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .timeout_global(Some(std::time::Duration::from_secs(30)))
                .build()
                .into();
            let mut total = 0;
            for file in FILES {
                let u = format!("{base}/{file}");
                let text = agent
                    .get(&u)
                    .call()
                    .and_then(|mut r| r.body_mut().read_to_string())
                    .with_context(|| format!("Download fehlgeschlagen: {u}"))?;
                // Validate before replacing the previous file.
                let mut check = AdvisoryDb::new();
                let n = check
                    .merge_toml(file, &text)
                    .with_context(|| format!("{u} ist keine gültige Advisory-Datei"))?;
                let target = dir.join(file);
                let tmp = target.with_extension("toml.tmp");
                std::fs::write(&tmp, &text)?;
                std::fs::rename(&tmp, &target)?;
                println!("{file}: {n} Advisories → {}", target.display());
                total += n;
            }
            println!(
                "{total} Advisories aktualisiert. Sie werden bei jedem Scan automatisch geladen."
            );
            Ok(0)
        }
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
