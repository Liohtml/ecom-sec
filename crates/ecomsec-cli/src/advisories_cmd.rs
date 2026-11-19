//! `ecomsec advisories …`: list, lint and update the vulnerability database.

use anyhow::Context;
use clap::Subcommand;
use ecomsec_core::AdvisoryDb;
use std::path::{Path, PathBuf};

/// Raw URL of the curated advisory files in the repository.
pub const DEFAULT_UPDATE_URL: &str =
    "https://raw.githubusercontent.com/liohtml/ecom-sec/main/advisories";
pub const FILES: &[&str] = &[
    "jtl5.toml",
    "shopware6.toml",
    "shopify.toml",
    "woocommerce.toml",
    "magento2.toml",
];

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
    db.merge_toml("builtin:woocommerce", ecomsec_woocommerce::ADVISORIES_TOML)?;
    db.merge_toml("builtin:magento2", ecomsec_magento2::ADVISORIES_TOML)?;
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
            let files = update(state_base, url.as_deref())?;
            let mut total = 0;
            for (file, n, target, changed) in &files {
                let status = if *changed {
                    "aktualisiert"
                } else {
                    "unverändert"
                };
                println!("{file}: {n} Advisories, {status} → {}", target.display());
                total += n;
            }
            println!(
                "{total} Advisories aktualisiert. Sie werden bei jedem Scan automatisch geladen."
            );
            Ok(0)
        }
    }
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct UpdateMetadata {
    schema_version: u32,
    updated_at: String,
    files: std::collections::BTreeMap<String, FileMetadata>,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
struct FileMetadata {
    url: String,
    fetched_at: String,
    etag: Option<String>,
    last_modified: Option<String>,
    advisory_count: usize,
    not_modified_at: Option<String>,
}

fn read_metadata(path: &Path) -> UpdateMetadata {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// Download and validate the advisory files into the state directory.
/// ETag revalidation avoids replacing unchanged files. The timestamp records
/// a successful revalidation, not a claim about the upstream data's coverage.
/// Returns `(file, number of advisories, path, body changed)` per file.
pub fn update(
    state_base: &Path,
    url: Option<&str>,
) -> anyhow::Result<Vec<(&'static str, usize, PathBuf, bool)>> {
    let base = url.unwrap_or(DEFAULT_UPDATE_URL).trim_end_matches('/');
    if !cfg!(test) && !base.starts_with("https://") {
        anyhow::bail!("Advisory-Update erfordert eine HTTPS-Basis-URL");
    }
    let dir = download_dir(state_base);
    std::fs::create_dir_all(&dir)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build()
        .into();
    let metadata_path = dir.join("update-metadata.json");
    let mut metadata = read_metadata(&metadata_path);
    let now = chrono::Utc::now().to_rfc3339();
    let mut out = Vec::new();
    for file in FILES {
        let u = format!("{base}/{file}");
        let target = dir.join(file);
        let previous = metadata.files.get(*file).cloned().unwrap_or_default();
        let mut request = agent.get(&u);
        if target.is_file() {
            if let Some(etag) = previous.etag.as_deref().filter(|v| !v.is_empty()) {
                request = request.header("If-None-Match", etag);
            } else if let Some(last_modified) =
                previous.last_modified.as_deref().filter(|v| !v.is_empty())
            {
                request = request.header("If-Modified-Since", last_modified);
            }
        }
        let mut response = request
            .call()
            .with_context(|| format!("Download fehlgeschlagen: {u}"))?;
        let etag = response
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let last_modified = response
            .headers()
            .get("Last-Modified")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let not_modified = response.status().as_u16() == 304;
        let text = if not_modified {
            std::fs::read_to_string(&target)
                .with_context(|| format!("Lokale Datei fehlt: {}", target.display()))?
        } else {
            response
                .body_mut()
                .read_to_string()
                .with_context(|| format!("Download fehlgeschlagen: {u}"))?
        };
        // Validate before replacing the previous file or metadata.
        let mut check = AdvisoryDb::new();
        let n = check
            .merge_toml(file, &text)
            .with_context(|| format!("{u} ist keine gültige Advisory-Datei"))?;
        if !not_modified {
            let tmp = target.with_extension("toml.tmp");
            std::fs::write(&tmp, &text)?;
            std::fs::rename(&tmp, &target)?;
        }
        metadata.files.insert(
            (*file).to_string(),
            FileMetadata {
                url: u,
                fetched_at: if not_modified {
                    previous.fetched_at
                } else {
                    now.clone()
                },
                etag: etag.or(previous.etag),
                last_modified: last_modified.or(previous.last_modified),
                advisory_count: n,
                not_modified_at: not_modified.then(|| now.clone()),
            },
        );
        out.push((*file, n, target, !not_modified));
    }
    metadata.schema_version = 1;
    metadata.updated_at = now;
    let tmp = metadata_path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(&metadata)?)?;
    std::fs::rename(tmp, metadata_path)?;
    Ok(out)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_corrupt_metadata_falls_back_to_fresh_download() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_metadata(&dir.path().join("missing.json"))
            .files
            .is_empty());
        std::fs::write(dir.path().join("bad.json"), "not json").unwrap();
        assert!(read_metadata(&dir.path().join("bad.json")).files.is_empty());
    }

    fn local_advisory_server() -> (
        String,
        std::sync::mpsc::Receiver<Vec<u8>>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            for (index, stream) in listener.incoming().take(FILES.len() * 2).enumerate() {
                use std::io::{Read, Write};
                let mut stream = stream.unwrap();
                let mut request = [0_u8; 4096];
                let size = stream.read(&mut request).unwrap();
                tx.send(request[..size].to_vec()).unwrap();
                let file = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../advisories")
                    .join(FILES[index % FILES.len()]);
                let body = if index < FILES.len() {
                    std::fs::read_to_string(file).unwrap()
                } else {
                    String::new()
                };
                let response = if index < FILES.len() {
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"fixture\"\r\nLast-Modified: Thu, 01 Jan 2026 00:00:00 GMT\r\nConnection: close\r\n\r\n{}", body.len(), body)
                } else {
                    "HTTP/1.1 304 Not Modified\r\nETag: \"fixture\"\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        (address, rx, handle)
    }

    #[test]
    fn etags_revalidate_without_replacing_valid_local_data() {
        let (url, requests, server) = local_advisory_server();
        let dir = tempfile::tempdir().unwrap();
        let first = update(dir.path(), Some(&url)).unwrap();
        assert_eq!(first[0].0, "jtl5.toml");
        assert!(first.iter().all(|entry| entry.3));
        let target = dir.path().join("advisories/jtl5.toml");
        let before = std::fs::read_to_string(&target).unwrap();
        let second = update(dir.path(), Some(&url)).unwrap();
        assert!(second.iter().all(|entry| !entry.3));
        assert_eq!(std::fs::read_to_string(target).unwrap(), before);
        server.join().unwrap();
        let recorded: Vec<String> = requests
            .iter()
            .map(|request| String::from_utf8(request).unwrap())
            .collect();
        assert_eq!(recorded.len(), FILES.len() * 2);
        for (index, file) in FILES.iter().enumerate() {
            assert!(recorded[index].starts_with(&format!("GET /{file} ")));
            assert!(!recorded[index]
                .to_ascii_lowercase()
                .contains("if-none-match:"));
            assert!(recorded[index + FILES.len()].starts_with(&format!("GET /{file} ")));
            assert!(
                recorded[index + FILES.len()]
                    .to_ascii_lowercase()
                    .contains("if-none-match: \"fixture\""),
                "missing conditional request for {file}: {}",
                recorded[index + FILES.len()]
            );
        }
        let metadata = read_metadata(&dir.path().join("advisories/update-metadata.json"));
        assert_eq!(metadata.files.len(), FILES.len());
        assert!(metadata
            .files
            .values()
            .all(|file| file.not_modified_at.is_some()));
    }

    #[test]
    fn persisted_metadata_does_not_contain_tokens_or_response_bodies() {
        let metadata = UpdateMetadata {
            schema_version: 1,
            updated_at: "2026-01-01T00:00:00Z".into(),
            files: [(
                "jtl5.toml".into(),
                FileMetadata {
                    url: "https://example.invalid/jtl5.toml".into(),
                    fetched_at: "2026-01-01T00:00:00Z".into(),
                    etag: Some("\"tag\"".into()),
                    last_modified: None,
                    advisory_count: 2,
                    not_modified_at: None,
                },
            )]
            .into(),
        };
        let text = serde_json::to_string(&metadata).unwrap();
        let decoded: UpdateMetadata = serde_json::from_str(&text).unwrap();
        assert_eq!(decoded.files["jtl5.toml"].etag.as_deref(), Some("\"tag\""));
        assert!(!text.contains("token"));
    }
}
