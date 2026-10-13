//! `ecomsec self-update`: replace the running binary with the latest GitHub
//! release.
//!
//! This is (together with `--online` and `advisories update`) one of the few
//! places where ecomsec talks to the network.  It never touches a shop.
//!
//! Flow: query `releases/latest`, compare the tag with `CARGO_PKG_VERSION`,
//! download the archive for the running platform plus `SHA256SUMS`, verify
//! the checksum, extract the binary next to the current one and swap it in
//! atomically (`rename`).  Windows cannot overwrite a running executable, so
//! the old binary is first renamed to `ecomsec.exe.old`.
//!
//! Release asset layout (see `.github/workflows/release.yml`):
//! `ecomsec-<tag>-<target>.tar.gz` (`.zip` on Windows) containing
//! `ecomsec-<tag>-<target>/ecomsec[.exe]`, plus `SHA256SUMS`.

use anyhow::{bail, Context};
use serde::Deserialize;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Repository URL from `Cargo.toml` (`workspace.package.repository`).
pub const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_DOWNLOAD: u64 = 200 * 1024 * 1024;

#[derive(clap::Args, Debug)]
pub struct SelfUpdateArgs {
    /// Nur prüfen, ob ein Update verfügbar ist (Exit-Code 1, wenn ja)
    #[arg(long)]
    pub check: bool,
    /// Auch installieren, wenn die Version gleich ist (Neuinstallation)
    #[arg(long)]
    pub force: bool,
}

/// `owner/repo` from a GitHub URL.
pub fn github_slug(url: &str) -> Option<String> {
    let url = url.trim().trim_end_matches('/');
    let url = url.strip_suffix(".git").unwrap_or(url);
    let rest = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))?;
    let mut parts = rest.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    if owner.is_empty() || repo.is_empty() || parts.next().is_some() {
        return None;
    }
    Some(format!("{owner}/{repo}"))
}

/// Release target triple matching the running binary.  Linux always maps to
/// the static musl build, which runs on every distribution.
pub fn current_target() -> Option<&'static str> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("x86_64-unknown-linux-musl")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Some("aarch64-unknown-linux-musl")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some("x86_64-apple-darwin")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("aarch64-apple-darwin")
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Some("x86_64-pc-windows-msvc")
    } else {
        None
    }
}

/// Archive name of a release asset.
pub fn asset_name(tag: &str, target: &str) -> String {
    let ext = if target.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    format!("ecomsec-{tag}-{target}.{ext}")
}

/// Semantic version (`v1.2.3`, `1.2.3-rc.1`, `1.2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    pub nums: [u64; 3],
    pub pre: Vec<String>,
}

impl SemVer {
    pub fn parse(s: &str) -> Option<SemVer> {
        let s = s.trim().trim_start_matches(['v', 'V']);
        let s = s.split('+').next()?; // build metadata is ignored
        let (core, pre) = match s.split_once('-') {
            Some((c, p)) => (c, p.split('.').map(str::to_string).collect()),
            None => (s, Vec::new()),
        };
        let mut nums = [0u64; 3];
        let mut n = 0;
        for (i, part) in core.split('.').enumerate() {
            if i >= 3 {
                return None;
            }
            nums[i] = part.parse().ok()?;
            n += 1;
        }
        if n == 0 {
            return None;
        }
        Some(SemVer { nums, pre })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        self.nums.cmp(&other.nums).then_with(|| {
            // A release is newer than any of its pre-releases.
            match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (a, b) in self.pre.iter().zip(&other.pre) {
                        let o = match (a.parse::<u64>(), b.parse::<u64>()) {
                            (Ok(x), Ok(y)) => x.cmp(&y),
                            (Ok(_), Err(_)) => Ordering::Less,
                            (Err(_), Ok(_)) => Ordering::Greater,
                            _ => a.cmp(b),
                        };
                        if o != Ordering::Equal {
                            return o;
                        }
                    }
                    self.pre.len().cmp(&other.pre.len())
                }
            }
        })
    }
}

/// `true` if `latest` is newer than `current`.  Unparseable versions never
/// trigger an update.
pub fn is_newer(latest: &str, current: &str) -> bool {
    match (SemVer::parse(latest), SemVer::parse(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

/// Parse a `sha256sum` style file (`<hash>  <name>` or `<hash> *<name>`).
pub fn parse_sha256sums(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let (hash, name) = l.trim().split_once(char::is_whitespace)?;
            let name = name.trim().trim_start_matches('*');
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            Some((name.to_string(), hash.to_ascii_lowercase()))
        })
        .collect()
}

/// Verify `bytes` against the checksum list.
pub fn verify_checksum(
    sums: &BTreeMap<String, String>,
    name: &str,
    bytes: &[u8],
) -> anyhow::Result<()> {
    let expected = sums
        .get(name)
        .with_context(|| format!("SHA256SUMS enthält keinen Eintrag für {name}"))?;
    let actual = ecomsec_core::util::sha256_hex(bytes);
    if &actual != expected {
        bail!("Prüfsumme von {name} stimmt nicht: erwartet {expected}, erhalten {actual} – Update abgebrochen");
    }
    Ok(())
}

fn binary_name() -> &'static str {
    if cfg!(windows) {
        "ecomsec.exe"
    } else {
        "ecomsec"
    }
}

/// Extract the `ecomsec` binary from a release archive.
pub fn extract_binary(archive_name: &str, bytes: &[u8], binary: &str) -> anyhow::Result<Vec<u8>> {
    let is_binary = |p: &Path| p.file_name().and_then(|n| n.to_str()) == Some(binary);
    if archive_name.ends_with(".zip") {
        let mut zip =
            zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("ZIP-Archiv ungültig")?;
        for i in 0..zip.len() {
            let mut file = zip.by_index(i)?;
            let Some(path) = file.enclosed_name() else {
                continue;
            };
            if file.is_file() && is_binary(&path) {
                let mut out = Vec::with_capacity(file.size() as usize);
                file.read_to_end(&mut out)?;
                return Ok(out);
            }
        }
    } else {
        let gz = flate2::read::GzDecoder::new(bytes);
        let mut tar = tar::Archive::new(gz);
        for entry in tar.entries().context("tar.gz-Archiv ungültig")? {
            let mut entry = entry?;
            let path = entry.path()?.into_owned();
            if entry.header().entry_type().is_file() && is_binary(&path) {
                let mut out = Vec::new();
                entry.read_to_end(&mut out)?;
                return Ok(out);
            }
        }
    }
    bail!("{binary} nicht im Archiv {archive_name} gefunden")
}

/// Write `new` next to `exe` and swap it in.  On Unix `rename` replaces the
/// file atomically; on Windows the running binary is moved aside to
/// `<exe>.old` first (and restored if the swap fails).
pub fn replace_binary(exe: &Path, new: &[u8]) -> anyhow::Result<()> {
    let dir = exe
        .parent()
        .context("Verzeichnis des Programms nicht ermittelbar")?;
    let tmp = dir.join(format!(".ecomsec-update-{}.tmp", std::process::id()));
    std::fs::write(&tmp, new).map_err(|e| permission_hint(e, dir))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(exe)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o755)
            | 0o111;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    }
    let result = if cfg!(windows) {
        let old = old_path(exe);
        let _ = std::fs::remove_file(&old);
        std::fs::rename(exe, &old).and_then(|_| {
            std::fs::rename(&tmp, exe).inspect_err(|_| {
                let _ = std::fs::rename(&old, exe);
            })
        })
    } else {
        std::fs::rename(&tmp, exe)
    };
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(permission_hint(e, dir));
    }
    Ok(())
}

fn old_path(exe: &Path) -> PathBuf {
    let mut s = exe.as_os_str().to_owned();
    s.push(".old");
    PathBuf::from(s)
}

fn permission_hint(e: std::io::Error, dir: &Path) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        anyhow::anyhow!(
            "Keine Schreibrechte in {} – Update mit Administratorrechten (z. B. sudo) ausführen oder ecomsec per install.sh in ein eigenes Verzeichnis installieren.",
            dir.display()
        )
    } else {
        anyhow::anyhow!("Binary kann nicht ersetzt werden ({}): {e}", dir.display())
    }
}

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .http_status_as_error(false)
        .build()
        .into()
}

fn get(agent: &ureq::Agent, url: &str, accept: &str) -> anyhow::Result<Vec<u8>> {
    let mut req = agent
        .get(url)
        .header("User-Agent", concat!("ecomsec/", env!("CARGO_PKG_VERSION")))
        .header("Accept", accept);
    if url.starts_with("https://api.github.com/") {
        if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            if !token.is_empty() {
                req = req.header("Authorization", format!("Bearer {token}"));
            }
        }
    }
    let mut resp = req
        .call()
        .with_context(|| format!("Anfrage an {url} fehlgeschlagen"))?;
    let status = resp.status().as_u16();
    if status == 404 {
        bail!("Nicht gefunden (HTTP 404): {url}");
    }
    if status == 403 || status == 429 {
        bail!("GitHub-Ratenlimit erreicht (HTTP {status}) – später erneut versuchen oder GITHUB_TOKEN setzen.");
    }
    if !(200..300).contains(&status) {
        bail!("HTTP {status} für {url}");
    }
    resp.body_mut()
        .with_config()
        .limit(MAX_DOWNLOAD)
        .read_to_vec()
        .with_context(|| format!("Download von {url} abgebrochen"))
}

/// Run the command.  Returns the process exit code.
pub fn run(args: &SelfUpdateArgs) -> anyhow::Result<u8> {
    let slug = github_slug(REPOSITORY)
        .with_context(|| format!("Repository-URL {REPOSITORY:?} ist keine GitHub-URL"))?;
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("Pfad des laufenden Programms nicht ermittelbar")?;
    if cfg!(windows) {
        let _ = std::fs::remove_file(old_path(&exe));
    }
    let agent = agent();
    let api = format!("https://api.github.com/repos/{slug}/releases/latest");
    let release: Release =
        serde_json::from_slice(&get(&agent, &api, "application/vnd.github+json")?)
            .context("Antwort der GitHub-API ungültig")?;
    let latest = release.tag_name.trim_start_matches(['v', 'V']).to_string();
    let newer = is_newer(&release.tag_name, CURRENT_VERSION);
    println!("Installiert: {CURRENT_VERSION}");
    println!(
        "Aktuell:     {latest}{}",
        if release.html_url.is_empty() {
            String::new()
        } else {
            format!("  ({})", release.html_url)
        }
    );
    if args.check {
        if newer {
            println!("Update verfügbar – mit `ecomsec self-update` installieren.");
            return Ok(1);
        }
        println!("ecomsec ist aktuell.");
        return Ok(0);
    }
    if !newer && !args.force {
        println!("ecomsec ist aktuell – nichts zu tun (Neuinstallation mit --force).");
        return Ok(0);
    }
    let target = current_target().context(
        "Für diese Plattform gibt es kein vorgefertigtes Release – bitte aus dem Quellcode bauen (cargo build --release).",
    )?;
    let name = asset_name(&release.tag_name, target);
    let find = |n: &str| {
        release
            .assets
            .iter()
            .find(|a| a.name == n)
            .map(|a| a.browser_download_url.clone())
    };
    let archive_url = find(&name)
        .with_context(|| format!("Release {} enthält kein Paket {name}", release.tag_name))?;
    let sums_url = find("SHA256SUMS").with_context(|| {
        format!(
            "Release {} enthält keine SHA256SUMS – Update aus Sicherheitsgründen abgebrochen",
            release.tag_name
        )
    })?;
    eprintln!("Lade {name} …");
    let sums = parse_sha256sums(&String::from_utf8_lossy(&get(
        &agent,
        &sums_url,
        "application/octet-stream",
    )?));
    let archive = get(&agent, &archive_url, "application/octet-stream")?;
    verify_checksum(&sums, &name, &archive)?;
    eprintln!("Prüfsumme (SHA-256) bestätigt.");
    let binary = extract_binary(&name, &archive, binary_name())?;
    if binary.len() < 1024 {
        bail!(
            "Entpacktes Binary ist unplausibel klein ({} Bytes) – Update abgebrochen",
            binary.len()
        );
    }
    replace_binary(&exe, &binary)?;
    println!(
        "ecomsec {latest} installiert: {}{}",
        exe.display(),
        if cfg!(windows) {
            " (alte Version als .old gesichert, wird beim nächsten Update entfernt)"
        } else {
            ""
        }
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn slug_from_repository_url() {
        assert_eq!(
            github_slug("https://github.com/liohtml/ecom-sec").as_deref(),
            Some("liohtml/ecom-sec")
        );
        assert_eq!(
            github_slug("https://github.com/a/b.git/").as_deref(),
            Some("a/b")
        );
        assert!(github_slug("https://gitlab.com/a/b").is_none());
        assert!(github_slug("https://github.com/a").is_none());
        assert!(github_slug("https://github.com/a/b/c").is_none());
        assert!(github_slug(REPOSITORY).is_some());
    }

    #[test]
    fn version_comparison() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(is_newer("0.1.1", "0.1.0"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(is_newer("v0.10.0", "0.9.0"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("0.0.9", "0.1.0"));
        // Pre-releases are older than the release.
        assert!(is_newer("1.0.0", "1.0.0-rc.1"));
        assert!(!is_newer("1.0.0-rc.1", "1.0.0"));
        assert!(is_newer("1.0.0-rc.2", "1.0.0-rc.1"));
        assert!(is_newer("1.0.0-rc.10", "1.0.0-rc.9"));
        assert!(is_newer("1.0.0-beta", "1.0.0-alpha"));
        // Short forms and build metadata.
        assert!(!is_newer("1.2", "1.2.0"));
        assert!(!is_newer("1.2.0+build5", "1.2.0"));
        // Garbage never triggers an update.
        assert!(!is_newer("latest", "0.1.0"));
        assert!(!is_newer("1.2.3.4", "0.1.0"));
    }

    #[test]
    fn asset_names_match_release_workflow() {
        assert_eq!(
            asset_name("v1.2.3", "x86_64-unknown-linux-musl"),
            "ecomsec-v1.2.3-x86_64-unknown-linux-musl.tar.gz"
        );
        assert_eq!(
            asset_name("v1.2.3", "x86_64-pc-windows-msvc"),
            "ecomsec-v1.2.3-x86_64-pc-windows-msvc.zip"
        );
        assert!(current_target().is_some());
    }

    #[test]
    fn checksums_are_parsed_and_verified() {
        let data = b"hello";
        let hash = ecomsec_core::util::sha256_hex(data);
        let text = format!(
            "{hash}  ecomsec-v1-x.tar.gz\n{} *other.zip\nbroken line\n",
            "a".repeat(64)
        );
        let sums = parse_sha256sums(&text);
        assert_eq!(sums.len(), 2);
        assert_eq!(sums["other.zip"], "a".repeat(64));
        verify_checksum(&sums, "ecomsec-v1-x.tar.gz", data).unwrap();
        assert!(verify_checksum(&sums, "ecomsec-v1-x.tar.gz", b"evil").is_err());
        assert!(verify_checksum(&sums, "missing", data).is_err());
    }

    #[test]
    fn extracts_from_tar_gz_and_zip() {
        // tar.gz
        let mut tar_bytes = Vec::new();
        {
            let gz = flate2::write::GzEncoder::new(&mut tar_bytes, flate2::Compression::fast());
            let mut builder = tar::Builder::new(gz);
            for (path, content) in [
                ("ecomsec-v1-t/README.md", &b"readme"[..]),
                ("ecomsec-v1-t/ecomsec", &b"BINARY"[..]),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o755);
                header.set_cksum();
                builder.append_data(&mut header, path, content).unwrap();
            }
            builder.into_inner().unwrap().finish().unwrap();
        }
        assert_eq!(
            extract_binary("a.tar.gz", &tar_bytes, "ecomsec").unwrap(),
            b"BINARY"
        );
        assert!(extract_binary("a.tar.gz", &tar_bytes, "ecomsec.exe").is_err());

        // zip
        let mut zip_bytes = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_bytes));
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            w.start_file("ecomsec-v1-t/LICENSE", opts).unwrap();
            w.write_all(b"MIT").unwrap();
            w.start_file("ecomsec-v1-t/ecomsec.exe", opts).unwrap();
            w.write_all(b"WINBINARY").unwrap();
            w.finish().unwrap();
        }
        assert_eq!(
            extract_binary("a.zip", &zip_bytes, "ecomsec.exe").unwrap(),
            b"WINBINARY"
        );
    }

    #[test]
    fn replaces_binary_in_place() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join(binary_name());
        std::fs::write(&exe, b"old").unwrap();
        replace_binary(&exe, b"new").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new");
        // No temporary files are left behind.
        let left: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(left.iter().all(|n| !n.to_string_lossy().ends_with(".tmp")));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&exe).unwrap().permissions().mode();
            assert_ne!(mode & 0o111, 0, "binary must be executable");
        }
    }
}
