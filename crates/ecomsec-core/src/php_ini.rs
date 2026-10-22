//! Hardening checks for the PHP runtime configuration (`php.ini`,
//! `.user.ini`).
//!
//! The checks target the session handling that turns a file upload into a
//! deserialization surface: the RFC 1867 upload-progress handler decodes and
//! re-encodes `$_SESSION` during request startup, so everything reachable from
//! a session record is reachable before a single line of shop code runs.  PHP
//! 8.5.12 restricted that path to `__PHP_Incomplete_Class` (CVE-2026-109618,
//! CVE-2026-109619); switching the feature off closes it regardless of the
//! PHP version in use.
//!
//! Two kinds of findings come out of this:
//!
//! * an explicitly insecure value – reported as a warning, the file states it;
//! * a missing directive in a `php.ini` – reported as info, because the
//!   built-in default is the insecure one and only `php -i` knows which
//!   `php.ini` is actually loaded.
//!
//! A `.user.ini` is never judged by absence: it only augments the main
//! configuration, so a directive missing there says nothing.

use crate::finding::{Category, Finding, Severity, Source};
use crate::platform::FileScanProfile;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Session directories that are shared between all accounts of a host, where
/// every local user can read and replace other sites' session records.
const SHARED_SAVE_PATHS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/private/tmp"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IniKind {
    /// A main `php.ini`: unset directives fall back to the built-in default.
    Main,
    /// A per-directory `.user.ini`: only overrides what it names.
    User,
}

/// One parsed INI file, directives flattened with last-one-wins semantics.
#[derive(Debug, Clone)]
pub struct IniFile {
    pub path: PathBuf,
    pub kind: IniKind,
    pub directives: BTreeMap<String, String>,
}

impl IniFile {
    pub fn parse(path: &Path, kind: IniKind, content: &str) -> Self {
        let mut directives = BTreeMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            // Section headers ([PHP], [Session], per-host blocks) do not scope
            // directive names, so the header itself carries no information.
            if line.starts_with('[') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim().to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            directives.insert(key, clean_value(value.trim()));
        }
        IniFile {
            path: path.to_path_buf(),
            kind,
            directives,
        }
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.directives.get(key).map(|v| v.as_str())
    }

    /// `Some(bool)` when the directive is set, `None` when it is absent.
    fn flag(&self, key: &str) -> Option<bool> {
        self.get(key).map(parse_bool)
    }
}

/// Strip an inline comment and surrounding quotes from a directive value.
fn clean_value(raw: &str) -> String {
    let value = if let Some(rest) = raw.strip_prefix('"') {
        // A quoted value may legitimately contain ';' and '#'.
        match rest.split_once('"') {
            Some((inner, _)) => return inner.to_string(),
            None => rest,
        }
    } else {
        raw
    };
    value
        .split([';', '#'])
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

/// PHP's own notion of a boolean INI value: everything but `off`, `no`,
/// `false`, `0` and the empty string is on.
fn parse_bool(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "off" | "no" | "false" | "none"
    )
}

/// Find and parse every `php.ini` / `.user.ini` below the scan root.
pub fn collect(profile: &FileScanProfile) -> Vec<IniFile> {
    let root = &profile.root;
    let mut files = Vec::new();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| {
            if e.depth() == 0 || !e.file_type().is_dir() {
                return true;
            }
            let rel = crate::util::relative_display(root, e.path());
            !crate::engine::file_scan::under_any(&rel, &profile.excluded_dirs)
        });
    for entry in walker.filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry
            .file_name()
            .to_str()
            .unwrap_or("")
            .to_ascii_lowercase();
        let kind = match name.as_str() {
            "php.ini" => IniKind::Main,
            ".user.ini" => IniKind::User,
            _ => continue,
        };
        // Sample files shipped with PHP describe defaults, they are not loaded.
        if name.ends_with("-production") || name.ends_with("-development") {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(entry.path()) {
            files.push(IniFile::parse(entry.path(), kind, &content));
        }
    }
    files
}

/// Run the session hardening checks over the collected INI files.
pub fn findings(root: &Path, files: &[IniFile]) -> Vec<Finding> {
    let mut out = Vec::new();
    for file in files {
        out.extend(check_file(root, file));
    }
    out.extend(check_serialize_handler(root, files));
    out
}

fn check_file(root: &Path, file: &IniFile) -> Vec<Finding> {
    let mut out = Vec::new();
    let rel = crate::util::relative_display(root, &file.path);

    // ---------------------------------------------- upload progress (rfc1867)
    match file.flag("session.upload_progress.enabled") {
        Some(true) => out.push(
            Finding::file(
                Severity::Warning,
                Category::InsecureConfiguration,
                "php_session_upload_progress",
                root,
                &file.path,
                "session.upload_progress.enabled ist aktiv",
            )
            .with_description(
                "Der Upload-Progress-Handler dekodiert und schreibt die Session bereits während \
                 des Request-Starts, bevor Shop-Code läuft. Damit erreicht ein Multipart-Upload \
                 mit dem Feld PHP_SESSION_UPLOAD_PROGRESS die Deserialisierung der Session-Daten. \
                 Wird serverseitiger Upload-Fortschritt nicht gebraucht (moderne Uploads messen \
                 client-seitig), `session.upload_progress.enabled = Off` setzen.",
            )
            .with_evidence(format!("{rel}: session.upload_progress.enabled = On")),
        ),
        None if file.kind == IniKind::Main => out.push(
            Finding::file(
                Severity::Info,
                Category::InsecureConfiguration,
                "php_session_upload_progress_default",
                root,
                &file.path,
                "session.upload_progress.enabled nicht gesetzt (Default: On)",
            )
            .with_description(
                "Die Direktive fehlt, der eingebaute Default ist On. Effektiven Wert mit \
                 `php -i | grep upload_progress` prüfen und bei Nichtgebrauch explizit auf Off \
                 setzen.",
            ),
        ),
        _ => {}
    }

    // ------------------------------------------------------------ strict mode
    match file.flag("session.use_strict_mode") {
        Some(false) => out.push(
            Finding::file(
                Severity::Warning,
                Category::InsecureConfiguration,
                "php_session_strict_mode",
                root,
                &file.path,
                "session.use_strict_mode ist deaktiviert",
                )
            .with_description(
                "Ohne strict mode übernimmt PHP eine vom Client frei erfundene Session-ID und \
                 legt dafür einen Record an. Das erlaubt Session Fixation und gibt einem \
                 Angreifer einen vorhersagbaren Session-Record, den er anschließend gezielt \
                 füllen kann. `session.use_strict_mode = 1` setzen.",
            )
            .with_evidence(format!("{rel}: session.use_strict_mode = Off")),
        ),
        None if file.kind == IniKind::Main => out.push(
            Finding::file(
                Severity::Info,
                Category::InsecureConfiguration,
                "php_session_strict_mode_default",
                root,
                &file.path,
                "session.use_strict_mode nicht gesetzt (Default: Off)",
            )
            .with_description(
                "Die Direktive fehlt, der eingebaute Default ist Off. `session.use_strict_mode = 1` \
                 setzen.",
            ),
        ),
        _ => {}
    }

    // -------------------------------------------------------- ID transport
    if file.flag("session.use_only_cookies") == Some(false) {
        out.push(
            Finding::file(
                Severity::Warning,
                Category::InsecureConfiguration,
                "php_session_use_only_cookies",
                root,
                &file.path,
                "session.use_only_cookies ist deaktiviert",
            )
            .with_description(
                "PHP akzeptiert die Session-ID dann auch aus GET/POST. Die ID landet in \
                 Logs, Referern und Links, und ein Angreifer kann sie einem Opfer per URL \
                 unterschieben. `session.use_only_cookies = 1` setzen.",
            )
            .with_evidence(format!("{rel}: session.use_only_cookies = Off")),
        );
    }
    if file.flag("session.use_trans_sid") == Some(true) {
        out.push(
            Finding::file(
                Severity::Warning,
                Category::InsecureConfiguration,
                "php_session_use_trans_sid",
                root,
                &file.path,
                "session.use_trans_sid ist aktiv",
            )
            .with_description(
                "PHP hängt die Session-ID an jede ausgehende URL. Sie wird damit über Referer \
                 und Logs nach außen getragen. `session.use_trans_sid = 0` setzen.",
            )
            .with_evidence(format!("{rel}: session.use_trans_sid = On")),
        );
    }

    // -------------------------------------------------- unserialize autoload
    if let Some(callback) = file.get("unserialize_callback_func") {
        if !callback.is_empty() {
            out.push(
                Finding::file(
                    Severity::Warning,
                    Category::InsecureConfiguration,
                    "php_unserialize_callback_func",
                    root,
                    &file.path,
                    "unserialize_callback_func ist gesetzt",
                )
                .with_description(
                    "Die Funktion wird aufgerufen, wenn unserialize() auf eine unbekannte Klasse \
                     trifft, und lädt sie typischerweise nach. Damit wird aus fremden \
                     Serialisierungsdaten ein Autoload-Hook. Direktive leeren und \
                     unserialize() auf Fremddaten nur mit \
                     `['allowed_classes' => false]` aufrufen.",
                )
                .with_evidence(format!("{rel}: unserialize_callback_func = {callback}")),
            );
        }
    }

    // ------------------------------------------------------------- save path
    if let Some(save_path) = file.get("session.save_path") {
        // The value may carry a leading "N;" depth or "N;0600;" mode prefix.
        let dir = save_path.rsplit(';').next().unwrap_or(save_path).trim();
        if SHARED_SAVE_PATHS.contains(&dir.trim_end_matches('/')) {
            out.push(
                Finding::file(
                    Severity::Warning,
                    Category::InsecureConfiguration,
                    "php_session_save_path_shared",
                    root,
                    &file.path,
                    format!("session.save_path liegt im gemeinsamen Verzeichnis {dir}"),
                )
                .with_description(
                    "Alle Accounts des Hosts schreiben und lesen dort. Ein anderer Account \
                     – oder ein anderer Shop auf derselben Maschine – kann Session-Records \
                     lesen und ersetzen und damit kontrollierte Serialisierungsdaten \
                     einspielen. Eigenen, nur für den Pool-Benutzer lesbaren Pfad setzen.",
                )
                .with_evidence(format!("{rel}: session.save_path = {save_path}")),
            );
        }
    }

    out
}

/// Session records are only readable with the handler that wrote them.  Two
/// INI files declaring different handlers for the same store means one side
/// decodes foreign bytes – the mismatch the PHP 8.5.12 advisories describe.
fn check_serialize_handler(root: &Path, files: &[IniFile]) -> Vec<Finding> {
    let mut by_handler: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for file in files {
        if let Some(handler) = file.get("session.serialize_handler") {
            if !handler.is_empty() {
                by_handler
                    .entry(handler)
                    .or_default()
                    .push(crate::util::relative_display(root, &file.path));
            }
        }
    }
    if by_handler.len() < 2 {
        return Vec::new();
    }
    let mut finding = Finding::new(
        Severity::Warning,
        Category::InsecureConfiguration,
        Source::Configuration,
        "php_session_serialize_handler_mismatch",
        "session.serialize_handler",
        "Unterschiedliche session.serialize_handler im Scan-Bereich",
    )
    .with_description(
        "Ein Session-Record lässt sich nur mit dem Handler lesen, der ihn geschrieben hat. \
         Treffen zwei Handler auf denselben Store, dekodiert eine Seite fremd formatierte \
         Bytes – genau die Verwechslung, die den Session-Lücken in PHP 8.5.12 zugrunde liegt. \
         Entweder überall denselben Handler setzen oder jedem Bereich einen eigenen \
         session.save_path geben.",
    );
    for (handler, paths) in by_handler {
        finding = finding.with_evidence(format!("{handler}: {}", paths.join(", ")));
    }
    vec![finding]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> IniFile {
        IniFile::parse(Path::new("/srv/shop/php.ini"), IniKind::Main, content)
    }

    #[test]
    fn parses_comments_sections_and_quotes() {
        let f = parse(
            "; comment\n[PHP]\nsession.use_strict_mode = 1 ; on\n#x = 1\nsession.save_path = \"/var/lib/sess;1\"\nbroken\n",
        );
        assert_eq!(f.get("session.use_strict_mode"), Some("1"));
        assert_eq!(f.get("session.save_path"), Some("/var/lib/sess;1"));
        assert_eq!(f.get("x"), None);
        assert_eq!(f.get("broken"), None);
    }

    #[test]
    fn last_assignment_wins() {
        let f =
            parse("session.upload_progress.enabled = On\nsession.upload_progress.enabled = Off\n");
        assert_eq!(f.flag("session.upload_progress.enabled"), Some(false));
    }

    #[test]
    fn php_boolean_values() {
        for off in ["0", "Off", "off", "no", "False", "", "none"] {
            assert!(!parse_bool(off), "{off:?} should be off");
        }
        for on in ["1", "On", "yes", "true", "2"] {
            assert!(parse_bool(on), "{on:?} should be on");
        }
    }

    #[test]
    fn flags_enabled_upload_progress_and_missing_strict_mode() {
        let root = Path::new("/srv/shop");
        let f = parse("session.upload_progress.enabled = On\n");
        let rules: Vec<String> = check_file(root, &f).into_iter().map(|f| f.rule).collect();
        assert!(rules.iter().any(|r| r == "php_session_upload_progress"));
        assert!(rules.iter().any(|r| r == "php_session_strict_mode_default"));
    }

    #[test]
    fn hardened_main_ini_is_clean() {
        let root = Path::new("/srv/shop");
        let f = parse(
            "session.upload_progress.enabled = Off\nsession.use_strict_mode = 1\n\
             session.use_only_cookies = 1\nsession.use_trans_sid = 0\n\
             unserialize_callback_func =\nsession.save_path = /var/lib/php/shop\n",
        );
        assert!(check_file(root, &f).is_empty());
    }

    #[test]
    fn user_ini_is_not_judged_by_absence() {
        let root = Path::new("/srv/shop");
        let f = IniFile::parse(
            Path::new("/srv/shop/.user.ini"),
            IniKind::User,
            "memory_limit = 512M\n",
        );
        assert!(check_file(root, &f).is_empty());
    }

    #[test]
    fn shared_save_path_with_depth_prefix() {
        let root = Path::new("/srv/shop");
        let f = parse("session.save_path = \"2;0600;/tmp\"\n");
        let rules: Vec<String> = check_file(root, &f).into_iter().map(|f| f.rule).collect();
        assert!(rules.iter().any(|r| r == "php_session_save_path_shared"));
    }

    #[test]
    fn serialize_handler_mismatch_needs_two_values() {
        let root = Path::new("/srv/shop");
        let a = IniFile::parse(
            Path::new("/srv/shop/php.ini"),
            IniKind::Main,
            "session.serialize_handler = php\n",
        );
        let b = IniFile::parse(
            Path::new("/srv/shop/admin/.user.ini"),
            IniKind::User,
            "session.serialize_handler = php_serialize\n",
        );
        assert!(check_serialize_handler(root, std::slice::from_ref(&a)).is_empty());
        let found = check_serialize_handler(root, &[a, b]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].evidence.len(), 2);
    }
}
