//! Read-only tools the model may call.  Every tool is scoped to the shop root
//! (files), the guarded read-only database helper or the scan report, has
//! hard output limits and redacts secrets before anything is returned.

use crate::redact::{path_sensitivity, redact, redact_cell, redact_for, Sensitivity};
use chrono::{DateTime, Utc};
use ecomsec_core::finding::{Category, Finding, ReviewVerdict, Severity, Source};
use ecomsec_core::platform::Advisory;
use ecomsec_core::report::Report;
use ecomsec_core::util::{excerpt, human_size, relative_display, sha256_hex};
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};
use walkdir::WalkDir;

/// Maximum size of one tool result (bytes).
pub const MAX_OUTPUT: usize = 64 * 1024;
/// Files are read up to this size (redaction needs the whole text).
const MAX_READ_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LINE_CHARS: usize = 4000;
const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;
const MAX_NEW_FINDINGS: usize = 50;
const MAX_LIST_ENTRIES: usize = 400;
const GREP_MAX_FILE: u64 = 8 * 1024 * 1024;
const GREP_MAX_FILES: usize = 20_000;
const GREP_TIME: Duration = Duration::from_secs(30);
/// Directories that are listed but not expanded / not searched.
const HEAVY_DIRS: &[&str] = &[".git", ".svn", ".hg", "node_modules"];

/// Executes guarded read-only SQL.  The tool validates every statement with
/// [`ecomsec_core::db::guard_read_only_sql`] before calling the executor.
pub trait SqlExecutor {
    fn query(&self, sql: &str) -> Result<Vec<Vec<(String, String)>>, String>;
}

/// MySQL/MariaDB executor using [`ecomsec_core::db::query_read_only`].
pub struct MysqlExecutor {
    creds: ecomsec_core::db::DbCredentials,
}

impl MysqlExecutor {
    pub fn new(creds: ecomsec_core::db::DbCredentials) -> Self {
        MysqlExecutor { creds }
    }
}

impl SqlExecutor for MysqlExecutor {
    fn query(&self, sql: &str) -> Result<Vec<Vec<(String, String)>>, String> {
        ecomsec_core::db::query_read_only(&self.creds, sql).map_err(|e| e.to_string())
    }
}

/// Vulnerability lookup for a Composer package (only with `--online`).
pub trait OsvLookup {
    fn lookup(&self, package: &str, version: &str) -> Result<Value, String>;
}

/// OSV.dev lookup via `ecomsec-osv` (sends package name and version only).
#[derive(Default)]
pub struct OsvOnline {
    client: ecomsec_osv::OsvClient,
}

impl OsvLookup for OsvOnline {
    fn lookup(&self, package: &str, version: &str) -> Result<Value, String> {
        let pkg = ecomsec_osv::ComposerPackage {
            name: package.to_string(),
            version: version.to_string(),
            dev: false,
        };
        let result = self
            .client
            .lookup(std::slice::from_ref(&pkg))
            .map_err(|e| e.to_string())?;
        let vulns = result
            .results
            .into_iter()
            .flat_map(|r| r.vulns)
            .collect::<Vec<_>>();
        Ok(json!({
            "package": package,
            "version": version,
            "vulnerabilities": vulns,
            "limitations": result.limitations,
        }))
    }
}

/// Verdict recorded by the model for an existing finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictRecord {
    pub finding_id: String,
    pub verdict: ReviewVerdict,
    pub confidence: f32,
    pub reasoning: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub subject: String,
}

/// What was sent to the model (transparency, stored in the audit report).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DataStats {
    pub tool_calls: u32,
    pub tool_errors: u32,
    /// Bytes of tool output sent to the API (after redaction).
    pub bytes_sent: u64,
    /// Number of masked values.
    pub redactions: u64,
    /// Files whose (redacted) content was read.
    pub files_read: BTreeSet<String>,
    pub greps: u32,
    pub db_queries: u32,
    pub osv_lookups: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    pub content: String,
    pub is_error: bool,
}

/// State shared by all tools during one audit.
pub struct ToolContext {
    root: Option<PathBuf>,
    pub report: Report,
    pub advisories: Vec<Advisory>,
    sql: Option<Box<dyn SqlExecutor>>,
    osv: Option<Box<dyn OsvLookup>>,
    pub model: String,
    pub verdicts: Vec<VerdictRecord>,
    pub new_findings: Vec<Finding>,
    pub stats: DataStats,
}

impl ToolContext {
    /// `root` is the shop root for file tools (`None` for hosted platforms).
    pub fn new(report: Report, root: Option<PathBuf>, model: &str) -> Self {
        let root = root.map(|r| r.canonicalize().unwrap_or(r));
        ToolContext {
            root,
            report,
            advisories: Vec::new(),
            sql: None,
            osv: None,
            model: model.to_string(),
            verdicts: Vec::new(),
            new_findings: Vec::new(),
            stats: DataStats::default(),
        }
    }

    pub fn with_advisories(mut self, advisories: Vec<Advisory>) -> Self {
        self.advisories = advisories;
        self
    }

    pub fn with_sql(mut self, sql: Box<dyn SqlExecutor>) -> Self {
        self.sql = Some(sql);
        self
    }

    pub fn with_osv(mut self, osv: Box<dyn OsvLookup>) -> Self {
        self.osv = Some(osv);
        self
    }

    pub fn root(&self) -> Option<&Path> {
        self.root.as_deref()
    }

    pub fn has_db(&self) -> bool {
        self.sql.is_some()
    }

    pub fn has_osv(&self) -> bool {
        self.osv.is_some()
    }

    /// Tool definitions for the Messages API.  File tools are only offered
    /// with a shop root, `db_query` only with database access and
    /// `osv_lookup` only with `--online`.
    pub fn definitions(&self) -> Vec<Value> {
        let mut tools = Vec::new();
        if self.root.is_some() {
            tools.push(json!({
                "name": "list_dir",
                "description": "Listet ein Verzeichnis der Shop-Installation (relativ zum Shop-Root) mit Typ, Größe und Änderungszeit. Höchstens 400 Einträge; .git/node_modules werden nicht aufgeklappt.",
                "input_schema": {"type": "object", "properties": {
                    "path": {"type": "string", "description": "Pfad relativ zum Shop-Root, z. B. \"plugins\" oder \".\""},
                    "depth": {"type": "integer", "minimum": 1, "maximum": 4, "description": "Rekursionstiefe (Standard 1)"}
                }, "required": ["path"]}
            }));
            tools.push(json!({
                "name": "read_file",
                "description": "Liest eine Datei zeilenweise (mit Zeilennummern). Höchstens 64 KiB pro Aufruf; Binärdateien als Hexdump-Anfang. Geheimnisse (Passwörter, Schlüssel, Tokens, lange Hex-/Base64-Werte, E-Mail-Adressen) sind maskiert; Schlüsseldateien werden nicht ausgegeben.",
                "input_schema": {"type": "object", "properties": {
                    "path": {"type": "string", "description": "Pfad relativ zum Shop-Root"},
                    "offset": {"type": "integer", "minimum": 1, "description": "Erste Zeile (1-basiert, Standard 1)"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 2000, "description": "Anzahl Zeilen (Standard 400)"}
                }, "required": ["path"]}
            }));
            tools.push(json!({
                "name": "grep",
                "description": "Durchsucht Dateien unterhalb eines Pfads mit einem regulären Ausdruck (Rust-Regex-Syntax) und liefert Pfad:Zeile: Ausschnitt. Gesucht wird in der redigierten Fassung; Schlüsseldateien werden übersprungen. Dateien > 8 MiB und Binärdateien werden ignoriert.",
                "input_schema": {"type": "object", "properties": {
                    "pattern": {"type": "string", "description": "Regulärer Ausdruck"},
                    "path": {"type": "string", "description": "Datei oder Verzeichnis relativ zum Shop-Root (Standard \".\")"},
                    "max_results": {"type": "integer", "minimum": 1, "maximum": 200, "description": "Maximale Trefferzahl (Standard 50)"},
                    "case_insensitive": {"type": "boolean"}
                }, "required": ["pattern"]}
            }));
            tools.push(json!({
                "name": "file_info",
                "description": "Metadaten einer Datei: Typ, Größe, mtime, ctime, Rechte (Modus), Besitzer (uid/gid), SHA-256, Symlink-Ziel.",
                "input_schema": {"type": "object", "properties": {
                    "path": {"type": "string", "description": "Pfad relativ zum Shop-Root"}
                }, "required": ["path"]}
            }));
        }
        tools.push(json!({
            "name": "get_report_summary",
            "description": "Überblick über den Scan-Report: Plattform, Version, Ampel, Zählung nach Kategorie und Schweregrad, Advisories mit Patch-Status, Einschränkungen des Scans.",
            "input_schema": {"type": "object", "properties": {}}
        }));
        tools.push(json!({
            "name": "list_findings",
            "description": "Listet Befunde des Scans (ID, Schweregrad, Kategorie, Regel, Subjekt, Titel). Standardmäßig ohne als unbedenklich markierte Befunde.",
            "input_schema": {"type": "object", "properties": {
                "severity": {"type": "string", "enum": ["critical", "warning", "info"]},
                "category": {"type": "string", "description": "Kategorie in snake_case, z. B. suspicious_pattern"},
                "text": {"type": "string", "description": "Teiltext in Subjekt, Titel oder Regel"},
                "include_accepted": {"type": "boolean"},
                "offset": {"type": "integer", "minimum": 0},
                "limit": {"type": "integer", "minimum": 1, "maximum": 300, "description": "Standard 100"}
            }}
        }));
        tools.push(json!({
            "name": "get_finding",
            "description": "Vollständige Details eines Befunds (Beschreibung, Beweisausschnitte, Regel, Gruppe).",
            "input_schema": {"type": "object", "properties": {
                "id": {"type": "string", "description": "Befund-ID (16 Hex-Zeichen)"}
            }, "required": ["id"]}
        }));
        tools.push(json!({
            "name": "get_integrity",
            "description": "Zeilen der Ansicht \"Shop-Integrität\" (Patch-Status, Admin-Konten, Zahlung, Dateirechte, Baseline …).",
            "input_schema": {"type": "object", "properties": {}}
        }));
        if self.sql.is_some() {
            tools.push(json!({
                "name": "db_query",
                "description": "Führt eine einzelne lesende SQL-Anweisung (nur SELECT, SHOW, DESCRIBE) auf der Shop-Datenbank aus. Höchstens 200 Zeilen (LIMIT wird ergänzt), 20 s Zeitlimit, keine Kommentare, keine Schreibzugriffe. Spalten mit Passwörtern/Tokens/Schlüsseln sowie E-Mail-Adressen werden maskiert.",
                "input_schema": {"type": "object", "properties": {
                    "sql": {"type": "string", "description": "z. B. SELECT cLogin, dLetzterLogin FROM tadminlogin"}
                }, "required": ["sql"]}
            }));
        }
        tools.push(json!({
            "name": "lookup_advisory",
            "description": "Sucht in der lokalen Schwachstellen-Datenbank (Advisories) nach ID (CVE/GHSA), Titel oder Tag und liefert betroffene Versionen, Fix-Versionen und den Patch-Status dieser Installation.",
            "input_schema": {"type": "object", "properties": {
                "id": {"type": "string", "description": "CVE-/GHSA-ID oder Suchbegriff"}
            }, "required": ["id"]}
        }));
        if self.osv.is_some() {
            tools.push(json!({
                "name": "osv_lookup",
                "description": "Fragt OSV.dev nach bekannten Schwachstellen eines Composer-Pakets in einer Version (sendet nur Paketname und Version).",
                "input_schema": {"type": "object", "properties": {
                    "package": {"type": "string", "description": "Composer-Paket, z. B. smarty/smarty"},
                    "version": {"type": "string", "description": "Installierte Version, z. B. 4.3.1"}
                }, "required": ["package", "version"]}
            }));
        }
        tools.push(json!({
            "name": "record_verdict",
            "description": "Speichert deine Bewertung eines bestehenden Befunds. confirmed = echter Kompromittierungs-/Schwachstellen-Hinweis; likely_false_positive = nach Prüfung sehr wahrscheinlich harmlos; needs_human = Beweislage unklar, Mensch muss entscheiden. Mehrere Befunde mit identischer Begründung über finding_ids.",
            "input_schema": {"type": "object", "properties": {
                "finding_id": {"type": "string"},
                "finding_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 200},
                "verdict": {"type": "string", "enum": ["confirmed", "likely_false_positive", "needs_human"]},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1, "description": "0.0 bis 1.0"},
                "reasoning": {"type": "string", "description": "Kurze deutsche Begründung mit Beleg (Pfad, Zeile, Ausschnitt)"}
            }, "required": ["verdict", "confidence", "reasoning"]}
        }));
        tools.push(json!({
            "name": "record_finding",
            "description": "Erfasst ein NEUES Problem, das der Scanner nicht gemeldet hat (z. B. SQL-Injection in einem eigenen Plugin, übersehene Hintertür, gefährliche Fehlkonfiguration). Nur mit konkretem Beleg.",
            "input_schema": {"type": "object", "properties": {
                "severity": {"type": "string", "enum": ["critical", "warning", "info"]},
                "category": {"type": "string", "enum": CATEGORY_NAMES},
                "title": {"type": "string", "description": "Kurzer deutscher Titel"},
                "subject": {"type": "string", "description": "Relativer Pfad, bei Code mit Zeile (pfad:zeile), oder DB-Datensatz"},
                "description": {"type": "string", "description": "Deutsche Erklärung: Was, warum gefährlich, wie verifizieren/beheben"},
                "evidence": {"type": "array", "items": {"type": "string"}, "maxItems": 10, "description": "Belege (Zeilenausschnitte, Metadaten)"}
            }, "required": ["severity", "category", "title", "subject", "description", "evidence"]}
        }));
        tools
    }

    /// Run a tool.  Errors are returned as `is_error` results so that the
    /// model can correct its call.
    pub fn execute(&mut self, name: &str, input: &Value) -> ToolOutput {
        self.stats.tool_calls += 1;
        let result = match name {
            "list_dir" => self.list_dir(input),
            "read_file" => self.read_file(input),
            "grep" => self.grep(input),
            "file_info" => self.file_info(input),
            "get_report_summary" => self.report_summary(),
            "list_findings" => self.list_findings(input),
            "get_finding" => self.get_finding(input),
            "get_integrity" => self.integrity(),
            "db_query" => self.db_query(input),
            "lookup_advisory" => self.lookup_advisory(input),
            "osv_lookup" => self.osv_lookup(input),
            "record_verdict" => self.record_verdict(input),
            "record_finding" => self.record_finding(input),
            other => Err(format!("Unbekanntes Werkzeug {other:?}")),
        };
        let (content, is_error) = match result {
            Ok(s) => (s, false),
            Err(e) => (format!("Fehler: {e}"), true),
        };
        if is_error {
            self.stats.tool_errors += 1;
        }
        let content = truncate_output(content);
        self.stats.bytes_sent += content.len() as u64;
        ToolOutput { content, is_error }
    }

    // ------------------------------------------------------------------ paths

    /// Resolve a model-supplied path inside the shop root.  Returns the
    /// canonical path, the path as given below the root (not following a
    /// final symlink) and the display path relative to the root.
    fn resolve(&self, path: &str) -> Result<(PathBuf, PathBuf, String), String> {
        let root = self
            .root
            .as_ref()
            .ok_or("Diese Plattform hat kein Dateisystem (gehostet).")?;
        let p = path.trim();
        let p = if p.is_empty() { "." } else { p };
        let given = Path::new(p);
        if given.components().any(|c| c == Component::ParentDir) {
            return Err("\"..\" ist in Pfaden nicht erlaubt".into());
        }
        let joined = if given.is_absolute() {
            given.to_path_buf()
        } else {
            root.join(given)
        };
        let canon = joined
            .canonicalize()
            .map_err(|_| format!("Pfad {p:?} existiert nicht"))?;
        if !canon.starts_with(root) {
            return Err(format!(
                "Pfad {p:?} liegt außerhalb des Shop-Verzeichnisses (Symlink?) – Zugriff verweigert"
            ));
        }
        let rel = relative_display(root, &canon);
        Ok((canon, joined, rel))
    }

    // ------------------------------------------------------------------ file tools

    fn list_dir(&mut self, input: &Value) -> Result<String, String> {
        let path = str_arg(input, "path").unwrap_or(".");
        let depth = u64_arg(input, "depth").unwrap_or(1).clamp(1, 4) as usize;
        let (abs, _, rel) = self.resolve(path)?;
        if !abs.is_dir() {
            return Err(format!("{rel} ist kein Verzeichnis"));
        }
        let root = self.root.clone().expect("root checked");
        let mut lines = Vec::new();
        let mut it = WalkDir::new(&abs)
            .min_depth(1)
            .max_depth(depth)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter();
        let mut truncated = false;
        while let Some(entry) = it.next() {
            let Ok(entry) = entry else { continue };
            if lines.len() >= MAX_LIST_ENTRIES {
                truncated = true;
                break;
            }
            let p = entry.path();
            let r = relative_display(&root, p);
            let ft = entry.file_type();
            let meta = entry.metadata().ok();
            let mtime = meta
                .as_ref()
                .and_then(|m| m.modified().ok())
                .map(fmt_time)
                .unwrap_or_default();
            if ft.is_symlink() {
                let target = fs::read_link(p)
                    .map(|t| t.display().to_string())
                    .unwrap_or_default();
                lines.push(format!("l  {r} -> {target}"));
            } else if ft.is_dir() {
                let heavy = HEAVY_DIRS.contains(&entry.file_name().to_string_lossy().as_ref());
                lines.push(format!(
                    "d  {r}/  {mtime}{}",
                    if heavy { "  (nicht aufgeklappt)" } else { "" }
                ));
                if heavy {
                    it.skip_current_dir();
                }
            } else {
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                lines.push(format!("f  {r}  {}  {mtime}", human_size(size)));
            }
        }
        let mut out = format!(
            "Verzeichnis {rel} (Tiefe {depth}, {} Einträge)\n",
            lines.len()
        );
        out.push_str(&lines.join("\n"));
        if truncated {
            out.push_str(&format!(
                "\n… nach {MAX_LIST_ENTRIES} Einträgen abgeschnitten – Unterverzeichnis gezielt auflisten."
            ));
        }
        let red = redact(&out);
        self.stats.redactions += red.count as u64;
        Ok(red.text)
    }

    fn read_file(&mut self, input: &Value) -> Result<String, String> {
        let path = str_arg(input, "path").ok_or("Parameter path fehlt")?;
        let (abs, _, rel) = self.resolve(path)?;
        if !abs.is_file() {
            return Err(format!("{rel} ist keine Datei"));
        }
        let meta = fs::metadata(&abs).map_err(|e| e.to_string())?;
        let size = meta.len();
        let mtime = meta.modified().map(fmt_time).unwrap_or_default();
        let sensitivity = path_sensitivity(&rel);
        self.stats.files_read.insert(rel.clone());
        let mut header = format!("Datei: {rel} · {} · geändert {mtime}", human_size(size));
        if sensitivity == Sensitivity::Withhold {
            self.stats.redactions += 1;
            return Ok(format!(
                "{header}\n[Inhalt zurückgehalten: Schlüssel-/Passwortdatei. Für die Bewertung reichen Metadaten (file_info).]"
            ));
        }
        let mut bytes = Vec::new();
        fs::File::open(&abs)
            .and_then(|f| f.take(MAX_READ_BYTES).read_to_end(&mut bytes))
            .map_err(|e| format!("{rel} nicht lesbar: {e}"))?;
        if bytes.iter().take(8000).any(|b| *b == 0) {
            return Ok(format!(
                "{header}\nBinärdatei – Hexdump der ersten 512 Bytes:\n{}",
                hexdump(&bytes[..bytes.len().min(512)])
            ));
        }
        let text = String::from_utf8_lossy(&bytes);
        let red = redact_for(sensitivity, &text);
        self.stats.redactions += red.count as u64;
        if sensitivity == Sensitivity::Strict {
            header.push_str(" · Zugangsdaten-Datei: Werte maskiert");
        }
        let lines: Vec<&str> = red.text.split('\n').collect();
        let total = if red.text.ends_with('\n') {
            lines.len() - 1
        } else {
            lines.len()
        };
        let offset = u64_arg(input, "offset").unwrap_or(1).max(1) as usize;
        let limit = u64_arg(input, "limit").unwrap_or(400).clamp(1, 2000) as usize;
        let start = (offset - 1).min(total);
        let end = (start + limit).min(total);
        let mut out = format!(
            "{header} · Zeilen {}–{end} von {total}{}\n",
            start + 1,
            if size > MAX_READ_BYTES {
                " (nur die ersten 16 MiB gelesen)"
            } else {
                ""
            }
        );
        let mut stopped = None;
        for (i, line) in lines.iter().enumerate().take(end).skip(start) {
            if out.len() > MAX_OUTPUT - 1024 {
                stopped = Some(i + 1);
                break;
            }
            let line = line.trim_end_matches('\r');
            let shown: String = line.chars().take(MAX_LINE_CHARS).collect();
            out.push_str(&format!("{:>6}│ {shown}", i + 1));
            if shown.len() < line.len() {
                out.push_str(&format!(
                    " … (Zeile gekürzt, {} Zeichen)",
                    line.chars().count()
                ));
            }
            out.push('\n');
        }
        if let Some(next) = stopped {
            out.push_str(&format!(
                "… Ausgabe bei 64 KiB gekürzt – weiter mit offset={next}\n"
            ));
        } else if end < total {
            out.push_str(&format!("… weitere Zeilen ab offset={}\n", end + 1));
        }
        Ok(out)
    }

    fn grep(&mut self, input: &Value) -> Result<String, String> {
        let pattern = str_arg(input, "pattern").ok_or("Parameter pattern fehlt")?;
        let path = str_arg(input, "path").unwrap_or(".");
        let max = u64_arg(input, "max_results").unwrap_or(50).clamp(1, 200) as usize;
        let ci = input
            .get("case_insensitive")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let re = RegexBuilder::new(pattern)
            .case_insensitive(ci)
            .size_limit(1 << 20)
            .dfa_size_limit(1 << 22)
            .build()
            .map_err(|e| format!("ungültiger regulärer Ausdruck: {e}"))?;
        let (abs, _, rel) = self.resolve(path)?;
        let root = self.root.clone().expect("root checked");
        self.stats.greps += 1;
        let started = Instant::now();
        let mut results = Vec::new();
        let mut files = 0usize;
        let mut skipped_secret = 0usize;
        let mut stop_reason = None;
        let walker = WalkDir::new(&abs)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|e| {
                !(e.depth() > 0
                    && e.file_type().is_dir()
                    && HEAVY_DIRS.contains(&e.file_name().to_string_lossy().as_ref()))
            });
        'walk: for entry in walker.flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            files += 1;
            if files > GREP_MAX_FILES {
                stop_reason = Some(format!("Dateilimit ({GREP_MAX_FILES}) erreicht"));
                break;
            }
            if started.elapsed() > GREP_TIME {
                stop_reason = Some("Zeitlimit (30 s) erreicht".to_string());
                break;
            }
            let p = entry.path();
            let r = relative_display(&root, p);
            let sensitivity = path_sensitivity(&r);
            if sensitivity == Sensitivity::Withhold {
                skipped_secret += 1;
                continue;
            }
            if entry.metadata().map(|m| m.len()).unwrap_or(0) > GREP_MAX_FILE {
                continue;
            }
            let Ok(bytes) = fs::read(p) else { continue };
            if bytes.iter().take(8000).any(|b| *b == 0) {
                continue;
            }
            let raw = String::from_utf8_lossy(&bytes);
            if !re.is_match(&raw) {
                continue;
            }
            // Match against the redacted text so that grep cannot be used as
            // an oracle for masked secrets.
            let red = redact_for(sensitivity, &raw);
            let mut hit = false;
            for (i, line) in red.text.lines().enumerate() {
                if re.is_match(line) {
                    hit = true;
                    results.push(format!("{r}:{}: {}", i + 1, excerpt(line.trim(), 300)));
                    if results.len() >= max {
                        stop_reason = Some(format!("max_results ({max}) erreicht"));
                        if hit {
                            self.stats.redactions += red.count as u64;
                        }
                        break 'walk;
                    }
                }
            }
            if hit {
                self.stats.redactions += red.count as u64;
            }
        }
        let mut out = format!(
            "{} Treffer für /{pattern}/ in {rel} ({files} Dateien durchsucht)\n",
            results.len()
        );
        out.push_str(&results.join("\n"));
        if let Some(r) = stop_reason {
            out.push_str(&format!("\n… Suche beendet: {r}"));
        }
        if skipped_secret > 0 {
            out.push_str(&format!(
                "\n({skipped_secret} Schlüssel-/Passwortdateien nicht durchsucht)"
            ));
        }
        Ok(out)
    }

    fn file_info(&mut self, input: &Value) -> Result<String, String> {
        let path = str_arg(input, "path").ok_or("Parameter path fehlt")?;
        let (abs, given, rel) = self.resolve(path)?;
        let lmeta = fs::symlink_metadata(&given).map_err(|e| e.to_string())?;
        let meta = fs::metadata(&abs).map_err(|e| e.to_string())?;
        let mut info = Map::new();
        info.insert("pfad".into(), json!(rel));
        let kind = if lmeta.file_type().is_symlink() {
            "symlink"
        } else if meta.is_dir() {
            "verzeichnis"
        } else {
            "datei"
        };
        info.insert("typ".into(), json!(kind));
        if lmeta.file_type().is_symlink() {
            if let Ok(t) = fs::read_link(&given) {
                info.insert("symlink_ziel".into(), json!(t.display().to_string()));
            }
        }
        info.insert("groesse_bytes".into(), json!(meta.len()));
        if let Ok(m) = meta.modified() {
            info.insert("mtime".into(), json!(fmt_time(m)));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let ctime = DateTime::<Utc>::from_timestamp(meta.ctime(), 0)
                .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string());
            info.insert("ctime".into(), json!(ctime));
            info.insert(
                "modus".into(),
                json!(format!("{:04o}", meta.mode() & 0o7777)),
            );
            info.insert("uid".into(), json!(meta.uid()));
            info.insert("gid".into(), json!(meta.gid()));
            info.insert("links".into(), json!(meta.nlink()));
        }
        if meta.is_file() {
            if meta.len() <= MAX_HASH_BYTES {
                if let Ok(bytes) = fs::read(&abs) {
                    info.insert("sha256".into(), json!(sha256_hex(&bytes)));
                }
            } else {
                info.insert("sha256".into(), json!("(Datei zu groß)"));
            }
        }
        info.insert(
            "sensibel".into(),
            json!(match path_sensitivity(&rel) {
                Sensitivity::Normal => "nein",
                Sensitivity::Strict => "Zugangsdaten (Inhalt wird maskiert)",
                Sensitivity::Withhold => "Schlüsseldatei (Inhalt wird nicht ausgegeben)",
            }),
        );
        serde_json::to_string_pretty(&Value::Object(info)).map_err(|e| e.to_string())
    }

    // ------------------------------------------------------------------ report tools

    fn all_findings(&self) -> impl Iterator<Item = &Finding> {
        self.report.findings.iter().chain(self.new_findings.iter())
    }

    fn report_summary(&mut self) -> Result<String, String> {
        let r = &self.report;
        let mut by_cat: BTreeMap<String, BTreeMap<&str, usize>> = BTreeMap::new();
        for f in &r.findings {
            let key = if f.accepted {
                "accepted"
            } else {
                f.severity.label_en()
            };
            *by_cat
                .entry(category_name(f.category))
                .or_default()
                .entry(key)
                .or_default() += 1;
        }
        let v = json!({
            "plattform": {
                "id": r.platform.id,
                "name": r.platform.name,
                "version": r.platform.version.as_ref().map(|v| v.to_string()),
                "ziel": r.platform.target,
                "details": r.platform.details,
            },
            "report_erstellt": r.generated_at,
            "referenzdatum": r.reference_date,
            "ampel": r.verdict,
            "zusammenfassung": r.summary,
            "befunde_nach_kategorie": by_cat,
            "advisories": r.advisories.iter().map(|a| json!({
                "id": a.advisory.id,
                "titel": a.advisory.title,
                "status": a.state,
                "begruendung": a.basis,
            })).collect::<Vec<_>>(),
            "einschraenkungen": r.limitations,
            "dateisystem_verfuegbar": self.root.is_some(),
            "datenbank_verfuegbar": self.sql.is_some(),
            "osv_verfuegbar": self.osv.is_some(),
        });
        self.redacted_json(&v)
    }

    fn integrity(&mut self) -> Result<String, String> {
        let v = json!({
            "integritaet": self.report.integrity,
            "advisories": self.report.advisories.iter().map(|a| json!({
                "id": a.advisory.id, "status": a.state, "begruendung": a.basis
            })).collect::<Vec<_>>(),
        });
        self.redacted_json(&v)
    }

    fn redacted_json(&mut self, v: &Value) -> Result<String, String> {
        let text = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
        let red = redact(&text);
        self.stats.redactions += red.count as u64;
        Ok(red.text)
    }

    fn list_findings(&mut self, input: &Value) -> Result<String, String> {
        let sev = str_arg(input, "severity").map(str::to_ascii_lowercase);
        let cat = str_arg(input, "category").map(str::to_ascii_lowercase);
        let text = str_arg(input, "text").map(str::to_lowercase);
        let include_accepted = input
            .get("include_accepted")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let offset = u64_arg(input, "offset").unwrap_or(0) as usize;
        let limit = u64_arg(input, "limit").unwrap_or(100).clamp(1, 300) as usize;
        let mut list: Vec<&Finding> = self
            .all_findings()
            .filter(|f| include_accepted || !f.accepted)
            .filter(|f| {
                sev.as_deref()
                    .map(|s| f.severity.label_en() == s)
                    .unwrap_or(true)
            })
            .filter(|f| {
                cat.as_deref()
                    .map(|c| category_name(f.category) == c)
                    .unwrap_or(true)
            })
            .filter(|f| {
                text.as_deref()
                    .map(|t| {
                        format!("{} {} {}", f.subject, f.title, f.rule)
                            .to_lowercase()
                            .contains(t)
                    })
                    .unwrap_or(true)
            })
            .collect();
        list.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.subject.cmp(&b.subject)));
        let total = list.len();
        let reviewed: BTreeMap<&str, ReviewVerdict> = self
            .verdicts
            .iter()
            .map(|v| (v.finding_id.as_str(), v.verdict))
            .collect();
        let mut out = format!(
            "{total} Befunde (Anzeige {}–{}). Spalten: id | schweregrad | kategorie | regel | subjekt | titel\n",
            (offset + 1).min(total),
            (offset + limit).min(total)
        );
        for f in list.iter().skip(offset).take(limit) {
            out.push_str(&format!(
                "{} | {} | {} | {} | {} | {}{}{}\n",
                f.id,
                f.severity.label_en(),
                category_name(f.category),
                f.rule,
                excerpt(&f.subject, 160),
                excerpt(&f.title, 160),
                if f.accepted { " [unbedenklich]" } else { "" },
                reviewed
                    .get(f.id.as_str())
                    .map(|v| format!(" [bewertet: {}]", verdict_name(*v)))
                    .unwrap_or_default()
            ));
        }
        let red = redact(&out);
        self.stats.redactions += red.count as u64;
        Ok(red.text)
    }

    fn get_finding(&mut self, input: &Value) -> Result<String, String> {
        let id = str_arg(input, "id").ok_or("Parameter id fehlt")?.trim();
        let f = self
            .all_findings()
            .find(|f| f.id.as_str() == id)
            .ok_or_else(|| format!("Befund {id} nicht gefunden"))?;
        let mut v = serde_json::to_value(f).map_err(|e| e.to_string())?;
        if let Some(o) = v.as_object_mut() {
            o.remove("path");
            o.remove("review");
        }
        self.redacted_json(&v)
    }

    // ------------------------------------------------------------------ database / advisories

    fn db_query(&mut self, input: &Value) -> Result<String, String> {
        let sql = str_arg(input, "sql").ok_or("Parameter sql fehlt")?;
        let statement = ecomsec_core::db::guard_read_only_sql(sql).map_err(|e| e.to_string())?;
        let exec = self
            .sql
            .as_ref()
            .ok_or("Keine Datenbankverbindung verfügbar.")?;
        self.stats.db_queries += 1;
        let rows = exec.query(&statement)?;
        let mut out = format!("{} Zeilen für: {statement}\n", rows.len());
        let mut redactions = 0usize;
        for row in rows.iter().take(ecomsec_core::db::READ_ONLY_MAX_ROWS) {
            let mut obj = Map::new();
            for (col, val) in row {
                let r = redact_cell(col, &excerpt(val, 500));
                redactions += r.count;
                obj.insert(col.clone(), Value::String(r.text));
            }
            out.push_str(&Value::Object(obj).to_string());
            out.push('\n');
            if out.len() > MAX_OUTPUT {
                break;
            }
        }
        self.stats.redactions += redactions as u64;
        Ok(out)
    }

    fn lookup_advisory(&mut self, input: &Value) -> Result<String, String> {
        let q = str_arg(input, "id")
            .ok_or("Parameter id fehlt")?
            .trim()
            .to_lowercase();
        if q.is_empty() {
            return Err("leerer Suchbegriff".into());
        }
        let status: BTreeMap<String, (&str, String)> = self
            .report
            .advisories
            .iter()
            .map(|a| {
                (
                    a.advisory.id.to_lowercase(),
                    (
                        match a.state {
                            ecomsec_core::platform::PatchState::Patched => "gepatcht",
                            ecomsec_core::platform::PatchState::Vulnerable => "verwundbar",
                            ecomsec_core::platform::PatchState::Unknown => "unbekannt",
                            ecomsec_core::platform::PatchState::NotAffected => "nicht betroffen",
                        },
                        a.basis.clone(),
                    ),
                )
            })
            .collect();
        let mut hits = Vec::new();
        let mut seen = BTreeSet::new();
        let candidates = self
            .advisories
            .iter()
            .chain(self.report.advisories.iter().map(|a| &a.advisory));
        for a in candidates {
            let id = a.id.to_lowercase();
            let matches = id == q
                || id.contains(&q)
                || a.title.to_lowercase().contains(&q)
                || a.tags.iter().any(|t| t.to_lowercase() == q);
            if matches && seen.insert(id.clone()) {
                let st = status.get(&id);
                hits.push(json!({
                    "id": a.id,
                    "titel": a.title,
                    "schweregrad": a.severity,
                    "score": a.score,
                    "betroffen": a.affected.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
                    "behoben_in": a.fixed_in.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
                    "backpatch_hinweis": a.backpatch_note,
                    "referenz": a.reference,
                    "veroeffentlicht": a.published,
                    "tags": a.tags,
                    "status_dieser_installation": st.map(|s| s.0),
                    "begruendung": st.map(|s| s.1.clone()),
                }));
            }
            if hits.len() >= 10 {
                break;
            }
        }
        if hits.is_empty() {
            return Ok(format!(
                "Keine Advisory für {q:?} in der lokalen Datenbank gefunden."
            ));
        }
        self.redacted_json(&Value::Array(hits))
    }

    fn osv_lookup(&mut self, input: &Value) -> Result<String, String> {
        let package = str_arg(input, "package")
            .ok_or("Parameter package fehlt")?
            .trim();
        let version = str_arg(input, "version")
            .ok_or("Parameter version fehlt")?
            .trim();
        let name_ok = regex::Regex::new(r"^[a-z0-9_.\-]+/[a-z0-9_.\-]+$")
            .expect("valid regex")
            .is_match(package);
        let version_ok = !version.is_empty()
            && version.len() < 64
            && version
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-+_".contains(c));
        if !name_ok || !version_ok {
            return Err("ungültiger Composer-Paketname oder Version".into());
        }
        let osv = self
            .osv
            .as_ref()
            .ok_or("OSV-Abfragen sind nur mit --online erlaubt.")?;
        self.stats.osv_lookups += 1;
        let v = osv.lookup(package, version)?;
        serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
    }

    // ------------------------------------------------------------------ results

    fn record_verdict(&mut self, input: &Value) -> Result<String, String> {
        let mut ids: Vec<String> = Vec::new();
        if let Some(id) = str_arg(input, "finding_id") {
            ids.push(id.trim().to_string());
        }
        if let Some(arr) = input.get("finding_ids").and_then(Value::as_array) {
            ids.extend(
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(|s| s.trim().to_string()),
            );
        }
        ids.retain(|s| !s.is_empty());
        ids.dedup();
        if ids.is_empty() {
            return Err("finding_id oder finding_ids angeben".into());
        }
        let verdict = str_arg(input, "verdict")
            .and_then(ReviewVerdict::parse)
            .ok_or("verdict muss confirmed, likely_false_positive oder needs_human sein")?;
        let mut confidence = input
            .get("confidence")
            .and_then(Value::as_f64)
            .ok_or("confidence (0.0–1.0) fehlt")?;
        if confidence > 1.0 && confidence <= 100.0 {
            confidence /= 100.0;
        }
        let confidence = confidence.clamp(0.0, 1.0) as f32;
        let reasoning = str_arg(input, "reasoning")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or("reasoning fehlt")?;
        let reasoning = redact(&excerpt_keep_lines(reasoning, 2000)).text;
        let mut saved = 0;
        let mut unknown = Vec::new();
        for id in ids {
            let Some(f) = self.report.findings.iter().find(|f| f.id.as_str() == id) else {
                unknown.push(id);
                continue;
            };
            let record = VerdictRecord {
                finding_id: id.clone(),
                verdict,
                confidence,
                reasoning: reasoning.clone(),
                severity: Some(f.severity),
                title: f.title.clone(),
                subject: f.subject.clone(),
            };
            match self.verdicts.iter_mut().find(|v| v.finding_id == id) {
                Some(existing) => *existing = record,
                None => self.verdicts.push(record),
            }
            saved += 1;
        }
        if !unknown.is_empty() {
            return Err(format!(
                "{saved} Bewertung(en) gespeichert; unbekannte Befund-IDs: {} (neue Probleme mit record_finding erfassen)",
                unknown.join(", ")
            ));
        }
        Ok(format!(
            "Bewertung \"{}\" ({:.0} %) für {saved} Befund(e) gespeichert.",
            verdict.label(),
            confidence * 100.0
        ))
    }

    fn record_finding(&mut self, input: &Value) -> Result<String, String> {
        let severity = match str_arg(input, "severity")
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("critical") => Severity::Critical,
            Some("warning") => Severity::Warning,
            Some("info") => Severity::Info,
            _ => return Err("severity muss critical, warning oder info sein".into()),
        };
        let category_raw = str_arg(input, "category").ok_or("category fehlt")?;
        let category: Category = serde_json::from_value(json!(category_raw))
            .map_err(|_| format!("unbekannte Kategorie {category_raw:?}"))?;
        let title = required_text(input, "title", 200)?;
        let subject = required_text(input, "subject", 300)?;
        let description = required_text(input, "description", 4000)?;
        let evidence: Vec<String> = input
            .get("evidence")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .take(10)
                    .map(|s| redact(&excerpt(s, 500)).text)
                    .collect()
            })
            .unwrap_or_default();
        if evidence.is_empty() {
            return Err("evidence muss mindestens einen Beleg enthalten".into());
        }
        let rule = format!("agent_{}", category_name(category));
        let mut finding = Finding::new(
            severity,
            category,
            Source::Scanner,
            rule,
            subject.clone(),
            title,
        )
        .with_description(description);
        finding.evidence = evidence;
        finding
            .evidence
            .push(format!("Quelle: KI-Audit ({})", self.model));
        // Attach the file when the subject names one inside the root.
        if let Some(root) = self.root.clone() {
            let file_part = subject.split(':').next().unwrap_or(&subject);
            if let Ok((abs, _, _)) = self.resolve(file_part) {
                if abs.is_file() {
                    finding.group = abs
                        .parent()
                        .map(|p| relative_display(&root, p))
                        .filter(|g| !g.is_empty() && g != ".");
                    finding.path = Some(abs);
                }
            }
        }
        let id = finding.id.clone();
        if let Some(existing) = self.new_findings.iter_mut().find(|f| f.id == id) {
            *existing = finding;
        } else {
            if self.new_findings.len() >= MAX_NEW_FINDINGS {
                return Err(format!(
                    "Höchstzahl von {MAX_NEW_FINDINGS} neuen Befunden erreicht"
                ));
            }
            self.new_findings.push(finding);
        }
        Ok(format!("Neuer Befund erfasst: #{id}"))
    }
}

// ---------------------------------------------------------------------- helpers

/// Category names (snake_case) accepted by `record_finding`.
pub const CATEGORY_NAMES: [&str; 17] = [
    "known_webshell",
    "modified_since_reference",
    "code_in_upload_dir",
    "webserver_config_manipulation",
    "suspicious_pattern",
    "exploit_payload",
    "timestamp_anomaly",
    "attack_trace",
    "patch_status",
    "admin_account",
    "payment_configuration",
    "config_permissions",
    "exposed_file",
    "integrity_deviation",
    "third_party_injection",
    "scan_limitation",
    "informational",
];

pub fn category_name(c: Category) -> String {
    serde_json::to_value(c)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

pub fn verdict_name(v: ReviewVerdict) -> &'static str {
    match v {
        ReviewVerdict::Confirmed => "confirmed",
        ReviewVerdict::LikelyFalsePositive => "likely_false_positive",
        ReviewVerdict::NeedsHuman => "needs_human",
    }
}

fn str_arg<'a>(input: &'a Value, key: &str) -> Option<&'a str> {
    input.get(key).and_then(Value::as_str)
}

fn u64_arg(input: &Value, key: &str) -> Option<u64> {
    let v = input.get(key)?;
    v.as_u64()
        .or_else(|| v.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64))
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

fn required_text(input: &Value, key: &str, max: usize) -> Result<String, String> {
    let v = str_arg(input, key)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{key} fehlt"))?;
    Ok(redact(&excerpt_keep_lines(v, max)).text)
}

/// Truncate to `max` characters but keep line breaks (unlike `excerpt`).
fn excerpt_keep_lines(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

fn fmt_time(t: std::time::SystemTime) -> String {
    DateTime::<Utc>::from(t)
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string()
}

fn hexdump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!("{:08x}  {:<47}  {ascii}\n", i * 16, hex.join(" ")));
    }
    out
}

fn truncate_output(mut s: String) -> String {
    if s.len() <= MAX_OUTPUT {
        return s;
    }
    let mut cut = MAX_OUTPUT - 200;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
    s.push_str("\n… Ausgabe auf 64 KiB gekürzt.");
    s
}
