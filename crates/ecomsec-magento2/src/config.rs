//! Parsing of `app/etc/env.php` / `app/etc/config.php` (PHP arrays) and
//! version detection.

use ecomsec_core::db::DbCredentials;
use ecomsec_core::util::strip_php_comments;
use ecomsec_core::version::Version;
use std::path::Path;

/// A literal from a PHP array file.  Anything that is not a literal
/// (constants, `getenv()` calls, concatenations) is kept as [`PhpLit::Expr`].
#[derive(Debug, Clone, PartialEq)]
pub enum PhpLit {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<(Option<PhpLit>, PhpLit)>),
    Expr(String),
}

impl PhpLit {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PhpLit::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Scalar as string (`1`, `true`, `text`).
    pub fn scalar(&self) -> Option<String> {
        match self {
            PhpLit::Str(s) => Some(s.clone()),
            PhpLit::Int(i) => Some(i.to_string()),
            PhpLit::Float(f) => Some(f.to_string()),
            PhpLit::Bool(b) => Some(b.to_string()),
            PhpLit::Null => None,
            PhpLit::Array(_) => None,
            PhpLit::Expr(e) => Some(e.clone()),
        }
    }

    pub fn entries(&self) -> &[(Option<PhpLit>, PhpLit)] {
        match self {
            PhpLit::Array(a) => a,
            _ => &[],
        }
    }

    pub fn get(&self, key: &str) -> Option<&PhpLit> {
        self.entries()
            .iter()
            .find(|(k, _)| k.as_ref().and_then(|k| k.scalar()).as_deref() == Some(key))
            .map(|(_, v)| v)
    }

    /// Nested lookup: `path(&["db", "connection", "default", "host"])`.
    pub fn path(&self, keys: &[&str]) -> Option<&PhpLit> {
        let mut cur = self;
        for k in keys {
            cur = cur.get(k)?;
        }
        Some(cur)
    }
}

/// Parse the array returned by a PHP file (`<?php return [ … ];`).
/// Tolerant: unknown expressions are captured verbatim.
pub fn parse_php_return(text: &str) -> Option<PhpLit> {
    let code = strip_php_comments(text);
    let idx = find_keyword(&code, "return")?;
    let mut p = Parser {
        b: code.as_bytes(),
        i: idx + "return".len(),
    };
    p.value(0)
}

fn find_keyword(code: &str, kw: &str) -> Option<usize> {
    let b = code.as_bytes();
    let mut from = 0;
    while let Some(pos) = code[from..].find(kw) {
        let i = from + pos;
        let before = if i == 0 { b' ' } else { b[i - 1] };
        let after = b.get(i + kw.len()).copied().unwrap_or(b' ');
        if !(before.is_ascii_alphanumeric() || before == b'_' || before == b'$')
            && !(after.is_ascii_alphanumeric() || after == b'_')
        {
            return Some(i);
        }
        from = i + kw.len();
    }
    None
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn starts_with(&self, s: &str) -> bool {
        self.b[self.i..]
            .iter()
            .zip(s.as_bytes())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
            && self.b.len() - self.i >= s.len()
    }

    fn value(&mut self, depth: usize) -> Option<PhpLit> {
        if depth > 48 {
            return None;
        }
        self.ws();
        let c = self.peek()?;
        let v = match c {
            b'[' => {
                self.i += 1;
                PhpLit::Array(self.entries(b']', depth)?)
            }
            b'\'' | b'"' => PhpLit::Str(self.string(c)?),
            _ if self.starts_with("array") && {
                let mut j = self.i + 5;
                while j < self.b.len() && self.b[j].is_ascii_whitespace() {
                    j += 1;
                }
                self.b.get(j) == Some(&b'(')
            } =>
            {
                while self.peek()? != b'(' {
                    self.i += 1;
                }
                self.i += 1;
                PhpLit::Array(self.entries(b')', depth)?)
            }
            _ => self.expr()?,
        };
        // Concatenations and other operators turn the value into an expression.
        self.ws();
        if matches!(self.peek(), Some(b'.') | Some(b'?') | Some(b'+')) {
            let rest = self.expr()?;
            let text = match (&v, rest) {
                (PhpLit::Str(s), PhpLit::Expr(e)) => format!("'{s}'{e}"),
                (_, PhpLit::Expr(e)) => e,
                (_, other) => format!("{other:?}"),
            };
            return Some(PhpLit::Expr(text));
        }
        Some(v)
    }

    fn string(&mut self, q: u8) -> Option<String> {
        self.i += 1;
        let mut out = Vec::new();
        while let Some(c) = self.peek() {
            self.i += 1;
            if c == b'\\' {
                let n = self.peek()?;
                self.i += 1;
                match (q, n) {
                    (_, b'\\') => out.push(b'\\'),
                    (_, x) if x == q => out.push(x),
                    (b'"', b'n') => out.push(b'\n'),
                    (b'"', b't') => out.push(b'\t'),
                    (_, x) => {
                        out.push(b'\\');
                        out.push(x);
                    }
                }
            } else if c == q {
                return Some(String::from_utf8_lossy(&out).to_string());
            } else {
                out.push(c);
            }
        }
        None
    }

    /// Anything up to the next `,` / `]` / `)` / `;` / `=>` at nesting level 0.
    fn expr(&mut self) -> Option<PhpLit> {
        let start = self.i;
        let mut depth = 0i32;
        while let Some(c) = self.peek() {
            match c {
                b'\'' | b'"' => {
                    self.string(c)?;
                    continue;
                }
                b'(' | b'[' => depth += 1,
                b')' | b']' if depth == 0 => break,
                b')' | b']' => depth -= 1,
                b',' | b';' if depth == 0 => break,
                b'=' if depth == 0 && self.b.get(self.i + 1) == Some(&b'>') => break,
                _ => {}
            }
            self.i += 1;
        }
        let raw = String::from_utf8_lossy(&self.b[start..self.i])
            .trim()
            .to_string();
        if raw.is_empty() {
            return None;
        }
        Some(match raw.to_ascii_lowercase().as_str() {
            "true" => PhpLit::Bool(true),
            "false" => PhpLit::Bool(false),
            "null" => PhpLit::Null,
            _ => {
                if let Ok(i) = raw.parse::<i64>() {
                    PhpLit::Int(i)
                } else if let Ok(f) = raw.parse::<f64>() {
                    PhpLit::Float(f)
                } else {
                    PhpLit::Expr(raw)
                }
            }
        })
    }

    fn entries(&mut self, close: u8, depth: usize) -> Option<Vec<(Option<PhpLit>, PhpLit)>> {
        let mut out = Vec::new();
        loop {
            self.ws();
            match self.peek()? {
                c if c == close => {
                    self.i += 1;
                    return Some(out);
                }
                b',' => {
                    self.i += 1;
                    continue;
                }
                _ => {}
            }
            let first = self.value(depth + 1)?;
            self.ws();
            if self.peek() == Some(b'=') && self.b.get(self.i + 1) == Some(&b'>') {
                self.i += 2;
                let v = self.value(depth + 1)?;
                out.push((Some(first), v));
            } else {
                out.push((None, first));
            }
            if out.len() > 100_000 {
                return None;
            }
        }
    }
}

/// Values from `app/etc/env.php`.
#[derive(Debug, Clone, Default)]
pub struct EnvConfig {
    pub raw: Option<PhpLit>,
    pub db: Option<DbCredentials>,
    pub table_prefix: String,
    pub mage_mode: Option<String>,
    pub admin_front_name: Option<String>,
    pub crypt_key_present: bool,
    /// Number of keys (Magento appends a new key on rotation).
    pub crypt_keys: usize,
    pub document_root_is_pub: Option<bool>,
    pub install_date: Option<String>,
}

impl EnvConfig {
    pub fn load(root: &Path) -> Self {
        match std::fs::read_to_string(root.join("app/etc/env.php")) {
            Ok(t) => EnvConfig::parse(&t),
            Err(e) => {
                log::warn!("cannot read app/etc/env.php: {e}");
                EnvConfig::default()
            }
        }
    }

    pub fn parse(text: &str) -> Self {
        let Some(raw) = parse_php_return(text) else {
            return EnvConfig::default();
        };
        let s = |keys: &[&str]| raw.path(keys).and_then(|v| v.scalar());
        let conn = ["db", "connection", "default"];
        let db = match (
            s(&[conn[0], conn[1], conn[2], "host"]),
            s(&[conn[0], conn[1], conn[2], "dbname"]),
            s(&[conn[0], conn[1], conn[2], "username"]),
        ) {
            (Some(host), Some(dbname), Some(user)) => {
                let password = s(&[conn[0], conn[1], conn[2], "password"]).unwrap_or_default();
                let port = s(&[conn[0], conn[1], conn[2], "port"]).and_then(|p| p.parse().ok());
                Some(credentials(&host, &dbname, &user, &password, port))
            }
            _ => None,
        };
        let crypt = s(&["crypt", "key"]).unwrap_or_default();
        let prefix = s(&["db", "table_prefix"]).unwrap_or_default();
        EnvConfig {
            db,
            table_prefix: if prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                prefix
            } else {
                String::new()
            },
            mage_mode: s(&["MAGE_MODE"]),
            admin_front_name: s(&["backend", "frontName"]),
            crypt_key_present: !crypt.trim().is_empty(),
            crypt_keys: crypt.split_whitespace().count(),
            document_root_is_pub: raw
                .path(&["directories", "document_root_is_pub"])
                .map(|v| matches!(v, PhpLit::Bool(true) | PhpLit::Int(1))),
            install_date: s(&["install", "date"]),
            raw: Some(raw),
        }
    }
}

/// Magento's `host` may be `host`, `host:port` or a socket path
/// (`/var/run/mysqld/mysqld.sock` or `localhost:/path.sock`).
pub fn credentials(
    host: &str,
    dbname: &str,
    user: &str,
    password: &str,
    port: Option<u16>,
) -> DbCredentials {
    let host = host.trim();
    let (h, p, sock) = if host.starts_with('/') {
        ("localhost".to_string(), None, Some(host.to_string()))
    } else {
        match host.split_once(':') {
            Some((h, rest)) if rest.starts_with('/') => {
                (h.to_string(), None, Some(rest.to_string()))
            }
            Some((h, rest)) if rest.chars().all(|c| c.is_ascii_digit()) => {
                (h.to_string(), rest.parse().ok(), None)
            }
            _ => (host.to_string(), None, None),
        }
    };
    DbCredentials {
        host: h,
        port: p.or(port),
        user: user.to_string(),
        password: password.to_string(),
        database: dbname.to_string(),
        socket: sock,
    }
}

/// Enabled/disabled modules from `app/etc/config.php`.
pub fn modules(root: &Path) -> Option<Vec<(String, bool)>> {
    let text = std::fs::read_to_string(root.join("app/etc/config.php")).ok()?;
    let raw = parse_php_return(&text)?;
    Some(
        raw.get("modules")?
            .entries()
            .iter()
            .filter_map(|(k, v)| {
                let name = k.as_ref()?.scalar()?;
                let enabled = matches!(v, PhpLit::Int(1) | PhpLit::Bool(true))
                    || v.scalar().as_deref() == Some("1");
                Some((name, enabled))
            })
            .collect(),
    )
}

/// Edition of the installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edition {
    OpenSource,
    Commerce,
    Unknown,
}

impl Edition {
    pub fn label(self) -> &'static str {
        match self {
            Edition::OpenSource => "Magento Open Source",
            Edition::Commerce => "Adobe Commerce",
            Edition::Unknown => "unbekannt",
        }
    }
}

const PRODUCT_PACKAGES: &[(&str, Edition)] = &[
    ("magento/product-enterprise-edition", Edition::Commerce),
    ("magento/magento-cloud-metapackage", Edition::Commerce),
    ("magento/product-community-edition", Edition::OpenSource),
    ("magento/magento2-ee-base", Edition::Commerce),
    ("magento/magento2-base", Edition::OpenSource),
];

/// Version from `composer.lock` / `vendor/composer/installed.json` (product
/// metapackage or magento2-base), `vendor/magento/magento2-base/composer.json`,
/// the framework version (`103.0.6-p3` ↔ `2.4.6-p3`) or the project
/// `composer.json` constraint.
pub fn detect_version(root: &Path) -> (Option<Version>, String, Edition) {
    for rel in ["composer.lock", "vendor/composer/installed.json"] {
        let Ok(text) = std::fs::read_to_string(root.join(rel)) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let packages = json
            .get("packages")
            .and_then(|p| p.as_array())
            .cloned()
            .or_else(|| json.as_array().cloned())
            .unwrap_or_default();
        let edition = PRODUCT_PACKAGES
            .iter()
            .find(|(name, _)| {
                packages
                    .iter()
                    .any(|p| p.get("name").and_then(|n| n.as_str()) == Some(name))
            })
            .map(|(_, e)| *e)
            .unwrap_or(Edition::Unknown);
        for (name, _) in PRODUCT_PACKAGES {
            if *name == "magento/magento-cloud-metapackage" {
                continue;
            }
            if let Some(v) = packages
                .iter()
                .find(|p| p.get("name").and_then(|n| n.as_str()) == Some(name))
                .and_then(|p| p.get("version").and_then(|v| v.as_str()))
                .and_then(Version::parse)
            {
                return (Some(v), format!("{rel} ({name})"), edition);
            }
        }
        if let Some(v) = packages
            .iter()
            .find(|p| p.get("name").and_then(|n| n.as_str()) == Some("magento/framework"))
            .and_then(|p| p.get("version").and_then(|v| v.as_str()))
            .and_then(product_from_framework)
        {
            return (
                Some(v),
                format!("{rel} (magento/framework, abgeleitet)"),
                edition,
            );
        }
    }
    for (rel, edition) in [
        (
            "vendor/magento/magento2-ee-base/composer.json",
            Edition::Commerce,
        ),
        (
            "vendor/magento/magento2-base/composer.json",
            Edition::OpenSource,
        ),
    ] {
        if let Some(v) = composer_version(&root.join(rel)) {
            return (Version::parse(&v), rel.to_string(), edition);
        }
    }
    if let Some(v) = composer_version(&root.join("vendor/magento/framework/composer.json"))
        .and_then(|v| product_from_framework(&v))
    {
        return (
            Some(v),
            "vendor/magento/framework/composer.json (abgeleitet)".into(),
            Edition::Unknown,
        );
    }
    if let Ok(text) = std::fs::read_to_string(root.join("composer.json")) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
            for (name, edition) in PRODUCT_PACKAGES {
                if let Some(c) = json
                    .get("require")
                    .and_then(|r| r.get(*name))
                    .and_then(|c| c.as_str())
                {
                    let c = c.trim().trim_start_matches(['=', '^', '~', 'v']);
                    if c.chars().next().is_some_and(|x| x.is_ascii_digit())
                        && !c.contains(['*', ' ', '|', '>', '<'])
                    {
                        return (
                            Version::parse(c),
                            format!("composer.json (Constraint {name})"),
                            *edition,
                        );
                    }
                }
            }
        }
    }
    (None, "nicht gefunden".into(), Edition::Unknown)
}

fn composer_version(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    json.get("version")?.as_str().map(str::to_string)
}

/// `magento/framework` 103.0.N ↔ Magento 2.4.N, 102.0.N ↔ 2.3.N,
/// 101.0.N ↔ 2.2.N (patch suffix `-pK` is kept).
pub fn product_from_framework(fw: &str) -> Option<Version> {
    let fw = fw.trim().trim_start_matches('v');
    let (core, suffix) = match fw.split_once('-') {
        Some((c, s)) => (c, format!("-{s}")),
        None => (fw, String::new()),
    };
    let parts: Vec<&str> = core.split('.').collect();
    let minor = match *parts.first()? {
        "103" => 4,
        "102" => 3,
        "101" => 2,
        _ => return None,
    };
    let patch = parts.get(2)?;
    Version::parse(&format!("2.{minor}.{patch}{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENV: &str = r#"<?php
return [
    'backend' => [
        'frontName' => 'admin_k3x9'
    ],
    'crypt' => [
        'key' => "0123456789abcdef0123456789abcdef\nfedcba9876543210fedcba9876543210"
    ],
    'db' => [
        'table_prefix' => 'm2_',
        'connection' => [
            'default' => [
                'host' => 'db.internal:3307',
                'dbname' => 'magento',
                'username' => 'mage',
                'password' => 'p\'w"d',
                'model' => 'mysql4',
                'active' => '1',
                'driver_options' => [
                    1014 => false
                ]
            ]
        ]
    ],
    // 'MAGE_MODE' => 'developer',
    'MAGE_MODE' => 'production',
    'session' => array('save' => 'files'),
    'directories' => [
        'document_root_is_pub' => true
    ],
    'queue' => ['amqp' => ['host' => getenv('AMQP_HOST') ?: 'localhost', 'port' => '5672']],
    'install' => [
        'date' => 'Tue, 02 Jan 2024 10:00:00 +0000'
    ]
];
"#;

    #[test]
    fn parses_env_php() {
        let env = EnvConfig::parse(ENV);
        let db = env.db.as_ref().unwrap();
        assert_eq!(db.host, "db.internal");
        assert_eq!(db.port, Some(3307));
        assert_eq!(db.database, "magento");
        assert_eq!(db.user, "mage");
        assert_eq!(db.password, "p'w\"d");
        assert_eq!(env.table_prefix, "m2_");
        assert_eq!(env.mage_mode.as_deref(), Some("production"));
        assert_eq!(env.admin_front_name.as_deref(), Some("admin_k3x9"));
        assert!(env.crypt_key_present);
        assert_eq!(env.crypt_keys, 2);
        assert_eq!(env.document_root_is_pub, Some(true));
        let raw = env.raw.as_ref().unwrap();
        assert!(matches!(
            raw.path(&["queue", "amqp", "host"]),
            Some(PhpLit::Expr(_))
        ));
        assert_eq!(
            raw.path(&["session", "save"]).and_then(|v| v.as_str()),
            Some("files")
        );
    }

    #[test]
    fn socket_hosts() {
        let c = credentials("/var/run/mysqld/mysqld.sock", "m", "u", "p", None);
        assert_eq!(c.socket.as_deref(), Some("/var/run/mysqld/mysqld.sock"));
        let c = credentials("localhost", "m", "u", "p", Some(3308));
        assert_eq!(c.port, Some(3308));
    }

    #[test]
    fn versions() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("composer.lock"),
            r#"{"packages":[{"name":"magento/framework","version":"103.0.6-p3"},{"name":"magento/product-community-edition","version":"2.4.6-p3"}]}"#,
        )
        .unwrap();
        let (v, src, ed) = detect_version(tmp.path());
        assert_eq!(v.unwrap().to_string(), "2.4.6-p3");
        assert!(src.contains("product-community-edition"));
        assert_eq!(ed, Edition::OpenSource);
        assert_eq!(
            product_from_framework("103.0.7-p2").unwrap(),
            Version::parse("2.4.7-p2").unwrap()
        );
        assert_eq!(
            product_from_framework("102.0.7").unwrap().to_string(),
            "2.3.7"
        );
    }
}
