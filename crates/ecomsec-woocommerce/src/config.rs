//! Parsing of `wp-config.php` and version detection for WordPress and
//! WooCommerce.

use ecomsec_core::db::DbCredentials;
use ecomsec_core::util::strip_php_comments;
use ecomsec_core::version::Version;
use regex::Regex;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The default salt placeholder of `wp-config-sample.php`.
pub const SALT_PLACEHOLDER: &str = "put your unique phrase here";

/// Authentication keys and salts defined in `wp-config.php`.
pub const SALT_KEYS: &[&str] = &[
    "AUTH_KEY",
    "SECURE_AUTH_KEY",
    "LOGGED_IN_KEY",
    "NONCE_KEY",
    "AUTH_SALT",
    "SECURE_AUTH_SALT",
    "LOGGED_IN_SALT",
    "NONCE_SALT",
];

/// Values from `wp-config.php`.
#[derive(Debug, Clone, Default)]
pub struct WpConfig {
    /// Absolute path of the configuration file that was read.
    pub path: Option<PathBuf>,
    /// `true` when `wp-config.php` lives one directory above the web root.
    pub outside_webroot: bool,
    pub defines: BTreeMap<String, String>,
    pub table_prefix: String,
    pub db: Option<DbCredentials>,
    /// `include`/`require` statements other than the regular
    /// `require_once ABSPATH . 'wp-settings.php'`.
    pub extra_includes: Vec<String>,
}

impl WpConfig {
    /// Locate `wp-config.php`: in the web root or – as WordPress itself
    /// does – one level up, provided that directory is not another
    /// WordPress installation (no `wp-settings.php`).
    pub fn locate(root: &Path) -> Option<(PathBuf, bool)> {
        let direct = root.join("wp-config.php");
        if direct.is_file() {
            return Some((direct, false));
        }
        let parent = root.parent()?;
        let up = parent.join("wp-config.php");
        if up.is_file() && !parent.join("wp-settings.php").is_file() {
            return Some((up, true));
        }
        None
    }

    pub fn load(root: &Path) -> Self {
        let Some((path, outside)) = WpConfig::locate(root) else {
            return WpConfig::from_env(WpConfig {
                table_prefix: "wp_".into(),
                ..Default::default()
            });
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let mut cfg = WpConfig::parse(&text);
                cfg.path = Some(path);
                cfg.outside_webroot = outside;
                WpConfig::from_env(cfg)
            }
            Err(e) => {
                log::warn!("cannot read {}: {e}", path.display());
                WpConfig {
                    path: Some(path),
                    outside_webroot: outside,
                    table_prefix: "wp_".into(),
                    ..Default::default()
                }
            }
        }
    }

    /// Container setups (official Docker image) read the credentials from
    /// `WORDPRESS_DB_*` environment variables via `getenv_docker()`.
    fn from_env(mut cfg: WpConfig) -> Self {
        if cfg.db.is_none() {
            let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
            if let (Some(host), Some(name), Some(user)) = (
                env("WORDPRESS_DB_HOST"),
                env("WORDPRESS_DB_NAME"),
                env("WORDPRESS_DB_USER"),
            ) {
                cfg.db = Some(credentials(
                    &host,
                    &name,
                    &user,
                    &env("WORDPRESS_DB_PASSWORD").unwrap_or_default(),
                ));
            }
            if let Some(p) = env("WORDPRESS_TABLE_PREFIX") {
                if valid_prefix(&p) {
                    cfg.table_prefix = p;
                }
            }
        }
        cfg
    }

    pub fn parse(text: &str) -> Self {
        static DEFINE: OnceLock<Regex> = OnceLock::new();
        static PREFIX: OnceLock<Regex> = OnceLock::new();
        static INCLUDE: OnceLock<Regex> = OnceLock::new();
        let define = DEFINE.get_or_init(|| {
            Regex::new(
                r#"(?mi)\bdefine\s*\(\s*(?:'([A-Za-z0-9_]+)'|"([A-Za-z0-9_]+)")\s*,\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"|([0-9]+|true|false))\s*\)"#,
            )
            .expect("regex")
        });
        let prefix = PREFIX.get_or_init(|| {
            Regex::new(r#"\$table_prefix\s*=\s*['"]([A-Za-z0-9_]*)['"]"#).expect("regex")
        });
        let include = INCLUDE.get_or_init(|| {
            Regex::new(r#"(?mi)(?:^|[;{}\s@])((?:include|require)(?:_once)?\b[^;]{0,200})"#)
                .expect("regex")
        });
        let code = strip_php_comments(text);
        let mut defines = BTreeMap::new();
        for c in define.captures_iter(&code) {
            let key = c.get(1).or_else(|| c.get(2)).map(|m| m.as_str());
            let value = c
                .get(3)
                .or_else(|| c.get(4))
                .or_else(|| c.get(5))
                .map(|m| unescape(m.as_str()))
                .unwrap_or_default();
            if let Some(k) = key {
                defines.insert(k.to_string(), value);
            }
        }
        let table_prefix = prefix
            .captures(&code)
            .map(|c| c[1].to_string())
            .filter(|p| valid_prefix(p))
            .unwrap_or_else(|| "wp_".into());
        let extra_includes = include
            .captures_iter(&code)
            .map(|c| c[1].trim().to_string())
            .filter(|s| !is_regular_include(s))
            .collect();
        let get = |k: &str| defines.get(k).cloned().filter(|v| !v.is_empty());
        let db = match (get("DB_HOST"), get("DB_NAME"), get("DB_USER")) {
            (Some(host), Some(name), Some(user)) => Some(credentials(
                &host,
                &name,
                &user,
                &get("DB_PASSWORD").unwrap_or_default(),
            )),
            _ => None,
        };
        WpConfig {
            path: None,
            outside_webroot: false,
            defines,
            table_prefix,
            db,
            extra_includes,
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.defines.get(key).map(String::as_str)
    }

    /// `true`/`false` constants (`define('DISALLOW_FILE_EDIT', true)`).
    pub fn flag(&self, key: &str) -> Option<bool> {
        self.get(key)
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "true" | "1"))
    }

    /// Salts that are missing, empty or still the sample placeholder.
    pub fn weak_salts(&self) -> Vec<&'static str> {
        SALT_KEYS
            .iter()
            .copied()
            .filter(|k| match self.get(k) {
                None => true,
                Some(v) => v.trim().len() < 16 || v.contains(SALT_PLACEHOLDER),
            })
            .collect()
    }
}

/// Table prefixes are interpolated into SQL: only `[A-Za-z0-9_]` is allowed.
pub fn valid_prefix(p: &str) -> bool {
    !p.is_empty() && p.len() <= 64 && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_regular_include(stmt: &str) -> bool {
    let s = stmt.to_ascii_lowercase().replace(' ', "");
    s.contains("wp-settings.php")
        || s.contains("wp-load.php") && s.contains("abspath")
        // Composer autoloaders and environment loaders of managed hostings /
        // Bedrock-like setups.
        || s.ends_with("vendor/autoload.php'")
        || s.ends_with("vendor/autoload.php\"")
        || s.ends_with("vendor/autoload.php')")
        || s.ends_with("vendor/autoload.php\")")
}

/// Build credentials from `DB_HOST` which may be `host`, `host:port`,
/// `host:/path/to/socket` or `:/path/to/socket`.
pub fn credentials(host: &str, name: &str, user: &str, password: &str) -> DbCredentials {
    let host = host.trim();
    let (host, port, socket) = match host.split_once(':') {
        Some((h, rest)) if rest.starts_with('/') => (
            if h.is_empty() { "localhost" } else { h }.to_string(),
            None,
            Some(rest.to_string()),
        ),
        Some((h, rest)) if !host.starts_with('[') && rest.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), rest.parse().ok(), None)
        }
        _ if host.starts_with('[') => match host.rsplit_once("]:") {
            Some((h, p)) => (format!("{h}]"), p.parse().ok(), None),
            None => (host.to_string(), None, None),
        },
        _ => (host.to_string(), None, None),
    };
    DbCredentials {
        host: host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string(),
        port,
        user: user.to_string(),
        password: password.to_string(),
        database: name.to_string(),
        socket,
    }
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(o) => out.push(o),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// WordPress core version from `wp-includes/version.php` (`$wp_version`).
pub fn wordpress_version(root: &Path) -> (Option<Version>, String) {
    let re =
        Regex::new(r#"\$wp_version\s*=\s*['"]([0-9]+(?:\.[0-9]+)*[^'"]*)['"]"#).expect("regex");
    let rel = "wp-includes/version.php";
    if let Ok(text) = std::fs::read_to_string(root.join(rel)) {
        if let Some(v) = re.captures(&text).and_then(|c| Version::parse(&c[1])) {
            return (Some(v), rel.to_string());
        }
    }
    (None, "nicht gefunden".into())
}

/// Read the WordPress file header (`Plugin Name:`, `Version:` …) of a plugin
/// or theme file.  WordPress only looks at the first 8 KiB.
pub fn file_headers(path: &Path) -> BTreeMap<String, String> {
    use std::io::Read;
    let mut buf = Vec::new();
    if let Ok(f) = std::fs::File::open(path) {
        let _ = f.take(8192).read_to_end(&mut buf);
    }
    parse_headers(&String::from_utf8_lossy(&buf))
}

pub fn parse_headers(text: &str) -> BTreeMap<String, String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?mi)^[ \t/*#@]*(Plugin Name|Theme Name|Version|Author|Requires at least|WC requires at least|Update URI|Text Domain|Template)\s*:\s*(.+?)\s*(?:\*/)?\s*$",
        )
        .expect("regex")
    });
    let mut out = BTreeMap::new();
    for c in re.captures_iter(text) {
        let key = c[1].to_ascii_lowercase();
        out.entry(key).or_insert_with(|| c[2].trim().to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?php
/** The name of the database for WordPress */
define( 'DB_NAME', 'shop_wp' );
define( 'DB_USER', 'wpuser' );
define( 'DB_PASSWORD', 'se\'cret' );
define( 'DB_HOST', 'db.local:3307' );
// define( 'DB_NAME', 'commented_out' );
define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'DISALLOW_FILE_EDIT', true );
$table_prefix = 'shop7_';
@include "\x2fvar/www/.cache/favicon_8a1b.ico";
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';
"#;

    #[test]
    fn parses_wp_config() {
        let c = WpConfig::parse(SAMPLE);
        let db = c.db.as_ref().unwrap();
        assert_eq!(db.database, "shop_wp");
        assert_eq!(db.password, "se'cret");
        assert_eq!(db.host, "db.local");
        assert_eq!(db.port, Some(3307));
        assert_eq!(c.table_prefix, "shop7_");
        assert_eq!(c.flag("DISALLOW_FILE_EDIT"), Some(true));
        assert!(c.weak_salts().contains(&"AUTH_KEY"));
        assert!(c.weak_salts().contains(&"NONCE_SALT"));
        assert_eq!(c.extra_includes.len(), 1, "{:?}", c.extra_includes);
        assert!(c.extra_includes[0].contains("favicon_8a1b.ico"));
    }

    #[test]
    fn db_host_variants() {
        let s = credentials("localhost:/var/run/mysqld/mysqld.sock", "d", "u", "p");
        assert_eq!(s.socket.as_deref(), Some("/var/run/mysqld/mysqld.sock"));
        assert_eq!(s.host, "localhost");
        let s = credentials(":/tmp/mysql.sock", "d", "u", "p");
        assert_eq!(s.socket.as_deref(), Some("/tmp/mysql.sock"));
        let s = credentials("127.0.0.1", "d", "u", "p");
        assert_eq!((s.host.as_str(), s.port), ("127.0.0.1", None));
        let s = credentials("[::1]:3308", "d", "u", "p");
        assert_eq!((s.host.as_str(), s.port), ("::1", Some(3308)));
    }

    #[test]
    fn locates_config_above_webroot() {
        let tmp = tempfile::tempdir().unwrap();
        let web = tmp.path().join("public_html");
        std::fs::create_dir_all(&web).unwrap();
        std::fs::write(tmp.path().join("wp-config.php"), SAMPLE).unwrap();
        let (p, outside) = WpConfig::locate(&web).unwrap();
        assert!(outside);
        assert_eq!(p, tmp.path().join("wp-config.php"));
        // Not when the parent is itself a WordPress installation.
        std::fs::write(tmp.path().join("wp-settings.php"), "<?php").unwrap();
        assert!(WpConfig::locate(&web).is_none());
    }

    #[test]
    fn versions_and_headers() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("wp-includes")).unwrap();
        std::fs::write(
            tmp.path().join("wp-includes/version.php"),
            "<?php\n$wp_version = '6.4.2';\n$wp_db_version = 56657;\n",
        )
        .unwrap();
        assert_eq!(
            wordpress_version(tmp.path()).0.unwrap().to_string(),
            "6.4.2"
        );
        let h = parse_headers(
            "<?php\n/**\n * Plugin Name: WooCommerce\n * Version: 8.9.1\n * Author: Automattic\n */",
        );
        assert_eq!(h["plugin name"], "WooCommerce");
        assert_eq!(h["version"], "8.9.1");
    }
}
