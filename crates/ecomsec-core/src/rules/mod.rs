//! A small YARA-like rule engine.
//!
//! Rules are described in TOML (see `signatures/*.toml`) and consist of named
//! strings (literal or regex, optionally case-insensitive) plus a condition
//! (`any`, `all` or `N of them`).  This covers the vast majority of
//! real-world webshell / obfuscation rules without pulling in a full YARA
//! runtime, and users can add their own rule files at runtime.

use crate::finding::{Category, Severity};
use regex::bytes::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("rule file {0}: {1}")]
    Parse(String, String),
    #[error("rule {rule}: invalid pattern {pattern:?}: {source}")]
    Pattern {
        rule: String,
        pattern: String,
        #[source]
        source: regex::Error,
    },
    #[error("rule {0}: condition {1:?} is not valid (use any, all or a number)")]
    Condition(String, String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Raw rule file representation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleFile {
    #[serde(default)]
    pub rule: Vec<RuleSpec>,
}

/// One rule as written in TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSpec {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub severity: Severity,
    #[serde(default = "default_category")]
    pub category: Category,
    /// `any` (default), `all` or a number of required string matches.
    #[serde(default = "default_condition")]
    pub condition: String,
    /// Restrict the rule to certain file "classes" (`php`, `htaccess`,
    /// `template`, `js`, `log`, `any`).  Empty means `php`.
    #[serde(default)]
    pub applies_to: Vec<String>,
    /// Tags such as `webshell`, `obfuscation`, `cve-2026-54390`, `ssti`.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Reference (URL, advisory id) for the rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default)]
    pub strings: Vec<StringSpec>,
}

fn default_category() -> Category {
    Category::SuspiciousPattern
}

fn default_condition() -> String {
    "any".to_string()
}

/// A string inside a rule: either a literal or a regular expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub literal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    #[serde(default)]
    pub nocase: bool,
}

#[derive(Debug, Clone)]
enum Condition {
    Any,
    All,
    AtLeast(usize),
}

/// A compiled rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub spec: RuleSpec,
    patterns: Vec<Regex>,
    condition: Condition,
}

/// Result of applying one rule to a buffer.
#[derive(Debug, Clone)]
pub struct RuleMatch<'a> {
    pub rule: &'a Rule,
    /// Excerpts around each matched string.
    pub excerpts: Vec<String>,
}

impl Rule {
    pub fn compile(spec: RuleSpec) -> Result<Self, RuleError> {
        let mut patterns = Vec::with_capacity(spec.strings.len());
        for s in &spec.strings {
            let (pattern, is_regex) = match (&s.regex, &s.literal) {
                (Some(r), _) => (r.clone(), true),
                (None, Some(l)) => (regex::escape(l), false),
                (None, None) => continue,
            };
            let _ = is_regex;
            let re = RegexBuilder::new(&pattern)
                .case_insensitive(s.nocase)
                .unicode(false)
                .dot_matches_new_line(false)
                .size_limit(1 << 24)
                .build()
                .map_err(|source| RuleError::Pattern {
                    rule: spec.name.clone(),
                    pattern: pattern.clone(),
                    source,
                })?;
            patterns.push(re);
        }
        let condition = match spec.condition.trim().to_ascii_lowercase().as_str() {
            "" | "any" | "any of them" => Condition::Any,
            "all" | "all of them" => Condition::All,
            other => {
                let num = other
                    .trim_end_matches(" of them")
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| RuleError::Condition(spec.name.clone(), spec.condition.clone()))?;
                Condition::AtLeast(num.max(1))
            }
        };
        Ok(Rule {
            spec,
            patterns,
            condition,
        })
    }

    pub fn name(&self) -> &str {
        &self.spec.name
    }

    /// Whether the rule is meant for this file class.
    pub fn applies_to(&self, class: &str) -> bool {
        if self.spec.applies_to.is_empty() {
            return class == "php";
        }
        self.spec
            .applies_to
            .iter()
            .any(|c| c == "any" || c.eq_ignore_ascii_case(class))
    }

    /// Apply the rule to `data`.
    pub fn matches<'a>(&'a self, data: &[u8]) -> Option<RuleMatch<'a>> {
        if self.patterns.is_empty() {
            return None;
        }
        let required = match self.condition {
            Condition::Any => 1,
            Condition::All => self.patterns.len(),
            Condition::AtLeast(n) => n.min(self.patterns.len()),
        };
        let mut excerpts = Vec::new();
        let mut hits = 0usize;
        for re in &self.patterns {
            if let Some(m) = re.find(data) {
                hits += 1;
                excerpts.push(excerpt_around(data, m.start(), m.end()));
            }
        }
        if hits >= required {
            Some(RuleMatch {
                rule: self,
                excerpts,
            })
        } else {
            None
        }
    }
}

fn excerpt_around(data: &[u8], start: usize, end: usize) -> String {
    let from = start.saturating_sub(24);
    let to = (end + 24).min(data.len());
    let slice = String::from_utf8_lossy(&data[from..to]);
    crate::util::excerpt(&slice, 120)
}

/// A set of compiled rules.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn empty() -> Self {
        RuleSet::default()
    }

    /// Parse a TOML rule file.
    pub fn from_toml(name: &str, text: &str) -> Result<Self, RuleError> {
        let file: RuleFile =
            toml::from_str(text).map_err(|e| RuleError::Parse(name.to_string(), e.to_string()))?;
        let mut rules = Vec::with_capacity(file.rule.len());
        for spec in file.rule {
            rules.push(Rule::compile(spec)?);
        }
        Ok(RuleSet { rules })
    }

    /// Load every `*.toml` rule file from a directory (non-recursive).
    pub fn from_dir(dir: &Path) -> Result<Self, RuleError> {
        let mut set = RuleSet::empty();
        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().map(|e| e == "toml").unwrap_or(false))
            .collect();
        entries.sort();
        for path in entries {
            let text = std::fs::read_to_string(&path)?;
            set.extend(RuleSet::from_toml(&path.display().to_string(), &text)?);
        }
        Ok(set)
    }

    pub fn extend(&mut self, other: RuleSet) {
        self.rules.extend(other.rules);
    }

    pub fn push(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter()
    }

    /// Apply all rules that apply to `class` to `data`.
    pub fn scan<'a>(&'a self, class: &str, data: &[u8]) -> Vec<RuleMatch<'a>> {
        self.rules
            .iter()
            .filter(|r| r.applies_to(class))
            .filter_map(|r| r.matches(data))
            .collect()
    }

    /// Group rules by tag (for `rules list`).
    pub fn by_tag(&self) -> BTreeMap<String, Vec<&Rule>> {
        let mut map: BTreeMap<String, Vec<&Rule>> = BTreeMap::new();
        for r in &self.rules {
            if r.spec.tags.is_empty() {
                map.entry("untagged".into()).or_default().push(r);
            }
            for t in &r.spec.tags {
                map.entry(t.clone()).or_default().push(r);
            }
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[[rule]]
name = "test_eval_base64"
severity = "critical"
condition = "all"
strings = [
  { regex = "eval\\s*\\(" , nocase = true },
  { literal = "base64_decode(" },
]

[[rule]]
name = "test_two_of"
severity = "warning"
condition = "2"
applies_to = ["php", "htaccess"]
strings = [
  { literal = "alpha" },
  { literal = "beta" },
  { literal = "gamma" },
]
"#;

    #[test]
    fn compiles_and_matches() {
        let set = RuleSet::from_toml("sample", SAMPLE).unwrap();
        assert_eq!(set.len(), 2);
        let hits = set.scan("php", b"<?php EVAL (base64_decode('x'));");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule.name(), "test_eval_base64");

        let hits = set.scan("php", b"alpha beta");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule.name(), "test_two_of");
        assert!(set.scan("php", b"alpha only").is_empty());
        assert!(set.scan("js", b"alpha beta").is_empty());
        assert_eq!(set.scan("htaccess", b"beta gamma").len(), 1);
    }
}
