//! A small YARA-like rule engine.
//!
//! Rules are described in TOML (see `signatures/*.toml`) and consist of named
//! strings (literal or regex, optionally case-insensitive) plus a condition
//! (`any`, `all` or `N of them`).  This covers the vast majority of
//! real-world webshell / obfuscation rules without pulling in a full YARA
//! runtime, and users can add their own rule files at runtime.
//!
//! `within = N` adds a proximity condition: the required strings have to
//! occur inside one window of `N` bytes.  Large bundles contain every
//! keyword somewhere; malware uses them next to each other.

use crate::deobf;
use crate::finding::{Category, Severity};
use regex::bytes::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, RwLock};
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
    /// `template`, `js`, `log`, `image`, `other`, `any`).  Empty means
    /// `php`.  The class `decoded` selects payloads that only exist after
    /// de-obfuscation (see `ecomsec_core::deobf`).
    #[serde(default)]
    pub applies_to: Vec<String>,
    /// The required strings must match within a window of this many bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub within: Option<usize>,
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
    /// Pattern sources as compiled (case-insensitivity inlined), for the
    /// prefilter set.
    sources: Vec<String>,
    condition: Condition,
}

/// Result of applying one rule to a buffer.
#[derive(Debug, Clone)]
pub struct RuleMatch<'a> {
    pub rule: &'a Rule,
    /// Excerpts around each matched string.
    pub excerpts: Vec<String>,
    /// De-obfuscation steps that made the match visible
    /// (`base64_decode → gzinflate`); `None` when the rule matches the
    /// content as written.  Set by [`RuleSet::scan_deep`].
    pub chain: Option<String>,
}

impl Rule {
    pub fn compile(spec: RuleSpec) -> Result<Self, RuleError> {
        let mut patterns = Vec::with_capacity(spec.strings.len());
        let mut sources = Vec::with_capacity(spec.strings.len());
        for s in &spec.strings {
            let pattern = match (&s.regex, &s.literal) {
                (Some(r), _) => r.clone(),
                (None, Some(l)) => regex::escape(l),
                (None, None) => continue,
            };
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
            sources.push(if s.nocase {
                format!("(?i:{pattern})")
            } else {
                format!("(?:{pattern})")
            });
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
            sources,
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
        // `any` covers the file classes, not de-obfuscated payloads: those
        // are scanned with the class of the file they came from.
        self.spec
            .applies_to
            .iter()
            .any(|c| (c == "any" && class != "decoded") || c.eq_ignore_ascii_case(class))
    }

    /// Number of strings that have to match.
    fn required(&self) -> usize {
        match self.condition {
            Condition::Any => 1,
            Condition::All => self.patterns.len(),
            Condition::AtLeast(n) => n.min(self.patterns.len()),
        }
    }

    /// Apply the rule to `data`.
    pub fn matches<'a>(&'a self, data: &[u8]) -> Option<RuleMatch<'a>> {
        if self.patterns.is_empty() {
            return None;
        }
        let required = self.required();
        let mut excerpts = Vec::new();
        let mut hits = 0usize;
        for re in &self.patterns {
            if let Some(m) = re.find(data) {
                hits += 1;
                excerpts.push(excerpt_around(data, m.start(), m.end()));
            }
        }
        if hits < required {
            return None;
        }
        if let Some(window) = self.spec.within {
            excerpts = self.window_match(data, required, window)?;
        }
        Some(RuleMatch {
            rule: self,
            excerpts,
            chain: None,
        })
    }

    /// Find a window of `window` bytes that contains matches of at least
    /// `required` different strings; returns the excerpts inside it.
    fn window_match(&self, data: &[u8], required: usize, window: usize) -> Option<Vec<String>> {
        // (start, end, pattern index)
        let mut events: Vec<(usize, usize, usize)> = Vec::new();
        for (idx, re) in self.patterns.iter().enumerate() {
            for m in re.find_iter(data) {
                events.push((m.start(), m.end(), idx));
                if events.len() > MAX_WINDOW_EVENTS {
                    // Too dense to place a window exactly.  Reporting is the
                    // safe side: padding must not switch a rule off.
                    return Some(vec![excerpt_around(data, m.start(), m.end())]);
                }
            }
        }
        events.sort_unstable();
        let mut counts = vec![0usize; self.patterns.len()];
        let mut distinct = 0usize;
        let mut left = 0usize;
        for right in 0..events.len() {
            let idx = events[right].2;
            counts[idx] += 1;
            if counts[idx] == 1 {
                distinct += 1;
            }
            while events[right].0 - events[left].0 > window {
                let l = events[left].2;
                counts[l] -= 1;
                if counts[l] == 0 {
                    distinct -= 1;
                }
                left += 1;
            }
            if distinct >= required {
                let mut seen = vec![false; self.patterns.len()];
                let mut excerpts = Vec::new();
                for &(start, end, idx) in &events[left..=right] {
                    if !seen[idx] {
                        seen[idx] = true;
                        excerpts.push(excerpt_around(data, start, end));
                    }
                }
                return Some(excerpts);
            }
        }
        None
    }
}

/// Upper bound for match positions collected by a proximity rule.
const MAX_WINDOW_EVENTS: usize = 200_000;

fn excerpt_around(data: &[u8], start: usize, end: usize) -> String {
    let from = start.saturating_sub(24);
    let to = (end + 24).min(data.len());
    let slice = String::from_utf8_lossy(&data[from..to]);
    crate::util::excerpt(&slice, 120)
}

/// A set of compiled rules.
#[derive(Debug, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
    /// Prefilter per class combination, built on first use.
    prefilters: RwLock<HashMap<String, Arc<Prefilter>>>,
}

impl Clone for RuleSet {
    fn clone(&self) -> Self {
        RuleSet {
            rules: self.rules.clone(),
            prefilters: RwLock::default(),
        }
    }
}

/// All strings of the rules for one class in a single automaton.  One pass
/// over a file tells which rules can match at all; only those are evaluated
/// string by string.  Most files match nothing and are done after that pass.
#[derive(Debug)]
struct Prefilter {
    /// `None` when the combined automaton could not be built; every rule is
    /// then evaluated on its own.
    set: Option<RegexSet>,
    rules: Vec<PrefilterRule>,
}

#[derive(Debug)]
struct PrefilterRule {
    /// Index into `RuleSet::rules`.
    rule: usize,
    /// The rule's strings inside the set.
    range: std::ops::Range<usize>,
    /// Strings kept out of the set (see [`is_heavy`]); they count as
    /// possible matches.
    heavy: usize,
}

/// Strings with a large counted repetition (`.{0,300}`) multiply the states
/// of a combined automaton and would make the single pass slower than the
/// separate searches it replaces.  They stay out of the prefilter.
fn is_heavy(pattern: &str) -> bool {
    const MAX_BOUND: u32 = 80;
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while let Some(open) = bytes[i..].iter().position(|b| *b == b'{').map(|p| p + i) {
        let Some(close) = bytes[open..]
            .iter()
            .position(|b| *b == b'}')
            .map(|p| p + open)
        else {
            break;
        };
        let inner = &pattern[open + 1..close];
        if !inner.is_empty()
            && inner.bytes().all(|b| b.is_ascii_digit() || b == b',')
            && inner
                .split(',')
                .filter_map(|n| n.parse::<u32>().ok())
                .any(|n| n >= MAX_BOUND)
        {
            return true;
        }
        i = close + 1;
    }
    false
}

impl RuleSet {
    pub fn empty() -> Self {
        RuleSet::default()
    }

    fn prefilter(&self, classes: &[&str]) -> Arc<Prefilter> {
        let key = classes.join(",");
        if let Some(p) = self
            .prefilters
            .read()
            .ok()
            .and_then(|m| m.get(&key).cloned())
        {
            return p;
        }
        let mut sources: Vec<&str> = Vec::new();
        let mut rules = Vec::new();
        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.patterns.is_empty() || !classes.iter().any(|c| rule.applies_to(c)) {
                continue;
            }
            let start = sources.len();
            let light = rule.sources.iter().filter(|s| !is_heavy(s));
            sources.extend(light.map(String::as_str));
            rules.push(PrefilterRule {
                rule: idx,
                heavy: rule.sources.len() - (sources.len() - start),
                range: start..sources.len(),
            });
        }
        let set = RegexSetBuilder::new(&sources)
            .unicode(false)
            .dot_matches_new_line(false)
            .size_limit(1 << 28)
            .dfa_size_limit(1 << 26)
            .build()
            .map_err(|e| log::warn!("rule prefilter for {key} not available: {e}"))
            .ok();
        let built = Arc::new(Prefilter { set, rules });
        if let Ok(mut map) = self.prefilters.write() {
            map.insert(key, built.clone());
        }
        built
    }

    /// Parse a TOML rule file.
    pub fn from_toml(name: &str, text: &str) -> Result<Self, RuleError> {
        let file: RuleFile =
            toml::from_str(text).map_err(|e| RuleError::Parse(name.to_string(), e.to_string()))?;
        let mut rules = Vec::with_capacity(file.rule.len());
        for spec in file.rule {
            rules.push(Rule::compile(spec)?);
        }
        Ok(RuleSet {
            rules,
            prefilters: RwLock::default(),
        })
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
        self.prefilters = RwLock::default();
    }

    pub fn push(&mut self, rule: Rule) {
        self.rules.push(rule);
        self.prefilters = RwLock::default();
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
        self.scan_classes(&[class], data)
    }

    /// Apply all rules that apply to at least one of `classes`.
    pub fn scan_classes<'a>(&'a self, classes: &[&str], data: &[u8]) -> Vec<RuleMatch<'a>> {
        let prefilter = self.prefilter(classes);
        let matched = prefilter.set.as_ref().map(|set| set.matches(data));
        prefilter
            .rules
            .iter()
            .filter(|p| match &matched {
                Some(m) => {
                    p.heavy + p.range.clone().filter(|i| m.matched(*i)).count()
                        >= self.rules[p.rule].required()
                }
                None => true,
            })
            .filter_map(|p| self.rules[p.rule].matches(data))
            .collect()
    }

    /// Like [`scan`](Self::scan), and additionally on the de-obfuscated
    /// layers of `data` (see [`crate::deobf`]): PHP for the class `php`,
    /// JavaScript for `js` and `template` (files, CMS blocks, options and
    /// other stored markup).  Each rule is reported once, preferring the
    /// match in the content as written; matches found only in a layer carry
    /// the steps in [`RuleMatch::chain`] and as a prefix of their excerpts.
    pub fn scan_deep<'a>(&'a self, class: &str, data: &[u8]) -> Vec<RuleMatch<'a>> {
        let mut hits = self.scan(class, data);
        let lang = match class {
            "php" => deobf::Lang::Php,
            "js" | "template" => deobf::Lang::Js,
            _ => return hits,
        };
        for layer in deobf::layers(data, lang, &deobf::Limits::default()) {
            let classes: &[&str] = if layer.decoded {
                &[class, "decoded"]
            } else {
                &[class]
            };
            for mut m in self.scan_classes(classes, &layer.data) {
                if hits.iter().any(|h| std::ptr::eq(h.rule, m.rule)) {
                    continue;
                }
                for excerpt in &mut m.excerpts {
                    *excerpt = format!("[{}] {excerpt}", layer.chain);
                }
                m.chain = Some(layer.chain.clone());
                hits.push(m);
            }
        }
        hits
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

    #[test]
    fn heavy_strings_stay_out_of_the_prefilter_but_still_match() {
        assert!(is_heavy(r"a.{0,300}b"));
        assert!(is_heavy(r"a[^;]{80}b"));
        assert!(!is_heavy(r"a.{0,40}b\x{41}"));
        let set = RuleSet::from_toml(
            "h",
            r#"
[[rule]]
name = "far_apart"
severity = "critical"
condition = "all"
strings = [ { regex = 'alpha[^;]{0,300}omega' }, { literal = "beta" } ]
"#,
        )
        .unwrap();
        let text = format!("beta alpha {} omega", "x".repeat(250));
        assert_eq!(set.scan("php", text.as_bytes()).len(), 1);
        assert!(set.scan("php", b"alpha omega").is_empty());
        assert!(set.scan("php", b"beta").is_empty());
    }

    #[test]
    fn proximity_window() {
        let set = RuleSet::from_toml(
            "w",
            r#"
[[rule]]
name = "near"
severity = "critical"
condition = "all"
within = 40
strings = [ { literal = "alpha" }, { literal = "beta" }, { literal = "gamma" } ]
"#,
        )
        .unwrap();
        let far = format!("alpha {} beta gamma", "x".repeat(200));
        assert!(set.scan("php", far.as_bytes()).is_empty());
        // The first `alpha` is far away, a later one is close.
        let near = format!("alpha {} gamma .. alpha . beta", "x".repeat(200));
        let hits = set.scan("php", near.as_bytes());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].excerpts.len(), 3);
    }

    #[test]
    fn decoded_class_is_explicit() {
        let set = RuleSet::from_toml(
            "d",
            r#"
[[rule]]
name = "everywhere"
severity = "info"
applies_to = ["any"]
strings = [ { literal = "x" } ]

[[rule]]
name = "payload_only"
severity = "info"
applies_to = ["decoded"]
strings = [ { literal = "x" } ]
"#,
        )
        .unwrap();
        assert_eq!(set.scan("php", b"x").len(), 1);
        assert_eq!(set.scan("decoded", b"x")[0].rule.name(), "payload_only");
        assert_eq!(set.scan_classes(&["php", "decoded"], b"x").len(), 2);
    }
}
