//! Advisory database: vulnerability entries loaded from TOML files.
//!
//! Adapters embed their file at build time; at run time additional
//! directories (`--advisories DIR`, downloaded updates) are merged on top,
//! entries with the same `id` replacing the embedded ones.

use crate::finding::Severity;
use crate::platform::Advisory;
use crate::version::{Version, VersionRange};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdvisoryError {
    #[error("advisory file {0}: {1}")]
    Parse(String, String),
    #[error("advisory {id}: invalid version range {range:?}")]
    Range { id: String, range: String },
    #[error("advisory {id}: invalid version {version:?}")]
    Version { id: String, version: String },
    #[error("advisory {0}: field `platform` is required")]
    Platform(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdvisoryFile {
    #[serde(default)]
    pub advisory: Vec<AdvisorySpec>,
}

/// One advisory as written in TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorySpec {
    pub id: String,
    pub platform: String,
    pub title: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    /// Ranges such as `>=5.2.0 <5.5.4`, `<6.4.20.1`, `>=1.0`.
    #[serde(default)]
    pub affected: Vec<String>,
    #[serde(default)]
    pub fixed_in: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backpatch_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(deserialize_with = "de_date", serialize_with = "ser_date")]
    pub published: NaiveDate,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Alias ids (GHSA ↔ CVE) used by the sync workflow for de-duplication.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Where the entry came from (NVD, GHSA, vendor advisory, manual).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Withdrawn entries are kept for the record but never evaluated.
    #[serde(default)]
    pub withdrawn: bool,
    /// Draft entries (auto-generated, not yet reviewed) are not evaluated.
    #[serde(default)]
    pub draft: bool,
    /// Component the ranges refer to when it is not the shop core
    /// (e.g. `WooCommerce` for the WordPress based `woocommerce` platform).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
}

/// Accept both TOML native dates (`2026-06-17`) and strings (`"2026-06-17"`).
fn de_date<'de, D: serde::Deserializer<'de>>(d: D) -> Result<NaiveDate, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Dt(toml::value::Datetime),
        S(String),
    }
    let text = match Raw::deserialize(d)? {
        Raw::Dt(dt) => dt.to_string(),
        Raw::S(s) => s,
    };
    let day = text.get(..10).unwrap_or(&text);
    NaiveDate::parse_from_str(day, "%Y-%m-%d").map_err(serde::de::Error::custom)
}

fn ser_date<S: serde::Serializer>(d: &NaiveDate, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&d.format("%Y-%m-%d").to_string())
}

/// Parse `>=a <b`, `<b`, `>=a`, `*` or a bare version (`== a`).
pub fn parse_range(input: &str) -> Option<VersionRange> {
    let s = input.trim();
    if s == "*" || s.is_empty() {
        return Some(VersionRange::new(None, None));
    }
    let mut min = None;
    let mut max = None;
    let mut exact = None;
    for tok in s.split_whitespace() {
        if let Some(v) = tok.strip_prefix(">=") {
            min = Some(Version::parse(v)?);
        } else if let Some(v) = tok.strip_prefix('<') {
            max = Some(Version::parse(v)?);
        } else if let Some(v) = tok.strip_prefix("==") {
            exact = Some(Version::parse(v)?);
        } else if let Some(v) = tok.strip_prefix('>') {
            // `>a` is treated as `>=a` with a note; exact successor is unknown.
            min = Some(Version::parse(v)?);
        } else if tok.starts_with("<=") {
            return None;
        } else {
            exact = Some(Version::parse(tok)?);
        }
    }
    if let Some(e) = exact {
        let mut next = e.clone();
        if let Some(last) = next.parts.last_mut() {
            *last += 1;
        }
        next.raw = next
            .parts
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(".");
        return Some(VersionRange {
            min_inclusive: Some(e),
            max_exclusive: Some(next),
        });
    }
    Some(VersionRange {
        min_inclusive: min,
        max_exclusive: max,
    })
}

impl AdvisorySpec {
    pub fn to_advisory(&self) -> Result<Advisory, AdvisoryError> {
        let mut affected = Vec::new();
        for r in &self.affected {
            affected.push(parse_range(r).ok_or_else(|| AdvisoryError::Range {
                id: self.id.clone(),
                range: r.clone(),
            })?);
        }
        let mut fixed_in = Vec::new();
        for v in &self.fixed_in {
            fixed_in.push(Version::parse(v).ok_or_else(|| AdvisoryError::Version {
                id: self.id.clone(),
                version: v.clone(),
            })?);
        }
        Ok(Advisory {
            id: self.id.clone(),
            title: self.title.clone(),
            severity: self.severity,
            score: self.score,
            affected,
            fixed_in,
            backpatch_note: self.backpatch_note.clone(),
            reference: self.reference.clone().or_else(|| self.source.clone()),
            published: self.published,
            tags: self.tags.clone(),
            component: self.component.clone().filter(|c| !c.trim().is_empty()),
        })
    }
}

/// Merged advisory database, keyed by platform id then advisory id.
#[derive(Debug, Clone, Default)]
pub struct AdvisoryDb {
    entries: BTreeMap<String, BTreeMap<String, AdvisorySpec>>,
    pub sources: Vec<String>,
}

impl AdvisoryDb {
    pub fn new() -> Self {
        AdvisoryDb::default()
    }

    /// Parse a TOML file and merge it (later wins by id).
    pub fn merge_toml(&mut self, name: &str, text: &str) -> Result<usize, AdvisoryError> {
        let file: AdvisoryFile = toml::from_str(text)
            .map_err(|e| AdvisoryError::Parse(name.to_string(), e.to_string()))?;
        let mut n = 0;
        for spec in file.advisory {
            if spec.platform.trim().is_empty() {
                return Err(AdvisoryError::Platform(spec.id));
            }
            // Validate eagerly so that broken files fail loudly.
            spec.to_advisory()?;
            self.entries
                .entry(spec.platform.clone())
                .or_default()
                .insert(spec.id.clone(), spec);
            n += 1;
        }
        self.sources.push(name.to_string());
        Ok(n)
    }

    /// Merge every `*.toml` in a directory (non-recursive, sorted).
    pub fn merge_dir(&mut self, dir: &Path) -> Result<usize, AdvisoryError> {
        let mut files: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().map(|e| e == "toml").unwrap_or(false))
            .filter(|p| {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                name != "ignored.toml" && !name.starts_with('_')
            })
            .collect();
        files.sort();
        let mut n = 0;
        for f in files {
            let text = std::fs::read_to_string(&f)?;
            n += self.merge_toml(&f.display().to_string(), &text)?;
        }
        Ok(n)
    }

    pub fn merge(&mut self, other: &AdvisoryDb) {
        for (platform, map) in &other.entries {
            let target = self.entries.entry(platform.clone()).or_default();
            for (id, spec) in map {
                target.insert(id.clone(), spec.clone());
            }
        }
        self.sources.extend(other.sources.iter().cloned());
    }

    /// Active (non-draft, non-withdrawn) advisories for a platform.
    pub fn for_platform(&self, platform: &str) -> Vec<Advisory> {
        self.entries
            .get(platform)
            .map(|m| {
                m.values()
                    .filter(|s| !s.withdrawn && !s.draft)
                    .filter_map(|s| s.to_advisory().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn specs(&self) -> impl Iterator<Item = &AdvisorySpec> {
        self.entries.values().flat_map(|m| m.values())
    }

    pub fn len(&self) -> usize {
        self.entries.values().map(|m| m.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn platforms(&self) -> Vec<&str> {
        self.entries.keys().map(String::as_str).collect()
    }
}

/// Merge `base` advisories with `overrides` by id (overrides win).
pub fn merge_by_id(base: Vec<Advisory>, overrides: Vec<Advisory>) -> Vec<Advisory> {
    let mut map: BTreeMap<String, Advisory> = base.into_iter().map(|a| (a.id.clone(), a)).collect();
    for a in overrides {
        map.insert(a.id.clone(), a);
    }
    map.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ranges() {
        let r = parse_range(">=5.2.0 <5.5.4").unwrap();
        assert!(r.contains(&Version::parse("5.3.0").unwrap()));
        assert!(!r.contains(&Version::parse("5.5.4").unwrap()));
        assert!(parse_range("<6.4.20.1")
            .unwrap()
            .contains(&Version::parse("6.0.0").unwrap()));
        let exact = parse_range("5.7.1").unwrap();
        assert!(exact.contains(&Version::parse("5.7.1").unwrap()));
        assert!(!exact.contains(&Version::parse("5.7.2").unwrap()));
        assert!(parse_range("<=1.0").is_none());
    }

    #[test]
    fn merges_and_overrides() {
        let a = r#"
[[advisory]]
id = "CVE-1"
platform = "jtl5"
title = "a"
severity = "warning"
affected = ["<1.0"]
fixed_in = ["1.0"]
published = 2026-01-01
"#;
        let b = r#"
[[advisory]]
id = "CVE-1"
platform = "jtl5"
title = "b (updated)"
severity = "critical"
affected = ["<1.1"]
fixed_in = ["1.1"]
published = 2026-01-01

[[advisory]]
id = "CVE-2"
platform = "jtl5"
title = "draft"
severity = "critical"
draft = true
published = 2026-01-01
"#;
        let mut db = AdvisoryDb::new();
        assert_eq!(db.merge_toml("a", a).unwrap(), 1);
        assert_eq!(db.merge_toml("b", b).unwrap(), 2);
        let active = db.for_platform("jtl5");
        assert_eq!(active.len(), 1, "draft must not be active");
        assert_eq!(active[0].title, "b (updated)");
        assert!(db.for_platform("shopware6").is_empty());
        assert!(db.merge_toml("bad", "[[advisory]]\nid='x'\nplatform='p'\ntitle='t'\nseverity='info'\naffected=['<=1']\npublished=2026-01-01\n").is_err());
    }
}
