//! Lenient version parsing and range matching for advisories.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

/// A numeric version such as `5.3.0`, `6.5.7.4` or `5.8`.  Non-numeric
/// suffixes (`-rc1`, `+build`) are ignored for comparison purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Version {
    pub parts: Vec<u64>,
    pub raw: String,
}

impl Version {
    pub fn parse(input: &str) -> Option<Self> {
        let raw = input.trim();
        let core = raw
            .trim_start_matches(['v', 'V'])
            .split(['-', '+', ' '])
            .next()?;
        let mut parts = Vec::new();
        for piece in core.split('.') {
            let digits: String = piece.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() {
                break;
            }
            parts.push(digits.parse().ok()?);
        }
        if parts.is_empty() {
            return None;
        }
        Some(Version {
            parts,
            raw: raw.to_string(),
        })
    }

    pub fn major(&self) -> u64 {
        self.parts.first().copied().unwrap_or(0)
    }

    pub fn minor(&self) -> u64 {
        self.parts.get(1).copied().unwrap_or(0)
    }

    /// `true` if `self` is on the same `major.minor` branch as `other`.
    pub fn same_branch(&self, other: &Version) -> bool {
        self.major() == other.major() && self.minor() == other.minor()
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl std::hash::Hash for Version {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Normalise trailing zeros so that 5.8 and 5.8.0 hash identically.
        let mut parts = self.parts.clone();
        while parts.len() > 1 && parts.last() == Some(&0) {
            parts.pop();
        }
        parts.hash(state);
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let n = self.parts.len().max(other.parts.len());
        for i in 0..n {
            let a = self.parts.get(i).copied().unwrap_or(0);
            let b = other.parts.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => continue,
                o => return o,
            }
        }
        Ordering::Equal
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for Version {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Version::parse(s).ok_or_else(|| format!("invalid version: {s:?}"))
    }
}

impl TryFrom<String> for Version {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Version> for String {
    fn from(v: Version) -> String {
        v.raw
    }
}

/// Inclusive lower bound / exclusive upper bound range, e.g. `>=5.2.0 <5.5.4`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_inclusive: Option<Version>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_exclusive: Option<Version>,
}

impl VersionRange {
    pub fn new(min_inclusive: Option<&str>, max_exclusive: Option<&str>) -> Self {
        VersionRange {
            min_inclusive: min_inclusive.and_then(Version::parse),
            max_exclusive: max_exclusive.and_then(Version::parse),
        }
    }

    pub fn contains(&self, v: &Version) -> bool {
        if let Some(min) = &self.min_inclusive {
            if v < min {
                return false;
            }
        }
        if let Some(max) = &self.max_exclusive {
            if v >= max {
                return false;
            }
        }
        true
    }
}

impl fmt::Display for VersionRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.min_inclusive, &self.max_exclusive) {
            (Some(a), Some(b)) => write!(f, ">={a} <{b}"),
            (Some(a), None) => write!(f, ">={a}"),
            (None, Some(b)) => write!(f, "<{b}"),
            (None, None) => f.write_str("*"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_compares() {
        let a = Version::parse("5.3.0").unwrap();
        let b = Version::parse("5.5.4").unwrap();
        let c = Version::parse("5.8").unwrap();
        assert!(a < b && b < c);
        assert_eq!(
            Version::parse("5.8.0").unwrap(),
            Version::parse("5.8").unwrap()
        );
        assert!(Version::parse("v6.5.7.4-rc1").unwrap() < Version::parse("6.5.8").unwrap());
        assert!(Version::parse("garbage").is_none());
    }

    #[test]
    fn ranges() {
        let r = VersionRange::new(Some("5.2.0"), Some("5.5.4"));
        assert!(r.contains(&Version::parse("5.3.0").unwrap()));
        assert!(!r.contains(&Version::parse("5.5.4").unwrap()));
        assert!(!r.contains(&Version::parse("5.1.8").unwrap()));
    }
}
