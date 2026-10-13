//! Software Bill of Materials of the Composer inventory (CycloneDX 1.5 JSON
//! or SPDX 2.3 JSON).  Read-only: the inventory comes from `composer.lock`
//! / `vendor/composer/installed.json` via [`ecomsec_osv::load_inventory`].

use chrono::{DateTime, Utc};
use ecomsec_osv::ComposerPackage;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SbomFormat {
    /// CycloneDX 1.5 (JSON)
    Cyclonedx,
    /// SPDX 2.3 (JSON)
    SpdxJson,
}

/// Everything an SBOM is built from.
pub struct SbomInput<'a> {
    pub platform_id: &'a str,
    pub platform_name: &'a str,
    pub platform_version: Option<String>,
    pub packages: &'a [ComposerPackage],
    /// Declared licenses per package name (from the inventory file).
    pub licenses: &'a BTreeMap<String, Vec<String>>,
    /// Inventory file relative to the root (`composer.lock`).
    pub source: &'a str,
    pub timestamp: DateTime<Utc>,
}

/// Package URL for a Composer package (`pkg:composer/vendor/name@1.2.3`).
pub fn purl(p: &ComposerPackage) -> String {
    let name: String = p
        .name
        .to_ascii_lowercase()
        .split('/')
        .map(|s| s.replace('@', "%40"))
        .collect::<Vec<_>>()
        .join("/");
    format!("pkg:composer/{name}@{}", p.version.replace('+', "%2B"))
}

/// Deterministic UUID (version-4 layout) derived from `seed`.
fn uuid_from(seed: &str) -> String {
    let h = ecomsec_core::util::sha256_hex(seed.as_bytes());
    format!(
        "{}-{}-4{}-a{}-{}",
        &h[0..8],
        &h[8..12],
        &h[13..16],
        &h[17..20],
        &h[20..32]
    )
}

fn spdx_id(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Read declared licenses (`"license": ["MIT"]`) from a Composer inventory.
pub fn read_licenses(path: &Path) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return out;
    };
    let mut lists: Vec<&Value> = Vec::new();
    for key in ["packages", "packages-dev"] {
        if let Some(a) = json.get(key) {
            lists.push(a);
        }
    }
    if json.is_array() {
        lists.push(&json);
    }
    for list in lists {
        for p in list.as_array().into_iter().flatten() {
            if let (Some(name), Some(lic)) = (
                p.get("name").and_then(|n| n.as_str()),
                p.get("license").and_then(|l| l.as_array()),
            ) {
                let l: Vec<String> = lic
                    .iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect();
                if !l.is_empty() {
                    out.insert(name.to_string(), l);
                }
            }
        }
    }
    out
}

fn seed(input: &SbomInput) -> String {
    // Unique per document (timestamp) but reproducible for identical input.
    let mut s = format!(
        "{}|{}|{}|{}",
        input.platform_id,
        input.platform_version.as_deref().unwrap_or(""),
        input.source,
        input.timestamp.timestamp()
    );
    for p in input.packages {
        s.push('|');
        s.push_str(&purl(p));
    }
    s
}

pub fn cyclonedx(input: &SbomInput) -> Value {
    let components: Vec<Value> = input
        .packages
        .iter()
        .map(|p| {
            let (group, name) = p.name.split_once('/').unwrap_or(("", p.name.as_str()));
            let mut c = json!({
                "type": "library",
                "bom-ref": purl(p),
                "name": name,
                "version": p.version,
                "purl": purl(p),
                "scope": if p.dev { "optional" } else { "required" },
            });
            if !group.is_empty() {
                c["group"] = json!(group);
            }
            if let Some(l) = input.licenses.get(&p.name) {
                c["licenses"] = json!(l
                    .iter()
                    .map(|id| json!({"license": {"id": id}}))
                    .collect::<Vec<_>>());
            }
            c
        })
        .collect();
    let mut root = json!({
        "type": "application",
        "bom-ref": format!("shop:{}", input.platform_id),
        "name": input.platform_name,
    });
    if let Some(v) = &input.platform_version {
        root["version"] = json!(v);
    }
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": format!("urn:uuid:{}", uuid_from(&seed(input))),
        "version": 1,
        "metadata": {
            "timestamp": input.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "tools": {"components": [{
                "type": "application",
                "name": "ecomsec",
                "version": env!("CARGO_PKG_VERSION"),
                "externalReferences": [{"type": "vcs", "url": env!("CARGO_PKG_REPOSITORY")}],
            }]},
            "component": root,
            "properties": [{"name": "ecomsec:inventory", "value": input.source}],
        },
        "components": components,
        "dependencies": [{
            "ref": format!("shop:{}", input.platform_id),
            "dependsOn": input.packages.iter().map(purl).collect::<Vec<_>>(),
        }],
    })
}

pub fn spdx(input: &SbomInput) -> Value {
    let root_id = format!("SPDXRef-{}", spdx_id(input.platform_id));
    let mut packages = vec![json!({
        "name": input.platform_name,
        "SPDXID": root_id,
        "versionInfo": input.platform_version.clone().unwrap_or_else(|| "NOASSERTION".into()),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
    })];
    let mut relationships = vec![json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_id,
    })];
    for (i, p) in input.packages.iter().enumerate() {
        let id = format!("SPDXRef-Package-{}-{i}", spdx_id(&p.name));
        let declared = input
            .licenses
            .get(&p.name)
            .map(|l| {
                if l.len() == 1 {
                    l[0].clone()
                } else {
                    format!("({})", l.join(" OR "))
                }
            })
            .unwrap_or_else(|| "NOASSERTION".into());
        packages.push(json!({
            "name": p.name,
            "SPDXID": id,
            "versionInfo": p.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": declared,
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl(p),
            }],
        }));
        relationships.push(if p.dev {
            // DEV_DEPENDENCY_OF points from the dependency to the dependant.
            json!({
                "spdxElementId": id,
                "relationshipType": "DEV_DEPENDENCY_OF",
                "relatedSpdxElement": root_id,
            })
        } else {
            json!({
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": id,
            })
        });
    }
    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("ecomsec-sbom-{}", input.platform_id),
        "documentNamespace": format!(
            "{}/spdx/{}-{}",
            env!("CARGO_PKG_REPOSITORY"),
            input.platform_id,
            uuid_from(&seed(input))
        ),
        "creationInfo": {
            "created": input.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "creators": [format!("Tool: ecomsec-{}", env!("CARGO_PKG_VERSION"))],
            "comment": format!("Composer-Inventar aus {}", input.source),
        },
        "packages": packages,
        "relationships": relationships,
    })
}

pub fn render(format: SbomFormat, input: &SbomInput) -> anyhow::Result<String> {
    let v = match format {
        SbomFormat::Cyclonedx => cyclonedx(input),
        SbomFormat::SpdxJson => spdx(input),
    };
    Ok(serde_json::to_string_pretty(&v)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"{"packages":[
        {"name":"shopware/core","version":"v6.5.7.3","license":["MIT"]},
        {"name":"symfony/http-kernel","version":"v6.4.1","license":["MIT"]},
        {"name":"smarty/smarty","version":"4.3.0","license":["LGPL-3.0-or-later","GPL-3.0"]}
      ],"packages-dev":[{"name":"phpunit/phpunit","version":"10.1.0","license":["BSD-3-Clause"]}]}"#;

    fn input<'a>(
        packages: &'a [ComposerPackage],
        licenses: &'a BTreeMap<String, Vec<String>>,
    ) -> SbomInput<'a> {
        SbomInput {
            platform_id: "shopware6",
            platform_name: "Shopware 6",
            platform_version: Some("6.5.7.3".into()),
            packages,
            licenses,
            source: "composer.lock",
            timestamp: DateTime::parse_from_rfc3339("2026-10-13T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    fn sample() -> (Vec<ComposerPackage>, BTreeMap<String, Vec<String>>) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("composer.lock"), LOCK).unwrap();
        let (packages, src) = ecomsec_osv::load_inventory(tmp.path(), &["composer.lock"]).unwrap();
        assert_eq!(src, "composer.lock");
        let licenses = read_licenses(&tmp.path().join("composer.lock"));
        (packages, licenses)
    }

    #[test]
    fn purl_format() {
        let p = ComposerPackage {
            name: "Shopware/Core".into(),
            version: "6.5.7.3".into(),
            dev: false,
        };
        assert_eq!(purl(&p), "pkg:composer/shopware/core@6.5.7.3");
    }

    #[test]
    fn cyclonedx_from_inventory() {
        let (packages, licenses) = sample();
        let v = cyclonedx(&input(&packages, &licenses));
        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.5");
        let serial = v["serialNumber"].as_str().unwrap();
        assert!(serial.starts_with("urn:uuid:"));
        assert_eq!(serial.len(), "urn:uuid:".len() + 36);
        let comps = v["components"].as_array().unwrap();
        assert_eq!(comps.len(), 4);
        let core = &comps[0];
        assert_eq!(core["group"], "shopware");
        assert_eq!(core["name"], "core");
        assert_eq!(core["version"], "6.5.7.3");
        assert_eq!(core["purl"], "pkg:composer/shopware/core@6.5.7.3");
        assert_eq!(core["licenses"][0]["license"]["id"], "MIT");
        let dev = comps
            .iter()
            .find(|c| c["name"] == "phpunit")
            .expect("dev package");
        assert_eq!(dev["scope"], "optional");
        assert_eq!(v["metadata"]["component"]["version"], "6.5.7.3");
        assert_eq!(
            v["dependencies"][0]["dependsOn"].as_array().unwrap().len(),
            4
        );
        // Deterministic for the same inventory.
        assert_eq!(
            cyclonedx(&input(&packages, &licenses))["serialNumber"],
            serial
        );
    }

    #[test]
    fn spdx_from_inventory() {
        let (packages, licenses) = sample();
        let v = spdx(&input(&packages, &licenses));
        assert_eq!(v["spdxVersion"], "SPDX-2.3");
        assert_eq!(v["dataLicense"], "CC0-1.0");
        assert_eq!(v["SPDXID"], "SPDXRef-DOCUMENT");
        let pkgs = v["packages"].as_array().unwrap();
        assert_eq!(pkgs.len(), 5);
        for p in pkgs {
            let id = p["SPDXID"].as_str().unwrap();
            assert!(id.starts_with("SPDXRef-"));
            assert!(id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'));
            assert!(p["downloadLocation"].is_string());
        }
        let smarty = pkgs.iter().find(|p| p["name"] == "smarty/smarty").unwrap();
        assert_eq!(smarty["licenseDeclared"], "(LGPL-3.0-or-later OR GPL-3.0)");
        assert_eq!(
            smarty["externalRefs"][0]["referenceLocator"],
            "pkg:composer/smarty/smarty@4.3.0"
        );
        let rels = v["relationships"].as_array().unwrap();
        assert_eq!(rels[0]["relationshipType"], "DESCRIBES");
        assert_eq!(rels.len(), 5);
        assert!(rels
            .iter()
            .any(|r| r["relationshipType"] == "DEV_DEPENDENCY_OF"));
    }
}
