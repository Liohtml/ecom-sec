//! Detection quality gate.
//!
//! `detection_corpus.toml` holds short samples of obfuscation and backdoor
//! techniques next to harmless look-alikes.  The test runs the same content
//! pipeline as the file scanner (rules on the text as written and on the
//! de-obfuscated layers) and fails when a technique is missed or a
//! look-alike is reported.

use ecomsec_core::engine::file_scan::{content_hits, FileClass};
use ecomsec_core::finding::Severity;
use ecomsec_core::signatures;
use serde::Deserialize;

#[derive(Deserialize)]
struct Corpus {
    sample: Vec<Sample>,
}

#[derive(Deserialize)]
struct Sample {
    name: String,
    class: String,
    expect: String,
    rule: Option<String>,
    content: String,
}

impl Sample {
    /// Code points up to U+00FF stand for single bytes.
    fn bytes(&self) -> Vec<u8> {
        self.content
            .chars()
            .map(|c| u8::try_from(c as u32).expect("corpus uses code points up to U+00FF"))
            .collect()
    }

    fn class(&self) -> FileClass {
        match self.class.as_str() {
            "php" => FileClass::Php,
            "js" => FileClass::Js,
            "htaccess" => FileClass::Htaccess,
            "ini" => FileClass::Ini,
            "image" => FileClass::Image,
            "other" => FileClass::Other,
            "template" => FileClass::Template,
            other => panic!("unknown class {other}"),
        }
    }
}

#[test]
fn corpus_is_detected_without_false_positives() {
    let corpus: Corpus = toml::from_str(include_str!("detection_corpus.toml")).unwrap();
    let rules = signatures::builtin_rules().unwrap();
    let mut failures = Vec::new();
    let mut malicious = 0;
    for sample in &corpus.sample {
        let hits = content_hits(&rules, sample.class(), &[sample.bytes()]);
        let worst = hits.iter().map(|h| h.rule.spec.severity).max();
        let names: Vec<&str> = hits.iter().map(|h| h.rule.name()).collect();
        let ok = match sample.expect.as_str() {
            "critical" => worst == Some(Severity::Critical),
            "warning" => worst >= Some(Severity::Warning),
            "clean" => worst < Some(Severity::Warning),
            other => panic!("unknown expectation {other}"),
        };
        if sample.expect != "clean" {
            malicious += 1;
        }
        let rule_ok = match sample.rule.as_deref() {
            Some(r) => names.contains(&r),
            None => true,
        };
        if !ok || !rule_ok {
            failures.push(format!(
                "{}: expected {}{} – got {:?} {:?}",
                sample.name,
                sample.expect,
                sample
                    .rule
                    .as_deref()
                    .map(|r| format!(" ({r})"))
                    .unwrap_or_default(),
                worst,
                names
            ));
        }
    }
    assert!(malicious >= 40, "corpus shrank to {malicious} samples");
    assert!(
        failures.is_empty(),
        "{} of {} samples failed:\n{}",
        failures.len(),
        corpus.sample.len(),
        failures.join("\n")
    );
}

/// Padding must not push a payload out of the scanned part of a file.
#[test]
fn payload_behind_padding_is_found() {
    use ecomsec_core::engine::file_scan::FileScanner;
    use ecomsec_core::engine::ScanOptions;
    use ecomsec_core::platform::FileScanProfile;
    use ecomsec_core::signatures::IocList;
    use ecomsec_core::state::StateStore;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("shop");
    std::fs::create_dir_all(root.join("lib")).unwrap();
    let mut big = b"<?php\n".to_vec();
    for _ in 0..40_000 {
        big.extend_from_slice(b"// padding padding padding padding\n");
    }
    big.extend_from_slice(b"@eval($_POST['x']);\n");
    std::fs::write(root.join("lib/cache.php"), &big).unwrap();

    let rules = signatures::builtin_rules().unwrap();
    let iocs = IocList::builtin().unwrap();
    let options = ScanOptions {
        no_persist: true,
        // Smaller than the file: only its beginning and end are read.
        max_file_size: 64 * 1024,
        ..Default::default()
    };
    let profile = FileScanProfile::new(&root);
    let state = StateStore::new(tmp.path().join("state"));
    let result = FileScanner::new(&profile, &rules, &iocs, &options)
        .run(&state, None)
        .unwrap();
    assert!(result
        .findings
        .iter()
        .any(|f| f.rule == "php_china_chopper" && f.severity == Severity::Critical));
    assert!(result.findings.iter().any(|f| f.rule == "file_too_large"));
}
