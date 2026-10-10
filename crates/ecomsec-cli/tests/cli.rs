//! End-to-end tests against the compiled binary using synthetic shop trees.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ecomsec"))
}

fn write(root: &Path, rel: &str, content: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, content).unwrap();
}

fn backdate(root: &Path) {
    // 2025-01-01 – before the default reference date.
    let t = filetime::FileTime::from_unix_time(1_735_689_600, 0);
    for entry in walkdir::WalkDir::new(root) {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            filetime::set_file_mtime(entry.path(), t).unwrap();
        }
    }
}

fn jtl_fixture(root: &Path) {
    write(
        root,
        "includes/config.JTL-Shop.ini.php",
        b"<?php\ndefine('URL_SHOP', 'https://demo.example');\ndefine('DB_HOST','127.0.0.1');\ndefine('DB_NAME','x');\ndefine('DB_USER','u');\ndefine('DB_PASS','p');\n",
    );
    write(
        root,
        "includes/defines.php",
        b"<?php\nconst APPLICATION_VERSION = '5.3.1';\n",
    );
    write(
        root,
        "includes/src/Smarty/MailSmarty.php",
        b"<?php\n$this->registerPlugin('modifier', 'unserialize', 'unserialize');\n",
    );
    write(root, "admin/index.php", b"<?php echo 1;");
    write(
        root,
        "mediafiles/Bilder/wso.php",
        b"<?php eval(base64_decode('x'));",
    );
    write(
        root,
        "mediafiles/.htaccess",
        b"AddHandler application/x-httpd-php .png\n",
    );
    write(
        root,
        "jtllogs/shop.log",
        b"vorname={capture name=a}x{/capture}{eval var=$smarty.capture.a}\n",
    );
    write(root, "backup.sql", b"CREATE TABLE t;");
    write(
        root,
        "templates_c/compiled.php",
        b"<?php /* smarty compiled */ echo 'x';",
    );
    backdate(root);
}

fn scan_json(root: &Path, state: &Path, extra: &[&str]) -> serde_json::Value {
    let out = bin()
        .env("ECOMSEC_STATE_DIR", state)
        .args(["scan", "--root"])
        .arg(root)
        .args(["--skip-remote", "--format", "json", "--fail-on", "never"])
        .args(extra)
        .output()
        .expect("run ecomsec");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("valid json")
}

fn rules_of(report: &serde_json::Value) -> Vec<(String, String)> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["rule"].as_str().unwrap().to_string(),
                f["subject"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn jtl_scan_detects_planted_artifacts_and_patch_state() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("shop");
    let state = tmp.path().join("state");
    jtl_fixture(&root);

    let report = scan_json(&root, &state, &[]);
    assert_eq!(report["platform"]["id"], "jtl5");
    assert_eq!(report["platform"]["version"], "5.3.1");
    assert_eq!(report["verdict"], "critical");
    let rules = rules_of(&report);
    let has = |r: &str, s: &str| rules.iter().any(|(a, b)| a == r && b == s);
    assert!(has("ioc_filename", "mediafiles/Bilder/wso.php"));
    assert!(has("php_in_upload_dir", "mediafiles/Bilder/wso.php"));
    assert!(has("php_eval_base64", "mediafiles/Bilder/wso.php"));
    assert!(has(
        "htaccess_php_handler_for_non_php",
        "mediafiles/.htaccess"
    ));
    assert!(has("jtl_ssti_capture_eval", "jtllogs/shop.log"));
    assert!(has("exposed_file", "backup.sql"));
    assert!(has("advisory_cve-2026-54390", "5.3.1"));
    let adv = &report["advisories"][0];
    assert_eq!(adv["state"], "vulnerable");
    assert!(adv["basis"].as_str().unwrap().contains("unserialize"));
    assert!(report["recommendations"].as_array().unwrap().len() >= 3);
    assert!(report["integrity"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["key"] == "patch.cve-2026-54390"));
}

#[test]
fn patched_version_is_reported_as_patched() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("shop");
    let state = tmp.path().join("state");
    jtl_fixture(&root);
    write(
        &root,
        "includes/defines.php",
        b"<?php\nconst APPLICATION_VERSION = '5.7.2';\n",
    );
    backdate(&root);
    let report = scan_json(&root, &state, &[]);
    assert_eq!(report["advisories"][0]["state"], "patched");
    assert!(!rules_of(&report)
        .iter()
        .any(|(r, _)| r.starts_with("advisory_")));
}

#[test]
fn backpatch_marker_in_renderer_counts_as_patched() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("shop");
    let state = tmp.path().join("state");
    jtl_fixture(&root);
    write(
        &root,
        "includes/src/Smarty/MailSmarty.php",
        b"<?php // modifiers removed\n",
    );
    write(
        &root,
        "includes/src/Mail/Renderer/SmartyRenderer.php",
        b"<?php\n// Fix for CVE-2026-54390\n$this->smarty->setSecurityPolicy(new Security());\n",
    );
    backdate(&root);
    let report = scan_json(&root, &state, &[]);
    assert_eq!(report["advisories"][0]["state"], "patched");
    assert!(report["advisories"][0]["basis"]
        .as_str()
        .unwrap()
        .contains("SmartyRenderer.php"));
}

#[test]
fn acceptance_persists_across_scans_and_changes_verdict() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("shop");
    let state = tmp.path().join("state");
    jtl_fixture(&root);
    // Remove everything critical except the dump and make the shop patched.
    fs::remove_dir_all(root.join("mediafiles")).unwrap();
    fs::remove_dir_all(root.join("jtllogs")).unwrap();
    write(
        &root,
        "includes/defines.php",
        b"<?php\nconst APPLICATION_VERSION = '5.7.2';\n",
    );
    backdate(&root);
    let report = scan_json(&root, &state, &[]);
    assert_eq!(report["verdict"], "critical");
    let dump_id = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule"] == "exposed_file")
        .map(|f| f["id"].as_str().unwrap().to_string())
        .unwrap();

    let out = bin()
        .env("ECOMSEC_STATE_DIR", &state)
        .args(["findings", "accept", "--root"])
        .arg(&root)
        .args([&dump_id, "--reason", "Testdump"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let report = scan_json(&root, &state, &[]);
    let dump = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == dump_id)
        .unwrap();
    assert_eq!(dump["accepted"], true);
    assert_eq!(dump["accepted_reason"], "Testdump");
    assert_eq!(report["summary"]["accepted"], 1);
    assert_ne!(report["verdict"], "critical");
}

#[test]
fn time_budget_resumes_and_html_export_works() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("shop");
    let state = tmp.path().join("state");
    jtl_fixture(&root);
    for i in 0..30 {
        write(
            &root,
            &format!("includes/src/F{i}.php"),
            b"<?php class F {}",
        );
    }
    backdate(&root);
    let first = scan_json(&root, &state, &["--time-budget", "1ms"]);
    assert_eq!(first["summary"]["complete"], false);
    let second = scan_json(&root, &state, &[]);
    assert_eq!(second["summary"]["complete"], true);
    assert!(second["summary"]["files_scanned"].as_u64().unwrap() >= 38);

    let html: PathBuf = tmp.path().join("report.html");
    let out = bin()
        .env("ECOMSEC_STATE_DIR", &state)
        .args(["report", "--root"])
        .arg(&root)
        .args(["--format", "html", "--output"])
        .arg(&html)
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = fs::read_to_string(&html).unwrap();
    assert!(text.contains("\"static\""));
    assert!(text.contains("jtl_ssti_capture_eval"));
}

#[test]
fn baseline_diff_reports_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("shop");
    let state = tmp.path().join("state");
    jtl_fixture(&root);
    let ok = bin()
        .env("ECOMSEC_STATE_DIR", &state)
        .args(["baseline", "create", "--root"])
        .arg(&root)
        .status()
        .unwrap();
    assert!(ok.success());
    write(&root, "admin/index.php", b"<?php echo 2;");
    write(&root, "includes/new.php", b"<?php");
    let out = bin()
        .env("ECOMSEC_STATE_DIR", &state)
        .args(["baseline", "diff", "--root"])
        .arg(&root)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("GEÄNDERT  admin/index.php"));
    assert!(text.contains("NEU       includes/new.php"));
    assert_eq!(out.status.code(), Some(1));

    let report = scan_json(&root, &state, &[]);
    assert!(rules_of(&report)
        .iter()
        .any(|(r, s)| r == "baseline_changed" && s == "admin/index.php"));
}

#[test]
fn shopware_detection_and_twig_rules() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("sw");
    let state = tmp.path().join("state");
    write(
        &root,
        "composer.json",
        br#"{"require":{"shopware/core":"6.5.7.3"}}"#,
    );
    write(
        &root,
        "composer.lock",
        br#"{"packages":[{"name":"shopware/core","version":"v6.5.7.3"}]}"#,
    );
    write(
        &root,
        ".env",
        b"APP_ENV=dev\nDATABASE_URL=mysql://u:p@127.0.0.1/sw\n",
    );
    write(&root, "public/index.php", b"<?php");
    write(
        &root,
        "public/media/x/shell.php",
        b"<?php @eval($_POST['c']);",
    );
    write(
        &root,
        "custom/plugins/P/src/mail.html.twig",
        b"{{ ['id']|filter('system') }}",
    );
    write(
        &root,
        "public/.htaccess",
        b"php_value auto_prepend_file /tmp/x.php\n",
    );
    backdate(&root);
    let report = scan_json(&root, &state, &[]);
    assert_eq!(report["platform"]["id"], "shopware6");
    let rules = rules_of(&report);
    let has = |r: &str| rules.iter().any(|(a, _)| a == r);
    assert!(has("php_in_upload_dir"));
    assert!(has("shopware_twig_ssti_filter_exec"));
    assert!(has("htaccess_auto_prepend"));
    assert!(has("app_env_not_prod"));
    assert!(has("advisory_cve-2024-22406"));
}

#[test]
fn unknown_directory_fails_with_exit_10() {
    let out = bin()
        .args(["scan", "--root", "/definitely/not/here"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(10));
}
