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

#[test]
fn advisories_lint_and_list_work_on_repo_files() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../advisories");
    let out = bin()
        .args(["advisories", "lint"])
        .arg(&repo)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = bin()
        .args(["advisories", "list", "--platform", "jtl5"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("CVE-2026-54390"));
}

#[test]
fn extra_advisory_dir_overrides_embedded_entries() {
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
    let adv = tmp.path().join("adv");
    write(
        &adv,
        "jtl5.toml",
        b"[[advisory]]\nid = \"CVE-2099-0001\"\nplatform = \"jtl5\"\ntitle = \"Test\"\nseverity = \"warning\"\naffected = [\"<9.0\"]\nfixed_in = [\"9.0\"]\npublished = 2026-10-01\n",
    );
    let report = scan_json(&root, &state, &["--advisories", adv.to_str().unwrap()]);
    let ids: Vec<&str> = report["advisories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["advisory"]["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"CVE-2099-0001"));
    assert!(ids.contains(&"CVE-2026-54390"));
    assert!(rules_of(&report)
        .iter()
        .any(|(r, _)| r == "advisory_cve-2099-0001"));
    // Without --online the dependency row says "nicht geprüft".
    let dep = report["integrity"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["key"] == "dependencies.osv")
        .unwrap();
    assert_eq!(dep["status"], "unknown");
}

// ------------------------------------------------------------------ monitoring

fn run(state: &Path, args: &[&str]) -> std::process::Output {
    bin()
        .env("ECOMSEC_STATE_DIR", state)
        .env_remove("ECOMSEC_CONFIG")
        .args(args)
        .output()
        .expect("run ecomsec")
}

fn subjects(list: &serde_json::Value) -> Vec<String> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|f| f["subject"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn diff_compares_last_two_scans_and_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("shop");
    let state = tmp.path().join("state");
    jtl_fixture(&root);
    let root_s = root.to_str().unwrap();

    let first = scan_json(&root, &state, &[]);
    // Only one scan: every active finding is listed, first_run is set.
    let out = run(&state, &["diff", "--root", root_s, "--format", "json"]);
    let d: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(d["first_run"], true);
    assert_eq!(out.status.code(), Some(2));

    // New webshell → new critical finding, exit code 2.
    write(
        &root,
        "mediafiles/Bilder/neu.php",
        b"<?php @eval($_POST['x']);",
    );
    backdate(&root);
    let second = scan_json(&root, &state, &[]);
    let out = run(&state, &["diff", "--root", root_s, "--format", "json"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let d: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(d["first_run"], false);
    assert_eq!(d["relevance"], "critical");
    assert!(subjects(&d["new_findings"]).contains(&"mediafiles/Bilder/neu.php".to_string()));
    assert!(d["resolved_findings"].as_array().unwrap().is_empty());

    // Text output.
    let out = run(&state, &["diff", "--root", root_s]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Neue Befunde"), "{text}");
    assert!(text.contains("mediafiles/Bilder/neu.php"));

    // Removing the dump → resolved only, exit code 0.
    fs::remove_file(root.join("backup.sql")).unwrap();
    scan_json(&root, &state, &[]);
    let out = run(&state, &["diff", "--root", root_s, "--format", "json"]);
    let d: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(subjects(&d["resolved_findings"]).contains(&"backup.sql".to_string()));
    assert!(d["new_findings"].as_array().unwrap().is_empty());
    assert_eq!(out.status.code(), Some(0));

    // Three complete scans are archived.
    let reports = walkdir::WalkDir::new(&state)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().parent().is_some_and(|p| p.ends_with("reports")))
        .count();
    assert_eq!(reports, 3);

    // Two exported JSON files.
    let a = tmp.path().join("a.json");
    let b = tmp.path().join("b.json");
    fs::write(&a, serde_json::to_vec(&first).unwrap()).unwrap();
    fs::write(&b, serde_json::to_vec(&second).unwrap()).unwrap();
    let out = run(
        &state,
        &[
            "diff",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    let d: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(subjects(&d["new_findings"]).contains(&"mediafiles/Bilder/neu.php".to_string()));
    // Reverse direction: the webshell is resolved, nothing new.
    let out = run(&state, &["diff", b.to_str().unwrap(), a.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Nicht mehr gefunden"));
    // A single file is an error.
    let out = run(&state, &["diff", a.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(10));
}

#[test]
fn watch_dry_run_and_file_notifications() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("shop");
    let state = tmp.path().join("state");
    jtl_fixture(&root);
    // Start from a patched shop without the planted artifacts.
    fs::remove_dir_all(root.join("mediafiles")).unwrap();
    fs::remove_dir_all(root.join("jtllogs")).unwrap();
    fs::remove_file(root.join("backup.sql")).unwrap();
    write(
        &root,
        "includes/defines.php",
        b"<?php\nconst APPLICATION_VERSION = '5.7.2';\n",
    );
    backdate(&root);
    let log = tmp.path().join("notify").join("changes.jsonl");
    let cfg = tmp.path().join("ecomsec.toml");
    fs::write(
        &cfg,
        format!(
            "[watch]\nupdate_advisories = false\n\n[notify]\non = \"warning\"\n\n[[notify.channel]]\nkind = \"file\"\nname = \"Protokoll\"\npath = {:?}\nformat = \"json\"\n",
            log.to_str().unwrap()
        ),
    )
    .unwrap();
    let base = [
        "--config",
        cfg.to_str().unwrap(),
        "--root",
        root.to_str().unwrap(),
        "watch",
        "--skip-remote",
    ];
    let watch = |extra: &[&str]| {
        let mut args: Vec<&str> = base.to_vec();
        args.extend_from_slice(extra);
        run(&state, &args)
    };

    // First run (dry): reports what would be sent, writes nothing.
    let out = watch(&["--no-notify", "--format", "json"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let d: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(d["first_run"], true);
    assert!(
        stderr.contains("--no-notify") && stderr.contains("Protokoll (file)"),
        "{stderr}"
    );
    assert!(!log.exists());

    // Unchanged second run: nothing to notify, exit 0.
    let out = watch(&[]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("Keine Änderungen"));
    assert!(!log.exists());

    // New webshell: notification written to the file channel, exit 2.
    write(
        &root,
        "mediafiles/Bilder/wso.php",
        b"<?php eval(base64_decode('x'));",
    );
    backdate(&root);
    let out = watch(&["--quiet"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty(), "--quiet prints nothing");
    let lines: Vec<serde_json::Value> = fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["event"], "ecomsec.changes");
    assert_eq!(lines[0]["level"], "critical");
    assert!(subjects(&lines[0]["diff"]["new_findings"])
        .contains(&"mediafiles/Bilder/wso.php".to_string()));

    // `--notify-on always` forces a message even without changes.
    let out = watch(&["--notify-on", "always", "-q"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(fs::read_to_string(&log).unwrap().lines().count(), 2);

    // Test message and channel listing.
    let out = run(
        &state,
        &["--config", cfg.to_str().unwrap(), "notify", "test"],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(fs::read_to_string(&log).unwrap().contains("ecomsec.test"));
    let out = run(
        &state,
        &["--config", cfg.to_str().unwrap(), "notify", "list"],
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("Protokoll"));

    // Scheduling helpers only print.
    let out = watch(&["--install-systemd", "--at", "03:05"]);
    let units = String::from_utf8_lossy(&out.stdout);
    assert!(units.contains("OnCalendar=*-*-* 03:05:00"), "{units}");
    assert!(units.contains(" watch "));
    assert!(units.contains("--skip-remote"));
    let out = watch(&["--install-cron"]);
    let cron = String::from_utf8_lossy(&out.stdout);
    assert!(cron.contains("17 4 * * * "), "{cron}");
    assert!(cron.contains("--quiet"));
}

// ---------------------------------------------------------------- KI-Audit

const PROXY_VARS: &[&str] = &[
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];

#[test]
fn audit_without_api_key_fails_with_german_error() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("shop");
    let state = tmp.path().join("state");
    jtl_fixture(&root);
    let out = bin()
        .env("ECOMSEC_STATE_DIR", &state)
        .env_remove("ANTHROPIC_API_KEY")
        .args(["audit", "--root"])
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(10));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Kein API-Schlüssel"), "{err}");
    assert!(err.contains("ANTHROPIC_API_KEY"), "{err}");
    // Nothing was scanned or stored.
    assert!(!state.exists());

    // A custom variable name from the configuration is honoured.
    let cfg = tmp.path().join("ecomsec.toml");
    fs::write(&cfg, "[audit]\napi_key_env = \"MY_AUDIT_KEY\"\n").unwrap();
    let out = bin()
        .env("ECOMSEC_STATE_DIR", &state)
        .env_remove("MY_AUDIT_KEY")
        .arg("--config")
        .arg(&cfg)
        .args(["audit", "--root"])
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(10));
    assert!(String::from_utf8_lossy(&out.stderr).contains("MY_AUDIT_KEY"));
}

/// Minimal HTTP/1.1 server on 127.0.0.1 that answers each request with the
/// next scripted JSON body and records the raw request (headers + body).
fn fake_api(responses: Vec<serde_json::Value>) -> (String, std::thread::JoinHandle<Vec<String>>) {
    use std::io::{BufRead, BufReader, Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for body in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = String::new();
            let mut len = 0usize;
            let mut chunked = false;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let lower = line.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
                    chunked = true;
                }
                head.push_str(&line);
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let mut req_body = Vec::new();
            if chunked {
                loop {
                    let mut size = String::new();
                    reader.read_line(&mut size).unwrap();
                    let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
                    let mut chunk = vec![0; n + 2];
                    reader.read_exact(&mut chunk).unwrap();
                    if n == 0 {
                        break;
                    }
                    req_body.extend_from_slice(&chunk[..n]);
                }
            } else {
                req_body.resize(len, 0);
                reader.read_exact(&mut req_body).unwrap();
            }
            seen.push(format!("{head}{}", String::from_utf8_lossy(&req_body)));
            let text = body.to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                text.len()
            )
            .unwrap();
            stream.flush().unwrap();
        }
        seen
    });
    (format!("http://{addr}"), handle)
}

#[test]
fn audit_end_to_end_against_local_fake_api() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("shop");
    let state = tmp.path().join("state");
    jtl_fixture(&root);
    let report = scan_json(&root, &state, &[]);
    let open: Vec<String> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["severity"] != "info" && f["accepted"] != true)
        .map(|f| f["id"].as_str().unwrap().to_string())
        .collect();
    assert!(!open.is_empty());
    let usage = serde_json::json!({"input_tokens": 1200, "output_tokens": 150, "cache_read_input_tokens": 0});
    let responses = vec![
        serde_json::json!({
            "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-sonnet-5-5",
            "stop_reason": "tool_use", "usage": usage,
            "content": [
                {"type": "text", "text": "Ich prüfe die Konfiguration."},
                {"type": "tool_use", "id": "toolu_a", "name": "read_file", "input": {"path": "includes/config.JTL-Shop.ini.php"}},
                {"type": "tool_use", "id": "toolu_b", "name": "record_verdict", "input": {
                    "finding_ids": open, "verdict": "needs_human", "confidence": 0.6,
                    "reasoning": "Testbewertung"}}
            ]
        }),
        serde_json::json!({
            "id": "msg_2", "type": "message", "role": "assistant", "model": "claude-sonnet-5-5",
            "stop_reason": "end_turn", "usage": usage,
            "content": [{"type": "text", "text": "Fertig.\n```json\n{\"overall_assessment\":\"unklar\",\"confidence\":0.5,\"summary\":\"Testlauf.\",\"next_steps\":[{\"priority\":1,\"action\":\"Befunde manuell prüfen\"}]}\n```"}]
        }),
    ];
    let (base, server) = fake_api(responses);
    let cfg = tmp.path().join("ecomsec.toml");
    fs::write(
        &cfg,
        format!("[audit]\napi_base = \"{base}\"\nfallback = false\n"),
    )
    .unwrap();
    let mut cmd = bin();
    for v in PROXY_VARS {
        cmd.env_remove(v);
    }
    let out = cmd
        .env("ECOMSEC_STATE_DIR", &state)
        .env("ANTHROPIC_API_KEY", "sk-test-key")
        .arg("--config")
        .arg(&cfg)
        .args(["audit", "--skip-remote", "--format", "json", "--root"])
        .arg(&root)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    let audit: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(audit["status"], "completed");
    assert_eq!(audit["model"], "claude-sonnet-5-5");
    assert_eq!(audit["overall_assessment"], "unklar");
    assert_eq!(audit["verdicts"].as_array().unwrap().len(), open.len());
    assert_eq!(audit["tokens_in"], 2400);
    assert!(stderr.contains("Token-Verbrauch"), "{stderr}");

    let seen = server.join().unwrap();
    assert_eq!(seen.len(), 2);
    let first = seen[0].to_ascii_lowercase();
    assert!(first.contains("x-api-key: sk-test-key"));
    assert!(first.contains("anthropic-version: 2023-06-01"));
    assert!(
        seen[0].contains("\"model\":\"claude-sonnet-5-5\""),
        "{}",
        &seen[0][..seen[0].len().min(600)]
    );
    // The config file reached the model only in redacted form.
    assert!(seen[1].contains("[REDIGIERT]"), "{}", seen[1]);
    assert!(!seen[1].contains("define('DB_PASS','p')"));

    // Stored results: audit files and reviews merged into the report.
    let store_dir = fs::read_dir(&state)
        .unwrap()
        .flatten()
        .find(|e| e.file_name().to_string_lossy().starts_with("jtl5-"))
        .unwrap()
        .path();
    assert!(store_dir.join("last-audit.json").is_file());
    assert!(fs::read_dir(&store_dir)
        .unwrap()
        .flatten()
        .any(|e| e.file_name().to_string_lossy().starts_with("audit-")));
    let out = bin()
        .env("ECOMSEC_STATE_DIR", &state)
        .args(["report", "--format", "json", "--root"])
        .arg(&root)
        .output()
        .unwrap();
    let merged: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let reviewed = merged["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["review"]["verdict"] == "needs_human")
        .count();
    assert_eq!(reviewed, open.len());
    let out = bin()
        .env("ECOMSEC_STATE_DIR", &state)
        .args(["report", "--root"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("KI: manuelle Prüfung nötig (60 %)"));
}
