//! Agent-loop tests with a scripted client (no network).

use crate::agent::{run_audit, AuditConfig};
use crate::client::{LlmError, MessagesResponse, ScriptedClient, Usage};
use crate::report::{merge_into_report, AuditMode, AuditStatus};
use crate::tools::{SqlExecutor, ToolContext};
use ecomsec_core::finding::{Category, Finding, ReviewVerdict, Severity, Source};
use ecomsec_core::report::Report;
use ecomsec_core::state::AcceptedFindings;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, Mutex};

const DB_SECRET: &str = "Sup3rGeheim!2026";

fn write(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

fn fixture() -> (tempfile::TempDir, Report) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    write(
        &root,
        "includes/config.JTL-Shop.ini.php",
        &format!("<?php\ndefine('URL_SHOP', 'https://demo.example');\ndefine('DB_HOST','127.0.0.1');\ndefine('DB_USER','shop');\ndefine('DB_PASS','{DB_SECRET}');\n"),
    );
    write(
        &root,
        "mediafiles/Bilder/wso.php",
        "<?php\n// WSO 2.5\n@eval($_POST['pass']);\n",
    );
    write(
        &root,
        "templates_c/abc.php",
        "<?php /* compiled */ echo 1;\n",
    );
    write(
        &root,
        "plugins/acme/Frontend.php",
        "<?php\n$db->query(\"SELECT * FROM tkunde WHERE kKunde = \" . $_GET['id']);\n",
    );
    let webshell = Finding::file(
        Severity::Critical,
        Category::SuspiciousPattern,
        "php_eval_post",
        &root,
        &root.join("mediafiles/Bilder/wso.php"),
        "Webshell-Muster eval($_POST)",
    )
    .with_evidence("@eval($_POST['pass']);");
    let compiled = Finding::file(
        Severity::Warning,
        Category::ModifiedSinceReference,
        "new_php_file",
        &root,
        &root.join("templates_c/abc.php"),
        "Neue PHP-Datei seit dem Referenzdatum",
    );
    let findings = vec![webshell, compiled];
    let (verdict, summary) = Report::compute_summary(&findings);
    let report: Report = serde_json::from_value(json!({
        "schema_version": 1,
        "generated_at": "2026-10-01T10:00:00Z",
        "platform": {"id": "jtl5", "name": "JTL-Shop 5", "kind": "self_hosted", "version": "5.3.1", "root": root},
        "reference_date": "2026-06-17",
        "verdict": verdict,
        "summary": summary,
        "findings": findings,
        "integrity": [],
        "advisories": [],
        "recommendations": [],
        "limitations": [],
    }))
    .unwrap();
    (tmp, report)
}

#[derive(Clone, Default)]
struct MockSql {
    seen: Arc<Mutex<Vec<String>>>,
}

impl SqlExecutor for MockSql {
    fn query(&self, sql: &str) -> Result<Vec<Vec<(String, String)>>, String> {
        self.seen.lock().unwrap().push(sql.to_string());
        Ok(vec![vec![
            ("cLogin".into(), "admin".into()),
            (
                "cPass".into(),
                "$2y$10$abcdefghijklmnopqrstuuJ0123456789ABCDEFGHIJKLMNOPQRST".into(),
            ),
            ("cMail".into(), "chef@example.com".into()),
        ]])
    }
}

fn usage(input: u64, output: u64) -> Usage {
    Usage {
        input_tokens: input,
        output_tokens: output,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
    }
}

fn final_json() -> String {
    "Der Shop ist kompromittiert: In mediafiles/Bilder/wso.php liegt eine Webshell.\n```json\n{\"overall_assessment\":\"kompromittiert\",\"confidence\":0.9,\"summary\":\"Webshell belegt.\",\"next_steps\":[{\"priority\":1,\"action\":\"Datei sichern, dann entfernen\",\"rationale\":\"#wso\"}]}\n```".into()
}

fn tool_result<'a>(
    request_messages: &'a [crate::client::Message],
    tool_name_suffix: &str,
) -> &'a Value {
    request_messages
        .iter()
        .flat_map(|m| m.content.iter())
        .find(|b| {
            b.get("tool_use_id")
                .and_then(Value::as_str)
                .map(|id| id.ends_with(tool_name_suffix))
                .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("tool result {tool_name_suffix} missing"))
}

#[test]
fn triage_loop_redacts_guards_sql_and_merges_verdicts() {
    let (_tmp, report) = fixture();
    let root = report.platform.root.clone().unwrap();
    let webshell_id = report.findings[0].id.to_string();
    let compiled_id = report.findings[1].id.to_string();

    let mut first = ScriptedClient::tool_calls(
        &[
            (
                "read_file",
                json!({"path": "includes/config.JTL-Shop.ini.php"}),
            ),
            ("get_finding", json!({"id": webshell_id})),
            ("read_file", json!({"path": "mediafiles/Bilder/wso.php"})),
        ],
        usage(5000, 300),
    );
    // A thinking block must be sent back unchanged.
    first.content.insert(
        0,
        json!({"type": "thinking", "thinking": "", "signature": "sig-1"}),
    );
    let second = ScriptedClient::tool_calls(
        &[
            (
                "record_verdict",
                json!({"finding_id": webshell_id, "verdict": "confirmed", "confidence": 0.95,
                       "reasoning": "mediafiles/Bilder/wso.php:3 @eval($_POST['pass'])"}),
            ),
            (
                "record_verdict",
                json!({"finding_ids": [compiled_id], "verdict": "likely_false_positive", "confidence": 85,
                       "reasoning": "Kompiliertes Smarty-Template"}),
            ),
            ("db_query", json!({"sql": "DELETE FROM tadminlogin"})),
            (
                "db_query",
                json!({"sql": "SELECT cLogin, cPass, cMail FROM tadminlogin"}),
            ),
            (
                "record_finding",
                json!({"severity": "critical", "category": "exploit_payload",
                       "title": "SQL-Injection im Plugin acme", "subject": "plugins/acme/Frontend.php:2",
                       "description": "kKunde wird ungefiltert aus $_GET übernommen.",
                       "evidence": ["plugins/acme/Frontend.php:2 ... . $_GET['id']"]}),
            ),
        ],
        usage(7000, 500),
    );
    let third = ScriptedClient::final_text(&final_json(), usage(8000, 400));
    let client = ScriptedClient::new(vec![first.clone(), second, third]);
    let sql = MockSql::default();
    let mut ctx = ToolContext::new(report.clone(), Some(root.clone()), "claude-sonnet-5-5")
        .with_sql(Box::new(sql.clone()));
    let cfg = AuditConfig::new(AuditMode::Triage);
    let mut events = 0;
    let audit = run_audit(&client, &cfg, &mut ctx, &mut |_| events += 1);

    assert_eq!(
        audit.status,
        AuditStatus::Completed,
        "{:?}",
        audit.abort_reason
    );
    assert_eq!(audit.turns, 3);
    assert!(events > 0);
    let requests = client.requests();
    assert_eq!(requests.len(), 3);

    // Nothing secret ever left the process.
    for r in &requests {
        let body = r.to_body().to_string();
        assert!(!body.contains(DB_SECRET), "secret leaked");
        assert!(!body.contains("chef@example.com"), "e-mail leaked");
        assert!(!body.contains("abcdefghijklmnopqrstuuJ"), "hash leaked");
    }
    // Tools and system prompt are sent; the first request has the task.
    assert!(requests[0].tools.iter().any(|t| t["name"] == "db_query"));
    assert!(requests[0].system.contains("forensische"));
    let task = requests[0].messages[0].content[0]["text"].as_str().unwrap();
    assert!(task.contains(&webshell_id) && task.contains(&compiled_id));

    // The assistant turn (with thinking block) is replayed unchanged.
    assert_eq!(requests[1].messages[1].content, first.content);
    let cfg_result = tool_result(&requests[1].messages, "0_read_file");
    let text = cfg_result["content"].as_str().unwrap();
    assert!(text.contains("[REDIGIERT]"), "{text}");
    assert!(text.contains("https://demo.example"));

    // SQL guard: DELETE rejected before reaching the executor; SELECT limited.
    let rejected = tool_result(&requests[2].messages, "2_db_query");
    assert_eq!(rejected["is_error"], true);
    let seen = sql.seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec!["SELECT cLogin, cPass, cMail FROM tadminlogin LIMIT 200"]
    );
    let rows = tool_result(&requests[2].messages, "3_db_query")["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(rows.contains("\"cLogin\":\"admin\""));
    assert!(rows.contains("\"cPass\":\"[REDIGIERT]\""), "{rows}");

    // Results.
    assert_eq!(audit.verdicts.len(), 2);
    let fp = audit
        .verdicts
        .iter()
        .find(|v| v.finding_id == compiled_id)
        .unwrap();
    assert_eq!(fp.verdict, ReviewVerdict::LikelyFalsePositive);
    assert!((fp.confidence - 0.85).abs() < 1e-6, "percent normalised");
    assert_eq!(audit.new_findings.len(), 1);
    let nf = &audit.new_findings[0];
    assert!(nf.rule.starts_with("agent_"));
    assert_eq!(nf.source, Source::Scanner);
    assert_eq!(nf.group.as_deref(), Some("plugins/acme"));
    assert!(audit.unreviewed.is_empty());
    assert_eq!(audit.overall_assessment.as_deref(), Some("kompromittiert"));
    assert_eq!(audit.confidence, Some(0.9));
    assert_eq!(audit.summary, "Webshell belegt.");
    assert_eq!(audit.next_steps.len(), 1);
    assert_eq!(audit.tokens_in, 20_000);
    assert_eq!(audit.tokens_out, 1200);
    assert!(audit.estimated_cost_usd.unwrap() > 0.0);
    assert_eq!(audit.data.db_queries, 1);
    assert!(audit.data.redactions >= 3);
    assert!(audit
        .data
        .files_read
        .contains("includes/config.JTL-Shop.ini.php"));

    // Merge into the scan report.
    let mut merged = report.clone();
    let n = merge_into_report(&audit, &mut merged, &AcceptedFindings::default());
    assert_eq!(n, 2);
    let review = merged.findings[0].review.as_ref().unwrap();
    assert_eq!(review.verdict, ReviewVerdict::Confirmed);
    assert_eq!(review.model, "claude-sonnet-5-5");
    assert_eq!(merged.findings.len(), 3);
    assert_eq!(merged.summary.critical, 2, "new critical finding counts");
    // Serialised report stays compatible.
    let json = serde_json::to_string(&merged).unwrap();
    let back: Report = serde_json::from_str(&json).unwrap();
    assert!(back.findings.iter().any(|f| f.review.is_some()));

    // Text output is German and mentions the verdicts.
    let text = crate::report::render_text(&audit);
    assert!(text.contains("GESAMTBEWERTUNG"));
    assert!(text.contains("Bestätigt (1)"));
}

#[test]
fn budget_abort_keeps_verdicts_and_stops_requests() {
    let (_tmp, report) = fixture();
    let id = report.findings[0].id.to_string();
    let client = ScriptedClient::new(vec![
        ScriptedClient::tool_calls(
            &[(
                "record_verdict",
                json!({"finding_id": id, "verdict": "needs_human", "confidence": 0.5, "reasoning": "unklar"}),
            )],
            usage(9_000, 2_000),
        ),
        ScriptedClient::final_text(&final_json(), usage(1, 1)),
    ]);
    let mut ctx = ToolContext::new(report, None, "claude-sonnet-5-5");
    let mut cfg = AuditConfig::new(AuditMode::Triage);
    cfg.max_tokens_budget = 10_000;
    let audit = run_audit(&client, &cfg, &mut ctx, &mut |_| {});
    assert_eq!(audit.status, AuditStatus::BudgetExceeded);
    assert!(audit
        .abort_reason
        .as_deref()
        .unwrap()
        .contains("Token-Budget überschritten"));
    assert_eq!(client.requests().len(), 1);
    assert_eq!(audit.verdicts.len(), 1, "verdict of the last turn is kept");
    assert!(!audit.summary.is_empty());
}

#[test]
fn max_turns_nudge_refusal_and_api_errors() {
    let (_tmp, report) = fixture();
    let looping =
        || ScriptedClient::tool_calls(&[("get_report_summary", json!({}))], usage(10, 10));

    // Turn limit.
    let client = ScriptedClient::new(vec![looping(), looping(), looping()]);
    let mut ctx = ToolContext::new(report.clone(), None, "m");
    let mut cfg = AuditConfig::new(AuditMode::Triage);
    cfg.max_turns = 2;
    let audit = run_audit(&client, &cfg, &mut ctx, &mut |_| {});
    assert_eq!(audit.status, AuditStatus::MaxTurns);
    assert_eq!(client.requests().len(), 2);
    // The second request carries the "budget almost exhausted" hint.
    let last = client.requests()[1].messages.last().unwrap().clone();
    assert!(last
        .content
        .iter()
        .any(|b| b["type"] == "text" && b["text"].as_str().unwrap().contains("fast erschöpft")));
    assert_eq!(audit.unreviewed.len(), 2);

    // Final answer without verdicts → one nudge, then completion.
    let client = ScriptedClient::new(vec![
        ScriptedClient::final_text("fertig", usage(10, 10)),
        ScriptedClient::final_text(&final_json(), usage(10, 10)),
    ]);
    let mut ctx = ToolContext::new(report.clone(), None, "m");
    let audit = run_audit(
        &client,
        &AuditConfig::new(AuditMode::Triage),
        &mut ctx,
        &mut |_| {},
    );
    assert_eq!(audit.status, AuditStatus::Completed);
    let reqs = client.requests();
    assert_eq!(reqs.len(), 2);
    let nudge = reqs[1].messages.last().unwrap().content[0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(nudge.contains("noch keine Bewertung"));
    assert_eq!(audit.unreviewed.len(), 2);

    // Refusal.
    let refusal = MessagesResponse {
        stop_reason: Some("refusal".into()),
        stop_details: Some(json!({"type": "refusal", "category": "cyber"})),
        ..Default::default()
    };
    let client = ScriptedClient::new(vec![refusal]);
    let mut ctx = ToolContext::new(report.clone(), None, "m");
    let audit = run_audit(
        &client,
        &AuditConfig::new(AuditMode::Triage),
        &mut ctx,
        &mut |_| {},
    );
    assert_eq!(audit.status, AuditStatus::Refused);
    assert!(audit.abort_reason.unwrap().contains("cyber"));

    // API error.
    let client = ScriptedClient::new(vec![]);
    client.push_error(LlmError::Api {
        status: 401,
        kind: "authentication_error".into(),
        message: "invalid x-api-key".into(),
    });
    let mut ctx = ToolContext::new(report, None, "m");
    let audit = run_audit(
        &client,
        &AuditConfig::new(AuditMode::Triage),
        &mut ctx,
        &mut |_| {},
    );
    assert_eq!(audit.status, AuditStatus::ApiError);
    assert!(audit.abort_reason.unwrap().contains("401"));
}

#[test]
fn hunt_mode_lists_candidates_and_tools_depend_on_sources() {
    let (_tmp, report) = fixture();
    let root = report.platform.root.clone().unwrap();
    let client = ScriptedClient::new(vec![ScriptedClient::final_text(&final_json(), usage(1, 1))]);
    let mut ctx = ToolContext::new(report.clone(), Some(root), "m");
    let names: Vec<String> = ctx
        .definitions()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert!(names.contains(&"read_file".to_string()));
    assert!(!names.contains(&"db_query".to_string()));
    assert!(!names.contains(&"osv_lookup".to_string()));
    let _ = run_audit(
        &client,
        &AuditConfig::new(AuditMode::Hunt),
        &mut ctx,
        &mut |_| {},
    );
    let task = client.requests()[0].messages[0].content[0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(task.contains("Code-Review"));
    assert!(task.contains("plugins/acme/Frontend.php"), "{task}");

    // Hosted platform: no file tools.
    let ctx = ToolContext::new(report, None, "m");
    assert!(!ctx
        .definitions()
        .iter()
        .any(|t| t["name"] == "read_file" || t["name"] == "grep"));
}

#[test]
fn file_tools_stay_inside_the_root() {
    let (tmp, report) = fixture();
    let root = report.platform.root.clone().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret.txt"), "top secret").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path().join("secret.txt"), root.join("link.txt")).unwrap();
    let mut ctx = ToolContext::new(report, Some(root.clone()), "m");
    for input in [
        json!({"path": "../x"}),
        json!({"path": "mediafiles/../../etc/passwd"}),
        json!({"path": outside.path().join("secret.txt")}),
    ] {
        let out = ctx.execute("read_file", &input);
        assert!(out.is_error, "{input}: {}", out.content);
    }
    #[cfg(unix)]
    {
        let out = ctx.execute("read_file", &json!({"path": "link.txt"}));
        assert!(
            out.is_error && out.content.contains("außerhalb"),
            "{}",
            out.content
        );
        let info = ctx.execute("file_info", &json!({"path": "mediafiles/Bilder/wso.php"}));
        assert!(info.content.contains("sha256"), "{}", info.content);
    }
    let ok = ctx.execute(
        "read_file",
        &json!({"path": "mediafiles/Bilder/wso.php", "offset": 3, "limit": 1}),
    );
    assert!(!ok.is_error);
    assert!(ok.content.contains("     3│ @eval"), "{}", ok.content);
    let grep = ctx.execute("grep", &json!({"pattern": "DB_PASS", "path": "."}));
    assert!(!grep.content.contains(DB_SECRET), "{}", grep.content);
    let grep = ctx.execute("grep", &json!({"pattern": "Sup3r"}));
    assert!(
        grep.content.starts_with("0 Treffer"),
        "grep must not be an oracle: {}",
        grep.content
    );
    let list = ctx.execute("list_dir", &json!({"path": ".", "depth": 2}));
    assert!(
        list.content.contains("mediafiles/Bilder/"),
        "{}",
        list.content
    );
    drop(tmp);
}
