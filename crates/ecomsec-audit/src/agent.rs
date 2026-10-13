//! The agentic loop: send the conversation, execute requested tools, append
//! results, repeat until the model finishes or a limit is hit.

use crate::client::{LlmClient, Message, MessagesRequest, Usage, DEFAULT_MODEL};
use crate::hunt::hunt_candidates;
use crate::pricing::estimate_cost;
use crate::redact::redact;
use crate::report::{AuditMode, AuditReport, AuditStatus, NextStep, AUDIT_SCHEMA_VERSION};
use crate::tools::{category_name, ToolContext};
use chrono::Utc;
use ecomsec_core::finding::{Finding, Severity};
use ecomsec_core::util::{excerpt, human_size};
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// The forensic-analyst system prompt.
pub const SYSTEM_PROMPT: &str = include_str!("../prompts/system.md");

/// Findings listed in the task message (the model can page through the rest
/// with `list_findings`).
const MAX_TASK_FINDINGS: usize = 150;

#[derive(Debug, Clone)]
pub struct AuditConfig {
    pub model: String,
    pub mode: AuditMode,
    pub max_turns: u32,
    /// Abort when input + output tokens of all requests exceed this.
    pub max_tokens_budget: u64,
    /// `max_tokens` per response.
    pub max_tokens: u32,
    /// `output_config.effort`.
    pub effort: Option<String>,
    /// Server-side refusal fallback (`fallbacks: "default"`).
    pub fallback: bool,
    pub hunt_max_files: usize,
    pub hunt_max_bytes: u64,
}

impl AuditConfig {
    pub fn new(mode: AuditMode) -> Self {
        let (max_turns, budget) = match mode {
            AuditMode::Triage => (40, 1_500_000),
            AuditMode::Hunt => (80, 4_000_000),
        };
        AuditConfig {
            model: DEFAULT_MODEL.into(),
            mode,
            max_turns,
            max_tokens_budget: budget,
            max_tokens: 16_000,
            effort: Some("medium".into()),
            fallback: true,
            hunt_max_files: 40,
            hunt_max_bytes: 800 * 1024,
        }
    }
}

/// Progress callback events (printed by the CLI with `-v`).
#[derive(Debug)]
pub enum ProgressEvent<'a> {
    Turn {
        turn: u32,
        max_turns: u32,
    },
    ToolCall {
        name: &'a str,
        input: &'a Value,
    },
    ToolResult {
        name: &'a str,
        bytes: usize,
        is_error: bool,
    },
    Usage {
        turn: u32,
        usage: &'a Usage,
        budget: u64,
    },
}

/// Short German description of a tool call for progress output.
pub fn describe_call(name: &str, input: &Value) -> String {
    let s = |k: &str| input.get(k).and_then(Value::as_str).unwrap_or("");
    match name {
        "list_dir" | "file_info" => format!("{name} {}", s("path")),
        "read_file" => {
            let off = input.get("offset").and_then(Value::as_u64).unwrap_or(1);
            format!("read_file {} ab Zeile {off}", s("path"))
        }
        "grep" => format!(
            "grep /{}/ in {}",
            excerpt(s("pattern"), 60),
            if s("path").is_empty() { "." } else { s("path") }
        ),
        "get_finding" => format!("get_finding #{}", s("id")),
        "db_query" => format!("db_query {}", excerpt(s("sql"), 100)),
        "lookup_advisory" => format!("lookup_advisory {}", s("id")),
        "osv_lookup" => format!("osv_lookup {} {}", s("package"), s("version")),
        "record_verdict" => {
            let n = input
                .get("finding_ids")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0)
                + usize::from(!s("finding_id").is_empty());
            format!("record_verdict {} ({n} Befund(e))", s("verdict"))
        }
        "record_finding" => format!(
            "record_finding [{}] {}",
            s("severity"),
            excerpt(s("title"), 80)
        ),
        other => other.to_string(),
    }
}

/// Critical and warning findings the model is asked to assess.
fn required_findings(ctx: &ToolContext) -> Vec<&Finding> {
    let mut v: Vec<&Finding> = ctx
        .report
        .findings
        .iter()
        .filter(|f| !f.accepted && f.severity >= Severity::Warning)
        .collect();
    v.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.subject.cmp(&b.subject)));
    v.truncate(MAX_TASK_FINDINGS);
    v
}

fn task_message(cfg: &AuditConfig, ctx: &ToolContext) -> String {
    let r = &ctx.report;
    let mut m = String::new();
    m.push_str(&format!(
        "# Auftrag: KI-Audit im Modus „{}“\n\n",
        match cfg.mode {
            AuditMode::Triage => "triage",
            AuditMode::Hunt => "hunt",
        }
    ));
    m.push_str(&format!(
        "Shop: {} {} (Plattform-ID {}){}\n",
        r.platform.name,
        r.platform
            .version
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "(Version unbekannt)".into()),
        r.platform.id,
        r.platform
            .target
            .as_ref()
            .map(|t| format!(", Ziel {t}"))
            .unwrap_or_default()
    ));
    m.push_str(&format!(
        "Scan-Report vom {}, Referenzdatum {}, Ampel: {:?}. Befunde: {} kritisch, {} Warnungen, {} Hinweise, {} als unbedenklich markiert.\n",
        r.generated_at.format("%d.%m.%Y %H:%M UTC"),
        r.reference_date.format("%d.%m.%Y"),
        r.verdict,
        r.summary.critical,
        r.summary.warning,
        r.summary.info,
        r.summary.accepted
    ));
    m.push_str(&format!(
        "Verfügbare Quellen: Dateisystem {}, Datenbank {}, OSV.dev {}.\n",
        yes_no(ctx.root().is_some()),
        yes_no(ctx.has_db()),
        yes_no(ctx.has_osv())
    ));
    if !r.limitations.is_empty() {
        m.push_str("Einschränkungen des Scans:\n");
        for l in r.limitations.iter().take(15) {
            m.push_str(&format!("- {}\n", excerpt(l, 200)));
        }
    }
    let required = required_findings(ctx);
    let total = r
        .findings
        .iter()
        .filter(|f| !f.accepted && f.severity >= Severity::Warning)
        .count();
    m.push_str(&format!(
        "\n## Zu bewertende Befunde ({} von {total} kritisch/Warnung)\n",
        required.len()
    ));
    if required.is_empty() {
        m.push_str("Keine offenen kritischen Befunde oder Warnungen. Prüfe trotzdem die Hinweise und die Integritätsdaten stichprobenartig.\n");
    } else {
        m.push_str("id | schweregrad | kategorie | regel | subjekt | titel\n");
        for f in &required {
            m.push_str(&format!(
                "{} | {} | {} | {} | {} | {}\n",
                f.id,
                f.severity.label_en(),
                category_name(f.category),
                f.rule,
                excerpt(&f.subject, 140),
                excerpt(&f.title, 140)
            ));
        }
        if total > required.len() {
            m.push_str("Weitere Befunde über list_findings (offset).\n");
        }
        m.push_str("\nBewerte jeden dieser Befunde mit record_verdict (gleichartige gesammelt über finding_ids). Prüfe dabei auch, ob die Befunde zusammen ein Angriffsmuster ergeben (Zeitpunkt, Verzeichnis, Payload).\n");
    }
    if cfg.mode == AuditMode::Hunt {
        m.push_str("\n## Code-Review (Modus hunt)\n");
        match ctx.root() {
            Some(root) => {
                let candidates = hunt_candidates(
                    root,
                    &r.platform.id,
                    r.reference_date,
                    cfg.hunt_max_files,
                    cfg.hunt_max_bytes,
                );
                m.push_str("Prüfe zusätzlich eigenen Code (Plugins, Templates, Theme-JavaScript) auf Schwachstellen: SQL-Injection, XSS, SSTI, RCE, IDOR, unsichere Uploads, fest einprogrammierte Zugangsdaten, veraltete Bibliotheken (Version im Code/composer.lock, ggf. lookup_advisory/osv_lookup). Erfasse belegte Funde mit record_finding.\n");
                if candidates.is_empty() {
                    m.push_str("Die Heuristik hat keine auffälligen Dateien gefunden; verschaffe dir mit list_dir einen Überblick über die Plugin-/Template-Verzeichnisse.\n");
                } else {
                    m.push_str(&format!(
                        "Kandidaten nach Risiko-Heuristik ({} Dateien, sortiert):\n",
                        candidates.len()
                    ));
                    for c in &candidates {
                        m.push_str(&format!(
                            "- {} ({}{}) Treffer: {}\n",
                            c.path,
                            human_size(c.size),
                            c.modified
                                .map(|t| format!(", geändert {}", t.format("%d.%m.%Y")))
                                .unwrap_or_default(),
                            c.hits
                                .iter()
                                .map(|(n, k)| format!("{n}×{k}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }
                }
            }
            None => m.push_str("Kein Dateisystem verfügbar (gehostete Plattform) – der Code-Review entfällt; konzentriere dich auf die Befunde und Integritätsdaten.\n"),
        }
    }
    m.push_str("\nSchließe mit der deutschen Zusammenfassung und dem JSON-Block ab.\n");
    redact(&m).text
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "ja"
    } else {
        "nein"
    }
}

/// Run the audit.  Never fails: API errors, budget and turn limits end the
/// loop with a corresponding [`AuditStatus`]; verdicts recorded so far are
/// kept.
pub fn run_audit(
    client: &dyn LlmClient,
    cfg: &AuditConfig,
    ctx: &mut ToolContext,
    progress: &mut dyn FnMut(ProgressEvent<'_>),
) -> AuditReport {
    let started = Utc::now();
    let tools = ctx.definitions();
    let mut messages = vec![Message::user_text(task_message(cfg, ctx))];
    let required: Vec<String> = required_findings(ctx)
        .iter()
        .map(|f| f.id.to_string())
        .collect();
    let mut usage = Usage::default();
    let mut turns = 0u32;
    let mut status = AuditStatus::Completed;
    let mut abort_reason: Option<String> = None;
    let mut final_text = String::new();
    let mut warned = false;
    let mut nudged = false;

    loop {
        if turns >= cfg.max_turns {
            status = AuditStatus::MaxTurns;
            abort_reason = Some(format!(
                "Maximale Rundenzahl ({}) erreicht. Bisherige Bewertungen wurden gespeichert; mit --max-turns erhöhen.",
                cfg.max_turns
            ));
            break;
        }
        turns += 1;
        progress(ProgressEvent::Turn {
            turn: turns,
            max_turns: cfg.max_turns,
        });
        let request = MessagesRequest {
            model: cfg.model.clone(),
            max_tokens: cfg.max_tokens,
            system: SYSTEM_PROMPT.to_string(),
            tools: tools.clone(),
            messages: messages.clone(),
            effort: cfg.effort.clone(),
            fallback: cfg.fallback,
        };
        let response = match client.create_message(&request) {
            Ok(r) => r,
            Err(e) => {
                status = AuditStatus::ApiError;
                abort_reason = Some(e.to_string());
                break;
            }
        };
        usage.add(&response.usage);
        log::info!(
            "audit turn {turns}: input {} (cache read {}, cache write {}), output {}",
            response.usage.input_tokens,
            response.usage.cache_read_input_tokens,
            response.usage.cache_creation_input_tokens,
            response.usage.output_tokens
        );
        if !response.model.is_empty() && response.model != cfg.model {
            log::warn!(
                "turn {turns} was served by {} instead of {}",
                response.model,
                cfg.model
            );
        }
        progress(ProgressEvent::Usage {
            turn: turns,
            usage: &usage,
            budget: cfg.max_tokens_budget,
        });
        let spent = usage.total_input() + usage.output_tokens;
        let stop = response.stop_reason.clone().unwrap_or_default();
        // Keep the assistant turn exactly as received (thinking blocks included).
        messages.push(Message::assistant(response.content.clone()));

        if stop == "refusal" {
            let category = response
                .stop_details
                .as_ref()
                .and_then(|d| d.get("category"))
                .and_then(Value::as_str)
                .unwrap_or("unbekannt");
            status = AuditStatus::Refused;
            abort_reason = Some(format!(
                "Das Modell hat die Anfrage abgelehnt (Kategorie: {category}). Bisherige Bewertungen wurden gespeichert."
            ));
            break;
        }

        let calls = response.tool_uses();
        if !calls.is_empty() {
            let mut results = Vec::with_capacity(calls.len() + 1);
            for (id, name, input) in &calls {
                progress(ProgressEvent::ToolCall { name, input });
                let out = ctx.execute(name, input);
                progress(ProgressEvent::ToolResult {
                    name,
                    bytes: out.content.len(),
                    is_error: out.is_error,
                });
                let mut block = json!({
                    "type": "tool_result",
                    "tool_use_id": id,
                    "content": out.content,
                });
                if out.is_error {
                    block["is_error"] = json!(true);
                }
                results.push(block);
            }
            if spent >= cfg.max_tokens_budget {
                status = AuditStatus::BudgetExceeded;
                abort_reason = Some(budget_message(spent, cfg.max_tokens_budget));
                break;
            }
            let near_budget = spent as f64 >= cfg.max_tokens_budget as f64 * 0.85;
            let near_turns = turns + 2 >= cfg.max_turns;
            if !warned && (near_budget || near_turns) {
                warned = true;
                results.push(json!({
                    "type": "text",
                    "text": "Hinweis von ecomsec: Das Budget für dieses Audit ist fast erschöpft. Erfasse ausstehende Bewertungen jetzt (gleichartige Befunde gesammelt) und schließe danach mit der Zusammenfassung und dem JSON-Block ab."
                }));
            }
            messages.push(Message::user_blocks(results));
            continue;
        }

        match stop.as_str() {
            "max_tokens" => {
                if spent >= cfg.max_tokens_budget {
                    status = AuditStatus::BudgetExceeded;
                    abort_reason = Some(budget_message(spent, cfg.max_tokens_budget));
                    final_text = response.text();
                    break;
                }
                messages.push(Message::user_text(
                    "Deine Antwort wurde wegen der Längenbegrenzung abgeschnitten. Gib jetzt nur die kurze Zusammenfassung und den JSON-Block aus.",
                ));
            }
            "pause_turn" => {}
            _ => {
                final_text = response.text();
                let reviewed: BTreeSet<&str> =
                    ctx.verdicts.iter().map(|v| v.finding_id.as_str()).collect();
                let missing: Vec<&str> = required
                    .iter()
                    .map(String::as_str)
                    .filter(|id| !reviewed.contains(id))
                    .collect();
                if !nudged
                    && !missing.is_empty()
                    && turns < cfg.max_turns
                    && spent < cfg.max_tokens_budget
                {
                    nudged = true;
                    messages.push(Message::user_text(format!(
                        "Folgende Befunde aus dem Auftrag haben noch keine Bewertung: {}. Bewerte sie bitte mit record_verdict (gleichartige gesammelt) und gib danach erneut die Zusammenfassung mit JSON-Block aus.",
                        missing.iter().take(60).copied().collect::<Vec<_>>().join(", ")
                    )));
                    continue;
                }
                break;
            }
        }
    }

    let parsed = parse_final(&final_text);
    let reviewed: BTreeSet<&str> = ctx.verdicts.iter().map(|v| v.finding_id.as_str()).collect();
    let unreviewed = required
        .iter()
        .filter(|id| !reviewed.contains(id.as_str()))
        .cloned()
        .collect();
    let summary = parsed
        .summary
        .clone()
        .or_else(|| (!parsed.prose.is_empty()).then(|| parsed.prose.clone()))
        .unwrap_or_else(|| abort_reason.clone().unwrap_or_default());
    AuditReport {
        schema_version: AUDIT_SCHEMA_VERSION,
        model: cfg.model.clone(),
        mode: cfg.mode,
        started,
        finished: Utc::now(),
        report_generated_at: ctx.report.generated_at,
        platform: format!(
            "{}{}",
            ctx.report.platform.name,
            ctx.report
                .platform
                .version
                .as_ref()
                .map(|v| format!(" {v}"))
                .unwrap_or_default()
        ),
        status,
        abort_reason,
        turns,
        tokens_in: usage.total_input(),
        tokens_out: usage.output_tokens,
        usage,
        estimated_cost_usd: estimate_cost(&cfg.model, &usage),
        verdicts: ctx.verdicts.clone(),
        new_findings: ctx.new_findings.clone(),
        unreviewed,
        overall_assessment: parsed.overall,
        confidence: parsed.confidence,
        summary: redact(&summary).text,
        next_steps: parsed.next_steps,
        data: ctx.stats.clone(),
    }
}

fn budget_message(spent: u64, budget: u64) -> String {
    format!(
        "Token-Budget überschritten: {spent} von {budget} Tokens verbraucht. Audit abgebrochen; bisherige Bewertungen wurden gespeichert. Mit --max-tokens-budget erhöhen."
    )
}

#[derive(Debug, Default)]
struct FinalSummary {
    overall: Option<String>,
    confidence: Option<f32>,
    summary: Option<String>,
    next_steps: Vec<NextStep>,
    prose: String,
}

/// Extract the closing JSON block (fenced ```json or the last object with
/// the expected keys) and the prose around it.
fn parse_final(text: &str) -> FinalSummary {
    let mut out = FinalSummary::default();
    let mut found: Option<(usize, usize, Value)> = None;
    if let Some(start) = text.rfind("```json") {
        let body_start = start + "```json".len();
        if let Some(len) = text[body_start..].find("```") {
            if let Ok(v) = serde_json::from_str::<Value>(text[body_start..body_start + len].trim())
            {
                found = Some((start, body_start + len + 3, v));
            }
        }
    }
    if found.is_none() {
        for (pos, _) in text.match_indices('{') {
            let mut it = serde_json::Deserializer::from_str(&text[pos..]).into_iter::<Value>();
            if let Some(Ok(v)) = it.next() {
                if v.get("overall_assessment").is_some() || v.get("next_steps").is_some() {
                    found = Some((pos, pos + it.byte_offset(), v));
                }
            }
        }
    }
    let Some((start, end, v)) = found else {
        out.prose = text.trim().to_string();
        return out;
    };
    out.prose = format!("{}{}", &text[..start], &text[end.min(text.len())..])
        .trim()
        .to_string();
    out.overall = v
        .get("overall_assessment")
        .and_then(Value::as_str)
        .map(|s| excerpt(s.trim(), 60));
    out.confidence = v.get("confidence").and_then(Value::as_f64).map(|c| {
        let c = if c > 1.0 { c / 100.0 } else { c };
        c.clamp(0.0, 1.0) as f32
    });
    out.summary = v
        .get("summary")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(steps) = v.get("next_steps").and_then(Value::as_array) {
        for (i, s) in steps.iter().enumerate().take(30) {
            let default_prio = (i + 1).min(9) as u8;
            let step = match s {
                Value::String(t) => NextStep {
                    priority: default_prio,
                    action: t.clone(),
                    rationale: String::new(),
                },
                Value::Object(o) => NextStep {
                    priority: o
                        .get("priority")
                        .and_then(Value::as_u64)
                        .map(|p| p.clamp(1, 9) as u8)
                        .unwrap_or(default_prio),
                    action: o
                        .get("action")
                        .or_else(|| o.get("massnahme"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    rationale: o
                        .get("rationale")
                        .or_else(|| o.get("begruendung"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                },
                _ => continue,
            };
            if !step.action.trim().is_empty() {
                out.next_steps.push(NextStep {
                    action: redact(&step.action).text,
                    rationale: redact(&step.rationale).text,
                    ..step
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fenced_and_bare_json() {
        let t = "Zusammenfassung vorab.\n```json\n{\"overall_assessment\":\"unklar\",\"confidence\":0.6,\"summary\":\"S\",\"next_steps\":[{\"priority\":1,\"action\":\"A\",\"rationale\":\"R\"},\"B\"]}\n```\nEnde";
        let p = parse_final(t);
        assert_eq!(p.overall.as_deref(), Some("unklar"));
        assert_eq!(p.confidence, Some(0.6));
        assert_eq!(p.summary.as_deref(), Some("S"));
        assert_eq!(p.next_steps.len(), 2);
        assert_eq!(p.next_steps[1].priority, 2);
        assert_eq!(p.prose, "Zusammenfassung vorab.\n\nEnde");

        let bare = "Text {\"overall_assessment\":\"sauber\",\"confidence\":90,\"next_steps\":[]}";
        let p = parse_final(bare);
        assert_eq!(p.overall.as_deref(), Some("sauber"));
        assert_eq!(p.confidence, Some(0.9));
        assert_eq!(p.prose, "Text");

        let none = parse_final("nur Text");
        assert!(none.overall.is_none());
        assert_eq!(none.prose, "nur Text");
    }
}
