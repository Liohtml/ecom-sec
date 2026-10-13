//! # ecomsec-audit
//!
//! Optional AI audit ("KI-Audit") for ecomsec.  After a normal scan, a Claude
//! model works through the findings as a forensic analyst.  It can only use
//! the read-only tools in [`tools`] – scoped to the shop root, the guarded
//! read-only database helper and the scan report – and every tool output is
//! redacted ([`redact`]) before it is sent.  The agentic loop lives in
//! [`agent`]; the model API is abstracted by [`client::LlmClient`] so that the
//! loop is testable without network access.
//!
//! Nothing here runs unless the user calls `ecomsec audit` with an API key.

pub mod agent;
pub mod client;
pub mod hunt;
pub mod pricing;
pub mod redact;
pub mod report;
pub mod tools;

pub use agent::{describe_call, run_audit, AuditConfig, ProgressEvent, SYSTEM_PROMPT};
pub use client::{AnthropicClient, LlmClient, LlmError, ScriptedClient};
pub use report::{
    merge_into_report, render_text, AuditMode, AuditReport, AuditStatus, LAST_AUDIT_FILE,
};
pub use tools::{MysqlExecutor, OsvOnline, ToolContext};

#[cfg(test)]
mod tests;
