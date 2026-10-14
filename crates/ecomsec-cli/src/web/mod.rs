//! Local web dashboard (`ecomsec serve`): overview, findings triage,
//! Shop-Integrität, Handlungsempfehlungen, history and the AI audit, plus
//! scan trigger with progress, risk acceptance and report export.
//!
//! The UI is a static app (`assets/app/`: `index.html`, `app.css`,
//! `app.js`) without external resources; all data comes from `/api/*`.

use crate::output::{self, html, Format};
use crate::platforms::TargetSpec;
use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::NaiveDate;
use ecomsec_core::finding::FindingId;
use ecomsec_core::{Engine, Report, ScanOptions, StateStore};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

struct Inner {
    spec: TargetSpec,
    options: ScanOptions,
    store: StateStore,
    report: Option<Report>,
    running: bool,
    done: usize,
    total: usize,
    error: Option<String>,
    started: Option<Instant>,
    /// Options of the scan started last from the dashboard.
    last_scan_options: Option<Value>,
}

#[derive(Clone)]
struct AppState {
    inner: Arc<Mutex<Inner>>,
    token: Option<String>,
}

pub fn serve(
    bind: SocketAddr,
    token: Option<String>,
    spec: TargetSpec,
    options: ScanOptions,
    store: StateStore,
) -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let inner = Inner {
            report: store.last_report(),
            spec,
            options,
            store,
            running: false,
            done: 0,
            total: 0,
            error: None,
            started: None,
            last_scan_options: None,
        };
        let state = AppState {
            inner: Arc::new(Mutex::new(inner)),
            token,
        };
        let app = router(state);
        let listener = tokio::net::TcpListener::bind(bind).await?;
        eprintln!("ecomsec Dashboard: http://{bind}/  (Strg+C zum Beenden)");
        axum::serve(listener, app).await?;
        Ok::<(), anyhow::Error>(())
    })
}

fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/report", get(get_report))
        .route("/report/export", get(export_report))
        .route("/status", get(get_status))
        .route("/scan", post(start_scan))
        .route("/findings/accept", post(accept))
        .route("/findings/unaccept", post(unaccept))
        .route("/findings/{id}", get(get_finding))
        .route("/history", get(history))
        .route("/archive", get(list_archive))
        .route("/archive/{stamp}", get(get_archived))
        .route("/diff", get(get_diff))
        .route("/audit", get(get_audit))
        .route("/baseline", post(create_baseline))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth));
    Router::new()
        .route("/", get(index))
        .route("/app.css", get(app_css))
        .route("/app.js", get(app_js))
        .nest("/api", api)
        .with_state(state)
}

async fn auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Query<HashMap<String, String>>,
    req: Request,
    next: Next,
) -> Response {
    if let Some(expected) = &state.token {
        let given = headers
            .get("x-auth-token")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .or_else(|| query.get("token").cloned());
        if given.as_deref() != Some(expected.as_str()) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Token fehlt oder ungültig"})),
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// Response with the given content type and `Cache-Control: no-cache` (the
/// assets are embedded in the binary and change with every update).
fn asset(content_type: &'static str, body: String) -> Response {
    let mut resp = body.into_response();
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

async fn index() -> Response {
    asset("text/html; charset=utf-8", html::render_web())
}

async fn app_css() -> Response {
    asset("text/css; charset=utf-8", html::WEB_APP_CSS.to_string())
}

async fn app_js() -> Response {
    asset(
        "text/javascript; charset=utf-8",
        html::WEB_APP_JS.to_string(),
    )
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({"error": msg.into()}))).into_response()
}

/// Current report; picks up changes made by other commands (e.g.
/// `ecomsec audit` merging AI reviews into the stored report) while the
/// dashboard is running.
fn current_report(inner: &mut Inner) -> Option<&Report> {
    if !inner.running {
        if let Some(r) = inner.store.last_report() {
            inner.report = Some(r);
        }
    }
    inner.report.as_ref()
}

async fn get_report(State(state): State<AppState>) -> Response {
    let mut inner = state.inner.lock().expect("lock");
    match current_report(&mut inner) {
        Some(r) => Json(r).into_response(),
        None => error(StatusCode::NOT_FOUND, "noch kein Scan vorhanden"),
    }
}

#[derive(Deserialize)]
struct ExportQuery {
    #[serde(default)]
    format: Option<String>,
}

/// Download the current report in one of the CLI formats
/// (`GET /api/report/export?format=json|html|markdown|sarif|junit|text`).
async fn export_report(State(state): State<AppState>, Query(q): Query<ExportQuery>) -> Response {
    let report = {
        let mut inner = state.inner.lock().expect("lock");
        match current_report(&mut inner) {
            Some(r) => r.clone(),
            None => return error(StatusCode::NOT_FOUND, "noch kein Scan vorhanden"),
        }
    };
    let (format, ext, content_type) = match q.format.as_deref().unwrap_or("json") {
        "json" => (Format::Json, "json", "application/json; charset=utf-8"),
        "html" => (Format::Html, "html", "text/html; charset=utf-8"),
        "markdown" | "md" => (Format::Markdown, "md", "text/markdown; charset=utf-8"),
        "sarif" => (
            Format::Sarif,
            "sarif",
            "application/sarif+json; charset=utf-8",
        ),
        "junit" => (Format::Junit, "xml", "application/xml; charset=utf-8"),
        "text" | "txt" => (Format::Text, "txt", "text/plain; charset=utf-8"),
        other => {
            return error(
                StatusCode::BAD_REQUEST,
                format!("unbekanntes Format {other:?} (json, html, markdown, sarif, junit, text)"),
            )
        }
    };
    let body = match tokio::task::spawn_blocking(move || {
        output::render(&report, format, true, false)
            .map(|b| (b, report.generated_at.format("%Y%m%d-%H%M").to_string()))
    })
    .await
    {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let (body, stamp) = body;
    let mut resp = asset(content_type, body);
    if let Ok(v) = HeaderValue::from_str(&format!(
        "attachment; filename=\"ecomsec-report-{stamp}.{ext}\""
    )) {
        resp.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

/// A single finding with the recommendations that reference it and its
/// risk-acceptance record.
async fn get_finding(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let mut inner = state.inner.lock().expect("lock");
    let acceptance = inner
        .store
        .accepted()
        .findings
        .remove(&FindingId(id.clone()));
    let Some(report) = current_report(&mut inner) else {
        return error(StatusCode::NOT_FOUND, "noch kein Scan vorhanden");
    };
    let Some(finding) = report.find(&id) else {
        return error(StatusCode::NOT_FOUND, "Befund nicht gefunden");
    };
    let recommendations: Vec<Value> = report
        .recommendations
        .iter()
        .flat_map(|g| {
            g.items
                .iter()
                .filter(|r| r.related.iter().any(|x| x.as_str() == id))
                .map(move |r| {
                    json!({
                        "group": g.kind,
                        "group_label": g.label,
                        "priority": r.priority,
                        "title": r.title,
                        "detail": r.detail,
                    })
                })
        })
        .collect();
    Json(json!({
        "finding": finding,
        "recommendations": recommendations,
        "acceptance": acceptance,
        "report_generated_at": report.generated_at,
    }))
    .into_response()
}

/// Result of the last AI audit (`ecomsec audit`), if any.
async fn get_audit(State(state): State<AppState>) -> Response {
    let store = state.inner.lock().expect("lock").store.clone();
    match store.document::<Value>(ecomsec_audit::LAST_AUDIT_FILE) {
        Some(a) => Json(a).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "noch kein KI-Audit vorhanden"})),
        )
            .into_response(),
    }
}

fn options_json(o: &ScanOptions) -> Value {
    json!({
        "online": o.online,
        "skip_remote": o.skip_remote,
        "reference_date": o.reference_date,
        "time_budget_ms": o.time_budget.map(|d| d.as_millis()),
    })
}

async fn get_status(State(state): State<AppState>) -> Json<Value> {
    let inner = state.inner.lock().expect("lock");
    Json(json!({
        "running": inner.running,
        "done": inner.done,
        "total": inner.total,
        "error": inner.error,
        "elapsed_ms": inner.started.map(|s| s.elapsed().as_millis()),
        "target": inner.spec.display(),
        "has_report": inner.report.is_some(),
        "version": env!("CARGO_PKG_VERSION"),
        "options": options_json(&inner.options),
        "last_scan_options": inner.last_scan_options,
    }))
}

/// Optional body of `POST /api/scan`: overrides for this one scan.
#[derive(Deserialize, Default)]
struct ScanRequest {
    #[serde(default)]
    online: Option<bool>,
    #[serde(default)]
    skip_remote: Option<bool>,
    /// `YYYY-MM-DD`; empty = server default.
    #[serde(default)]
    reference_date: Option<String>,
    /// `45s`, `2m` …; empty = no budget.
    #[serde(default)]
    time_budget: Option<String>,
}

fn scan_options_for(base: &ScanOptions, req: &ScanRequest) -> Result<ScanOptions, String> {
    let mut o = base.clone();
    if let Some(v) = req.online {
        o.online = v;
    }
    if let Some(v) = req.skip_remote {
        o.skip_remote = v;
    }
    if let Some(d) = req.reference_date.as_deref().map(str::trim) {
        if !d.is_empty() {
            o.reference_date = d
                .parse::<NaiveDate>()
                .map_err(|_| format!("ungültiges Referenzdatum {d:?} (JJJJ-MM-TT)"))?;
        }
    }
    if let Some(tb) = req.time_budget.as_deref().map(str::trim) {
        o.time_budget = if tb.is_empty() {
            None
        } else {
            Some(
                ecomsec_core::engine::parse_duration(tb)
                    .ok_or_else(|| format!("ungültiges Zeitbudget {tb:?} (z. B. 45s, 2m)"))?,
            )
        };
    }
    Ok(o)
}

async fn start_scan(State(state): State<AppState>, body: Bytes) -> Response {
    let req: ScanRequest = if body.iter().all(u8::is_ascii_whitespace) {
        ScanRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    format!("ungültige Scan-Optionen: {e}"),
                )
            }
        }
    };
    let options = {
        let mut inner = state.inner.lock().expect("lock");
        if inner.running {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "Scan läuft bereits"})),
            )
                .into_response();
        }
        let options = match scan_options_for(&inner.options, &req) {
            Ok(o) => o,
            Err(e) => return error(StatusCode::BAD_REQUEST, e),
        };
        inner.running = true;
        inner.done = 0;
        inner.total = 0;
        inner.error = None;
        inner.started = Some(Instant::now());
        inner.last_scan_options = Some(options_json(&options));
        options
    };
    let shared = state.inner.clone();
    tokio::task::spawn_blocking(move || {
        let (spec, store) = {
            let inner = shared.lock().expect("lock");
            (inner.spec.clone(), inner.store.clone())
        };
        let progress_state = shared.clone();
        let progress: ecomsec_core::engine::file_scan::ProgressFn = Box::new(move |done, total| {
            if let Ok(mut inner) = progress_state.lock() {
                inner.done = done;
                inner.total = total;
            }
        });
        let result = (|| -> anyhow::Result<Report> {
            let platform = spec.open()?;
            let engine = Engine::new(&options)?;
            let outcome =
                engine.scan_with_progress(platform.as_ref(), &store, &options, Some(progress))?;
            Ok(outcome.report)
        })();
        let mut inner = shared.lock().expect("lock");
        inner.running = false;
        match result {
            Ok(report) => inner.report = Some(report),
            Err(e) => inner.error = Some(format!("{e:#}")),
        }
    });
    (StatusCode::ACCEPTED, Json(json!({"started": true}))).into_response()
}

#[derive(Deserialize)]
struct AcceptBody {
    ids: Vec<String>,
    #[serde(default)]
    reason: Option<String>,
}

fn refreshed(inner: &mut Inner) -> Response {
    let accepted = inner.store.accepted();
    match &mut inner.report {
        Some(report) => {
            report.reapply_acceptance(&accepted);
            let _ = inner.store.save_last_report(report);
            Json(&*report).into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "kein Report"}))).into_response(),
    }
}

async fn accept(State(state): State<AppState>, Json(body): Json<AcceptBody>) -> Response {
    let mut inner = state.inner.lock().expect("lock");
    let reason = body.reason.filter(|r| !r.trim().is_empty());
    for id in &body.ids {
        let subject = inner
            .report
            .as_ref()
            .and_then(|r| r.find(id))
            .map(|f| f.subject.clone())
            .unwrap_or_default();
        if let Err(e) = inner
            .store
            .accept(FindingId(id.clone()), &subject, reason.clone())
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    }
    refreshed(&mut inner)
}

async fn unaccept(State(state): State<AppState>, Json(body): Json<AcceptBody>) -> Response {
    let mut inner = state.inner.lock().expect("lock");
    for id in &body.ids {
        if let Err(e) = inner.store.unaccept(&FindingId(id.clone())) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    }
    refreshed(&mut inner)
}

async fn history(State(state): State<AppState>) -> Json<Value> {
    let inner = state.inner.lock().expect("lock");
    Json(serde_json::to_value(inner.store.history()).unwrap_or(Value::Array(vec![])))
}

/// Stamps of the archived complete reports (`reports/<stamp>.json`).
async fn list_archive(State(state): State<AppState>) -> Json<Value> {
    let store = state.inner.lock().expect("lock").store.clone();
    Json(json!({ "reports": store.archived_stamps() }))
}

/// One archived report (for the history detail view).
async fn get_archived(State(state): State<AppState>, Path(stamp): Path<String>) -> Response {
    let store = state.inner.lock().expect("lock").store.clone();
    match tokio::task::spawn_blocking(move || store.archived_report(&stamp)).await {
        Ok(Some(r)) => Json(r).into_response(),
        _ => error(StatusCode::NOT_FOUND, "Report nicht im Archiv"),
    }
}

/// Changes of the latest scan against the one before ("Änderungen seit
/// letztem Scan").
async fn get_diff(State(state): State<AppState>) -> Json<Value> {
    let store = state.inner.lock().expect("lock").store.clone();
    let diff = tokio::task::spawn_blocking(move || ecomsec_core::diff::latest_from_store(&store))
        .await
        .ok()
        .flatten();
    Json(match diff {
        Some(d) if !d.first_run => json!({"available": true, "diff": d}),
        Some(_) => json!({
            "available": false,
            "reason": "Erst ein vollständiger Scan vorhanden – der Vergleich erscheint ab dem zweiten Scan."
        }),
        None => json!({"available": false, "reason": "Noch kein Scan vorhanden."}),
    })
}

async fn create_baseline(State(state): State<AppState>) -> Response {
    let (spec, store) = {
        let inner = state.inner.lock().expect("lock");
        (inner.spec.clone(), inner.store.clone())
    };
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
        let platform = spec.open()?;
        let profile = platform.file_scan_profile().ok_or_else(|| {
            anyhow::anyhow!("Plattform ohne Dateisystem – keine Baseline möglich")
        })?;
        let info = platform.info();
        let baseline = ecomsec_core::baseline::Baseline::create(
            &profile,
            &info.id,
            info.version.map(|v| v.to_string()),
            false,
        )?;
        let n = baseline.files.len();
        store.save_baseline(&baseline)?;
        Ok(n)
    })
    .await;
    match result {
        Ok(Ok(n)) => Json(json!({"files": n})).into_response(),
        Ok(Err(e)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("{e:#}")})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ScanOptions {
        ScanOptions::default()
    }

    #[test]
    fn scan_request_overrides_options() {
        let req = ScanRequest {
            online: Some(true),
            skip_remote: Some(true),
            reference_date: Some("2026-06-01".into()),
            time_budget: Some("45s".into()),
        };
        let o = scan_options_for(&base(), &req).unwrap();
        assert!(o.online && o.skip_remote);
        assert_eq!(o.reference_date.to_string(), "2026-06-01");
        assert_eq!(o.time_budget, Some(std::time::Duration::from_secs(45)));
    }

    #[test]
    fn empty_scan_request_keeps_defaults() {
        let mut b = base();
        b.time_budget = Some(std::time::Duration::from_secs(10));
        let o = scan_options_for(
            &b,
            &ScanRequest {
                reference_date: Some(" ".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(o.reference_date, b.reference_date);
        assert_eq!(o.time_budget, b.time_budget);
        // An explicitly empty budget removes it.
        let o = scan_options_for(
            &b,
            &ScanRequest {
                time_budget: Some(String::new()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(o.time_budget, None);
    }

    #[test]
    fn invalid_scan_request_is_rejected() {
        let bad_date = ScanRequest {
            reference_date: Some("17.06.2026".into()),
            ..Default::default()
        };
        assert!(scan_options_for(&base(), &bad_date).is_err());
        let bad_budget = ScanRequest {
            time_budget: Some("bald".into()),
            ..Default::default()
        };
        assert!(scan_options_for(&base(), &bad_budget).is_err());
    }
}
