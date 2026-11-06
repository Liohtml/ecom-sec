//! Local web dashboard (`ecomsec serve`): overview, findings triage,
//! Shop-Integrität, Handlungsempfehlungen, history and the AI audit, plus
//! scan trigger with progress, risk acceptance and report export.
//!
//! The UI is a static app (`assets/app/`: `index.html`, `app.css`,
//! `app.js`) without external resources; all data comes from `/api/*`.
//!
//! Every API call needs the `X-Auth-Token` header. The token is never read
//! from the query string. On loopback a token is generated when none was
//! configured and embedded in the HTML for that host only. Requests whose
//! `Host` or `Origin` is not the bind address (or an explicitly trusted
//! hostname) are rejected, as are browser `Sec-Fetch-Site: cross-site`
//! requests. Binding somewhere other than loopback without a token fails
//! at startup.

use crate::output::{self, html, Format};
use crate::platforms::TargetSpec;
use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::NaiveDate;
use ecomsec_core::finding::FindingId;
use ecomsec_core::{Engine, Report, ScanOptions, StateStore};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use subtle::ConstantTimeEq;

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
    token: String,
    policy: HostPolicy,
}

/// Result of resolving the dashboard token before the listener starts.
#[derive(Debug)]
pub struct ServeAuth {
    pub token: String,
    /// `true` when the token was created for this process (loopback only).
    pub generated: bool,
}

/// Require an explicit token when the socket is not loopback-only.
/// An empty token does not count. On loopback a token is generated.
pub fn prepare_serve_auth(
    bind: SocketAddr,
    configured: Option<String>,
) -> anyhow::Result<ServeAuth> {
    if let Some(token) = configured
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
    {
        return Ok(ServeAuth {
            token,
            generated: false,
        });
    }
    if !bind.ip().is_loopback() {
        anyhow::bail!(
            "Das Dashboard lauscht auf {bind} und ist damit nicht nur über Loopback erreichbar. \
             Ein Zugriffstoken ist erforderlich (--auth-token, ECOMSEC_AUTH_TOKEN oder [serve] token)."
        );
    }
    Ok(ServeAuth {
        token: generate_token(),
        generated: true,
    })
}

pub fn serve(
    bind: SocketAddr,
    token: String,
    generated: bool,
    trusted_hosts: Vec<String>,
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
            token: token.clone(),
            policy: HostPolicy {
                bind,
                extra_hosts: normalize_hosts(trusted_hosts),
            },
        };
        let app = router(state);
        let listener = tokio::net::TcpListener::bind(bind).await?;
        eprintln!("ecomsec Dashboard: http://{bind}/  (Strg+C zum Beenden)");
        if generated {
            eprintln!(
                "Zugriffstoken für diese Sitzung (Header X-Auth-Token, nicht in der Adresse): {token}"
            );
        } else {
            eprintln!("Zugriff nur mit gesetztem Token (Header X-Auth-Token).");
        }
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
        .route("/baseline", post(create_baseline));
    Router::new()
        .route("/", get(index))
        .route("/app.css", get(app_css))
        .route("/app.js", get(app_js))
        .nest("/api", api)
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// Hosts the dashboard is willing to answer. Domain names are rejected
/// unless listed in `extra_hosts`, so a rebound DNS name does not match.
#[derive(Clone, Debug)]
struct HostPolicy {
    bind: SocketAddr,
    extra_hosts: Vec<String>,
}

async fn guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if let Some(loc) = location_without_token(req.uri()) {
        // The query token is never accepted. GET/HEAD drop it from the
        // address bar; other methods are rejected so the body is not retried
        // as a GET.
        if *req.method() == Method::GET || *req.method() == Method::HEAD {
            return see_other(loc);
        }
        return error(
            StatusCode::BAD_REQUEST,
            "Der Parameter token wird nicht akzeptiert",
        );
    }
    let headers = req.headers();
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !host_allowed(&state.policy, host) {
        return error(StatusCode::FORBIDDEN, "Host nicht erlaubt");
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if !origin_allowed(&state.policy, origin) {
            return error(StatusCode::FORBIDDEN, "Origin nicht erlaubt");
        }
    }
    if headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("cross-site"))
    {
        return error(StatusCode::FORBIDDEN, "Cross-Site-Anfrage abgelehnt");
    }
    if req.uri().path().starts_with("/api") {
        let given = headers
            .get("x-auth-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !tokens_equal(&state.token, given) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Token fehlt oder ungültig"})),
            )
                .into_response();
        }
    }
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if !headers.contains_key(header::CONTENT_SECURITY_POLICY) {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
            ),
        );
    }
    resp
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

async fn index(State(state): State<AppState>) -> Response {
    let nonce = random_hex(16);
    let body = html::render_web()
        .replace("__AUTH_TOKEN__", &escape_attr(&state.token))
        .replace("__CSP_NONCE__", &escape_attr(&nonce));
    let mut resp = asset("text/html; charset=utf-8", body);
    if let Ok(value) = HeaderValue::from_str(&format!(
        "default-src 'none'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
    )) {
        resp.headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, value);
    }
    resp
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

fn generate_token() -> String {
    random_hex(32)
}

fn random_hex(nbytes: usize) -> String {
    let mut buf = vec![0u8; nbytes];
    getrandom::getrandom(&mut buf).expect("CSPRNG");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(nbytes * 2);
    for byte in buf {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// SHA-256 both sides so the comparison length does not depend on the token,
/// then compare with `subtle`.
fn tokens_equal(expected: &str, presented: &str) -> bool {
    let a = Sha256::digest(expected.as_bytes());
    let b = Sha256::digest(presented.as_bytes());
    bool::from(a.as_slice().ct_eq(b.as_slice()))
}

fn escape_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
        .replace('<', "&lt;")
}

fn normalize_hosts(hosts: Vec<String>) -> Vec<String> {
    hosts
        .into_iter()
        .filter_map(|host| {
            let host = host.trim().trim_end_matches('.');
            if host.is_empty() {
                return None;
            }
            split_host(host).map(|(name, _)| name)
        })
        .collect()
}

/// `host[:port]` or `[ipv6]:port` → (name lowercase, port).
fn split_host(value: &str) -> Option<(String, Option<u16>)> {
    let value = value.trim();
    if value.is_empty() || value.contains(['/', '@', '?', '#', '\\']) {
        return None;
    }
    if let Some(rest) = value.strip_prefix('[') {
        let (name, after) = rest.split_once(']')?;
        if name.is_empty() {
            return None;
        }
        if after.is_empty() {
            return Some((name.to_ascii_lowercase(), None));
        }
        let port = after.strip_prefix(':')?.parse().ok()?;
        return Some((name.to_ascii_lowercase(), Some(port)));
    }
    match value.matches(':').count() {
        0 => Some((value.to_ascii_lowercase(), None)),
        1 => {
            let (name, port) = value.split_once(':')?;
            if name.is_empty() {
                return None;
            }
            Some((name.to_ascii_lowercase(), Some(port.parse().ok()?)))
        }
        _ => None,
    }
}

fn name_allowed(policy: &HostPolicy, name: &str) -> bool {
    if policy
        .extra_hosts
        .iter()
        .any(|host| host.eq_ignore_ascii_case(name))
    {
        return true;
    }
    let bind_ip = policy.bind.ip();
    if bind_ip.is_loopback() {
        return name.eq_ignore_ascii_case("localhost")
            || matches!(name.parse::<IpAddr>(), Ok(ip) if ip.is_loopback());
    }
    if let Ok(parsed) = name.parse::<IpAddr>() {
        return bind_ip.is_unspecified() || parsed == bind_ip;
    }
    bind_ip.is_unspecified() && name.eq_ignore_ascii_case("localhost")
}

fn port_allowed(policy: &HostPolicy, name: &str, port: Option<u16>, https: bool) -> bool {
    match port {
        Some(p) => p == policy.bind.port(),
        None => {
            let default = if https { 443 } else { 80 };
            policy.bind.port() == default
                || policy
                    .extra_hosts
                    .iter()
                    .any(|host| host.eq_ignore_ascii_case(name))
        }
    }
}

fn host_allowed(policy: &HostPolicy, host: &str) -> bool {
    let Some((name, port)) = split_host(host) else {
        return false;
    };
    port_allowed(policy, &name, port, false) && name_allowed(policy, &name)
}

fn origin_allowed(policy: &HostPolicy, origin: &str) -> bool {
    let origin = origin.trim();
    if origin.is_empty() || origin.eq_ignore_ascii_case("null") {
        return false;
    }
    let (https, rest) = if let Some(rest) = origin.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = origin.strip_prefix("http://") {
        (false, rest)
    } else {
        return false;
    };
    if rest.contains(['/', '?', '@', '#', '\\']) {
        return false;
    }
    // The dashboard speaks HTTP on `bind.port`, except an explicit trusted
    // name reached through a TLS-terminating proxy (port omitted or 443).
    let Some((name, port)) = split_host(rest) else {
        return false;
    };
    if https
        && policy.bind.port() != 443
        && !policy
            .extra_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&name))
    {
        return false;
    }
    if !https && policy.bind.port() == 443 {
        return false;
    }
    port_allowed(policy, &name, port, https) && name_allowed(policy, &name)
}

/// Redirect target with every `token` parameter removed. `None` when the
/// query did not contain one.
fn location_without_token(uri: &Uri) -> Option<String> {
    let query = uri.query()?;
    let mut kept = Vec::new();
    let mut saw = false;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let name = pair.split('=').next().unwrap_or("");
        if name == "token" {
            saw = true;
            continue;
        }
        kept.push(pair);
    }
    if !saw {
        return None;
    }
    let path = if uri.path().is_empty() {
        "/"
    } else {
        uri.path()
    };
    if kept.is_empty() {
        Some(path.to_string())
    } else {
        Some(format!("{path}?{}", kept.join("&")))
    }
}

fn see_other(location: String) -> Response {
    let mut resp = StatusCode::SEE_OTHER.into_response();
    match HeaderValue::from_str(&location) {
        Ok(value) => {
            resp.headers_mut().insert(header::LOCATION, value);
            resp
        }
        Err(_) => error(StatusCode::BAD_REQUEST, "Anfrage abgelehnt"),
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

    #[test]
    fn token_comparison_rejects_near_misses() {
        let token = "0123456789abcdef0123456789abcdef";
        assert!(tokens_equal(token, token));
        assert!(!tokens_equal(token, ""));
        assert!(!tokens_equal(token, &token[..token.len() - 1]));
        assert!(!tokens_equal(token, &format!("{token}00")));
        assert!(!tokens_equal(token, &format!("ff{token}")));
        let mut flipped = token.to_string();
        flipped.replace_range(0..1, "1");
        assert!(!tokens_equal(token, &flipped));
    }

    #[test]
    fn non_loopback_without_token_is_refused() {
        let open: SocketAddr = "0.0.0.0:8787".parse().unwrap();
        let err = prepare_serve_auth(open, None).unwrap_err();
        assert!(err.to_string().contains("Zugriffstoken"));
        assert!(prepare_serve_auth(open, Some("  ".into())).is_err());
        let kept = prepare_serve_auth(open, Some(" fest ".into())).unwrap();
        assert_eq!(kept.token, "fest");
        assert!(!kept.generated);

        let local: SocketAddr = "127.0.0.1:8787".parse().unwrap();
        let generated = prepare_serve_auth(local, None).unwrap();
        assert!(generated.generated);
        assert_eq!(generated.token.len(), 64);
        assert!(generated.token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn host_policy_allows_loopback_names_and_rejects_dns_names() {
        let policy = host_policy("127.0.0.1:8787", &[]);
        assert!(host_allowed(&policy, "127.0.0.1:8787"));
        assert!(host_allowed(&policy, "localhost:8787"));
        assert!(host_allowed(&policy, "[::1]:8787"));
        assert!(!host_allowed(&policy, "evil.example:8787"));
        assert!(!host_allowed(&policy, "127.0.0.1:9"));
        assert!(!host_allowed(&policy, "127.0.0.1"));
        assert!(origin_allowed(&policy, "http://127.0.0.1:8787"));
        assert!(!origin_allowed(&policy, "http://evil.example:8787"));
        assert!(!origin_allowed(&policy, "null"));
        assert!(!origin_allowed(&policy, "https://127.0.0.1:8787"));
    }

    #[test]
    fn unspecified_bind_allows_ip_literals_only() {
        let policy = host_policy("0.0.0.0:8787", &[]);
        assert!(host_allowed(&policy, "192.0.2.10:8787"));
        assert!(host_allowed(&policy, "127.0.0.1:8787"));
        assert!(host_allowed(&policy, "localhost:8787"));
        assert!(!host_allowed(&policy, "rebind.example:8787"));
        let trusted = host_policy("0.0.0.0:8787", &["dash.example"]);
        assert!(host_allowed(&trusted, "dash.example"));
        assert!(host_allowed(&trusted, "dash.example:8787"));
        assert!(origin_allowed(&trusted, "https://dash.example"));
        assert!(!host_allowed(&trusted, "other.example"));
    }

    fn host_policy(bind: &str, extra: &[&str]) -> HostPolicy {
        HostPolicy {
            bind: bind.parse().unwrap(),
            extra_hosts: normalize_hosts(extra.iter().map(|s| (*s).to_string()).collect()),
        }
    }

    fn test_router(token: &str, bind: &str, extra: &[&str]) -> Router {
        let dir = std::env::temp_dir().join(format!("ecomsec-web-test-{}", std::process::id()));
        let state = AppState {
            inner: Arc::new(Mutex::new(Inner {
                spec: TargetSpec {
                    platform: "jtl5".into(),
                    root: None,
                    shop: None,
                    token: None,
                    api_version: None,
                    allow_hosts: vec![],
                    max_assets: None,
                },
                options: ScanOptions::default(),
                store: StateStore::new(dir),
                report: None,
                running: false,
                done: 0,
                total: 0,
                error: None,
                started: None,
                last_scan_options: None,
            })),
            token: token.to_string(),
            policy: host_policy(bind, extra),
        };
        router(state)
    }

    async fn send(
        app: Router,
        method: &str,
        uri: &str,
        host: &str,
        extra: &[(&str, &str)],
    ) -> Response {
        use axum::body::Body;
        use tower::ServiceExt;
        let mut builder = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("host", host);
        for (name, value) in extra {
            builder = builder.header(*name, *value);
        }
        app.oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn body_string(resp: Response) -> String {
        use http_body_util::BodyExt;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn api_requires_header_token_and_ignores_query_token() {
        let app = test_router("sekret", "127.0.0.1:8787", &[]);
        let missing = send(app.clone(), "GET", "/api/status", "127.0.0.1:8787", &[]).await;
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

        let wrong = send(
            app.clone(),
            "GET",
            "/api/status",
            "127.0.0.1:8787",
            &[("x-auth-token", "falsch")],
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

        let query = send(
            app.clone(),
            "GET",
            "/api/status?token=sekret",
            "127.0.0.1:8787",
            &[],
        )
        .await;
        assert_eq!(query.status(), StatusCode::SEE_OTHER);
        let location = query
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(location, "/api/status");
        assert!(!location.contains("sekret"));

        let posted = send(
            app.clone(),
            "POST",
            "/api/scan?token=sekret",
            "127.0.0.1:8787",
            &[("x-auth-token", "sekret")],
        )
        .await;
        assert_eq!(posted.status(), StatusCode::BAD_REQUEST);

        let ok = send(
            app,
            "GET",
            "/api/status",
            "127.0.0.1:8787",
            &[("x-auth-token", "sekret")],
        )
        .await;
        assert_eq!(ok.status(), StatusCode::OK);
        let text = body_string(ok).await;
        assert!(text.contains("\"running\""));
    }

    #[tokio::test]
    async fn foreign_host_origin_and_cross_site_are_rejected() {
        let token = "sekret";
        let app = test_router(token, "127.0.0.1:8787", &[]);
        let auth = [("x-auth-token", token)];

        let rebound = send(
            app.clone(),
            "GET",
            "/api/report",
            "evil.example:8787",
            &auth,
        )
        .await;
        assert_eq!(rebound.status(), StatusCode::FORBIDDEN);
        assert!(!body_string(rebound).await.contains(token));

        let page = send(app.clone(), "GET", "/", "evil.example:8787", &[]).await;
        assert_eq!(page.status(), StatusCode::FORBIDDEN);
        assert!(!body_string(page).await.contains(token));

        let origin = send(
            app.clone(),
            "POST",
            "/api/baseline",
            "127.0.0.1:8787",
            &[
                ("x-auth-token", token),
                ("origin", "http://evil.example:8787"),
            ],
        )
        .await;
        assert_eq!(origin.status(), StatusCode::FORBIDDEN);

        let fetched = send(
            app.clone(),
            "GET",
            "/api/status",
            "127.0.0.1:8787",
            &[("x-auth-token", token), ("sec-fetch-site", "cross-site")],
        )
        .await;
        assert_eq!(fetched.status(), StatusCode::FORBIDDEN);

        let same = send(
            app,
            "GET",
            "/api/status",
            "127.0.0.1:8787",
            &[
                ("x-auth-token", token),
                ("origin", "http://127.0.0.1:8787"),
                ("sec-fetch-site", "same-origin"),
            ],
        )
        .await;
        assert_eq!(same.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn dashboard_embeds_token_only_for_an_allowed_host() {
        let app = test_router("sekret", "0.0.0.0:8787", &[]);
        let ok = send(app.clone(), "GET", "/", "127.0.0.1:8787", &[]).await;
        assert_eq!(ok.status(), StatusCode::OK);
        let csp = ok
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(csp.contains("script-src 'self' 'nonce-"));
        let html = body_string(ok).await;
        assert!(html.contains("content=\"sekret\""));
        assert!(html.contains("nonce=\""));
        assert!(!html.contains("__AUTH_TOKEN__"));
        assert!(!html.contains("?token="));
        let nonce = csp
            .split("nonce-")
            .nth(1)
            .unwrap()
            .split('\'')
            .next()
            .unwrap();
        assert!(html.contains(&format!("nonce=\"{nonce}\"")));

        let blocked = send(
            app,
            "GET",
            "/?token=sekret&theme=dark",
            "rebind.example:8787",
            &[],
        )
        .await;
        assert_eq!(blocked.status(), StatusCode::SEE_OTHER);
        let location = blocked
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(location, "/?theme=dark");
        assert!(!body_string(blocked).await.contains("sekret"));
    }
}
