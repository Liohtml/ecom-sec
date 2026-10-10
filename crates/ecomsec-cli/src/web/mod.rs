//! Local web dashboard (`ecomsec serve`): the three tabs of the original
//! backend plugin – Security Scan, Shop-Integrität, Handlungsempfehlungen –
//! plus scan trigger with progress, risk acceptance and history.

use crate::output::html;
use crate::platforms::TargetSpec;
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
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
        };
        let state = AppState {
            inner: Arc::new(Mutex::new(inner)),
            token,
        };
        let api = Router::new()
            .route("/report", get(get_report))
            .route("/status", get(get_status))
            .route("/scan", post(start_scan))
            .route("/findings/accept", post(accept))
            .route("/findings/unaccept", post(unaccept))
            .route("/history", get(history))
            .route("/baseline", post(create_baseline))
            .route_layer(middleware::from_fn_with_state(state.clone(), auth));
        let app = Router::new()
            .route("/", get(index))
            .nest("/api", api)
            .with_state(state);
        let listener = tokio::net::TcpListener::bind(bind).await?;
        eprintln!("ecomsec Dashboard: http://{bind}/  (Strg+C zum Beenden)");
        axum::serve(listener, app).await?;
        Ok::<(), anyhow::Error>(())
    })
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

async fn index() -> Html<String> {
    Html(html::render_web())
}

async fn get_report(State(state): State<AppState>) -> Response {
    let inner = state.inner.lock().expect("lock");
    match &inner.report {
        Some(r) => Json(r).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "noch kein Scan vorhanden"})),
        )
            .into_response(),
    }
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
    }))
}

async fn start_scan(State(state): State<AppState>) -> Response {
    {
        let mut inner = state.inner.lock().expect("lock");
        if inner.running {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "Scan läuft bereits"})),
            )
                .into_response();
        }
        inner.running = true;
        inner.done = 0;
        inner.total = 0;
        inner.error = None;
        inner.started = Some(Instant::now());
    }
    let shared = state.inner.clone();
    tokio::task::spawn_blocking(move || {
        let (spec, options, store) = {
            let inner = shared.lock().expect("lock");
            (
                inner.spec.clone(),
                inner.options.clone(),
                inner.store.clone(),
            )
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
