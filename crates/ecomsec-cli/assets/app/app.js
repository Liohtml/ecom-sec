/* ecomsec dashboard – plain ES2020, no framework, no build step and no
   external requests.  All data comes from the local `/api/*` endpoints of
   `ecomsec serve`. */
"use strict";
(function () {
  // ================================================================ helpers
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ESC[c]);
  const icon = (name, cls = "") => `<svg class="icon ${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
  const QUERY = new URLSearchParams(location.search);
  const TOKEN = QUERY.get("token") || "";
  const NF = new Intl.NumberFormat("de-DE");
  const fmtNum = (n) => NF.format(n || 0);
  const fmtDateTime = (t) => (t ? new Date(t).toLocaleString("de-DE", { dateStyle: "medium", timeStyle: "short" }) : "–");
  const fmtDayMonth = (t) => new Date(t).toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit" });
  const fmtShort = (t) => new Date(t).toLocaleString("de-DE", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
  const fmtDate = (d) => (d ? String(d).split("-").reverse().join(".") : "–");
  const fmtDuration = (ms) => {
    ms = Number(ms) || 0;
    if (ms < 1000) return `${ms} ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1).replace(".", ",")} s`;
    return `${Math.floor(ms / 60000)} min ${Math.round((ms % 60000) / 1000)} s`;
  };
  const fmtRel = (t) => {
    const s = (Date.now() - new Date(t).getTime()) / 1000;
    if (s < 60) return "gerade eben";
    if (s < 3600) return `vor ${Math.round(s / 60)} Min.`;
    if (s < 86400) return `vor ${Math.round(s / 3600)} Std.`;
    const d = Math.round(s / 86400);
    return d === 1 ? "gestern" : `vor ${d} Tagen`;
  };
  const plural = (n, one, many) => `${fmtNum(n)} ${n === 1 ? one : many}`;
  const signed = (n) => (n > 0 ? `+${n}` : n < 0 ? `−${Math.abs(n)}` : "±0");
  const debounce = (fn, ms) => {
    let t = 0;
    return (...a) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...a), ms);
    };
  };
  /** Archive stamp of a report time (`20261013T041700.123Z`, see StateStore). */
  const stampOf = (iso) => {
    const m = String(iso).match(/^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?/);
    if (!m) return "";
    return `${m[1]}${m[2]}${m[3]}T${m[4]}${m[5]}${m[6]}.${(m[7] || "").padEnd(3, "0").slice(0, 3)}Z`;
  };
  const sameTime = (a, b) => a && b && new Date(a).getTime() === new Date(b).getTime();

  // Storage never throws (private mode, blocked site data).
  const store = {
    get(k, d) {
      try {
        const v = localStorage.getItem(k);
        return v === null ? d : JSON.parse(v);
      } catch (e) {
        return d;
      }
    },
    set(k, v) {
      try {
        localStorage.setItem(k, JSON.stringify(v));
      } catch (e) { /* ignore */ }
    },
    raw(k, v) {
      try {
        if (v === undefined) return localStorage.getItem(k);
        if (v === null) localStorage.removeItem(k);
        else localStorage.setItem(k, v);
      } catch (e) { /* ignore */ }
      return null;
    },
  };

  // ================================================================ labels
  const SEV = {
    critical: { label: "Kritisch", icon: "crit", rank: 0 },
    warning: { label: "Warnung", icon: "warn", rank: 1 },
    info: { label: "Hinweis", icon: "info", rank: 2 },
  };
  const CAT = {
    known_webshell: "Bekannte Webshell", modified_since_reference: "Neue/geänderte Datei", code_in_upload_dir: "Code im Upload-Verzeichnis",
    webserver_config_manipulation: "Webserver-Konfiguration", suspicious_pattern: "Verdächtiges Code-Muster", exploit_payload: "Exploit-Payload",
    timestamp_anomaly: "Zeitstempel-Anomalie", attack_trace: "Angriffsspur", patch_status: "Patch-Status", admin_account: "Admin-Konto",
    payment_configuration: "Zahlungs-Konfiguration", config_permissions: "Dateirechte", exposed_file: "Öffentlich erreichbare Datei",
    integrity_deviation: "Integritätsabweichung", third_party_injection: "Fremdcode / Injection", scan_limitation: "Scan-Einschränkung", informational: "Information",
  };
  const catLabel = (c) => CAT[c] || c;
  const SOURCE = { file_system: "Dateisystem", database: "Datenbank", api: "API", configuration: "Konfiguration", scanner: "Scanner" };
  const ST = {
    ok: { label: "OK", icon: "ok", rank: 0 },
    unknown: { label: "Unbekannt", icon: "unknown", rank: 1 },
    warning: { label: "Prüfen", icon: "warn", rank: 2 },
    critical: { label: "Kritisch", icon: "crit", rank: 3 },
  };
  const PATCH = {
    vulnerable: { label: "Verwundbar", st: "critical", icon: "crit" },
    unknown: { label: "Unklar", st: "warning", icon: "warn" },
    patched: { label: "Gepatcht", st: "ok", icon: "ok" },
    not_affected: { label: "Nicht betroffen", st: "ok", icon: "ok" },
  };
  const VERDICT = {
    critical: { title: "Kritische Befunde – sofort handeln", lamp: "r", lampLabel: "rot",
      text: "Mindestens ein Befund deutet auf eine Kompromittierung oder eine offene Schwachstelle hin. Befunde zuerst verifizieren und sichern, dann handeln." },
    warning: { title: "Warnungen – zeitnah prüfen", lamp: "y", lampLabel: "gelb",
      text: "Keine eindeutigen Angriffsspuren, aber Auffälligkeiten, die in den nächsten Tagen geprüft werden sollten." },
    clean: { title: "Keine kritischen Befunde", lamp: "g", lampLabel: "grün",
      text: "Keine offenen kritischen Befunde oder Warnungen. Ein sauberes Ergebnis ist keine Garantie – regelmäßig wiederholen." },
  };
  const VERDICT_SHORT = { critical: "Kritisch", warning: "Warnungen", clean: "Sauber" };
  const VERDICT_ST = { critical: "critical", warning: "warning", clean: "ok" };
  const GRADE = { A: "sehr gut", B: "gut", C: "befriedigend", D: "mangelhaft", F: "ungenügend" };
  const gradeTone = (g) => (g === "A" || g === "B" ? "g-good" : g === "F" ? "g-bad" : "g-mid");
  const AI = {
    confirmed: { label: "bestätigt", st: "critical", icon: "crit" },
    needs_human: { label: "manuelle Prüfung", st: "warning", icon: "warn" },
    likely_false_positive: { label: "wahrscheinlich Fehlalarm", st: "ok", icon: "ok" },
  };
  const ASSESS = {
    kompromittiert: ["critical", "Kompromittiert"], wahrscheinlich_kompromittiert: ["critical", "Wahrscheinlich kompromittiert"],
    unklar: ["warning", "Unklar"], wahrscheinlich_sauber: ["ok", "Wahrscheinlich sauber"], sauber: ["ok", "Sauber"],
  };
  const AUDIT_STATUS = {
    completed: "abgeschlossen", budget_exceeded: "abgebrochen: Token-Budget erschöpft", max_turns: "abgebrochen: maximale Rundenzahl erreicht",
    refused: "abgebrochen: Anfrage vom Modell abgelehnt", api_error: "abgebrochen: API-Fehler",
  };
  const GROUP_ORDER = ["check_first", "immediate", "compromise_check", "hardening"];
  const VIEWS = {
    overview: "Übersicht", findings: "Befunde", integrity: "Shop-Integrität", recommendations: "Empfehlungen",
    history: "Verlauf", audit: "KI-Audit", settings: "Einstellungen & Hilfe",
  };
  const DOCS = "https://github.com/liohtml/ecom-sec/blob/main/";

  const sevBadge = (s) => `<span class="badge sev-${s}">${icon(SEV[s].icon)}${SEV[s].label}</span>`;
  const stIcon = (s) => `<span class="ic-${s}" title="${ST[s].label}">${icon(ST[s].icon)}<span class="sr-only">${ST[s].label}</span></span>`;
  const stBadge = (s, label) => `<span class="badge st-${s}">${icon(ST[s].icon)}${esc(label || ST[s].label)}</span>`;
  const aiBadge = (rv) => {
    const a = AI[rv.verdict] || { label: rv.verdict, st: "neutral", icon: "ai" };
    return `<span class="badge st-${a.st}" title="KI-Bewertung (${esc(rv.model || "")}) – Entscheidungshilfe, keine Garantie">${icon("ai")}KI: ${esc(a.label)} · ${Math.round((rv.confidence || 0) * 100)} %</span>`;
  };
  const acceptedBadge = () => `<span class="badge st-ok">${icon("accepted")}Unbedenklich</span>`;
  const newBadge = () => `<span class="badge st-accent" title="Neu seit dem letzten Scan">Neu</span>`;
  const gradeBadge = (g) => (g ? `<span class="grade grade-${esc(g)}" aria-hidden="true">${esc(g)}</span>` : "");

  // ================================================================ API
  class ApiError extends Error {
    constructor(status, message) {
      super(message);
      this.status = status;
    }
  }
  async function api(path, opts = {}) {
    const headers = {};
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    if (TOKEN) headers["X-Auth-Token"] = TOKEN;
    let r;
    try {
      r = await fetch(path, {
        method: opts.method || "GET",
        headers,
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        cache: "no-store",
      });
    } catch (e) {
      throw new ApiError(0, "Server nicht erreichbar – läuft „ecomsec serve“ noch?");
    }
    if (!r.ok) {
      let msg = r.statusText || `HTTP ${r.status}`;
      try {
        const j = await r.json();
        if (j && j.error) msg = j.error;
      } catch (e) { /* not json */ }
      if (r.status === 401) msg = "Zugriff verweigert: Token fehlt oder ist ungültig. Dashboard mit ?token=… öffnen.";
      throw new ApiError(r.status, msg);
    }
    return r.status === 204 ? null : r.json();
  }
  const withToken = (url) => (TOKEN ? `${url}${url.includes("?") ? "&" : "?"}token=${encodeURIComponent(TOKEN)}` : url);

  // ================================================================ state
  const DEFAULT_STATE_FILTER = ["open"];
  const S = {
    report: null,
    reportState: "loading", // loading | ok | empty | error
    reportError: null,
    status: null,
    diff: null,
    history: null,
    archive: new Set(),
    audit: null,
    auditState: "loading",
    view: "overview",
    f: { q: "", state: new Set(DEFAULT_STATE_FILTER), sev: new Set(), chg: new Set(), ai: new Set(), cat: new Set(), rule: new Set(), dir: new Set() },
    idFilter: null, // {label, ids:Set}
    sort: { key: "severity", dir: 1 },
    group: !!store.get("ecomsec.group", false),
    page: 0,
    pageSize: store.get("ecomsec.pageSize", 100),
    selected: new Set(),
    facetMore: {},
    facetsOpen: false,
    lastList: [],
    drawerId: null,
    drawerExtra: null,
    histSel: null,
    histDetail: null,
    hideDone: !!store.get("ecomsec.recs.hideDone", false),
    flashRec: null,
  };
  const findById = (id) => (S.report ? S.report.findings.find((f) => f.id === id) : null);
  const newIds = () => new Set(S.diff && S.diff.available ? S.diff.diff.new_findings.map((f) => f.id) : []);

  // ================================================================ theme & nav
  const root = document.documentElement;
  const mqDark = window.matchMedia ? matchMedia("(prefers-color-scheme: dark)") : null;
  const effectiveTheme = () => root.getAttribute("data-theme") || (mqDark && mqDark.matches ? "dark" : "light");
  function setTheme(t) {
    if (t === "light" || t === "dark") {
      root.setAttribute("data-theme", t);
      store.raw("ecomsec-theme", t);
    } else {
      root.removeAttribute("data-theme");
      store.raw("ecomsec-theme", null);
    }
    $$("[data-action='theme-set']").forEach((b) => b.setAttribute("aria-pressed", String((b.dataset.theme || "") === (root.getAttribute("data-theme") || ""))));
  }
  const toggleTheme = () => {
    setTheme(effectiveTheme() === "dark" ? "light" : "dark");
    toast(effectiveTheme() === "dark" ? "Dunkles Design aktiviert" : "Helles Design aktiviert");
  };
  function setNavCollapsed(on) {
    if (on) root.setAttribute("data-nav", "collapsed");
    else root.removeAttribute("data-nav");
    store.raw("ecomsec-nav-collapsed", on ? "1" : "0");
    $("#navCollapse").setAttribute("aria-label", on ? "Seitenleiste ausklappen" : "Seitenleiste einklappen");
  }
  function setMobileNav(open) {
    $("#sidebar").classList.toggle("open", open);
    $("#navScrim").hidden = !open;
    $("#navOpen").setAttribute("aria-expanded", String(open));
    if (open) {
      const a = $("#nav a[aria-current='page']") || $("#nav a");
      a.focus();
    }
  }

  // ================================================================ toasts
  function toast(msg, kind = "info", action) {
    const el = document.createElement("div");
    el.className = `toast t-${kind}`;
    const ic = kind === "ok" ? "ok" : kind === "err" ? "crit" : "info";
    el.innerHTML = `${icon(ic)}<span></span>${action ? `<button type="button" data-t="act"></button>` : ""}<button type="button" data-t="close" aria-label="Meldung schließen">${icon("x", "icon-sm")}</button>`;
    el.querySelector("span").textContent = msg;
    const remove = () => {
      el.remove();
    };
    if (action) {
      const b = el.querySelector("[data-t='act']");
      b.textContent = action.label;
      b.onclick = () => {
        remove();
        action.fn();
      };
    }
    el.querySelector("[data-t='close']").onclick = remove;
    $("#toasts").appendChild(el);
    setTimeout(remove, kind === "err" ? 9000 : action ? 7000 : 4000);
  }
  const announce = (msg) => {
    const a = $("#announcer");
    a.textContent = "";
    setTimeout(() => (a.textContent = msg), 30);
  };

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
      } catch (e2) { /* ignore */ }
      ta.remove();
    }
    toast("In die Zwischenablage kopiert", "ok");
  }

  // ================================================================ modal
  let modalState = null;
  function openModal({ title, body, confirm, confirmClass = "btn-primary", cancel = "Abbrechen", onConfirm }) {
    const wrap = $("#modal");
    const box = $(".modal", wrap);
    modalState = { onConfirm, lastFocus: document.activeElement };
    box.innerHTML = `<div class="modal-head"><h2 id="modalTitle">${esc(title)}</h2><button type="button" class="icon-btn" data-modal="cancel" aria-label="Schließen">${icon("x")}</button></div>
      <div class="modal-body">${body}</div>
      <div class="modal-foot">${confirm ? `<button type="button" class="btn" data-modal="cancel">${esc(cancel)}</button><button type="button" class="btn ${confirmClass}" data-modal="confirm">${esc(confirm)}</button>` : `<button type="button" class="btn btn-primary" data-modal="cancel">Schließen</button>`}</div>`;
    wrap.hidden = false;
    const first = $("textarea, input, [data-modal='confirm']", box) || $("[data-modal='cancel']", box);
    setTimeout(() => first.focus(), 20);
  }
  function closeModal() {
    const wrap = $("#modal");
    if (wrap.hidden) return;
    wrap.hidden = true;
    const lf = modalState && modalState.lastFocus;
    modalState = null;
    if (lf && document.contains(lf)) lf.focus();
  }
  async function confirmModal(btn) {
    if (!modalState || !modalState.onConfirm) return closeModal();
    btn.disabled = true;
    btn.textContent = "Bitte warten …";
    try {
      const keep = await modalState.onConfirm($(".modal"));
      if (keep !== false) closeModal();
    } catch (e) {
      toast(e.message, "err");
      btn.disabled = false;
      btn.textContent = "Erneut versuchen";
    }
  }
  function trapFocus(e, container) {
    const items = $$("button:not([disabled]), [href], input, textarea, select, [tabindex]:not([tabindex='-1'])", container).filter((x) => x.offsetParent !== null);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  // ================================================================ data loading
  async function loadReport() {
    try {
      S.report = await api("/api/report");
      S.reportState = "ok";
      S.reportError = null;
    } catch (e) {
      if (e.status === 404) {
        S.report = null;
        S.reportState = "empty";
      } else {
        S.reportState = "error";
        S.reportError = e;
      }
    }
  }
  async function loadDiff() {
    try {
      S.diff = await api("/api/diff");
    } catch (e) {
      S.diff = { available: false, reason: e.message, error: true };
    }
  }
  async function loadHistory() {
    try {
      S.history = await api("/api/history");
    } catch (e) {
      S.history = [];
    }
  }
  async function loadArchive() {
    try {
      const a = await api("/api/archive");
      S.archive = new Set(a.reports || []);
    } catch (e) {
      S.archive = new Set();
    }
  }
  async function loadAudit() {
    try {
      S.audit = await api("/api/audit");
      S.auditState = "ok";
    } catch (e) {
      S.audit = null;
      S.auditState = e.status === 404 ? "empty" : "error";
    }
  }
  async function loadAll() {
    if (S.reportState === "error") {
      S.reportState = "loading";
      renderView();
    }
    await Promise.all([loadReport(), loadDiff(), loadHistory(), loadArchive(), loadAudit()]);
    pruneSelection();
    renderAll();
  }
  function pruneSelection() {
    if (!S.report) {
      S.selected.clear();
      return;
    }
    const ids = new Set(S.report.findings.map((f) => f.id));
    for (const id of S.selected) if (!ids.has(id)) S.selected.delete(id);
  }

  // ================================================================ scan
  let pollTimer = 0;
  const schedulePoll = (ms) => {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(poll, ms);
  };
  function scanRequestBody() {
    const o = store.get("ecomsec.scanOptions", null);
    if (!o) return {};
    const body = {};
    if (typeof o.online === "boolean") body.online = o.online;
    if (typeof o.skip_remote === "boolean") body.skip_remote = o.skip_remote;
    if (typeof o.reference_date === "string") body.reference_date = o.reference_date;
    if (typeof o.time_budget === "string") body.time_budget = o.time_budget;
    return body;
  }
  async function startScan() {
    if (S.status && S.status.running) return;
    try {
      await api("/api/scan", { method: "POST", body: scanRequestBody() });
      S.status = Object.assign({}, S.status || {}, { running: true, done: 0, total: 0, error: null });
      renderScanState();
      renderView();
      announce("Scan gestartet");
      schedulePoll(400);
    } catch (e) {
      if (e.status === 409) {
        toast("Es läuft bereits ein Scan.");
        schedulePoll(300);
      } else toast(`Scan konnte nicht gestartet werden: ${e.message}`, "err");
    }
  }
  async function poll() {
    try {
      const was = S.status && S.status.running;
      const s = await api("/api/status");
      S.status = s;
      renderScanState();
      if (s.running) schedulePoll(800);
      else if (was) await onScanFinished(s);
    } catch (e) {
      schedulePoll(3000);
    }
  }
  async function onScanFinished(s) {
    await loadAll();
    if (s.error) {
      toast(`Scan fehlgeschlagen: ${s.error}`, "err", { label: "Erneut starten", fn: startScan });
      return;
    }
    const r = S.report;
    if (r) {
      const msg = r.summary.complete
        ? `Scan abgeschlossen: ${plural(r.summary.critical, "kritischer Befund", "kritische Befunde")}, ${plural(r.summary.warning, "Warnung", "Warnungen")}`
        : "Zeitbudget erreicht – Scan unvollständig, beim nächsten Start wird fortgesetzt.";
      toast(msg, r.summary.complete ? "ok" : "info");
      announce(msg);
    }
  }
  function renderScanState() {
    const s = S.status || {};
    const btn = $("#scanBtn");
    const bar = $("#scanProgress");
    const running = !!s.running;
    btn.classList.toggle("running", running);
    btn.disabled = running;
    btn.setAttribute("aria-busy", String(running));
    const pct = s.total ? Math.min(100, Math.round((100 * s.done) / s.total)) : 0;
    $(".scan-label", btn).textContent = running ? (s.total ? `${pct} %` : "Scan läuft …") : "Scan starten";
    btn.title = running && s.total ? `${fmtNum(s.done)} von ${fmtNum(s.total)} Dateien geprüft` : "Neuen Scan starten";
    bar.hidden = !running;
    bar.classList.toggle("indeterminate", running && !s.total);
    bar.setAttribute("aria-valuenow", String(pct));
    bar.firstElementChild.style.width = s.total ? `${pct}%` : "";
    $$(".scan-inline").forEach((el) => (el.textContent = running ? (s.total ? `${fmtNum(s.done)} von ${fmtNum(s.total)} Dateien (${pct} %)` : "Dateien werden gezählt …") : ""));
  }

  // ================================================================ routing
  function parseHash() {
    const m = location.hash.match(/^#\/([a-z]+)(?:\/([^?#]+))?/);
    return { view: m ? m[1] : "", arg: m && m[2] ? decodeURIComponent(m[2]) : null };
  }
  function navigate(view) {
    if (location.hash === `#/${view}`) route();
    else location.hash = `#/${view}`;
  }
  let firstRoute = true;
  function route() {
    const { view, arg } = parseHash();
    const next = VIEWS[view] ? view : "overview";
    const changed = next !== S.view || firstRoute;
    S.view = next;
    $$(".view").forEach((v) => (v.hidden = v.dataset.view !== next));
    $$("#nav a").forEach((a) => {
      if (a.dataset.view === next) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    document.title = `${VIEWS[next]} · ecomsec`;
    setMobileNav(false);
    renderView();
    if (next === "findings" && arg) openDrawer(arg);
    else if (changed && S.drawerId && next !== "findings") closeDrawer(true);
    if (changed && !firstRoute) {
      window.scrollTo(0, 0);
      $("#main").focus({ preventScroll: true });
    }
    firstRoute = false;
  }

  // ================================================================ render: shell
  const displayTarget = (p) => (p.target ? p.target.replace(/^https?:\/\//, "").replace(/\/$/, "") : p.root || "");
  function renderShell() {
    const r = S.report;
    const name = $("#targetName");
    const meta = $("#targetMeta");
    const target = $("#target");
    if (r) {
      name.textContent = `${r.platform.name}${r.platform.version ? " " + r.platform.version : ""}`;
      meta.textContent = `${displayTarget(r.platform)} · Scan ${fmtRel(r.generated_at)}${r.summary.complete ? "" : " · unvollständig"}`;
      target.title = `${r.platform.root || r.platform.target || ""}\nLetzter Scan: ${fmtDateTime(r.generated_at)}`;
    } else {
      name.textContent = "ecomsec";
      meta.textContent = S.status ? S.status.target : S.reportState === "loading" ? "Lade Daten …" : "";
    }
    const chip = $("#scoreChip");
    if (r && r.score != null && r.grade) {
      chip.hidden = false;
      chip.innerHTML = `${gradeBadge(r.grade)}<span class="score-num">${r.score}</span><small>/100</small>`;
      chip.setAttribute("aria-label", `Sicherheitsniveau ${r.score} von 100, Note ${r.grade} (${GRADE[r.grade] || ""})`);
      chip.title = `Sicherheitsniveau ${r.score}/100 · Note ${r.grade} (${GRADE[r.grade] || ""})`;
    } else chip.hidden = true;
    // navigation badges
    const badge = (key, text, cls, title) => {
      const b = $(`[data-badge='${key}']`);
      if (!b) return;
      b.hidden = !text;
      b.textContent = text || "";
      b.className = `nav-badge ${cls || ""}`;
      b.title = title || "";
    };
    if (r) {
      const open = r.summary.critical + r.summary.warning;
      badge("findings", open ? String(open) : "", r.summary.critical ? "crit" : "warn", `${r.summary.critical} kritisch, ${r.summary.warning} Warnungen`);
      const crit = r.integrity.filter((i) => i.status === "critical").length;
      const warn = r.integrity.filter((i) => i.status === "warning").length;
      badge("integrity", crit ? String(crit) : warn ? String(warn) : "", crit ? "crit" : "warn", crit ? `${crit} kritische Prüfungen` : `${warn} zu prüfen`);
      const recOpen = openRecs().length;
      badge("recommendations", recOpen ? String(recOpen) : "", "", `${recOpen} offene Empfehlungen`);
    } else ["findings", "integrity", "recommendations"].forEach((k) => badge(k, ""));
    badge("audit", auditStale() ? "!" : "", "warn", "KI-Bewertung bezieht sich auf einen älteren Scan");
  }
  const auditStale = () => !!(S.audit && S.report && !sameTime(S.audit.report_generated_at, S.report.generated_at));

  function renderAll() {
    renderShell();
    renderScanState();
    renderView();
    if (S.drawerId) {
      if (findById(S.drawerId)) renderDrawer();
      else closeDrawer(true);
    }
  }
  function renderView() {
    const fn = { overview: renderOverview, findings: renderFindings, integrity: renderIntegrity, recommendations: renderRecs, history: renderHistory, audit: renderAudit, settings: renderSettings }[S.view];
    fn();
  }

  // ---------------------------------------------------------------- shared states
  const pageHead = (view, desc, actions = "", srOnly = false) =>
    `<div class="page-head${srOnly ? " sr-only" : ""}"><div><h1 id="h-${view}">${esc(VIEWS[view])}</h1>${desc ? `<p>${desc}</p>` : ""}</div>${actions ? `<div class="page-actions">${actions}</div>` : ""}</div>`;
  function stateBlock() {
    const running = S.status && S.status.running;
    if (S.reportState === "loading" || (!S.report && running)) {
      return `<div class="card" aria-busy="true">${running ? `<div class="row" style="margin-bottom:12px"><b>Scan läuft</b><span class="muted scan-inline"></span></div>` : `<span class="sr-only">Lade Daten …</span>`}
        <div class="skel skel-line" style="width:40%"></div><div class="skel skel-line" style="width:70%"></div><div class="skel skel-block" style="margin-top:16px"></div>
        <div class="grid grid-4" style="margin-top:16px"><div class="skel skel-block" style="height:80px"></div><div class="skel skel-block" style="height:80px"></div><div class="skel skel-block" style="height:80px"></div><div class="skel skel-block" style="height:80px"></div></div></div>`;
    }
    if (S.reportState === "error") {
      return `<div class="card empty" role="alert"><div class="empty-icon ic-critical">${icon("crit")}</div><h2>Daten konnten nicht geladen werden</h2><p>${esc(S.reportError ? S.reportError.message : "Unbekannter Fehler")}</p><button type="button" class="btn" data-action="retry">${icon("scan")}Erneut versuchen</button></div>`;
    }
    if (!S.report) {
      return `<div class="card empty"><div class="empty-icon">${icon("scan")}</div><h2>Noch kein Scan vorhanden</h2><p>Der erste Scan prüft die Installation read-only auf Webshells, manipulierte Dateien, Exploit-Spuren und den Patch-Status. Je nach Größe dauert er Sekunden bis wenige Minuten.</p><button type="button" class="btn btn-primary" data-action="scan">${icon("scan")}Scan starten</button></div>`;
    }
    return "";
  }

  // ================================================================ view: overview
  function historyPrev() {
    const h = S.history || [];
    const r = S.report;
    if (!r || !h.length) return null;
    const t = new Date(r.generated_at).getTime();
    const before = h.filter((e) => new Date(e.generated_at).getTime() < t);
    return before.length ? before[before.length - 1] : null;
  }
  /** History entries; risk acceptance re-scores the current report without a
   *  new history entry, so the matching run shows the current values. */
  function histEntries() {
    const r = S.report;
    return (S.history || []).map((e) => (r && sameTime(e.generated_at, r.generated_at)
      ? Object.assign({}, e, { verdict: r.verdict, score: r.score != null ? r.score : e.score, grade: r.grade || e.grade, critical: r.summary.critical, warning: r.summary.warning, info: r.summary.info, accepted: r.summary.accepted })
      : e));
  }
  function trendPoints(limit) {
    const pts = histEntries().filter((e) => e.score != null);
    return limit ? pts.slice(-limit) : pts;
  }
  function renderOverview() {
    const el = $("#view-overview");
    const st = stateBlock();
    if (st) {
      el.innerHTML = pageHead("overview", "", "", true) + st;
      renderScanState();
      return;
    }
    const r = S.report;
    const v = VERDICT[r.verdict];
    const scoreKnown = r.score != null && r.grade;
    const C = 2 * Math.PI * 64;
    const off = scoreKnown ? C * (1 - r.score / 100) : C;
    const drivers = (r.score_drivers || []).slice(0, 4);
    const maxPts = Math.max(1, ...drivers.map((d) => d.points));
    const prev = historyPrev();
    const kpi = (key, label, value, ic, st2, prevVal, preset, upIsBad = true) => {
      let delta = `<span class="kpi-delta">${prev ? "unverändert seit letztem Scan" : "erster Scan"}</span>`;
      if (prev && prevVal != null && value !== prevVal) {
        const d = value - prevVal;
        const bad = upIsBad ? d > 0 : false;
        const good = upIsBad ? d < 0 : false;
        delta = `<span class="kpi-delta ${bad ? "bad" : good ? "good" : ""}">${icon(d > 0 ? "trend-up" : "trend-down")}${signed(d)} seit letztem Scan</span>`;
      }
      return `<button type="button" class="card kpi" data-action="goto-findings" data-preset="${preset}" aria-label="${esc(label)}: ${value} – Befunde anzeigen">
        <span class="kpi-top"><span class="kpi-icon st-${st2}">${icon(ic)}</span>${esc(label)}</span>
        <span class="kpi-value">${fmtNum(value)}</span>${delta}</button>`;
    };
    el.innerHTML = `${pageHead("overview", "", "", true)}
      <div class="stack">
        <section class="card hero v-${r.verdict}" aria-label="Gesamtergebnis">
          <div class="verdict">
            <div class="lamp" role="img" aria-label="Ampel: ${v.lampLabel}"><i class="r ${v.lamp === "r" ? "on" : ""}"></i><i class="y ${v.lamp === "y" ? "on" : ""}"></i><i class="g ${v.lamp === "g" ? "on" : ""}"></i></div>
            <div>
              <h2 class="verdict-title">${esc(v.title)}</h2>
              <p>${esc(v.text)}</p>
              <div class="facts">
                <span>${icon("file", "icon-sm")}${plural(r.summary.files_scanned, "Datei", "Dateien")} geprüft</span>
                <span>${icon("history", "icon-sm")}${fmtDuration(r.summary.duration_ms)}</span>
                <span>${icon("layers", "icon-sm")}Referenzdatum ${fmtDate(r.reference_date)}</span>
                ${r.summary.complete ? "" : `<span class="ic-warning">${icon("warn", "icon-sm")}Scan unvollständig (Zeitbudget)</span>`}
              </div>
            </div>
          </div>
          <div class="ring-wrap">
            <div class="ring" role="img" aria-label="${scoreKnown ? `Sicherheitsniveau ${r.score} von 100, Note ${r.grade}` : "Sicherheitsniveau unbekannt"}">
              <svg viewBox="0 0 148 148" aria-hidden="true"><circle class="track" cx="74" cy="74" r="64"/><circle class="val ${scoreKnown ? gradeTone(r.grade) : ""}" cx="74" cy="74" r="64" stroke-dasharray="${C.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}"/></svg>
              <div class="ring-center"><b>${scoreKnown ? r.score : "–"}</b><small>von 100</small></div>
            </div>
            <div class="ring-caption">${scoreKnown ? `${gradeBadge(r.grade)}<span>Note ${esc(r.grade)} · ${esc(GRADE[r.grade] || "")}</span>` : "kein Score"}</div>
          </div>
          <div class="drivers">
            <h3>Was den Score senkt</h3>
            ${drivers.length ? drivers.map((d) => `<div class="driver"><span>${esc(d.label)}</span><b>−${d.points}</b><span class="bar" aria-hidden="true"><i style="width:${Math.max(4, (100 * d.points) / maxPts)}%"></i></span></div>`).join("") : `<p class="muted">Keine Abzüge – alle bewerteten Prüfungen ohne Befund.</p>`}
            ${(r.score_drivers || []).length > 4 ? `<button type="button" class="link-btn" data-action="show-drivers">Alle ${r.score_drivers.length} Faktoren${icon("right", "icon-sm")}</button>` : ""}
          </div>
        </section>
        <div class="grid grid-4">
          ${kpi("critical", "Kritisch", r.summary.critical, "crit", "critical", prev && prev.critical, "sev:critical")}
          ${kpi("warning", "Warnungen", r.summary.warning, "warn", "warning", prev && prev.warning, "sev:warning")}
          ${kpi("info", "Hinweise", r.summary.info, "info", "info", prev && prev.info, "sev:info")}
          ${kpi("accepted", "Unbedenklich", r.summary.accepted, "accepted", "ok", prev && prev.accepted, "state:accepted", false)}
        </div>
        ${advisoryStrip(r)}
        <div class="grid grid-main-side">
          <div class="stack">${diffCard()}${trendCard()}</div>
          <div class="stack">${nextStepsCard()}${auditMiniCard()}</div>
        </div>
      </div>`;
    drawCharts(el);
  }
  function advisoryStrip(r) {
    const adv = r.advisories || [];
    const baseline = r.integrity.find((i) => i.key === "integrity.baseline");
    const chips = adv.length
      ? adv.slice(0, 6).map((a) => {
          const p = PATCH[a.state] || PATCH.unknown;
          return `<a class="chip" href="#/integrity" title="${esc(a.advisory.title)} – ${esc(p.label)}"><span class="dot dot-${p.st}"></span><b>${esc(a.advisory.id)}</b>&nbsp;${esc(p.label)}</a>`;
        }).join("") + (adv.length > 6 ? `<a class="chip" href="#/integrity">+${adv.length - 6} weitere</a>` : "")
      : `<span class="muted small">Für diese Plattform sind keine Advisories hinterlegt.</span>`;
    const lim = (r.limitations || []).length;
    return `<section class="card strip" aria-label="Schwachstellen und Prüfumfang">
      <span class="strip-label">${icon("shield")}Bekannte Schwachstellen</span>${chips}
      <span class="sep" aria-hidden="true"></span>
      ${baseline ? `<a class="chip" href="#/integrity"><span class="dot dot-${baseline.status}"></span>Baseline: ${esc(baseline.value)}</a>` : ""}
      ${lim ? `<a class="chip" href="#/settings"><span class="dot dot-warning"></span>${plural(lim, "Einschränkung", "Einschränkungen")}</a>` : `<span class="chip" aria-disabled="true"><span class="dot dot-ok"></span>Alle Prüfungen ausgeführt</span>`}
    </section>`;
  }
  function diffCard() {
    const head = (sub) => `<div class="card-head"><h2>${icon("diff")}Änderungen seit letztem Scan</h2>${sub ? `<span class="sub">${sub}</span>` : ""}</div>`;
    if (!S.diff) return `<section class="card">${head("")}<div class="skel skel-line"></div><div class="skel skel-line" style="width:60%"></div></section>`;
    if (!S.diff.available) return `<section class="card">${head("")}<div class="empty compact"><p>${esc(S.diff.reason || "Kein Vergleich verfügbar.")}</p></div></section>`;
    const d = S.diff.diff;
    const integ = d.integrity_changes.filter((c) => c.significant);
    const worstNew = d.new_findings.reduce((m, f) => (SEV[f.severity].rank < SEV[m].rank ? f.severity : m), "info");
    const box = (n, label, cls) => `<div class="diff-count ${n ? cls : ""}"><b>${fmtNum(n)}</b><span>${label}</span></div>`;
    const items = [];
    d.new_advisories.forEach((a) => items.push(`<li>${sevBadge(a.severity)}<div class="grow"><div class="title">${esc(a.id)} – ${esc(a.title)}</div><div class="sub">neu verwundbar${a.fixed_in && a.fixed_in.length ? ` · behoben in ${esc(a.fixed_in.join(", "))}` : ""}</div></div></li>`));
    d.new_findings.slice(0, 6).forEach((f) => items.push(`<li><button type="button" class="item" data-action="open-finding" data-id="${esc(f.id)}">${sevBadge(f.severity)}<span class="grow"><span class="title">${esc(f.title)}</span><span class="sub mono" style="display:block">${esc(f.subject)}</span></span></button></li>`));
    d.changed_severity.slice(0, 3).forEach((c) => items.push(`<li>${sevBadge(c.after)}<div class="grow"><div class="title">${esc(c.finding.title)}</div><div class="sub">${esc(c.finding.subject)} · ${SEV[c.before].label} → ${SEV[c.after].label}</div></div></li>`));
    integ.slice(0, 4).forEach((c) => {
      const s = c.status_after || "unknown";
      const change = c.change === "added" ? "neu" : c.change === "removed" ? "entfernt" : `${ST[c.status_before || "unknown"].label} → ${ST[s].label}`;
      items.push(`<li>${stBadge(s)}<div class="grow"><div class="title">${esc(c.section)} · ${esc(c.label)}</div><div class="sub">${esc(change)}${c.value_after ? ` · ${esc(c.value_after)}` : ""}</div></div></li>`);
    });
    d.resolved_findings.slice(0, 3).forEach((f) => items.push(`<li><span class="badge st-ok">${icon("check")}Behoben</span><div class="grow"><div class="title muted">${esc(f.title)}</div><div class="sub mono">${esc(f.subject)}</div></div></li>`));
    const more = d.new_findings.length > 6 ? `<button type="button" class="link-btn" data-action="goto-findings" data-preset="new">Alle ${d.new_findings.length} neuen Befunde anzeigen${icon("right", "icon-sm")}</button>` : "";
    return `<section class="card">${head(`${fmtShort(d.before_generated_at)} → ${fmtShort(d.after_generated_at)}`)}
      <div class="diff-counts">
        ${box(d.new_findings.length, "neue Befunde", worstNew === "critical" ? "c-crit" : "c-warn")}
        ${box(d.resolved_findings.length, "nicht mehr gefunden", "c-good")}
        ${box(d.changed_severity.length, "Schweregrad geändert", "c-warn")}
        ${box(d.new_advisories.length, "neu verwundbar", "c-crit")}
        ${box(integ.length, "Integrität geändert", integ.some((c) => c.status_after === "critical") ? "c-crit" : "c-warn")}
      </div>
      ${items.length ? `<ul class="list">${items.join("")}</ul>${more}` : `<p class="muted" style="margin:0">Keine Änderungen seit dem letzten Scan.</p>`}
    </section>`;
  }
  function trendCard() {
    const pts = trendPoints(30);
    if (!pts.length) return "";
    const last = pts[pts.length - 1];
    const prev = pts.length > 1 ? pts[pts.length - 2] : null;
    const d = prev ? last.score - prev.score : 0;
    return `<section class="card"><div class="card-head"><h2>${icon("history")}Sicherheitsniveau</h2><span class="sub">${pts.length === 1 ? "erster Scan" : `letzte ${pts.length} Scans`}</span></div>
      <div class="trend" data-chart="30" data-height="170"></div>
      <div class="row small muted" style="margin-top:8px"><span>aktuell <b class="tnum" style="color:var(--text)">${last.score}/100</b> (Note ${esc(last.grade || "–")})${prev ? ` · ${signed(d)} Punkte seit dem vorherigen Scan` : ""}</span><span class="spacer"></span><a href="#/history">Als Tabelle${icon("right", "icon-sm")}</a></div>
    </section>`;
  }
  function openRecs() {
    if (!S.report) return [];
    const done = doneSet();
    const out = [];
    S.report.recommendations.forEach((g) => g.items.forEach((it) => {
      if (!done.has(recKey(g, it))) out.push({ g, it });
    }));
    out.sort((a, b) => GROUP_ORDER.indexOf(a.g.kind) - GROUP_ORDER.indexOf(b.g.kind) || a.it.priority - b.it.priority);
    return out;
  }
  function nextStepsCard() {
    const recs = openRecs();
    const top = recs.slice(0, 3);
    return `<section class="card"><div class="card-head"><h2>${icon("checklist")}Nächste Schritte</h2><span class="sub">${recs.length} offen</span></div>
      ${top.length ? `<ul class="list">${top.map(({ g, it }) => `<li><button type="button" class="item" data-action="goto-rec" data-key="${esc(recKey(g, it))}"><span class="prio prio-${Math.min(3, it.priority)}">P${it.priority}</span><span class="grow"><span class="title">${esc(it.title)}</span><span class="sub" style="display:block">${esc(g.label)}${it.related && it.related.length ? ` · ${plural(it.related.length, "Befund", "Befunde")}` : ""}</span></span></button></li>`).join("")}</ul>
        <a class="link-btn" href="#/recommendations" style="margin-top:8px">Alle Empfehlungen${icon("right", "icon-sm")}</a>`
      : `<div class="note n-ok">${icon("ok")}<span>Alle Empfehlungen sind als erledigt markiert.</span></div>`}
    </section>`;
  }
  function auditMiniCard() {
    const a = S.audit;
    if (!a) return "";
    const as = ASSESS[a.overall_assessment] || ["unknown", a.overall_assessment || "keine Gesamtbewertung"];
    return `<section class="card"><div class="card-head"><h2>${icon("ai")}KI-Audit</h2><span class="sub">${fmtShort(a.finished)}</span></div>
      <div class="row" style="margin-bottom:8px">${stBadge(as[0] === "critical" || as[0] === "warning" || as[0] === "ok" ? as[0] : "unknown", as[1])}${a.confidence != null ? `<span class="muted small">Konfidenz ${Math.round(a.confidence * 100)} %</span>` : ""}</div>
      ${auditStale() ? `<div class="note n-warn" style="margin-bottom:8px">${icon("warn")}<span>Bezieht sich auf einen älteren Scan.</span></div>` : ""}
      <p class="muted small" style="margin:0 0 8px">${esc((a.summary || "").slice(0, 220))}${(a.summary || "").length > 220 ? " …" : ""}</p>
      <a class="link-btn" href="#/audit">Zum KI-Audit${icon("right", "icon-sm")}</a></section>`;
  }

  // ---------------------------------------------------------------- chart
  const observed = new WeakSet();
  const resizeObs = window.ResizeObserver
    ? new ResizeObserver((entries) => entries.forEach((e) => {
        if (document.contains(e.target)) drawTrend(e.target);
        else resizeObs.unobserve(e.target);
      }))
    : null;
  function drawCharts(container) {
    $$(".trend[data-chart]", container).forEach((el) => {
      drawTrend(el);
      if (resizeObs && !observed.has(el)) {
        resizeObs.observe(el);
        observed.add(el);
      }
    });
  }
  /** Single-series line chart of the posture score (0–100) with grade
   *  thresholds as hairline gridlines, crosshair tooltip and keyboard access. */
  function drawTrend(el) {
    const pts = trendPoints(Number(el.dataset.chart) || 30);
    const W = Math.max(260, Math.round(el.clientWidth || 600));
    if (el._w === W && el._n === pts.length && el._last === (pts.length && pts[pts.length - 1].generated_at)) return;
    el._w = W;
    el._n = pts.length;
    el._last = pts.length && pts[pts.length - 1].generated_at;
    const H = Number(el.dataset.height) || 170;
    const L = 46, R = 44, T = 10, B = 24;
    const iw = W - L - R, ih = H - T - B;
    const x = (i) => L + (pts.length === 1 ? iw / 2 : (i * iw) / (pts.length - 1));
    const y = (v) => T + ih - (v / 100) * ih;
    // Gridlines at the grade thresholds (A 90, B 75, C 60, D 40).
    const ticks = [[0, "0"], [40, "D 40"], [60, "C 60"], [75, "B 75"], [90, "A 90"]];
    const grid = ticks.map(([t, lab]) => `<line class="${t === 0 ? "axis" : "grid-line"}" x1="${L}" x2="${W - R}" y1="${y(t)}" y2="${y(t)}"/><text class="tick" x="${L - 6}" y="${y(t) + 4}" text-anchor="end">${lab}</text>`).join("");
    const line = pts.map((e, i) => `${x(i).toFixed(1)},${y(e.score).toFixed(1)}`).join(" L");
    const area = pts.length > 1 ? `<path class="area" d="M${x(0).toFixed(1)},${y(0)} L${line} L${x(pts.length - 1).toFixed(1)},${y(0)} Z"/>` : "";
    const path = pts.length > 1 ? `<path class="line" d="M${line}"/>` : "";
    const xl = [];
    if (pts.length) {
      xl.push(`<text class="tick" x="${x(0)}" y="${H - 6}" text-anchor="${pts.length === 1 ? "middle" : "start"}">${fmtDayMonth(pts[0].generated_at)}</text>`);
      if (pts.length > 2 && iw > 360) {
        const m = Math.floor((pts.length - 1) / 2);
        xl.push(`<text class="tick" x="${x(m)}" y="${H - 6}" text-anchor="middle">${fmtDayMonth(pts[m].generated_at)}</text>`);
      }
      if (pts.length > 1) xl.push(`<text class="tick" x="${x(pts.length - 1)}" y="${H - 6}" text-anchor="end">${fmtDayMonth(pts[pts.length - 1].generated_at)}</text>`);
    }
    const last = pts[pts.length - 1];
    const endDot = last ? `<circle class="dot" cx="${x(pts.length - 1)}" cy="${y(last.score)}" r="4.5"/><text class="end-label" x="${x(pts.length - 1) + 9}" y="${y(last.score) + 4}">${last.score}</text>` : "";
    const lo = pts.length ? Math.min(...pts.map((p) => p.score)) : 0;
    const hi = pts.length ? Math.max(...pts.map((p) => p.score)) : 0;
    el.setAttribute("tabindex", "0");
    el.setAttribute("role", "img");
    el.setAttribute("aria-label", pts.length ? `Sicherheitsniveau der letzten ${pts.length} Scans: aktuell ${last.score} von 100, Minimum ${lo}, Maximum ${hi}. Pfeiltasten zeigen einzelne Scans.` : "Noch kein Verlauf");
    el.innerHTML = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" aria-hidden="true">${grid}${xl.join("")}${area}${path}
      <line class="cross" x1="0" x2="0" y1="${T}" y2="${T + ih}" visibility="hidden"/><circle class="dot hl" r="4.5" cx="0" cy="0" visibility="hidden"/>
      ${endDot}<rect class="overlay" x="${L}" y="${T}" width="${iw}" height="${ih}"/></svg><div class="tip" hidden></div>`;
    const svg = $("svg", el);
    const cross = $(".cross", svg);
    const hl = $(".hl", svg);
    const tip = $(".tip", el);
    const show = (i) => {
      if (!pts.length) return;
      i = Math.max(0, Math.min(pts.length - 1, i));
      el._idx = i;
      const p = pts[i];
      const px = x(i), py = y(p.score);
      cross.setAttribute("x1", px);
      cross.setAttribute("x2", px);
      cross.setAttribute("visibility", "visible");
      hl.setAttribute("cx", px);
      hl.setAttribute("cy", py);
      hl.setAttribute("visibility", "visible");
      tip.hidden = false;
      tip.innerHTML = `<b>${p.score}<span class="muted" style="font-size:12px;font-weight:500"> / 100 · Note ${esc(p.grade || "–")}</span></b><span class="k"></span>${esc(fmtDateTime(p.generated_at))}<br><span class="muted">${p.critical} kritisch · ${p.warning} Warnungen${p.complete ? "" : " · unvollständig"}</span>`;
      const tx = Math.max(80, Math.min(W - 80, px));
      tip.style.left = `${tx}px`;
      tip.style.top = `${py}px`;
    };
    const hide = () => {
      cross.setAttribute("visibility", "hidden");
      hl.setAttribute("visibility", "hidden");
      tip.hidden = true;
    };
    const ov = $(".overlay", svg);
    ov.addEventListener("pointermove", (e) => {
      const rect = svg.getBoundingClientRect();
      const mx = ((e.clientX - rect.left) * W) / rect.width;
      const i = pts.length === 1 ? 0 : Math.round(((mx - L) / iw) * (pts.length - 1));
      show(i);
    });
    ov.addEventListener("pointerleave", hide);
    el.onfocus = () => show(el._idx != null ? el._idx : pts.length - 1);
    el.onblur = hide;
    el.onkeydown = (e) => {
      if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
        e.preventDefault();
        show((el._idx != null ? el._idx : pts.length - 1) + (e.key === "ArrowLeft" ? -1 : 1));
      } else if (e.key === "Home") show(0);
      else if (e.key === "End") show(pts.length - 1);
    };
  }

  // ================================================================ view: findings
  const dirOf = (f) => f.group || "(ohne Verzeichnis)";
  const FACETS = [
    { key: "state", title: "Status", get: (f) => (f.accepted ? "accepted" : "open"), label: (v) => (v === "open" ? "Offen" : "Unbedenklich"), order: ["open", "accepted"] },
    { key: "sev", title: "Schweregrad", get: (f) => f.severity, label: (v) => SEV[v].label, order: ["critical", "warning", "info"], dot: true },
    { key: "chg", title: "Änderung", get: (f) => (S._newIds.has(f.id) ? "new" : "known"), label: (v) => (v === "new" ? "Neu seit letztem Scan" : "Bereits bekannt"), order: ["new", "known"], showIf: () => S.diff && S.diff.available },
    { key: "ai", title: "KI-Bewertung", get: (f) => (f.review ? f.review.verdict : "none"), label: (v) => (v === "none" ? "ohne KI-Bewertung" : (AI[v] || { label: v }).label), order: ["confirmed", "needs_human", "likely_false_positive", "none"], showIf: () => S.report.findings.some((f) => f.review) },
    { key: "cat", title: "Kategorie", get: (f) => f.category, label: catLabel },
    { key: "rule", title: "Regel", get: (f) => f.rule, label: (v) => v, mono: true },
    { key: "dir", title: "Verzeichnis", get: dirOf, label: (v) => v, mono: true },
  ];
  S._newIds = new Set();
  const hay = new WeakMap();
  const haystack = (f) => {
    let h = hay.get(f);
    if (!h) {
      h = [f.title, f.subject, f.rule, catLabel(f.category), f.id, f.description, f.group, (f.evidence || []).join(" "), f.accepted_reason, f.review && f.review.reasoning].join("\u0001").toLowerCase();
      hay.set(f, h);
    }
    return h;
  };
  function filterFindings(exceptKey) {
    const terms = S.f.q.toLowerCase().split(/\s+/).filter(Boolean);
    const facets = FACETS.filter((fc) => fc.key !== exceptKey && S.f[fc.key].size && (!fc.showIf || fc.showIf()));
    const ids = S.idFilter ? S.idFilter.ids : null;
    return S.report.findings.filter((f) => (!ids || ids.has(f.id)) && facets.every((fc) => S.f[fc.key].has(fc.get(f))) && terms.every((t) => haystack(f).includes(t)));
  }
  const SORTS = {
    severity: (a, b) => SEV[a.severity].rank - SEV[b.severity].rank || a.accepted - b.accepted,
    subject: (a, b) => a.subject.localeCompare(b.subject, "de"),
    category: (a, b) => catLabel(a.category).localeCompare(catLabel(b.category), "de"),
    rule: (a, b) => a.rule.localeCompare(b.rule),
    state: (a, b) => a.accepted - b.accepted || (a.review ? 0 : 1) - (b.review ? 0 : 1),
  };
  function sortedList(list) {
    const cmp = SORTS[S.sort.key] || SORTS.severity;
    const dir = S.sort.dir;
    const out = list.slice().sort((a, b) => dir * cmp(a, b) || SEV[a.severity].rank - SEV[b.severity].rank || a.subject.localeCompare(b.subject, "de"));
    if (S.group) out.sort((a, b) => dirOf(a).localeCompare(dirOf(b), "de") || 0);
    return out;
  }
  function filtersAreDefault() {
    return !S.f.q && !S.idFilter && FACETS.every((fc) => (fc.key === "state" ? S.f.state.size === 1 && S.f.state.has("open") : S.f[fc.key].size === 0));
  }
  function resetFilters() {
    S.f.q = "";
    FACETS.forEach((fc) => S.f[fc.key].clear());
    DEFAULT_STATE_FILTER.forEach((v) => S.f.state.add(v));
    S.idFilter = null;
    S.page = 0;
    const s = $("#fSearch");
    if (s) s.value = "";
  }
  function applyPreset(p) {
    resetFilters();
    const [k, v] = p.split(":");
    if (k === "sev") S.f.sev.add(v);
    else if (k === "state") {
      S.f.state.clear();
      S.f.state.add(v);
    } else if (k === "new") S.f.chg.add("new");
    else if (k === "rule") S.f.rule.add(v);
    else if (k === "dir") S.f.dir.add(v);
    else if (k === "all") S.f.state.clear();
  }

  function renderFindings() {
    const el = $("#view-findings");
    const st = stateBlock();
    if (st) {
      el.innerHTML = pageHead("findings", "Alle Befunde des letzten Scans: filtern, prüfen und als unbedenklich markieren.") + st;
      el._shell = false;
      renderScanState();
      return;
    }
    if (!el._shell) {
      el.innerHTML = `${pageHead("findings", `<span id="fCount"></span>`, `<button type="button" class="btn facet-toggle" data-action="facet-toggle" aria-expanded="false" aria-controls="facets">${icon("filter")}Filter</button>`)}
        <div class="toolbar" role="search">
          <label class="search"><span class="sr-only">Befunde durchsuchen</span>${icon("search")}<input id="fSearch" class="input" type="search" placeholder="Suchen: Pfad, Regel, Titel, Beweis …" autocomplete="off" spellcheck="false"><kbd aria-hidden="true">/</kbd></label>
          <label class="check"><input type="checkbox" id="fGroup">Nach Verzeichnis gruppieren</label>
          <label class="sr-only" for="fSort">Sortierung</label>
          <select id="fSort" class="select" aria-label="Sortierung">
            <option value="severity:1">Schweregrad</option><option value="subject:1">Pfad A–Z</option><option value="category:1">Kategorie</option><option value="rule:1">Regel</option><option value="state:1">Status</option>
          </select>
        </div>
        <div class="findings-layout">
          <aside class="card facets" id="facets" aria-label="Filter"></aside>
          <div class="min0">
            <div class="active-filters" id="fActive"></div>
            <div id="fTable"></div>
            <div id="fBulk"></div>
          </div>
        </div>`;
      el._shell = true;
      const search = $("#fSearch", el);
      search.value = S.f.q;
      search.addEventListener("input", debounce(() => {
        S.f.q = search.value.trim();
        S.page = 0;
        renderFindingsBody();
      }, 120));
      $("#fGroup", el).addEventListener("change", (e) => {
        S.group = e.target.checked;
        store.set("ecomsec.group", S.group);
        S.page = 0;
        renderFindingsBody();
      });
      $("#fSort", el).addEventListener("change", (e) => {
        const [k, d] = e.target.value.split(":");
        S.sort = { key: k, dir: Number(d) };
        renderFindingsBody();
      });
      el.addEventListener("change", onFindingsChange);
      el.addEventListener("click", onFindingsClick);
      el.addEventListener("keydown", onFindingsKey);
    }
    $("#fGroup", el).checked = S.group;
    $("#fSearch", el).value = S.f.q;
    renderFindingsBody();
  }
  function renderFindingsBody() {
    const r = S.report;
    if (!r) return;
    S._newIds = newIds();
    const list = sortedList(filterFindings());
    S.lastList = list;
    const pages = Math.max(1, Math.ceil(list.length / S.pageSize));
    S.page = Math.min(S.page, pages - 1);
    const start = S.page * S.pageSize;
    const slice = list.slice(start, start + S.pageSize);
    $("#fCount").textContent = `${fmtNum(list.length)} von ${plural(r.findings.length, "Befund", "Befunden")} angezeigt · ${fmtNum(r.summary.critical)} kritisch, ${fmtNum(r.summary.warning)} Warnungen offen`;
    const sortSel = $("#fSort");
    if (sortSel) sortSel.value = `${S.sort.key}:${S.sort.dir}`;
    $("#facets").innerHTML = renderFacets();
    $("#facets").classList.toggle("open", S.facetsOpen);
    // active filters
    const chips = [];
    if (S.idFilter) chips.push(`<button type="button" class="chip" data-action="remove-idfilter">${esc(S.idFilter.label)}<span class="x">${icon("x", "icon-sm")}</span><span class="sr-only">Filter entfernen</span></button>`);
    if (S.f.q) chips.push(`<button type="button" class="chip" data-action="remove-search">Suche: „${esc(S.f.q)}“<span class="x">${icon("x", "icon-sm")}</span><span class="sr-only">Filter entfernen</span></button>`);
    FACETS.forEach((fc) => S.f[fc.key].forEach((v) => {
      if (fc.showIf && !fc.showIf()) return;
      chips.push(`<button type="button" class="chip" data-action="remove-filter" data-key="${fc.key}" data-val="${esc(v)}">${esc(fc.title)}: ${esc(fc.label(v))}<span class="x">${icon("x", "icon-sm")}</span><span class="sr-only">Filter entfernen</span></button>`);
    }));
    $("#fActive").innerHTML = chips.join("") + (filtersAreDefault() ? "" : `<button type="button" class="link-btn" data-action="clear-filters">Filter zurücksetzen</button>`);
    // table
    const tbl = $("#fTable");
    if (!list.length) {
      tbl.innerHTML = `<div class="card empty compact"><div class="empty-icon">${icon(r.findings.length ? "filter" : "ok")}</div><h2>${r.findings.length ? "Keine Befunde für diese Filter" : "Keine Befunde"}</h2><p>${r.findings.length ? "Passen Sie Suche oder Filter an." : "Der Scan hat keine Befunde ergeben."}</p>${r.findings.length && !filtersAreDefault() ? `<button type="button" class="btn" data-action="clear-filters">Filter zurücksetzen</button>` : ""}</div>`;
    } else {
      const allSel = slice.every((f) => S.selected.has(f.id));
      const someSel = slice.some((f) => S.selected.has(f.id));
      const th = (key, label, cls = "") => {
        const active = S.sort.key === key;
        return `<th scope="col" class="${cls}"${active ? ` aria-sort="${S.sort.dir === 1 ? "ascending" : "descending"}"` : ""}><button type="button" class="sort" data-sort="${key}">${label}${icon(active && S.sort.dir === -1 ? "up" : "down")}</button></th>`;
      };
      const groupCount = new Map();
      if (S.group) list.forEach((f) => groupCount.set(dirOf(f), (groupCount.get(dirOf(f)) || 0) + 1));
      let lastDir = null;
      const rows = [];
      slice.forEach((f) => {
        if (S.group && dirOf(f) !== lastDir) {
          lastDir = dirOf(f);
          const openInDir = r.findings.filter((x) => !x.accepted && x.group && x.group === f.group).length;
          rows.push(`<tr class="group-row"><th colspan="4" scope="colgroup"><div class="row">${icon("folder", "icon-sm")}<span class="mono">${esc(lastDir)}</span><span class="muted">(${groupCount.get(lastDir)})</span><span class="spacer"></span>${f.group && openInDir ? `<button type="button" class="btn btn-sm btn-ghost" data-action="accept-dir" data-dir="${esc(f.group)}">${icon("accepted")}Verzeichnis unbedenklich</button>` : ""}</div></th></tr>`);
        }
        const sel = S.selected.has(f.id);
        rows.push(`<tr class="row-click${sel ? " is-selected" : ""}${f.accepted ? " is-accepted" : ""}${S.drawerId === f.id ? " is-active" : ""}" data-id="${esc(f.id)}" tabindex="0" aria-label="${esc(SEV[f.severity].label)}: ${esc(f.title)} – ${esc(f.subject)}">
          <td class="col-check"><input type="checkbox" data-sel="${esc(f.id)}" ${sel ? "checked" : ""} aria-label="Auswählen: ${esc(f.subject)}"></td>
          <td class="col-sev">${sevBadge(f.severity)}</td>
          <td><div class="sev-inline">${sevBadge(f.severity)}</div><div class="f-title">${esc(f.title)}</div>
            <div class="f-sub"><span class="f-subject">${esc(f.subject)}</span><span class="f-rule">${esc(f.rule)}</span></div>
            ${S._newIds.has(f.id) || f.accepted || f.review ? `<div class="f-badges">${S._newIds.has(f.id) ? newBadge() : ""}${f.accepted ? acceptedBadge() : ""}${f.review ? aiBadge(f.review) : ""}</div>` : ""}</td>
          <td class="col-cat">${esc(catLabel(f.category))}</td>
        </tr>`);
      });
      const end = Math.min(list.length, start + S.pageSize);
      tbl.innerHTML = `<div class="card card-flush"><div class="table-wrap"><table class="table" aria-label="Befunde" aria-describedby="fCount">
        <thead><tr><th scope="col" class="col-check"><input type="checkbox" id="fSelPage" ${allSel ? "checked" : ""} aria-label="Alle Befunde dieser Seite auswählen"></th>
        ${th("severity", "Schwere", "col-sev")}${th("subject", "Befund")}${th("category", "Kategorie", "col-cat")}</tr></thead>
        <tbody>${rows.join("")}</tbody></table></div>
        <div class="table-foot"><span class="tnum">${fmtNum(start + 1)}–${fmtNum(end)} von ${fmtNum(list.length)}</span><span class="spacer"></span>
          <label class="row">Pro Seite <select class="select" id="fPageSize" style="height:30px">${[50, 100, 250, 500].map((n) => `<option ${n === S.pageSize ? "selected" : ""}>${n}</option>`).join("")}</select></label>
          ${pages > 1 ? `<button type="button" class="icon-btn icon-btn-sm" data-action="page" data-page="${S.page - 1}" ${S.page === 0 ? "disabled" : ""} aria-label="Vorherige Seite">${icon("left")}</button><span class="tnum">Seite ${S.page + 1} / ${pages}</span><button type="button" class="icon-btn icon-btn-sm" data-action="page" data-page="${S.page + 1}" ${S.page >= pages - 1 ? "disabled" : ""} aria-label="Nächste Seite">${icon("right")}</button>` : ""}
        </div></div>`;
      const sp = $("#fSelPage");
      sp.indeterminate = someSel && !allSel;
    }
    renderBulkBar(list);
  }
  function renderFacets() {
    return FACETS.filter((fc) => !fc.showIf || fc.showIf()).map((fc) => {
      const base = filterFindings(fc.key);
      const counts = new Map();
      base.forEach((f) => {
        const v = fc.get(f);
        counts.set(v, (counts.get(v) || 0) + 1);
      });
      const present = new Set(S.report.findings.map(fc.get));
      let vals = fc.order ? fc.order.filter((v) => present.has(v)) : [...present].sort((a, b) => (counts.get(b) || 0) - (counts.get(a) || 0) || String(a).localeCompare(String(b), "de"));
      const limit = 8;
      const total = vals.length;
      if (!fc.order && !S.facetMore[fc.key] && vals.length > limit) {
        const head = vals.slice(0, limit);
        S.f[fc.key].forEach((v) => {
          if (!head.includes(v)) head.push(v);
        });
        vals = head;
      }
      if (!vals.length) return "";
      const id = `facet-${fc.key}`;
      return `<div class="facet" role="group" aria-labelledby="${id}"><h3 id="${id}">${esc(fc.title)}</h3>
        ${vals.map((v) => {
          const n = counts.get(v) || 0;
          const on = S.f[fc.key].has(v);
          return `<label class="${n || on ? "" : "zero"}"><input type="checkbox" data-facet="${fc.key}" value="${esc(v)}" ${on ? "checked" : ""}>${fc.dot ? `<i class="dot dot-${v}" aria-hidden="true"></i>` : ""}<span class="${fc.mono ? "mono" : ""}" title="${esc(fc.label(v))}">${esc(fc.label(v))}</span><em>${fmtNum(n)}</em></label>`;
        }).join("")}
        ${!fc.order && total > limit ? `<button type="button" class="link-btn more" data-action="facet-more" data-key="${fc.key}">${S.facetMore[fc.key] ? "Weniger anzeigen" : `Alle ${total} anzeigen`}</button>` : ""}
      </div>`;
    }).join("");
  }
  function renderBulkBar(list) {
    const el = $("#fBulk");
    if (!el) return;
    const n = S.selected.size;
    if (!n) {
      el.innerHTML = "";
      return;
    }
    const sel = [...S.selected].map(findById).filter(Boolean);
    const openSel = sel.filter((f) => !f.accepted).length;
    const accSel = sel.length - openSel;
    const notSelectedInList = list.filter((f) => !S.selected.has(f.id)).length;
    el.innerHTML = `<div class="bulkbar" role="region" aria-label="Mehrfachauswahl">
      <b>${plural(n, "Befund", "Befunde")} ausgewählt</b>
      ${notSelectedInList ? `<button type="button" class="btn btn-sm" data-action="select-all-filtered">Alle ${fmtNum(list.length)} gefilterten auswählen</button>` : ""}
      <span class="spacer"></span>
      ${openSel ? `<button type="button" class="btn btn-sm btn-primary" data-action="bulk-accept">${icon("accepted")}${openSel} als unbedenklich markieren</button>` : ""}
      ${accSel ? `<button type="button" class="btn btn-sm" data-action="bulk-unaccept">${icon("undo")}${accSel} Markierung${accSel === 1 ? "" : "en"} aufheben</button>` : ""}
      <button type="button" class="btn btn-sm" data-action="bulk-clear">Auswahl aufheben</button>
    </div>`;
  }
  function onFindingsChange(e) {
    const t = e.target;
    if (t.dataset.facet) {
      const set = S.f[t.dataset.facet];
      if (t.checked) set.add(t.value);
      else set.delete(t.value);
      S.page = 0;
      renderFindingsBody();
    } else if (t.dataset.sel) {
      if (t.checked) S.selected.add(t.dataset.sel);
      else S.selected.delete(t.dataset.sel);
      const tr = t.closest("tr");
      if (tr) tr.classList.toggle("is-selected", t.checked);
      const page = $$("tbody input[data-sel]");
      const sp = $("#fSelPage");
      if (sp) {
        sp.checked = page.every((c) => c.checked);
        sp.indeterminate = !sp.checked && page.some((c) => c.checked);
      }
      renderBulkBar(S.lastList);
    } else if (t.id === "fSelPage") {
      $$("tbody input[data-sel]").forEach((c) => {
        c.checked = t.checked;
        if (t.checked) S.selected.add(c.dataset.sel);
        else S.selected.delete(c.dataset.sel);
        c.closest("tr").classList.toggle("is-selected", t.checked);
      });
      renderBulkBar(S.lastList);
    } else if (t.id === "fPageSize") {
      S.pageSize = Number(t.value) || 100;
      store.set("ecomsec.pageSize", S.pageSize);
      S.page = 0;
      renderFindingsBody();
    }
  }
  function onFindingsClick(e) {
    const sortBtn = e.target.closest("[data-sort]");
    if (sortBtn) {
      const k = sortBtn.dataset.sort;
      S.sort = S.sort.key === k ? { key: k, dir: -S.sort.dir } : { key: k, dir: 1 };
      renderFindingsBody();
      return;
    }
    if (e.target.closest("input, button, a, label, select")) return;
    const tr = e.target.closest("tr[data-id]");
    if (tr) openDrawer(tr.dataset.id);
  }
  function onFindingsKey(e) {
    const tr = e.target.closest && e.target.closest("tr[data-id]");
    if (!tr || e.target !== tr) return;
    if (e.key === "Enter") {
      e.preventDefault();
      openDrawer(tr.dataset.id);
    } else if (e.key === " " || e.key === "x") {
      e.preventDefault();
      const c = $("input[data-sel]", tr);
      c.checked = !c.checked;
      c.dispatchEvent(new Event("change", { bubbles: true }));
    } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      moveRow(e.key === "ArrowDown" ? 1 : -1);
    }
  }
  function moveRow(d) {
    const rows = $$("#fTable tr[data-id]");
    if (!rows.length) return;
    const i = rows.indexOf(document.activeElement);
    const next = rows[Math.max(0, Math.min(rows.length - 1, i < 0 ? 0 : i + d))];
    next.focus();
  }

  // ---------------------------------------------------------------- triage actions
  async function doAccept(ids, reason) {
    S.report = await api("/api/findings/accept", { method: "POST", body: { ids, reason: reason || null } });
    ids.forEach((id) => S.selected.delete(id));
    afterTriage();
    toast(`${plural(ids.length, "Befund", "Befunde")} als unbedenklich markiert`, "ok", { label: "Rückgängig", fn: () => doUnaccept(ids, true) });
  }
  async function doUnaccept(ids, quiet) {
    try {
      S.report = await api("/api/findings/unaccept", { method: "POST", body: { ids } });
      ids.forEach((id) => S.selected.delete(id));
      afterTriage();
      toast(quiet ? "Markierung zurückgenommen" : `Markierung für ${plural(ids.length, "Befund", "Befunde")} aufgehoben`, "ok");
    } catch (e) {
      toast(`Aktion fehlgeschlagen: ${e.message}`, "err");
    }
  }
  function afterTriage() {
    loadDiff().then(() => renderAll());
    renderAll();
  }
  function confirmAccept(ids, title) {
    const list = ids.map(findById).filter((f) => f && !f.accepted);
    if (!list.length) {
      toast("Keine offenen Befunde in der Auswahl.");
      return;
    }
    const crit = list.filter((f) => f.severity === "critical").length;
    openModal({
      title,
      body: `<p class="muted" style="margin:0">Die Markierung bleibt über künftige Scans erhalten, zählt nicht mehr in Ampel und Score und lässt sich jederzeit aufheben.</p>
        ${crit ? `<div class="note n-crit">${icon("crit")}<span>Darunter ${plural(crit, "kritischer Befund", "kritische Befunde")}. Nur markieren, wenn die Datei verifiziert und als legitim bekannt ist.</span></div>` : ""}
        <div><div class="section-title">${plural(list.length, "Befund", "Befunde")}</div><ul class="list affected">${list.slice(0, 60).map((f) => `<li><i class="dot dot-${f.severity}" aria-hidden="true"></i><span class="mono break">${esc(f.subject)}</span><span class="muted">– ${esc(f.title)}</span></li>`).join("")}${list.length > 60 ? `<li class="muted">… und ${list.length - 60} weitere</li>` : ""}</ul></div>
        <label class="field"><span>Begründung</span><textarea class="textarea" id="acceptReason" maxlength="500" placeholder="z. B. eigene Anpassung durch Agentur XY am 20.06."></textarea><small>Wird mit der Markierung gespeichert und im Bericht angezeigt.</small></label>`,
      confirm: list.length === 1 ? "Als unbedenklich markieren" : `${list.length} Befunde markieren`,
      onConfirm: async (box) => {
        await doAccept(list.map((f) => f.id), $("#acceptReason", box).value.trim());
      },
    });
  }
  const openInDir = (dir) => S.report.findings.filter((f) => !f.accepted && f.group === dir).map((f) => f.id);
  const openWithRule = (rule) => S.report.findings.filter((f) => !f.accepted && f.rule === rule).map((f) => f.id);

  // ================================================================ drawer
  let drawerLastFocus = null;
  async function openDrawer(id) {
    const f = findById(id);
    if (!f) {
      if (S.reportState === "ok") toast("Befund nicht im aktuellen Report gefunden.", "err");
      return;
    }
    const wasOpen = !!S.drawerId;
    if (!wasOpen) drawerLastFocus = document.activeElement;
    S.drawerId = id;
    S.drawerExtra = null;
    renderDrawer();
    $("#drawer").hidden = false;
    $("#drawerScrim").hidden = false;
    if (!wasOpen) setTimeout(() => $("#drawer").focus(), 10);
    markActiveRow();
    if (S.view === "findings" && location.hash !== `#/findings/${encodeURIComponent(id)}`) history.replaceState(null, "", `#/findings/${encodeURIComponent(id)}`);
    try {
      const extra = await api(`/api/findings/${encodeURIComponent(id)}`);
      if (S.drawerId === id) {
        S.drawerExtra = extra;
        renderDrawer();
      }
    } catch (e) { /* local data is sufficient */ }
  }
  function closeDrawer(silent) {
    if (!S.drawerId) return;
    S.drawerId = null;
    $("#drawer").hidden = true;
    $("#drawerScrim").hidden = true;
    markActiveRow();
    if (S.view === "findings" && /^#\/findings\//.test(location.hash)) history.replaceState(null, "", "#/findings");
    if (!silent && drawerLastFocus && document.contains(drawerLastFocus)) drawerLastFocus.focus();
  }
  function markActiveRow() {
    $$("#fTable tr[data-id]").forEach((tr) => tr.classList.toggle("is-active", tr.dataset.id === S.drawerId));
  }
  function drawerStep(d) {
    const list = S.view === "findings" && S.lastList.length ? S.lastList : S.report.findings;
    const i = list.findIndex((f) => f.id === S.drawerId);
    if (i < 0) return;
    const next = list[i + d];
    if (next) openDrawer(next.id);
  }
  function renderDrawer() {
    const f = findById(S.drawerId);
    if (!f) return;
    const r = S.report;
    const x = S.drawerExtra && S.drawerExtra.finding && S.drawerExtra.finding.id === f.id ? S.drawerExtra : null;
    const recs = x ? x.recommendations : r.recommendations.flatMap((g) => g.items.filter((it) => (it.related || []).includes(f.id)).map((it) => ({ group: g.kind, group_label: g.label, priority: it.priority, title: it.title })));
    const acc = x && x.acceptance;
    const isNew = newIds().has(f.id);
    const list = S.view === "findings" && S.lastList.length ? S.lastList : r.findings;
    const idx = list.findIndex((y) => y.id === f.id);
    const dirN = f.group ? openInDir(f.group).length : 0;
    const ruleN = openWithRule(f.rule).length;
    const rv = f.review;
    const copyBtn = (label, attr) => `<button type="button" class="icon-btn icon-btn-sm" data-action="copy" ${attr} aria-label="${esc(label)}" title="${esc(label)}">${icon("copy")}</button>`;
    $("#drawer").innerHTML = `
      <div class="drawer-head">
        <div class="grow">
          <div class="row">${sevBadge(f.severity)}${f.accepted ? acceptedBadge() : ""}${isNew ? newBadge() : ""}${rv ? aiBadge(rv) : ""}</div>
          <h2 id="drawerTitle">${esc(f.title)}</h2>
        </div>
        <div class="drawer-nav">
          <button type="button" class="icon-btn" data-action="drawer-prev" ${idx <= 0 ? "disabled" : ""} aria-label="Vorheriger Befund (k)" title="Vorheriger Befund (k)">${icon("up")}</button>
          <button type="button" class="icon-btn" data-action="drawer-next" ${idx < 0 || idx >= list.length - 1 ? "disabled" : ""} aria-label="Nächster Befund (j)" title="Nächster Befund (j)">${icon("down")}</button>
          <button type="button" class="icon-btn" data-action="drawer-close" aria-label="Schließen (Esc)" title="Schließen (Esc)">${icon("x")}</button>
        </div>
      </div>
      <div class="drawer-body">
        <dl class="dl">
          <dt>Betroffen</dt><dd class="copyline"><code>${esc(f.subject)}</code>${copyBtn("Betroffenes Objekt kopieren", `data-copy="${esc(f.subject)}"`)}</dd>
          ${f.path ? `<dt>Pfad</dt><dd class="copyline"><code>${esc(f.path)}</code>${copyBtn("Pfad kopieren", `data-copy="${esc(f.path)}"`)}</dd>` : ""}
          <dt>Kategorie</dt><dd>${esc(catLabel(f.category))}</dd>
          <dt>Regel</dt><dd><code>${esc(f.rule)}</code> <button type="button" class="link-btn" data-action="filter-rule" data-rule="${esc(f.rule)}">alle anzeigen</button></dd>
          <dt>Quelle</dt><dd>${esc(SOURCE[f.source] || f.source)}</dd>
          ${f.group ? `<dt>Verzeichnis</dt><dd><code>${esc(f.group)}</code> <button type="button" class="link-btn" data-action="filter-dir" data-dir="${esc(f.group)}">alle anzeigen</button></dd>` : ""}
          <dt>Gefunden</dt><dd>Scan vom ${esc(fmtDateTime(r.generated_at))}${isNew ? " · neu seit dem letzten Scan" : ""}</dd>
          ${acc ? `<dt>Markiert am</dt><dd>${esc(fmtDateTime(acc.accepted_at))}</dd>` : ""}
          <dt>Befund-ID</dt><dd class="copyline"><code>${esc(f.id)}</code>${copyBtn("Befund-ID kopieren", `data-copy="${esc(f.id)}"`)}</dd>
        </dl>
        ${f.accepted ? `<div class="note n-ok">${icon("accepted")}<div><b>Als unbedenklich markiert</b>${f.accepted_reason ? `<div class="prose">${esc(f.accepted_reason)}</div>` : `<div class="muted">ohne Begründung</div>`}</div></div>` : ""}
        ${f.description ? `<section><h3 class="section-title">Beschreibung</h3><p class="prose" style="margin:0">${esc(f.description)}</p></section>` : ""}
        ${(f.evidence || []).length ? `<section><h3 class="section-title">Beweise (${f.evidence.length})</h3>${f.evidence.map((ev, i) => `<div class="evidence"><pre>${esc(ev)}</pre>${copyBtn(`Beweis ${i + 1} kopieren`, `data-copy-ev="${i}"`)}</div>`).join("")}</section>` : ""}
        ${rv ? `<section><h3 class="section-title">KI-Bewertung</h3><div class="ai-box stack" style="gap:8px">
            <div class="row">${aiBadge(rv)}<span class="spacer"></span><span class="muted small">${esc(rv.model)}${rv.reviewed_at ? ` · ${esc(fmtShort(rv.reviewed_at))}` : ""}</span></div>
            <div class="meter" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round((rv.confidence || 0) * 100)}" aria-label="Konfidenz"><i style="width:${Math.round((rv.confidence || 0) * 100)}%"></i></div>
            ${rv.reasoning ? `<p class="prose" style="margin:0">${esc(rv.reasoning)}</p>` : ""}
            <p class="muted small" style="margin:0">Entscheidungshilfe, keine Garantie. Nichts löschen, bevor der Befund verifiziert und gesichert ist.</p></div></section>` : ""}
        ${recs.length ? `<section><h3 class="section-title">Verknüpfte Empfehlungen</h3><ul class="list">${recs.map((rc) => `<li><button type="button" class="item" data-action="goto-rec" data-key="${esc(rc.group + "|" + rc.title)}"><span class="prio prio-${Math.min(3, rc.priority)}">P${rc.priority}</span><span class="grow"><span class="title">${esc(rc.title)}</span><span class="sub" style="display:block">${esc(rc.group_label)}</span></span></button></li>`).join("")}</ul></section>` : ""}
      </div>
      <div class="drawer-foot">
        ${f.accepted
          ? `<button type="button" class="btn" data-action="unaccept-one" data-id="${esc(f.id)}">${icon("undo")}Markierung aufheben</button>`
          : `<button type="button" class="btn btn-primary" data-action="accept-one" data-id="${esc(f.id)}">${icon("accepted")}Als unbedenklich markieren</button>
             ${dirN > 1 ? `<button type="button" class="btn" data-action="accept-dir" data-dir="${esc(f.group)}" title="Alle ${dirN} offenen Befunde in ${esc(f.group)}">Verzeichnis (${dirN})</button>` : ""}
             ${ruleN > 1 ? `<button type="button" class="btn" data-action="accept-rule" data-rule="${esc(f.rule)}" title="Alle ${ruleN} offenen Befunde der Regel ${esc(f.rule)}">Regel (${ruleN})</button>` : ""}`}
      </div>`;
  }

  // ================================================================ view: integrity
  function renderIntegrity() {
    const el = $("#view-integrity");
    const desc = "Patch-Status, Admin-Konten, Zahlungsempfänger, Dateirechte und Fremdcode – das Ergebnis der Plattform-Prüfungen.";
    const st = stateBlock();
    if (st) {
      el.innerHTML = pageHead("integrity", desc) + st;
      return;
    }
    const r = S.report;
    const p = r.platform;
    const counts = { critical: 0, warning: 0, unknown: 0, ok: 0 };
    r.integrity.forEach((i) => (counts[i.status] = (counts[i.status] || 0) + 1));
    const sections = [];
    r.integrity.forEach((i) => {
      let s = sections.find((x) => x.name === i.section);
      if (!s) sections.push((s = { name: i.section, items: [] }));
      s.items.push(i);
    });
    const worst = (items) => items.reduce((m, i) => (ST[i.status].rank > ST[m].rank ? i.status : m), "ok");
    // Sections with problems first; otherwise keep the adapter's order.
    sections.forEach((s, n) => (s.order = n));
    sections.sort((a, b) => ST[worst(b.items)].rank - ST[worst(a.items)].rank || a.order - b.order);
    const adv = (r.advisories || []).slice().sort((a, b) => ["vulnerable", "unknown", "patched", "not_affected"].indexOf(a.state) - ["vulnerable", "unknown", "patched", "not_affected"].indexOf(b.state));
    const fixed = (a) => (a.advisory.fixed_in || []).map(String).join(", ");
    el.innerHTML = `${pageHead("integrity", desc, `<button type="button" class="btn" data-action="baseline">${icon("layers")}Baseline erzeugen</button>`)}
      <div class="stack">
        <div class="grid grid-main-side">
          <section class="card"><div class="card-head"><h2>${icon("server")}Installation</h2><span class="sub">${esc(p.kind === "hosted" ? "gehostet" : "selbst gehostet")}</span></div>
            <dl class="dl">
              <dt>Plattform</dt><dd>${esc(p.name)}${p.version ? ` <b>${esc(p.version)}</b>` : ` <span class="muted">Version unbekannt</span>`}</dd>
              ${p.root ? `<dt>Verzeichnis</dt><dd class="copyline"><code>${esc(p.root)}</code></dd>` : ""}
              ${p.target ? `<dt>Shop</dt><dd>${esc(p.target)}</dd>` : ""}
              ${(p.details || []).filter((d) => !/^Shop-URL$/.test(d[0]) || !p.target).map((d) => `<dt>${esc(d[0])}</dt><dd>${esc(d[1])}</dd>`).join("")}
              <dt>Referenzdatum</dt><dd>${fmtDate(r.reference_date)}</dd>
              <dt>Letzter Scan</dt><dd>${esc(fmtDateTime(r.generated_at))}</dd>
            </dl></section>
          <section class="card"><div class="card-head"><h2>${icon("shield")}Zusammenfassung</h2><span class="sub">${plural(r.integrity.length, "Prüfung", "Prüfungen")}</span></div>
            <div class="stat-tiles">
              <div class="stat"><b>${counts.critical}</b><span>${icon("crit", "icon-sm ic-critical")}Kritisch</span></div>
              <div class="stat"><b>${counts.warning}</b><span>${icon("warn", "icon-sm ic-warning")}Prüfen</span></div>
              <div class="stat"><b>${counts.unknown}</b><span>${icon("unknown", "icon-sm ic-unknown")}Unbekannt</span></div>
              <div class="stat"><b>${counts.ok}</b><span>${icon("ok", "icon-sm ic-ok")}OK</span></div>
            </div>
            ${(r.limitations || []).length ? `<div class="note n-warn" style="margin-top:16px">${icon("warn")}<div><b>Eingeschränkte Prüfung</b><ul class="ol" style="padding-left:1.1em">${r.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul></div></div>` : ""}
          </section>
        </div>
        <section aria-labelledby="h-adv"><div class="card-head" style="margin:8px 0 12px"><h2 id="h-adv" style="font-size:var(--fs-lg)">Bekannte Schwachstellen</h2><span class="sub">${adv.length ? `${adv.filter((a) => a.state === "vulnerable").length} verwundbar · ${adv.length} geprüft` : ""}</span></div>
          ${adv.length ? `<div class="grid ${adv.length > 1 ? "grid-2" : ""}">${adv.map((a) => {
            const pst = PATCH[a.state] || PATCH.unknown;
            return `<article class="card adv-card s-${esc(a.state)}">
              <div class="adv-top"><div><h3>${esc(a.advisory.id)}</h3><div class="adv-title">${esc(a.advisory.title)}</div></div>${stBadge(pst.st, pst.label)}</div>
              <div class="meta">${sevBadge(a.advisory.severity)}${a.advisory.score != null ? `<span>CVSS <b>${esc(a.advisory.score)}</b></span>` : ""}<span>veröffentlicht ${fmtDate(a.advisory.published)}</span>${fixed(a) ? `<span>behoben in <b>${esc(fixed(a))}</b></span>` : ""}${a.advisory.component ? `<span>Komponente ${esc(a.advisory.component)}</span>` : ""}</div>
              <div><div class="section-title">Bewertungsgrundlage</div><p style="margin:0" class="break basis">${esc(a.basis)}</p></div>
              ${a.advisory.backpatch_note ? `<p class="muted small" style="margin:0">${esc(a.advisory.backpatch_note)}</p>` : ""}
              ${a.advisory.reference ? `<a href="${esc(a.advisory.reference)}" target="_blank" rel="noopener noreferrer" class="small">Referenz öffnen${icon("ext", "icon-sm")}</a>` : ""}
            </article>`;
          }).join("")}</div>` : `<div class="card empty compact"><p>Für diese Plattform sind keine Advisories hinterlegt.</p></div>`}
        </section>
        <section aria-labelledby="h-checks"><div class="card-head" style="margin:8px 0 12px"><h2 id="h-checks" style="font-size:var(--fs-lg)">Prüfungen</h2></div>
          ${sections.length ? `<div class="cards-masonry">${sections.map((s) => {
            const w = worst(s.items);
            const issues = s.items.filter((i) => i.status === "critical" || i.status === "warning").length;
            return `<article class="card"><div class="card-head"><h2>${stIcon(w)}${esc(s.name)}</h2><span class="sub">${plural(s.items.length, "Prüfung", "Prüfungen")}${issues ? ` · ${issues} auffällig` : ""}</span></div>
              <table class="kv-table"><tbody>${s.items.map((i) => {
                // Long values (account details …) read better below the label.
                const long = String(i.value).length > 28;
                return `<tr><td class="st">${stIcon(i.status)}</td><td${long ? ` colspan="2"` : ""}><div class="lbl">${esc(i.label)}</div>${long ? `<div class="val-long">${esc(i.value)}</div>` : ""}${i.detail ? `<div class="det">${esc(i.detail)}</div>` : ""}</td>${long ? "" : `<td class="val">${esc(i.value)}</td>`}</tr>`;
              }).join("")}</tbody></table></article>`;
          }).join("")}</div>` : `<div class="card empty compact"><p>Keine Integritätsdaten.</p></div>`}
        </section>
      </div>`;
  }

  // ================================================================ view: recommendations
  const targetKey = () => {
    const p = S.report && S.report.platform;
    return p ? `${p.id}:${p.root || p.target || ""}` : "none";
  };
  const recKey = (g, it) => `${g.kind}|${it.title}`;
  const doneSet = () => new Set(store.get(`ecomsec.recs.${targetKey()}`, []));
  function setDone(key, on) {
    const s = doneSet();
    if (on) s.add(key);
    else s.delete(key);
    store.set(`ecomsec.recs.${targetKey()}`, [...s]);
  }
  function renderRecs() {
    const el = $("#view-recommendations");
    const desc = "Priorisierte Checkliste aus den Befunden. „Erledigt“ wird nur in diesem Browser gespeichert.";
    const st = stateBlock();
    if (st) {
      el.innerHTML = pageHead("recommendations", desc) + st;
      return;
    }
    const r = S.report;
    const done = doneSet();
    const groups = r.recommendations.slice().sort((a, b) => GROUP_ORDER.indexOf(a.kind) - GROUP_ORDER.indexOf(b.kind));
    const total = groups.reduce((n, g) => n + g.items.length, 0);
    const nDone = groups.reduce((n, g) => n + g.items.filter((it) => done.has(recKey(g, it))).length, 0);
    const chip = (id) => {
      const f = findById(id);
      if (!f) return "";
      const short = f.subject.length > 42 ? "…" + f.subject.slice(-40) : f.subject;
      return `<button type="button" class="chip" data-action="open-finding" data-id="${esc(f.id)}" title="${esc(f.title)} – ${esc(f.subject)}"><i class="dot dot-${f.severity}" aria-hidden="true"></i><span class="mono">${esc(short)}</span></button>`;
    };
    el.innerHTML = `${pageHead("recommendations", desc, `<button type="button" class="btn" data-action="rec-hide-done" aria-pressed="${S.hideDone}">${icon(S.hideDone ? "check" : "filter")}Erledigte ausblenden</button>${nDone ? `<button type="button" class="btn btn-ghost" data-action="rec-reset">${icon("undo")}Zurücksetzen</button>` : ""}`)}
      <div class="stack">
        <section class="card" aria-label="Fortschritt"><div class="row" style="margin-bottom:10px"><b>${nDone} von ${total} erledigt</b><span class="spacer"></span><span class="muted small">${total - nDone} offen</span></div>
          <div class="progress-line" role="progressbar" aria-valuemin="0" aria-valuemax="${total}" aria-valuenow="${nDone}" aria-label="Erledigte Empfehlungen"><i style="width:${total ? (100 * nDone) / total : 0}%"></i></div></section>
        ${groups.map((g) => {
          const items = g.items.filter((it) => !S.hideDone || !done.has(recKey(g, it)));
          const gd = g.items.filter((it) => done.has(recKey(g, it))).length;
          return `<section class="card" aria-labelledby="g-${esc(g.kind)}"><div class="card-head"><h2 id="g-${esc(g.kind)}">${esc(g.label)}</h2><span class="sub">${gd}/${g.items.length} erledigt</span></div>
            ${items.length ? items.map((it) => {
              const key = recKey(g, it);
              const isDone = done.has(key);
              const rel = it.related || [];
              return `<div class="rec-item${isDone ? " done" : ""}" data-key="${esc(key)}">
                <input type="checkbox" class="rec-check" data-rec="${esc(key)}" ${isDone ? "checked" : ""} aria-label="Erledigt: ${esc(it.title)}">
                <span class="prio prio-${Math.min(3, it.priority)}" title="Priorität ${it.priority}">P${it.priority}</span>
                <div class="min0"><h3>${esc(it.title)}</h3><p>${esc(it.detail)}</p>
                  ${rel.length ? `<div class="chips">${rel.slice(0, 6).map(chip).join("")}${rel.length > 6 ? `<button type="button" class="chip" data-action="rec-findings" data-key="${esc(key)}">alle ${rel.length} Befunde${icon("right", "icon-sm")}</button>` : ""}</div>` : ""}
                </div></div>`;
            }).join("") : `<p class="muted" style="margin:0">Alle Punkte dieser Gruppe sind erledigt.</p>`}
          </section>`;
        }).join("")}
      </div>`;
    if (S.flashRec) {
      const item = $$(".rec-item", el).find((x) => x.dataset.key === S.flashRec);
      S.flashRec = null;
      if (item) {
        item.scrollIntoView({ block: "center" });
        item.classList.add("flash");
        $("input", item).focus({ preventScroll: true });
      }
    }
  }
  function findRec(key) {
    for (const g of (S.report && S.report.recommendations) || []) for (const it of g.items) if (recKey(g, it) === key) return { g, it };
    return null;
  }

  // ================================================================ view: history
  function renderHistory() {
    const el = $("#view-history");
    const desc = "Alle Scans dieser Installation. Die letzten zehn vollständigen Reports sind archiviert und lassen sich im Detail öffnen.";
    if (S.history === null) {
      el.innerHTML = pageHead("history", desc) + `<div class="card"><div class="skel skel-block"></div></div>`;
      return;
    }
    const h = histEntries().slice().reverse();
    if (!h.length) {
      el.innerHTML = pageHead("history", desc) + `<div class="card empty"><div class="empty-icon">${icon("history")}</div><h2>Noch kein Verlauf</h2><p>Nach dem ersten Scan erscheinen hier alle Läufe mit Ergebnis und Score.</p></div>`;
      return;
    }
    if (!S.histSel) S.histSel = h[0].generated_at;
    el.innerHTML = `${pageHead("history", desc)}
      <div class="stack">
        ${trendPoints(30).length ? `<section class="card"><div class="card-head"><h2>${icon("history")}Sicherheitsniveau</h2><span class="sub">letzte ${Math.min(30, trendPoints().length)} Scans · Hilfslinien bei den Notengrenzen A 90 · B 75 · C 60 · D 40</span></div><div class="trend" data-chart="30" data-height="220"></div></section>` : ""}
        <div class="hist-layout">
          <section class="card card-flush" aria-label="Scan-Verlauf"><div class="table-wrap"><table class="table">
            <thead><tr><th scope="col">Zeitpunkt</th><th scope="col">Ergebnis</th><th scope="col">Score</th><th scope="col" class="tnum">Krit.</th><th scope="col" class="tnum">Warn.</th><th scope="col" class="col-hide-sm tnum">Hinw.</th><th scope="col" class="col-hide-sm">Dateien</th></tr></thead>
            <tbody>${h.slice(0, 200).map((e) => `<tr class="row-click${sameTime(e.generated_at, S.histSel) ? " is-selected is-active" : ""}" data-hist="${esc(e.generated_at)}" tabindex="0" aria-label="Scan vom ${esc(fmtDateTime(e.generated_at))}">
              <td class="nowrap">${esc(fmtShort(e.generated_at))}${S.archive.has(stampOf(e.generated_at)) ? ` <span class="muted" title="Report archiviert">${icon("file", "icon-sm")}</span>` : ""}</td>
              <td>${stBadge(VERDICT_ST[e.verdict], VERDICT_SHORT[e.verdict])}${e.complete ? "" : ` <span class="muted small">unvollst.</span>`}</td>
              <td class="nowrap">${e.score != null ? `<span class="score-cell">${gradeBadge(e.grade)}<span class="tnum">${e.score}</span></span>` : "–"}</td>
              <td class="tnum">${e.critical}</td><td class="tnum">${e.warning}</td><td class="tnum col-hide-sm">${e.info}</td><td class="tnum col-hide-sm">${fmtNum(e.files_scanned)}</td></tr>`).join("")}</tbody>
          </table></div></section>
          <section class="card hist-detail" id="histDetail" aria-live="polite"></section>
        </div>
      </div>`;
    drawCharts(el);
    renderHistDetail();
    if (!S.histDetail || !sameTime(S.histDetail.generated_at, S.histSel)) selectHistory(S.histSel);
  }
  async function selectHistory(at) {
    S.histSel = at;
    S.histDetail = null;
    $$("#view-history tr[data-hist]").forEach((tr) => {
      const on = tr.dataset.hist === at;
      tr.classList.toggle("is-selected", on);
      tr.classList.toggle("is-active", on);
    });
    renderHistDetail();
    const stamp = stampOf(at);
    if (S.archive.has(stamp)) {
      try {
        const rep = await api(`/api/archive/${stamp}`);
        if (S.histSel === at) {
          S.histDetail = rep;
          renderHistDetail();
        }
      } catch (e) {
        if (S.histSel === at) {
          S.histDetail = { error: e.message };
          renderHistDetail();
        }
      }
    }
  }
  function renderHistDetail() {
    const el = $("#histDetail");
    if (!el) return;
    const h = S.history || [];
    const e = histEntries().find((x) => x.generated_at === S.histSel);
    if (!e) {
      el.innerHTML = `<p class="muted">Scan auswählen, um Details zu sehen.</p>`;
      return;
    }
    const stamp = stampOf(e.generated_at);
    const archived = S.archive.has(stamp);
    const rep = S.histDetail && !S.histDetail.error && sameTime(S.histDetail.generated_at, e.generated_at) ? S.histDetail : null;
    const isCurrent = S.report && sameTime(S.report.generated_at, e.generated_at);
    let body = "";
    if (rep) {
      const top = rep.findings.filter((f) => !f.accepted).sort((a, b) => SEV[a.severity].rank - SEV[b.severity].rank).slice(0, 8);
      body = `${(rep.score_drivers || []).length ? `<div><div class="section-title">Score-Faktoren</div><ul class="list">${rep.score_drivers.slice(0, 5).map((d) => `<li><span class="grow">${esc(d.label)}</span><b class="tnum small">−${d.points}</b></li>`).join("")}</ul></div>` : ""}
        <div><div class="section-title">Wichtigste offene Befunde</div>${top.length ? `<ul class="list">${top.map((f) => `<li>${findById(f.id) ? `<button type="button" class="item" data-action="open-finding" data-id="${esc(f.id)}">` : `<span class="item" style="display:flex;gap:12px">`}${sevBadge(f.severity)}<span class="grow"><span class="title">${esc(f.title)}</span><span class="sub mono" style="display:block">${esc(f.subject)}</span></span>${findById(f.id) ? "</button>" : "</span>"}</li>`).join("")}</ul>` : `<p class="muted">Keine offenen Befunde.</p>`}</div>
        ${(rep.limitations || []).length ? `<div class="note n-warn">${icon("warn")}<span>${rep.limitations.map(esc).join("<br>")}</span></div>` : ""}`;
    } else if (archived && !(S.histDetail && S.histDetail.error)) {
      body = `<div class="skel skel-line"></div><div class="skel skel-line" style="width:70%"></div><div class="skel skel-line" style="width:50%"></div>`;
    } else {
      body = `<div class="note">${icon("info")}<span>${S.histDetail && S.histDetail.error ? esc(S.histDetail.error) : e.complete ? "Für diesen Scan ist kein Report mehr archiviert – es werden die letzten zehn vollständigen Scans aufbewahrt." : "Unvollständige Scans (Zeitbudget) werden nicht archiviert."}</span></div>`;
    }
    el.innerHTML = `<div class="card-head"><h2>${esc(fmtDateTime(e.generated_at))}</h2>${stBadge(VERDICT_ST[e.verdict], VERDICT_SHORT[e.verdict])}</div>
      <div class="stack">
        <div class="row small muted">${e.score != null ? `${gradeBadge(e.grade)}<span><b class="tnum" style="color:var(--text)">${e.score}/100</b> · Note ${esc(e.grade)} (${esc(GRADE[e.grade] || "")})</span>` : "<span>kein Score</span>"}<span class="spacer"></span>${isCurrent ? `<span class="badge st-accent">Aktueller Report</span>` : ""}</div>
        <div class="mini-counts"><div><b class="tnum">${e.critical}</b><span>kritisch</span></div><div><b class="tnum">${e.warning}</b><span>Warnungen</span></div><div><b class="tnum">${e.info}</b><span>Hinweise</span></div><div><b class="tnum">${e.accepted}</b><span>unbedenklich</span></div></div>
        <div class="small muted">${plural(e.files_scanned, "Datei", "Dateien")} geprüft · Version ${esc(e.version || "unbekannt")}${e.complete ? "" : " · unvollständig"}</div>
        ${body}
      </div>`;
  }

  // ================================================================ view: audit
  function renderAudit() {
    const el = $("#view-audit");
    const desc = "Optionale Zweitmeinung durch ein Sprachmodell mit Read-only-Werkzeugen (<code>ecomsec audit</code>). Entscheidungshilfe, keine Garantie.";
    if (S.auditState === "loading") {
      el.innerHTML = pageHead("audit", desc) + `<div class="card"><div class="skel skel-block"></div></div>`;
      return;
    }
    const a = S.audit;
    if (!a) {
      el.innerHTML = pageHead("audit", desc) + `<div class="card empty"><div class="empty-icon">${icon("ai")}</div><h2>Noch kein KI-Audit vorhanden</h2>
        <p>Das Audit läuft auf der Kommandozeile und benötigt einen eigenen API-Schlüssel. Die Ergebnisse erscheinen anschließend hier und als KI-Bewertung an den Befunden.</p>
        <div class="evidence" style="text-align:left;min-width:min(420px,100%)"><pre>ANTHROPIC_API_KEY=… ecomsec audit</pre><button type="button" class="icon-btn icon-btn-sm" data-action="copy" data-copy="ecomsec audit" aria-label="Befehl kopieren">${icon("copy")}</button></div>
        <a href="${DOCS}docs/AUDIT.md" target="_blank" rel="noopener noreferrer">Dokumentation zum KI-Audit${icon("ext", "icon-sm")}</a></div>`;
      return;
    }
    const as = ASSESS[a.overall_assessment] || ["unknown", a.overall_assessment ? a.overall_assessment.replace(/_/g, " ") : "keine Gesamtbewertung"];
    const counts = { confirmed: 0, needs_human: 0, likely_false_positive: 0 };
    (a.verdicts || []).forEach((v) => (counts[v.verdict] = (counts[v.verdict] || 0) + 1));
    const steps = (a.next_steps || []).slice().sort((x, y) => x.priority - y.priority);
    const usage = a.usage || {};
    const data = a.data || {};
    const verdicts = (a.verdicts || []).slice().sort((x, y) => ["confirmed", "needs_human", "likely_false_positive"].indexOf(x.verdict) - ["confirmed", "needs_human", "likely_false_positive"].indexOf(y.verdict) || y.confidence - x.confidence);
    el.innerHTML = `${pageHead("audit", desc)}
      <div class="stack">
        ${auditStale() ? `<div class="note n-warn">${icon("warn")}<span>Diese Bewertung bezieht sich auf den Scan vom ${esc(fmtDateTime(a.report_generated_at))}. Nach dem neuen Scan <code>ecomsec audit</code> erneut ausführen.</span></div>` : ""}
        ${a.status !== "completed" ? `<div class="note n-warn">${icon("warn")}<span>Audit ${esc(AUDIT_STATUS[a.status] || a.status)}${a.abort_reason ? ` – ${esc(a.abort_reason)}` : ""}</span></div>` : ""}
        <div class="grid grid-main-side">
          <div class="stack">
            <section class="card"><div class="card-head"><h2>${icon("ai")}Gesamtbewertung</h2><span class="sub">${esc(fmtDateTime(a.finished))}</span></div>
              <div class="row" style="margin-bottom:12px">${stBadge(["critical", "warning", "ok"].includes(as[0]) ? as[0] : "unknown", as[1])}${a.confidence != null ? `<span class="muted small">Konfidenz ${Math.round(a.confidence * 100)} %</span>` : ""}</div>
              ${a.confidence != null ? `<div class="meter" style="margin-bottom:16px" role="meter" aria-label="Konfidenz" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round(a.confidence * 100)}"><i style="width:${Math.round(a.confidence * 100)}%"></i></div>` : ""}
              <p class="prose" style="margin:0">${esc(a.summary || "")}</p></section>
            ${steps.length ? `<section class="card"><div class="card-head"><h2>${icon("checklist")}Nächste Schritte</h2></div><ol class="steps">${steps.map((s) => `<li><span class="prio prio-${Math.min(3, s.priority)}">P${s.priority}</span><div><div>${esc(s.action)}</div>${s.rationale ? `<div class="rat">${esc(s.rationale)}</div>` : ""}</div></li>`).join("")}</ol></section>` : ""}
          </div>
          <div class="stack">
            <section class="card"><div class="card-head"><h2>Bewertungen</h2><span class="sub">${(a.verdicts || []).length} Befunde bewertet</span></div>
              <div class="stat-tiles">
                <div class="stat"><b>${counts.confirmed}</b><span>${icon("crit", "icon-sm ic-critical")}bestätigt</span></div>
                <div class="stat"><b>${counts.needs_human}</b><span>${icon("warn", "icon-sm ic-warning")}manuelle Prüfung</span></div>
                <div class="stat"><b>${counts.likely_false_positive}</b><span>${icon("ok", "icon-sm ic-ok")}wahrsch. Fehlalarm</span></div>
                <div class="stat"><b>${(a.new_findings || []).length}</b><span>${icon("info", "icon-sm ic-info")}neue Befunde</span></div>
                ${(a.unreviewed || []).length ? `<div class="stat"><b>${a.unreviewed.length}</b><span>${icon("unknown", "icon-sm ic-unknown")}ohne Bewertung</span></div>` : ""}
              </div></section>
            <section class="card"><div class="card-head"><h2>Lauf</h2><span class="sub">${esc(a.mode === "hunt" ? "Hunt (Triage + Code-Review)" : "Triage")}</span></div>
              <dl class="dl">
                <dt>Modell</dt><dd><code>${esc(a.model)}</code></dd>
                <dt>Zeitraum</dt><dd>${esc(fmtShort(a.started))} – ${esc(new Date(a.finished).toLocaleTimeString("de-DE"))}</dd>
                <dt>Bezug</dt><dd>Scan vom ${esc(fmtDateTime(a.report_generated_at))}</dd>
                <dt>Runden</dt><dd>${fmtNum(a.turns)} · ${fmtNum(data.tool_calls)} Werkzeugaufrufe</dd>
                <dt>Tokens</dt><dd>${fmtNum(a.tokens_in)} Eingabe${usage.cache_read_input_tokens ? ` (davon ${fmtNum(usage.cache_read_input_tokens)} aus Cache)` : ""} · ${fmtNum(a.tokens_out)} Ausgabe</dd>
                <dt>Kosten</dt><dd>${a.estimated_cost_usd != null ? `ca. ${a.estimated_cost_usd.toFixed(2).replace(".", ",")} USD` : "keine Schätzung verfügbar"}</dd>
                <dt>Übertragen</dt><dd>${((data.bytes_sent || 0) / 1024).toFixed(1).replace(".", ",")} KiB redigiert · ${fmtNum(data.redactions)} Werte maskiert · ${fmtNum((data.files_read || []).length)} Dateien gelesen</dd>
              </dl></section>
          </div>
        </div>
        ${verdicts.length ? `<section class="card card-flush"><div class="card-head"><h2>Bewertete Befunde</h2></div><div class="table-wrap"><table class="table">
          <thead><tr><th scope="col">Bewertung</th><th scope="col">Befund</th><th scope="col" class="col-hide-sm">Begründung</th></tr></thead>
          <tbody>${verdicts.map((v) => {
            const f = findById(v.finding_id);
            const ai = AI[v.verdict] || { label: v.verdict, st: "neutral", icon: "ai" };
            return `<tr class="${f ? "row-click" : ""}" ${f ? `data-open="${esc(f.id)}" tabindex="0"` : ""}><td class="nowrap"><span class="badge st-${ai.st}">${icon(ai.icon)}${esc(ai.label)}</span><div class="muted small tnum" style="margin-top:4px">${Math.round((v.confidence || 0) * 100)} %</div></td>
              <td><div class="f-title">${esc(v.title || (f && f.title) || v.finding_id)}</div><div class="f-sub">${esc(v.subject || (f && f.subject) || "")}</div></td>
              <td class="col-hide-sm small" style="color:var(--text-2)">${esc((v.reasoning || "").slice(0, 260))}${(v.reasoning || "").length > 260 ? " …" : ""}</td></tr>`;
          }).join("")}</tbody></table></div></section>` : ""}
        <p class="muted small">Die KI-Bewertung ersetzt keine forensische Analyse. Nichts löschen, bevor ein Befund verifiziert und gesichert ist.</p>
      </div>`;
  }

  // ================================================================ view: settings & help
  function renderSettings() {
    const el = $("#view-settings");
    const r = S.report;
    const srv = (S.status && S.status.options) || {};
    const saved = store.get("ecomsec.scanOptions", null);
    const val = (k, d) => (saved && saved[k] !== undefined ? saved[k] : d);
    const theme = root.getAttribute("data-theme") || "";
    const exp = [["json", "JSON", "maschinenlesbar, vollständig"], ["html", "HTML", "eigenständiger Bericht"], ["markdown", "Markdown", "für Tickets und PRs"], ["sarif", "SARIF", "Code Scanning"], ["junit", "JUnit-XML", "CI-Systeme"], ["text", "Text", "wie im Terminal"]];
    const tb = srv.time_budget_ms ? `${Math.round(srv.time_budget_ms / 1000)}s` : "";
    el.innerHTML = `${pageHead("settings", "Scan-Optionen, Darstellung, Export und Hilfe.")}
      <div class="grid grid-2" style="align-items:start">
        <div class="stack">
          <section class="card" aria-labelledby="h-scanopts"><div class="card-head"><h2 id="h-scanopts">${icon("scan")}Scan-Optionen</h2><span class="sub">für Scans aus dem Dashboard</span></div>
            <form id="scanOptsForm" class="stack" novalidate>
              <label class="check check-top"><input type="checkbox" name="online" ${val("online", !!srv.online) ? "checked" : ""}><span><b>Online-Abgleich (OSV.dev)</b><br><span class="muted small">Sendet Paketnamen und -versionen an OSV.dev. Alle anderen Prüfungen laufen offline.</span></span></label>
              <label class="check check-top"><input type="checkbox" name="skip_remote" ${val("skip_remote", !!srv.skip_remote) ? "checked" : ""}><span><b>Datenbank-/API-Prüfungen überspringen</b><br><span class="muted small">Nur das Dateisystem prüfen (entspricht <code>--skip-remote</code>).</span></span></label>
              <div class="form-grid">
                <label class="field"><span>Referenzdatum</span><input class="input" type="date" name="reference_date" value="${esc(val("reference_date", srv.reference_date || ""))}"><small>Danach geänderte ausführbare Dateien gelten als verdächtig.</small></label>
                <label class="field"><span>Zeitbudget</span><input class="input" type="text" name="time_budget" inputmode="text" placeholder="z. B. 45s oder 2m" value="${esc(val("time_budget", tb))}"><small>Leer = ohne Begrenzung; ein unvollständiger Scan wird fortgesetzt.</small></label>
              </div>
              <div class="row"><button type="submit" class="btn btn-primary" data-submit="scan">${icon("scan")}Speichern und scannen</button><button type="submit" class="btn" data-submit="save">Speichern</button><span class="spacer"></span>${saved ? `<button type="button" class="btn btn-ghost" data-action="settings-reset">${icon("undo")}Server-Standard</button>` : ""}</div>
              <p class="muted small" style="margin:0">${saved ? "Eigene Optionen aktiv (in diesem Browser gespeichert)." : "Es gelten die Optionen, mit denen <code>ecomsec serve</code> gestartet wurde."}</p>
            </form></section>
          <section class="card"><div class="card-head"><h2>${icon("sun")}Darstellung</h2></div>
            <div class="stack">
              <div class="row"><span style="min-width:110px">Farbschema</span><div class="seg" role="group" aria-label="Farbschema">
                <button type="button" data-action="theme-set" data-theme="" aria-pressed="${theme === ""}">System</button><button type="button" data-action="theme-set" data-theme="light" aria-pressed="${theme === "light"}">Hell</button><button type="button" data-action="theme-set" data-theme="dark" aria-pressed="${theme === "dark"}">Dunkel</button></div></div>
              <label class="check hide-mobile"><input type="checkbox" id="setNav" ${root.getAttribute("data-nav") === "collapsed" ? "checked" : ""}>Seitenleiste eingeklappt</label>
            </div></section>
          <section class="card"><div class="card-head"><h2>${icon("download")}Bericht exportieren</h2><span class="sub">${r ? `Scan vom ${esc(fmtShort(r.generated_at))}` : "kein Report"}</span></div>
            ${r ? `<div class="docs-links">${exp.map(([f, l, d]) => `<a href="${esc(withToken(`/api/report/export?format=${f}`))}" download><span><b>${l}</b><br><span class="muted small" style="font-weight:400">${d}</span></span>${icon("download")}</a>`).join("")}</div>` : `<p class="muted">Nach dem ersten Scan verfügbar.</p>`}</section>
          <section class="card"><div class="card-head"><h2>${icon("layers")}Integritäts-Baseline</h2></div>
            <p class="muted">Ein Hash-Manifest der Kerndateien als Vergleichsbasis für künftige Scans. Nur nach einer verifizierten, sauberen Prüfung erzeugen – sonst werden manipulierte Dateien zur Referenz.</p>
            <button type="button" class="btn" data-action="baseline">${icon("layers")}Baseline erzeugen</button></section>
        </div>
        <div class="stack">
          <section class="card"><div class="card-head"><h2>${icon("keyboard")}Tastenkürzel</h2></div>${shortcutsHtml()}</section>
          <section class="card"><div class="card-head"><h2>${icon("help")}Was dieser Scan leistet</h2></div>
            <p>Der Kompromittierungs-Check prüft eine Shop-Installation read-only auf Spuren eines Angriffs: bekannte Webshell-Namen (IOC-Listen von CISA/NSA/MITRE), seit dem Referenzdatum neue oder geänderte ausführbare Dateien inkl. Zeitstempel-Manipulation, PHP in Upload-Verzeichnissen, manipulierte Webserver-Konfiguration, verdächtige Code-Muster, CVE-spezifische Exploit-Payloads, Angriffsspuren in E-Mail-Historie und Logs sowie die Shop-Integrität (Patch-Status, Admin-Konten, Zahlungsempfänger, Dateirechte, Fremdcode).</p>
            <p class="muted" style="margin:0">Der Scan ist eine Triage-Hilfe und ersetzt keine forensische Analyse. Ein sauberes Ergebnis ist keine Garantie für einen nicht kompromittierten Shop.</p></section>
          <section class="card"><div class="card-head"><h2>${icon("warn")}Einschränkungen dieses Scans</h2></div>
            ${r ? (r.limitations.length ? `<ul class="ol">${r.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>` : `<p class="muted" style="margin:0">Keine – alle Prüfungen wurden ausgeführt.</p>`) : `<p class="muted" style="margin:0">Noch kein Scan.</p>`}</section>
          <section class="card"><div class="card-head"><h2>${icon("crit")}Im Notfall</h2></div>
            <ol class="ol">
              <li>Shop nicht sofort abschalten – kritische Befunde zuerst verifizieren (Empfehlungen, Gruppe „Zuerst prüfen“).</li>
              <li>Bestätigte Fremddateien sichern (Forensik), dann entfernen; alle Zugangsdaten rotieren.</li>
              <li>Patch einspielen, Baseline erzeugen, Scan wöchentlich wiederholen. Eine Web Application Firewall reduziert die Angriffsfläche.</li>
              <li>Bei Datenabfluss: Meldepflicht nach DSGVO Art. 33 (72 Stunden) prüfen.</li>
            </ol></section>
          <section class="card"><div class="card-head"><h2>${icon("book")}Über ecomsec</h2><span class="sub">Version ${esc((S.status && S.status.version) || "")}</span></div>
            <p class="muted">Read-only, ohne externe Dienste. Das Dashboard lädt keine Ressourcen aus dem Internet; Links unten öffnen die Dokumentation auf GitHub.</p>
            <div class="docs-links">
              ${[["README.md", "Handbuch"], ["docs/MONITORING.md", "Überwachung"], ["docs/AUDIT.md", "KI-Audit"], ["docs/CI.md", "CI & Score"], ["docs/RULES.md", "Regeln"], ["docs/ARCHITECTURE.md", "Architektur"]].map(([p, l]) => `<a href="${DOCS}${p}" target="_blank" rel="noopener noreferrer">${icon("book")}<span>${l}</span>${icon("ext")}</a>`).join("")}
            </div></section>
        </div>
      </div>`;
    const form = $("#scanOptsForm", el);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      const tbv = String(fd.get("time_budget") || "").trim();
      if (tbv && !/^\d+(\.\d+)?\s*(ms|s|m|h)?$/.test(tbv)) {
        toast("Zeitbudget bitte als Zahl mit Einheit angeben, z. B. 45s oder 2m.", "err");
        form.time_budget.focus();
        return;
      }
      store.set("ecomsec.scanOptions", { online: fd.get("online") === "on", skip_remote: fd.get("skip_remote") === "on", reference_date: String(fd.get("reference_date") || ""), time_budget: tbv });
      const scan = e.submitter && e.submitter.dataset.submit === "scan";
      toast("Scan-Optionen gespeichert", "ok");
      renderSettings();
      if (scan) startScan();
    });
    const nav = $("#setNav", el);
    if (nav) nav.addEventListener("change", () => setNavCollapsed(nav.checked));
  }
  function shortcutsHtml() {
    const k = (...keys) => keys.map((x) => `<kbd>${x}</kbd>`).join(" ");
    return `<dl class="shortcut-list">
      <dt>${k("/")}</dt><dd>Befunde durchsuchen</dd>
      <dt>${k("g")} ${k("o")}</dt><dd>Übersicht</dd><dt>${k("g")} ${k("b")}</dt><dd>Befunde</dd><dt>${k("g")} ${k("i")}</dt><dd>Shop-Integrität</dd>
      <dt>${k("g")} ${k("e")}</dt><dd>Empfehlungen</dd><dt>${k("g")} ${k("v")}</dt><dd>Verlauf</dd><dt>${k("g")} ${k("k")}</dt><dd>KI-Audit</dd><dt>${k("g")} ${k("s")}</dt><dd>Einstellungen &amp; Hilfe</dd>
      <dt>${k("j")} ${k("k")}</dt><dd>Nächster / vorheriger Befund (in der Detailansicht)</dd>
      <dt>${k("↑")} ${k("↓")} ${k("Enter")}</dt><dd>In der Befundliste bewegen und öffnen</dd>
      <dt>${k("x")}</dt><dd>Befund in der Liste auswählen</dd>
      <dt>${k("t")}</dt><dd>Hell/Dunkel umschalten</dd>
      <dt>${k("Esc")}</dt><dd>Detailansicht oder Dialog schließen</dd>
      <dt>${k("?")}</dt><dd>Diese Übersicht</dd></dl>`;
  }
  function showHelp() {
    openModal({ title: "Tastenkürzel", body: shortcutsHtml() });
  }
  function confirmBaseline() {
    openModal({
      title: "Integritäts-Baseline erzeugen",
      body: `<p style="margin:0">Erzeugt ein Hash-Manifest der Kerndateien im State-Verzeichnis. Künftige Scans melden jede Abweichung davon.</p>
        <div class="note n-warn">${icon("warn")}<span>Nur ausführen, wenn die Installation geprüft und sauber ist – sonst werden manipulierte Dateien zur Referenz. Eine bestehende Baseline wird ersetzt.</span></div>`,
      confirm: "Baseline erzeugen",
      onConfirm: async () => {
        const res = await api("/api/baseline", { method: "POST" });
        toast(`Baseline mit ${fmtNum(res.files)} Dateien erzeugt – wirksam ab dem nächsten Scan`, "ok", { label: "Jetzt scannen", fn: startScan });
      },
    });
  }

  // ================================================================ global events
  function onClick(e) {
    const t = e.target.closest("[data-action], [data-modal], tr[data-hist], tr[data-open]");
    if (!t) return;
    if (t.dataset.modal) {
      if (t.dataset.modal === "confirm") confirmModal(t);
      else closeModal();
      return;
    }
    if (t.dataset.hist) {
      selectHistory(t.dataset.hist);
      return;
    }
    if (t.dataset.open) {
      openDrawer(t.dataset.open);
      return;
    }
    const a = t.dataset.action;
    switch (a) {
      case "scan": startScan(); break;
      case "retry": loadAll(); break;
      case "open-finding": openDrawer(t.dataset.id); break;
      case "goto-findings": applyPreset(t.dataset.preset || "all"); closeDrawer(true); navigate("findings"); break;
      case "goto-rec": S.flashRec = t.dataset.key; closeDrawer(true); navigate("recommendations"); break;
      case "show-drivers": showDrivers(); break;
      case "drawer-close": closeDrawer(); break;
      case "drawer-prev": drawerStep(-1); break;
      case "drawer-next": drawerStep(1); break;
      case "accept-one": confirmAccept([t.dataset.id], "Als unbedenklich markieren"); break;
      case "unaccept-one": doUnaccept([t.dataset.id]); break;
      case "accept-dir": confirmAccept(openInDir(t.dataset.dir), `Verzeichnis ${t.dataset.dir} als unbedenklich markieren`); break;
      case "accept-rule": confirmAccept(openWithRule(t.dataset.rule), `Regel ${t.dataset.rule} als unbedenklich markieren`); break;
      case "filter-rule": applyPreset(`rule:${t.dataset.rule}`); S.f.state.clear(); closeDrawer(true); navigate("findings"); break;
      case "filter-dir": applyPreset(`dir:${t.dataset.dir}`); S.f.state.clear(); closeDrawer(true); navigate("findings"); break;
      case "bulk-accept": confirmAccept([...S.selected], `${plural([...S.selected].filter((id) => { const f = findById(id); return f && !f.accepted; }).length, "Befund", "Befunde")} als unbedenklich markieren`); break;
      case "bulk-unaccept": doUnaccept([...S.selected].filter((id) => { const f = findById(id); return f && f.accepted; })); break;
      case "bulk-clear": S.selected.clear(); renderFindingsBody(); break;
      case "select-all-filtered": S.lastList.forEach((f) => S.selected.add(f.id)); renderFindingsBody(); break;
      case "copy": copyText(t.dataset.copy || ""); break;
      case "clear-filters": resetFilters(); renderFindingsBody(); break;
      case "remove-filter": S.f[t.dataset.key].delete(t.dataset.val); S.page = 0; renderFindingsBody(); break;
      case "remove-search": S.f.q = ""; $("#fSearch").value = ""; renderFindingsBody(); break;
      case "remove-idfilter": S.idFilter = null; renderFindingsBody(); break;
      case "page": S.page = Number(t.dataset.page) || 0; renderFindingsBody(); $("#fTable").scrollIntoView({ block: "start" }); break;
      case "facet-more": S.facetMore[t.dataset.key] = !S.facetMore[t.dataset.key]; renderFindingsBody(); break;
      case "facet-toggle": S.facetsOpen = !S.facetsOpen; t.setAttribute("aria-expanded", String(S.facetsOpen)); $("#facets").classList.toggle("open", S.facetsOpen); break;
      case "rec-hide-done": S.hideDone = !S.hideDone; store.set("ecomsec.recs.hideDone", S.hideDone); renderRecs(); break;
      case "rec-reset": store.set(`ecomsec.recs.${targetKey()}`, []); renderRecs(); renderShell(); toast("Erledigt-Markierungen zurückgesetzt"); break;
      case "rec-findings": {
        const rec = findRec(t.dataset.key);
        if (rec) {
          resetFilters();
          S.f.state.clear();
          S.idFilter = { label: `Empfehlung: ${rec.it.title.slice(0, 40)}${rec.it.title.length > 40 ? " …" : ""}`, ids: new Set(rec.it.related) };
          navigate("findings");
        }
        break;
      }
      case "baseline": confirmBaseline(); break;
      case "theme-set": setTheme(t.dataset.theme); break;
      case "settings-reset": store.set("ecomsec.scanOptions", null); renderSettings(); toast("Server-Standard wiederhergestellt"); break;
      default: break;
    }
  }
  function showDrivers() {
    const r = S.report;
    openModal({
      title: "Faktoren des Sicherheitsniveaus",
      body: `<p class="muted" style="margin:0">Ausgangswert 100 Punkte; jeder Faktor zieht Punkte ab. Offene kritische Befunde begrenzen den Score auf höchstens 49, Warnungen auf 89.</p>
        <ul class="list">${(r.score_drivers || []).map((d) => `<li><span class="grow">${esc(d.label)}</span><b class="tnum">−${d.points}</b></li>`).join("")}</ul>`,
    });
  }
  function onChange(e) {
    const t = e.target;
    if (t.dataset.rec) {
      setDone(t.dataset.rec, t.checked);
      const item = t.closest(".rec-item");
      if (S.hideDone && t.checked) renderRecs();
      else {
        if (item) item.classList.toggle("done", t.checked);
        renderRecsProgress();
      }
      renderShell();
      if (t.checked) toast("Als erledigt markiert", "ok", { label: "Rückgängig", fn: () => { setDone(t.dataset.rec, false); renderRecs(); renderShell(); } });
    }
  }
  function renderRecsProgress() {
    // Cheap full re-render keeps counters consistent; focus is restored.
    const key = document.activeElement && document.activeElement.dataset && document.activeElement.dataset.rec;
    renderRecs();
    if (key) {
      const el = $$("#view-recommendations [data-rec]").find((x) => x.dataset.rec === key);
      if (el) el.focus({ preventScroll: true });
    }
  }
  let gAt = 0;
  function onKey(e) {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    const modalOpen = !$("#modal").hidden;
    if (modalOpen) {
      if (e.key === "Escape") {
        e.preventDefault();
        closeModal();
      } else if (e.key === "Tab") trapFocus(e, $(".modal"));
      else if (e.key === "Enter" && e.target.tagName !== "TEXTAREA" && e.target.tagName !== "BUTTON") {
        const c = $("[data-modal='confirm']");
        if (c) {
          e.preventDefault();
          confirmModal(c);
        }
      }
      return;
    }
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.target.isContentEditable;
    if (e.key === "Escape") {
      if (typing && e.target.id === "fSearch" && e.target.value) return;
      if (S.drawerId) {
        e.preventDefault();
        closeDrawer();
      } else if ($("#sidebar").classList.contains("open")) setMobileNav(false);
      else if (typing) e.target.blur();
      return;
    }
    if (typing) return;
    if (gAt && Date.now() - gAt < 1500) {
      gAt = 0;
      const map = { o: "overview", u: "overview", b: "findings", f: "findings", i: "integrity", e: "recommendations", r: "recommendations", v: "history", h: "history", k: "audit", a: "audit", s: "settings" };
      if (map[e.key]) {
        e.preventDefault();
        closeDrawer(true);
        navigate(map[e.key]);
      }
      return;
    }
    switch (e.key) {
      case "g": gAt = Date.now(); break;
      case "/":
        e.preventDefault();
        if (S.view !== "findings") navigate("findings");
        setTimeout(() => {
          const s = $("#fSearch");
          if (s) {
            s.focus();
            s.select();
          }
        }, 30);
        break;
      case "?": e.preventDefault(); showHelp(); break;
      case "t": toggleTheme(); break;
      case "j": if (S.drawerId) { e.preventDefault(); drawerStep(1); } else if (S.view === "findings") { e.preventDefault(); moveRow(1); } break;
      case "k": if (S.drawerId) { e.preventDefault(); drawerStep(-1); } else if (S.view === "findings") { e.preventDefault(); moveRow(-1); } break;
      default: break;
    }
  }

  // ================================================================ init
  function init() {
    document.addEventListener("click", onClick);
    document.addEventListener("change", onChange);
    document.addEventListener("keydown", onKey);
    // Copy buttons for evidence read the text from the DOM (no escaping issues).
    document.addEventListener("click", (e) => {
      const b = e.target.closest("[data-copy-ev]");
      if (b) copyText($("pre", b.closest(".evidence")).textContent);
    });
    document.addEventListener("keydown", (e) => {
      const tr = e.target.closest && e.target.closest("tr[data-hist], tr[data-open]");
      if (tr && e.target === tr && (e.key === "Enter" || e.key === " ")) {
        e.preventDefault();
        tr.click();
      }
    });
    $("#scanBtn").addEventListener("click", startScan);
    $("#themeToggle").addEventListener("click", toggleTheme);
    $("#helpBtn").addEventListener("click", showHelp);
    $("#navCollapse").addEventListener("click", () => setNavCollapsed(root.getAttribute("data-nav") !== "collapsed"));
    $("#navOpen").addEventListener("click", () => setMobileNav(!$("#sidebar").classList.contains("open")));
    $("#navScrim").addEventListener("click", () => setMobileNav(false));
    $("#drawerScrim").addEventListener("click", () => closeDrawer());
    $("#modal").addEventListener("mousedown", (e) => {
      if (e.target.id === "modal") closeModal();
    });
    $("#drawer").addEventListener("keydown", (e) => {
      if (e.key === "Tab" && window.innerWidth <= 760) trapFocus(e, $("#drawer"));
    });
    if (mqDark && mqDark.addEventListener) mqDark.addEventListener("change", () => setTheme(root.getAttribute("data-theme") || ""));
    window.addEventListener("hashchange", route);
    // Legacy deep links (?tab=scan|integrity|recs|help) and ?view=…
    const legacy = { scan: "findings", integrity: "integrity", recs: "recommendations", help: "settings" };
    const qv = QUERY.get("view") || legacy[QUERY.get("tab")];
    if (qv && !location.hash && VIEWS[qv]) history.replaceState(null, "", `#/${qv}`);
    route();
    renderShell();
    api("/api/status").then((s) => {
      S.status = s;
      renderShell();
      renderScanState();
      if (s.running) schedulePoll(500);
      if (S.view === "settings") renderSettings();
    }).catch(() => {});
    loadAll().then(() => {
      // Deep link to a finding (#/findings/<id>) once data is there.
      const { view, arg } = parseHash();
      if (view === "findings" && arg && !S.drawerId) openDrawer(arg);
    });
    setInterval(renderShell, 60000);
  }
  init();
})();
