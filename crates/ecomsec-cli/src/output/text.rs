//! Terminal report renderer (German).
//!
//! Layout for 60–120 columns: a header card with verdict, score and scan
//! metadata, findings grouped by severity, compact integrity/advisory
//! tables, a numbered recommendation checklist and a footer with the next
//! commands.  Unicode box drawing is used on UTF-8 locales; otherwise (and
//! with `NO_COLOR`) the renderer falls back to plain ASCII.  Colours are
//! only emitted when the caller asks for them (TTY, no `NO_COLOR`).

use ecomsec_core::finding::Finding;
use ecomsec_core::platform::{IntegrityStatus, PatchState};
use ecomsec_core::{Grade, Report, Severity, Verdict};
use std::fmt::Write;

/// Narrowest and widest layout; wider terminals still get 120 columns so
/// lines stay readable.
pub const MIN_WIDTH: usize = 60;
pub const MAX_WIDTH: usize = 120;
pub const DEFAULT_WIDTH: usize = 100;

/// Rendering options.  [`TextOptions::detect`] derives them from the
/// environment; tests construct them directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextOptions {
    /// Show informational findings too (`--all`).
    pub show_all: bool,
    /// Emit ANSI colours.
    pub color: bool,
    /// Use Unicode box drawing and symbols (else ASCII).
    pub unicode: bool,
    /// Layout width in columns (clamped to [`MIN_WIDTH`]..=[`MAX_WIDTH`]).
    pub width: usize,
}

impl TextOptions {
    pub fn detect(show_all: bool, color: bool) -> Self {
        let env = |k: &str| std::env::var(k).ok();
        TextOptions {
            show_all,
            color,
            unicode: unicode_from_env(env),
            width: width_from(terminal_columns(), env("COLUMNS").as_deref()),
        }
    }
}

/// Columns of the terminal attached to stdout, if any.
fn terminal_columns() -> Option<usize> {
    terminal_size::terminal_size().map(|(w, _)| w.0 as usize)
}

/// Layout width: the terminal width, else `$COLUMNS`, else 100 – clamped.
pub fn width_from(terminal: Option<usize>, columns_env: Option<&str>) -> usize {
    terminal
        .filter(|w| *w > 0)
        .or_else(|| columns_env.and_then(|c| c.trim().parse::<usize>().ok()))
        .filter(|w| *w > 0)
        .unwrap_or(DEFAULT_WIDTH)
        .clamp(MIN_WIDTH, MAX_WIDTH)
}

/// Unicode output only on a UTF-8 locale (POSIX precedence `LC_ALL` >
/// `LC_CTYPE` > `LANG`) and without `NO_COLOR`.
pub fn unicode_from_env(get: impl Fn(&str) -> Option<String>) -> bool {
    if get("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    let locale = ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|k| get(k).filter(|v| !v.is_empty()));
    locale.is_some_and(|l| {
        let l = l.to_ascii_lowercase();
        l.contains("utf-8") || l.contains("utf8")
    })
}

/// Render with options detected from the environment.
pub fn render(report: &Report, show_all: bool, color: bool) -> String {
    render_with(report, &TextOptions::detect(show_all, color))
}

// ------------------------------------------------------------------ glyphs

struct Glyphs {
    h: &'static str,
    v: &'static str,
    tl: &'static str,
    tr: &'static str,
    bl: &'static str,
    br: &'static str,
    heavy: &'static str,
    gutter: &'static str,
    bullet: &'static str,
    arrow: &'static str,
    dot: &'static str,
    ok: &'static str,
    warn: &'static str,
    crit: &'static str,
    unknown: &'static str,
    accepted: &'static str,
    full: &'static str,
    empty: &'static str,
    checkbox: &'static str,
    ellipsis: &'static str,
    minus: &'static str,
}

const UNICODE: Glyphs = Glyphs {
    h: "─",
    v: "│",
    tl: "╭",
    tr: "╮",
    bl: "╰",
    br: "╯",
    heavy: "━",
    gutter: "▌",
    bullet: "•",
    arrow: "›",
    dot: "·",
    ok: "✔",
    warn: "▲",
    crit: "✖",
    unknown: "?",
    accepted: "○",
    full: "█",
    empty: "░",
    checkbox: "☐",
    ellipsis: "…",
    minus: "−",
};

const ASCII: Glyphs = Glyphs {
    h: "-",
    v: "|",
    tl: "+",
    tr: "+",
    bl: "+",
    br: "+",
    heavy: "=",
    gutter: "|",
    bullet: "*",
    arrow: ">",
    dot: "-",
    ok: "+",
    warn: "!",
    crit: "x",
    unknown: "?",
    accepted: "o",
    full: "#",
    empty: ".",
    checkbox: "[ ]",
    ellipsis: "...",
    minus: "-",
};

// ------------------------------------------------------------------ style

struct Style {
    color: bool,
}

#[derive(Clone, Copy)]
enum Tone {
    Crit,
    Warn,
    Ok,
    Info,
}

impl Style {
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.color && !s.is_empty() {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    fn fg(&self, tone: Tone, s: &str) -> String {
        match tone {
            Tone::Crit => self.wrap("1;31", s),
            Tone::Warn => self.wrap("1;33", s),
            Tone::Ok => self.wrap("1;32", s),
            Tone::Info => self.wrap("1;34", s),
        }
    }
    /// Text on a coloured background (badges, verdict bar).
    fn bg(&self, tone: Tone, s: &str) -> String {
        match tone {
            Tone::Crit => self.wrap("1;97;41", s),
            Tone::Warn => self.wrap("1;30;43", s),
            Tone::Ok => self.wrap("1;30;42", s),
            Tone::Info => self.wrap("1;97;44", s),
        }
    }
}

fn sev_tone(s: Severity) -> Tone {
    match s {
        Severity::Critical => Tone::Crit,
        Severity::Warning => Tone::Warn,
        Severity::Info => Tone::Info,
    }
}

fn sev_badge(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "KRITISCH",
        Severity::Warning => "WARNUNG",
        Severity::Info => "HINWEIS",
    }
}

fn grade_tone(g: Grade) -> Tone {
    match g {
        Grade::A | Grade::B => Tone::Ok,
        Grade::C | Grade::D => Tone::Warn,
        Grade::F => Tone::Crit,
    }
}

// ------------------------------------------------------------------ text helpers

/// Visible width of a string (ANSI escapes are ignored).
pub fn visible_width(s: &str) -> usize {
    let mut n = 0;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            n += 1;
        }
    }
    n
}

/// Truncate plain text to `width` columns, ending with `ellipsis`.
pub fn truncate(s: &str, width: usize, ellipsis: &str) -> String {
    if s.chars().count() <= width {
        return s.to_string();
    }
    let keep = width.saturating_sub(ellipsis.chars().count());
    let mut t: String = s.chars().take(keep).collect();
    t.push_str(ellipsis);
    t
}

/// Greedy word wrap; words longer than `width` are hard-broken.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(8);
    let mut lines = Vec::new();
    let mut cur = String::new();
    let mut cur_len = 0;
    for word in text.split_whitespace() {
        let mut word: Vec<char> = word.chars().collect();
        while word.len() > width {
            if cur_len > 0 {
                lines.push(std::mem::take(&mut cur));
                cur_len = 0;
            }
            lines.push(word.drain(..width).collect());
        }
        if word.is_empty() {
            continue;
        }
        if cur_len > 0 && cur_len + 1 + word.len() > width {
            lines.push(std::mem::take(&mut cur));
            cur_len = 0;
        }
        if cur_len > 0 {
            cur.push(' ');
            cur_len += 1;
        }
        cur.extend(word.iter());
        cur_len += word.len();
    }
    if cur_len > 0 {
        lines.push(cur);
    }
    lines
}

/// Wrap and cap at `max_lines`, marking the cut with an ellipsis.
fn wrap_max(text: &str, width: usize, max_lines: usize, ellipsis: &str) -> Vec<String> {
    let mut lines = wrap(text, width);
    if lines.len() > max_lines {
        lines.truncate(max_lines);
        if let Some(last) = lines.last_mut() {
            let room = width.saturating_sub(ellipsis.chars().count() + 1);
            *last = format!("{} {ellipsis}", truncate(last, room, ""));
        }
    }
    lines
}

/// Replace control characters and binary garbage in evidence excerpts.
fn printable(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\t' {
                ' '
            } else if c.is_control() || c == '\u{fffd}' {
                '.'
            } else {
                c
            }
        })
        .collect()
}

fn pad(s: &str, width: usize) -> String {
    let n = visible_width(s);
    format!("{s}{}", " ".repeat(width.saturating_sub(n)))
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

// ------------------------------------------------------------------ renderer

struct Out<'a> {
    buf: String,
    st: Style,
    g: &'a Glyphs,
    w: usize,
}

impl Out<'_> {
    fn line(&mut self, s: &str) {
        let _ = writeln!(self.buf, "{s}");
    }
    fn blank(&mut self) {
        self.buf.push('\n');
    }
    /// `━━ TITLE ━━━━━━━━━━━━━━━━━━ info ━━`
    fn section(&mut self, title: &str, info: &str) {
        let g = self.g;
        let left = format!("{}{} {} ", g.heavy, g.heavy, title);
        let right = if info.is_empty() {
            format!("{}{}", g.heavy, g.heavy)
        } else {
            format!(" {info} {}{}", g.heavy, g.heavy)
        };
        let fill = self
            .w
            .saturating_sub(visible_width(&left) + visible_width(&right));
        let text = format!("{left}{}{right}", g.heavy.repeat(fill));
        self.blank();
        let styled = self.st.bold(&text);
        self.line(&styled);
    }
    /// A row inside the header card: `│ content… │`.
    fn card_row(&mut self, content: &str) {
        let inner = self.w - 4;
        let v = self.st.dim(self.g.v);
        let row = format!("{v} {} {v}", pad(content, inner));
        self.line(&row);
    }
}

pub fn render_with(report: &Report, opts: &TextOptions) -> String {
    let g = if opts.unicode { &UNICODE } else { &ASCII };
    let mut o = Out {
        buf: String::new(),
        st: Style { color: opts.color },
        g,
        w: opts.width.clamp(MIN_WIDTH, MAX_WIDTH),
    };
    header(&mut o, report);
    findings(&mut o, report, opts.show_all);
    integrity(&mut o, report);
    advisories(&mut o, report);
    recommendations(&mut o, report);
    limitations(&mut o, report);
    next_steps(&mut o, report);
    let note = o.st.dim(&wrap(
        "Hinweis: Dieser Scan ist eine Triage-Hilfe und ersetzt keine forensische Analyse. Ein sauberes Ergebnis ist keine Garantie.",
        o.w,
    )
    .join("\n"));
    o.blank();
    o.line(&note);
    o.buf
}

// ------------------------------------------------------------------ header card

fn target_of(report: &Report) -> String {
    report
        .platform
        .root
        .as_ref()
        .map(|p| p.display().to_string())
        .or_else(|| report.platform.target.clone())
        .unwrap_or_default()
}

fn header(o: &mut Out, report: &Report) {
    let g = o.g;
    let inner = o.w - 4;
    let version = report
        .platform
        .version
        .as_ref()
        .map(|v| v.to_string())
        .unwrap_or_else(|| "unbekannt".into());

    // ╭─ ecomsec Security Scan ───────────── JTL-Shop 5 · 5.3.1 ─╮
    let title = " ecomsec Security Scan ";
    let right = truncate(
        &format!(" {} {} {} ", report.platform.name, g.dot, version),
        inner / 2,
        g.ellipsis,
    );
    let fill =
        o.w.saturating_sub(2 + 1 + title.chars().count() + right.chars().count() + 1);
    let top = format!(
        "{}{}{}{}{}{}{}",
        o.st.dim(&format!("{}{}", g.tl, g.h)),
        o.st.bold(title),
        o.st.dim(&g.h.repeat(fill)),
        right,
        o.st.dim(g.h),
        o.st.dim(g.tr),
        ""
    );
    o.line(&top);
    o.card_row("");

    // Verdict bar.
    let (tone, badge) = match report.verdict {
        Verdict::Critical => (Tone::Crit, "KRITISCH"),
        Verdict::Warning => (Tone::Warn, "WARNUNG"),
        Verdict::Clean => (Tone::Ok, "OK"),
    };
    let bar_text = if o.st.color {
        format!(" {badge} {} {}", g.dot, report.verdict.label())
    } else {
        format!("[ {badge} ] {}", report.verdict.label())
    };
    let bar_text = truncate(&bar_text, inner, g.ellipsis);
    let bar = if o.st.color {
        o.st.bg(tone, &pad(&bar_text, inner))
    } else {
        bar_text
    };
    o.card_row(&bar);
    if !report.summary.complete {
        let t = o.st.fg(
            Tone::Warn,
            &truncate(
                "Scan unvollständig – Zeitbudget erschöpft, bitte erneut starten.",
                inner,
                g.ellipsis,
            ),
        );
        o.card_row(&t);
    }
    o.card_row("");

    // Key-value rows.
    const KEY: usize = 19;
    let val_w = inner - KEY;
    let posture = report.posture();
    let cells = 10usize;
    let filled = ((posture.score as usize) * cells + 50) / 100;
    let meter = format!(
        "{}{}",
        o.st.fg(grade_tone(posture.grade), &g.full.repeat(filled)),
        o.st.dim(&g.empty.repeat(cells - filled))
    );
    let score = o.st.fg(
        grade_tone(posture.grade),
        &format!(
            "{}/100 {} Note {} ({})",
            posture.score,
            g.dot,
            posture.grade,
            posture.grade.label()
        ),
    );
    let mut rows: Vec<(String, Vec<String>)> = Vec::new();
    let score_line = if visible_width(&score) + 2 + cells <= val_w {
        format!("{score}  {meter}")
    } else {
        score
    };
    rows.push(("Sicherheitsniveau:".into(), vec![score_line]));
    if !posture.drivers.is_empty() {
        // One driver per line: "−48  9 kritische Befunde".
        let drivers: Vec<String> = posture
            .top_drivers()
            .iter()
            .map(|d| {
                let pts = format!("{}{}", g.minus, d.points);
                let label = truncate(&d.label, val_w.saturating_sub(6), g.ellipsis);
                format!("{} {label}", o.st.fg(Tone::Crit, &format!("{pts:>4}")))
            })
            .collect();
        rows.push(("Score-Treiber:".into(), drivers));
    }
    let wrapped = |s: &str| wrap(s, val_w);
    rows.push(("Ziel:".into(), wrapped(&target_of(report))));
    rows.push(("Version:".into(), wrapped(&version)));
    for (k, v) in &report.platform.details {
        rows.push((format!("{}:", truncate(k, KEY - 2, g.ellipsis)), wrapped(v)));
    }
    rows.push((
        "Referenzdatum:".into(),
        vec![report.reference_date.format("%d.%m.%Y").to_string()],
    ));
    rows.push((
        "Scan-Zeitpunkt:".into(),
        vec![report
            .generated_at
            .format("%d.%m.%Y %H:%M:%S UTC")
            .to_string()],
    ));
    rows.push((
        "Umfang:".into(),
        wrapped(&format!(
            "{} Dateien, {} gelesen, {:.1} s",
            report.summary.files_scanned,
            ecomsec_core::util::human_size(report.summary.bytes_scanned),
            report.summary.duration_ms as f64 / 1000.0
        )),
    ));
    let s = &report.summary;
    let counts = format!(
        "{} {d} {} {d} {} {d} {}",
        o.st.fg(Tone::Crit, &format!("{} kritisch", s.critical)),
        o.st.fg(Tone::Warn, &plural(s.warning, "Warnung", "Warnungen")),
        plural(s.info, "Hinweis", "Hinweise"),
        o.st.dim(&format!("{} unbedenklich", s.accepted)),
        d = g.dot,
    );
    let counts = if visible_width(&counts) <= val_w {
        vec![counts]
    } else {
        wrap(
            &format!(
                "{} kritisch {d} {} {d} {} {d} {} unbedenklich",
                s.critical,
                plural(s.warning, "Warnung", "Warnungen"),
                plural(s.info, "Hinweis", "Hinweise"),
                s.accepted,
                d = g.dot
            ),
            val_w,
        )
    };
    rows.push(("Befunde:".into(), counts));

    for (key, vals) in rows {
        for (i, v) in vals.iter().enumerate() {
            let k = if i == 0 {
                o.st.dim(&pad(&key, KEY))
            } else {
                " ".repeat(KEY)
            };
            o.card_row(&format!("{k}{v}"));
        }
    }
    o.card_row("");
    let bottom =
        o.st.dim(&format!("{}{}{}", g.bl, g.h.repeat(o.w - 2), g.br));
    o.line(&bottom);
}

// ------------------------------------------------------------------ findings

fn findings(o: &mut Out, report: &Report, show_all: bool) {
    let g = o.g;
    let s = &report.summary;
    let open: Vec<&Finding> = report
        .sorted_findings()
        .into_iter()
        .filter(|f| !f.accepted)
        .collect();
    let accepted: Vec<&Finding> = report.findings.iter().filter(|f| f.accepted).collect();
    let shown_open = s.critical + s.warning + if show_all { s.info } else { 0 };
    o.section(
        "BEFUNDE",
        &format!("{} offen {} {} unbedenklich", shown_open, g.dot, s.accepted),
    );
    if open
        .iter()
        .all(|f| f.severity == Severity::Info && !show_all)
    {
        o.blank();
        let msg = o.st.fg(
            Tone::Ok,
            &format!("{} Keine kritischen Befunde und keine Warnungen.", g.ok),
        );
        o.line(&msg);
    }
    for sev in [Severity::Critical, Severity::Warning, Severity::Info] {
        if sev == Severity::Info && !show_all {
            continue;
        }
        let list: Vec<&&Finding> = open.iter().filter(|f| f.severity == sev).collect();
        if list.is_empty() {
            continue;
        }
        let heading = match sev {
            Severity::Critical => "Kritisch",
            Severity::Warning => "Warnungen",
            Severity::Info => "Hinweise",
        };
        o.blank();
        let h = o.st.fg(
            sev_tone(sev),
            &format!("{} {} ({})", g.heavy, heading, list.len()),
        );
        o.line(&h);
        for f in list {
            o.blank();
            finding_block(o, f);
        }
    }
    let hidden_info = if show_all { 0 } else { s.info };
    if hidden_info > 0 {
        o.blank();
        let t = o.st.dim(&format!(
            "{} ausgeblendet {} mit --all anzeigen",
            plural(hidden_info, "Hinweis", "Hinweise"),
            g.dot
        ));
        o.line(&t);
    }
    if !accepted.is_empty() {
        o.blank();
        let h = o.st.dim(&format!(
            "{} Als unbedenklich markiert ({})",
            g.heavy,
            accepted.len()
        ));
        o.line(&h);
        for f in accepted {
            let reason = f
                .accepted_reason
                .as_deref()
                .map(|r| format!(" {} {r}", g.dot))
                .unwrap_or_default();
            let text = format!(
                "  {} #{}  {} {} {}{}",
                g.accepted, f.id, f.title, g.dot, f.subject, reason
            );
            let t = o.st.dim(&truncate(&text, o.w, g.ellipsis));
            o.line(&t);
        }
    }
}

fn finding_block(o: &mut Out, f: &Finding) {
    let g = o.g;
    let tone = sev_tone(f.severity);
    let gutter = format!("  {} ", o.st.fg(tone, g.gutter));
    let body_w = o.w - 4;

    // Line 1: badge + title (wrapped, continuation aligned after the badge).
    let badge_plain = format!(" {:<8} ", sev_badge(f.severity));
    let badge = if o.st.color {
        o.st.bg(tone, &badge_plain)
    } else {
        format!("[{}]", sev_badge(f.severity))
    };
    let badge_w = visible_width(&badge) + 1;
    let title_lines = wrap_max(&f.title, body_w - badge_w, 3, g.ellipsis);
    for (i, l) in title_lines.iter().enumerate() {
        let lead = if i == 0 {
            format!("{badge} ")
        } else {
            " ".repeat(badge_w)
        };
        let line = format!("{gutter}{lead}{}", o.st.bold(l));
        o.line(&line);
    }

    // Line 2: category · subject  #id
    let id = format!("#{}", f.id);
    let meta = format!("{} {} {}", f.category, g.dot, f.subject);
    let meta_w = body_w.saturating_sub(id.len() + 2);
    let meta = truncate(&meta, meta_w, g.ellipsis);
    let gap = body_w.saturating_sub(meta.chars().count() + id.len());
    let line = format!(
        "{gutter}{}{}{}",
        meta,
        " ".repeat(gap.max(2)),
        o.st.dim(&id)
    );
    o.line(&line);

    // Description (max 3 lines), evidence (max 2 lines), review.
    if !f.description.is_empty() {
        for l in wrap_max(&f.description, body_w, 3, g.ellipsis) {
            let line = format!("{gutter}{}", o.st.dim(&l));
            o.line(&line);
        }
    }
    for e in f.evidence.iter().take(2) {
        let e = truncate(printable(e).trim_end(), body_w - 2, g.ellipsis);
        let line = format!("{gutter}{} {e}", o.st.dim(g.arrow));
        o.line(&line);
    }
    if f.evidence.len() > 2 {
        let more = o.st.dim(&format!(
            "  (+{} weitere Belege im HTML-/JSON-Bericht)",
            f.evidence.len() - 2
        ));
        let line = format!("{gutter}{more}");
        o.line(&line);
    }
    if let Some(rv) = &f.review {
        let head = format!(
            "KI: {} ({:.0} %)",
            rv.verdict.label(),
            rv.confidence * 100.0
        );
        let rest = truncate(
            &rv.reasoning
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
            body_w.saturating_sub(head.chars().count() + 3),
            g.ellipsis,
        );
        let line = format!(
            "{gutter}{} {}",
            o.st.fg(Tone::Info, &head),
            o.st.dim(&format!("{} {rest}", g.dot))
        );
        o.line(&line);
    }
}

// ------------------------------------------------------------------ integrity

fn status_glyph(o: &Out, st: IntegrityStatus) -> String {
    let g = o.g;
    match st {
        IntegrityStatus::Ok => o.st.fg(Tone::Ok, g.ok),
        IntegrityStatus::Warning => o.st.fg(Tone::Warn, g.warn),
        IntegrityStatus::Critical => o.st.fg(Tone::Crit, g.crit),
        IntegrityStatus::Unknown => o.st.dim(g.unknown),
    }
}

fn integrity(o: &mut Out, report: &Report) {
    if report.integrity.is_empty() {
        return;
    }
    let g = o.g;
    let issues = report
        .integrity
        .iter()
        .filter(|i| {
            matches!(
                i.status,
                IntegrityStatus::Critical | IntegrityStatus::Warning
            )
        })
        .count();
    o.section(
        "SHOP-INTEGRITÄT",
        &format!(
            "{} Prüfpunkte {} {} auffällig",
            report.integrity.len(),
            g.dot,
            issues
        ),
    );
    let mut sections: Vec<&str> = Vec::new();
    for item in &report.integrity {
        if !sections.contains(&item.section.as_str()) {
            sections.push(&item.section);
        }
    }
    let label_max = (o.w * 2 / 5).max(20);
    for section in sections {
        o.blank();
        let h = o.st.bold(section);
        o.line(&h);
        let items: Vec<_> = report
            .integrity
            .iter()
            .filter(|i| i.section == section)
            .collect();
        let label_w = items
            .iter()
            .map(|i| i.label.chars().count())
            .max()
            .unwrap_or(0)
            .min(label_max);
        let value_w = o.w.saturating_sub(4 + label_w + 2).max(10);
        for item in items {
            let label = truncate(&item.label, label_w, g.ellipsis);
            let value = truncate(&item.value, value_w, g.ellipsis);
            let line = format!(
                "  {} {}  {}",
                status_glyph(o, item.status),
                pad(&label, label_w),
                value
            );
            o.line(&line);
            if let Some(d) = &item.detail {
                let d = truncate(d, o.w - 4, g.ellipsis);
                let line = format!("    {}", o.st.dim(&d));
                o.line(&line);
            }
        }
    }
}

// ------------------------------------------------------------------ advisories

fn advisories(o: &mut Out, report: &Report) {
    if report.advisories.is_empty() {
        return;
    }
    let g = o.g;
    let vulnerable = report
        .advisories
        .iter()
        .filter(|a| a.state == PatchState::Vulnerable)
        .count();
    o.section(
        "BEKANNTE SCHWACHSTELLEN",
        &format!(
            "{} geprüft {} {} verwundbar",
            report.advisories.len(),
            g.dot,
            vulnerable
        ),
    );
    o.blank();
    let id_w = report
        .advisories
        .iter()
        .map(|a| a.advisory.id.chars().count())
        .max()
        .unwrap_or(10)
        .clamp(10, 24);
    const STATE_W: usize = 17;
    let head = o.st.dim(&format!(
        "  {} {}  Schwachstelle",
        pad("Status", STATE_W),
        pad("Kennung", id_w)
    ));
    o.line(&head);
    let mut list: Vec<_> = report.advisories.iter().collect();
    let order = |s: PatchState| match s {
        PatchState::Vulnerable => 0,
        PatchState::Unknown => 1,
        PatchState::Patched => 2,
        PatchState::NotAffected => 3,
    };
    list.sort_by_key(|a| order(a.state));
    let title_w = o.w.saturating_sub(2 + STATE_W + 1 + id_w + 2).max(10);
    for a in list {
        let (tone, glyph, label) = match a.state {
            PatchState::Patched => (Tone::Ok, g.ok, "gepatcht"),
            PatchState::NotAffected => (Tone::Ok, g.ok, "nicht betroffen"),
            PatchState::Vulnerable => (Tone::Crit, g.crit, "VERWUNDBAR"),
            PatchState::Unknown => (Tone::Warn, g.unknown, "unbekannt"),
        };
        let state = o.st.fg(tone, &format!("{glyph} {label}"));
        let line = format!(
            "  {} {}  {}",
            pad(&state, STATE_W),
            pad(&truncate(&a.advisory.id, id_w, g.ellipsis), id_w),
            truncate(&a.advisory.title, title_w, g.ellipsis)
        );
        o.line(&line);
        let indent = 2 + STATE_W + 1;
        for l in wrap_max(&a.basis, o.w - indent, 2, g.ellipsis) {
            let line = format!("{}{}", " ".repeat(indent), o.st.dim(&l));
            o.line(&line);
        }
    }
}

// ------------------------------------------------------------------ recommendations

fn recommendations(o: &mut Out, report: &Report) {
    let groups: Vec<_> = report
        .recommendations
        .iter()
        .filter(|g| !g.items.is_empty())
        .collect();
    if groups.is_empty() {
        return;
    }
    let g = o.g;
    let total: usize = groups.iter().map(|g| g.items.len()).sum();
    o.section("HANDLUNGSEMPFEHLUNGEN", &plural(total, "Punkt", "Punkte"));
    let checkbox_w = g.checkbox.chars().count();
    for group in groups {
        o.blank();
        let h =
            o.st.bold(&format!("{} ({})", group.label, group.items.len()));
        o.line(&h);
        for (i, r) in group.items.iter().enumerate() {
            let num = format!("{:>3}.", i + 1);
            let prio = format!("P{}", r.priority);
            let prio_tone = match r.priority {
                0 | 1 => Tone::Crit,
                2 => Tone::Warn,
                _ => Tone::Info,
            };
            // " 1. ☐ "
            let lead_w = num.len() + 1 + checkbox_w + 1;
            let indent = " ".repeat(lead_w);
            let title_w = o.w.saturating_sub(lead_w + prio.len() + 2);
            let title_lines = wrap(&r.title, title_w);
            for (j, l) in title_lines.iter().enumerate() {
                let line = if j == 0 {
                    format!(
                        "{} {} {}  {}",
                        o.st.dim(&num),
                        g.checkbox,
                        o.st.bold(l),
                        o.st.fg(prio_tone, &prio)
                    )
                } else {
                    format!("{indent}{}", o.st.bold(l))
                };
                o.line(&line);
            }
            for l in wrap(&r.detail, o.w - lead_w) {
                let line = format!("{indent}{l}");
                o.line(&line);
            }
            if !r.related.is_empty() {
                let ids: Vec<String> = r.related.iter().map(|i| format!("#{i}")).collect();
                let label = "Befunde: ";
                let mut lines = wrap(&ids.join(" "), o.w - lead_w - label.len());
                if lines.len() > 2 {
                    lines.truncate(2);
                    if let Some(last) = lines.last_mut() {
                        last.push_str(&format!(" {}", g.ellipsis));
                    }
                }
                for (j, l) in lines.iter().enumerate() {
                    let prefix = if j == 0 {
                        label.to_string()
                    } else {
                        " ".repeat(label.len())
                    };
                    let line = format!("{indent}{}", o.st.dim(&format!("{prefix}{l}")));
                    o.line(&line);
                }
            }
        }
    }
}

// ------------------------------------------------------------------ limitations, next steps

fn limitations(o: &mut Out, report: &Report) {
    if report.limitations.is_empty() {
        return;
    }
    let g = o.g;
    o.section("EINSCHRÄNKUNGEN", "");
    o.blank();
    for l in &report.limitations {
        for (i, line) in wrap(l, o.w - 4).iter().enumerate() {
            let lead = if i == 0 { g.bullet } else { " " };
            let s = format!("  {lead} {line}");
            o.line(&s);
        }
    }
}

/// The three most useful follow-up commands for this report.
pub fn next_commands(report: &Report) -> Vec<(String, String)> {
    let target = match (&report.platform.root, &report.platform.target) {
        (Some(root), _) => format!(" --root {}", shell_quote(&root.display().to_string())),
        (None, Some(shop)) => format!(
            " --platform {} --shop {}",
            report.platform.id,
            shell_quote(shop)
        ),
        _ => String::new(),
    };
    let mut steps = Vec::new();
    let first_open = report
        .sorted_findings()
        .into_iter()
        .find(|f| !f.accepted && f.severity != Severity::Info);
    let no_baseline = report
        .integrity
        .iter()
        .any(|i| i.key == "integrity.baseline" && i.status == IntegrityStatus::Unknown);
    match first_open {
        Some(f) => steps.push((
            "Befunde prüfen, bekannte und harmlose als unbedenklich markieren".to_string(),
            format!("ecomsec findings accept{target} {} --reason \"…\"", f.id),
        )),
        None if no_baseline && report.platform.root.is_some() => steps.push((
            "Sauberen Stand als Baseline sichern".to_string(),
            format!("ecomsec baseline create{target}"),
        )),
        None => steps.push((
            "Verlauf der bisherigen Scans ansehen".to_string(),
            format!("ecomsec history{target}"),
        )),
    }
    steps.push((
        "Bericht als HTML-Datei für Agentur, Hoster oder Geschäftsführung".to_string(),
        format!("ecomsec report{target} --format html --output ecomsec-bericht.html"),
    ));
    steps.push((
        "Täglich automatisch prüfen und nur bei Änderungen benachrichtigen".to_string(),
        format!("ecomsec watch{target} --install-cron"),
    ));
    steps
}

fn shell_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-:@+".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

fn next_steps(o: &mut Out, report: &Report) {
    o.section("NÄCHSTE SCHRITTE", "");
    for (i, (what, cmd)) in next_commands(report).iter().enumerate() {
        o.blank();
        let head = format!("  {}. {}", i + 1, truncate(what, o.w - 5, o.g.ellipsis));
        o.line(&head);
        let cmd = format!(
            "     {} {}",
            o.st.dim("$"),
            o.st.fg(Tone::Info, &truncate(cmd, o.w - 7, o.g.ellipsis))
        );
        o.line(&cmd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_support::sample_report;
    use ecomsec_core::finding::{Review, ReviewVerdict};

    fn opts(width: usize, unicode: bool) -> TextOptions {
        TextOptions {
            show_all: false,
            color: false,
            unicode,
            width,
        }
    }

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| {
            pairs
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn wrap_respects_width_and_breaks_long_words() {
        let lines = wrap("eins zwei drei vier fünf sechs sieben", 12);
        assert_eq!(
            lines,
            vec!["eins zwei", "drei vier", "fünf sechs", "sieben"]
        );
        assert!(lines.iter().all(|l| l.chars().count() <= 12));
        let long = wrap("a/sehr/langer/pfad/ohne/leerzeichen/datei.php ende", 10);
        assert!(long.iter().all(|l| l.chars().count() <= 10), "{long:?}");
        assert_eq!(long.last().unwrap(), "i.php ende");
        assert!(wrap("", 20).is_empty());
    }

    #[test]
    fn wrap_max_marks_cut() {
        let lines = wrap_max("eins zwei drei vier fünf sechs", 10, 2, "…");
        assert_eq!(lines.len(), 2);
        assert!(lines[1].ends_with('…'));
        assert!(lines.iter().all(|l| l.chars().count() <= 10), "{lines:?}");
    }

    #[test]
    fn truncate_and_visible_width_ignore_ansi() {
        assert_eq!(truncate("abcdefgh", 5, "…"), "abcd…");
        assert_eq!(truncate("abcdefgh", 5, "..."), "ab...");
        assert_eq!(truncate("abc", 5, "…"), "abc");
        assert_eq!(visible_width("\x1b[1;31mrot\x1b[0m"), 3);
        assert_eq!(visible_width("Größe"), 5);
    }

    #[test]
    fn width_detection_and_clamping() {
        assert_eq!(width_from(Some(80), Some("200")), 80);
        assert_eq!(width_from(None, Some("90")), 90);
        assert_eq!(width_from(None, Some("abc")), DEFAULT_WIDTH);
        assert_eq!(width_from(None, None), DEFAULT_WIDTH);
        assert_eq!(width_from(Some(300), None), MAX_WIDTH);
        assert_eq!(width_from(Some(20), None), MIN_WIDTH);
        assert_eq!(width_from(Some(0), Some("70")), 70);
    }

    #[test]
    fn unicode_detection_from_locale() {
        assert!(unicode_from_env(env(&[("LANG", "de_DE.UTF-8")])));
        assert!(unicode_from_env(env(&[
            ("LC_ALL", "C.utf8"),
            ("LANG", "C")
        ])));
        assert!(!unicode_from_env(env(&[
            ("LC_ALL", "C"),
            ("LANG", "de_DE.UTF-8")
        ])));
        assert!(!unicode_from_env(env(&[("LANG", "C")])));
        assert!(!unicode_from_env(env(&[])));
        assert!(!unicode_from_env(env(&[
            ("LANG", "de_DE.UTF-8"),
            ("NO_COLOR", "1")
        ])));
    }

    #[test]
    fn lines_fit_the_width() {
        let report = sample_report();
        for width in [60, 80, 100, 120] {
            for unicode in [true, false] {
                let out = render_with(&report, &opts(width, unicode));
                for line in out.lines() {
                    assert!(
                        visible_width(line) <= width,
                        "width {width}, unicode {unicode}: {} > {width}: {line:?}",
                        visible_width(line)
                    );
                }
            }
        }
        // Colour codes do not change the visible layout.
        let mut colored = opts(80, true);
        colored.color = true;
        let out = render_with(&report, &colored);
        assert!(out.contains("\x1b["));
        assert!(out.lines().all(|l| visible_width(l) <= 80));
    }

    #[test]
    fn ascii_fallback_has_no_box_drawing() {
        let report = sample_report();
        let out = render_with(&report, &opts(100, false));
        for glyph in ["─", "│", "╭", "━", "▌", "✔", "✖", "█", "░", "☐"] {
            assert!(!out.contains(glyph), "unexpected {glyph:?} in ASCII output");
        }
        assert!(out.starts_with("+- ecomsec Security Scan "));
        assert!(out.contains("[ KRITISCH ] Kritische Befunde – sofort handeln"));
        assert!(out.contains("[KRITISCH] Bekannter Webshell-Dateiname: wso.php"));
        let uni = render_with(&report, &opts(100, true));
        assert!(uni.starts_with("╭─ ecomsec Security Scan "));
        assert!(uni.contains("▌"));
    }

    #[test]
    fn key_lines_snapshot() {
        let report = sample_report();
        let out = render_with(&report, &opts(100, true));
        let has = |needle: &str| assert!(out.contains(needle), "missing {needle:?} in\n{out}");
        has("│ Sicherheitsniveau: ");
        has("│ Score-Treiber:     ");
        has("│ Ziel:              /var/www/shop");
        has("│ Version:           5.3.1");
        has("│ Referenzdatum:     17.06.2026");
        has("│ Befunde:           2 kritisch · 1 Warnung · 1 Hinweis · 1 unbedenklich");
        has("━━ BEFUNDE ━━");
        has("━ Kritisch (2)");
        has("Bekannte Webshell · mediafiles/wso.php");
        has("› WSO");
        has("1 Hinweis ausgeblendet · mit --all anzeigen");
        has("━ Als unbedenklich markiert (1)");
        has("○ #");
        has("Datenbank-Dump im Webroot · backup.sql · Testdump");
        has("━━ SHOP-INTEGRITÄT ━━");
        has("  ▲ admin  aktiv · 2FA: nein · letzter Login: nie");
        has("CVE-2026-54390  Smarty-SSTI in Mailvorlagen");
        has("✖ VERWUNDBAR");
        has("━━ EINSCHRÄNKUNGEN ━━");
        has("  • Datenbank-Prüfungen übersprungen (--skip-remote).");
        has("━━ NÄCHSTE SCHRITTE ━━");
        has("$ ecomsec findings accept --root /var/www/shop ");
        has("$ ecomsec report --root /var/www/shop --format html --output ecomsec-bericht.html");
        has("$ ecomsec watch --root /var/www/shop --install-cron");
        // Info only with --all.
        assert!(!out.contains("Admin-Konto ohne Zwei-Faktor-Authentifizierung"));
        let all = render_with(
            &report,
            &TextOptions {
                show_all: true,
                ..opts(100, true)
            },
        );
        assert!(all.contains("━ Hinweise (1)"));
        assert!(all.contains("[HINWEIS]") || all.contains("Admin-Konto ohne Zwei-Faktor"));
    }

    #[test]
    fn review_and_evidence_lines() {
        let mut report = sample_report();
        report.findings[0].review = Some(Review {
            verdict: ReviewVerdict::NeedsHuman,
            confidence: 0.6,
            reasoning: "Datei   prüfen.\nKontext fehlt.".into(),
            model: "test".into(),
            reviewed_at: None,
        });
        report.findings[0].evidence = vec![
            "\u{fffd}\u{fffd}JFIF<?php system($_GET[\"c\"]);\x01".into(),
            "zwei".into(),
            "drei".into(),
        ];
        let out = render_with(&report, &opts(80, false));
        assert!(out.contains("KI: manuelle Prüfung nötig (60 %) - Datei prüfen. Kontext fehlt."));
        assert!(out.contains("> ..JFIF<?php system($_GET[\"c\"]);."));
        assert!(out.contains("(+1 weitere Belege im HTML-/JSON-Bericht)"));
    }

    #[test]
    fn next_commands_without_open_findings_suggest_baseline() {
        let mut report = sample_report();
        for f in &mut report.findings {
            f.accepted = true;
        }
        let cmds = next_commands(&report);
        assert!(cmds[0]
            .1
            .starts_with("ecomsec history --root /var/www/shop"));
        report
            .integrity
            .push(ecomsec_core::platform::IntegrityItem::new(
                "integrity.baseline",
                "Integrität",
                "Baseline",
                IntegrityStatus::Unknown,
                "keine Baseline vorhanden",
            ));
        let cmds = next_commands(&report);
        assert_eq!(cmds.len(), 3);
        assert!(cmds[0]
            .1
            .starts_with("ecomsec baseline create --root /var/www/shop"));
        assert_eq!(shell_quote("/srv/mein shop"), "'/srv/mein shop'");
    }
}
