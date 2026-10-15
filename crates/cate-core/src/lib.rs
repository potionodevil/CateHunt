// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! cate-core: Metriken (Verschachtelungstiefe, Funktionslaenge, Duplikat-Hashes),
//! Evidence-Level E0-E4, Health-Score Stub.
#[cfg(feature = "tree-sitter")]
pub mod metrics_ts;
pub mod redact;
pub mod scope;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Kompilierter Metrik-Pfad: `"tree-sitter"` (Feature an) oder
/// `"heuristic"` (Feature aus). Einzelne Aufrufe koennen trotzdem auf
/// die Heuristik zurueckfallen (Parse-Fehler → `*_heuristic`).
pub fn metrics_backend() -> &'static str {
    if cfg!(feature = "tree-sitter") {
        "tree-sitter"
    } else {
        "heuristic"
    }
}

/// Evidence-Level nach Masterplan: E0 (unbelegt) bis E4 (verifiziert/laufzeitbestaetigt).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub enum EvidenceLevel {
    #[default]
    E0,
    E1,
    E2,
    E3,
    E4,
}

impl std::fmt::Display for EvidenceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceLevel::E0 => write!(f, "E0"),
            EvidenceLevel::E1 => write!(f, "E1"),
            EvidenceLevel::E2 => write!(f, "E2"),
            EvidenceLevel::E3 => write!(f, "E3"),
            EvidenceLevel::E4 => write!(f, "E4"),
        }
    }
}

impl std::str::FromStr for EvidenceLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_uppercase().as_str() {
            "E0" => Ok(EvidenceLevel::E0),
            "E1" => Ok(EvidenceLevel::E1),
            "E2" => Ok(EvidenceLevel::E2),
            "E3" => Ok(EvidenceLevel::E3),
            "E4" => Ok(EvidenceLevel::E4),
            other => Err(format!("unknown evidence level: {other}")),
        }
    }
}

/// Metriken pro Datei/Funktion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetrics {
    pub path: String,
    pub lines: usize,
    pub max_nesting_depth: usize,
    pub functions: Vec<FunctionMetric>,
    pub duplicate_hashes: Vec<String>,
    pub evidence: EvidenceLevel,
}

/// Metrik pro Funktion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionMetric {
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub length: usize,
    pub nesting_depth: usize,
    pub evidence: EvidenceLevel,
}

/// Zaehlt die maximale Verschachtelungstiefe.
///
/// Mit Feature `tree-sitter`: Kontrollfluss-Tiefe per Grammatik
/// (Rust: `if`/`match`/`for`/`while`/`loop`; Python: `if`/`for`/`while`/
/// `try`/`with`/`match`; Funktionsrumpf = 1). Ohne Feature oder bei
/// Parse-Fehler: Heuristik ([`nesting_depth_heuristic`]).
pub fn nesting_depth(source: &str) -> usize {
    #[cfg(feature = "tree-sitter")]
    {
        // Klammern → Rust-Versuch zuerst, sonst Python zuerst;
        // je Fehlschlag die jeweils andere Sprache, dann Heuristik.
        let (first, second) = if source.contains('{') || source.contains('}') {
            (metrics_ts::TsLang::Rust, metrics_ts::TsLang::Python)
        } else {
            (metrics_ts::TsLang::Python, metrics_ts::TsLang::Rust)
        };
        if let Some(d) = metrics_ts::nesting_ts(source, first) {
            return d;
        }
        if let Some(d) = metrics_ts::nesting_ts(source, second) {
            return d;
        }
    }
    nesting_depth_heuristic(source)
}

/// Heuristik-Pfad von [`nesting_depth`] (auch Fallback bei Parse-Fehler):
/// Enthaelt die Quelle `{`/`}`, zaehlt die Klammertiefe (Rust/Go/JS/…),
/// sonst die Einrueckungs-Tiefe per Dedent-Logik (Python).
/// Klammern in Kommentaren, Strings, Raw-Strings und Char-Literalen
/// werden ignoriert (s. [`strip_rust_line`]).
pub fn nesting_depth_heuristic(source: &str) -> usize {
    if source.contains('{') || source.contains('}') {
        nesting_depth_braces(source)
    } else {
        python_nesting_depth(source)
    }
}

/// Klammer-basierte Tiefe (Rust/Go/JS-Heuristik): zaehlt `{`/`}` im
/// echten Code; Strings (inkl. Raw-/Byte-Strings), Char-Literale und
/// Kommentare (Zeile + `/* */`) traegt [`strip_rust_line`] aus.
fn nesting_depth_braces(source: &str) -> usize {
    let mut depth = 0usize;
    let mut max = 0usize;
    let mut block = 0usize; // offene /*-Kommentare ueber Zeilen hinweg
    for line in source.lines() {
        let code = strip_rust_line(line, &mut block);
        for ch in code.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    if depth > max {
                        max = depth;
                    }
                }
                '}' => {
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
        }
    }
    max
}

/// Python-Block-Schluesselwoerter, die mit `:` einen Einrueckungs-Block
/// oeffnen (`def`, `class`, `if`, Schleifen, `try`/`with`, `match`, …).
/// `async def`/`async for`/`async with` sind ueber das `async`-Praefix abgedeckt.
const PYTHON_BLOCK_KEYWORDS: &[&str] = &[
    "def", "class", "if", "elif", "else", "for", "while", "try", "except", "finally", "with",
    "match", "case",
];

/// Einrueckungsbreite = Anzahl fuehrender Leerzeichen/Tabs.
fn indent_width(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ' || *c == '\t').count()
}

/// Python-Kommentar (`#`) grob entfernen (naiv: erstes `#`).
fn strip_python_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => line[..idx].trim_end(),
        None => line,
    }
}

/// true, wenn die (eingerueckte) Zeile einen Python-Block oeffnet:
/// erstes Wort ist ein Block-Schluesselwort (nach optionalem `async `)
/// und die Zeile endet mit `:`.
fn is_python_block_opener(line: &str) -> bool {
    let code = strip_python_comment(line).trim();
    let Some(head) = code.strip_suffix(':') else {
        return false;
    };
    let first = head
        .trim()
        .strip_prefix("async ")
        .unwrap_or(head.trim())
        .split_whitespace()
        .next()
        .unwrap_or("");
    let first = first.trim_end_matches('(');
    PYTHON_BLOCK_KEYWORDS.contains(&first)
}

/// Maximale Einrueckungs-Verschachtelung fuer Python-Quellen (Dedent-Logik,
/// ohne Tree-sitter): Top-Level-Block-Rumpf (z.B. `def`-Koerper) = 1,
/// jeder weiter eingerueckte Block +1. Leer-/Kommentarzeilen zaehlen nicht
/// und beenden keinen Block.
pub fn python_nesting_depth(source: &str) -> usize {
    let mut stack: Vec<usize> = Vec::new(); // Einrueckungen offener Bloecke
    let mut max = 0usize;
    for line in source.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let indent = indent_width(line);
        while stack.last().is_some_and(|top| indent <= *top) {
            stack.pop();
        }
        if is_python_block_opener(line) {
            let depth = stack.len() + 1;
            if depth > max {
                max = depth;
            }
            stack.push(indent);
        } else if stack.len() > max {
            max = stack.len();
        }
    }
    max
}

/// Funktionslaenge in Zeilen (end - start + 1, Untergrenze 0).
pub fn function_length(start_line: usize, end_line: usize) -> usize {
    end_line.saturating_sub(start_line).saturating_add(1)
}

/// Normalisiert eine Zeile fuer Duplikat-Erkennung (trim + whitespace collapse).
pub fn normalize_line(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Hash-Schema aller Hash-Helfer in diesem Crate (`sha256`, lowercase Hex).
/// Alte 64-bit-`DefaultHasher`-Werte (16 Hex-Zeichen) gelten als Legacy
/// und treffen nie auf neue Hashes (Laengen-/Formatwechsel) — alte Caches
/// werden damit automatisch zum Miss statt zum stillen Hit.
pub const HASH_SCHEME: &str = "sha256";

/// SHA-256 ueber `input` als lowercase Hex-String (64 Zeichen).
pub fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Fingerprint = `sha256(rule_id | code_hash | CWE-normalisiert)` als Hex.
/// CWE wird getrimmt + uppercased (`cwe-328` == `CWE-328`); Trennzeichen
/// ist `|`. Signatur `-> String` wie der alte 64-bit-Stub, Werte sind
/// nicht kompatibel (16-stellige Altwerte treffen nie).
pub fn fingerprint(rule_id: &str, code_hash: &str, cwe: &str) -> String {
    sha256_hex(&format!(
        "{}|{}|{}",
        rule_id,
        code_hash,
        cwe.trim().to_uppercase()
    ))
}

/// true, wenn `s` wie ein alter 64-bit-`DefaultHasher`-Hex aussieht
/// (genau 16 Hex-Zeichen). Dient der Cache-Migration: solche Werte
/// duerfen nie als Hit gegen neue sha256-Hashes gelten.
pub fn is_legacy_hash(s: &str) -> bool {
    s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// SHA-256-Hash einer normalisierten Zeile als Hex-String (64 Zeichen).
/// Gleiche normalisierte Zeilen -> gleicher Hash (stabile
/// Gleichheitsklassen wie zuvor, nur kollisionssicherer).
pub fn hash_line(line: &str) -> String {
    sha256_hex(&normalize_line(line))
}

/// Findet duplizierte (nicht-leere) Zeilen: gibt sortierte Hash-Liste der
/// Zeilen zurueck, die mehr als einmal vorkommen.
pub fn duplicate_hashes(source: &str) -> Vec<String> {
    use std::collections::HashMap;
    let mut counts: HashMap<String, usize> = HashMap::new();
    for line in source.lines() {
        let n = normalize_line(line);
        if n.is_empty() {
            continue;
        }
        let h = hash_line(&n);
        *counts.entry(h).or_insert(0) += 1;
    }
    let mut out: Vec<String> = counts
        .into_iter()
        .filter(|(_, c)| *c > 1)
        .map(|(h, _)| h)
        .collect();
    out.sort();
    out
}

/// Scannt eine Funktionsliste.
///
/// Mit Feature `tree-sitter`: per Grammatik (Rust `fn` inkl. Methoden,
/// Python `def`/`class` inkl. Dekoratoren/verschachtelte Defs), sonst und
/// bei Parse-Fehler (fremde Sprache, kaputte Syntax): Heuristik
/// ([`scan_functions_heuristic`]).
pub fn scan_functions(source: &str) -> Vec<FunctionMetric> {
    #[cfg(feature = "tree-sitter")]
    {
        let (first, second) = if source.contains('{') || source.contains('}') {
            (metrics_ts::TsLang::Rust, metrics_ts::TsLang::Python)
        } else {
            (metrics_ts::TsLang::Python, metrics_ts::TsLang::Rust)
        };
        if let Some(f) = metrics_ts::scan_ts(source, first) {
            return f;
        }
        if let Some(f) = metrics_ts::scan_ts(source, second) {
            return f;
        }
    }
    scan_functions_heuristic(source)
}

/// Heuristik-Pfad von [`scan_functions`] (auch Fallback bei Parse-Fehler):
/// Rust `fn name(` (inkl. `pub`/`async`/`unsafe`/`const`-/`extern`-Praefixe),
/// JS/TS `function name`, Go `func name` (inkl. Receiver) per
/// Klammer-Ausgleich; Python `def name(`/`class Name` (inkl. `async`)
/// per Dedent-Logik.
pub fn scan_functions_heuristic(source: &str) -> Vec<FunctionMetric> {
    let lines: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if let Some((name, kind)) = guess_function(lines[i]) {
            let start = match kind {
                FnKind::Indent => include_decorators(&lines, i) + 1, // 1-basiert
                FnKind::Brace => i + 1,                              // 1-basiert
            };
            let end = match kind {
                FnKind::Brace => brace_function_end(&lines, i),
                FnKind::Indent => indent_function_end(&lines, i),
            };
            let slice = &lines[i..end.min(lines.len())].join("\n");
            let fn_depth = match kind {
                FnKind::Brace => nesting_depth_braces(slice),
                FnKind::Indent => python_nesting_depth(slice),
            };
            out.push(FunctionMetric {
                name,
                start_line: start,
                end_line: end,
                length: function_length(start, end),
                nesting_depth: fn_depth,
                evidence: EvidenceLevel::E0,
            });
            // Klammer-Funktionen: Rumpf ueberspringen (wie frueher).
            // Python: innen weiter suchen, damit verschachtelte `def`s
            // als eigene Eintraege auftauchen.
            i = match kind {
                FnKind::Brace => end,
                FnKind::Indent => i + 1,
            };
        } else {
            i += 1;
        }
    }
    out
}

/// Funktionsende per Klammer-Ausgleich ab Zeile `i` (1-basiert zurueck).
fn brace_function_end(lines: &[&str], i: usize) -> usize {
    let start = i + 1; // 1-basiert
    let mut depth = 0i64;
    let mut seen_open = false;
    let mut end = start;
    let mut block = 0usize;
    for (j, l) in lines.iter().enumerate().skip(i) {
        let code = strip_rust_line(l, &mut block);
        for ch in code.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    seen_open = true;
                }
                '}' => {
                    depth -= 1;
                }
                _ => {}
            }
        }
        if seen_open && depth <= 0 {
            end = j + 1;
            break;
        }
        end = j + 1;
    }
    end
}

/// Funktionsende per Dedent ab `def`/`class`-Zeile `i` (1-basiert zurueck):
/// letzte nicht-leere Zeile, die tiefer eingerueckt ist als die
/// `def`-Zeile. Leer-/Kommentarzeilen zaehlen nicht als Ende.
fn indent_function_end(lines: &[&str], i: usize) -> usize {
    let base = indent_width(lines[i]);
    let mut end = i + 1; // 1-basiert; Minimum: nur die `def`-Zeile
    for (j, l) in lines.iter().enumerate().skip(i + 1) {
        let t = l.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if indent_width(l) <= base {
            break;
        }
        end = j + 1;
    }
    end
}

/// `@`-Dekoratoren direkt ueber Zeile `i` gehoeren zur Funktion:
/// Index der ersten Dekorator-Zeile (sonst `i`).
fn include_decorators(lines: &[&str], i: usize) -> usize {
    let mut s = i;
    while s > 0 && lines[s - 1].trim_start().starts_with('@') {
        s -= 1;
    }
    s
}

/// Vollstaendige Datei-Metrik.
///
/// Mit Feature `tree-sitter`: Sprache per Dateiendung (`.py` → Python,
/// sonst Rust-Versuch), bei Parse-Fehler Heuristik. Ohne Feature und
/// fuer fremde Sprachen (Go/JS/…): immer Heuristik.
pub fn analyze_file(path: &str, source: &str) -> FileMetrics {
    #[cfg(feature = "tree-sitter")]
    {
        let lang = metrics_ts::detect_lang(path);
        let other = match lang {
            metrics_ts::TsLang::Rust => metrics_ts::TsLang::Python,
            metrics_ts::TsLang::Python => metrics_ts::TsLang::Rust,
        };
        if let Some(m) = metrics_ts::analyze_ts(path, source, lang) {
            return m;
        }
        if let Some(m) = metrics_ts::analyze_ts(path, source, other) {
            return m;
        }
    }
    analyze_file_heuristic(path, source)
}

/// Heuristik-Pfad von [`analyze_file`] (auch Fallback bei Parse-Fehler).
pub fn analyze_file_heuristic(path: &str, source: &str) -> FileMetrics {
    let fns = scan_functions_heuristic(source);
    FileMetrics {
        path: path.to_string(),
        lines: source.lines().count(),
        max_nesting_depth: nesting_depth_heuristic(source),
        functions: fns,
        duplicate_hashes: duplicate_hashes(source),
        evidence: EvidenceLevel::E0,
    }
}

/// Entfernt aus einer Rust/Go/JS-Zeile alles, was keine echte Klammer
/// sein kann: Zeilenkommentare (`//`), Blockkommentare (`/* */`,
/// nestbar), normale/`b`-/`c`-Strings, Raw-Strings (`r"…"`, `r#"…"#`,
/// `br…`) und Char-Literale (`'x'`, `'{'`, `'\\n'`).
/// `block` zaehlt offene Blockkommentare und wird vom Caller ueber die
/// Zeilen einer Datei hinweg durchgereicht. Lifetimes (`'a`, `'static`)
/// sind keine Char-Literale und bleiben unangetastet.
fn strip_rust_line(line: &str, block: &mut usize) -> String {
    let mut out = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0;
    // Restzeile ab `i` ist noch innerhalb eines Blockkommentars:
    // bis zum schliessenden `*/` (ggf. geschachtelt) ueberspringen.
    if *block > 0 && !consume_block(bytes, &mut i, block) {
        return out;
    }
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'/' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'/' {
                break; // Zeilenkommentar: Rest faellt weg
            }
            if bytes[i + 1] == b'*' {
                *block += 1;
                i += 2;
                if !consume_block(bytes, &mut i, block) {
                    break;
                }
                continue;
            }
        }
        if c == b'"' {
            skip_quoted(bytes, &mut i);
            continue;
        }
        if c == b'\'' {
            if !skip_char_literal(bytes, &mut i) {
                out.push('\''); // Lifetime o. Ae.: harmlos, kein Klammerzeichen
                i += 1;
            }
            continue;
        }
        if (c == b'r' || c == b'b' || c == b'c') && skip_prefixed_string(bytes, &mut i) {
            continue;
        }
        out.push(c as char);
        i += 1;
    }
    out
}

/// Ab `i` (nach `/*` bzw. Zeilenanfang im Kommentar): ueberspringt bis
/// `*block` wieder 0 ist. true = Kommentar in dieser Zeile geschlossen,
/// false = Zeilenende erreicht, `*block` > 0 bleibt.
fn consume_block(bytes: &[u8], i: &mut usize, block: &mut usize) -> bool {
    while *i < bytes.len() {
        if *i + 1 < bytes.len() && bytes[*i] == b'/' && bytes[*i + 1] == b'*' {
            *block += 1;
            *i += 2;
        } else if *i + 1 < bytes.len() && bytes[*i] == b'*' && bytes[*i + 1] == b'/' {
            *block -= 1; // > 0 garantiert: Rueckkehr bei 0 s. u.
            *i += 2;
            if *block == 0 {
                return true;
            }
        } else {
            *i += 1;
        }
    }
    *block == 0
}

/// Ueberspringt `"…"` mit `\"`-Escapes ab dem oeffnenden `"`.
fn skip_quoted(bytes: &[u8], i: &mut usize) {
    *i += 1; // oeffnendes "
    let mut esc = false;
    while *i < bytes.len() {
        let c = bytes[*i];
        if esc {
            esc = false;
        } else if c == b'\\' {
            esc = true;
        } else if c == b'"' {
            *i += 1;
            return;
        }
        *i += 1;
    }
}

/// Ueberspringt ein Char-Literal ab `'`. true = Literal uebersprungen,
/// false = kein Literal (Lifetime o. Ae.), Caller emittiert `'` selbst.
fn skip_char_literal(bytes: &[u8], i: &mut usize) -> bool {
    let mut j = *i + 1;
    if j >= bytes.len() {
        return false;
    }
    if bytes[j] == b'\\' {
        j += 1; // Escape: naechstes Zeichen gehoert dazu
        if j < bytes.len() && bytes[j] == b'u' {
            // `\u{...}`: bis `}` ueberspringen
            while j < bytes.len() && bytes[j] != b'}' {
                j += 1;
            }
            if j < bytes.len() {
                j += 1;
            }
        } else if bytes[j] == b'x' {
            j += 3; // `\xNN`
        } else {
            j += 1; // `\n`, `\'`, `\\`, …
        }
    } else {
        j += 1; // einzelnes Zeichen (auch `{`, `}`, `'...'`-Inhalt)
    }
    // ASCII-Annahme reicht: Nach dem Literal muss `'` folgen; bei
    // Multi-Byte-Zeichen greift der Fallback (kein Skip, harmlos).
    if j < bytes.len() && bytes[j] == b'\'' {
        *i = j + 1;
        return true;
    }
    false
}

/// Versucht ab `i` einen praefigierten String (`r"…"`, `r#"…"#`,
/// `br…"…`, `b"…"` Byte-String, `c"…"` C-String). true = uebersprungen.
fn skip_prefixed_string(bytes: &[u8], i: &mut usize) -> bool {
    let mut j = *i;
    if bytes[j] == b'b' {
        j += 1;
        if j < bytes.len() && bytes[j] == b'\'' {
            return false; // `b'x'`: Char-Pfad des Callers zustaendig
        }
        if j >= bytes.len() || (bytes[j] != b'r' && bytes[j] != b'"') {
            return false;
        }
    } else if bytes[j] == b'c' {
        j += 1;
        if j >= bytes.len() || bytes[j] != b'"' {
            return false;
        }
        let mut k = j;
        skip_quoted(bytes, &mut k);
        *i = k;
        return true;
    }
    // Hier: `r…` (ggf. nach `b`).
    if bytes[j] != b'r' {
        return false;
    }
    j += 1;
    let mut hashes = 0usize;
    while j < bytes.len() && bytes[j] == b'#' {
        hashes += 1;
        j += 1;
    }
    if j >= bytes.len() || bytes[j] != b'"' {
        return false; // z.B. Bezeichner mit `r` — kein String
    }
    j += 1; // oeffnendes "
    if hashes == 0 {
        // `r"…"` ohne Hashes: Escapes gelten wie im normalen String.
        let mut k = j;
        let mut esc = false;
        while k < bytes.len() {
            let c = bytes[k];
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                *i = k + 1;
                return true;
            }
            k += 1;
        }
        *i = k;
        return true;
    }
    // `r#"…"#`: roh bis `"` + exakt `hashes` × `#`.
    while j < bytes.len() {
        if bytes[j] == b'"' {
            let mut k = j + 1;
            let mut n = 0;
            while n < hashes && k < bytes.len() && bytes[k] == b'#' {
                n += 1;
                k += 1;
            }
            if n == hashes {
                *i = k;
                return true;
            }
        }
        j += 1;
    }
    *i = j; // unterminiert: Rest der Zeile faellt weg
    true
}

/// Erkennungsart einer Funktion: Klammer-Ausgleich (Rust/Go/JS)
/// oder Einrueckungs-Dedent (Python `def`/`class`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FnKind {
    Brace,
    Indent,
}

/// Rust-Funktionsname aus getrimmter Zeile: frisst `pub[(…)]`-, `async`-,
/// `unsafe`-, `const`- und `extern "…"`-Praefixe und matcht dann `fn name`.
/// Gibt `None` zurueck, wenn kein `fn`-Kopf vorliegt.
fn strip_rust_fn_name(t: &str) -> Option<String> {
    let mut rest = t;
    loop {
        if let Some(after_pub) = rest.strip_prefix("pub") {
            let mut chars = after_pub.chars();
            match chars.next() {
                Some('(') => {
                    // `pub(crate)` / `pub(super)` / `pub(in path)` / `pub(self)`
                    let idx = after_pub.find(')')?;
                    rest = after_pub[idx + 1..].trim_start();
                }
                Some(c) if c.is_whitespace() => rest = after_pub.trim_start(),
                _ => break, // z.B. `publish_…` — kein Sichtbarkeits-Prefix
            }
        } else if let Some(r) = strip_keyword(rest, "async") {
            rest = r;
        } else if let Some(r) = strip_keyword(rest, "unsafe") {
            rest = r;
        } else if let Some(r) = strip_keyword(rest, "const") {
            rest = r;
        } else if let Some(r) = strip_keyword(rest, "extern") {
            // `extern "C" fn …`: optionales ABI-Literal ueberspringen
            rest = r.trim_start();
            if rest.starts_with('"') {
                let end = rest[1..].find('"')?;
                rest = rest[end + 2..].trim_start();
            }
        } else {
            break;
        }
    }
    let rest = rest.strip_prefix("fn ")?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Streift `keyword` + mind. ein Leerzeichen am Anfang, sonst `None`.
/// Verhindert Fehlmatches wie `async_fn` oder `constant`.
fn strip_keyword<'a>(s: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = s.strip_prefix(keyword)?;
    if rest.starts_with(char::is_whitespace) {
        Some(rest.trim_start())
    } else {
        None
    }
}

fn guess_function(line: &str) -> Option<(String, FnKind)> {
    let t = line.trim();
    // Rust: [pub[(…)] | async | unsafe | const | extern "…"] fn name(
    // (Spike-Luege 1: `pub fn` war unsichtbar — groesste FN-Quelle.)
    if let Some(name) = strip_rust_fn_name(t) {
        return Some((name, FnKind::Brace));
    }
    // JS/TS: function name(
    if let Some(rest) = t.strip_prefix("function ") {
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
            .collect();
        if !name.is_empty() {
            return Some((name, FnKind::Brace));
        }
    }
    // Go: func name( / func (recv) name(
    if let Some(rest) = t.strip_prefix("func ") {
        let rest = rest.trim_start();
        // Receiver ueberspringen: `func (s *S) name(`
        let after_recv = if rest.starts_with('(') {
            match rest.find(')') {
                Some(idx) => rest[idx + 1..].trim_start(),
                None => rest,
            }
        } else {
            rest
        };
        let name: String = after_recv
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            return Some((name, FnKind::Brace));
        }
    }
    // Python: [async] def name( / [async] class Name
    let body = t.strip_prefix("async ").unwrap_or(t);
    if let Some(rest) = body
        .strip_prefix("def ")
        .or_else(|| body.strip_prefix("class "))
    {
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            return Some((name, FnKind::Indent));
        }
    }
    None
}

// ---- Health-Score Stub (Masterplan: Struktur / Sicherheit-nur-E2+ / Abhaengigkeiten) ----

/// Teilscores 0..100 plus E2+-Zaehllung aus Findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthScore {
    pub structure: u8,
    pub security: u8,
    pub dependencies: u8,
    pub total: u8,
    /// Anzahl Findings mit Evidence >= E2.
    pub total_e2_plus: usize,
    /// E2+-Findings gruppiert nach Level (z.B. "error", "warning").
    pub by_level: std::collections::BTreeMap<String, usize>,
}

/// Ein Finding, reduziert auf das für den Health-Score Relevante.
/// Caller (z.B. CLI) mappen ihre Finding-Typen hierher.
///
/// `provenance` ist die optionale AI-BOM-Herkunft (Spez: docs/AI_BOM.md).
/// Fehlt das Feld im JSON, wird es per serde-default zu `None`
/// (abwaertskompatibel); `None` wird beim Serialisieren weggelassen
/// (`skip_serializing_if`), damit bestehende Goldens byte-stabil bleiben.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredFinding {
    pub level: String,
    pub evidence: EvidenceLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ProvenanceRecord>,
}

impl ScoredFinding {
    /// Haengt eine Provenienz an (Builder-Stil, fuer CLI/MCP-Verdrahtung).
    pub fn with_provenance(mut self, provenance: ProvenanceRecord) -> Self {
        self.provenance = Some(provenance);
        self
    }

    /// Haengt eine Provenienz an (mutable Variante).
    pub fn attach_provenance(&mut self, provenance: ProvenanceRecord) {
        self.provenance = Some(provenance);
    }
}

/// Health-Score: Struktur aus Nesting/Laenge/Duplikaten, Security aus
/// E2+-Findings (E0/E1 zaehlen nicht), Dependencies aus der Anzahl
/// verdaechtiger Abhaengigkeiten (Caller zaehlt, z.B. Registry-Checks).
/// Level-Penalty: error=15, warning=8, note=3, sonst 8. Deps: 10 pro Treffer.
pub fn health_score(
    metrics: &[FileMetrics],
    findings: &[ScoredFinding],
    suspicious_deps: usize,
) -> HealthScore {
    let mut penalty: u32 = 0;
    for m in metrics {
        if m.max_nesting_depth > 4 {
            penalty += (m.max_nesting_depth as u32 - 4) * 5;
        }
        for f in &m.functions {
            if f.length > 50 {
                penalty += 5;
            }
        }
        penalty += (m.duplicate_hashes.len() as u32).min(10);
    }
    let structure = 100u8.saturating_sub(penalty.min(100) as u8);

    let mut by_level: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut sec_penalty: u32 = 0;
    for f in findings {
        if f.evidence < EvidenceLevel::E2 {
            continue;
        }
        *by_level.entry(f.level.clone()).or_insert(0) += 1;
        sec_penalty += match f.level.as_str() {
            "error" => 15,
            "warning" => 8,
            "note" => 3,
            _ => 8,
        };
    }
    let total_e2_plus: usize = by_level.values().sum();
    let security = 100u8.saturating_sub(sec_penalty.min(100) as u8);
    let dependencies = 100u8.saturating_sub(((suspicious_deps as u32) * 10).min(100) as u8);
    let total = ((structure as u32 + security as u32 + dependencies as u32) / 3) as u8;
    HealthScore {
        structure,
        security,
        dependencies,
        total,
        total_e2_plus,
        by_level,
    }
}

/// Stub-Kompatibilitaet: ohne Findings/Deps (Security/Deps = 100).
pub fn health_score_stub(metrics: &[FileMetrics]) -> HealthScore {
    health_score(metrics, &[], 0)
}

/// Note 0..100 -> Schulnote A/B/C/D/F (fuer Testprojekt-Fixture und UI-Anzeige).
/// Grenzen: A ab 90, B ab 75, C ab 60, D ab 40, sonst F.
pub fn health_grade(total: u8) -> &'static str {
    match total {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    }
}

// ---- AI-BOM / Provenienz (M-4, Spez: docs/AI_BOM.md) ----

/// Tool-Name im Provenienz-Record (einheitlich fuer alle Cate-Binaerprogramme).
pub const PROVENANCE_TOOL_NAME: &str = "cate";

/// Tool-Version aus der Paketversion (Compile-Zeit, `CARGO_PKG_VERSION`).
pub fn tool_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Commit-SHA, zur Buildzeit eingebettet (`cate-core/build.rs` setzt
/// `CATE_COMMIT_SHA` aus `git rev-parse HEAD`, Fallback `"unknown"` ohne
/// Git). Ein manuell gesetztes Build-Env `CATE_COMMIT_SHA` gewinnt.
/// Rueckgabe ist nie leer.
pub fn commit_sha() -> &'static str {
    match option_env!("CATE_COMMIT_SHA") {
        Some(s) if !s.is_empty() => s,
        _ => "unknown",
    }
}

/// Aktuelle UTC-Zeit als RFC-3339 (`YYYY-MM-DDTHH:MM:SSZ`), ohne externe Deps.
pub fn utc_now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix_rfc3339(secs)
}

fn format_unix_rfc3339(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (hour, min, sec) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);
    // civil_from_days (Hinnant), nur nicht-negative Tage.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Modellname zur Laufzeit: `CATE_MODEL`-Env, sonst `"unknown"`.
/// Wire-up (CLI/MCP/Backends) setzt die Variable oder nutzt direkt
/// `ProvenanceRecord::current_with_model`.
pub fn provenance_model() -> String {
    std::env::var("CATE_MODEL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// AI-BOM-Provenienz-Record: WER (Tool + Version + Modell) hat WANN
/// (UTC-Timestamp) aus WELCHEM Stand (Commit-SHA) ein Finding/Verdict erzeugt.
/// Alle Felder sind Strings; `commit_sha`/`model` fallen auf `"unknown"`
/// zurueck statt den Build/Run zu brechen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub tool_name: String,
    pub tool_version: String,
    pub model: String,
    pub commit_sha: String,
    pub timestamp: String,
}

impl ProvenanceRecord {
    /// Aktueller Record; Modell aus `CATE_MODEL`-Env (Fallback `"unknown"`).
    pub fn current() -> Self {
        Self::current_with_model(provenance_model())
    }

    /// Aktueller Record mit explizitem Modellnamen (fuer CLI/MCP-Verdrahtung).
    pub fn current_with_model(model: impl Into<String>) -> Self {
        Self {
            tool_name: PROVENANCE_TOOL_NAME.to_string(),
            tool_version: tool_version().to_string(),
            model: model.into(),
            commit_sha: commit_sha().to_string(),
            timestamp: utc_now_rfc3339(),
        }
    }
}

/// Helper fuer CLI/MCP-Verdrahtung: aktueller Record als JSON-Objekt
/// (`tool_name`, `tool_version`, `model`, `commit_sha`, `timestamp`).
/// Modell aus `CATE_MODEL`-Env, sonst `"unknown"`.
pub fn provenance_record() -> serde_json::Value {
    serde_json::to_value(ProvenanceRecord::current()).unwrap_or(serde_json::Value::Null)
}

/// Wie [`provenance_record`], mit explizitem Modellnamen.
pub fn provenance_record_for(model: &str) -> serde_json::Value {
    serde_json::to_value(ProvenanceRecord::current_with_model(model))
        .unwrap_or(serde_json::Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nesting_counts_braces() {
        let src = "fn a() {\n if x {\n while y {\n }\n }\n}\n";
        assert_eq!(nesting_depth(src), 3);
    }

    #[test]
    fn duplicates_found() {
        let src = "let x = 1;\nlet y = 2;\nlet x = 1;\n";
        assert_eq!(duplicate_hashes(src).len(), 1);
    }

    #[test]
    fn sha256_known_vector() {
        // NIST-Vektor: sha256("abc").
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(HASH_SCHEME, "sha256");
    }

    #[test]
    fn hash_line_stabil_und_normiert() {
        assert_eq!(hash_line("let x = 1;"), hash_line("  let   x  =  1;  "));
        let h = hash_line("let x = 1;");
        assert_eq!(h.len(), 64, "sha256-Hex statt 16-stelligem Stub");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!is_legacy_hash(&h), "neuer Hash darf nie Legacy sein");
    }

    #[test]
    fn fingerprint_stabil_und_cwe_normalisiert() {
        let a = fingerprint("rule", "hash", "CWE-328");
        assert_eq!(a.len(), 64);
        assert_eq!(a, fingerprint("rule", "hash", "cwe-328"));
        assert_eq!(a, fingerprint("rule", "hash", "  CWE-328  "));
        assert_ne!(a, fingerprint("other-rule", "hash", "CWE-328"));
        assert_ne!(a, fingerprint("rule", "other-hash", "CWE-328"));
        assert_ne!(a, fingerprint("rule", "hash", "CWE-79"));
    }

    #[test]
    fn migration_alt_zu_neu_ist_miss() {
        // Alt-Cache (64-bit-Stub, 16 Hex-Zeichen) trifft nie auf Neu-Werte:
        // Lookup per neuem Fingerprint findet den Legacy-Key nicht.
        use std::collections::HashMap;
        let mut cache: HashMap<String, String> = HashMap::new();
        let legacy_fp = "0123456789abcdef";
        assert!(is_legacy_hash(legacy_fp));
        cache.insert(legacy_fp.to_string(), "close".to_string());
        let neu = fingerprint("rule", "hash", "CWE-328");
        assert!(!is_legacy_hash(&neu));
        assert_eq!(cache.get(&neu), None, "Alt->Neu muss Miss sein");
        // Umgekehrt genauso: 16-stelliger Key != 64-stelliger Wert.
        assert_ne!(legacy_fp.len(), neu.len());
    }

    #[test]
    fn python_def_gefunden_mit_dedent_ende() {
        let src = "import os\n\n\ndef read_doc(filename: str) -> bytes:\n    path = os.path.join(filename)\n    with open(path, \"rb\") as f:\n        return f.read()\n\n\ndef second():\n    return 1\n";
        let fns = scan_functions(src);
        assert_eq!(fns.len(), 2, "beide defs: {fns:?}");
        assert_eq!(fns[0].name, "read_doc");
        assert_eq!((fns[0].start_line, fns[0].end_line), (4, 7));
        assert_eq!(fns[0].nesting_depth, 2, "def > with: {fns:?}");
        assert_eq!(fns[1].name, "second");
        assert_eq!((fns[1].start_line, fns[1].end_line), (10, 11));
    }

    #[test]
    fn python_nested_if_for_und_dateitiefe() {
        let src = "def handle(items):\n    total = 0\n    for it in items:\n        if it > 0:\n            total += it\n    return total\n";
        let fns = scan_functions(src);
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].nesting_depth, 3, "def > for > if: {fns:?}");
        assert_eq!(nesting_depth(src), 3);
    }

    #[test]
    fn python_deep_nesting_flag_faehig() {
        // Tiefe 5 (def/if/while/if/for) — Stufe-1-Schwelle (> 3) greift.
        let src = "def deep(data):\n    if data:\n        while data:\n            if len(data) > 1:\n                for x in data:\n                    print(x)\n    return None\n";
        assert_eq!(nesting_depth(src), 5);
        let fns = scan_functions(src);
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].name, "deep");
        assert_eq!(fns[0].nesting_depth, 5);
        assert!(fns[0].nesting_depth > 3);
    }

    #[test]
    fn python_class_async_decorator_und_nested_def() {
        let src = "class Repo:\n    def get(self, key):\n        if key:\n            return self.store[key]\n        return None\n\n\n@cached\nasync def fetch(url):\n    return await get(url)\n";
        let fns = scan_functions(src);
        let names: Vec<&str> = fns.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"Repo"), "class: {names:?}");
        assert!(names.contains(&"get"), "methode: {names:?}");
        assert!(names.contains(&"fetch"), "async def: {names:?}");
        let fetch = fns.iter().find(|f| f.name == "fetch").unwrap();
        assert_eq!(fetch.start_line, 8, "Dekorator gehoert dazu: {fetch:?}");
    }

    #[test]
    fn rust_heuristik_unveraendert_trotz_python_worten() {
        // `def`-Wort in Kommentar/String erzeugt keine Zusatzfunktion.
        let src = "fn a() {\n    // def fake():\n    let s = \"def fake():\";\n    if x {\n        while y {\n        }\n    }\n}\n";
        let fns = scan_functions(src);
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].name, "a");
        assert_eq!(fns[0].nesting_depth, 3);
        assert_eq!(nesting_depth(src), 3);
    }

    #[test]
    fn evidence_serde_roundtrip() {
        let e = EvidenceLevel::E2;
        let s = serde_json::to_string(&e).unwrap();
        assert_eq!(s, "\"E2\"");
    }

    #[test]
    fn e1_finding_does_not_lower_security() {
        let f = vec![ScoredFinding {
            level: "error".into(),
            evidence: EvidenceLevel::E1,
            provenance: None,
        }];
        let h = health_score(&[], &f, 0);
        assert_eq!(h.security, 100);
        assert_eq!(h.total_e2_plus, 0);
    }

    #[test]
    fn e2_error_lowers_security_and_counts_by_level() {
        let f = vec![
            ScoredFinding {
                level: "error".into(),
                evidence: EvidenceLevel::E2,
                provenance: None,
            },
            ScoredFinding {
                level: "warning".into(),
                evidence: EvidenceLevel::E3,
                provenance: None,
            },
        ];
        let h = health_score(&[], &f, 0);
        assert_eq!(h.total_e2_plus, 2);
        assert_eq!(h.by_level.get("error"), Some(&1));
        assert_eq!(h.by_level.get("warning"), Some(&1));
        assert!(h.security < 100, "security muss sinken: {h:?}");
    }

    #[test]
    fn suspicious_deps_lower_dependencies() {
        let h = health_score(&[], &[], 2);
        assert_eq!(h.dependencies, 80);
        let clean = health_score(&[], &[], 0);
        assert_eq!(clean.dependencies, 100);
    }

    #[test]
    fn stub_without_findings_stays_100() {
        let h = health_score_stub(&[]);
        assert_eq!(h.security, 100);
        assert_eq!(h.dependencies, 100);
        assert_eq!(h.total_e2_plus, 0);
    }

    #[test]
    fn health_grade_grenzen() {
        assert_eq!(health_grade(100), "A");
        assert_eq!(health_grade(90), "A");
        assert_eq!(health_grade(89), "B");
        assert_eq!(health_grade(75), "B");
        assert_eq!(health_grade(74), "C");
        assert_eq!(health_grade(60), "C");
        assert_eq!(health_grade(59), "D");
        assert_eq!(health_grade(40), "D");
        assert_eq!(health_grade(39), "F");
        assert_eq!(health_grade(0), "F");
    }

    #[test]
    fn unix_rfc3339_fixpunkte() {
        assert_eq!(format_unix_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_rfc3339(946_684_800), "2000-01-01T00:00:00Z");
        assert_eq!(format_unix_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn provenance_record_felder_und_fallbacks() {
        let r = ProvenanceRecord::current_with_model("unit");
        assert_eq!(r.tool_name, PROVENANCE_TOOL_NAME);
        assert_eq!(r.tool_version, tool_version());
        assert_eq!(r.model, "unit");
        assert!(!r.commit_sha.is_empty());
        assert!(r.timestamp.ends_with('Z'));
        let v = provenance_record();
        assert_eq!(v["tool_name"], "cate");
    }
}
