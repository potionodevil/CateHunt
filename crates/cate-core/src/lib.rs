//! cate-core: Metriken (Verschachtelungstiefe, Funktionslaenge, Duplikat-Hashes),
//! Evidence-Level E0-E4, Health-Score Stub.
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Evidence-Level nach Masterplan: E0 (unbelegt) bis E4 (verifiziert/laufzeitbestaetigt).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvidenceLevel {
    E0,
    E1,
    E2,
    E3,
    E4,
}

impl Default for EvidenceLevel {
    fn default() -> Self {
        EvidenceLevel::E0
    }
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

/// Zaehlt die maximale Verschachtelungstiefe anhand von `{`/`}`.
/// Ignoriert Klammern in Zeilenkommentaren (//) und Strings (naiv).
pub fn nesting_depth(source: &str) -> usize {
    let mut depth = 0usize;
    let mut max = 0usize;
    for line in source.lines() {
        let code = strip_line_comment(line);
        let code = strip_strings_naive(&code);
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

/// Funktionslaenge in Zeilen (end - start + 1, Untergrenze 0).
pub fn function_length(start_line: usize, end_line: usize) -> usize {
    end_line.saturating_sub(start_line).saturating_add(1)
}

/// Normalisiert eine Zeile fuer Duplikat-Erkennung (trim + whitespace collapse).
pub fn normalize_line(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// 64-bit Hash einer normalisierten Zeile als Hex-String.
pub fn hash_line(line: &str) -> String {
    let mut h = DefaultHasher::new();
    normalize_line(line).hash(&mut h);
    format!("{:016x}", h.finish())
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

/// Scannt eine Funktionsliste sehr grob: sucht Zeilen mit `fn name(` (Rust)
/// oder `function name` / `name(...) {` Heuristik und misst bis zum
/// Ausgleich der Klammertiefe. Reicht als Phase-1-Stub ohne Tree-sitter.
pub fn scan_functions(source: &str) -> Vec<FunctionMetric> {
    let lines: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if let Some(name) = guess_function_name(lines[i]) {
            let start = i + 1; // 1-basiert
            let mut depth = 0i64;
            let mut seen_open = false;
            let mut end = start;
            for (j, l) in lines.iter().enumerate().skip(i) {
                let code = strip_strings_naive(&strip_line_comment(l));
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
            let fn_depth = nesting_depth(&lines[i..end.min(lines.len())].join("\n"));
            out.push(FunctionMetric {
                name,
                start_line: start,
                end_line: end,
                length: function_length(start, end),
                nesting_depth: fn_depth,
                evidence: EvidenceLevel::E0,
            });
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

/// Vollstaendige Datei-Metrik.
pub fn analyze_file(path: &str, source: &str) -> FileMetrics {
    let fns = scan_functions(source);
    FileMetrics {
        path: path.to_string(),
        lines: source.lines().count(),
        max_nesting_depth: nesting_depth(source),
        functions: fns,
        duplicate_hashes: duplicate_hashes(source),
        evidence: EvidenceLevel::E0,
    }
}

fn strip_line_comment(line: &str) -> String {
    match line.find("//") {
        Some(idx) => line[..idx].to_string(),
        None => line.to_string(),
    }
}

fn strip_strings_naive(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_str = false;
    let mut prev_backslash = false;
    for ch in s.chars() {
        if in_str {
            if ch == '"' && !prev_backslash {
                in_str = false;
            }
        } else if ch == '"' {
            in_str = true;
            continue;
        } else {
            out.push(ch);
        }
        prev_backslash = ch == '\\';
    }
    out
}

fn guess_function_name(line: &str) -> Option<String> {
    let t = line.trim();
    // Rust: fn name(
    if let Some(rest) = t.strip_prefix("fn ") {
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            return Some(name);
        }
    }
    // JS/TS: function name(
    if let Some(rest) = t.strip_prefix("function ") {
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
            .collect();
        if !name.is_empty() {
            return Some(name);
        }
    }
    None
}

// ---- Health-Score Stub (Masterplan: Struktur / Sicherheit-nur-E2+ / Abhaengigkeiten) ----

/// Teilscores 0..100.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HealthScore {
    pub structure: u8,
    pub security: u8,
    pub dependencies: u8,
    pub total: u8,
}

/// Stub: Struktur aus Nesting/Laenge abgeleitet, Security default 100
/// (nur E2+ Findings zaehlen — Phase 1: keine, also 100),
/// Dependencies default 100 (kein Befund).
pub fn health_score_stub(metrics: &[FileMetrics]) -> HealthScore {
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
    let security = 100;
    let dependencies = 100;
    let total = ((structure as u32 + security as u32 + dependencies as u32) / 3) as u8;
    HealthScore {
        structure,
        security,
        dependencies,
        total,
    }
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
    fn evidence_serde_roundtrip() {
        let e = EvidenceLevel::E2;
        let s = serde_json::to_string(&e).unwrap();
        assert_eq!(s, "\"E2\"");
    }
}
