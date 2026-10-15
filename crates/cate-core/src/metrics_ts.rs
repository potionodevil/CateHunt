// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! tree-sitter-Metriken (Feature `tree-sitter`, default an).
//!
//! Primaerer Pfad fuer [`crate::scan_functions`], [`crate::nesting_depth`]
//! und [`crate::analyze_file`]: Rust- und Python-Quellen werden per
//! Grammatik geparst (Funktionsknoten + Kontrollfluss-Nesting).
//! Schlaegt das Parsen fehl (fremde Sprache, Syntaxfehler), geben alle
//! Funktionen hier `None` zurueck und der Caller faellt auf die
//! Heuristik (`*_heuristic`) zurueck — ohne Deps (`--no-default-features`)
//! ist die Heuristik der einzige Pfad.

use super::{duplicate_hashes, function_length, EvidenceLevel, FunctionMetric};

/// Von tree-sitter abgedeckte Sprachen (vorerst Rust + Python).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsLang {
    Rust,
    Python,
}

/// Sprache per Dateiendung: `.py` (case-insensitiv) → Python,
/// alles andere → Rust-Versuch (Go/JS/… scheitern dort mit
/// Parse-Fehler und fallen auf die Heuristik zurueck).
pub fn detect_lang(path: &str) -> TsLang {
    let ext = path.rsplit(['/', '\\', '.']).next().unwrap_or("");
    let is_py = path.contains('.') && ext.eq_ignore_ascii_case("py");
    if is_py {
        TsLang::Python
    } else {
        TsLang::Rust
    }
}

fn language(lang: TsLang) -> tree_sitter::Language {
    match lang {
        TsLang::Rust => tree_sitter_rust::LANGUAGE.into(),
        TsLang::Python => tree_sitter_python::LANGUAGE.into(),
    }
}

fn ctrl_kinds(lang: TsLang) -> &'static [&'static str] {
    match lang {
        TsLang::Rust => &[
            "if_expression",
            "match_expression",
            "for_expression",
            "while_expression",
            "loop_expression",
        ],
        // `with`/`try` zaehlen mit: Die Python-Heuristik (Dedent) wertet
        // sie als Block — gleiche Semantik, sonst kippt der
        // `read_doc`-Unit-Test (`def` > `with` = 2).
        TsLang::Python => &[
            "if_statement",
            "for_statement",
            "while_statement",
            "try_statement",
            "with_statement",
            "match_statement",
        ],
    }
}

/// Parsen; `None` bei Fehler → Caller nutzt Heuristik-Fallback.
pub fn parse(source: &str, lang: TsLang) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language(lang)).ok()?;
    let tree = parser.parse(source, None)?;
    if tree.root_node().has_error() {
        return None;
    }
    Some(tree)
}

/// true, wenn `node` einen eigenen Scope eroeffnet, dessen Inneres
/// nicht zum Nesting des aeusseren Scopes zaehlt.
fn is_scope_node(kind: &str) -> bool {
    matches!(
        kind,
        "function_item"
            | "function_definition"
            | "class_definition"
            | "decorated_definition"
            | "closure_expression"
            | "lambda"
    )
}

/// Maximale Kontrollfluss-Tiefe unterhalb `node` (ohne den Knoten selbst).
/// Verschachtelte Funktions-/Klassen-Scopes werden nicht mitgezaehlt.
fn depth_below(node: tree_sitter::Node<'_>, kinds: &[&str]) -> usize {
    let mut best = 0usize;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if is_scope_node(child.kind()) {
            continue;
        }
        let own = usize::from(kinds.contains(&child.kind()));
        let inner = depth_below(child, kinds);
        best = best.max(own + inner);
    }
    best
}

struct TsFn {
    name: String,
    start: usize,
    end: usize,
    depth: usize,
}

// Tree-Lifetime: `collect` laeuft vollstaendig innerhalb von
// `scan_ts`/`nesting_ts`, der Tree lebt waehrenddessen —
// es werden nur (Name, Zeilen, Tiefe) kopiert, keine Nodes gehalten.
fn collect(
    node: tree_sitter::Node<'_>,
    lang: TsLang,
    kinds: &[&str],
    src: &[u8],
    out: &mut Vec<TsFn>,
) {
    // Sicherheitsnetz gegen zyklische Doppel-Emits bei dekorierten Defs.
    fn go(
        node: tree_sitter::Node<'_>,
        lang: TsLang,
        kinds: &[&str],
        src: &[u8],
        out: &mut Vec<TsFn>,
        skip_emit: Option<usize>,
    ) {
        let kind = node.kind();
        let mut inner: Option<tree_sitter::Node<'_>> = None;
        let mut start_row = node.start_position().row;
        let mut is_fn = false;
        match lang {
            TsLang::Rust => {
                // `function_signature_item` (body-lose Trait-Dekl) ist
                // kein Eintrag — anders als die alte Heuristik, die jede
                // `fn`-Zeile zaehlte (dort ohne Rumpf mit degeneriertem Ende).
                if kind == "function_item" && node.child_by_field_name("body").is_some() {
                    is_fn = true;
                }
            }
            TsLang::Python => {
                if kind == "function_definition" || kind == "class_definition" {
                    is_fn = true;
                } else if kind == "decorated_definition" {
                    // Dekorator gehoert dazu (Start = `@...`-Zeile, wie
                    // `include_decorators` in der Heuristik).
                    let mut cursor = node.walk();
                    let kids: Vec<_> = node.children(&mut cursor).collect();
                    if let Some(def) = kids.into_iter().find(|c| {
                        c.is_named()
                            && (c.kind() == "function_definition" || c.kind() == "class_definition")
                    }) {
                        inner = Some(def);
                        start_row = node.start_position().row;
                        is_fn = true;
                    }
                }
            }
        }
        let def_node = inner.unwrap_or(node);
        if is_fn && Some(node.id()) != skip_emit {
            if let Some(name_node) = def_node.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(src) {
                    if !name.is_empty() {
                        out.push(TsFn {
                            name: name.to_string(),
                            start: start_row + 1,
                            end: def_node.end_position().row + 1,
                            // Rumpf selbst = 1, jede Kontrollfluss-Ebene +1.
                            depth: 1 + depth_below(def_node, kinds),
                        });
                    }
                }
            }
        }
        let skip = if inner.is_some() {
            Some(def_node.id())
        } else {
            skip_emit
        };
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            go(child, lang, kinds, src, out, skip);
        }
    }
    go(node, lang, kinds, src, out, None);
}

/// Funktionsliste per tree-sitter; `None` → Heuristik-Fallback.
pub fn scan_ts(source: &str, lang: TsLang) -> Option<Vec<FunctionMetric>> {
    let tree = parse(source, lang)?;
    let kinds = ctrl_kinds(lang);
    let src = source.as_bytes();
    let mut fns = Vec::new();
    collect(tree.root_node(), lang, kinds, src, &mut fns);
    Some(
        fns.iter()
            .map(|f| FunctionMetric {
                name: f.name.clone(),
                start_line: f.start,
                end_line: f.end,
                length: function_length(f.start, f.end),
                nesting_depth: f.depth,
                evidence: EvidenceLevel::E0,
            })
            .collect(),
    )
}

/// Datei-Nesting per tree-sitter (Funktionsruempfe + Top-Level-Kontrollfluss);
/// `None` → Heuristik-Fallback.
pub fn nesting_ts(source: &str, lang: TsLang) -> Option<usize> {
    let tree = parse(source, lang)?;
    let kinds = ctrl_kinds(lang);
    let root = tree.root_node();
    let mut best = depth_below(root, kinds);
    let mut fns = Vec::new();
    collect(root, lang, kinds, source.as_bytes(), &mut fns);
    for f in &fns {
        best = best.max(f.depth);
    }
    Some(best)
}

/// Vollstaendige Datei-Metrik per tree-sitter; `None` → Fallback.
pub fn analyze_ts(path: &str, source: &str, lang: TsLang) -> Option<super::FileMetrics> {
    let functions = scan_ts(source, lang)?;
    let max_nesting_depth = nesting_ts(source, lang).unwrap_or(0);
    Some(super::FileMetrics {
        path: path.to_string(),
        lines: source.lines().count(),
        max_nesting_depth,
        functions,
        duplicate_hashes: duplicate_hashes(source),
        evidence: EvidenceLevel::E0,
    })
}
