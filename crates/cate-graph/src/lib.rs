// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! cate-graph: Rust-Modulgraph (use/mod-Beziehungen aus .rs-Dateien).
//!
//! Knoten `{id, path, health, color}`, Kanten als Abhaengigkeiten.
//! `get_graph` liefert Modulbaum + Health-Scores (aus cate-core) als JSON.
//! Der Parser ist ueber [`ModuleParser`] erweiterbar (spaeter z.B. TS/Python).
use cate_core::{analyze_file, health_score_stub};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub mod proposal;
pub use proposal::{proposals_to_json, Proposal, ProposalStatus};

/// Health-Farbe pro Knoten: gruen > 85, gelb 60–85, rot < 60.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeColor {
    Green,
    Yellow,
    Red,
}

/// Health-Score (0–100) auf [`NodeColor`] abbilden.
pub fn health_color(score: u8) -> NodeColor {
    if score > 85 {
        NodeColor::Green
    } else if score >= 60 {
        NodeColor::Yellow
    } else {
        NodeColor::Red
    }
}

/// Ein Modul als Graph-Knoten.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub path: String,
    pub health: u8,
    pub color: NodeColor,
}

/// Gerichtete Abhaengigkeit `from` -> `to`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
}

/// Modulgraph: Knoten (Modulbaum + Health) + Kanten (Abhaengigkeiten).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

/// Erweiterbarer Modul-Parser: liefert pro Datei rohe Abhaengigkeits-Pfade
/// als Segmentlisten, z.B. `use crate::a::b;` -> `["a", "b"]`.
pub trait ModuleParser {
    fn parse_deps(&self, source: &str) -> Vec<Vec<String>>;
}

/// Rust-Parser: `mod foo;` / `mod foo {` + `use`-Pfaden aus .rs-Dateien.
#[derive(Debug, Clone, Copy, Default)]
pub struct RustModuleParser;

impl RustModuleParser {
    fn clean_line(line: &str) -> &str {
        match line.find("//") {
            Some(i) => line[..i].trim(),
            None => line.trim(),
        }
    }

    fn ident(s: &str) -> String {
        s.trim()
            .trim_matches(|c: char| c == ';' || c == '{' || c == '}')
            .trim()
            .to_string()
    }
}

impl ModuleParser for RustModuleParser {
    fn parse_deps(&self, source: &str) -> Vec<Vec<String>> {
        let mut deps = Vec::new();
        for raw in source.lines() {
            let line = Self::clean_line(raw);
            if line.is_empty() {
                continue;
            }
            let mod_rest = line
                .strip_prefix("mod ")
                .or_else(|| line.strip_prefix("pub mod "))
                .or_else(|| line.strip_prefix("pub(crate) mod "))
                .or_else(|| line.strip_prefix("pub(super) mod "));
            if let Some(rest) = mod_rest {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    deps.push(vec![name]);
                }
                continue;
            }
            let use_rest = line
                .strip_prefix("use ")
                .or_else(|| line.strip_prefix("pub use "));
            if let Some(rest) = use_rest {
                let mut path = rest.split(';').next().unwrap_or("").trim();
                path = path.split('{').next().unwrap_or("").trim();
                path = path.split(" as ").next().unwrap_or("").trim();
                if path.ends_with("::*") {
                    path = path.trim_end_matches("::*").trim();
                }
                if path.is_empty() {
                    continue;
                }
                let mut segs: Vec<String> = path
                    .split("::")
                    .map(Self::ident)
                    .filter(|s| !s.is_empty())
                    .collect();
                if segs.is_empty() {
                    continue;
                }
                while matches!(
                    segs.first().map(String::as_str),
                    Some("crate") | Some("self") | Some("super") | Some("pub")
                ) {
                    segs.remove(0);
                }
                if segs.is_empty() {
                    continue;
                }
                deps.push(segs);
            }
        }
        deps
    }
}

/// Dateipfad (relativ, mit `/`) auf Modul-ID abbilden:
/// `foo/mod.rs` -> `foo`, `foo.rs` -> `foo`, `main.rs` -> `main`.
pub fn module_id_for_path(rel_path: &str) -> String {
    let norm = rel_path.replace('\\', "/");
    let no_ext = norm.strip_suffix(".rs").unwrap_or(&norm);
    match no_ext.strip_suffix("/mod") {
        Some(parent) if !parent.is_empty() => parent.to_string(),
        _ if no_ext == "mod" => "mod".to_string(),
        _ => no_ext.to_string(),
    }
}

/// Health-Score (0–100) eines Moduls aus seinem Quelltext (cate-core).
pub fn module_health(path: &str, source: &str) -> u8 {
    let m = analyze_file(path, source);
    health_score_stub(std::slice::from_ref(&m)).total
}

/// Graph aus `(Pfad, Quelltext)`-Paaren bauen (Pfade relativ, `/`-separiert).
/// Kanten werden auf existierende Knoten aufgeloest (Vollpfad, sonst 1. Segment).
pub fn build_graph<P: ModuleParser>(modules: &[(String, String)], parser: &P) -> ModuleGraph {
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for (path, _) in modules {
        ids.insert(module_id_for_path(path));
    }
    let mut nodes: Vec<GraphNode> = modules
        .iter()
        .map(|(path, src)| {
            let id = module_id_for_path(path);
            let health = module_health(path, src);
            let color = health_color(health);
            GraphNode {
                id,
                path: path.clone(),
                health,
                color,
            }
        })
        .collect();
    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    nodes.dedup_by(|a, b| a.id == b.id);

    let mut edge_set: BTreeSet<(String, String)> = BTreeSet::new();
    for (path, src) in modules {
        let from = module_id_for_path(path);
        for segs in parser.parse_deps(src) {
            if let Some(to) = resolve_dep(&segs, &ids) {
                if to != from {
                    edge_set.insert((from.clone(), to));
                }
            }
        }
    }
    let edges: Vec<GraphEdge> = edge_set
        .into_iter()
        .map(|(from, to)| GraphEdge { from, to })
        .collect();
    ModuleGraph { nodes, edges }
}

fn resolve_dep(segs: &[String], ids: &BTreeSet<String>) -> Option<String> {
    if segs.is_empty() {
        return None;
    }
    for len in (1..=segs.len()).rev() {
        let cand = segs[..len].join("/");
        if ids.contains(&cand) {
            return Some(cand);
        }
    }
    None
}

/// Modulgraph eines Verzeichnisses: alle `.rs`-Dateien (ohne `target/`).
pub fn get_graph(root: &Path) -> Result<ModuleGraph, String> {
    let files = collect_rs_files(root)?;
    let mut modules = Vec::new();
    for f in &files {
        let rel = f
            .strip_prefix(root)
            .map_err(|e| format!("rel path: {e}"))?
            .to_string_lossy()
            .replace('\\', "/");
        match std::fs::read_to_string(f) {
            Ok(src) => modules.push((rel, src)),
            Err(e) => return Err(format!("read {}: {e}", f.display())),
        }
    }
    Ok(build_graph(&modules, &RustModuleParser))
}

/// [`get_graph`] als JSON (Modulbaum + Health-Scores).
pub fn get_graph_json(root: &Path) -> Result<String, String> {
    let g = get_graph(root)?;
    serde_json::to_string_pretty(&g).map_err(|e| format!("json: {e}"))
}

/// True, wenn der Graph einen Zyklus enthaelt (DFS).
pub fn has_cycle(graph: &ModuleGraph) -> bool {
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        Temp,
        Perm,
    }
    let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for n in &graph.nodes {
        adj.entry(n.id.as_str()).or_default();
    }
    for e in &graph.edges {
        adj.entry(e.from.as_str()).or_default().push(e.to.as_str());
    }
    fn visit<'a>(
        node: &'a str,
        adj: &BTreeMap<&'a str, Vec<&'a str>>,
        marks: &mut BTreeMap<&'a str, Mark>,
    ) -> bool {
        match marks.get(node) {
            Some(Mark::Perm) => return false,
            Some(Mark::Temp) => return true,
            None => {}
        }
        marks.insert(node, Mark::Temp);
        if let Some(next) = adj.get(node) {
            for m in next {
                if visit(m, adj, marks) {
                    return true;
                }
            }
        }
        marks.insert(node, Mark::Perm);
        false
    }
    let keys: Vec<&str> = adj.keys().copied().collect();
    let mut marks: BTreeMap<&str, Mark> = BTreeMap::new();
    for k in keys {
        if visit(k, &adj, &mut marks) {
            return true;
        }
    }
    false
}

/// Modul-IDs ohne ein- oder ausgehende Kanten.
pub fn isolated_modules(graph: &ModuleGraph) -> Vec<String> {
    let mut touched: BTreeSet<&str> = BTreeSet::new();
    for e in &graph.edges {
        touched.insert(e.from.as_str());
        touched.insert(e.to.as_str());
    }
    graph
        .nodes
        .iter()
        .filter(|n| !touched.contains(n.id.as_str()))
        .map(|n| n.id.clone())
        .collect()
}

fn collect_rs_files(root: &Path) -> Result<Vec<std::path::PathBuf>, String> {
    if !root.is_dir() {
        return Err(format!("not a directory: {}", root.display()));
    }
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("read_dir: {e}"))?;
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if matches!(name, "target" | ".git") {
                    continue;
                }
                stack.push(p);
            } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn red_health_color_thresholds() {
        assert_eq!(health_color(90), NodeColor::Green);
    }

    #[test]
    fn color_green_above_85() {
        assert_eq!(health_color(86), NodeColor::Green);
        assert_eq!(health_color(100), NodeColor::Green);
    }

    #[test]
    fn color_yellow_between_60_and_85() {
        assert_eq!(health_color(85), NodeColor::Yellow);
        assert_eq!(health_color(60), NodeColor::Yellow);
        assert_eq!(health_color(70), NodeColor::Yellow);
    }

    #[test]
    fn color_red_below_60() {
        assert_eq!(health_color(59), NodeColor::Red);
        assert_eq!(health_color(0), NodeColor::Red);
    }

    #[test]
    fn mod_declaration_creates_edge() {
        let modules = vec![
            ("main.rs".to_string(), "mod foo;\nfn main() {}".to_string()),
            ("foo.rs".to_string(), "pub fn x() {}".to_string()),
        ];
        let g = build_graph(&modules, &RustModuleParser);
        assert_eq!(g.nodes.len(), 2);
        assert!(g.edges.iter().any(|e| e.from == "main" && e.to == "foo"));
    }

    #[test]
    fn use_crate_path_creates_edge() {
        let modules = vec![
            (
                "main.rs".to_string(),
                "use crate::util::helper;\nfn main() {}".to_string(),
            ),
            ("util.rs".to_string(), String::new()),
        ];
        let g = build_graph(&modules, &RustModuleParser);
        assert!(g.edges.iter().any(|e| e.from == "main" && e.to == "util"));
    }

    #[test]
    fn cycle_is_detected() {
        let modules = vec![
            ("a.rs".to_string(), "mod b;".to_string()),
            ("b.rs".to_string(), "mod a;".to_string()),
        ];
        let g = build_graph(&modules, &RustModuleParser);
        assert!(has_cycle(&g), "a<->b muss Zyklus sein: {g:?}");
    }

    #[test]
    fn acyclic_graph_has_no_cycle() {
        let modules = vec![
            ("main.rs".to_string(), "mod a;".to_string()),
            ("a.rs".to_string(), "pub fn x() {}".to_string()),
        ];
        let g = build_graph(&modules, &RustModuleParser);
        assert!(!has_cycle(&g));
    }

    #[test]
    fn isolated_module_is_reported() {
        let modules = vec![
            ("main.rs".to_string(), "mod a;".to_string()),
            ("a.rs".to_string(), String::new()),
            ("lone.rs".to_string(), "pub fn y() {}".to_string()),
        ];
        let g = build_graph(&modules, &RustModuleParser);
        assert_eq!(isolated_modules(&g), vec!["lone".to_string()]);
    }

    #[test]
    fn node_carries_health_and_color() {
        let modules = vec![("tiny.rs".to_string(), "pub fn x() {}\n".to_string())];
        let g = build_graph(&modules, &RustModuleParser);
        assert_eq!(g.nodes.len(), 1);
        let n = &g.nodes[0];
        assert_eq!(n.id, "tiny");
        assert!(n.health >= 60, "kleines Modul muss gesund sein: {n:?}");
        assert_eq!(n.color, health_color(n.health));
    }

    #[test]
    fn graph_serializes_to_json() {
        let modules = vec![("main.rs".to_string(), "mod a;".to_string())];
        let g = build_graph(&modules, &RustModuleParser);
        let v: serde_json::Value = serde_json::to_value(&g).unwrap();
        assert!(v.get("nodes").is_some());
        assert!(v.get("edges").is_some());
    }
}
