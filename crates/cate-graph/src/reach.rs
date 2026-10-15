// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! L3 Reachability-Engine (docs/CHECK_LAYERING.md): "Nur Erreichbares zaehlt."
//!
//! Zwei Sichten, beide deterministisch (BTreeSet-Reihenfolge) mit
//! Loop-Schutz (`visited`) und Pfadlaengen-Limit (`max_path`):
//!
//! (a) **Befund -> Sink (ModulePath):** BFS vom Modul des Befunds zu einem
//!     Sink-Modul. Kanten (`use`/`mod`) werden als Caller-Wirkung gelesen.
//!     Befund und Sink im selben Modul ist Pfadlaenge 0 (ueber `min_path`
//!     abregelbar; Default `Some(1)`).
//! (b) **Dependency-Vulnerability -> Use-Pfad (DepUsePath):** ein Advisory
//!     trifft das Paket `P` (Crate-Name, `-`/`_`-gleich); erreichbar ist
//!     es nur, wenn im eigenen Code ein Import auf `P` existiert
//!     (`use p::...`-Kante). Ohne Import-Pfad: `reachable:false`.
//!
//! Nicht erreichbare Findings werden **de-eskaliert, nicht geloescht**
//! ([`escalation_after_unreachable`]) — die Loesch-Entscheidung bleibt dem
//! Policy-Layer (cate-triage) ueberlassen.
use crate::severity::demote_severity;
use crate::ModuleGraph;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Wie der Finding die Sink-Abhaengigkeit erreicht (Sensor-Sicht).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReachKind {
    /// Finding-Modul ist (direkt oder ueber Kanten) mit dem Sink verbunden.
    ModulePath,
    /// Dep-Vulnerability mit Import-Kontext (Use-Pfad existiert).
    DepUsePath,
}

/// Sensor-Ergebnis der BFS (reiner Datentyp, keine Policy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reachable {
    pub kind: ReachKind,
    pub reachable: bool,
    /// Anzahl der Kanten vom Finding zum Sink (0 = gleiche Datei).
    pub path_len: usize,
    /// Modul-IDs des Pfads vom Finding zum Sink (inklusive beide Enden).
    pub path: Vec<String>,
}

impl Reachable {
    /// Sensor-Kurzfassung fuer "nicht erreichbar" (De-Eskalation, nicht Loeschen).
    pub fn not_reachable(kind: ReachKind) -> Self {
        Reachable {
            kind,
            reachable: false,
            path_len: 0,
            path: Vec::new(),
        }
    }
}

/// Parametrisierung des BFS-Laufs.
///
/// `min_path`/`max_path` beschraenken den erlaubten Kanten-Abstand:
/// `Some(1)` setzt voraus, dass Finding und Sink in verschiedenen Modulen
/// liegen; `None` erlaubt Pfadlaenge 0. Default: 1..=8 Kanten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachParams {
    pub min_path: Option<usize>,
    pub max_path: usize,
}

impl Default for ReachParams {
    fn default() -> Self {
        ReachParams {
            min_path: Some(1),
            max_path: 8,
        }
    }
}

impl ReachParams {
    fn contains(&self, len: usize) -> bool {
        self.min_path.is_none_or(|m| len >= m) && len <= self.max_path
    }
}

/// Convenience ohne Parameter (Default: min 1, max 8).
pub fn reachability_from_module(graph: &ModuleGraph, from_module: &str, sink: &str) -> Reachable {
    reachability_from_module_params(graph, from_module, sink, &ReachParams::default())
}

/// Adjazenz-Map: ID -> sortierte Nachfolger (deterministische BFS-Ordnung).
pub(crate) fn adjacency(graph: &ModuleGraph) -> BTreeMap<&str, BTreeSet<&str>> {
    let mut adj: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for n in &graph.nodes {
        adj.entry(n.id.as_str()).or_default();
    }
    for e in &graph.edges {
        adj.entry(e.from.as_str())
            .or_default()
            .insert(e.to.as_str());
    }
    adj
}

/// Deterministischer BFS-Shortest-Path `from -> sink`.
/// `visited`/`dist` schuetzen vor Zyklen (a<->b), `params` begrenzt die
/// Pfadlaenge ([`ReachParams::min_path`]/[`ReachParams::max_path`]).
fn bfs_module_path(
    graph: &ModuleGraph,
    from_module: &str,
    sink: &str,
    params: &ReachParams,
) -> Reachable {
    if from_module == sink {
        // Gleiche Datei: Pfadlaenge 0, mit min_path >= 1 kein "Pfad".
        return if params.contains(0) {
            Reachable {
                kind: ReachKind::ModulePath,
                reachable: true,
                path_len: 0,
                path: vec![sink.to_string()],
            }
        } else {
            Reachable::not_reachable(ReachKind::ModulePath)
        };
    }
    let adj = adjacency(graph);
    if !adj.contains_key(sink) {
        return Reachable::not_reachable(ReachKind::ModulePath);
    }
    let mut visited: BTreeSet<&str> = BTreeSet::new();
    let mut parent: BTreeMap<&str, &str> = BTreeMap::new();
    let mut dist: BTreeMap<&str, usize> = BTreeMap::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    queue.push_back(from_module);
    visited.insert(from_module);
    dist.insert(from_module, 0);
    while let Some(cur) = queue.pop_front() {
        let d = dist.get(cur).copied().unwrap_or(0);
        if d >= params.max_path {
            continue; // max_path erreicht: Ebene nicht weiter expandieren.
        }
        let next_list = match adj.get(cur) {
            Some(list) => list,
            None => continue,
        };
        for &nxt in next_list {
            if visited.contains(nxt) {
                continue; // Loop-Schutz (auch bei Zyklen a<->b).
            }
            visited.insert(nxt);
            parent.insert(nxt, cur);
            dist.insert(nxt, d + 1);
            if nxt == sink {
                let mut path: Vec<String> = vec![sink.to_string()];
                let mut cur = sink;
                while let Some(&p) = parent.get(cur) {
                    path.push(p.to_string());
                    cur = p;
                }
                path.reverse();
                let len = path.len() - 1;
                if params.contains(len) {
                    return Reachable {
                        kind: ReachKind::ModulePath,
                        reachable: true,
                        path_len: len,
                        path,
                    };
                }
                continue; // min_path verletzt: weiter suchen.
            }
            queue.push_back(nxt);
        }
    }
    Reachable::not_reachable(ReachKind::ModulePath)
}

/// (a) Befund -> Sink-Knoten BFS.
///
/// Regel (docs/CHECK_LAYERING.md, Reachability): Kanten sind "wissen von",
/// unter gleicher Distanz entscheidet die ID-Reihenfolge (`BTreeSet`),
/// das Ergebnis ist damit deterministisch.
pub fn reachability_from_module_params(
    graph: &ModuleGraph,
    from_module: &str,
    sink: &str,
    params: &ReachParams,
) -> Reachable {
    bfs_module_path(graph, from_module, sink, params)
}

/// (b) Dep-Vulnerability -> Use-Pfad: Advisory trifft Paket `P`.
///
/// Erreichbar nur, wenn mindestens ein eigener Modul-Knoten eine
/// `use p::...`/`use p;`-Kante in den Crate-Baum von `P` hat. Die Kanten
/// des Graphen sind genau diese Imports; unter mehreren Treffern gewinnt
/// deterministisch der lexikalisch kleinste `(Importer, Ziel)`.
pub fn reachability_to_crate(graph: &ModuleGraph, crate_name: &str) -> Reachable {
    let target = norm_crate(crate_name);
    if target.is_empty() {
        return Reachable::not_reachable(ReachKind::DepUsePath);
    }
    // Alle Kanten mit Crate-Segment == target (normierte Segmente).
    let mut imported: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for e in &graph.edges {
        let first = norm_crate(e.to.split('/').next().unwrap_or(""));
        if first == target {
            imported
                .entry(e.from.as_str())
                .or_default()
                .insert(e.to.as_str());
        }
    }
    if imported.is_empty() {
        return Reachable::not_reachable(ReachKind::DepUsePath);
    }
    // Deterministisch: kleinster (Importer, Ziel) gewinnt.
    let mut best: Option<(&str, &str)> = None;
    for (from, targets) in &imported {
        for &to in targets {
            let candidate = (*from, to);
            best = match best {
                Some(prev) if prev <= candidate => Some(prev),
                _ => Some(candidate),
            };
        }
    }
    let (from, to) = best.unwrap();
    // Import direkt im Modul: path_len 1 (Modul -> Crate-Segment).
    let path = vec![from.to_string(), to.to_string()];
    Reachable {
        kind: ReachKind::DepUsePath,
        reachable: true,
        path_len: path.len() - 1,
        path,
    }
}

/// Crate-Namen: `-` <=> `_` (crate `my-lib` heisst im Code `my_lib`).
fn norm_crate(s: &str) -> String {
    s.trim().replace('-', "_").to_ascii_lowercase()
}

/// De-Eskalation nach Nicht-Erreichbarkeit: nie loeschen, genau eine Stufe
/// runter ([`demote_severity`]).
pub fn escalation_after_unreachable(severity: &str) -> String {
    demote_severity(severity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph(edges: &[(&str, &str)]) -> ModuleGraph {
        let mut ids: BTreeSet<String> = BTreeSet::new();
        for (a, b) in edges {
            ids.insert(a.to_string());
            ids.insert(b.to_string());
        }
        ModuleGraph {
            nodes: ids
                .iter()
                .map(|id| crate::GraphNode {
                    id: id.clone(),
                    path: format!("{id}.rs"),
                    health: 100,
                    color: crate::health_color(100),
                })
                .collect(),
            edges: edges
                .iter()
                .map(|(a, b)| crate::GraphEdge {
                    from: a.to_string(),
                    to: b.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn module_path_direct_edge_reachable() {
        let g = graph(&[("src/lib", "util"), ("util", "sink")]);
        let r = reachability_from_module_params(&g, "src/lib", "sink", &Default::default());
        assert!(r.reachable);
        assert_eq!(r.path_len, 2);
        assert_eq!(r.path, vec!["src/lib", "util", "sink"]);
        assert_eq!(r.kind, ReachKind::ModulePath);
    }

    #[test]
    fn module_path_same_module_is_len_zero() {
        let g = graph(&[("sink", "util")]);
        // Default min=1: gleiche Datei zaehlt nicht als Pfad.
        let r = reachability_from_module_params(&g, "sink", "sink", &Default::default());
        assert!(!r.reachable);
        // min=None erlaubt Pfadlaenge 0.
        let params = ReachParams {
            min_path: None,
            max_path: 8,
        };
        let r = reachability_from_module_params(&g, "sink", "sink", &params);
        assert!(r.reachable);
        assert_eq!(r.path_len, 0);
        assert_eq!(r.path, vec!["sink"]);
    }

    #[test]
    fn module_path_unreachable_without_edge() {
        let g = graph(&[("src/lib", "util")]);
        let r = reachability_from_module(&g, "util", "sink");
        assert!(!r.reachable);
        assert!(r.path.is_empty());
    }

    #[test]
    fn module_path_unreachable_unknown_sink() {
        let g = graph(&[("src/lib", "util")]);
        let r = reachability_from_module(&g, "src/lib", "gibts-nicht");
        assert!(!r.reachable);
    }

    #[test]
    fn module_path_respects_max_path() {
        let g = graph(&[("a", "b"), ("b", "c"), ("c", "d")]);
        let params = ReachParams {
            min_path: Some(1),
            max_path: 2,
        };
        let r = reachability_from_module_params(&g, "a", "d", &params);
        assert!(!r.reachable, "3 Kanten > max_path=2");
    }

    #[test]
    fn module_path_survives_cycles() {
        let g = graph(&[("a", "b"), ("b", "a"), ("b", "sink")]);
        let r = reachability_from_module(&g, "a", "sink");
        assert!(r.reachable);
        assert_eq!(r.path_len, 2);
        assert_eq!(r.path, vec!["a", "b", "sink"]);
    }

    #[test]
    fn dep_use_path_reachable_on_import() {
        let g = graph(&[("src/lib", "evil_crate/src/lib")]);
        let r = reachability_to_crate(&g, "evil_crate");
        assert!(r.reachable, "Import der Crate muss DepUsePath eroeffnen");
        assert_eq!(r.kind, ReachKind::DepUsePath);
        assert_eq!(r.path_len, 1);
        assert_eq!(r.path, vec!["src/lib", "evil_crate/src/lib"]);
    }

    #[test]
    fn dep_use_path_unreachable_without_import() {
        let g = graph(&[("src/lib", "other/src/lib")]);
        let r = reachability_to_crate(&g, "evil_crate");
        assert!(!r.reachable);
        assert_eq!(r.kind, ReachKind::DepUsePath);
        assert!(r.path.is_empty());
    }

    #[test]
    fn dep_use_path_normalizes_hyphen_underscore() {
        let g = graph(&[("a", "my-lib/src/lib")]);
        assert!(reachability_to_crate(&g, "my_lib").reachable, "-/_ matchen");
        assert!(reachability_to_crate(&g, "my-lib").reachable);
    }

    #[test]
    fn dep_use_path_empty_crate_name_never_reachable() {
        let g = graph(&[("a", "b")]);
        assert!(!reachability_to_crate(&g, "").reachable);
        assert!(!reachability_to_crate(&g, "   ").reachable);
    }

    #[test]
    fn dep_unreachable_demotes_not_deletes() {
        // Regel (CHECK_LAYERING.md): unreachable -> de-eskalieren, nicht loeschen.
        assert_eq!(escalation_after_unreachable("critical"), "high");
        assert_eq!(escalation_after_unreachable("low"), "note");
        assert_eq!(escalation_after_unreachable("note"), "note");
    }
}
