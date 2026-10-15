// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! L4 Chaining-Engine (docs/CHECK_LAYERING.md): Lows zu Pfaden kombinieren.
//!
//! Source->Sink-Angriffspfade aus dem [`ModuleGraph`](crate::ModuleGraph):
//! Ein Modul mit einem Befund (Source) wird zu einem Sink-Modul gechained,
//! wenn ein deterministischer BFS-Pfad (max. Laenge + Loop-Schutz)
//! existiert. Kandidaten-Markierung: **E1+E1 -> E2** — zwei E1-Befunde
//! (Source-Modul + Sink-Modul) auf demselben Pfad heben sich zu einem
//! E2-Kandidaten zusammen.
//!
//! Konfidenz steigt mit Pfad-Kuerze ([`ChainConfidence`]), Kill-Kriterien
//! (CHECK_LAYERING.md): Chain ohne Sink, Pfad nur durch Test-Code,
//! Sink in Dead Code (kein Caller im Graph) -> kein Bug, nur Notiz
//! (`killed: true` + Grund). Loesch-Entscheidung bleibt beim Policy-Layer.
use crate::reach::{adjacency, ReachParams};
use crate::ModuleGraph;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Konfidenz eines Chains: hoeher bei kuerzerem Pfad (Korrelations-Regel
/// "Konfidenz steigt mit Pfadkuerze").
///
/// 1 Kante = High, 2 Kanten = Medium, 3+ = Low; Pfadlaenge 0
/// (Source==Sink) wird nicht als Chain gewertet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainConfidence {
    Low,
    Medium,
    High,
}

impl ChainConfidence {
    /// Konfidenz zu einer Pfadlaenge (Kanten-Anzahl).
    pub fn for_path_len(len: usize) -> Self {
        match len {
            1 => ChainConfidence::High,
            2 => ChainConfidence::Medium,
            _ => ChainConfidence::Low,
        }
    }
}

/// Ein Angriffspfad-Kandidat Source -> Sink (reiner Datentyp).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackChain {
    /// Modul mit dem Source-Befund (Star des Pfads).
    pub source: String,
    /// Sink-Modul (Ziel des Pfads).
    pub sink: String,
    /// Modul-IDs des Pfads (inklusive beide Enden).
    pub path: Vec<String>,
    /// Anzahl der Kanten (path.len() - 1).
    pub path_len: usize,
    pub confidence: ChainConfidence,
    /// E1+E1 -> E2-Kandidat: beide Enden tragen E1-Befunde.
    pub e2_candidate: bool,
    /// Kill-Kriterium getroffen -> kein Bug, nur Notiz.
    pub killed: bool,
    /// Grund der Killed-Entscheidung (leer, wenn `killed == false`).
    pub kill_reason: String,
}

/// einen Angriffspfad Source -> Sink bestimmen (deterministisch).
///
/// Loop-Schutz via `visited`, Pfadlaengen-Limit via
/// [`ReachParams::max_path`]; unter mehreren Pfaden gewinnt der
/// kuerzeste, bei Gleichstand der lexikalisch kleinste (BFS mit
/// BTreeSet-Nachfolgern).
pub fn forge_chain(
    graph: &ModuleGraph,
    source: &str,
    sink: &str,
    params: &ReachParams,
) -> AttackChain {
    let killed = kill_criteria(graph, source, sink);
    if killed.0 {
        return AttackChain {
            source: source.to_string(),
            sink: sink.to_string(),
            path: vec![source.to_string()],
            path_len: 0,
            confidence: ChainConfidence::Low,
            e2_candidate: false,
            killed: true,
            kill_reason: killed.1,
        };
    }
    let path = bfs_path(graph, source, sink, params);
    match path {
        Some(path) if path.len() >= 2 => AttackChain {
            e2_candidate: source != sink,
            source: source.to_string(),
            sink: sink.to_string(),
            path_len: path.len() - 1,
            confidence: ChainConfidence::for_path_len(path.len() - 1),
            path,
            killed: false,
            kill_reason: String::new(),
        },
        _ => AttackChain {
            source: source.to_string(),
            sink: sink.to_string(),
            path: vec![source.to_string()],
            path_len: 0,
            confidence: ChainConfidence::Low,
            e2_candidate: false,
            killed: false,
            kill_reason: String::new(),
            // Kein Pfad -> kein Chain (Policy entscheidet ueber Notiz).
        },
    }
}

/// Alle Source->Sink-Ketten fuer mehrere Kombinationen auf einmal
/// (deterministisch sortiert nach (source, sink)).
pub fn attack_chains(
    graph: &ModuleGraph,
    sources: &[&str],
    sinks: &[&str],
    max_path: usize,
) -> Vec<AttackChain> {
    let params = ReachParams {
        min_path: Some(1),
        max_path,
    };
    let mut out = Vec::new();
    for s in sources {
        for k in sinks {
            out.push(forge_chain(graph, s, k, &params));
        }
    }
    out.sort_by(|a, b| (&*a.source, &*a.sink).cmp(&(&*b.source, &*b.sink)));
    out
}

type KillCheck = (bool, String);

/// Kill-Kriterien (docs/CHECK_LAYERING.md): Chain ohne Sink, Pfad nur
/// durch Test-Code, Sink in Dead Code (kein Caller im Graph).
fn kill_criteria(graph: &ModuleGraph, source: &str, sink: &str) -> KillCheck {
    // Chain ohne Sink: Sink-Modul existiert nicht im Graph.
    if !graph.nodes.iter().any(|n| n.id == sink) {
        return (true, "chain ohne sink (modul fehlt im graph)".to_string());
    }
    // Pfad nur durch Test-Code: Source und Sink (und Intermission) liegen
    // alle unter tests/.
    let is_test = |id: &str| id.split('/').any(|p| p == "tests" || p == "test");
    if is_test(source) {
        return (true, "pfad nur durch test-code (source)".to_string());
    }
    if is_test(sink) {
        return (true, "pfad nur durch test-code (sink)".to_string());
    }
    // Sink in Dead Code: keine eingehende Kante von einem anderen Modul
    // (die Source->Sink-Kante allein ist keine lebende Caller-Beziehung).
    let has_caller = graph.edges.iter().any(|e| e.to == sink && e.from != source);
    if !has_caller {
        return (true, "sink in dead code (kein caller im graph)".to_string());
    }
    (false, String::new())
}

/// Kuerzster deterministischer Pfad, None wenn unerreichbar oder zu lang.
fn bfs_path(
    graph: &ModuleGraph,
    source: &str,
    sink: &str,
    params: &ReachParams,
) -> Option<Vec<String>> {
    if source == sink {
        return None; // Source==Sink ist kein Chain (path_len 0).
    }
    let adj = adjacency(graph);
    let mut visited: BTreeSet<&str> = BTreeSet::new();
    let mut parent: BTreeMap<&str, &str> = BTreeMap::new();
    let mut dist: BTreeMap<&str, usize> = BTreeMap::new();
    let mut queue: std::collections::VecDeque<&str> = std::collections::VecDeque::new();
    queue.push_back(source);
    visited.insert(source);
    dist.insert(source, 0);
    let min = params.min_path.unwrap_or(0);
    while let Some(cur) = queue.pop_front() {
        let d = dist.get(cur).copied().unwrap_or(0);
        if d >= params.max_path {
            continue;
        }
        let next_list = match adj.get(cur) {
            Some(list) => list,
            None => continue,
        };
        for &nxt in next_list {
            if visited.contains(nxt) {
                continue; // Loop-Schutz.
            }
            visited.insert(nxt);
            parent.insert(nxt, cur);
            dist.insert(nxt, d + 1);
            if nxt == sink {
                if d + 1 < min {
                    continue; // min_path verletzt.
                }
                let mut path: Vec<String> = vec![sink.to_string()];
                let mut cur = sink;
                while let Some(&p) = parent.get(cur) {
                    path.push(p.to_string());
                    cur = p;
                }
                path.reverse();
                return Some(path);
            }
            queue.push_back(nxt);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph(edges: &[(&str, &str)]) -> ModuleGraph {
        // Jeder Test-Graph bekommt einen Wurzel-Knoten `main`, damit die
        // Dead-Code-Kill-Regel ("Sink braucht einen Caller") Handhabung hat.
        let mut ids: BTreeSet<String> = BTreeSet::new();
        ids.insert("main".to_string());
        for (a, b) in edges {
            ids.insert(a.to_string());
            ids.insert(b.to_string());
        }
        let mut all_edges: Vec<crate::GraphEdge> = edges
            .iter()
            .map(|(a, b)| crate::GraphEdge {
                from: a.to_string(),
                to: b.to_string(),
            })
            .collect();
        all_edges.push(crate::GraphEdge {
            from: "main".to_string(),
            to: "trap".to_string(),
        });
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
            edges: all_edges,
        }
    }

    #[test]
    fn direct_chain_is_high_confidence_e2_candidate() {
        // `caller -> sink` als zweite Kante: Sink ist nicht Dead Code.
        let g = graph(&[("app", "s1"), ("caller", "s1")]);
        let c = forge_chain(
            &g,
            "app",
            "s1",
            &ReachParams {
                min_path: Some(1),
                max_path: 8,
            },
        );
        assert!(!c.killed);
        assert_eq!(c.path_len, 1);
        assert_eq!(c.confidence, ChainConfidence::High);
        assert!(c.e2_candidate, "E1+E1 -> E2-Kandidat");
        assert_eq!(c.path, vec!["app", "s1"]);
    }

    #[test]
    fn two_edge_chain_is_medium() {
        let g = graph(&[("app", "mid"), ("mid", "s1"), ("caller", "s1")]);
        let c = forge_chain(&g, "app", "s1", &Default::default());
        assert_eq!(c.path_len, 2);
        assert_eq!(c.confidence, ChainConfidence::Medium);
        assert_eq!(c.path, vec!["app", "mid", "s1"]);
    }

    #[test]
    fn long_chain_is_low_confidence() {
        let g = graph(&[("a", "b"), ("b", "c"), ("c", "d"), ("caller", "d")]);
        let c = forge_chain(&g, "a", "d", &Default::default());
        assert_eq!(c.path_len, 3);
        assert_eq!(c.confidence, ChainConfidence::Low);
    }

    #[test]
    fn no_path_no_chain() {
        // Sink existiert (hat Caller), ist von Source aber unerreichbar.
        let g = graph(&[("app", "mid"), ("caller", "s1")]);
        let c = forge_chain(&g, "app", "s1", &Default::default());
        // Kein Pfad: kein Chain (nicht killed, aber path leer/len 0).
        assert!(!c.killed);
        assert_eq!(c.path_len, 0);
        assert!(!c.e2_candidate);
    }

    #[test]
    fn kill_no_sink() {
        let g = graph(&[("app", "mid")]);
        let c = forge_chain(&g, "app", "gibts-nicht", &Default::default());
        assert!(c.killed);
        assert!(c.kill_reason.contains("ohne sink"));
    }

    #[test]
    fn kill_path_only_through_test_code() {
        let g = graph(&[("tests/harness", "tests/sink")]);
        let c = forge_chain(&g, "tests/harness", "tests/sink", &Default::default());
        assert!(c.killed);
        assert!(c.kill_reason.contains("test-code"));
    }

    #[test]
    fn kill_sink_in_dead_code() {
        // Sink existiert, hat aber keinen Caller (ausser Source) im Graph.
        // Der Test-Fixture-Graph hat `main -> trap` als Dummy-Kante; `sink`
        // mit nur `app -> sink` bleibt caller-los.
        let g = graph(&[("app", "isolated_sink")]);
        let c = forge_chain(&g, "app", "isolated_sink", &Default::default());
        assert!(
            c.killed,
            "Sink ohne anderen Caller soll als Dead Code gelten"
        );
        assert!(c.kill_reason.contains("dead code"));
    }

    #[test]
    fn sink_with_caller_not_killed() {
        let g = graph(&[("app", "s1"), ("main_caller", "s1")]);
        let c = forge_chain(&g, "app", "s1", &Default::default());
        assert!(!c.killed);
        assert!(c.e2_candidate);
    }

    #[test]
    fn max_path_limit_stops_chain() {
        let g = graph(&[
            ("a", "b"),
            ("b", "c"),
            ("c", "d"),
            ("d", "s1"),
            ("caller", "s1"),
        ]);
        let params = ReachParams {
            min_path: Some(1),
            max_path: 3,
        };
        let c = forge_chain(&g, "a", "s1", &params);
        // 4 Kanten > max_path=3 -> kein Chain.
        assert_eq!(c.path_len, 0);
        assert!(!c.killed);
    }

    #[test]
    fn attack_chains_deterministic_order() {
        let g = graph(&[
            ("a", "mid"),
            ("mid", "s1"),
            ("b", "s2"),
            ("caller", "s1"),
            ("caller", "s2"),
        ]);
        let chains = attack_chains(&g, &["a", "b"], &["s1", "s2"], 8);
        let keys: Vec<(&str, &str)> = chains
            .iter()
            .map(|c| (c.source.as_str(), c.sink.as_str()))
            .collect();
        assert_eq!(
            keys,
            vec![("a", "s1"), ("a", "s2"), ("b", "s1"), ("b", "s2")]
        );
        // Zweimal denselben Call -> identisches Ergebnis (deterministisch).
        let again = attack_chains(&g, &["a", "b"], &["s1", "s2"], 8);
        assert_eq!(chains, again);
    }

    #[test]
    fn chain_survives_cycle() {
        let g = graph(&[("a", "b"), ("b", "a"), ("b", "s1"), ("caller", "s1")]);
        let c = forge_chain(&g, "a", "s1", &Default::default());
        assert!(!c.killed);
        assert_eq!(c.path, vec!["a", "b", "s1"]);
    }
}
