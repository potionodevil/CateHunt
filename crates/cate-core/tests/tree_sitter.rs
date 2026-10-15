// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! tree-sitter-Tests (nur mit Feature `tree-sitter`):
//! Vergleich tree-sitter vs. Heuristik auf echten Repo-Dateien (Spike §3),
//! Fallback bei Parse-Fehler, Backend-Lage.
#![cfg(feature = "tree-sitter")]

use cate_core::metrics_ts::{detect_lang, nesting_ts, scan_ts, TsLang};
use cate_core::{
    analyze_file, analyze_file_heuristic, metrics_backend, nesting_depth, scan_functions,
    scan_functions_heuristic,
};
use std::collections::HashSet;

// Die 5 Spike-Vergleichsdateien (§3), per include_str! deterministisch.
const CORE_LIB: &str = include_str!("../src/lib.rs");
const CLI_MAIN: &str = include_str!("../../cate-cli/src/main.rs");
const TRIAGE_LIB: &str = include_str!("../../cate-triage/src/lib.rs");
const HARNESS_PY: &str = include_str!("../../../harness/harness.py");
const CWE_PY: &str = include_str!("../../../corpus/cwe-328/01_vuln.py");

#[test]
fn backend_lage_ist_tree_sitter() {
    assert_eq!(metrics_backend(), "tree-sitter");
}

#[test]
fn sprache_per_endung() {
    assert_eq!(detect_lang("src/a.rs"), TsLang::Rust);
    assert_eq!(detect_lang("harness/harness.py"), TsLang::Python);
    assert_eq!(detect_lang("x/harness.PY"), TsLang::Python);
    assert_eq!(detect_lang("main.go"), TsLang::Rust); // Rust-Versuch, dann Fallback
}

fn names(fns: &[cate_core::FunctionMetric]) -> HashSet<&str> {
    fns.iter().map(|f| f.name.as_str()).collect()
}

/// Kern-Vergleich: tree-sitter findet mind. alles, was die (gefixte)
/// Heuristik findet — keine echten Funktionen gehen verloren.
fn assert_ts_superset(path: &str, src: &str, lang: TsLang, spot: &[&str], min_depth: usize) {
    let ts = scan_ts(src, lang).expect("Spike-Dateien parsen fehlerfrei");
    let heur = scan_functions_heuristic(src);
    let ts_names = names(&ts);
    let heur_names = names(&heur);
    assert!(
        ts.len() >= heur.len(),
        "{path}: ts={} < heur={}",
        ts.len(),
        heur.len()
    );
    for n in &heur_names {
        assert!(
            ts_names.contains(n),
            "{path}: Heuristik-{n} fehlt in tree-sitter"
        );
    }
    for n in spot {
        assert!(
            ts_names.contains(n),
            "{path}: Spot-Check {n} fehlt: {ts_names:?}"
        );
    }
    // Spannen sind wohlgeformt.
    for f in &ts {
        assert!(
            f.start_line >= 1 && f.end_line >= f.start_line,
            "{path}: {f:?}"
        );
        assert_eq!(f.length, f.end_line - f.start_line + 1, "{path}: {f:?}");
    }
    // Datei-Tiefe plausibel (Rumpf = 1, jede Kontrollfluss-Ebene +1).
    let d = nesting_ts(src, lang).expect("Nesting fehlerfrei");
    assert!(d >= min_depth, "{path}: Tiefe {d} zu flach");
}

#[test]
fn vergleich_core_lib() {
    assert_ts_superset(
        "cate-core/src/lib.rs",
        CORE_LIB,
        TsLang::Rust,
        &[
            "analyze_file",
            "scan_functions",
            "health_score",
            "fingerprint",
        ],
        2,
    );
}

#[test]
fn vergleich_cli_main() {
    assert_ts_superset("cate-cli/src/main.rs", CLI_MAIN, TsLang::Rust, &["main"], 2);
}

#[test]
fn vergleich_triage_lib() {
    assert_ts_superset(
        "cate-triage/src/lib.rs",
        TRIAGE_LIB,
        TsLang::Rust,
        &["normalize_cwe", "apply_policy"],
        2,
    );
}

#[test]
fn vergleich_harness_py() {
    // Spike-Luege 4: Heuristik fand 0 von 7 — per Grammatik alle da.
    assert_ts_superset(
        "harness/harness.py",
        HARNESS_PY,
        TsLang::Python,
        &["main", "run_corpus", "load_verdicts"],
        2,
    );
    let ts = scan_ts(HARNESS_PY, TsLang::Python).unwrap();
    assert!(ts.len() >= 7, "alle defs: {}", ts.len());
}

#[test]
fn vergleich_cwe_py() {
    assert_ts_superset(
        "corpus/cwe-328/01_vuln.py",
        CWE_PY,
        TsLang::Python,
        &["hash_password"],
        1,
    );
}

#[test]
fn dispatch_nutzt_tree_sitter() {
    // Oeffentliche Pfade liefern TS-Werte (nicht Heuristik).
    let m = analyze_file("src/a.rs", CORE_LIB);
    assert!(m.functions.len() >= scan_functions_heuristic(CORE_LIB).len());
    assert!(m.functions.iter().any(|f| f.name == "analyze_file"));
    let d = nesting_depth(CORE_LIB);
    assert!(d >= 2);
    assert_eq!(scan_functions(CORE_LIB).len(), m.functions.len());
}

#[test]
fn fallback_bei_syntaxfehler_gleich_heuristic() {
    // Kaputte Quelle: beide Grammatiken scheitern → exakt Heuristik.
    let broken = "pub fn broken(((\n    {{{ not rust\ndef broken(((:\n    {{{\n";
    assert!(scan_ts(broken, TsLang::Rust).is_none());
    assert!(scan_ts(broken, TsLang::Python).is_none());
    assert_eq!(
        scan_functions(broken).len(),
        scan_functions_heuristic(broken).len()
    );
    let m = analyze_file("src/broken.rs", broken);
    let h = analyze_file_heuristic("src/broken.rs", broken);
    assert_eq!(m.functions.len(), h.functions.len());
    assert_eq!(m.max_nesting_depth, h.max_nesting_depth);
}

#[test]
fn fallback_fuer_fremdsprache_go() {
    // Go: Rust- und Python-Parse scheitern → Heuristik findet `func`.
    let src = "package main\n\nfunc main() {\n\tprintln(\"hi\")\n}\n";
    assert!(scan_ts(src, TsLang::Rust).is_none());
    let fns = scan_functions(src);
    assert_eq!(fns.len(), 1, "{fns:?}");
    assert_eq!(fns[0].name, "main");
    let m = analyze_file("main.go", src);
    assert_eq!(m.functions.len(), 1);
}
