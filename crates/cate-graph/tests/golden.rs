// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! P1 Golden-Test: Graph-Export-JSON (TESTING.md §1.3).
//! Update nur via UPDATE_GOLDEN=1 + Review (s. cate-core/tests/golden.rs).
use cate_graph::{build_graph, RustModuleParser};
use std::path::PathBuf;

const SCHEMA_VERSION: &str = "graph/v1";

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("graph_v1.json")
}

fn fixture_modules() -> Vec<(String, String)> {
    vec![
        (
            "main.rs".into(),
            "mod foo;\nmod bar;\nuse crate::foo;\nfn main() {}\n".into(),
        ),
        ("foo.rs".into(), "use crate::bar;\npub fn x() {}\n".into()),
        ("bar.rs".into(), "pub fn y() {}\n".into()),
    ]
}

#[test]
fn graph_golden_byte_stable() {
    let g = build_graph(&fixture_modules(), &RustModuleParser);
    assert_eq!(g.nodes.len(), 3);
    assert!(g.edges.iter().any(|e| e.from == "main" && e.to == "foo"));
    let v = serde_json::json!({ "schema_version": SCHEMA_VERSION, "graph": g });
    let bytes = serde_json::to_string_pretty(&v).unwrap();
    assert_eq!(bytes, serde_json::to_string_pretty(&v).unwrap());
    // Keine Absolutpfade im Snapshot (nur relative Modulpfade).
    assert!(!bytes.contains(":\\"), "Absolutpfad im Golden");
    let p = golden_path();
    if std::env::var("UPDATE_GOLDEN").as_deref() == Ok("1") {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("{bytes}\n")).unwrap();
        return;
    }
    let expected_raw = std::fs::read_to_string(&p).unwrap_or_else(|_| {
        panic!(
            "Golden fehlt: {} (einmalig UPDATE_GOLDEN=1 setzen)",
            p.display()
        )
    });
    // CRLF-Toleranz (Windows-Checkout): Golden sind LF-pinning via .gitattributes.
    let expected = expected_raw.replace("\r\n", "\n");
    assert_eq!(
        expected,
        format!("{bytes}\n"),
        "Golden-Drift — Review + UPDATE_GOLDEN=1"
    );
    let back: serde_json::Value = serde_json::from_str(&expected).unwrap();
    assert_eq!(back["schema_version"], SCHEMA_VERSION);
    assert_eq!(back, v);
}
