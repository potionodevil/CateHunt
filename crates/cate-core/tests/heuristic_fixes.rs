// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Heuristik-Fix-Tests (Spike-Luegen 1-3): laufen MIT und OHNE
//! tree-sitter-Feature, da sie die `*_heuristic`-Funktionen direkt nutzen.

use cate_core::{analyze_file_heuristic, nesting_depth_heuristic, scan_functions_heuristic};

#[test]
fn pub_fn_wird_gefunden() {
    let src = "pub fn analyze_file(path: &str) -> u8 {\n    1\n}\n";
    let fns = scan_functions_heuristic(src);
    assert_eq!(fns.len(), 1, "{fns:?}");
    assert_eq!(fns[0].name, "analyze_file");
    assert_eq!((fns[0].start_line, fns[0].end_line), (1, 3));
}

#[test]
fn sichtbarkeit_und_qualifizierer_varianten() {
    let src = "pub(crate) fn a() {\n}\n Pub f\u{00e4}llt nicht: egal\npub async fn b() {\n}\nunsafe fn c() {\n}\nconst fn d() {\n}\nextern \"C\" fn e() {\n}\nfn f() {\n}\n";
    let names: Vec<String> = scan_functions_heuristic(src)
        .iter()
        .map(|f| f.name.clone())
        .collect();
    for want in ["a", "b", "c", "d", "e", "f"] {
        assert!(names.contains(&want.to_string()), "{want} fehlt: {names:?}");
    }
}

#[test]
fn kein_fehlmatch_bei_aehnlichen_praefixen() {
    // `publish_…`, `constant`, `async_fn` sind keine fn-Koepfe.
    let src = "fn publish_it() {\n}\n// constant x\nfn echt() {\n}\n";
    let names: Vec<String> = scan_functions_heuristic(src)
        .iter()
        .map(|f| f.name.clone())
        .collect();
    assert_eq!(names, vec!["publish_it".to_string(), "echt".to_string()]);
}

#[test]
fn raw_strings_sprengen_kein_klammerkonto() {
    // Spike-Luege 2 (cate-cli audit-...): JSON in r#"…"# verschob end_line.
    let src = "pub fn f() {\n    let s = r#\"{\"key\": \"}\"}\"#;\n    if x {\n    }\n}\n";
    let fns = scan_functions_heuristic(src);
    assert_eq!(fns.len(), 1, "{fns:?}");
    assert_eq!((fns[0].start_line, fns[0].end_line), (1, 5), "{fns:?}");
    assert_eq!(fns[0].nesting_depth, 2, "{fns:?}");
    assert_eq!(nesting_depth_heuristic(src), 2);
}

#[test]
fn char_literale_zaehlen_nicht() {
    // Spike-Luege 3 (ollama.rs): '{'/'}' sind keine echten Klammern.
    let src = "fn f(s: &str) {\n    let a = s.find('{');\n    let b = s.rfind('}');\n    if a.is_some() {\n    }\n}\n";
    assert_eq!(nesting_depth_heuristic(src), 2);
    let fns = scan_functions_heuristic(src);
    assert_eq!(fns.len(), 1, "{fns:?}");
    assert_eq!((fns[0].start_line, fns[0].end_line), (1, 6), "{fns:?}");
}

#[test]
fn block_und_zeilenkommentare_zaehlen_nicht() {
    let src = "fn f() {\n    /* { geschachtelt /* } */ noch zu */\n    // }\n    let url = \"http://e.com/{x}\";\n    if y {\n    }\n}\n";
    assert_eq!(nesting_depth_heuristic(src), 2);
    let fns = scan_functions_heuristic(src);
    assert_eq!(fns.len(), 1, "{fns:?}");
    assert_eq!((fns[0].start_line, fns[0].end_line), (1, 7), "{fns:?}");
}

#[test]
fn lifetimes_bleiben_harmlos() {
    let src = "fn f<'a>(x: &'a str) {\n    if !x.is_empty() {\n    }\n}\n";
    assert_eq!(nesting_depth_heuristic(src), 2);
    let fns = scan_functions_heuristic(src);
    assert_eq!(fns.len(), 1, "{fns:?}");
    assert_eq!(fns[0].name, "f");
}

#[test]
fn heuristik_datei_metrik_auf_rust_mit_pub() {
    let src = "pub fn a() {\n    if x {\n    }\n}\n\nfn b() {\n}\n";
    let m = analyze_file_heuristic("src/a.rs", src);
    assert_eq!(m.functions.len(), 2, "{m:?}");
    assert_eq!(m.max_nesting_depth, 2);
}
