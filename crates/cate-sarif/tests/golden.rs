// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! P1 Golden-Test: SARIF-Findings-JSON (TESTING.md §1.3).
//! Update nur via UPDATE_GOLDEN=1 + Review (s. cate-core/tests/golden.rs).
use std::path::PathBuf;

const SCHEMA_VERSION: &str = "findings/v1";
const SARIF_FIXTURE: &str = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[
  {"ruleId":"no-eval","message":{"text":"avoid eval"},"level":"error",
   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/a.js"},"region":{"startLine":3}}}]},
  {"ruleId":"no-md5","message":{"text":"weak hash"},"level":"warning",
   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/b.py"},"region":{"startLine":11}}}]},
  {"ruleId":"","message":{},"locations":[]}
]}]}"#;

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("findings_v1.json")
}

#[test]
fn findings_golden_byte_stable() {
    let findings = cate_sarif::import_sarif(SARIF_FIXTURE).unwrap();
    assert_eq!(findings.len(), 3);
    // Pflichtfelder (TESTING.md §1.1 SARIF): ruleId/level/locations abgedeckt.
    assert_eq!(findings[0].rule_id, "no-eval");
    assert_eq!(findings[2].rule_id, "unknown"); // Default statt Abbruch
    let v = serde_json::json!({ "schema_version": SCHEMA_VERSION, "findings": findings });
    let bytes = serde_json::to_string_pretty(&v).unwrap();
    assert_eq!(bytes, serde_json::to_string_pretty(&v).unwrap());
    let p = golden_path();
    if std::env::var("UPDATE_GOLDEN").as_deref() == Ok("1") {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("{bytes}\n")).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&p).unwrap_or_else(|_| {
        panic!(
            "Golden fehlt: {} (einmalig UPDATE_GOLDEN=1 setzen)",
            p.display()
        )
    });
    assert_eq!(
        expected,
        format!("{bytes}\n"),
        "Golden-Drift — Review + UPDATE_GOLDEN=1"
    );
    let back: serde_json::Value = serde_json::from_str(&expected).unwrap();
    assert_eq!(back["schema_version"], SCHEMA_VERSION);
    assert_eq!(back, v);
}
