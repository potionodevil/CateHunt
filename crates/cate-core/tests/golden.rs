// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! P1 Golden-Test: Health-Score-JSON (TESTING.md §1.3).
//!
//! Byte-stabil: `serde_json::to_string_pretty` ueber Structs mit
//! sortierten Maps (BTreeMap), keine Timestamps/PIDs/Absolutpfade.
//! Update NUR lokal: `UPDATE_GOLDEN=1 cargo test -p cate-core --test golden`
//! + Review-Diff im PR (stilles Bless im CI verboten).
use cate_core::{analyze_file, health_score, HealthScore, ScoredFinding};
use std::path::PathBuf;

const SCHEMA_VERSION: &str = "health/v1";

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("health_v1.json")
}

fn fixture_score() -> serde_json::Value {
    let src =
        "fn a() {\n  if x {\n    while y {\n      let x = 1;\n      let x = 1;\n    }\n  }\n}\n";
    let m = analyze_file("src/a.rs", src);
    let findings = vec![
        ScoredFinding {
            level: "error".into(),
            evidence: cate_core::EvidenceLevel::E2,
            provenance: None,
        },
        ScoredFinding {
            level: "warning".into(),
            evidence: cate_core::EvidenceLevel::E3,
            provenance: None,
        },
        ScoredFinding {
            level: "note".into(),
            evidence: cate_core::EvidenceLevel::E1,
            provenance: None,
        },
    ];
    let h: HealthScore = health_score(std::slice::from_ref(&m), &findings, 1);
    serde_json::json!({ "schema_version": SCHEMA_VERSION, "health": h })
}

#[test]
fn health_golden_byte_stable() {
    let v = fixture_score();
    let bytes = serde_json::to_string_pretty(&v).unwrap();
    // Determinismus: zweimal serialisieren = identische Bytes.
    assert_eq!(bytes, serde_json::to_string_pretty(&v).unwrap());
    // Keine Umgebungs-Leaks im Snapshot.
    for leak in [
        std::env::temp_dir().to_string_lossy().into_owned(),
        "C:\\Users".into(),
    ] {
        assert!(!bytes.contains(&leak), "Umgebungs-Leak im Golden: {leak}");
    }
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
    // Rueckparse == Fixture (schliesst schleichende Typaenderung aus).
    let back: serde_json::Value = serde_json::from_str(&expected).unwrap();
    assert_eq!(back["schema_version"], SCHEMA_VERSION);
    assert_eq!(back, v);
}
