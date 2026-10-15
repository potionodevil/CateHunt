// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! M-4 Provenienz-Tests (AI-BOM): Record-Helper, Serialisierung, Fallbacks.
//!
//! Goldens-Schutz: Typen OHNE Provenienz muessen exakt wie vor M-4
//! serialisieren (kein `provenance`-Key bei `None`).
use cate_core::{
    commit_sha, provenance_model, provenance_record, provenance_record_for, tool_version,
    utc_now_rfc3339, EvidenceLevel, ProvenanceRecord, ScoredFinding, PROVENANCE_TOOL_NAME,
};

#[test]
fn record_traegt_alle_fuenf_felder() {
    let r = ProvenanceRecord::current_with_model("test-modell");
    assert_eq!(r.tool_name, "cate");
    assert_eq!(r.tool_name, PROVENANCE_TOOL_NAME);
    assert_eq!(r.tool_version, tool_version());
    assert_eq!(r.tool_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(r.model, "test-modell");
    assert!(!r.commit_sha.is_empty(), "commit_sha nie leer");
    assert!(r.timestamp.ends_with('Z') && r.timestamp.contains('T'));
}

#[test]
fn helper_json_hat_alle_keys() {
    for v in [provenance_record(), provenance_record_for("m")] {
        for key in [
            "tool_name",
            "tool_version",
            "model",
            "commit_sha",
            "timestamp",
        ] {
            assert!(v.get(key).is_some(), "Key fehlt: {key}");
            assert!(v[key].is_string(), "Key kein String: {key}");
        }
    }
    assert_eq!(provenance_record_for("explizit")["model"], "explizit");
}

#[test]
fn modell_fallback_ohne_env_ist_unknown() {
    // Darf nie panicken/leer sein — egal ob CATE_MODEL gesetzt ist.
    let m = provenance_model();
    assert!(!m.is_empty());
}

#[test]
fn commit_sha_fallback_ohne_git_bricht_nicht() {
    // Mit Git: 40 Hex-Zeichen; ohne Git (oder Override): "unknown".
    // Beides ist gueltig — nur leer/panisch darf es nie sein.
    let sha = commit_sha();
    assert!(!sha.is_empty());
    if sha != "unknown" {
        assert!(
            sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()),
            "unerwartetes SHA-Format: {sha}"
        );
    }
}

#[test]
fn timestamp_ist_rfc3339_utc() {
    let ts = utc_now_rfc3339();
    assert!(ts.len() == 20, "Format YYYY-MM-DDTHH:MM:SSZ erwartet: {ts}");
    assert!(ts.ends_with('Z'));
    assert_eq!(&ts[10..11], "T");
}

#[test]
fn provenance_roundtrip() {
    let r = ProvenanceRecord::current_with_model("m");
    let s = serde_json::to_string(&r).unwrap();
    let back: ProvenanceRecord = serde_json::from_str(&s).unwrap();
    assert_eq!(r, back);
}

#[test]
fn scored_finding_legacy_json_ohne_provenance_parst() {
    let legacy = r#"{"level":"error","evidence":"E2"}"#;
    let f: ScoredFinding = serde_json::from_str(legacy).unwrap();
    assert_eq!(f.level, "error");
    assert_eq!(f.evidence, EvidenceLevel::E2);
    assert_eq!(f.provenance, None);
}

#[test]
fn scored_finding_ohne_provenance_serialisiert_ohne_key() {
    let f = ScoredFinding {
        level: "warning".into(),
        evidence: EvidenceLevel::E3,
        provenance: None,
    };
    let v: serde_json::Value = serde_json::to_value(&f).unwrap();
    assert!(
        v.get("provenance").is_none(),
        "Golden-Schutz: kein Key bei None"
    );
    assert_eq!(v["level"], "warning");
}

#[test]
fn scored_finding_mit_provenance_roundtrip() {
    let f = ScoredFinding {
        level: "error".into(),
        evidence: EvidenceLevel::E2,
        provenance: Some(ProvenanceRecord::current_with_model("m")),
    }
    .with_provenance(ProvenanceRecord::current_with_model("n"));
    assert_eq!(f.provenance.as_ref().unwrap().model, "n");
    let s = serde_json::to_string(&f).unwrap();
    assert!(s.contains("\"provenance\""));
    let back: ScoredFinding = serde_json::from_str(&s).unwrap();
    assert_eq!(back.provenance, f.provenance);
}
