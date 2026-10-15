// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! M-4 Provenienz-Tests (AI-BOM): Verdict-Feld, Legacy-Kompatibilitaet,
//! Cache-Roundtrip mit Provenienz.
use cate_triage::{load_cache, lookup, store_verdict, CacheRecord, Verdict, VerdictAction};

fn verdict_ohne_provenance() -> Verdict {
    Verdict {
        rule_id: "semgrep:test.rule".into(),
        cwe: "CWE-79".into(),
        code_hash: "abc123".into(),
        action: VerdictAction::Close,
        severity_after: "medium".into(),
        model: "test".into(),
        prompt_version: "v1".into(),
        tokens_in: 0,
        tokens_out: 0,
        policy_override: false,
        provenance: None,
    }
}

#[test]
fn verdict_legacy_json_ohne_provenance_parst() {
    let legacy = r#"{"rule_id":"r","cwe":"CWE-79","code_hash":"h","action":"close","severity_after":"medium","model":"m","prompt_version":"v1","tokens_in":0,"tokens_out":0,"policy_override":false}"#;
    let v: Verdict = serde_json::from_str(legacy).unwrap();
    assert_eq!(v.provenance, None);
}

#[test]
fn verdict_ohne_provenance_serialisiert_ohne_key() {
    let v: serde_json::Value = serde_json::to_value(verdict_ohne_provenance()).unwrap();
    assert!(
        v.get("provenance").is_none(),
        "Cache-/Harness-Schutz: kein Key bei None"
    );
    // Top-Level-Form unveraendert (10 Keys wie vor M-4).
    assert_eq!(v.as_object().unwrap().len(), 10);
}

#[test]
fn verdict_mit_provenance_roundtrip() {
    let v = verdict_ohne_provenance()
        .with_provenance(cate_core::ProvenanceRecord::current_with_model("m"));
    let s = serde_json::to_string(&v).unwrap();
    assert!(s.contains("\"provenance\""));
    assert!(s.contains("\"commit_sha\""));
    let back: Verdict = serde_json::from_str(&s).unwrap();
    assert_eq!(back.provenance, v.provenance);
}

#[test]
fn cache_record_legacy_zeile_bleibt_lesbar() {
    let legacy = r#"{"fingerprint":"fp-1","rule_id":"r","cwe":"CWE-79","code_hash":"h","action":"open","severity_after":"medium","model":"m","prompt_version":"v1","tokens_in":0,"tokens_out":0,"policy_override":false,"created_at":"2026-10-14T00:00:00Z"}"#;
    let rec: CacheRecord = serde_json::from_str(legacy).unwrap();
    assert_eq!(rec.fingerprint, "fp-1");
    assert_eq!(rec.verdict.provenance, None);
}

#[test]
fn store_load_rundreise_erhaelt_provenance() {
    let dir = std::env::temp_dir().join(format!("cate_prov_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cache = dir.join("cache.jsonl");
    let mut v = verdict_ohne_provenance();
    v.attach_provenance(cate_core::ProvenanceRecord::current_with_model("m-neu"));
    let rec = CacheRecord {
        fingerprint: "fp-prov".into(),
        verdict: v,
        created_at: cate_core::utc_now_rfc3339(),
        format_version: cate_triage::CACHE_FORMAT_VERSION,
    };
    store_verdict(&cache, &rec).unwrap();
    let loaded = load_cache(&cache).unwrap();
    let hit = lookup(&loaded, "fp-prov").expect("cache hit erwartet");
    let p = hit
        .verdict
        .provenance
        .as_ref()
        .expect("provenance erwartet");
    assert_eq!(p.model, "m-neu");
    assert_eq!(p.tool_name, "cate");
    let _ = std::fs::remove_dir_all(&dir);
}
