// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Paket A — Cache-Roundtrip + Deny-Hochstufung (CWE-328).
//!
//! TDD RED: scheitert, bis `load_cache`/`store_verdict`/`lookup` existieren.
use cate_triage::{load_cache, lookup, store_verdict, CacheRecord, Verdict, VerdictAction};
use std::collections::HashMap;

fn test_verdict(cwe: &str, action: VerdictAction) -> Verdict {
    Verdict {
        rule_id: "semgrep:test.rule".into(),
        cwe: cwe.into(),
        code_hash: "abc123".into(),
        action,
        severity_after: "high".into(),
        model: "test".into(),
        prompt_version: "v1".into(),
        tokens_in: 0,
        tokens_out: 0,
        policy_override: false,
        provenance: None,
    }
}

fn test_record(fp: &str, cwe: &str, action: VerdictAction) -> CacheRecord {
    CacheRecord {
        fingerprint: fp.into(),
        verdict: test_verdict(cwe, action),
        created_at: "2026-10-14T00:00:00Z".into(),
        format_version: cate_triage::CACHE_FORMAT_VERSION,
    }
}

#[test]
fn roundtrip_store_then_lookup_hits() {
    let dir = std::env::temp_dir().join(format!("cate_rt_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cache = dir.join("cache.jsonl");

    // Leerer Cache: Miss.
    let empty = load_cache(&cache).unwrap();
    assert!(lookup(&empty, "fp-1").is_none());

    // Store + Reload + Lookup = Hit ohne Modell-Call.
    store_verdict(&cache, &test_record("fp-1", "CWE-79", VerdictAction::Close)).unwrap();
    let loaded = load_cache(&cache).unwrap();
    let hit = lookup(&loaded, "fp-1").expect("cache hit erwartet");
    assert_eq!(hit.verdict.action, VerdictAction::Close);
    assert!(!hit.verdict.policy_override);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn deny_cwe_328_suppress_wird_eskaliert() {
    // close/suppress auf Deny-CWE-328 darf nie persistiert werden:
    // Policy stuft zu demote (= escalate) hoch + Override-Flag.
    let dir = std::env::temp_dir().join(format!("cate_deny_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cache = dir.join("cache.jsonl");

    let overridden = store_verdict(
        &cache,
        &test_record("fp-328", "CWE-328", VerdictAction::Close),
    )
    .unwrap();
    assert!(overridden, "policy muss bei CWE-328 eingreifen");

    let loaded: HashMap<String, CacheRecord> = load_cache(&cache).unwrap();
    let hit = lookup(&loaded, "fp-328").expect("cache hit erwartet");
    assert_eq!(hit.verdict.action, VerdictAction::Demote);
    assert!(hit.verdict.policy_override);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn legacy_zeile_wird_zu_miss_nie_hit() {
    // Alte 64-bit-Caches (16-stelliger Fingerprint, keine format_version)
    // duerfen nach der sha256-Umstellung nie als Hit gelten.
    let dir = std::env::temp_dir().join(format!("cate_legacy_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cache = dir.join("cache.jsonl");

    let legacy_fp = "0123456789abcdef";
    assert!(cate_core::is_legacy_hash(legacy_fp));
    let legacy_zeile = format!(
        "{{\"fingerprint\":\"{legacy_fp}\",\"rule_id\":\"r\",\"cwe\":\"CWE-79\",\
         \"code_hash\":\"{legacy_fp}\",\"action\":\"close\",\"severity_after\":\"high\",\
         \"model\":\"alt\",\"prompt_version\":\"v1\",\"tokens_in\":0,\"tokens_out\":0,\
         \"policy_override\":false,\"created_at\":\"2026-10-14T00:00:00Z\"}}"
    );
    std::fs::write(&cache, format!("{legacy_zeile}\n")).unwrap();

    let loaded = load_cache(&cache).unwrap();
    assert!(loaded.is_empty(), "legacy-zeile muss verworfen werden");
    assert!(lookup(&loaded, legacy_fp).is_none());

    // Auch direkt eingelegt (ohne load_cache-Filter) bleibt es ein Miss.
    let mut direkt = HashMap::new();
    direkt.insert(
        legacy_fp.to_string(),
        CacheRecord {
            fingerprint: legacy_fp.into(),
            verdict: test_verdict("CWE-79", VerdictAction::Close),
            created_at: "2026-10-14T00:00:00Z".into(),
            format_version: 0,
        },
    );
    assert!(lookup(&direkt, legacy_fp).is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn roundtrip_stempelt_format_version_und_trifft() {
    let dir = std::env::temp_dir().join(format!("cate_ver_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cache = dir.join("cache.jsonl");

    // Rekord ohne Version einliefern — store_verdict stempelt aktuell.
    let rec = CacheRecord {
        fingerprint: "fp-neu".into(),
        verdict: test_verdict("CWE-79", VerdictAction::Close),
        created_at: "2026-10-14T00:00:00Z".into(),
        format_version: 0,
    };
    store_verdict(&cache, &rec).unwrap();

    let roh = std::fs::read_to_string(&cache).unwrap();
    assert!(
        roh.contains(&format!(
            "\"format_version\":{}",
            cate_triage::CACHE_FORMAT_VERSION
        )),
        "persistierte zeile ohne version: {roh}"
    );

    let loaded = load_cache(&cache).unwrap();
    let hit = lookup(&loaded, "fp-neu").expect("cache hit erwartet");
    assert_eq!(hit.format_version, cate_triage::CACHE_FORMAT_VERSION);
    assert_eq!(hit.verdict.action, VerdictAction::Close);

    let _ = std::fs::remove_dir_all(&dir);
}
