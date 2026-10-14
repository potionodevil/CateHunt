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
    }
}

fn test_record(fp: &str, cwe: &str, action: VerdictAction) -> CacheRecord {
    CacheRecord {
        fingerprint: fp.into(),
        verdict: test_verdict(cwe, action),
        created_at: "2026-10-14T00:00:00Z".into(),
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
