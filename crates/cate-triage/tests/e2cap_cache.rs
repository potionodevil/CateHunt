// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! P1: E2-Cap ueber alle Adapter + Cache-Hit/Miss-Matrix (TESTING.md §2.2/§2.4).
//!
//! - E3/E4-Vorschlaege werden auf E2 gekappt (ollama, gemini, deep_engines).
//! - Cache-Hit ohne Modell-Call (Runner wird nie aufgerufen / Garbage-Output
//!   wird nie geparst); geaenderter Input -> Miss; Modellname im Record.
//! - Deny-Cap: suppress auf Deny-CWE -> escalate + Override (alle Adapter).
use cate_triage::ollama::{decide_with_cache, FindingContext};
use std::collections::HashMap;

fn ctx(cwe: &str, snippet: &str) -> FindingContext {
    FindingContext {
        rule_id: "semgrep:test.rule".into(),
        cwe: cwe.into(),
        file: "a.py".into(),
        start_line: Some(1),
        message: "msg".into(),
        code_snippet: snippet.into(),
    }
}

fn proposal(ev: &str, verdict: &str) -> String {
    format!("{{\"verdict\": \"{verdict}\", \"evidence_proposed\": \"{ev}\", \"reason\": \"t\"}}")
}

#[test]
fn e2_cap_gilt_fuer_alle_adapter() {
    // gemini/deep_engines delegieren an ollama::parse_proposal — trotzdem
    // pro Adapter getestet (Freeze gegen stilles Abweichen).
    for ev in ["E3", "E4"] {
        let raw = proposal(ev, "confirm");
        for (name, p) in [
            (
                "ollama",
                cate_triage::ollama::parse_proposal(&raw, "CWE-79"),
            ),
            (
                "gemini",
                cate_triage::gemini::parse_proposal(&raw, "CWE-79"),
            ),
            (
                "deep",
                cate_triage::deep_engines::parse_proposal(&raw, "CWE-79"),
            ),
        ] {
            let p = p.unwrap_or_else(|e| panic!("{name}: parse fehlgeschlagen: {e}"));
            assert_eq!(p.evidence_proposed, "E2", "{name} kappt {ev} nicht");
        }
    }
    // E0/E1 bleiben unveraendert (alle Adapter).
    for ev in ["E0", "E1", "E2"] {
        let raw = proposal(ev, "confirm");
        assert_eq!(
            cate_triage::ollama::parse_proposal(&raw, "CWE-79")
                .unwrap()
                .evidence_proposed,
            ev
        );
        assert_eq!(
            cate_triage::gemini::parse_proposal(&raw, "CWE-79")
                .unwrap()
                .evidence_proposed,
            ev
        );
        assert_eq!(
            cate_triage::deep_engines::parse_proposal(&raw, "CWE-79")
                .unwrap()
                .evidence_proposed,
            ev
        );
    }
}

#[test]
fn deny_cap_suppress_wird_eskaliert_alle_adapter() {
    for cwe in ["CWE-328", "CWE-798", "CWE-502"] {
        let raw = proposal("E3", "suppress");
        for (name, p) in [
            ("ollama", cate_triage::ollama::parse_proposal(&raw, cwe)),
            ("gemini", cate_triage::gemini::parse_proposal(&raw, cwe)),
            ("deep", cate_triage::deep_engines::parse_proposal(&raw, cwe)),
        ] {
            let p = p.unwrap_or_else(|e| panic!("{name}: parse fehlgeschlagen: {e}"));
            assert_eq!(p.verdict, "escalate", "{name} {cwe}: kein Escalate");
            assert_eq!(p.evidence_proposed, "E2", "{name} {cwe}: kein E2-Cap");
            assert!(p.policy_override, "{name} {cwe}: Override-Flag fehlt");
        }
    }
}

#[test]
fn cache_hit_ohne_modell_call_alle_adapter() {
    // Cache mit Record fuettern; Hit-Pfad mit Garbage-Modelltext aufrufen —
    // faende ein Parse statt, wuerde das fehlschlagen. Beweist: kein Call.
    let c = ctx("CWE-79", "let x = 1;");
    let fp = c.fingerprint();
    let mut cache: HashMap<String, cate_triage::CacheRecord> = HashMap::new();
    cache.insert(
        fp.clone(),
        cate_triage::CacheRecord {
            fingerprint: fp.clone(),
            verdict: cate_triage::Verdict {
                rule_id: "semgrep:test.rule".into(),
                cwe: "CWE-79".into(),
                code_hash: cate_triage::code_hash("let x = 1;"),
                action: cate_triage::VerdictAction::Close,
                severity_after: "medium".into(),
                model: "m1".into(),
                prompt_version: "v1".into(),
                tokens_in: 0,
                tokens_out: 0,
                policy_override: false,
                provenance: None,
            },
            created_at: "2026-10-14T00:00:00Z".into(),
            format_version: cate_triage::CACHE_FORMAT_VERSION,
        },
    );
    let garbage = "definitiv kein JSON {{{";
    let o = decide_with_cache(&cache, &c, garbage, "m-neu").unwrap();
    assert!(o.cache_hit);
    assert_eq!(o.record.fingerprint, fp);
    let g = cate_triage::gemini::decide_with_cache(&cache, &c, garbage, "m-neu").unwrap();
    assert!(g.cache_hit);
    let d = cate_triage::deep_engines::decide_with_cache(&cache, &c, garbage, "m-neu").unwrap();
    assert!(d.cache_hit);
}

#[test]
fn runner_wird_bei_hit_nie_aufgerufen() {
    // End-to-end mit panickendem Runner: Hit darf ihn nie erreichen.
    let c = ctx("CWE-79", "let x = 1;");
    let fp = c.fingerprint();
    let mut cache: HashMap<String, cate_triage::CacheRecord> = HashMap::new();
    cache.insert(
        fp.clone(),
        cate_triage::CacheRecord {
            fingerprint: fp,
            verdict: cate_triage::Verdict {
                rule_id: "r".into(),
                cwe: "CWE-79".into(),
                code_hash: "h".into(),
                action: cate_triage::VerdictAction::Open,
                severity_after: "medium".into(),
                model: "m".into(),
                prompt_version: "v1".into(),
                tokens_in: 0,
                tokens_out: 0,
                policy_override: false,
                provenance: None,
            },
            created_at: "t".into(),
            format_version: cate_triage::CACHE_FORMAT_VERSION,
        },
    );
    let g = cate_triage::gemini::triage_with_runner(
        &cache,
        &c,
        &cate_triage::gemini::GeminiConfig::default(),
        |_, _| panic!("Modell-Runner darf bei Hit nicht laufen (gemini)"),
    )
    .unwrap();
    assert!(g.cache_hit);
    let d = cate_triage::deep_engines::triage_with_runner(
        &cache,
        &c,
        &cate_triage::deep_engines::DeepConfig::opencode(),
        |_, _| panic!("Modell-Runner darf bei Hit nicht laufen (deep)"),
    )
    .unwrap();
    assert!(d.cache_hit);
}

#[test]
fn geaenderter_input_ist_miss_modellname_im_record() {
    let cache: HashMap<String, cate_triage::CacheRecord> = HashMap::new();
    let c1 = ctx("CWE-79", "let x = 1;");
    let c2 = ctx("CWE-79", "let x = 2; // geaendert");
    assert_ne!(c1.fingerprint(), c2.fingerprint(), "Key muss Input hashen");
    let ok = proposal("E1", "confirm");
    let o = decide_with_cache(&cache, &c1, &ok, "modell-xyz").unwrap();
    assert!(!o.cache_hit);
    assert_eq!(o.record.verdict.model, "modell-xyz");
    // Unterschiedliche Rule -> anderer Key.
    let mut c3 = ctx("CWE-79", "let x = 1;");
    c3.rule_id = "semgrep:other.rule".into();
    assert_ne!(c1.fingerprint(), c3.fingerprint());
}

#[test]
fn deny_miss_kappt_und_eskaliert_in_decide() {
    let cache: HashMap<String, cate_triage::CacheRecord> = HashMap::new();
    let c = ctx("CWE-328", "import md5;");
    let evil = proposal("E4", "suppress");
    let o = decide_with_cache(&cache, &c, &evil, "m").unwrap();
    assert!(!o.cache_hit);
    assert_eq!(o.proposal.verdict, "escalate");
    assert_eq!(o.proposal.evidence_proposed, "E2");
    assert_eq!(o.record.verdict.action, cate_triage::VerdictAction::Demote);
    assert!(o.record.verdict.policy_override);
}

#[test]
fn legacy_fingerprint_ist_miss_trotz_eintrag() {
    // 64-bit-Alt-Eintrag direkt in der Map: decide_with_cache darf ihn
    // nie als Hit werten, sondern muss den Modell-Output parsen (Miss).
    let legacy_fp = "0123456789abcdef";
    assert!(cate_core::is_legacy_hash(legacy_fp));
    let c = ctx("CWE-79", "let x = 1;");
    let mut cache: HashMap<String, cate_triage::CacheRecord> = HashMap::new();
    cache.insert(
        legacy_fp.to_string(),
        cate_triage::CacheRecord {
            fingerprint: legacy_fp.into(),
            verdict: cate_triage::Verdict {
                rule_id: "semgrep:test.rule".into(),
                cwe: "CWE-79".into(),
                code_hash: legacy_fp.into(),
                action: cate_triage::VerdictAction::Close,
                severity_after: "medium".into(),
                model: "alt".into(),
                prompt_version: "v1".into(),
                tokens_in: 0,
                tokens_out: 0,
                policy_override: false,
                provenance: None,
            },
            created_at: "2026-10-14T00:00:00Z".into(),
            format_version: 0,
        },
    );
    let ok = proposal("E1", "confirm");
    let o = decide_with_cache(&cache, &c, &ok, "m-neu").unwrap();
    assert!(!o.cache_hit, "legacy-eintrag darf nie Hit sein");
    assert_eq!(o.proposal.verdict, "confirm");
    assert_eq!(o.record.verdict.model, "m-neu");
}
