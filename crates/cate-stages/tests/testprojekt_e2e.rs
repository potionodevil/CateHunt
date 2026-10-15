// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Testprojekt-E2E (offline): Stufe 1 -> Signale -> deterministischer Fallback
//! -> Kette -> Health, geprueft gegen `testprojekt/expected.json`.
//!
//! Kein Netz, kein Modell, keine CLIs: `StageAvailability::offline` plus
//! injizierte Runner, die immer fehlschlagen — der Fallback muss alles tragen.
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

fn testprojekt_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testprojekt")
}

fn load_fixture() -> serde_json::Value {
    let raw = std::fs::read_to_string(testprojekt_dir().join("expected.json"))
        .expect("testprojekt/expected.json lesbar");
    serde_json::from_str(&raw).expect("expected.json gueltig")
}

#[test]
fn stufe1_signale_fallback_gegen_fixture() {
    let fx = load_fixture();
    let cases = fx["cases"].as_array().expect("cases als Array");
    assert!(!cases.is_empty(), "Fixture ohne Faelle");
    let cache: HashMap<String, cate_triage::CacheRecord> = HashMap::new();
    let th = cate_stages::Stage1Thresholds::default();

    for c in cases {
        let file = c["file"].as_str().expect("file");
        let cwe = c["cwe"].as_str().expect("cwe");
        let src = std::fs::read_to_string(testprojekt_dir().join(file))
            .unwrap_or_else(|e| panic!("{file} lesbar: {e}"));

        // 1) Stufe 1.
        let s1 = cate_stages::stage1_scan(file, &src, &th);
        assert_eq!(
            s1.clean,
            c["stage1_clean"].as_bool().unwrap(),
            "stufe-1-weiche falsch bei {file}: {s1:?}"
        );
        assert_eq!(s1.evidence, cate_core::EvidenceLevel::E0);

        // 2) Signale.
        let sig = cate_stages::signals_from_source(&src, cwe);
        assert_eq!(
            sig.architecture_hint,
            c["architecture_hint"].as_bool().unwrap(),
            "architektur-signal falsch bei {file}"
        );
        assert_eq!(
            sig.complexity_hint,
            c["complexity_hint"].as_bool().unwrap(),
            "komplexitaet-signal falsch bei {file}"
        );

        // 3) Deterministischer Fallback: nie suppress/Close, nie > E2.
        let ctx = cate_triage::ollama::FindingContext {
            rule_id: c["rule_id"].as_str().unwrap().to_string(),
            cwe: cwe.to_string(),
            file: file.to_string(),
            start_line: Some(1),
            message: c["message"].as_str().unwrap().to_string(),
            code_snippet: src.clone(),
        };
        let out = cate_triage::pipeline::deterministic_triage(&cache, &ctx)
            .unwrap_or_else(|e| panic!("fallback bei {file}: {e}"));
        assert!(!out.cache_hit);
        assert_eq!(
            out.proposal.verdict,
            c["deterministic_verdict"].as_str().unwrap(),
            "fallback-verdict falsch bei {file}"
        );
        assert_eq!(
            out.proposal.evidence_proposed,
            c["deterministic_evidence"].as_str().unwrap(),
            "fallback-evidence falsch bei {file}"
        );
        assert_ne!(
            out.record.verdict.action,
            cate_triage::VerdictAction::Close,
            "fallback schliesst nie ({file})"
        );

        // 4) Deny-Flag ehrlich.
        let deny = cate_triage::verdict_cap(cwe) == cate_triage::MaxAction::DemoteOnly;
        assert_eq!(deny, c["deny"].as_bool().unwrap(), "deny-flag bei {file}");
        if deny {
            assert_eq!(out.proposal.verdict, "escalate");
        }
    }
}

#[test]
fn offline_kette_faellt_ohne_netz_aufs_fallback() {
    let fx = load_fixture();
    let first = &fx["cases"][0];
    let file = first["file"].as_str().unwrap();
    let src = std::fs::read_to_string(testprojekt_dir().join(file)).unwrap();
    let ctx = cate_triage::ollama::FindingContext {
        rule_id: first["rule_id"].as_str().unwrap().to_string(),
        cwe: first["cwe"].as_str().unwrap().to_string(),
        file: file.to_string(),
        start_line: Some(1),
        message: first["message"].as_str().unwrap().to_string(),
        code_snippet: src,
    };
    // Offline: leere Kette, beide (mock-)Stufen down.
    let plan = cate_triage::pipeline::plan_stages_checked(
        false,
        false,
        false,
        cate_triage::deep_engines::Engine::Claude,
        &cate_triage::pipeline::StageAvailability::offline(),
    );
    assert!(plan.chain.is_empty());
    let cache: HashMap<String, cate_triage::CacheRecord> = HashMap::new();
    let out = cate_triage::pipeline::run_chain_with_fallback(
        &plan.chain,
        &mut |_| Err::<cate_triage::ollama::TriageOutcome, String>("alles down".to_string()),
        || {
            cate_triage::pipeline::deterministic_triage(&cache, &ctx)
                .expect("fallback deterministisch")
        },
    );
    assert!(out.used_fallback, "offline muss Fallback nutzen");
    assert_eq!(out.stage, None);
    assert_eq!(
        out.value.proposal.verdict,
        first["deterministic_verdict"].as_str().unwrap()
    );
    assert_eq!(
        out.value.proposal.evidence_proposed,
        first["deterministic_evidence"].as_str().unwrap()
    );
}

#[test]
fn health_gegen_fixture() {
    let fx = load_fixture();
    let cases = fx["cases"].as_array().unwrap();
    let mut metrics = Vec::new();
    let mut findings = Vec::new();
    let cache: HashMap<String, cate_triage::CacheRecord> = HashMap::new();

    for c in cases {
        let file = c["file"].as_str().unwrap();
        let cwe = c["cwe"].as_str().unwrap();
        let src = std::fs::read_to_string(testprojekt_dir().join(file)).unwrap();
        metrics.push(cate_core::analyze_file(file, &src));
        let ctx = cate_triage::ollama::FindingContext {
            rule_id: c["rule_id"].as_str().unwrap().to_string(),
            cwe: cwe.to_string(),
            file: file.to_string(),
            start_line: Some(1),
            message: c["message"].as_str().unwrap().to_string(),
            code_snippet: src,
        };
        let out = cate_triage::pipeline::deterministic_triage(&cache, &ctx).unwrap();
        findings.push(cate_core::ScoredFinding {
            level: c["level"].as_str().unwrap().to_string(),
            evidence: cate_core::EvidenceLevel::from_str(&out.proposal.evidence_proposed).unwrap(),
            provenance: None,
        });
    }

    let h = cate_core::health_score(&metrics, &findings, 0);
    let want = &fx["health"];
    assert_eq!(
        h.total_e2_plus,
        want["total_e2_plus"].as_u64().unwrap() as usize,
        "e2+-zaehlung: {h:?}"
    );
    assert_eq!(
        h.security,
        want["security"].as_u64().unwrap() as u8,
        "security-score: {h:?}"
    );
    assert_eq!(
        cate_core::health_grade(h.total),
        want["grade"].as_str().unwrap(),
        "health-note: {h:?}"
    );
    assert!(
        h.security < 100,
        "vulnerable Samples muessen Security senken"
    );
    // Saubere Referenz allein: volle Punktzahl.
    let clean = cate_core::health_score(&[], &[], 0);
    assert_eq!(clean.total, 100);
    assert_eq!(cate_core::health_grade(clean.total), "A");
}
