// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Eskalations-Guard (P2, TESTING.md §2.3): Deep nur bei Opt-in + Deny + unsicher,
//! sonst NIE ein Modell-Call.
//!
//! Guard-Regel: `select_deep_engine` liefert nur bei
//! (deny_cwe && uncertain && deep_opt_in) eine Engine — jede andere
//! Kombination bleibt bei Stufe 1/2 bzw. deterministischem Fallback.
//! Offline (keine Stufe verfuegbar) darf der Modell-Runner 0-mal laufen.

use cate_triage::deep_engines::{select_deep_engine, Engine};
use cate_triage::pipeline::{
    plan_stages_checked, run_chain_with_fallback, Stage, StageAvailability,
};

#[test]
fn deep_nur_bei_opt_in_plus_deny_plus_unsicher() {
    // Einzige erlaubte Kombination.
    assert_eq!(
        select_deep_engine(true, true, true, Engine::Claude),
        Some(Engine::Claude)
    );
    assert_eq!(
        select_deep_engine(true, true, true, Engine::Opencode),
        Some(Engine::Opencode)
    );
}

#[test]
fn deep_ohne_opt_in_nie() {
    // Vollmatrix: sobald ein Flag fehlt, kein Deep — egal welche Engine.
    for prefer in [Engine::Claude, Engine::Opencode] {
        assert_eq!(
            select_deep_engine(true, true, false, prefer),
            None,
            "ohne Opt-in"
        );
        assert_eq!(
            select_deep_engine(true, false, true, prefer),
            None,
            "ohne Unsicherheit"
        );
        assert_eq!(
            select_deep_engine(false, true, true, prefer),
            None,
            "ohne Deny-CWE"
        );
        assert_eq!(
            select_deep_engine(false, false, false, prefer),
            None,
            "alles aus"
        );
    }
}

#[test]
fn plan_ohne_opt_in_enthaelt_nie_deep() {
    let avail = StageAvailability::all_available();
    for uncertain in [true, false] {
        for deny in [true, false] {
            let plan = plan_stages_checked(deny, uncertain, false, Engine::Claude, &avail);
            assert_eq!(plan.deep, None, "deny={deny} uncertain={uncertain}");
            assert!(
                !plan.chain.iter().any(|s| matches!(s, Stage::Deep(_))),
                "Kette enthaelt Deep ohne Opt-in"
            );
        }
    }
}

#[test]
fn plan_mit_opt_in_aber_ohne_deny_oder_sicherheit_enthaelt_nie_deep() {
    let avail = StageAvailability::all_available();
    // Opt-in allein reicht nicht: Deny UND unsicher muessen dazu.
    let plan = plan_stages_checked(false, true, true, Engine::Claude, &avail);
    assert_eq!(plan.deep, None);
    let plan = plan_stages_checked(true, false, true, Engine::Claude, &avail);
    assert_eq!(plan.deep, None);
    let plan = plan_stages_checked(true, true, true, Engine::Claude, &avail);
    assert_eq!(plan.deep, Some(Engine::Claude));
}

#[test]
fn offline_laueft_kein_modell_call_nur_fallback() {
    // Offline-Verfuegbarkeit: leere Kette -> Fallback, Runner 0-mal aufgerufen.
    let plan = plan_stages_checked(
        true,
        true,
        true,
        Engine::Claude,
        &StageAvailability::offline(),
    );
    assert!(plan.chain.is_empty(), "offline muss Kette leer sein");
    let mut calls = 0;
    let out = run_chain_with_fallback(
        &plan.chain,
        &mut |_: &Stage| -> Result<&str, String> {
            calls += 1;
            Ok("modell")
        },
        || "fallback",
    );
    assert_eq!(calls, 0, "offline darf kein Modell-Call laufen");
    assert!(out.used_fallback);
    assert_eq!(out.value, "fallback");
    assert_eq!(out.stage, None);
}

#[test]
fn ohne_deep_cli_kein_deep_in_kette() {
    // Deep-CLI fehlt im PATH: Plan zeigt ehrlich `deep: None`, keine tote Stufe.
    let avail = StageAvailability {
        ollama_reachable: true,
        gemini_cli_present: true,
        deep_cli_present: false,
    };
    let plan = plan_stages_checked(true, true, true, Engine::Opencode, &avail);
    assert_eq!(plan.deep, None);
    assert!(!plan.chain.iter().any(|s| matches!(s, Stage::Deep(_))));
}
