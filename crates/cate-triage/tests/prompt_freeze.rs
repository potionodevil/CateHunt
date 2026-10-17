// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Prompt-Freeze (P2, TESTING.md §2.1): Systemprompt-Hash pro Adapter.
//!
//! Jede Aenderung am Prompt-Template (Wortlaut, Regeln, Kappung, Redaction)
//! aendert den Hash und macht diesen Test ROT — das ist Absicht: Prompt-Drift
//! braucht bewusstes Review, kein stilles Durchrutschen. Update nur mit
//! Doku des Grundes (PROMPT_VERSION-Bump + Hash-Erneuerung hier).

use cate_triage::{deep_engines, gemini, ollama};

/// Stabile FNV-1a-64 ueber die Prompt-Bytes (deterministisch, plattformunabhaengig).
fn fnv1a_hex(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn fixture_ctx() -> ollama::FindingContext {
    ollama::FindingContext {
        rule_id: "semgrep:test.rule".into(),
        cwe: "CWE-502".into(),
        file: "src/auth.py".into(),
        start_line: Some(7),
        message: "unsichere Deserialisierung".into(),
        code_snippet: "pickle.loads(data)\n".into(),
    }
}

// Gefroren 2026-10-17 (FNV-1a-64 ueber Fixture-Prompt). Aenderung nur mit
// PROMPT_VERSION-Bump + Review-Doku (TESTING.md §2.1).
const FROZEN_OLLAMA: &str = "6ce4901fa27c411c";
const FROZEN_GEMINI: &str = "6ce4901fa27c411c";
const FROZEN_DEEP: &str = "6ce4901fa27c411c";

#[test]
fn prompt_version_ist_v1_fuer_alle_adapter() {
    assert_eq!(ollama::PROMPT_VERSION, "v1");
    assert_eq!(gemini::PROMPT_VERSION, "v1");
    assert_eq!(deep_engines::PROMPT_VERSION, "v1");
}

#[test]
fn ollama_prompt_hash_gefroren() {
    let p = ollama::build_prompt(&fixture_ctx(), "qwen2.5-coder:7b");
    assert_eq!(
        fnv1a_hex(&p),
        FROZEN_OLLAMA,
        "Ollama-Prompt gedriftet — Review + Hash-Update noetig"
    );
}

#[test]
fn gemini_prompt_hash_gefroren() {
    let p = gemini::build_prompt(&fixture_ctx(), "gemini");
    assert_eq!(
        fnv1a_hex(&p),
        FROZEN_GEMINI,
        "Gemini-Prompt gedriftet — Review + Hash-Update noetig"
    );
}

#[test]
fn deep_prompt_hash_gefroren() {
    let p = deep_engines::build_prompt(&fixture_ctx(), "claude");
    assert_eq!(
        fnv1a_hex(&p),
        FROZEN_DEEP,
        "Deep-Prompt gedriftet — Review + Hash-Update noetig"
    );
}

#[test]
fn alle_adapter_teilen_sich_das_template() {
    // Gemuess TESTING.md §2.1: identische Regeln (E2-Cap, Deny-escalate, Redaction).
    let c = fixture_ctx();
    let (o, g, d) = (
        ollama::build_prompt(&c, "m"),
        gemini::build_prompt(&c, "m"),
        deep_engines::build_prompt(&c, "m"),
    );
    assert_eq!(fnv1a_hex(&o), fnv1a_hex(&g));
    assert_eq!(fnv1a_hex(&o), fnv1a_hex(&d));
}

#[test]
fn prompt_enthaelt_sicherheitsregeln() {
    // Inhaltliche Anker (ergaenzen den Hash): E2-Cap + Deny-escalate + JSON-Format.
    let p = ollama::build_prompt(&fixture_ctx(), "m");
    assert!(p.contains("E2"), "E2-Cap fehlt im Prompt");
    assert!(p.contains("NIE suppressen"), "Deny-Regel fehlt im Prompt");
    assert!(
        p.contains("AUSSCHLIESSLICH als JSON"),
        "JSON-Formatzwang fehlt im Prompt"
    );
}
