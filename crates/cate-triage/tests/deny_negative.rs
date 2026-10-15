// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Deny-Negativ-Tests (P0): alle 17 Deny-CWEs x alle Verdict-Schreibweisen.
//!
//! Invariante: close/suppress auf Deny-CWE wird NIE close/suppress,
//! sondern hochgestuft (escalate/demote + Override-Flag). Begruendung ist Pflicht.

use cate_triage::{apply_policy, parse_action, verdict_cap, MaxAction, Verdict, VerdictAction};

const DENY: [&str; 17] = [
    "327", "328", "326", "331", "338", "259", "798", "321", "287", "384", "613", "620", "639",
    "862", "863", "502", "915",
];

fn verdict_for(cwe: &str, action: VerdictAction) -> Verdict {
    Verdict {
        rule_id: "t".into(),
        cwe: cwe.into(),
        code_hash: "abc".into(),
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

#[test]
fn alle_17_deny_cwes_kappen_close() {
    assert_eq!(DENY.len(), 17);
    for cwe in DENY {
        assert_eq!(
            verdict_cap(&format!("CWE-{cwe}")),
            MaxAction::DemoteOnly,
            "Deny-Cap fehlt: {cwe}"
        );
    }
}

#[test]
fn close_und_suppress_werden_auf_deny_nie_close() {
    // Alle Schreibweisen aus parse_action-Vokabular: close/suppress in allen Cases.
    let spellings = [
        "close", "suppress", "Close", "Suppress", "CLOSE", "SUPPRESS",
    ];
    for cwe in DENY {
        for s in spellings {
            let action = parse_action(s).unwrap_or_else(|| panic!("parse_action kennt {s} nicht"));
            assert_eq!(action, VerdictAction::Close, "Alias {s} muss Close mappen");
            let mut v = verdict_for(&format!("CWE-{cwe}"), action);
            assert!(apply_policy(&mut v), "Policy griff nicht ein: {cwe}/{s}");
            assert_ne!(
                v.action,
                VerdictAction::Close,
                "nie close auf Deny: {cwe}/{s}"
            );
            assert_eq!(v.action, VerdictAction::Demote);
            assert!(v.policy_override, "Override-Flag Pflicht: {cwe}/{s}");
        }
    }
}

#[test]
fn modell_suppress_wird_auf_deny_immer_eskaliert_mit_begruendung() {
    // close/suppress-Schreibweisen des Modell-Vokabulars (ollama/gemini/deep_engines
    // teilen sich einen Parser): suppress|close in allen Cases.
    let verdict_spellings = [
        "suppress", "close", "Suppress", "Close", "SUPPRESS", "CLOSE",
    ];
    for cwe in DENY {
        for vs in verdict_spellings {
            let raw = format!(
                "{{\"verdict\": \"{vs}\", \"evidence_proposed\": \"E1\", \"reason\": \"begruendung {cwe}\"}}"
            );
            for parse in [
                cate_triage::ollama::parse_proposal,
                cate_triage::gemini::parse_proposal,
                cate_triage::deep_engines::parse_proposal,
            ] {
                let p = parse(&raw, &format!("CWE-{cwe}"))
                    .unwrap_or_else(|e| panic!("parse schlug fehl {cwe}/{vs}: {e}"));
                assert_ne!(p.verdict, "suppress", "nie suppress auf Deny: {cwe}/{vs}");
                assert_eq!(
                    p.verdict, "escalate",
                    "Deny-suppress muss escalate: {cwe}/{vs}"
                );
                assert!(p.policy_override, "Override-Flag Pflicht: {cwe}/{vs}");
                assert!(
                    !p.reason.trim().is_empty(),
                    "Begruendung Pflicht: {cwe}/{vs}"
                );
            }
        }
    }
}

#[test]
fn begruendung_ist_pflicht_leer_oder_fehlend_ist_fehler() {
    for raw in [
        "{\"verdict\": \"confirm\", \"evidence_proposed\": \"E1\"}",
        "{\"verdict\": \"confirm\", \"evidence_proposed\": \"E1\", \"reason\": \"\"}",
        "{\"verdict\": \"confirm\", \"evidence_proposed\": \"E1\", \"reason\": \"   \"}",
        "{\"verdict\": \"suppress\", \"evidence_proposed\": \"E1\", \"reason\": \"\"}",
    ] {
        for parse in [
            cate_triage::ollama::parse_proposal,
            cate_triage::gemini::parse_proposal,
            cate_triage::deep_engines::parse_proposal,
        ] {
            assert!(
                parse(raw, "CWE-79").is_err(),
                "leere/fehlende Begruendung muss Fehler sein: {raw}"
            );
        }
    }
}

#[test]
fn alle_schreibweisen_aller_deny_cwes_werden_erkannt() {
    for cwe in DENY {
        for variant in [
            format!("CWE-{cwe}"),
            format!("cwe-{cwe}"),
            format!("CWE{cwe}"),
            format!("cwe{cwe}"),
            format!("CWE {cwe}"),
            format!("  CWE-{cwe}  "),
        ] {
            assert_eq!(
                verdict_cap(&variant),
                MaxAction::DemoteOnly,
                "Schreibweise nicht erkannt: {variant}"
            );
            let raw = "{\"verdict\": \"suppress\", \"evidence_proposed\": \"E1\", \"reason\": \"fp-pruefung\"}";
            let p = cate_triage::ollama::parse_proposal(raw, &variant)
                .unwrap_or_else(|e| panic!("parse schlug fehl {variant}: {e}"));
            assert_eq!(p.verdict, "escalate", "Deny-Cap fehlt: {variant}");
            assert!(p.policy_override);
        }
    }
}

#[test]
fn nicht_deny_darf_suppressen() {
    // Gegenprobe: kein Overblocking auf Nicht-Deny-CWEs.
    for cwe in ["CWE-79", "CWE-89", "CWE-22"] {
        assert_eq!(verdict_cap(cwe), MaxAction::Close);
        let mut v = verdict_for(cwe, VerdictAction::Close);
        assert!(!apply_policy(&mut v));
        assert_eq!(v.action, VerdictAction::Close);
    }
}
