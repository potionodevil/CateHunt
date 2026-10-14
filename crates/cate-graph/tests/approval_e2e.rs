// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Approval-E2E (P0): kein Apply ohne Zustimmung, Auto-Apply-Gate, Audit-Log.
//!
//! Kette: proposed -> approve (mit Begruendung) -> applied.
//! Ohne Genehmigung -> Err; auto_apply=false ohne Vorab-Genehmigung ->
//! APPROVAL_REQUIRED; jeder Apply schreibt einen Audit-Log-Eintrag.

use cate_graph::proposal::{request_apply, Proposal, ProposalStatus};

fn sample(id: &str) -> Proposal {
    Proposal::new(id, "f1", "node-a", "nesting reduzieren", "tiefe 6 -> 4")
        .expect("sample muss gueltig sein")
}

#[test]
fn e2e_proposed_approve_mit_begruendung_applied() {
    let mut p = sample("p1");
    assert_eq!(p.status, ProposalStatus::Proposed);
    p.approve("sinnvoll, weil Lesbarkeit").unwrap();
    assert_eq!(p.status, ProposalStatus::Approved);
    let mut audit = Vec::new();
    request_apply(&mut p, true, "tester", &mut audit).unwrap();
    assert_eq!(p.status, ProposalStatus::Applied);
    assert_eq!(audit.len(), 1, "genau ein Audit-Eintrag");
    assert_eq!(audit[0].proposal_id, "p1");
    assert_eq!(audit[0].event, "applied");
    assert!(
        !audit[0].rationale.trim().is_empty(),
        "Audit braucht Begruendung"
    );
}

#[test]
fn ohne_genehmigung_kein_apply() {
    let mut p = sample("p2");
    assert!(p.apply().is_err());
    assert_eq!(p.status, ProposalStatus::Proposed);
    let mut audit = Vec::new();
    let err = request_apply(&mut p, true, "tester", &mut audit).unwrap_err();
    assert!(err.contains("APPROVAL_REQUIRED"), "unerwartet: {err}");
    assert_eq!(p.status, ProposalStatus::Proposed);
    assert!(audit.is_empty(), "kein Audit ohne Apply");
}

#[test]
fn auto_apply_false_ohne_vorab_genehmigung_ist_approval_required() {
    let mut p = sample("p3");
    let mut audit = Vec::new();
    let err = request_apply(&mut p, false, "tester", &mut audit).unwrap_err();
    assert!(err.contains("APPROVAL_REQUIRED"), "unerwartet: {err}");
    assert_eq!(p.status, ProposalStatus::Proposed);
    assert!(audit.is_empty());
    // Nach Genehmigung darf auch auto_apply=false anwenden + Audit schreiben.
    p.approve("ok, manuell bestaetigt").unwrap();
    request_apply(&mut p, false, "tester", &mut audit).unwrap();
    assert_eq!(p.status, ProposalStatus::Applied);
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].event, "applied");
}

#[test]
fn approve_ohne_begruendung_ist_fehler() {
    let mut p = sample("p4");
    assert!(p.approve("   ").is_err());
    assert_eq!(p.status, ProposalStatus::Proposed);
}

#[test]
fn teil_approval_wendet_nur_genehmigte_an() {
    let mut ps = [sample("a"), sample("b"), sample("c")];
    ps[0].approve("ja 1").unwrap();
    ps[2].approve("ja 3").unwrap();
    let mut audit = Vec::new();
    let mut applied = 0;
    for p in ps.iter_mut() {
        if request_apply(p, false, "tester", &mut audit).is_ok() {
            applied += 1;
        }
    }
    assert_eq!(applied, 2, "nur 2 genehmigte duerfen applied werden");
    assert_eq!(ps[1].status, ProposalStatus::Proposed);
    assert_eq!(audit.len(), 2);
}
