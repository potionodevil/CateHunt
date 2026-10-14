// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Fix-Flow (Tauri): suggest_fix -> approve_fix -> apply_fix.
//!
//! Default read-only: `apply_fix` scheitert mit `APPROVAL_REQUIRED`, solange
//! kein Approval vorliegt. Erfolgreiche Applies werden audit-geloggt
//! (append-only, inkl. proposal_id, approved_by, Zeitstempel wird vom
//! Caller/Frontend getragen).
use cate_graph::proposal::{request_apply, AuditEntry, Proposal};
use std::collections::HashMap;

/// In-Memory-Store (Tauri-State, hinter `Mutex`).
#[derive(Debug, Default)]
pub struct FixStore {
    proposals: HashMap<String, Proposal>,
    audit: Vec<AuditEntry>,
    next_id: u64,
}

impl FixStore {
    /// Legt ein Proposal an (Status `Proposed`, read-only Default).
    pub fn suggest(
        &mut self,
        finding_id: &str,
        title: &str,
        rationale: &str,
    ) -> Result<Proposal, String> {
        self.next_id += 1;
        let id = format!("p-{}", self.next_id);
        // Node ableiten: finding-gebunden (finding_id als node_id-Anker).
        let p = Proposal::new(&id, finding_id, finding_id, title, rationale)?;
        self.proposals.insert(id, p.clone());
        Ok(p)
    }

    /// Zustimmung (User-Approval). Nur aus `Proposed` moeglich.
    pub fn approve(
        &mut self,
        proposal_id: &str,
        rationale: &str,
    ) -> Result<Proposal, String> {
        let p = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| format!("unbekannte proposal_id: {proposal_id}"))?;
        p.approve(rationale)?;
        Ok(p.clone())
    }

    /// Anwenden — NUR nach Approval, sonst `APPROVAL_REQUIRED`.
    /// Schreibt bei Erfolg einen Audit-Log-Eintrag.
    pub fn apply(&mut self, proposal_id: &str, approved_by: &str) -> Result<Proposal, String> {
        if approved_by.trim().is_empty() {
            return Err(
                "APPROVAL_REQUIRED: apply_fix braucht approved_by oder vorherige Genehmigung"
                    .to_string(),
            );
        }
        let mut audit = std::mem::take(&mut self.audit);
        let result = match self.proposals.get_mut(proposal_id) {
            Some(p) => request_apply(p, false, approved_by, &mut audit),
            None => Err(format!("unbekannte proposal_id: {proposal_id}")),
        };
        self.audit = audit;
        result?;
        Ok(self
            .proposals
            .get(proposal_id)
            .cloned()
            .expect("proposal muss nach apply existieren"))
    }

    pub fn audit_log(&self) -> Vec<AuditEntry> {
        self.audit.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suggested() -> (FixStore, Proposal) {
        let mut s = FixStore::default();
        let p = s
            .suggest("f1", "nesting reduzieren", "tiefe 6 -> 4 aufsplitten")
            .expect("suggest muss klappen");
        assert_eq!(p.status, cate_graph::ProposalStatus::Proposed);
        (s, p)
    }

    #[test]
    fn apply_ohne_approval_ist_approval_required() {
        let (mut s, p) = suggested();
        let err = s.apply(&p.id, "reviewer").unwrap_err();
        assert!(err.contains("APPROVAL_REQUIRED"), "unerwartet: {err}");
        assert!(s.audit_log().is_empty());
    }

    #[test]
    fn apply_ohne_approved_by_ist_approval_required() {
        let (mut s, p) = suggested();
        s.approve(&p.id, "sieht gut aus").unwrap();
        let err = s.apply(&p.id, "  ").unwrap_err();
        assert!(err.contains("APPROVAL_REQUIRED"), "unerwartet: {err}");
    }

    #[test]
    fn approve_dann_apply_schreibt_audit() {
        let (mut s, p) = suggested();
        s.approve(&p.id, "begruendet ok").unwrap();
        let done = s.apply(&p.id, "reviewer").expect("apply muss klappen");
        assert_eq!(done.status, cate_graph::ProposalStatus::Applied);
        let log = s.audit_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].proposal_id, p.id);
        assert_eq!(log[0].actor, "reviewer");
        assert_eq!(log[0].event, "applied");
    }

    #[test]
    fn suggest_ohne_rationale_abgelehnt() {
        let mut s = FixStore::default();
        assert!(s.suggest("f1", "t", "  ").is_err());
    }

    #[test]
    fn unbekannte_id_fehlert() {
        let mut s = FixStore::default();
        assert!(s.apply("p-999", "x").is_err());
        assert!(s.approve("p-999", "x").is_err());
    }
}
