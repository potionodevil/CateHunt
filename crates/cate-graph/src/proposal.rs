// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! cate-graph Proposal-Workflow: Verbesserungs-Vorschlaege als eigene
//! Knoten (finding -> proposal). Default read-only: Anwenden NUR nach
//! User-Zustimmung (`Approved` -> `apply`). Ungenehmigte Proposals
//! werden nie applied.
use serde::{Deserialize, Serialize};

/// Lebenszyklus eines Proposals: nur `Approved` darf applied werden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProposalStatus {
    Proposed,
    Approved,
    Applied,
    Rejected,
}

/// Verbesserungs-Vorschlag zu einem Befund/Knoten.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub finding_id: String,
    pub node_id: String,
    pub title: String,
    pub rationale: String,
    pub status: ProposalStatus,
}

impl Proposal {
    /// Neues Proposal, immer Status `Proposed` (read-only Default).
    /// `rationale` (Begruendung) ist Pflicht (nicht leer).
    pub fn new(
        id: &str,
        finding_id: &str,
        node_id: &str,
        title: &str,
        rationale: &str,
    ) -> Result<Self, String> {
        if rationale.trim().is_empty() {
            return Err("proposal braucht eine Begruendung (rationale)".to_string());
        }
        Ok(Proposal {
            id: id.to_string(),
            finding_id: finding_id.to_string(),
            node_id: node_id.to_string(),
            title: title.to_string(),
            rationale: rationale.to_string(),
            status: ProposalStatus::Proposed,
        })
    }

    /// Zustimmung (User-Approval). Nur aus `Proposed` moeglich.
    pub fn approve(&mut self, rationale: &str) -> Result<(), String> {
        if self.status != ProposalStatus::Proposed {
            return Err(format!(
                "approve nur aus proposed moeglich (aktuell {:?})",
                self.status
            ));
        }
        if rationale.trim().is_empty() {
            return Err("approval braucht eine Begruendung".to_string());
        }
        self.rationale = rationale.to_string();
        self.status = ProposalStatus::Approved;
        Ok(())
    }

    /// Ablehnung. Nur aus `Proposed` moeglich.
    pub fn reject(&mut self, rationale: &str) -> Result<(), String> {
        if self.status != ProposalStatus::Proposed {
            return Err(format!(
                "reject nur aus proposed moeglich (aktuell {:?})",
                self.status
            ));
        }
        if rationale.trim().is_empty() {
            return Err("rejection braucht eine Begruendung".to_string());
        }
        self.rationale = rationale.to_string();
        self.status = ProposalStatus::Rejected;
        Ok(())
    }

    /// Anwenden — NUR nach User-Zustimmung (`Approved`). Alles andere
    /// wird abgelehnt, d.h. ungenehmigte Proposals werden nie applied.
    pub fn apply(&mut self) -> Result<(), String> {
        if self.status != ProposalStatus::Approved {
            return Err(format!(
                "apply nur nach approval moeglich (aktuell {:?}) — read-only default",
                self.status
            ));
        }
        self.status = ProposalStatus::Applied;
        Ok(())
    }
}

/// Proposals als JSON exportieren (fuer Editor-Ansicht und MCP).
pub fn proposals_to_json(proposals: &[Proposal]) -> Result<String, String> {
    serde_json::to_string_pretty(proposals).map_err(|e| format!("json: {e}"))
}

/// Audit-Log-Eintrag: wer hat was mit welcher Begruendung angewendet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub proposal_id: String,
    pub event: String,
    pub actor: String,
    pub rationale: String,
}

/// Apply mit Gate: nur `Approved` darf applied werden — sonst
/// `APPROVAL_REQUIRED` (kein Apply ohne Zustimmung, auto_apply=false
/// ohne Vorab-Genehmigung eingeschlossen). Erfolgreicher Apply schreibt
/// einen Audit-Log-Eintrag (wer/was/Begruendung).
pub fn request_apply(
    p: &mut Proposal,
    _auto_apply: bool,
    actor: &str,
    audit: &mut Vec<AuditEntry>,
) -> Result<(), String> {
    if p.status != ProposalStatus::Approved {
        return Err(format!(
            "APPROVAL_REQUIRED: apply nur nach approval moeglich (aktuell {:?})",
            p.status
        ));
    }
    p.apply()?;
    audit.push(AuditEntry {
        proposal_id: p.id.clone(),
        event: "applied".to_string(),
        actor: actor.to_string(),
        rationale: p.rationale.clone(),
    });
    Ok(())
}

/// S4 Dry-Run/COW fuer Fix-Anwendung: reiner Datentyp, keine UI-Aenderung.
///
/// Regel: `apply` erst nach Preview-Bestaetigung. `preview_apply`
/// beschreibt den Effekt, ohne zu schreiben (kein Statuswechsel);
/// `apply_with_preview` schreibt nur mit passender Preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyPreview {
    pub proposal_id: String,
    pub node_id: String,
    pub title: String,
    pub effect: String,
    pub rationale: String,
}

impl Proposal {
    /// Preview-Modus: Effekt beschreiben ohne zu schreiben. Nur aus
    /// `Approved` moeglich; aendert den Status NICHT (read-only).
    pub fn preview_apply(&self) -> Result<ApplyPreview, String> {
        if self.status != ProposalStatus::Approved {
            return Err(format!(
                "APPROVAL_REQUIRED: preview nur nach approval moeglich (aktuell {:?})",
                self.status
            ));
        }
        Ok(ApplyPreview {
            proposal_id: self.id.clone(),
            node_id: self.node_id.clone(),
            title: self.title.clone(),
            effect: format!(
                "wuerde Proposal anwenden: finding {}, Titel {} (kein Schreibzugriff im Preview)",
                self.finding_id, self.title
            ),
            rationale: self.rationale.clone(),
        })
    }

    /// Apply erst nach Preview-Bestaetigung: die Preview muss zu diesem
    /// Proposal gehoeren (id-Match) und das Proposal weiterhin
    /// `Approved` sein. Sonst kein Schreibzugriff.
    pub fn apply_with_preview(&mut self, preview: &ApplyPreview) -> Result<(), String> {
        if self.status != ProposalStatus::Approved {
            return Err(format!(
                "APPROVAL_REQUIRED: apply nur nach approval moeglich (aktuell {:?}) — read-only default",
                self.status
            ));
        }
        if preview.proposal_id != self.id {
            return Err(
                "preview gehoert zu anderem Proposal (id-Mismatch) — kein Apply".to_string(),
            );
        }
        self.status = ProposalStatus::Applied;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Proposal {
        Proposal::new("p1", "f1", "node-a", "nesting reduzieren", "tiefe 6 -> 4")
            .expect("sample muss gueltig sein")
    }

    #[test]
    fn new_starts_as_proposed() {
        assert_eq!(sample().status, ProposalStatus::Proposed);
    }

    #[test]
    fn new_rejects_empty_rationale() {
        assert!(Proposal::new("p", "f", "n", "t", "  ").is_err());
    }

    #[test]
    fn proposed_cannot_be_applied() {
        let mut p = sample();
        assert!(p.apply().is_err());
        assert_eq!(p.status, ProposalStatus::Proposed);
    }

    #[test]
    fn rejected_cannot_be_applied() {
        let mut p = sample();
        p.reject("falsch-positiv, weil ...").unwrap();
        assert!(p.apply().is_err());
        assert_eq!(p.status, ProposalStatus::Rejected);
    }

    #[test]
    fn approved_can_be_applied() {
        let mut p = sample();
        p.approve("sinnvoll, weil ...").unwrap();
        assert!(p.apply().is_ok());
        assert_eq!(p.status, ProposalStatus::Applied);
    }

    #[test]
    fn applied_cannot_be_applied_twice() {
        let mut p = sample();
        p.approve("ok").unwrap();
        p.apply().unwrap();
        assert!(p.apply().is_err());
    }

    #[test]
    fn approve_needs_rationale() {
        let mut p = sample();
        assert!(p.approve("  ").is_err());
        assert_eq!(p.status, ProposalStatus::Proposed);
    }

    #[test]
    fn export_roundtrip() {
        let v = proposals_to_json(&[sample()]).unwrap();
        let back: Vec<Proposal> = serde_json::from_str(&v).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].status, ProposalStatus::Proposed);
    }

    #[test]
    fn dry_run_preview_aendert_nichts() {
        let mut p = sample();
        p.approve("sinnvoll, weil ...").unwrap();
        let pv = p.preview_apply().unwrap();
        assert_eq!(pv.proposal_id, "p1");
        assert_eq!(pv.node_id, "node-a");
        assert_eq!(p.status, ProposalStatus::Approved);
    }

    #[test]
    fn dry_run_preview_braucht_approval() {
        let p = sample();
        assert!(p.preview_apply().is_err());
    }

    #[test]
    fn dry_run_roundtrip_preview_dann_apply() {
        let mut p = sample();
        p.approve("sinnvoll, weil ...").unwrap();
        let pv = p.preview_apply().unwrap();
        // Roundtrip ueber JSON (reiner Datentyp).
        let json = serde_json::to_string(&pv).unwrap();
        let back: ApplyPreview = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pv);
        p.apply_with_preview(&back).unwrap();
        assert_eq!(p.status, ProposalStatus::Applied);
    }

    #[test]
    fn dry_run_fremde_preview_wird_abgelehnt() {
        let mut p = sample();
        p.approve("ok").unwrap();
        let mut pv = p.preview_apply().unwrap();
        pv.proposal_id = "fremd".to_string();
        assert!(p.apply_with_preview(&pv).is_err());
        assert_eq!(p.status, ProposalStatus::Approved);
    }

    #[test]
    fn dry_run_apply_ohne_approval_scheitert() {
        let mut p = sample();
        // Konstruierte Preview ohne Approval: kein Apply.
        let pv = ApplyPreview {
            proposal_id: "p1".to_string(),
            node_id: "node-a".to_string(),
            title: "t".to_string(),
            effect: "e".to_string(),
            rationale: "r".to_string(),
        };
        assert!(p.apply_with_preview(&pv).is_err());
        assert_eq!(p.status, ProposalStatus::Proposed);
    }
}
