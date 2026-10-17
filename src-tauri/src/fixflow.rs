// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Fix-Flow (Tauri): suggest_fix -> approve_fix -> apply_fix.
//!
//! Default read-only: `apply_fix` scheitert mit `APPROVAL_REQUIRED`, solange
//! kein Approval vorliegt. Erfolgreiche Applies werden audit-geloggt
//! (append-only, inkl. proposal_id, approved_by, Zeitstempel wird vom
//! Caller/Frontend getragen).
//!
//! S-3 Suppress-Gate: Jede Zustimmung (Approval) traegt Reviewer,
//! Begruendung und Ablaufdatum (`expires_at`, Default 30 Tage ab Approval).
//! - `approve` verlangt eine nicht-leere Begruendung (wie bisher);
//!   `approve_reviewed` verlangt zusaetzlich einen Reviewer.
//! - `apply` verlangt Reviewer (`approved_by`), lehnt abgelaufene Approvals
//!   mit `APPROVAL_EXPIRED` ab und blockt Suppress-Vorschlaege auf
//!   Deny-CWEs mit `DENY_SUPPRESS_BLOCKED` (Pruefung gegen
//!   `cate_triage::verdict_cap`).
//!
//! Kompatibilitaet: `suggest`/`approve`/`apply` behalten ihre Signaturen
//! (Tauri-Commands in `main.rs` unveraendert). Neue Varianten
//! (`suggest_with_ttl`, `suggest_suppress`, `approve_reviewed`) bieten die
//! Gate-Felder explizit an; `apply` fuellt einen fehlenden Reviewer aus
//! `approved_by` nach, sodass jede angewandte Suppression einen Reviewer hat.
use cate_graph::apply::{self, ApplyReport, FileChange, FileDiff};
use cate_graph::proposal::{request_apply, AuditEntry, Proposal};
use cate_triage::{verdict_cap, MaxAction};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default-Gueltigkeit einer Zustimmung in Tagen (S-3: Ablaufdatum Pflicht).
pub const DEFAULT_APPROVAL_TTL_DAYS: u64 = 30;
/// Sekunden pro Tag (fuer `expires_at`-Arithmetik ohne Zeit-Dependency).
pub const SECS_PER_DAY: u64 = 86_400;

/// Aktuelle Unix-Zeit in Sekunden (fuer `approved_at`/`expires_at`).
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// S-3: `true`, wenn `cwe` auf der Deny-List steht und damit nie
/// suppressen/geschlossen werden darf (`cate_triage::verdict_cap`).
pub fn is_suppress_blocked(cwe: &str) -> bool {
    verdict_cap(cwe) == MaxAction::DemoteOnly
}

/// Zustimmung zu einem Proposal: Reviewer + Zeitpunkt + Ablaufdatum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalMeta {
    /// Reviewer (leer, bis per `approve_reviewed` oder `apply` gesetzt).
    pub reviewer: String,
    /// Unix-Zeit der Zustimmung.
    pub approved_at: u64,
    /// Unix-Zeit, ab der die Zustimmung verfallen ist (`APPROVAL_EXPIRED`).
    pub expires_at: u64,
}

impl ApprovalMeta {
    /// `true`, wenn `now` nach `expires_at` liegt.
    pub fn expired(&self, now: u64) -> bool {
        now > self.expires_at
    }
}

/// In-Memory-Store (Tauri-State, hinter `Mutex`).
#[derive(Debug, Default)]
pub struct FixStore {
    proposals: HashMap<String, Proposal>,
    audit: Vec<AuditEntry>,
    next_id: u64,
    approvals: HashMap<String, ApprovalMeta>,
    /// Wunsch-Gueltigkeit je Proposal (Sekunden), gesetzt bei `suggest`.
    pending_ttl_secs: HashMap<String, u64>,
    /// Suppress-Vorschlaege: proposal_id -> CWE (fuer Deny-Re-Check bei apply).
    suppress_cwe: HashMap<String, String>,
    /// Ablage der zuletzt previewten Datei-Aenderungen je Proposal
    /// (S4-Regel: `apply_with_files` nur nach passender `preview_files`).
    previews: HashMap<String, Vec<FileChange>>,
}

impl FixStore {
    /// Legt ein Proposal an (Status `Proposed`, read-only Default).
    /// Ablaufdatum: Default 30 Tage ab spaeterer Zustimmung.
    pub fn suggest(
        &mut self,
        finding_id: &str,
        title: &str,
        rationale: &str,
    ) -> Result<Proposal, String> {
        self.suggest_with_ttl(finding_id, title, rationale, DEFAULT_APPROVAL_TTL_DAYS)
    }

    /// Wie `suggest`, mit expliziter Gueltigkeit in Tagen ab Zustimmung.
    pub fn suggest_with_ttl(
        &mut self,
        finding_id: &str,
        title: &str,
        rationale: &str,
        ttl_days: u64,
    ) -> Result<Proposal, String> {
        self.next_id += 1;
        let id = format!("p-{}", self.next_id);
        // Node ableiten: finding-gebunden (finding_id als node_id-Anker).
        let p = Proposal::new(&id, finding_id, finding_id, title, rationale)?;
        self.pending_ttl_secs
            .insert(id.clone(), ttl_days.saturating_mul(SECS_PER_DAY));
        self.proposals.insert(id, p.clone());
        Ok(p)
    }

    /// Suppress-Vorschlag zu einer CWE. Auf Deny-CWEs wird bereits der
    /// Vorschlag mit `DENY_SUPPRESS_BLOCKED` abgelehnt (nie suppressen).
    pub fn suggest_suppress(
        &mut self,
        finding_id: &str,
        title: &str,
        rationale: &str,
        cwe: &str,
        ttl_days: Option<u64>,
    ) -> Result<Proposal, String> {
        if is_suppress_blocked(cwe) {
            return Err(format!(
                "DENY_SUPPRESS_BLOCKED: CWE {cwe} steht auf der Deny-List und darf nie suppressen (nur eskalieren)"
            ));
        }
        let p = self.suggest_with_ttl(
            finding_id,
            title,
            rationale,
            ttl_days.unwrap_or(DEFAULT_APPROVAL_TTL_DAYS),
        )?;
        self.suppress_cwe.insert(p.id.clone(), cwe.to_string());
        Ok(p)
    }

    /// Zustimmung (User-Approval). Nur aus `Proposed` moeglich, Begruendung
    /// Pflicht. Reviewer kann spaetestens bei `apply` (`approved_by`)
    /// nachgetragen werden; explizit geht `approve_reviewed`.
    pub fn approve(&mut self, proposal_id: &str, rationale: &str) -> Result<Proposal, String> {
        self.approve_inner(proposal_id, rationale, None)
    }

    /// Zustimmung mit Begruendung UND Reviewer (S-3: beides Pflicht).
    /// Leerer Reviewer -> `REVIEWER_REQUIRED`, Status bleibt `Proposed`.
    pub fn approve_reviewed(
        &mut self,
        proposal_id: &str,
        rationale: &str,
        reviewer: &str,
    ) -> Result<Proposal, String> {
        if reviewer.trim().is_empty() {
            return Err(
                "REVIEWER_REQUIRED: approve braucht einen Reviewer (approved_by)".to_string(),
            );
        }
        self.approve_inner(proposal_id, rationale, Some(reviewer.trim()))
    }

    fn approve_inner(
        &mut self,
        proposal_id: &str,
        rationale: &str,
        reviewer: Option<&str>,
    ) -> Result<Proposal, String> {
        let ttl = self
            .pending_ttl_secs
            .get(proposal_id)
            .copied()
            .unwrap_or(DEFAULT_APPROVAL_TTL_DAYS.saturating_mul(SECS_PER_DAY));
        let now = now_secs();
        let p = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| format!("unbekannte proposal_id: {proposal_id}"))?;
        p.approve(rationale)?;
        self.approvals.insert(
            proposal_id.to_string(),
            ApprovalMeta {
                reviewer: reviewer.unwrap_or("").to_string(),
                approved_at: now,
                expires_at: now.saturating_add(ttl),
            },
        );
        Ok(p.clone())
    }

    /// Anwenden — NUR nach Approval, sonst `APPROVAL_REQUIRED`.
    /// Abgelaufene Approvals -> `APPROVAL_EXPIRED`; Suppress auf Deny-CWE
    /// -> `DENY_SUPPRESS_BLOCKED` (Re-Check, Defense in Depth).
    /// Fehlgeschlagene Applies schreiben KEINEN Audit-Eintrag. Erfolg traegt
    /// einen fehlenden Reviewer aus `approved_by` nach, sodass jede
    /// angewandte Suppression Begruendung + Reviewer + Ablaufdatum hat.
    /// Schreibt bei Erfolg einen Audit-Log-Eintrag.
    pub fn apply(&mut self, proposal_id: &str, approved_by: &str) -> Result<Proposal, String> {
        if approved_by.trim().is_empty() {
            return Err(
                "APPROVAL_REQUIRED: apply_fix braucht approved_by oder vorherige Genehmigung"
                    .to_string(),
            );
        }
        if let Some(cwe) = self.suppress_cwe.get(proposal_id) {
            if is_suppress_blocked(cwe) {
                return Err(format!(
                    "DENY_SUPPRESS_BLOCKED: CWE {cwe} darf nie suppressen (nur eskalieren)"
                ));
            }
        }
        match self.approvals.get(proposal_id) {
            Some(meta) if meta.expired(now_secs()) => {
                return Err(format!(
                    "APPROVAL_EXPIRED: Zustimmung zu {proposal_id} ist abgelaufen (expires_at {}), erneut anfordern",
                    meta.expires_at
                ));
            }
            // Kein Approval-Metadatum: Proposal kennt den Grund
            // (APPROVAL_REQUIRED aus request_apply weiter unten).
            _ => {}
        }
        let mut audit = std::mem::take(&mut self.audit);
        let result = match self.proposals.get_mut(proposal_id) {
            Some(p) => request_apply(p, false, approved_by, &mut audit),
            None => Err(format!("unbekannte proposal_id: {proposal_id}")),
        };
        self.audit = audit;
        result?;
        // Reviewer nachtragen, falls Approval ohne Reviewer erfolgte.
        if let Some(meta) = self.approvals.get_mut(proposal_id) {
            if meta.reviewer.trim().is_empty() {
                meta.reviewer = approved_by.trim().to_string();
            }
        }
        Ok(self
            .proposals
            .get(proposal_id)
            .cloned()
            .expect("proposal muss nach apply existieren"))
    }

    /// Diff-Vorschau echter Datei-Aenderungen (read-only, S4-Regel).
    /// Legt die previewten `changes` je Proposal ab; nur exakt diese
    /// duerfen danach per `apply_with_files` geschrieben werden.
    /// Pfade werden auf `root` gejailt, Secrets im Diff redigiert.
    pub fn preview_files(
        &mut self,
        root: &std::path::Path,
        proposal_id: &str,
        changes: &[FileChange],
    ) -> Result<Vec<FileDiff>, String> {
        let p = self
            .proposals
            .get(proposal_id)
            .ok_or_else(|| format!("unbekannte proposal_id: {proposal_id}"))?;
        let diffs = apply::preview_apply_files(root, p, changes)?;
        self.previews
            .insert(proposal_id.to_string(), changes.to_vec());
        Ok(diffs)
    }

    /// Echte Dateianwendung: schreibt `changes` nach `root` (Backup `.orig`,
    /// Rollback bei Fehler, kein Teil-Apply). Gates wie `apply` (Approval,
    /// Ablauf, Deny-Re-Check) plus S4-Preview-Gate (`PREVIEW_REQUIRED`,
    /// wenn `changes` nicht exakt dem letzten `preview_files` entspricht).
    /// Erfolg traegt Reviewer aus `approved_by` nach und audit-loggt.
    pub fn apply_with_files(
        &mut self,
        root: &std::path::Path,
        proposal_id: &str,
        approved_by: &str,
        changes: &[FileChange],
    ) -> Result<(Proposal, ApplyReport), String> {
        if approved_by.trim().is_empty() {
            return Err(
                "APPROVAL_REQUIRED: apply_fix braucht approved_by oder vorherige Genehmigung"
                    .to_string(),
            );
        }
        if let Some(cwe) = self.suppress_cwe.get(proposal_id) {
            if is_suppress_blocked(cwe) {
                return Err(format!(
                    "DENY_SUPPRESS_BLOCKED: CWE {cwe} darf nie suppressen (nur eskalieren)"
                ));
            }
        }
        match self.approvals.get(proposal_id) {
            Some(meta) if meta.expired(now_secs()) => {
                return Err(format!(
                    "APPROVAL_EXPIRED: Zustimmung zu {proposal_id} ist abgelaufen (expires_at {}), erneut anfordern",
                    meta.expires_at
                ));
            }
            _ => {}
        }
        match self.previews.get(proposal_id) {
            Some(prev) if prev == changes => {}
            _ => {
                return Err(format!(
                    "PREVIEW_REQUIRED: {proposal_id} erst per preview_fix vorschauen, dann exakt diese changes anwenden"
                ));
            }
        }
        let mut audit = std::mem::take(&mut self.audit);
        let result = match self.proposals.get_mut(proposal_id) {
            Some(p) => apply::apply_files(root, p, approved_by, changes, &mut audit),
            None => Err(format!("unbekannte proposal_id: {proposal_id}")),
        };
        self.audit = audit;
        let report = result?;
        if let Some(meta) = self.approvals.get_mut(proposal_id) {
            if meta.reviewer.trim().is_empty() {
                meta.reviewer = approved_by.trim().to_string();
            }
        }
        self.previews.remove(proposal_id);
        Ok((
            self.proposals
                .get(proposal_id)
                .cloned()
                .expect("proposal muss nach apply existieren"),
            report,
        ))
    }

    /// Ablaufdatum einer Zustimmung (Unix-Sekunden), falls genehmigt.
    pub fn expires_at_of(&self, proposal_id: &str) -> Option<u64> {
        self.approvals.get(proposal_id).map(|m| m.expires_at)
    }
    /// Zustimmungs-Metadatum (Reviewer + Zeitraum), falls genehmigt.
    pub fn approval_of(&self, proposal_id: &str) -> Option<ApprovalMeta> {
        self.approvals.get(proposal_id).cloned()
    }

    /// Test-Hook: laesst eine Zustimmung sofort verfallen.
    #[cfg(test)]
    pub fn force_expire(&mut self, proposal_id: &str) -> Result<(), String> {
        let m = self
            .approvals
            .get_mut(proposal_id)
            .ok_or_else(|| format!("unbekannte proposal_id: {proposal_id}"))?;
        m.expires_at = 0;
        Ok(())
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

    #[test]
    fn default_ttl_ist_30_tage_ab_approval() {
        let (mut s, p) = suggested();
        let before = now_secs();
        s.approve(&p.id, "mit begruendung").unwrap();
        let meta = s.approval_of(&p.id).expect("approval muss existieren");
        assert_eq!(
            meta.expires_at.saturating_sub(meta.approved_at),
            DEFAULT_APPROVAL_TTL_DAYS * SECS_PER_DAY
        );
        assert!(meta.approved_at >= before);
        assert_eq!(DEFAULT_APPROVAL_TTL_DAYS, 30);
        assert_eq!(s.expires_at_of(&p.id), Some(meta.expires_at));
    }

    #[test]
    fn custom_ttl_wird_uebernommen() {
        let mut s = FixStore::default();
        let p = s
            .suggest_with_ttl("f1", "t", "begruendung", 7)
            .expect("suggest muss klappen");
        s.approve(&p.id, "ok").unwrap();
        let meta = s.approval_of(&p.id).unwrap();
        assert_eq!(meta.expires_at - meta.approved_at, 7 * SECS_PER_DAY);
    }

    #[test]
    fn abgelaufene_approval_blockt_apply_mit_expired() {
        let (mut s, p) = suggested();
        s.approve(&p.id, "begruendet ok").unwrap();
        s.force_expire(&p.id).unwrap();
        let err = s.apply(&p.id, "reviewer").unwrap_err();
        assert!(err.contains("APPROVAL_EXPIRED"), "unerwartet: {err}");
        assert!(s.audit_log().is_empty(), "kein Audit bei Ablauf");
        assert_eq!(
            s.proposals.get(&p.id).unwrap().status,
            cate_graph::ProposalStatus::Approved
        );
    }

    #[test]
    fn approve_reviewed_ohne_reviewer_abgelehnt() {
        let (mut s, p) = suggested();
        let err = s
            .approve_reviewed(&p.id, "gute begruendung", "  ")
            .unwrap_err();
        assert!(err.contains("REVIEWER_REQUIRED"), "unerwartet: {err}");
        assert_eq!(
            s.proposals.get(&p.id).unwrap().status,
            cate_graph::ProposalStatus::Proposed
        );
        assert!(s.approval_of(&p.id).is_none());
    }

    #[test]
    fn reviewer_wird_bei_apply_aus_approved_by_nachgetragen() {
        let (mut s, p) = suggested();
        s.approve(&p.id, "begruendet ok").unwrap();
        assert_eq!(s.approval_of(&p.id).unwrap().reviewer, "");
        s.apply(&p.id, "alice").unwrap();
        assert_eq!(s.approval_of(&p.id).unwrap().reviewer, "alice");
    }

    #[test]
    fn deny_cwe_kann_nie_suppressen() {
        assert!(is_suppress_blocked("CWE-328"));
        assert!(is_suppress_blocked("798"));
        assert!(!is_suppress_blocked("CWE-79"));
        let mut s = FixStore::default();
        let err = s
            .suggest_suppress("f1", "md5 ok?", "harmlos", "CWE-328", None)
            .unwrap_err();
        assert!(err.contains("DENY_SUPPRESS_BLOCKED"), "unerwartet: {err}");
        // Nicht-Deny geht durch und laeuft normal durchs Gate.
        let p = s
            .suggest_suppress("f2", "xss fix", "output-encoding", "CWE-79", Some(7))
            .expect("nicht-deny muss klappen");
        s.approve_reviewed(&p.id, "sinnvoll", "bob").unwrap();
        let done = s.apply(&p.id, "bob").expect("apply muss klappen");
        assert_eq!(done.status, cate_graph::ProposalStatus::Applied);
    }

    fn tmp_root(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cate_fixflow_{name}_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn file_change(path: &str, new_content: &str) -> FileChange {
        FileChange {
            path: path.to_string(),
            new_content: new_content.to_string(),
            expected_old: None,
        }
    }

    #[test]
    fn datei_apply_ohne_preview_ist_preview_required() {
        let root = tmp_root("gate");
        let (mut s, p) = suggested();
        s.approve(&p.id, "begruendet ok").unwrap();
        let err = s
            .apply_with_files(&root, &p.id, "alice", &[file_change("a.txt", "neu")])
            .unwrap_err();
        assert!(err.contains("PREVIEW_REQUIRED"), "unerwartet: {err}");
        assert!(!root.join("a.txt").exists());
        assert!(s.audit_log().is_empty());
    }

    #[test]
    fn datei_apply_ohne_approval_schreibt_nichts() {
        let root = tmp_root("noapproval");
        let (mut s, p) = suggested();
        // Preview selbst verlangt Approval (read-only Gate).
        let err = s
            .preview_files(&root, &p.id, &[file_change("a.txt", "neu")])
            .unwrap_err();
        assert!(err.contains("APPROVAL_REQUIRED"), "unerwartet: {err}");
        assert!(!root.join("a.txt").exists());
    }

    #[test]
    fn preview_dann_datei_apply_mit_backup_audit_reviewer() {
        let root = tmp_root("happy");
        std::fs::write(root.join("a.txt"), "alt\n").unwrap();
        let (mut s, p) = suggested();
        s.approve(&p.id, "begruendet ok").unwrap();
        let changes = vec![file_change("a.txt", "neu\n")];
        let diffs = s.preview_files(&root, &p.id, &changes).unwrap();
        assert_eq!(diffs.len(), 1);
        assert!(diffs[0].diff.contains("+ neu"));
        let (done, report) = s
            .apply_with_files(&root, &p.id, "alice", &changes)
            .expect("apply muss klappen");
        assert_eq!(done.status, cate_graph::ProposalStatus::Applied);
        assert_eq!(report.files_changed, vec!["a.txt".to_string()]);
        assert_eq!(report.backups.len(), 1);
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "neu\n"
        );
        let log = s.audit_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].actor, "alice");
        assert_eq!(s.approval_of(&p.id).unwrap().reviewer, "alice");
    }

    #[test]
    fn datei_apply_jail_reject_vor_write() {
        let root = tmp_root("jail");
        let (mut s, p) = suggested();
        s.approve(&p.id, "begruendet ok").unwrap();
        // Preview jailed bereits: Jail-Verstoss scheitert vor jedem Write.
        let err = s
            .preview_files(&root, &p.id, &[file_change("../escape.txt", "x")])
            .unwrap_err();
        assert!(err.contains("INVALID_PATH"), "unerwartet: {err}");
        assert!(s.audit_log().is_empty());
    }

    #[test]
    fn datei_apply_abgelaufen_blockt_trotz_preview() {
        let root = tmp_root("expired");
        std::fs::write(root.join("a.txt"), "alt\n").unwrap();
        let (mut s, p) = suggested();
        s.approve(&p.id, "begruendet ok").unwrap();
        let changes = vec![file_change("a.txt", "neu\n")];
        s.preview_files(&root, &p.id, &changes).unwrap();
        s.force_expire(&p.id).unwrap();
        let err = s
            .apply_with_files(&root, &p.id, "alice", &changes)
            .unwrap_err();
        assert!(err.contains("APPROVAL_EXPIRED"), "unerwartet: {err}");
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "alt\n"
        );
        assert!(s.audit_log().is_empty());
    }
}
