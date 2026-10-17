// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Echte Fix-Anwendung (`cate-graph::apply`).
//!
//! Ablage-Entscheid (s. `docs/FIX_APPLY.md`): die Dateianwendung liegt als
//! Shared-Library in `cate-graph`, nicht im CLI. Das CLI (`cate scan`,
//! `audit`, ...) bleibt read-only; Approvals + Review gehoeren in den
//! Desktop-Flow (Tauri: `preview_fix` / `apply_fix_files` in
//! `src-tauri/src/fixflow.rs`). Der MCP-Platzhalter
//! (`catehunt_apply_proposal`, Gate + Audit ohne Dateischreibung) bleibt
//! unveraendert gate-only.
//!
//! Ablauf: `preview_apply_files` (read-only Diff-Vorschau, Secrets
//! redigiert) -> `apply_files` (nur nach Approval). `apply_files`
//! schreibt `.orig`-Backups, jailt alle Pfade auf `root` und rollt bei
//! Fehlern alle bereits geschriebenen Dateien zurueck (kein Teil-Apply).
use super::proposal::{AuditEntry, Proposal, ProposalStatus};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

/// Eine Datei-Aenderung, relativ zu `root`: `new_content` wird als neuer
/// Dateiinhalt geschrieben. `expected_old` (optional) ist ein
/// TOCTOU-Schutz: weicht der aktuelle Inhalt ab, bricht der Apply mit
/// `STALE_FILE` ab (mit Rollback).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChange {
    pub path: String,
    pub new_content: String,
    #[serde(default)]
    pub expected_old: Option<String>,
}

/// Read-only Diff-Vorschau pro Datei (Secrets redigiert, s. `preview`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDiff {
    pub path: String,
    pub diff: String,
    pub is_new: bool,
}

/// Ergebnis eines erfolgreichen Applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyReport {
    pub proposal_id: String,
    pub files_changed: Vec<String>,
    pub backups: Vec<String>,
}

/// Loest `rel` gegen `root` auf und prueft den Path-Jail.
/// Abgelehnt mit `INVALID_PATH`: leere Pfade, NUL-Bytes, absolute Pfade
/// (inkl. UNC/Prefix/RootDir-Komponenten), `..`-Komponenten sowie Ziele,
/// die nach Kanonisierung (Symlink-Aufloesung) ausserhalb von `root`
/// liegen. `root` muss ein existierendes Verzeichnis sein.
pub fn resolve_in_jail(root: &Path, rel: &str) -> Result<PathBuf, String> {
    if rel.is_empty() || rel.contains('\0') {
        return Err(format!("INVALID_PATH: ungueltiger Pfad: {rel:?}"));
    }
    let p = Path::new(rel);
    if p.is_absolute() {
        return Err(format!(
            "INVALID_PATH: absoluter Pfad ausserhalb Jail: {rel}"
        ));
    }
    for comp in p.components() {
        match comp {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("INVALID_PATH: Pfad entkommt Jail: {rel}"));
            }
            Component::CurDir | Component::Normal(_) => {}
        }
    }
    let root_c =
        std::fs::canonicalize(root).map_err(|e| format!("INVALID_PATH: root ungueltig: {e}"))?;
    if !root_c.is_dir() {
        return Err("INVALID_PATH: root ist kein Verzeichnis".to_string());
    }
    // Längsten existierenden Vorfahren kanonisieren (Symlink-Aufloesung),
    // Rest lexikalisch anhaengen (dae `..` oben schon abgelehnt ist).
    let mut ancestor = root_c.clone();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    let mut probe = root_c.join(p);
    loop {
        if probe.exists() {
            match std::fs::canonicalize(&probe) {
                Ok(canon) => {
                    ancestor = canon;
                    break;
                }
                Err(_) => {
                    // Toter Link o.ae.: Elternteil versuchen.
                    rest.push(
                        probe
                            .file_name()
                            .map(|s| s.to_os_string())
                            .unwrap_or_default(),
                    );
                    if !probe.pop() {
                        break;
                    }
                    continue;
                }
            }
        }
        // Noch nicht existent: ein Segment zurueck.
        match probe.file_name() {
            Some(name) => {
                rest.push(name.to_os_string());
                probe.pop();
            }
            None => break,
        }
        if probe == root_c {
            ancestor = root_c.clone();
            break;
        }
    }
    if ancestor != root_c && !ancestor.starts_with(&root_c) {
        return Err(format!(
            "INVALID_PATH: Pfad entkommt Jail (Symlink?): {rel}"
        ));
    }
    let mut full = ancestor;
    for seg in rest.iter().rev() {
        full.push(seg);
    }
    if full != root_c && !full.starts_with(&root_c) {
        return Err(format!("INVALID_PATH: Pfad entkommt Jail: {rel}"));
    }
    Ok(full)
}

/// Jail-Check fuer alle Pfade (fail-fast, ohne zu schreiben).
pub fn jail_all(root: &Path, changes: &[FileChange]) -> Result<Vec<PathBuf>, String> {
    changes
        .iter()
        .map(|c| resolve_in_jail(root, &c.path))
        .collect()
}

/// Einfaches Zeilen-Diff (`- alt` / `+ neu`), Secrets redigiert.
/// Reines Anzeigeformat, kein Patch-Parser.
fn line_diff(old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    // LCS-laenge pro Prefix (kleine Dateien im Fix-Flow; O(n*m) ok).
    let (n, m) = (old_lines.len(), new_lines.len());
    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if old_lines[i] == new_lines[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    let mut out = String::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if old_lines[i] == new_lines[j] {
            out.push_str("  ");
            out.push_str(old_lines[i]);
            out.push('\n');
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            out.push_str("- ");
            out.push_str(old_lines[i]);
            out.push('\n');
            i += 1;
        } else {
            out.push_str("+ ");
            out.push_str(new_lines[j]);
            out.push('\n');
            j += 1;
        }
    }
    for line in &old_lines[i..] {
        out.push_str("- ");
        out.push_str(line);
        out.push('\n');
    }
    for line in &new_lines[j..] {
        out.push_str("+ ");
        out.push_str(line);
        out.push('\n');
    }
    cate_core::redact::redact_text(&out)
}

/// Diff-Vorschau (read-only, kein Statuswechsel, keine Writes).
/// Nur aus `Approved` moeglich (`APPROVAL_REQUIRED`), sonst kein Preview.
/// Alle Pfade werden zuerst gejailt (fail-fast); Secrets im Diff werden
/// redigiert (`cate-core::redact`).
pub fn preview_apply_files(
    root: &Path,
    proposal: &Proposal,
    changes: &[FileChange],
) -> Result<Vec<FileDiff>, String> {
    if proposal.status != ProposalStatus::Approved {
        return Err(format!(
            "APPROVAL_REQUIRED: preview nur nach approval moeglich (aktuell {:?})",
            proposal.status
        ));
    }
    if changes.is_empty() {
        return Err("INVALID_PARAMS: keine Aenderungen (changes leer)".to_string());
    }
    let targets = jail_all(root, changes)?;
    let mut out = Vec::with_capacity(changes.len());
    for (change, abs) in changes.iter().zip(targets.iter()) {
        let current = std::fs::read_to_string(abs).unwrap_or_default();
        let is_new = !abs.exists();
        out.push(FileDiff {
            path: change.path.clone(),
            diff: line_diff(&current, &change.new_content),
            is_new,
        });
    }
    Ok(out)
}

/// Echte Dateianwendung: schreibt `new_content` je Datei (Backup `<datei>.orig`,
/// Rollback bei Fehler, kein Teil-Apply).
///
/// Gates (vor jedem Filesystem-Write):
/// - `approved_by` leer -> `APPROVAL_REQUIRED`;
/// - Proposal nicht `Approved` -> `APPROVAL_REQUIRED`;
/// - `expected_old` weicht ab -> `STALE_FILE` (Rollback);
/// - Pfad ausserhalb Jail -> `INVALID_PATH` (kein Write).
///
/// Erfolg: Status `Applied` + Audit-Eintrag (`applied`, actor, rationale).
/// Fehler lassen Dateien + Status unveraendert (Rollback aus `.orig` bzw.
/// In-Memory-Original; erzeugte `.orig`-Backups des Laufs werden dabei
/// wieder entfernt).
pub fn apply_files(
    root: &Path,
    proposal: &mut Proposal,
    approved_by: &str,
    changes: &[FileChange],
    audit: &mut Vec<AuditEntry>,
) -> Result<ApplyReport, String> {
    if approved_by.trim().is_empty() {
        return Err(
            "APPROVAL_REQUIRED: apply braucht approved_by oder vorherige Genehmigung".to_string(),
        );
    }
    if proposal.status != ProposalStatus::Approved {
        return Err(format!(
            "APPROVAL_REQUIRED: apply nur nach approval moeglich (aktuell {:?})",
            proposal.status
        ));
    }
    if changes.is_empty() {
        return Err("INVALID_PARAMS: keine Aenderungen (changes leer)".to_string());
    }
    let targets = jail_all(root, changes)?;

    // Aktuelle Inhalte lesen (TOCTOU-Check + Rollback-Basis).
    let mut current: Vec<Option<String>> = Vec::with_capacity(changes.len());
    for abs in &targets {
        current.push(std::fs::read_to_string(abs).ok().filter(|_| abs.is_file()));
    }
    for (change, old) in changes.iter().zip(current.iter()) {
        if let Some(expected) = change.expected_old.as_deref() {
            if old.as_deref().unwrap_or("") != expected {
                return Err(format!(
                    "STALE_FILE: {} hat sich seit Preview geaendert (erneut previewen)",
                    change.path
                ));
            }
        }
    }

    struct Done {
        target: PathBuf,
        backup: Option<PathBuf>,
        backup_created: bool,
        original: Option<String>,
    }
    let mut done: Vec<Done> = Vec::new();
    let rollback = |done: &[Done]| {
        for d in done.iter().rev() {
            if let Some(orig) = d.original.as_deref() {
                let _ = std::fs::write(&d.target, orig);
            } else {
                let _ = std::fs::remove_file(&d.target);
            }
            if d.backup_created {
                if let Some(b) = d.backup.as_deref() {
                    let _ = std::fs::remove_file(b);
                }
            }
        }
    };

    let mut backups: Vec<String> = Vec::new();
    for ((change, abs), old) in changes.iter().zip(targets.iter()).zip(current.iter()) {
        // Backup .orig (bestehendes .orig nie ueberschreiben).
        let mut backup_path: Option<PathBuf> = None;
        let mut backup_created = false;
        if old.is_some() {
            let cand = abs.with_extension(format!(
                "{}.orig",
                abs.extension().and_then(|e| e.to_str()).unwrap_or("bak")
            ));
            // Falls with_extension die Extension ersetzt statt anhaengt,
            // Fallback: einfach `.orig` anhaengen.
            let cand = if cand == *abs {
                abs.with_extension("orig")
            } else {
                cand
            };
            if cand.exists() {
                // Fremdes Backup bewahren: Inhalt liegt in `current`.
                backup_path = Some(cand);
            } else if let Err(e) = std::fs::copy(abs, &cand) {
                rollback(&done);
                return Err(format!(
                    "APPLY_FAILED: backup {}: {e} (rollback ok)",
                    change.path
                ));
            } else {
                backup_created = true;
                backups.push(cand.display().to_string());
                backup_path = Some(cand);
            }
        }
        // Elternverzeichnisse (innerhalb Jail) anlegen.
        if let Some(parent) = abs.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                rollback(&done);
                return Err(format!(
                    "APPLY_FAILED: mkdir {}: {e} (rollback ok)",
                    change.path
                ));
            }
        }
        if let Err(e) = std::fs::write(abs, &change.new_content) {
            // Backup-Eintrag zuruecknehmen, falls wir ihn angelegt haben.
            if backup_created {
                backups.pop();
            }
            done.push(Done {
                target: abs.clone(),
                backup: backup_path,
                backup_created,
                original: old.clone(),
            });
            rollback(&done);
            return Err(format!(
                "APPLY_FAILED: write {}: {e} (rollback ok)",
                change.path
            ));
        }
        done.push(Done {
            target: abs.clone(),
            backup: backup_path,
            backup_created,
            original: old.clone(),
        });
    }

    proposal.apply().map_err(|e| {
        rollback(&done);
        format!("{e} (rollback ok)")
    })?;
    audit.push(AuditEntry {
        proposal_id: proposal.id.clone(),
        event: "applied".to_string(),
        actor: approved_by.trim().to_string(),
        rationale: proposal.rationale.clone(),
    });
    Ok(ApplyReport {
        proposal_id: proposal.id.clone(),
        files_changed: changes.iter().map(|c| c.path.clone()).collect(),
        backups,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    fn tmp_root() -> PathBuf {
        let id = N.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("cate_apply_{}_{id}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn approved(id: &str) -> Proposal {
        let mut p = Proposal::new(id, "f1", "n1", "titel", "begruendung").unwrap();
        p.approve("review-begruendung").unwrap();
        p
    }

    fn change(path: &str, new_content: &str) -> FileChange {
        FileChange {
            path: path.to_string(),
            new_content: new_content.to_string(),
            expected_old: None,
        }
    }

    #[test]
    fn approval_gate_ohne_approved_wird_nichts_geschrieben() {
        let root = tmp_root();
        let mut p = Proposal::new("p1", "f1", "n1", "t", "r").unwrap();
        let mut audit = Vec::new();
        let err = apply_files(
            &root,
            &mut p,
            "alice",
            &[change("a.txt", "neu")],
            &mut audit,
        )
        .unwrap_err();
        assert!(err.contains("APPROVAL_REQUIRED"), "unerwartet: {err}");
        assert!(!root.join("a.txt").exists());
        assert!(audit.is_empty());
        assert_eq!(p.status, ProposalStatus::Proposed);
    }

    #[test]
    fn approval_gate_leerer_actor_wird_abgelehnt() {
        let root = tmp_root();
        let mut p = approved("p1");
        let mut audit = Vec::new();
        let err =
            apply_files(&root, &mut p, "  ", &[change("a.txt", "neu")], &mut audit).unwrap_err();
        assert!(err.contains("APPROVAL_REQUIRED"), "unerwartet: {err}");
        assert!(!root.join("a.txt").exists());
        assert!(audit.is_empty());
    }

    #[test]
    fn preview_dann_apply_schreibt_backup_und_audit() {
        let root = tmp_root();
        std::fs::write(root.join("a.txt"), "alt\n").unwrap();
        let mut p = approved("p1");
        let changes = vec![change("a.txt", "neu\n")];
        let preview = preview_apply_files(&root, &p, &changes).unwrap();
        assert_eq!(preview.len(), 1);
        assert!(preview[0].diff.contains("- alt"));
        assert!(preview[0].diff.contains("+ neu"));

        let mut audit = Vec::new();
        let report = apply_files(&root, &mut p, "alice", &changes, &mut audit).unwrap();
        assert_eq!(report.files_changed, vec!["a.txt".to_string()]);
        assert_eq!(report.backups.len(), 1);
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "neu\n"
        );
        // Backup enthaelt Original.
        let backup = PathBuf::from(&report.backups[0]);
        assert_eq!(std::fs::read_to_string(backup).unwrap(), "alt\n");
        assert_eq!(p.status, ProposalStatus::Applied);
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].proposal_id, "p1");
        assert_eq!(audit[0].actor, "alice");
        assert_eq!(audit[0].event, "applied");
    }

    #[test]
    fn stale_file_rollt_erste_datei_zurueck() {
        let root = tmp_root();
        std::fs::write(root.join("a.txt"), "a-alt\n").unwrap();
        std::fs::write(root.join("b.txt"), "b-geaendert\n").unwrap();
        let mut p = approved("p1");
        let changes = vec![
            change("a.txt", "a-neu\n"),
            FileChange {
                path: "b.txt".to_string(),
                new_content: "b-neu\n".to_string(),
                expected_old: Some("b-alt\n".to_string()),
            },
        ];
        let mut audit = Vec::new();
        let err = apply_files(&root, &mut p, "alice", &changes, &mut audit).unwrap_err();
        assert!(err.contains("STALE_FILE"), "unerwartet: {err}");
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "a-alt\n"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("b.txt")).unwrap(),
            "b-geaendert\n"
        );
        assert!(audit.is_empty());
        assert_eq!(p.status, ProposalStatus::Approved);
    }

    #[test]
    fn jail_reject_dotdot_absolut_und_prefix() {
        let root = tmp_root();
        let mut p = approved("p1");
        let mut audit = Vec::new();
        for evil in [
            "../escape.txt",
            "..\\escape.txt",
            "/abs/olut.txt",
            "sub/../../x.txt",
        ] {
            let err =
                apply_files(&root, &mut p, "alice", &[change(evil, "x")], &mut audit).unwrap_err();
            assert!(err.contains("INVALID_PATH"), "{evil}: {err}");
        }
        assert!(audit.is_empty());
        // Legitimer Unterpfad geht durch.
        let report = apply_files(
            &root,
            &mut p,
            "alice",
            &[change("sub/ok.txt", "x")],
            &mut audit,
        )
        .unwrap();
        assert_eq!(report.backups.len(), 0, "neue Datei braucht kein Backup");
        assert_eq!(
            std::fs::read_to_string(root.join("sub/ok.txt")).unwrap(),
            "x"
        );
    }

    #[test]
    fn preview_redigiert_secrets() {
        let root = tmp_root();
        std::fs::write(root.join("k.txt"), "harmlos\n").unwrap();
        let p = approved("p1");
        let preview =
            preview_apply_files(&root, &p, &[change("k.txt", "password=supersecret123\n")])
                .unwrap();
        assert!(!preview[0].diff.contains("supersecret123"));
        assert!(preview[0].diff.contains("[REDACTED]"));
    }

    #[test]
    fn leere_changes_abgelehnt() {
        let root = tmp_root();
        let mut p = approved("p1");
        let mut audit = Vec::new();
        let err = apply_files(&root, &mut p, "alice", &[], &mut audit).unwrap_err();
        assert!(err.contains("INVALID_PARAMS"), "unerwartet: {err}");
    }
}
