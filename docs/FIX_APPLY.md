# Echte Fix-Anwendung (`preview_fix` / `apply_fix_files`)

> Stand: 2026-10-17. `suggest_fix` / `approve_fix` / `apply_fix`
> (Status-Gates) und MCP `apply_proposal` (Gate + Audit, keine
> Dateischreibung) sind Platzhalter ohne Filesystem-Effekt. Dieses
> Dokument beschreibt die echte Dateianwendung.

## Ablage-Entscheid: Shared-Library + Tauri-seitig (kein CLI-Subcommand)

- **Shared-Library:** `crates/cate-graph/src/apply.rs`
  (`resolve_in_jail`, `preview_apply_files`, `apply_files`,
  Typen `FileChange` / `FileDiff` / `ApplyReport`).
- **Tauri:** `src-tauri/src/fixflow.rs` (`FixStore::preview_files`,
  `FixStore::apply_with_files`) + Commands `preview_fix`,
  `apply_fix_files` in `src-tauri/src/main.rs`.
- **Kein CLI-Subcommand:** `cate scan` / `audit` / ... bleiben
  bewusst read-only (Analyse ohne Schreibrecht). Approvals +
  Reviewer leben im Desktop-Review-Flow; ein CLI-Write-Pfad wuerde
  das Approval-Gate umgehen und ist daher nicht vorgesehen.
- **MCP unveraendert:** `catehunt_apply_proposal` bleibt gate-only
  (Genehmigung + Audit, `files_changed: []`). Echte Writes laufen
  nur ueber Tauri + `cate-graph::apply`.

## Ablauf (S4-Regel: Preview vor Apply)

1. `suggest_fix` -> `approve_fix` (Reviewer + Begruendung, TTL 30 Tage).
2. `preview_fix(proposal_id, root, changes)` — read-only Diff
   (`- alt` / `+ neu`), Secrets redigiert (`cate-core::redact`).
   Merkt sich `changes` je Proposal.
3. `apply_fix_files(proposal_id, approved_by, root, changes)` —
   nur bei exaktem Preview-Match, sonst `PREVIEW_REQUIRED`.

## Garantien

- **Approval-Gate:** ohne `Approved`-Status oder ohne `approved_by`
  -> `APPROVAL_REQUIRED`; kein Filesystem-Touch, kein Audit-Eintrag.
  Abgelaufene Approvals -> `APPROVAL_EXPIRED`; Suppress auf
  Deny-CWE -> `DENY_SUPPRESS_BLOCKED` (Re-Check).
- **Path-Jail:** alle Pfade relativ zu `root` (Default: CWD,
  kanonisiert, Verzeichnis-Pflicht). Abgelehnt mit `INVALID_PATH`:
  leer/NUL, absolut, UNC/Prefix, `..`, Symlink-Ziele ausserhalb Root.
- **Backup + Rollback:** jede ueberschriebene Datei wird vorher nach
  `<datei>.orig` kopiert (bestehendes `.orig` wird nie ueberschrieben;
  neue Dateien brauchen kein Backup). Jeder `APPLY_FAILED`-/
  `STALE_FILE`-Fehler rollt alle bereits geschriebenen Dateien
  zurueck (kein Teil-Apply); Lauf-Backups werden dabei entfernt,
  Erfolgs-Backups bleiben liegen.
- **TOCTOU:** `FileChange.expected_old` (optional) bricht bei
  abweichendem Inhalt mit `STALE_FILE` ab (erneut previewen).
- **Audit:** Erfolg schreibt einen append-only Eintrag
  (`proposal_id`, `applied`, `approved_by`); Fehler schreiben nichts.
- **Default read-only:** das alte `apply_fix` (nur Statuswechsel)
  bleibt unveraendert; Dateischreibung gibt es nur ueber
  `apply_fix_files`.

## Fehlercodes

`APPROVAL_REQUIRED` | `APPROVAL_EXPIRED` | `PREVIEW_REQUIRED` |
`DENY_SUPPRESS_BLOCKED` | `INVALID_PATH` | `STALE_FILE` |
`APPLY_FAILED` (immer mit Rollback) | `INVALID_PARAMS` (leere changes)
