// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Scope/Inventar Stufe 0: geaenderte Dateien seit Base (git diff parse)
//! + Lockfile-Bestandsaufnahme. Kein Netz, keine Semantik.
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Eine geaenderte Datei aus `git diff --name-status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedFile {
    /// Statusbuchstabe: A/M/D/R/C/...
    pub status: char,
    /// Pfad (bei Rename: neuer Pfad).
    pub path: String,
}

/// Bestandsaufnahme: welche Lockfiles liegen im Scan-Root?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    pub lockfiles: Vec<String>,
    pub has_cargo_lock: bool,
    pub has_package_lock: bool,
}

/// Parst `git diff --name-status`-Output (eine Datei pro Zeile:
/// `<STATUS>\t<pfad>`; Rename/Copy: `<R100>\t<alt>\t<neu>`).
/// Leere/unbekannte Zeilen werden ignoriert.
pub fn parse_git_diff_name_status(output: &str) -> Vec<ChangedFile> {
    let mut out = Vec::new();
    for line in output.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split('\t');
        let status_raw = match parts.next() {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };
        let status = status_raw.chars().next().unwrap_or('?');
        if !matches!(status, 'A' | 'M' | 'D' | 'R' | 'C' | 'T' | 'U' | 'X' | 'B') {
            continue;
        }
        // Bei Rename/Copy gilt der neue Pfad (letztes Feld).
        let path = parts.next_back().unwrap_or("").to_string();
        if path.is_empty() {
            continue;
        }
        // NUL-Bytes sind auf keinem Ziel-OS gueltige Pfadbestandteile
        // und wuerden spaetere OS-Aufrufe sprengen -> Eintrag verwerfen.
        if path.contains('\0') {
            continue;
        }
        out.push(ChangedFile { status, path });
    }
    out
}

/// Fragt git nach geaenderten Dateien seit `base`:
/// `git -C <dir> diff --name-status <base>`. Gibt (stdout) zurueck;
/// bei Fehler (kein Repo, unbekannte Rev) eine Beschreibung.
pub fn changed_files_since(dir: &Path, base: &str) -> Result<Vec<ChangedFile>, String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .arg("diff")
        .arg("--name-status")
        .arg(base)
        .output()
        .map_err(|e| format!("git diff failed: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(format!("git diff --name-status {base}: {err}"));
    }
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    Ok(parse_git_diff_name_status(&stdout))
}

/// Lockfile-Bestandsaufnahme im Verzeichnis `dir` (Stufe 0: Existenz).
pub fn inventory(dir: &Path) -> Inventory {
    let mut lockfiles = Vec::new();
    let has_cargo_lock = dir.join("Cargo.lock").is_file();
    let has_package_lock = dir.join("package-lock.json").is_file();
    if has_cargo_lock {
        lockfiles.push("Cargo.lock".to_string());
    }
    if has_package_lock {
        lockfiles.push("package-lock.json".to_string());
    }
    Inventory {
        lockfiles,
        has_cargo_lock,
        has_package_lock,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_added_modified_deleted() {
        let diff = "A\tsrc/neu.rs\nM\tsrc/alt.rs\nD\tsrc/weg.rs\n";
        let files = parse_git_diff_name_status(diff);
        assert_eq!(files.len(), 3);
        assert_eq!(files[0].status, 'A');
        assert_eq!(files[0].path, "src/neu.rs");
        assert_eq!(files[2].status, 'D');
    }

    #[test]
    fn rename_takes_new_path() {
        let diff = "R100\tsrc/alt.rs\tsrc/neu.rs\n";
        let files = parse_git_diff_name_status(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].status, 'R');
        assert_eq!(files[0].path, "src/neu.rs");
    }

    #[test]
    fn empty_and_garbage_lines_ignored() {
        let diff = "\n\n???\nM\tok.rs\n";
        let files = parse_git_diff_name_status(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "ok.rs");
    }

    #[test]
    fn inventory_finds_lockfiles() {
        let dir = std::env::temp_dir().join(format!(
            "cate_inv_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Cargo.lock"), "x").unwrap();
        let inv = inventory(&dir);
        assert!(inv.has_cargo_lock);
        assert!(!inv.has_package_lock);
        assert_eq!(inv.lockfiles, vec!["Cargo.lock".to_string()]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn inventory_empty_dir_has_nothing() {
        let dir = std::env::temp_dir().join(format!(
            "cate_inv_empty_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let inv = inventory(&dir);
        assert!(!inv.has_cargo_lock);
        assert!(inv.lockfiles.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}
