// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! S4-TOCTOU-Tests: Pfad-NACH-Aufloesung gegen Allowlist (kein Race
//! zwischen Pruefen und Spawnen). Windows-kompatibel (Junction/Symlink).
use cate_sandbox::{toctou_resolve, SandboxConfig, SandboxError};
use std::path::{Path, PathBuf};

/// Legt einen Scratch-Ordner + einen spuerbaren Stub-Binary an.
fn setup_stub(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "cate-toctou-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("toctou dir");
    let exe = dir.join(format!("{name}_stub.cmd"));
    std::fs::write(&exe, "@echo off\r\necho toctou-ok\r\n").expect("stub schreiben");
    (dir, exe)
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn toctou_resolution_returns_canonical_path() {
    let (dir, exe) = setup_stub("ok");
    // keine Allowlist noetig: absoluter Pfad ist explizit erlaubt.
    let cfg = SandboxConfig::default();
    let p = exe.to_string_lossy().into_owned();
    let canon = toctou_resolve(&cfg, &p).expect("legaler Pfad muss resolve");
    assert!(
        canon.to_string_lossy().contains("cate-toctou-ok"),
        "kanonischer Pfad zeigt auf Stub: {canon:?}"
    );
    cleanup(&dir);
}

#[test]
fn toctou_rejects_symlink_swap_after_check() {
    // Ablauf wie der TOCTOU-Angriff:
    //  1. `resolve` gegen den Stub-Pfad pruften (erster Check, ok),
    //  2. Pfad (Junction) nacherstellen/austauschen, der auf ein
    //     anderes Ziel zeigt ("nach Pruefen ausgetauscht"),
    //  3. `toctou_resolve` erneut aufrufen -> muss Ablehnen (Abweichung)
    //     — kein Race-Exploit.
    let (dir, _exe) = setup_stub("swap");
    // Windows: Symlink auf Datei braucht Privileg; Directory-Junctions
    // sind unprivilegiert moeglich (mklink /J), deshalb ueber Verzeichnis.
    let (dir2, _exe2) = setup_stub("target");
    let link = dir.join("link_dir");
    // Junction erstellen: fs::symlink_dir geht falls Dev-Mode; sonst
    // via cmd (mklink /J ist unprivilegiert).
    let created = std::os::windows::fs::symlink_dir(&dir2, &link);
    if created.is_err() {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&dir2)
            .status()
            .expect("cmd verfuegbar");
        assert!(
            status.success(),
            "weder fs::symlink_dir noch mklink /J moeglich"
        );
    }

    // Stub-DATEI gleichnamig in das Link-Ziel legen (fuer die Pruefung).
    let swapped = link.join("swap_stub.cmd");
    std::fs::write(&swapped, "@echo off\r\necho bazis-ok\r\n").expect("linkziels stub");

    // Erst Auflösung (erwartet: ok, da knapp vor dem Austausch).
    let cfg = SandboxConfig::default();
    let raw = swapped.to_string_lossy().into_owned();
    let first = toctou_resolve(&cfg, &raw);
    // JETZT den Link umhaengen ("nach Pruefen ausgetauscht") —
    // Junction retarget ist nicht direkt moeglich; stattdessen loeschen
    // und neu auf das ERSTE Ziel legen.
    let _ = std::fs::remove_dir(&link);
    let created = std::os::windows::fs::symlink_dir(&dir, &link);
    if created.is_err() {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&dir)
            .status()
            .expect("cmd verfuegbar");
        assert!(status.success(), "Junction-Neulegen muss klappen");
    }
    // Lokal identischer Pfad — aber unter dem Link liegt jetzt das
    // andere Verzeichnis (ohne swap_stub). Auflösung muss verweigern
    // (fail-closed), statt auf den gelinkten Pfad zu spawnen.
    let second = toctou_resolve(&cfg, &raw);
    assert!(
        second.is_err(),
        "Symlink/Junction-Nachtraeglichkeit muss verweigern: {second:?} (first={first:?})"
    );
    let err = second.unwrap_err();
    assert!(
        matches!(err, SandboxError::BinaryNotAllowed(_)),
        "falscher Fehler: {err}"
    );
    let _ = std::fs::remove_file(&swapped);
    cleanup(&dir);
    cleanup(&dir2);
}

#[test]
fn toctou_rejects_missing_target_fail_closed() {
    let dir = std::env::temp_dir().join(format!("cate-toctou-missing-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let cfg = SandboxConfig::default();
    let ghost = dir.join("gibts-nicht.cmd");
    let res = toctou_resolve(&cfg, &ghost.to_string_lossy());
    assert!(
        matches!(res, Err(SandboxError::BinaryNotAllowed(_))),
        "fehlendes Ziel muss fail-closed verweigern"
    );
    let _ = std::fs::remove_dir(&dir);
}
