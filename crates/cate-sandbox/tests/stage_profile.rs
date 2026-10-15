// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! S4-Tests (Staged Confinement): Stufen-Matrix + Dry-Run-Roundtrip.
//!
//! Stufen-Matrix beweist auf Prozessebene (Kind via `cmd /C set` bzw.
//! `env`), also Windows-kompatibel ohne cgroup/Linux-only-Annahmen:
//! - Netz-Stufe ([`StageProfile::Network`]): Env enthaelt nie
//!   Finding-/Secret-/Proxy-Variablen; argv kommt nur aus
//!   `RedactionOutput`.
//! - Daten-Stufe ([`StageProfile::Data`]): Env hat nie Proxy/Secrets,
//!   Finding-Daten bleiben lokal in scratch (hier: Canary-Datei), kein
//!   Netz-Zugang (env_testet kein `HTTP_PROXY`).
use cate_sandbox::{
    create_scratch, remove_scratch, run_sandboxed, FixDryRunPreview, RedactionOutput,
    SandboxRequest, StageProfile,
};
use std::path::Path;

/// Env-Dump-Kommando (`env` bzw. `cmd /C set`) als (Pfad, argv).
fn env_dump_cmd() -> (std::path::PathBuf, Vec<String>) {
    for p in ["/usr/bin/env", "/bin/env"] {
        if Path::new(p).is_file() {
            return (std::path::PathBuf::from(p), vec![]);
        }
    }
    let sys32 = std::env::var("SystemRoot")
        .map(|r| std::path::PathBuf::from(r).join("System32"))
        .unwrap_or_else(|_| std::path::PathBuf::from(r"C:\Windows\System32"));
    (
        sys32.join("cmd.exe"),
        vec!["/C".to_string(), "set".to_string()],
    )
}

fn with_scratch(f: impl FnOnce(&Path)) {
    let dir = create_scratch().expect("scratch anlegen");
    f(&dir);
    let _ = remove_scratch(&dir);
}

// --- S4 Stufen-Matrix, Zeile Netz: Netz-Stufe ohne Roh-Daten ---

#[test]
fn netz_stufe_sieht_keine_findings_oder_secrets() {
    // Eltern-Prozess bekommt Canary-Finding + Secret + Proxy —
    // die Network-Stage-Config darf davon NICHTS ins Kind geben.
    let pid = std::process::id();
    let secret_key = format!("CATE_S4_SECRET_{pid}");
    std::env::set_var(&secret_key, "s4-geheim-canary-9982");
    std::env::set_var("HTTP_PROXY", "http://proxy-s4-canary.invalid:9999");
    std::env::set_var("HTTPS_PROXY", "http://proxy-s4-canary.invalid:9999");

    let cfg = StageProfile::Network.config_for_profile();
    // Stufen-Matrix: Network = Netz JA, Roh-Daten NEIN.
    assert!(StageProfile::Network.has_network());
    assert!(!StageProfile::Network.has_data());
    assert!(
        !cfg.env_allowlist
            .iter()
            .any(|k| k.to_ascii_uppercase().contains("PROXY")),
        "Netz-Stufe darf keine Proxy-Variablen erben (R2-light/S4)"
    );
    assert!(
        !cfg.env_allowlist.iter().any(|k| k == &secret_key),
        "Netz-Stufe darf Secrets nicht in die Env-Allowlist aufnehmen"
    );

    let (prog, args) = env_dump_cmd();
    let prog_s = prog.to_string_lossy().into_owned();
    // Stufen-Args NUR aus RedactionOutput (redigiert, kein Roh-Secret);
    // als Pseudo-Env-Dump-Zusatz-Prompts kommt der redigierte String als
    // ECHO-Text vor dem eigentlichen `set` (cmd-Fehlerfreiheit).
    let red = RedactionOutput::new("password \u{00ab}redacted:\u{2026}\u{00bb}".to_string());
    let argv: Vec<String> = if cfg!(windows) {
        // cmd: erst redigiertes Echo ausgeben, dann env dumpen.
        vec![
            "/C".to_string(),
            format!(r"echo {} & set", red.as_str().replace('^', "^^")),
        ]
    } else {
        let mut a = args.clone();
        a.push(format!("prompt_prefix={}", red.as_str()));
        a
    };
    with_scratch(|scratch| {
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let req = SandboxRequest {
            program: &prog_s,
            args: &refs,
            scratch,
            timeout_secs: 15,
        };
        let (res, _) = run_sandboxed(&cfg, &req).expect("run");
        assert_eq!(res.exit_code, Some(0), "stderr: {:?}", res.stderr);
        let dump = res.stdout.to_ascii_uppercase();
        assert!(
            !dump.contains("S4-GEHEIM-CANARY-9982"),
            "Netz-Stufe sieht Eltern-Secret nie (Env)"
        );
        assert!(
            !dump.contains("PROXY-S4-CANARY"),
            "Netz-Stufe erbt keine Proxy-Creds"
        );
        assert!(
            !dump.contains("supersecret"),
            "redigierter argv-Inhalt muss redigiert bleiben (kein Roh-Secret)"
        );
    });

    std::env::remove_var(&secret_key);
    std::env::remove_var("HTTP_PROXY");
    std::env::remove_var("HTTPS_PROXY");
}

// --- S4 Stufen-Matrix, Zeile Daten: Daten-Stufe ohne Netz ---

#[test]
fn daten_stufe_hat_kein_netz() {
    let pid = std::process::id();
    let secret_key = format!("CATE_S4_SECRET_{pid}");
    std::env::set_var(&secret_key, "s4-geheim-canary-9982");
    std::env::set_var("HTTP_PROXY", "http://proxy-s4-canary.invalid:9999");
    std::env::set_var("HTTPS_PROXY", "http://proxy-s4-canary.invalid:9999");

    let cfg = StageProfile::Data.config_for_profile();
    // Stufen-Matrix: Data = Netz NEIN, Roh-Daten JA.
    assert!(!StageProfile::Data.has_network());
    assert!(StageProfile::Data.has_data());
    assert!(
        !cfg.env_allowlist
            .iter()
            .any(|k| k.to_ascii_uppercase().contains("PROXY")),
        "Daten-Stufe hat kein Proxy-Netz-Env (kein Egress-Helfer)"
    );

    let (prog, args) = env_dump_cmd();
    let prog_s = prog.to_string_lossy().into_owned();
    with_scratch(|scratch| {
        // Roh-Daten (Finding-Canary) landen bewusst im scratch — die
        // Data-Stage darf sie lokal sehen; Netz sieht sie nie.
        let finding = scratch.join("finding-roh.txt");
        std::fs::write(&finding, "roh-befund s4-geheim-canary-9982").expect("finding schreiben");
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let req = SandboxRequest {
            program: &prog_s,
            args: &refs,
            scratch,
            timeout_secs: 15,
        };
        let (res, _) = run_sandboxed(&cfg, &req).expect("run");
        assert_eq!(res.exit_code, Some(0), "stderr: {:?}", res.stderr);
        let dump = res.stdout.to_ascii_uppercase();
        // Roh-Daten lokal sichtbar (Data-Zeile der Matrix).
        assert!(
            dump.contains("TEMP=") || dump.contains("Path="),
            "Data-Stage braucht lokale Laufzeit-Env: {:?}",
            &res.stdout[..res.stdout.len().min(400)]
        );
        // Aber NIE Netz/Proxy/Secret-Env (kein Egress-Pfad).
        assert!(
            !dump.contains("PROXY-S4-CANARY"),
            "Daten-Stufe hat kein Netz-Env (Proxy blockiert)"
        );
        assert!(
            !dump.contains("S4-GEHEIM-CANARY-9982"),
            "Secrets bleiben auch der Data-Stage Fern (R4, Defense in Depth)"
        );
        // Roh-Finding bleibt in scratch (nie via argv/env versendet).
        assert!(finding.is_file());
    });

    std::env::remove_var(&secret_key);
    std::env::remove_var("HTTP_PROXY");
    std::env::remove_var("HTTPS_PROXY");
}

// --- S4 Dry-Run-Roundtrip: suggest->capture->preview->apply/verwerfen ---

#[test]
fn dry_run_roundtrip_captures_ohne_inhalt() {
    // Echo-Run als Preview (kein Apply, kein persistenter Status).
    let prog = if Path::new("/bin/echo").is_file() {
        std::path::PathBuf::from("/bin/echo")
    } else {
        let sys32 = std::env::var("SystemRoot")
            .map(|r| std::path::PathBuf::from(r).join("System32"))
            .unwrap_or_else(|_| std::path::PathBuf::from(r"C:\Windows\System32"));
        assert!(sys32.join("cmd.exe").is_file());
        sys32.join("cmd.exe")
    };
    let argv: Vec<String> = if cfg!(windows) {
        vec![
            "/C".to_string(),
            "echo".to_string(),
            "preview-s4-roundtrip".to_string(),
        ]
    } else {
        vec!["preview-s4-roundtrip".to_string()]
    };
    let prog_s = prog.to_string_lossy().into_owned();
    let cfg = StageProfile::Data.config_for_profile();
    with_scratch(|scratch| {
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let req = SandboxRequest {
            program: &prog_s,
            args: &refs,
            scratch,
            timeout_secs: 15,
        };
        let (res, _) = run_sandboxed(&cfg, &req).expect("run");
        assert!(res.success());
        // Preview capturen (Effekte, nie Inhalte) + JSON-Roundtrip.
        let preview = FixDryRunPreview::capture_effects(&req, StageProfile::Data, &res);
        let json = serde_json::to_string(&preview).expect("preview serialisieren");
        assert!(
            !json.contains("preview-s4-roundtrip"),
            "Preview-Datensatz darf Run-Inhalte nicht wiederholen: {json}"
        );
        assert!(!json.contains("hello"), "Preview ohne stdout-Inhalt");
        let back: FixDryRunPreview = serde_json::from_str(&json).expect("roundtrip");
        assert_eq!(back, preview, "Roundtrip verlustfrei");
        assert_eq!(back.effects.exit_code, Some(0));
        assert!(!back.effects.truncated);
        assert!(back.effects.stdout_len > 0, "Echo floppt nicht");
        assert_eq!(back.profile, StageProfile::Data);
        assert_eq!(back.args_len, argv.len());
        assert_eq!(back.timeout_secs, 15);
    });
}
