// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Negativ-Tests der Prozess-Sandbox (echter Exec, kurze Timeouts).
use cate_sandbox::{
    cap_output, create_scratch, remove_scratch, resolve_in_scratch, resolve_program, run_sandboxed,
    SandboxConfig, SandboxError, SandboxRequest,
};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Schlaf-Kommando als (absoluter Pfad, argv) — expliziter Pfad, keine Allowlist noetig.
fn sleep_cmd(secs: &str) -> (PathBuf, Vec<String>) {
    if Path::new("/bin/sleep").is_file() {
        return (PathBuf::from("/bin/sleep"), vec![secs.to_string()]);
    }
    let sys32 = std::env::var("SystemRoot")
        .map(|r| PathBuf::from(r).join("System32"))
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\System32"));
    // powershell zuerst: timeout.exe verweigert redirectes stdin
    // ("Input redirection is not supported") und taugt nicht als Sleep-Stub.
    let ps = sys32
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    if ps.is_file() {
        return (
            ps,
            vec![
                "-NoProfile".to_string(),
                "-Command".to_string(),
                format!("Start-Sleep -Seconds {secs}"),
            ],
        );
    }
    let cmd = sys32.join("cmd.exe");
    if cmd.is_file() {
        // ping -n <secs+1> wartet ca. <secs> Sekunden, liest kein stdin.
        let n = secs.parse::<u32>().unwrap_or(30) + 1;
        return (
            cmd,
            vec!["/C".to_string(), format!("ping -n {n} 127.0.0.1 >NUL")],
        );
    }
    panic!("kein Schlaf-Binary gefunden (weder /bin/sleep noch powershell.exe/cmd.exe)");
}

/// Echo-Kommando (kurze Ausgabe, Exit 0 erwartet).
fn echo_cmd() -> (PathBuf, Vec<String>) {
    if Path::new("/bin/echo").is_file() {
        return (
            PathBuf::from("/bin/echo"),
            vec!["hello-sandbox".to_string()],
        );
    }
    let sys32 = std::env::var("SystemRoot")
        .map(|r| PathBuf::from(r).join("System32"))
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\System32"));
    let cmd = sys32.join("cmd.exe");
    assert!(cmd.is_file(), "cmd.exe fehlt: {}", cmd.display());
    (
        cmd,
        vec!["/C".to_string(), "echo hello-sandbox".to_string()],
    )
}

fn with_scratch(f: impl FnOnce(&Path)) {
    let dir = create_scratch().expect("scratch anlegen");
    f(&dir);
    let _ = remove_scratch(&dir);
    assert!(!dir.exists(), "scratch muss aufgeraeumt sein");
}

// --- S2-Haertung: Env-Dump als (absoluter Pfad, argv) ---

/// Gibt die Kind-Umgebung auf stdout aus (`env` bzw. `cmd /C set`).
fn env_dump_cmd() -> (PathBuf, Vec<String>) {
    for p in ["/usr/bin/env", "/bin/env"] {
        if Path::new(p).is_file() {
            return (PathBuf::from(p), vec![]);
        }
    }
    let sys32 = std::env::var("SystemRoot")
        .map(|r| PathBuf::from(r).join("System32"))
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\System32"));
    let cmd = sys32.join("cmd.exe");
    assert!(cmd.is_file(), "cmd.exe fehlt: {}", cmd.display());
    (cmd, vec!["/C".to_string(), "set".to_string()])
}

/// Shell-Interpreter als absoluter Pfad (sh bzw. powershell.exe).
fn shell_prog() -> PathBuf {
    for p in ["/bin/sh", "/usr/bin/sh"] {
        if Path::new(p).is_file() {
            return PathBuf::from(p);
        }
    }
    let sys32 = std::env::var("SystemRoot")
        .map(|r| PathBuf::from(r).join("System32"))
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\System32"));
    let ps = sys32
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    assert!(ps.is_file(), "kein Shell-Interpreter gefunden");
    ps
}

fn count_lines(path: &Path) -> usize {
    std::fs::read_to_string(path)
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

// --- S2/R4: Canary-Env ist im Kind unsichtbar ---

#[test]
fn canary_env_not_visible_in_child() {
    let pid = std::process::id();
    let canary_key = format!("CATE_SANDBOX_TEST_CANARY_{pid}");
    let canary_val = "canary-geheim-9f3k2-x7";
    std::env::set_var(&canary_key, canary_val);
    std::env::set_var("HTTP_PROXY", "http://proxy-canary-xyz.invalid:9999");
    std::env::set_var("HTTPS_PROXY", "http://proxy-canary-xyz.invalid:9999");

    let (prog, args) = env_dump_cmd();
    let prog_s = prog.to_string_lossy().into_owned();
    let cfg = SandboxConfig::default();
    with_scratch(|scratch| {
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let req = SandboxRequest {
            program: &prog_s,
            args: &arg_refs,
            scratch,
            timeout_secs: 15,
        };
        let (res, _) = run_sandboxed(&cfg, &req).expect("run");
        assert_eq!(res.exit_code, Some(0), "stderr: {:?}", res.stderr);
        let dump = res.stdout.to_ascii_uppercase();
        assert!(
            !dump.contains(&canary_val.to_ascii_uppercase()),
            "Canary-Env darf im Kind nicht sichtbar sein"
        );
        assert!(
            !dump.contains("PROXY-CANARY-XYZ"),
            "Proxy-Creds duerfen das Kind nie erreichen (R2-light)"
        );
        assert!(
            dump.contains("PATH="),
            "Laufzeit-Env (PATH) muss vererbt sein, Dump: {:?}",
            &res.stdout[..res.stdout.len().min(300)]
        );
    });

    std::env::remove_var(&canary_key);
    std::env::remove_var("HTTP_PROXY");
    std::env::remove_var("HTTPS_PROXY");
}

// --- S2/R4: Env-Secret erreicht das Kind nie (extra_env als Positiv-Kontrolle) ---

#[test]
fn secret_env_never_reaches_child() {
    let pid = std::process::id();
    let secret_key = format!("CATE_SANDBOX_TEST_SECRET_{pid}");
    let secret_val = "sk-test-geheim-aaaaaaaa";
    let extra_key = format!("CATE_SANDBOX_TEST_EXTRA_{pid}");
    std::env::set_var(&secret_key, secret_val);

    let (prog, args) = env_dump_cmd();
    let prog_s = prog.to_string_lossy().into_owned();
    let mut cfg = SandboxConfig::default();
    cfg.extra_env
        .push((extra_key.clone(), "extra-sichtbar-123".to_string()));
    with_scratch(|scratch| {
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let req = SandboxRequest {
            program: &prog_s,
            args: &arg_refs,
            scratch,
            timeout_secs: 15,
        };
        let (res, _) = run_sandboxed(&cfg, &req).expect("run");
        assert_eq!(res.exit_code, Some(0), "stderr: {:?}", res.stderr);
        assert!(
            !res.stdout.contains(secret_val),
            "Eltern-Secret darf das Kind nie erreichen"
        );
        assert!(
            res.stdout.contains("extra-sichtbar-123"),
            "extra_env (Operator) muss durchkommen"
        );
    });

    std::env::remove_var(&secret_key);
}

// --- S2/R1: Enkel ueberleben den Timeout nicht (Heartbeat-Beweis) ---

#[test]
fn grandchildren_die_on_timeout() {
    with_scratch(|scratch| {
        let beat = scratch.join("heartbeat.log");
        let beat_s = beat.to_string_lossy().into_owned();
        let sh = shell_prog();

        // Spawner: startet Enkel mit Heartbeat-Loop, schlaeft dann 60 s.
        // Unix: sh-Skript; Windows: powershell-Skript (Enkel via
        // Start-Process — bleibt im Job, kein Breakaway).
        let (script, args): (PathBuf, Vec<String>) = if cfg!(windows) {
            // Enkel = cmd-Loop (Start-Process, headless-sicher, ~200 ms
            // Start; bleibt im Job, kein Breakaway). Schreibt Beats ab
            // Sekunde 1 — powershell-Kaltstart des Spawners (~1-2 s)
            // bleibt damit unkritisch. loop.bat leitet den Beat-Pfad aus
            // %~dp0 ab (kein Pfad-Argument → kein cmd-/c-Quoting-Trap).
            let heartbeat = scratch.join("loop.bat");
            std::fs::write(
                &heartbeat,
                "@echo off\r\n:loop\r\necho beat>> \"%~dp0heartbeat.log\"\r\nping -n 2 127.0.0.1 >nul\r\ngoto loop\r\n",
            )
            .expect("loop schreiben");
            let ps1 = scratch.join("spawner.ps1");
            let loop_s = heartbeat.to_string_lossy().into_owned();
            // Pfad als positionales Arg; /S schuetzt Quoting mit Leerzeichen.
            std::fs::write(
                &ps1,
                "param($Loop)\r\n$cmd = '\"' + $Loop + '\"'\r\nStart-Process -FilePath 'cmd.exe' -ArgumentList '/S', '/c', $cmd -WindowStyle Hidden\r\nStart-Sleep -Seconds 60\r\n",
            )
            .expect("spawner schreiben");
            let ps1_s = ps1.to_string_lossy().into_owned();
            (
                sh.clone(),
                vec![
                    "-NoProfile".to_string(),
                    "-ExecutionPolicy".to_string(),
                    "Bypass".to_string(),
                    "-File".to_string(),
                    ps1_s,
                    loop_s,
                ],
            )
        } else {
            let spawner = scratch.join("spawner.sh");
            std::fs::write(
                &spawner,
                "#!/bin/sh\nOUT=\"$1\"\n( while true; do echo beat >> \"$OUT\"; sleep 1; done ) &\nsleep 60\n",
            )
            .expect("spawner schreiben");
            let spawner_s = spawner.to_string_lossy().into_owned();
            (sh.clone(), vec![spawner_s, beat_s.clone()])
        };
        let script_s = script.to_string_lossy().into_owned();
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let cfg = SandboxConfig::default();
        let req = SandboxRequest {
            program: &script_s,
            args: &arg_refs,
            scratch,
            timeout_secs: 8,
        };
        let start = Instant::now();
        let (res, _) = run_sandboxed(&cfg, &req).expect("run");
        assert!(res.timed_out, "60-s-Spawner muss nach 8 s gekillt sein");
        assert!(!res.success());
        assert!(
            start.elapsed().as_secs() < 30,
            "Kill kam zu spaet: {:?}",
            start.elapsed()
        );

        // Heartbeat-Beweis: nach Kill + Nachfrist darf kein neuer Beat
        // mehr kommen (Enkel tot), mindestens einer muss da sein
        // (Enkel lebte vor dem Kill).
        std::thread::sleep(std::time::Duration::from_secs(4));
        let before = count_lines(&beat);
        std::thread::sleep(std::time::Duration::from_secs(2));
        let after = count_lines(&beat);
        assert!(before >= 1, "Enkel muss vor dem Kill gelebt haben");
        assert_eq!(
            before, after,
            "Enkel-Beats nach Kill: vorher {before}, nachher {after} — Kind ueberlebte den Timeout"
        );
    });
}

// --- S2/R3: (begrenzte) Fork-Bombe stirbt, Host bleibt reaktiv ---

#[test]
fn bounded_fork_bomb_dies() {
    with_scratch(|scratch| {
        let sh = shell_prog();
        let (script, args): (PathBuf, Vec<String>) = if cfg!(windows) {
            // 80 kurzlebige Enkel, dann 30 s Vordergrund-Sleep.
            // Job-Prozesslimit faengt die Masse ab, Kill den Rest.
            let bomb = scratch.join("bomb.cmd");
            std::fs::write(
                &bomb,
                "@echo off\r\nfor /L %%i in (1,1,80) do start /min cmd /c \"ping -n 60 127.0.0.1 >nul\"\r\nping -n 31 127.0.0.1 >nul\r\n",
            )
            .expect("bomb schreiben");
            let bomb_s = bomb.to_string_lossy().into_owned();
            let sys32 = std::env::var("SystemRoot")
                .map(|r| PathBuf::from(r).join("System32"))
                .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\System32"));
            let cmd = sys32.join("cmd.exe");
            (cmd, vec!["/C".to_string(), bomb_s])
        } else {
            let bomb = scratch.join("bomb.sh");
            std::fs::write(
                &bomb,
                "#!/bin/sh\ni=0\nwhile [ \"$i\" -lt 200 ]; do i=$((i + 1)); sleep 60 & done\nsleep 30\n",
            )
            .expect("bomb schreiben");
            let bomb_s = bomb.to_string_lossy().into_owned();
            (sh.clone(), vec![bomb_s])
        };
        let script_s = script.to_string_lossy().into_owned();
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut cfg = SandboxConfig::default();
        // Windows: Prozesslimit als Mechanismus-Beweis (pro Job sicher).
        // Linux: Gruppen-Kill (RLIMIT_NPROC pro UID — kein Default).
        // Timeout je Pfad: Windows erwartet fruehen Fail-Exit (s. u.),
        // 20 s ist reiner Backstop; Linux killt per Gruppe nach 8 s.
        #[cfg(windows)]
        {
            cfg.limits.max_processes = Some(16);
        }
        let req = SandboxRequest {
            program: &script_s,
            args: &arg_refs,
            scratch,
            #[cfg(windows)]
            timeout_secs: 20,
            #[cfg(not(windows))]
            timeout_secs: 8,
        };
        let start = Instant::now();
        let (res, _) = run_sandboxed(&cfg, &req).expect("run");
        if cfg!(windows) {
            // Mechanismus (verifiziert, aber lastabhängig WANN er greift):
            // nach ~15 lebenden Enkeln verweigert das Job-Limit jeden
            // weiteren Spawn ("Nicht genügend Quoten ...") — sogar der
            // Vordergrund-Sleep kann nicht starten, die Bombe endet
            // nach Sekunden mit Fehler-Exit statt 30 s zu laufen.
            // Unter Volllast (parallele Test-Binaries) kann der
            // Quota-Fail den 20-s-Backstop verpassen — dann greift der
            // Timeout-Kill (S2-Job-Kill, ebenfalls Garantie). Beide Pfade
            // sind deterministisch an ihrem Ausgang pruefbar:
            if !res.timed_out {
                assert!(!res.success(), "Bombe darf nicht gelingen");
                assert!(
                    !res.stderr.is_empty(),
                    "Quota-Fehler muessen sichtbar sein (Limit-Beweis)"
                );
            }
            // Timeout-Pfad: Kill-Beweis ist das Ende vor dem 30-s-Sleep.
        } else {
            assert!(res.timed_out, "Fork-Bombe muss per Timeout sterben");
        }
        let elapsed = start.elapsed();
        assert!(elapsed.as_secs() < 30, "Bombe fraß den Host: {elapsed:?}");

        // Host reaktiv: Folge-Run gelingt sofort.
        let (prog, echo_args) = echo_cmd();
        let prog_s = prog.to_string_lossy().into_owned();
        let echo_refs: Vec<&str> = echo_args.iter().map(String::as_str).collect();
        let req2 = SandboxRequest {
            program: &prog_s,
            args: &echo_refs,
            scratch,
            timeout_secs: 15,
        };
        let (res2, _) = run_sandboxed(&SandboxConfig::default(), &req2).expect("folge-run");
        assert!(res2.success(), "Host muss nach Bombe reaktiv sein");
    });
}

// --- S2/R3 (Linux): Disk-Fueller stoppt am File-Limit (RLIMIT_FSIZE) ---

#[cfg(target_os = "linux")]
#[test]
fn disk_filler_stopped_by_file_limit() {
    let dd = ["/usr/bin/dd", "/bin/dd"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file());
    let Some(dd) = dd else { return }; // ohne dd kein Mechanismus-Test
    let dd_s = dd.to_string_lossy().into_owned();
    with_scratch(|scratch| {
        let mut cfg = SandboxConfig::default();
        cfg.limits.max_file_bytes = Some(1_000_000);
        let args = vec![
            "if=/dev/zero".to_string(),
            "of=blob.bin".to_string(),
            "bs=65536".to_string(),
            "count=100".to_string(), // 6,4 MiB > 1-MiB-Limit
        ];
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let req = SandboxRequest {
            program: &dd_s,
            args: &arg_refs,
            scratch,
            timeout_secs: 10,
        };
        let start = Instant::now();
        let (res, _) = run_sandboxed(&cfg, &req).expect("run");
        // SIGXFSZ killt dd vor Deadline: kein Timeout, kein Erfolg.
        assert!(!res.timed_out, "File-Limit muss vor Timeout zuschlagen");
        assert!(!res.success(), "Disk-Fueller darf nicht gelingen");
        assert!(
            start.elapsed().as_secs() < 8,
            "File-Limit griff zu spaet: {:?}",
            start.elapsed()
        );
        let size = std::fs::metadata(scratch.join("blob.bin"))
            .map(|m| m.len())
            .unwrap_or(0);
        assert!(size <= 1_100_000, "Blob ueber Limit gewachsen: {size}");
    });
}

#[test]
fn timeout_kills_long_running_process() {
    let (prog, args) = sleep_cmd("30");
    let prog_s = prog.to_string_lossy().into_owned();
    let cfg = SandboxConfig::default();
    with_scratch(|scratch| {
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let req = SandboxRequest {
            program: &prog_s,
            args: &arg_refs,
            scratch,
            timeout_secs: 2,
        };
        let start = Instant::now();
        let (res, audit) = run_sandboxed(&cfg, &req).expect("run");
        let elapsed = start.elapsed();
        assert!(res.timed_out, "30-s-Sleep muss nach 2 s gekillt sein");
        assert!(elapsed.as_secs() < 25, "Kill kam zu spaet: {elapsed:?}");
        assert!(!res.success());
        assert!(audit.timed_out);
        assert!(audit.to_json()["run_id"].as_str().is_some());
    });
}

#[test]
fn non_allowlisted_binary_rejected_without_spawn() {
    let cfg = SandboxConfig::default(); // leere Allowlist
    with_scratch(|scratch| {
        let req = SandboxRequest {
            program: "evil-binary-xyz-12345",
            args: &[],
            scratch,
            timeout_secs: 5,
        };
        let err = run_sandboxed(&cfg, &req).expect_err("muss ablehnen");
        assert!(
            matches!(err, SandboxError::BinaryNotAllowed(_)),
            "falscher Fehler: {err}"
        );
    });
    // Auch resolve_program direkt: relativer Pfad mit Separator ist weder
    // Allowlist-Name noch expliziter absoluter Pfad.
    let cfg = SandboxConfig::default();
    assert!(matches!(
        resolve_program(&cfg, "sub/tool"),
        Err(SandboxError::BinaryNotAllowed(_))
    ));
}

#[test]
fn scratch_escape_rejected() {
    let scratch = create_scratch().expect("scratch anlegen");
    for bad in [
        "../ausbruch.txt",
        "a/../../b",
        "/etc/passwd",
        "C:\\Windows\\x",
        "",
    ] {
        assert!(
            resolve_in_scratch(&scratch, bad).is_err(),
            "Escape muss abgelehnt werden: {bad:?}"
        );
    }
    let ok = resolve_in_scratch(&scratch, "sub/dir/befund.txt").expect("gueltig");
    assert!(ok.starts_with(&scratch));
    let _ = remove_scratch(&scratch);
}

#[test]
fn explicit_path_runs_without_allowlist_entry() {
    let (prog, args) = echo_cmd();
    let prog_s = prog.to_string_lossy().into_owned();
    let cfg = SandboxConfig::default(); // keine Allowlist — expliziter Pfad genuegt
    with_scratch(|scratch| {
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let req = SandboxRequest {
            program: &prog_s,
            args: &arg_refs,
            scratch,
            timeout_secs: 15,
        };
        let (res, audit) = run_sandboxed(&cfg, &req).expect("run");
        assert!(!res.timed_out);
        assert_eq!(res.exit_code, Some(0));
        assert!(res.success());
        assert!(
            res.stdout.contains("hello-sandbox"),
            "stdout: {:?}",
            res.stdout
        );
        assert_eq!(audit.exit_code, Some(0));
        assert!(!audit.truncated);
    });
}

#[test]
fn output_cap_truncates() {
    let big = vec![b'y'; 5000];
    let (s, truncated) = cap_output(&big, 100);
    assert!(truncated);
    assert_eq!(s.len(), 100);
    // Kleiner Cap am laufenden Prozess: Ausgabe wird gekappt, Run bleibt gueltig.
    let (prog, args) = echo_cmd();
    let prog_s = prog.to_string_lossy().into_owned();
    let cfg = SandboxConfig {
        max_output_bytes: 5,
        ..Default::default()
    };
    with_scratch(|scratch| {
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let req = SandboxRequest {
            program: &prog_s,
            args: &arg_refs,
            scratch,
            timeout_secs: 15,
        };
        let (res, _) = run_sandboxed(&cfg, &req).expect("run");
        assert_eq!(res.exit_code, Some(0));
        assert!(res.stdout_truncated);
        assert!(res.stdout.len() <= 5);
    });
}

#[test]
fn audit_entry_is_json_serializable() {
    let (prog, args) = echo_cmd();
    let prog_s = prog.to_string_lossy().into_owned();
    let cfg = SandboxConfig::default();
    with_scratch(|scratch| {
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let req = SandboxRequest {
            program: &prog_s,
            args: &arg_refs,
            scratch,
            timeout_secs: 15,
        };
        let (_, audit) = run_sandboxed(&cfg, &req).expect("run");
        let v = audit.to_json();
        assert!(v["run_id"].as_str().is_some_and(|s| s.starts_with("sbx-")));
        assert_eq!(v["program"], prog_s);
        assert_eq!(v["timeout_secs"], 15);
    });
}
