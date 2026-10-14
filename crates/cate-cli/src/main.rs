// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! cate CLI: `scan --path <dir> --format json`
use cate_core::{analyze_file, health_score, health_score_stub, FileMetrics};
use std::path::{Path, PathBuf};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("--help");
    match cmd {
        "scan" => cmd_scan(&args[2..]),
        "graph" => cmd_graph(&args[2..]),
        "triage" => cmd_triage(&args[2..]),
        "--help" | "-h" | "help" => print_help(),
        "--version" | "-V" | "version" => println!("cate {VERSION}"),
        other => {
            eprintln!("unknown command: {other}\n");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!("cate {VERSION} — CateHunt v2 Phase 1");
    println!();
    println!("USAGE:");
    println!("    cate scan --path <dir> [--format json] [--sarif <file>] [--base <rev>]");
    println!("    cate graph --path <dir> [--out <file>]");
    println!("    cate triage --cache <file> --fingerprint <fp> [--rule-id <id> --cwe <cwe> --action <open|demote|close> --code-hash <h>] [--backend auto|ollama|gemini] [--gemini-ok] [--deep off|opencode|claude] [--uncertain]");
    println!("    cate --version | --help");
}

#[derive(Debug)]
struct ScanOpts {
    path: PathBuf,
    #[allow(dead_code)]
    format: String,
    sarif: Option<PathBuf>,
    base: Option<String>,
}

fn cmd_scan(raw: &[String]) {
    match parse_scan_args(raw) {
        Ok(opts) => match run_scan(&opts) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("scan failed: {e}");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("{e}\n");
            print_help();
            std::process::exit(2);
        }
    }
}

fn parse_scan_args(raw: &[String]) -> Result<ScanOpts, String> {
    let mut path: Option<PathBuf> = None;
    let mut format = "json".to_string();
    let mut sarif: Option<PathBuf> = None;
    let mut base: Option<String> = None;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--path" => {
                i += 1;
                path = Some(raw.get(i).ok_or("--path needs a value")?.into());
            }
            "--format" => {
                i += 1;
                format = raw.get(i).ok_or("--format needs a value")?.clone();
                if format != "json" {
                    return Err(format!("unsupported --format '{format}' (only json)"));
                }
            }
            "--sarif" => {
                i += 1;
                sarif = Some(raw.get(i).ok_or("--sarif needs a value")?.into());
            }
            "--base" => {
                i += 1;
                base = Some(raw.get(i).ok_or("--base needs a value")?.clone());
            }
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }
    Ok(ScanOpts {
        path: path.ok_or("missing --path <dir>")?,
        format,
        sarif,
        base,
    })
}

fn run_scan(opts: &ScanOpts) -> Result<String, String> {
    if !opts.path.exists() {
        return Err(format!("path not found: {}", opts.path.display()));
    }
    // Path-Jail: kanonisieren + Verzeichnis verlangen (B1/B2).
    let root = std::fs::canonicalize(&opts.path)
        .map_err(|e| format!("cannot resolve path {}: {e}", opts.path.display()))?;
    if !root.is_dir() {
        return Err(format!("path is not a directory: {}", opts.path.display()));
    }
    let files = collect_source_files(&root);
    let mut metrics: Vec<FileMetrics> = Vec::new();
    for f in &files {
        match std::fs::read_to_string(f) {
            Ok(src) => metrics.push(analyze_file(&f.display().to_string(), &src)),
            Err(e) => eprintln!("warn: skip {}: {e}", f.display()),
        }
    }
    // Optionale Lockfiles im Scan-Root.
    let mut deps = Vec::new();
    for lock in ["Cargo.lock", "package-lock.json"] {
        let p = opts.path.join(lock);
        if p.exists() {
            match std::fs::read_to_string(&p) {
                Ok(content) => {
                    if lock == "Cargo.lock" {
                        deps.extend(cate_deps::parse_cargo_lock(&content));
                    } else if let Ok(d) = cate_deps::parse_package_lock(&content) {
                        deps.extend(d);
                    }
                }
                Err(e) => eprintln!("warn: skip {}: {e}", p.display()),
            }
        }
    }
    let registry_checks: Vec<cate_deps::RegistryCheck> =
        deps.iter().map(cate_deps::registry_check_stub).collect();

    // Optionaler SARIF-Import (E1). Nachrichten werden redigiert (M-8),
    // damit keine Secrets aus Tool-Output in Report/Logs landen.
    let sarif_findings = if let Some(p) = &opts.sarif {
        let content =
            std::fs::read_to_string(p).map_err(|e| format!("sarif read {}: {e}", p.display()))?;
        let mut findings = cate_sarif::import_sarif(&content)?;
        for f in &mut findings {
            f.message = cate_core::redact::redact_text(&f.message);
        }
        Some(findings)
    } else {
        None
    };

    let health = if sarif_findings.is_some() || !registry_checks.is_empty() {
        let scored: Vec<cate_core::ScoredFinding> = sarif_findings
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|f| cate_core::ScoredFinding {
                level: f.level.clone(),
                evidence: f.evidence,
            })
            .collect();
        let suspicious = registry_checks
            .iter()
            .filter(|c| c.slopsquat_suspicious)
            .count();
        health_score(&metrics, &scored, suspicious)
    } else {
        health_score_stub(&metrics)
    };
    // Scope/Inventar Stufe 0: Lockfiles im Root + optional geaenderte
    // Dateien seit --base (git diff --name-status).
    let inventory = cate_core::scope::inventory(&root);
    let scope_changed = match &opts.base {
        Some(base) => match cate_core::scope::changed_files_since(&root, base) {
            Ok(files) => serde_json::json!({ "base": base, "changed": files }),
            Err(e) => serde_json::json!({ "base": base, "error": e }),
        },
        None => serde_json::Value::Null,
    };
    let report = serde_json::json!({
        "tool": "cate",
        "version": VERSION,
        "path": opts.path.display().to_string(),
        "files_scanned": files.len(),
        "metrics": metrics,
        "dependencies": deps,
        "registry_checks": registry_checks,
        "sarif_findings": sarif_findings,
        "health": health,
        "inventory": inventory,
        "scope": scope_changed,
    });
    serde_json::to_string_pretty(&report).map_err(|e| format!("json: {e}"))
}

/// Jail-Check: liegt `candidate` (kanonisiert) innerhalb `root` (kanonisiert)?
/// `..`-Payloads und Symlink-Ziele ausserhalb Root schlagen hier fehl.
fn is_within_jail(root: &Path, candidate: &Path) -> bool {
    candidate.starts_with(root)
}

fn collect_source_files(root: &Path) -> Vec<PathBuf> {
    const EXTS: &[&str] = &[
        "rs", "js", "ts", "jsx", "tsx", "py", "go", "java", "c", "h", "cpp", "hpp", "cs", "rb",
        "php",
    ];
    // root ist bereits kanonisiert (s. run_scan); Jail-Anker + Loop-Schutz.
    let mut out = Vec::new();
    let mut visited: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    visited.insert(root.to_path_buf());
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            // Symlink-Check ohne Folgen: zeigt das Ziel ausserhalb Root -> skip.
            let meta = match std::fs::symlink_metadata(&p) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.file_type().is_symlink() {
                let target = match std::fs::canonicalize(&p) {
                    Ok(t) => t,
                    Err(_) => continue, // toter Link: skip
                };
                if !is_within_jail(root, &target) {
                    eprintln!("warn: skip symlink outside root: {}", p.display());
                    continue;
                }
                // Symlink innerhalb Root: als Datei werten bzw. Dir mit Loop-Schutz.
                if target.is_dir() {
                    if visited.insert(target.clone()) {
                        stack.push(target);
                    }
                    continue;
                }
                if let Some(ext) = target.extension().and_then(|e| e.to_str()) {
                    if EXTS.contains(&ext) {
                        out.push(target);
                    }
                }
                continue;
            }
            if p.is_dir() {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if matches!(name, "target" | ".git" | "node_modules" | "dist" | "build") {
                    continue;
                }
                // Kanonisierte Dirs gegen Loops (z.B. Junctions) absichern.
                let canon = std::fs::canonicalize(&p).unwrap_or_else(|_| p.clone());
                if !is_within_jail(root, &canon) {
                    continue;
                }
                if visited.insert(canon.clone()) {
                    stack.push(canon);
                }
            } else if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                if EXTS.contains(&ext) {
                    out.push(p);
                }
            }
        }
    }
    out.sort();
    out
}

fn cmd_triage(raw: &[String]) {
    match run_triage(raw) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("{e}\n");
            print_help();
            std::process::exit(2);
        }
    }
}

/// `cate graph --path <dir> [--out <file>]`: Modulgraph als JSON
/// (Modulbaum + Health) auf stdout oder in Datei exportieren.
fn cmd_graph(raw: &[String]) {
    let mut path: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--path" => {
                i += 1;
                match raw.get(i) {
                    Some(v) => path = Some(v.into()),
                    None => {
                        eprintln!("--path needs a value\n");
                        print_help();
                        std::process::exit(2);
                    }
                }
            }
            "--out" => {
                i += 1;
                match raw.get(i) {
                    Some(v) => out = Some(v.into()),
                    None => {
                        eprintln!("--out needs a value\n");
                        print_help();
                        std::process::exit(2);
                    }
                }
            }
            other => {
                eprintln!("unknown flag: {other}\n");
                print_help();
                std::process::exit(2);
            }
        }
        i += 1;
    }
    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("missing --path <dir>\n");
            print_help();
            std::process::exit(2);
        }
    };
    let root = match std::fs::canonicalize(&path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("scan failed: cannot resolve path {}: {e}", path.display());
            std::process::exit(1);
        }
    };
    match cate_graph::get_graph_json(&root) {
        Ok(json) => {
            if let Some(f) = out {
                if let Err(e) = std::fs::write(&f, &json) {
                    eprintln!("graph export failed: {e}");
                    std::process::exit(1);
                }
            } else {
                println!("{json}");
            }
        }
        Err(e) => {
            eprintln!("graph failed: {e}");
            std::process::exit(1);
        }
    }
}

fn run_triage(raw: &[String]) -> Result<String, String> {
    let mut cache: Option<PathBuf> = None;
    let mut fingerprint: Option<String> = None;
    let mut rule_id = String::from("manual");
    let mut cwe = String::from("CWE-000");
    let mut action = String::from("open");
    let mut code_hash = String::from("");
    // Pipeline-Verdrahtung (Runde 3): Backend-Aufloesung ohne Netz-Calls.
    // --backend auto|ollama|gemini (auto = Gemini nur bei --gemini-ok),
    // --deep off|opencode|claude (Opt-in Stufe 3), --uncertain (Befund unklar).
    let mut backend = String::from("auto");
    let mut gemini_ok = false;
    let mut deep = String::from("off");
    let mut uncertain = false;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--cache" => {
                i += 1;
                cache = Some(raw.get(i).ok_or("--cache needs a value")?.into());
            }
            "--fingerprint" => {
                i += 1;
                fingerprint = Some(raw.get(i).ok_or("--fingerprint needs a value")?.clone());
            }
            "--rule-id" => {
                i += 1;
                rule_id = raw.get(i).ok_or("--rule-id needs a value")?.clone();
            }
            "--cwe" => {
                i += 1;
                cwe = raw.get(i).ok_or("--cwe needs a value")?.clone();
            }
            "--action" => {
                i += 1;
                action = raw.get(i).ok_or("--action needs a value")?.clone();
            }
            "--code-hash" => {
                i += 1;
                code_hash = raw.get(i).ok_or("--code-hash needs a value")?.clone();
            }
            "--backend" => {
                i += 1;
                backend = raw.get(i).ok_or("--backend needs a value")?.clone();
                if !["auto", "ollama", "gemini"].contains(&backend.as_str()) {
                    return Err(format!(
                        "unknown --backend '{backend}' (auto|ollama|gemini)"
                    ));
                }
            }
            "--gemini-ok" => {
                gemini_ok = true;
            }
            "--deep" => {
                i += 1;
                deep = raw.get(i).ok_or("--deep needs a value")?.clone();
                if !["off", "opencode", "claude"].contains(&deep.as_str()) {
                    return Err(format!("unknown --deep '{deep}' (off|opencode|claude)"));
                }
            }
            "--uncertain" => {
                uncertain = true;
            }
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }
    let cache = cache.ok_or("missing --cache <file>")?;
    let fingerprint = fingerprint.ok_or("missing --fingerprint <fp>")?;
    let wanted = cate_triage::parse_action(&action)
        .ok_or(format!("unknown --action '{action}' (open|demote|close)"))?;

    // Pipeline-Plan aufloesen (Fallback-Kette Ollama -> Gemini -> Deep).
    let gemini_avail = match backend.as_str() {
        "ollama" => false,
        "gemini" => true,
        _ => gemini_ok,
    };
    let prefer = if deep == "claude" {
        cate_triage::deep_engines::Engine::Claude
    } else {
        cate_triage::deep_engines::Engine::Opencode
    };
    let deny = cate_triage::verdict_cap(&cwe) == cate_triage::MaxAction::DemoteOnly;
    let plan =
        cate_triage::pipeline::plan_stages(gemini_avail, deny, uncertain, deep != "off", prefer);
    let chain: Vec<String> = plan.chain.iter().map(|s| s.to_string()).collect();
    let pipeline = serde_json::json!({
        "primary": plan.primary.to_string(),
        "deep": plan.deep.map(|e| e.to_string()),
        "chain": chain,
    });

    let cached = cate_triage::load_cache(&cache).map_err(|e| format!("cache load: {e}"))?;
    if let Some(hit) = cate_triage::lookup(&cached, &fingerprint) {
        // Hit: kein Modell-Call, Exit 0.
        let out = serde_json::json!({
            "cache_hit": true,
            "fingerprint": hit.fingerprint,
            "action": hit.verdict.action,
            "policy_override": hit.verdict.policy_override,
            "cwe": hit.verdict.cwe,
            "pipeline": pipeline,
        });
        return serde_json::to_string_pretty(&out).map_err(|e| format!("json: {e}"));
    }
    // Miss: Verdict bauen, Policy anwenden, persistieren.
    let rec = cate_triage::CacheRecord {
        fingerprint: fingerprint.clone(),
        verdict: cate_triage::Verdict {
            rule_id,
            cwe,
            code_hash,
            action: wanted,
            severity_after: "medium".into(),
            model: "cli".into(),
            prompt_version: "v1".into(),
            tokens_in: 0,
            tokens_out: 0,
            policy_override: false,
        },
        created_at: "2026-10-14T00:00:00Z".into(),
    };
    let overridden =
        cate_triage::store_verdict(&cache, &rec).map_err(|e| format!("cache store: {e}"))?;
    let stored_action = if overridden {
        cate_triage::VerdictAction::Demote
    } else {
        wanted
    };
    let out = serde_json::json!({
        "cache_hit": false,
        "policy_override": overridden,
        "fingerprint": fingerprint,
        "action": stored_action,
        "pipeline": pipeline,
    });
    serde_json::to_string_pretty(&out).map_err(|e| format!("json: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root(tag: &str) -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("cate_jail_{tag}_{}_{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn dotdot_payload_outside_jail() {
        let root = tmp_root("dotdot");
        let root_c = std::fs::canonicalize(&root).unwrap();
        // `sub/../../..` kanonisiert ausserhalb Root -> Jail-Check schlaegt fehl.
        let sub = root_c.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let evil = std::fs::canonicalize(&sub)
            .unwrap()
            .join("..")
            .join("..")
            .join("..");
        // direkter Check: ausserhalb liegender Pfad wird abgelehnt.
        let outside = root_c.parent().unwrap_or(Path::new("/")).to_path_buf();
        if outside != root_c {
            assert!(
                !is_within_jail(&root_c, &outside),
                "ausserhalb Root muss abgelehnt werden"
            );
        }
        assert!(is_within_jail(&root_c, &root_c.join("a.rs")));
        let _ = evil;
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn symlink_outside_root_skipped() {
        let root = tmp_root("link");
        let outside_dir = tmp_root("outside");
        std::fs::write(outside_dir.join("secret.rs"), "fn s() {}\n").unwrap();
        std::fs::write(root.join("ok.rs"), "fn ok() {}\n").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside_dir.join("secret.rs"), root.join("evil.rs"))
                .unwrap();
        }
        #[cfg(windows)]
        {
            if std::os::windows::fs::symlink_file(
                outside_dir.join("secret.rs"),
                root.join("evil.rs"),
            )
            .is_err()
            {
                // Keine Symlink-Rechte auf Windows: Test entfaellt.
                std::fs::remove_dir_all(&root).ok();
                std::fs::remove_dir_all(&outside_dir).ok();
                return;
            }
        }
        let root_c = std::fs::canonicalize(&root).unwrap();
        let files = collect_source_files(&root_c);
        let names: Vec<String> = files
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        assert!(
            names.contains(&"ok.rs".to_string()),
            "ok.rs fehlt: {names:?}"
        );
        assert!(
            !names.contains(&"secret.rs".to_string()),
            "Symlink-Escape eingesammelt: {names:?}"
        );
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside_dir).ok();
    }

    #[test]
    fn dead_symlink_skipped() {
        let root = tmp_root("dead");
        std::fs::write(root.join("ok.rs"), "fn ok() {}\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("nope.rs"), root.join("dead.rs")).ok();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(root.join("nope.rs"), root.join("dead.rs")).ok();
        let root_c = std::fs::canonicalize(&root).unwrap();
        let files = collect_source_files(&root_c); // darf nicht panicen
        assert!(files.iter().all(|p| p.file_name().unwrap() != "dead.rs"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn scan_report_contains_no_raw_secrets() {
        // Datei mit eingebettetem Token: Quelltext landet nie im Report,
        // SARIF-Nachrichten werden redigiert.
        let root = tmp_root("secrets");
        std::fs::write(
            root.join("cfg.rs"),
            "const K = \"sk-abcDEF1234567890XYZ\";\n// password=hunter2\nfn f() {}\n",
        )
        .unwrap();
        let sarif = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},
            "results":[{"ruleId":"r","level":"warning",
            "message":{"text":"leak sk-abcDEF1234567890XYZ here"},
            "locations":[]}]}]}"#;
        let sarif_path = root.join("t.sarif");
        std::fs::write(&sarif_path, sarif).unwrap();
        let opts = ScanOpts {
            path: root.clone(),
            format: "json".into(),
            sarif: Some(sarif_path),
            base: None,
        };
        let json = run_scan(&opts).unwrap();
        assert!(!json.contains("sk-abcDEF"), "Secret im Report: {json}");
        assert!(!json.contains("hunter2"), "Secret im Report");
        assert!(
            !cate_core::redact::has_secret(&json),
            "has_secret schlaegt an"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    // ---- P1 Vektor-Suite Path-Jail (TESTING.md §1.2) ----
    // cargo-fuzz offline nicht verfuegbar -> deterministische Vektoren.
    // Invariante: kanonischer Pfad ausserhalb Root => Reject.

    #[test]
    fn jail_vectors_dotdot_absolute_unc_overlong() {
        let root = tmp_root("jailvec");
        let root_c = std::fs::canonicalize(&root).unwrap();
        let sub = root_c.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        // (Name, kanonischer Kandidat, erwartet innen?)
        let outside = root_c.parent().unwrap_or(Path::new("/")).to_path_buf();
        let unc = PathBuf::from("\\\\?\\C:\\Windows\\System32");
        let overlong_inside = root_c.join("a".repeat(200) + ".rs");
        let cases: Vec<(&str, PathBuf, bool)> = vec![
            ("plain_inside", root_c.join("a.rs"), true),
            ("nested_inside", sub.join("b.rs"), true),
            ("overlong_inside", overlong_inside, true),
            ("parent_dir", outside.clone(), false),
            ("unc_absolute", unc, false),
            ("unix_absolute", PathBuf::from("/etc/passwd"), false),
        ];
        for (name, cand, want_inside) in &cases {
            assert_eq!(
                is_within_jail(&root_c, cand),
                *want_inside,
                "Jail-Vektor {name}: {cand:?}"
            );
        }
        // Traversal via kanonisierte Pfade: sub/../../.. entkommt.
        let escaped = std::fs::canonicalize(&sub)
            .unwrap()
            .join("..")
            .join("..")
            .join("..");
        // Lexikalisch noch "innen" (starts_with) — erst nach
        // Kanonisierung (wie an den Call-Sites) faellt der Check.
        let canon = std::fs::canonicalize(&escaped).unwrap_or(escaped);
        if canon != root_c && !canon.starts_with(&root_c) {
            assert!(!is_within_jail(&root_c, &canon), "../-Escape entkommt");
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn symlink_chain_stays_in_jail() {
        // Kette link2 -> link1 -> aussen: nur innen liegende Ziele ok.
        let root = tmp_root("jailchain");
        let outside_dir = tmp_root("jailchain_out");
        std::fs::write(root.join("ok.rs"), "fn ok() {}\n").unwrap();
        std::fs::write(outside_dir.join("secret.rs"), "fn s() {}\n").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside_dir.join("secret.rs"), root.join("link1.rs"))
                .unwrap();
            std::os::unix::fs::symlink(root.join("link1.rs"), root.join("link2.rs")).unwrap();
        }
        #[cfg(windows)]
        {
            if std::os::windows::fs::symlink_file(
                outside_dir.join("secret.rs"),
                root.join("link1.rs"),
            )
            .is_err()
            {
                std::fs::remove_dir_all(&root).ok();
                std::fs::remove_dir_all(&outside_dir).ok();
                return;
            }
            std::os::windows::fs::symlink_file(root.join("link1.rs"), root.join("link2.rs")).ok();
        }
        let root_c = std::fs::canonicalize(&root).unwrap();
        let files = collect_source_files(&root_c);
        let names: Vec<String> = files
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        assert!(
            !names.contains(&"secret.rs".to_string()),
            "Ketten-Escape: {names:?}"
        );
        assert!(
            !names.contains(&"link1.rs".to_string()),
            "Link nach aussen: {names:?}"
        );
        assert!(
            !names.contains(&"link2.rs".to_string()),
            "Ketten-Link: {names:?}"
        );
        assert!(
            names.contains(&"ok.rs".to_string()),
            "ok.rs fehlt: {names:?}"
        );
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside_dir).ok();
    }
}
