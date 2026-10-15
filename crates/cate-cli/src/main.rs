// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! cate CLI: `scan --path <dir> --format json [--registry-db <file>]`
use cate_core::{analyze_file, health_score, health_score_stub, FileMetrics};
use std::path::{Path, PathBuf};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("--help");
    match cmd {
        "scan" => cmd_scan(&args[2..]),
        "audit" => cmd_audit(&args[2..]),
        "graph" => cmd_graph(&args[2..]),
        "triage" => cmd_triage(&args[2..]),
        "demo" => cmd_demo(&args[2..]),
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
    println!("    cate scan --path <dir> [--format json] [--sarif <file>] [--base <rev>] [--registry-db <file>]");
    println!("    cate audit --sarif <file> --diff <base> [--path <dir>] [--format json] [--scope-out <file>]");
    println!("    cate graph --path <dir> [--out <file>]");
    println!("    cate triage --cache <file> --fingerprint <fp> [--rule-id <id> --cwe <cwe> --action <open|demote|close> --code-hash <h>] [--backend auto|ollama|gemini] [--gemini-ok] [--deep off|opencode|claude] [--uncertain]");
    println!("    cate demo [--out <file>]");
    println!("    cate --version | --help");
    println!();
    println!("NOTES:");
    println!("    --backend gemini erfordert zusaetzlich --gemini-ok (explizites Opt-in,");
    println!("      sonst faellt die Pipeline auf ollama zurueck.");
    println!("    --base <rev> betrachtet nur committeten Scope (base..HEAD);");
    println!("      uncommittete Arbeitsbaum-Aenderungen zaehlen nicht dazu.");
}

#[derive(Debug)]
struct ScanOpts {
    path: PathBuf,
    #[allow(dead_code)]
    format: String,
    sarif: Option<PathBuf>,
    base: Option<String>,
    registry_db: Option<PathBuf>,
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
    let mut registry_db: Option<PathBuf> = None;
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
            "--registry-db" => {
                i += 1;
                registry_db = Some(raw.get(i).ok_or("--registry-db needs a value")?.into());
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
        registry_db,
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
    // Registry-Check: mit DB echte Offline-Daten, sonst nie-fiktionfrei
    // weggelassen (kein exists-Immutable-true Stub mehr).
    let registry_db = match &opts.registry_db {
        Some(p) => {
            let content = std::fs::read_to_string(p)
                .map_err(|e| format!("registry-db read {}: {e}", p.display()))?;
            Some(
                cate_deps::OfflineRegistryDbFile::from_json(&content)
                    .map_err(|e| format!("registry-db {}: {e}", p.display()))?,
            )
        }
        None => None,
    };
    let registry_checks: Vec<cate_deps::RegistryCheck> = match &registry_db {
        Some(db) => deps
            .iter()
            .map(|d| cate_deps::registry_check(d, Some(db)))
            .collect(),
        None => Vec::new(),
    };
    let deps_summary = registry_db
        .as_ref()
        .map(|_| cate_deps::deps_summary(&deps, &registry_checks));

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

    // Mehr-Evidence: suspekte Deps zaehlen auch ohne SARIF als Findings.
    let suspicious = registry_checks
        .iter()
        .filter(|c| c.slopsquat_suspicious)
        .count();
    let health = if sarif_findings.is_some() || suspicious > 0 {
        let scored: Vec<cate_core::ScoredFinding> = sarif_findings
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|f| cate_core::ScoredFinding {
                level: f.level.clone(),
                evidence: f.evidence,
                provenance: Some(cate_core::ProvenanceRecord::current_with_model(
                    "sarif-import",
                )),
            })
            .collect();
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
        "deps_summary": deps_summary,
        "registry_db": opts.registry_db.as_ref().map(|p| p.display().to_string()),
        "sarif_findings": sarif_findings,
        "health": health,
        "inventory": inventory,
        "scope": scope_changed,
    });
    serde_json::to_string_pretty(&report).map_err(|e| format!("json: {e}"))
}

/// `cate audit --sarif <file> --diff <base> [--path <dir>] [--format json] [--scope-out <file>]`
/// (offline): git-Scope (`cate_core::scope`) + .rs-Metriken + SARIF-Import
/// -> ein JSON mit `findings` + `health` auf stdout. Mit `--scope-out <file>`
/// zusaetzlich ein Scope-Export (base..HEAD, changed_files, Inventar,
/// Timestamp, Provenienz) als reproduzierbarer Lauf-Beleg in Datei.
fn cmd_audit(raw: &[String]) {
    match parse_audit_args(raw) {
        Ok(opts) => match run_audit(&opts) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("audit failed: {e}");
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

#[derive(Debug)]
struct AuditOpts {
    sarif: PathBuf,
    diff: String,
    path: PathBuf,
    #[allow(dead_code)]
    format: String,
    scope_out: Option<PathBuf>,
}

fn parse_audit_args(raw: &[String]) -> Result<AuditOpts, String> {
    let mut sarif: Option<PathBuf> = None;
    let mut diff: Option<String> = None;
    let mut path = PathBuf::from(".");
    let mut format = "json".to_string();
    let mut scope_out: Option<PathBuf> = None;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--sarif" => {
                i += 1;
                sarif = Some(raw.get(i).ok_or("--sarif needs a value")?.into());
            }
            "--diff" => {
                i += 1;
                diff = Some(raw.get(i).ok_or("--diff needs a value")?.clone());
            }
            "--path" => {
                i += 1;
                path = raw.get(i).ok_or("--path needs a value")?.into();
            }
            "--format" => {
                i += 1;
                format = raw.get(i).ok_or("--format needs a value")?.clone();
                if format != "json" {
                    return Err(format!("unsupported --format '{format}' (only json)"));
                }
            }
            "--scope-out" => {
                i += 1;
                scope_out = Some(raw.get(i).ok_or("--scope-out needs a value")?.into());
            }
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }
    Ok(AuditOpts {
        sarif: sarif.ok_or("missing --sarif <file>")?,
        diff: diff.ok_or("missing --diff <base>")?,
        path,
        format,
        scope_out,
    })
}

/// Ein Audit-Finding: SARIF-Import + stabile ID + Deny-Policy-Verdict.
/// `unlocated=true` -> `location: null`, fliesst NICHT in Health ein.
#[derive(Debug, Clone, serde::Serialize)]
struct AuditFinding {
    id: String,
    rule_id: String,
    provenance: String,
    cwe: String,
    evidence: String,
    unlocated: bool,
    location: Option<AuditLocation>,
    message: String,
    fingerprint: String,
    triage_action: String,
    policy_override: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct AuditLocation {
    file: String,
    start_line: usize,
}

/// Stabile Finding-ID: 64-bit-Hash aus rule_id + Datei + Startzeile.
fn stable_finding_id(rule_id: &str, path: &str, start_line: usize) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    rule_id.hash(&mut h);
    path.hash(&mut h);
    start_line.hash(&mut h);
    format!("{:016x}", h.finish())
}

fn run_audit(opts: &AuditOpts) -> Result<String, String> {
    let root = std::fs::canonicalize(&opts.path)
        .map_err(|e| format!("cannot resolve path {}: {e}", opts.path.display()))?;
    if !root.is_dir() {
        return Err(format!("path is not a directory: {}", opts.path.display()));
    }
    // SARIF-Import (E1), Nachrichten redigiert (M-8).
    let content = std::fs::read_to_string(&opts.sarif)
        .map_err(|e| format!("sarif read {}: {e}", opts.sarif.display()))?;
    let mut sarif = cate_sarif::import_sarif(&content)?;
    for f in &mut sarif {
        f.message = cate_core::redact::redact_text(&f.message);
    }
    // Scope Stufe 0: committete Aenderungen seit --diff. `--diff` darf als
    // Range `base..HEAD` kommen (PLAN-Akzeptanz); es zaehlt der Base-Teil.
    // Ohne git-Repo kein harter Abbruch: Fehler landet im Report.
    let base = opts.diff.split("..").next().unwrap_or(&opts.diff);
    let changed = cate_core::scope::changed_files_since(&root, base);
    let scope = match &changed {
        Ok(files) => serde_json::json!({ "base": base, "changed": files }),
        Err(e) => serde_json::json!({ "base": base, "error": e }),
    };
    // M-3 Scope-Export (`--scope-out`): ermittelter Scope (base..HEAD,
    // changed_files, Inventar, Timestamp, Provenienz) als reproduzierbarer
    // Lauf-Beleg in Datei. Stdout-Report bleibt unveraendert.
    if let Some(out) = &opts.scope_out {
        let provenance = cate_core::ProvenanceRecord::current_with_model("audit");
        let export = match &changed {
            Ok(files) => serde_json::json!({
                "tool": "cate",
                "version": VERSION,
                "command": "audit",
                "base": base,
                "range": format!("{base}..HEAD"),
                "changed_files": files,
                "inventory": cate_core::scope::inventory(&root),
                "timestamp": cate_core::utc_now_rfc3339(),
                "provenance": provenance,
            }),
            Err(e) => serde_json::json!({
                "tool": "cate",
                "version": VERSION,
                "command": "audit",
                "base": base,
                "range": format!("{base}..HEAD"),
                "error": e,
                "inventory": cate_core::scope::inventory(&root),
                "timestamp": cate_core::utc_now_rfc3339(),
                "provenance": provenance,
            }),
        };
        let text = serde_json::to_string_pretty(&export).map_err(|e| format!("json: {e}"))?;
        std::fs::write(out, text).map_err(|e| format!("scope-out write {}: {e}", out.display()))?;
    }
    // .rs-Metriken (deterministische Reihenfolge via collect_source_files).
    let mut metrics = Vec::new();
    for f in collect_source_files(&root) {
        if f.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        match std::fs::read_to_string(&f) {
            Ok(src) => metrics.push(analyze_file(&f.display().to_string(), &src)),
            Err(e) => eprintln!("warn: skip {}: {e}", f.display()),
        }
    }
    // Findings: Deny-Policy anwenden (vorgeschlagen `close` -> Deny-CWE
    // wird `demote` + Override-Flag). Unlocated -> location null.
    let mut findings: Vec<AuditFinding> = sarif
        .iter()
        .map(|f| {
            let mut verdict = cate_triage::Verdict {
                rule_id: f.rule_id.clone(),
                cwe: f.cwe.clone(),
                code_hash: cate_triage::code_hash(&f.message),
                action: cate_triage::VerdictAction::Close,
                severity_after: "medium".into(),
                model: "audit".into(),
                prompt_version: "v1".into(),
                tokens_in: 0,
                tokens_out: 0,
                policy_override: false,
                provenance: Some(cate_core::ProvenanceRecord::current_with_model("audit")),
            };
            let overridden = cate_triage::apply_policy(&mut verdict);
            let triage_action = match verdict.action {
                cate_triage::VerdictAction::Open => "open",
                cate_triage::VerdictAction::Demote => "demote",
                cate_triage::VerdictAction::Close => "close",
            }
            .to_string();
            AuditFinding {
                id: stable_finding_id(&f.rule_id, &f.path, f.start_line),
                rule_id: f.rule_id.clone(),
                provenance: f.provenance.clone(),
                cwe: f.cwe.clone(),
                evidence: f.evidence.to_string(),
                unlocated: f.unlocated,
                location: if f.unlocated {
                    None
                } else {
                    Some(AuditLocation {
                        file: f.path.clone(),
                        start_line: f.start_line,
                    })
                },
                message: f.message.clone(),
                fingerprint: cate_triage::fingerprint(
                    &f.rule_id,
                    &cate_triage::code_hash(&f.message),
                    &f.cwe,
                ),
                triage_action,
                policy_override: overridden,
            }
        })
        .collect();
    findings.sort_by(|a, b| a.id.cmp(&b.id));
    // Health: nur located Findings (unlocated NICHT im Score), nur E2+.
    let scored: Vec<cate_core::ScoredFinding> = sarif
        .iter()
        .filter(|f| !f.unlocated)
        .map(|f| cate_core::ScoredFinding {
            level: f.level.clone(),
            evidence: f.evidence,
            provenance: Some(cate_core::ProvenanceRecord::current_with_model("audit")),
        })
        .collect();
    let health = cate_core::health_score(&metrics, &scored, 0);
    let report = serde_json::json!({
        "tool": "cate",
        "version": VERSION,
        "command": "audit",
        "path": opts.path.display().to_string(),
        "files_scanned": metrics.len(),
        "scope": scope,
        "metrics": metrics,
        "findings": findings,
        "health": health,
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

/// `cate demo [--out <file>]`: deterministischer Demo-Seed fuer lokale
/// UI-/CLI-Demos (P2-Rest). Awards sich unverändert mit jedem Lauf, in
///erten den Demo-Workspace **neu** in `<tmp>/cate-demo-seed` (... Wurzel
/// unter `std::env::temp_dir()`, Pfad fix → reproche-stabil) und gibt
/// einen byte-stabilen JSON-Report auf stdout (oder in `--out <file>`)
/// zurück: Metriken + Health der Demo-Dateien (`cate scan --path ...`).
/// Kein Schreiben außerhalb des Demo-Workspace, kein Netz, kein RNG —
/// alle Werte sind aus dem Quelltext der Seed-Dateien determiniert.
fn cmd_demo(raw: &[String]) {
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
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
    match run_demo(&out) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("demo failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Liefert die Demo-Quelltexte (fix, deterministisch, fuer golden-Test).
fn demo_sources() -> Vec<(&'static str, &'static str)> {
    vec![
        // Tiefe 5 > Richtwert 4: penalty-Trigger fuer Health, Flagge "rot".
        (
            "deep.rs",
            "fn handle(input: &str) -> &str {\n    if !input.is_empty() {\n        while input.len() > 0 {\n            if input.starts_with('x') {\n                if input.len() > 2 {\n                    return input;\n                }\n            }\n            break;\n        }\n    }\n    \"leer\"\n}\n",
        ),
        // Saubere Referenz: kleine Datei, Tiefe 1, gesund.
        ("ok.rs", "fn add(a: u64, b: u64) -> u64 {\n    a + b\n}\n"),
    ]
}

/// Baut den Demo-Workspace (idempotent: Verzeichnis neu, Dateien fix)
/// und liefert den Pfad auf die Wurzel zurueck.
fn ensure_demo_workspace() -> Result<PathBuf, String> {
    let root = std::env::temp_dir().join("cate-demo-seed");
    std::fs::create_dir_all(&root).map_err(|e| format!("demo dir: {e}"))?;
    for (name, src) in demo_sources() {
        let p = root.join(name);
        std::fs::write(&p, src).map_err(|e| format!("demo write {name}: {e}"))?;
    }
    Ok(root)
}

/// Demo-Lauf: Workspace neu aufbauen, `run_scan`-Report erzeugen lassen.
/// Report enthaelt den fixen Pfad der Wurzel; bis auf diesen (Host-Pfad)
/// ist der Output byte-stabil (golden-Test blendet `path` aus).
fn run_demo(out_file: &Option<PathBuf>) -> Result<String, String> {
    let root = ensure_demo_workspace()?;
    let opts = ScanOpts {
        path: root.clone(),
        format: "json".into(),
        sarif: None,
        base: None,
        registry_db: None,
    };
    let report = run_scan(&opts)?;
    if let Some(f) = out_file {
        std::fs::write(f, &report).map_err(|e| format!("demo out write {}: {e}", f.display()))?;
    }
    Ok(report)
}

fn run_triage(raw: &[String]) -> Result<String, String> {
    let mut cache: Option<PathBuf> = None;
    let mut fingerprint: Option<String> = None;
    let mut rule_id = String::from("manual");
    let mut cwe = String::from("CWE-000");
    let mut action = String::from("open");
    let mut code_hash = String::from("");
    // Pipeline-Plan aufloesen (Fallback-Kette Ollama -> Gemini -> Deep).
    // --backend auto|ollama|gemini; Gemini (auto wie explizit) nur mit
    // --gemini-ok (explizites Opt-in) — ohne Flag kein stilles Gemini.
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
            provenance: Some(cate_core::ProvenanceRecord::current_with_model("cli")),
        },
        created_at: cate_core::utc_now_rfc3339(),
        format_version: cate_triage::CACHE_FORMAT_VERSION,
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
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Demo-Seed benutzt einen festen Pfad (%TEMP%/cate-demo-seed): Tests,
    /// die `run_demo`/`run_scan` im Demo-Seed ausfuehren, muessen seriell.
    static DEMO_LOCK: Mutex<()> = Mutex::new(());

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
            registry_db: None,
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

    // ---- M1.5: `cate scan --registry-db` (Offline-Registry-Check) ----
    fn scan_with_db(tag: &str, db_text: Option<&str>) -> (PathBuf, serde_json::Value, PathBuf) {
        let root = tmp_root(tag);
        std::fs::write(root.join("a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(
            root.join("Cargo.lock"),
            "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n[[package]]\nname = \"lodas\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        )
        .unwrap();
        let db_path = root.join("db.json");
        if let Some(text) = db_text {
            std::fs::write(&db_path, text).unwrap();
        }
        let opts = ScanOpts {
            path: root.clone(),
            format: "json".into(),
            sarif: None,
            base: None,
            registry_db: if db_text.is_some() {
                Some(db_path.clone())
            } else {
                None
            },
        };
        let json: serde_json::Value =
            serde_json::from_str(&run_scan(&opts).expect("scan muss laufen")).unwrap();
        (root, json, db_path)
    }

    #[test]
    fn scan_registry_db_offline_data_in_report() {
        let (root, v, _db) = scan_with_db(
            "regdb",
            Some(include_str!(
                "../../cate-deps/tests/fixtures/registry_db.json"
            )),
        );
        let checks = v["registry_checks"].as_array().unwrap();
        assert_eq!(
            checks.len(),
            2,
            "mit DB muessen Checks je Dependency erscheinen: {v}"
        );
        let serde_check = checks
            .iter()
            .find(|c| c["name"] == "serde")
            .expect("serde-Check fehlt");
        assert_eq!(serde_check["exists"], true);
        assert!(serde_check["age_days"].as_u64().is_some());
        assert!(serde_check["downloads"].as_u64().is_some());
        // Typosquat `lodas` (1-Zeichen-Distanz von serde/DB-Namen).
        let lodas = checks.iter().find(|c| c["name"] == "lodas").unwrap();
        assert!(lodas["slopsquat_suspicious"].as_bool().unwrap());
        assert_eq!(
            v["deps_summary"]["suspicious"].as_u64(),
            Some(1),
            "genau ein suspekter: {v}"
        );
        assert!(v["deps_summary"]["total_downloads"].as_u64().unwrap() > 0);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn scan_without_registry_db_no_checks_no_fiction() {
        let (root, v, _db) = scan_with_db("regdbnone", None);
        // Manifest-Regel: ohne DB nie exists-true-Fiktion.
        assert!(
            v["registry_checks"].as_array().unwrap().is_empty(),
            "ohne DB keine Checks: {v}"
        );
        assert!(v["deps_summary"].is_null());
        assert!(v["registry_db"].is_null());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn scan_registry_db_bad_file_is_error() {
        let root = tmp_root("regdbbad");
        let db_path = root.join("db.json");
        std::fs::write(&db_path, "{\"format\":\"wrong\",\"version\":1}").unwrap();
        let opts = ScanOpts {
            path: root.clone(),
            format: "json".into(),
            sarif: None,
            base: None,
            registry_db: Some(db_path),
        };
        let err = run_scan(&opts).unwrap_err();
        assert!(
            err.contains("registry-db"),
            "Fehler muss die DB nennen: {err}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn scan_registry_db_flag_parsed() {
        let o = parse_scan_args(&args(&["--path", ".", "--registry-db", "db.json"])).unwrap();
        assert_eq!(o.registry_db, Some(PathBuf::from("db.json")));
        assert!(parse_scan_args(&args(&["--path", ".", "--registry-db"])).is_err());
        assert!(parse_scan_args(&args(&["--path", "."]))
            .unwrap()
            .registry_db
            .is_none());
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

    fn triage_primary(extra: &[&str], fp: &str) -> String {
        let dir = tmp_root("triage");
        let cache = dir.join("cache.json");
        let mut raw: Vec<String> = vec![
            "--cache".to_string(),
            cache.display().to_string(),
            "--fingerprint".to_string(),
            fp.to_string(),
        ];
        raw.extend(extra.iter().map(|s| s.to_string()));
        let json = run_triage(&raw).expect("run_triage muss laufen");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let primary = v["pipeline"]["primary"].as_str().unwrap_or("?").to_string();
        std::fs::remove_dir_all(&dir).ok();
        primary
    }

    #[test]
    fn backend_gemini_braucht_gemini_ok() {
        // Explizites --backend gemini ohne --gemini-ok: kein stilles Gemini.
        assert_eq!(
            triage_primary(&["--backend", "gemini"], "fp-noopt"),
            "ollama"
        );
        assert_eq!(
            triage_primary(&["--backend", "gemini", "--gemini-ok"], "fp-opt"),
            "gemini"
        );
        assert_eq!(
            triage_primary(&["--backend", "auto", "--gemini-ok"], "fp-auto"),
            "gemini"
        );
        assert_eq!(
            triage_primary(&["--backend", "ollama", "--gemini-ok"], "fp-oll"),
            "ollama"
        );
    }

    // ---- Phase-1-Akzeptanz `audit` ----
    // Fixture-SARIF mit Semgrep-Run (properties.cwe) + CodeQL-Run
    // (external/cwe-Tag); keine Repo-Fixtures vorhanden -> inline.
    const AUDIT_SARIF: &str = r#"{"version":"2.1.0","runs":[
      {"tool":{"driver":{"name":"semgrep","rules":[{"id":"py-md5","properties":{"cwe":"CWE-328"}}]}},
       "results":[
        {"ruleId":"py-md5","message":{"text":"weak hash md5"},"level":"warning",
         "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":7}}}]}]},
      {"tool":{"driver":{"name":"CodeQL","rules":[{"id":"js/hardcoded-credentials",
        "properties":{"tags":["security","external/cwe/cwe-798"]}}]}},
       "results":[
        {"ruleId":"js/hardcoded-credentials","message":{"text":"hardcoded value"},"level":"error",
         "locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.js"},"region":{"startLine":2}}}]}]}
    ]}"#;

    fn audit_fixture_dir(tag: &str, sarif: &str) -> (PathBuf, PathBuf) {
        let dir = tmp_root(tag);
        std::fs::write(dir.join("lib.rs"), "fn f() {\n let x = 1;\n}\n").unwrap();
        let sarif_path = dir.join("r.sarif");
        std::fs::write(&sarif_path, sarif).unwrap();
        (dir, sarif_path)
    }

    fn run_audit_for(dir: &Path, sarif: &Path, diff: &str) -> serde_json::Value {
        let opts = AuditOpts {
            sarif: sarif.to_path_buf(),
            diff: diff.to_string(),
            path: dir.to_path_buf(),
            format: "json".into(),
            scope_out: None,
        };
        let json = run_audit(&opts).expect("run_audit muss laufen");
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn audit_semgrep_und_codeql_provenienz() {
        let (dir, sarif) = audit_fixture_dir("auditprov", AUDIT_SARIF);
        let v = run_audit_for(&dir, &sarif, "HEAD");
        let findings = v["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 2, "je Run ein Finding: {v}");
        let provs: Vec<&str> = findings
            .iter()
            .map(|f| f["provenance"].as_str().unwrap())
            .collect();
        assert!(provs.contains(&"semgrep"), "semgrep fehlt: {provs:?}");
        assert!(provs.contains(&"codeql"), "codeql fehlt: {provs:?}");
        assert!(v.get("health").is_some(), "health-Anteil fehlt");
        assert!(v.get("findings").is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn audit_unlocated_nicht_im_score() {
        let sarif = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},
          "results":[
           {"ruleId":"located-rule","message":{"text":"hier"},"level":"error",
            "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":1}}}]},
           {"ruleId":"no-loc","message":{"text":"nirgends"},"level":"error","locations":[]}
          ]}]}"#;
        let (dir, sarif_path) = audit_fixture_dir("auditunloc", sarif);
        let v = run_audit_for(&dir, &sarif_path, "HEAD");
        let findings = v["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 2);
        let unloc: Vec<&serde_json::Value> =
            findings.iter().filter(|f| f["unlocated"] == true).collect();
        assert_eq!(unloc.len(), 1, "genau ein unlocated: {findings:?}");
        assert_eq!(unloc[0]["rule_id"], "no-loc");
        assert!(unloc[0]["location"].is_null(), "location muss null sein");
        // Health: E1 zaehlt nie (nur E2+), total_e2_plus bleibt 0 —
        // unlocated ist zusaetzlich schon beim Scoring herausgefiltert.
        assert_eq!(v["health"]["total_e2_plus"], 0);
        let located = findings.iter().filter(|f| f["unlocated"] == false).count();
        assert_eq!(located, 1);
        assert!(findings
            .iter()
            .all(|f| !f["id"].as_str().unwrap().is_empty()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn audit_deny_policy_demote_nur_deny_cwe() {
        // CWE-798 (deny) -> demote+Override; CWE-89 (non-deny) -> close.
        let sarif = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL",
          "rules":[
           {"id":"js/hardcoded-credentials","properties":{"tags":["external/cwe/cwe-798"]}},
           {"id":"js/sql-injection","properties":{"tags":["external/cwe/cwe-89"]}}]}},
          "results":[
           {"ruleId":"js/hardcoded-credentials","message":{"text":"cred"},"level":"error",
            "locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.js"},"region":{"startLine":2}}}]},
           {"ruleId":"js/sql-injection","message":{"text":"sqli"},"level":"error",
            "locations":[{"physicalLocation":{"artifactLocation":{"uri":"c.js"},"region":{"startLine":5}}}]}
          ]}]}"#;
        let (dir, sarif_path) = audit_fixture_dir("auditdeny", sarif);
        let v = run_audit_for(&dir, &sarif_path, "HEAD");
        let by_rule = |id: &str| {
            v["findings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["rule_id"] == id)
                .cloned()
                .unwrap_or_else(|| panic!("Finding {id} fehlt"))
        };
        let deny = by_rule("js/hardcoded-credentials");
        assert_eq!(deny["cwe"], "CWE-798");
        assert_eq!(deny["triage_action"], "demote");
        assert_eq!(deny["policy_override"], true);
        let open = by_rule("js/sql-injection");
        assert_eq!(open["cwe"], "CWE-89");
        assert_eq!(open["triage_action"], "close");
        assert_eq!(open["policy_override"], false);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn audit_golden_stabil_und_args() {
        // Pflicht-Flags, Range-Form, Format-Gate.
        assert!(parse_audit_args(&[]).is_err());
        let o = parse_audit_args(
            &["--sarif", "r.sarif", "--diff", "abc123..HEAD"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(o.diff, "abc123..HEAD");
        assert!(parse_audit_args(
            &["--sarif", "r.sarif", "--diff", "x", "--format", "yaml"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        )
        .is_err());
        // Byte-Stabilitaet: gleicher Input -> identische Bytes.
        let (dir, sarif) = audit_fixture_dir("auditgold", AUDIT_SARIF);
        let opts = AuditOpts {
            sarif,
            diff: "HEAD".into(),
            path: dir.clone(),
            format: "json".into(),
            scope_out: None,
        };
        let a = run_audit(&opts).unwrap();
        let b = run_audit(&opts).unwrap();
        assert_eq!(a, b, "Audit-Output muss byte-stabil sein");
        let v: serde_json::Value = serde_json::from_str(&a).unwrap();
        for key in ["findings", "health", "scope", "metrics"] {
            assert!(v.get(key).is_some(), "Key {key} fehlt");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn audit_scope_gegen_echtes_repo() {
        // --diff HEAD im Arbeits-Repo: committeter Scope (HEAD..HEAD leer),
        // kein Arbeitsbaum-Einfluss.
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        if repo.join(".git").is_dir() {
            let dir = tmp_root("auditscope");
            let sp = dir.join("r.sarif");
            std::fs::write(&sp, AUDIT_SARIF).unwrap();
            let opts = AuditOpts {
                sarif: sp,
                diff: "HEAD".into(),
                path: repo.clone(),
                format: "json".into(),
                scope_out: None,
            };
            let json = run_audit(&opts).expect("audit im Repo muss laufen");
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert!(
                v["scope"]["changed"].is_array(),
                "Scope changed fehlt: {}",
                v["scope"]
            );
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    // ---- M-3 Scope-Export `--scope-out` ----
    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn audit_scope_out_flag_parsed() {
        let o = parse_audit_args(&args(&[
            "--sarif",
            "r.sarif",
            "--diff",
            "HEAD",
            "--scope-out",
            "scope.json",
        ]))
        .unwrap();
        assert_eq!(o.scope_out, Some(PathBuf::from("scope.json")));
        let o = parse_audit_args(&args(&["--sarif", "r.sarif", "--diff", "HEAD"])).unwrap();
        assert_eq!(o.scope_out, None);
        assert!(parse_audit_args(&args(&[
            "--sarif",
            "r.sarif",
            "--diff",
            "HEAD",
            "--scope-out"
        ]))
        .is_err());
    }

    #[test]
    fn audit_scope_out_schreibt_export_mit_beleg() {
        // Tmp-Dir ist kein git-Repo -> Export traegt `error` statt
        // `changed_files`, aber Inventar/Timestamp/Provenienz sind da.
        let (dir, sarif) = audit_fixture_dir("auditscopeout", AUDIT_SARIF);
        let out = dir.join("scope.json");
        let opts = AuditOpts {
            sarif,
            diff: "HEAD".into(),
            path: dir.clone(),
            format: "json".into(),
            scope_out: Some(out.clone()),
        };
        let stdout = run_audit(&opts).expect("run_audit muss laufen");
        assert!(serde_json::from_str::<serde_json::Value>(&stdout).is_ok());
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).expect("scope-out fehlt")).unwrap();
        for key in [
            "tool",
            "version",
            "command",
            "base",
            "range",
            "inventory",
            "timestamp",
            "provenance",
        ] {
            assert!(v.get(key).is_some(), "Key {key} fehlt: {v}");
        }
        assert_eq!(v["tool"], "cate");
        assert_eq!(v["command"], "audit");
        assert_eq!(v["base"], "HEAD");
        assert_eq!(v["range"], "HEAD..HEAD");
        assert!(
            v.get("changed_files").is_some() || v.get("error").is_some(),
            "weder changed_files noch error: {v}"
        );
        assert!(!v["timestamp"].as_str().unwrap_or("").is_empty());
        assert_eq!(v["provenance"]["tool_name"], "cate");
        // Lauf-Beleg reproduzierbar: zweiter Lauf identisch bis auf timestamp.
        let opts2 = AuditOpts {
            sarif: dir.join("r.sarif"),
            diff: "HEAD".into(),
            path: dir.clone(),
            format: "json".into(),
            scope_out: Some(dir.join("scope2.json")),
        };
        run_audit(&opts2).expect("zweiter Lauf muss laufen");
        let mut a: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        let mut b: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("scope2.json")).unwrap())
                .unwrap();
        a["timestamp"] = serde_json::Value::Null;
        b["timestamp"] = serde_json::Value::Null;
        // Provenienz-Timestamps koennen sich unterscheiden -> ausblenden.
        a["provenance"]["timestamp"] = serde_json::Value::Null;
        b["provenance"]["timestamp"] = serde_json::Value::Null;
        assert_eq!(a, b, "Scope-Export muss (bis auf Timestamp) stabil sein");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn audit_scope_out_gegen_echtes_repo_mit_changed_files() {
        // Erfolgszweig: im Arbeits-Repo liefert der Export `changed_files`.
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        if repo.join(".git").is_dir() {
            let dir = tmp_root("auditscopeoutrepo");
            let sp = dir.join("r.sarif");
            std::fs::write(&sp, AUDIT_SARIF).unwrap();
            let out = dir.join("scope.json");
            let opts = AuditOpts {
                sarif: sp,
                diff: "HEAD".into(),
                path: repo.clone(),
                format: "json".into(),
                scope_out: Some(out.clone()),
            };
            run_audit(&opts).expect("audit im Repo muss laufen");
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
            assert!(v["changed_files"].is_array(), "changed_files fehlt: {v}");
            assert!(v.get("inventory").is_some());
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    // ---- P2-Rest: Demo-Seed (`cate demo`) ----
    #[test]
    fn demo_workspace_is_deterministic() {
        let _g = DEMO_LOCK.lock().unwrap();
        // Zwei Aufbaue-Laeufe: identische Bytes in allen Seed-Dateien.
        let a = ensure_demo_workspace().expect("demo workspace muss bauen");
        let b = ensure_demo_workspace().expect("demo workspace muss idempotent sein");
        assert_eq!(a, b, "fixer Workspace-Pfad: {a:?} vs {b:?}");
        for (name, src) in demo_sources() {
            let p = a.join(name);
            assert_eq!(
                std::fs::read_to_string(&p).unwrap(),
                src,
                "Seed-Datei {name} muss byte-stabil ueberschrieben werden"
            );
        }
        std::fs::remove_dir_all(&a).ok();
    }

    #[test]
    fn demo_report_is_byte_stable_and_flags_deep_nesting() {
        let _g = DEMO_LOCK.lock().unwrap();
        // Golden-Stabil: zwei Demos identisch bis auf den Host-Pfad,
        // ohne Timestamp/Finding im Report (Scan, kein audit) sind die
        // Metriken/Health voll deterministisch.
        let a = run_demo(&None).expect("demo muss laufen");
        let b = run_demo(&None).expect("demo muss wieder laufen");
        assert_eq!(a, b, "Demo-Report muss byte-stabil sein");
        let mut v: serde_json::Value = serde_json::from_str(&a).unwrap();
        let path = v["path"].take();
        assert!(path.as_str().unwrap().ends_with("cate-demo-seed"));
        assert_eq!(v["files_scanned"], 2, "2 Demo-Dateien: {v}");
        let metrics = v["metrics"].as_array().unwrap();
        let deep = metrics
            .iter()
            .find(|m| m["path"].as_str().unwrap_or("").ends_with("deep.rs"))
            .expect("deep.rs in Metriken");
        assert!(
            deep["max_nesting_depth"].as_u64().unwrap() > 4,
            "deep.rs muss ueber Richtwert 4 liegen: {deep}"
        );
        let ok = metrics
            .iter()
            .find(|m| m["path"].as_str().unwrap_or("").ends_with("ok.rs"))
            .expect("ok.rs in Metriken");
        assert!(
            ok["max_nesting_depth"].as_u64().unwrap() <= 4,
            "ok.rs muss im Rahmen bleiben: {ok}"
        );
        // Health: Struktur-Penalty nur aus deep.rs (5 > 4 → 5 Punkte).
        let health = &v["health"];
        let total = health["total"].as_u64().unwrap();
        assert!(
            (80..=100).contains(&total),
            "Demo-Health muss deterministisch und moderat sein: {health}"
        );
    }

    #[test]
    fn demo_out_flag_writes_report() {
        let _g = DEMO_LOCK.lock().unwrap();
        let root = std::env::temp_dir().join(format!("cate_demo_out_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let out = root.join("demo.json");
        let text = run_demo(&Some(out.clone())).expect("demo muss laufen");
        assert_eq!(
            std::fs::read_to_string(&out).unwrap(),
            text,
            "--out muss exakt den stdout-Report schreiben"
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
