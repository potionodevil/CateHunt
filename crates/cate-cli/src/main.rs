//! cate CLI: `scan --path <dir> --format json`
use cate_core::{analyze_file, health_score_stub, FileMetrics};
use std::path::{Path, PathBuf};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("--help");
    match cmd {
        "scan" => cmd_scan(&args[2..]),
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
    println!("    cate scan --path <dir> [--format json] [--sarif <file>]");
    println!("    cate --version | --help");
}

#[derive(Debug)]
struct ScanOpts {
    path: PathBuf,
    #[allow(dead_code)]
    format: String,
    sarif: Option<PathBuf>,
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
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }
    Ok(ScanOpts {
        path: path.ok_or("missing --path <dir>")?,
        format,
        sarif,
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

    // Optionaler SARIF-Import (E1).
    let sarif_findings = if let Some(p) = &opts.sarif {
        let content =
            std::fs::read_to_string(p).map_err(|e| format!("sarif read {}: {e}", p.display()))?;
        Some(cate_sarif::import_sarif(&content)?)
    } else {
        None
    };

    let health = health_score_stub(&metrics);
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
    });
    serde_json::to_string_pretty(&report).map_err(|e| format!("json: {e}"))
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
                if !target.starts_with(root) {
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
                if !canon.starts_with(root) {
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
