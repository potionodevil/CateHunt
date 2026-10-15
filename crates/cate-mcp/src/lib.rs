// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! cate-mcp: JSON-RPC-Server ueber stdio (kein Netz).
//! Tools: `audit_diff`, `get_graph`, `explain_nesting`, `apply_proposal`,
//! `verify_fix` (sandbox-gated, ohne Sandbox immer NO_SANDBOX),
//! `check_dependencies` (offline Advisory-DB, kein Netz), `ping`.
use cate_core::{analyze_file, scan_functions};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

/// Fehler mit Spec-Code (INVALID_PARAMS, INVALID_PATH, NOT_FOUND,
/// APPROVAL_REQUIRED, INTERNAL).
#[derive(Debug)]
pub struct ToolError {
    pub code: &'static str,
    pub message: String,
}

impl ToolError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Pfad-Jail: absolut oder `..`-Escape → Err. Gibt den Relativpfad zurueck.
pub fn jail_rel(raw: &str) -> Result<String, ToolError> {
    let t = raw.replace('\\', "/");
    if t.is_empty() {
        return Err(ToolError::new(
            "INVALID_PARAMS",
            "Pfad darf nicht leer sein",
        ));
    }
    let p = Path::new(&t);
    if p.is_absolute()
        || t.split('/').any(|s| s == "..")
        || t.starts_with("~/")
        || (t.len() > 1 && t.chars().nth(1) == Some(':'))
    {
        return Err(ToolError::new(
            "INVALID_PATH",
            format!("Pfad ausserhalb Scan-Root: {raw}"),
        ));
    }
    Ok(t)
}

/// Audit-Log-Eintrag (append-only).
#[derive(Debug, Clone)]
pub struct McpAuditEntry {
    pub audit_log_id: String,
    pub proposal_id: String,
    pub approved_by: Option<String>,
    pub applied: bool,
}

/// Proposal-Registry + Audit-Log (In-Memory; Server haelt eine Instanz).
#[derive(Debug, Default)]
pub struct ProposalStore {
    approved: HashMap<String, bool>,
    audit: Vec<McpAuditEntry>,
    counter: u64,
}

impl ProposalStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Demo-Proposal registrieren (Tests / Server-Start-Seed).
    pub fn register_demo(&mut self, id: &str) {
        self.approved.insert(id.to_string(), false);
    }

    pub fn approve(&mut self, id: &str) {
        self.approved.insert(id.to_string(), true);
    }

    pub fn audit_log(&self) -> &[McpAuditEntry] {
        &self.audit
    }

    fn next_audit_id(&mut self) -> String {
        self.counter += 1;
        format!("audit-2026-{:05}", self.counter)
    }

    fn log(&mut self, proposal_id: &str, approved_by: Option<&str>, applied: bool) -> String {
        let id = self.next_audit_id();
        self.audit.push(McpAuditEntry {
            audit_log_id: id.clone(),
            proposal_id: proposal_id.to_string(),
            approved_by: approved_by.map(str::to_string),
            applied,
        });
        id
    }
}

/// `audit_diff`: ChangedFiles via scope.rs + Lockfile-Inventar + Issues-Geruest.
/// Issues: .rs-Dateien mit nesting_depth > 4 → E0-Kandidat (Richtwert 4).
///
/// Scope ist immer `base..HEAD`: `params.base` ist Pflicht (leere, NUL- oder
/// `-`-fuehrende Werte → INVALID_PARAMS); `params.head` darf fehlen oder muss
/// exakt `"HEAD"` sein — jeder andere Wert → INVALID_PARAMS (kein stilles
/// Ignorieren). Die `changed_files_since`-Signatur bleibt unveraendert.
pub fn catehunt_audit_diff(root: &Path, params: &Value) -> Result<Value, ToolError> {
    let base = params
        .get("base")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if base.is_empty() {
        return Err(ToolError::new(
            "INVALID_PARAMS",
            "params.base fehlt oder leer",
        ));
    }
    if base.contains('\0') || base.starts_with('-') {
        return Err(ToolError::new(
            "INVALID_PARAMS",
            format!("params.base ungueltig: {base}"),
        ));
    }
    let head = params
        .get("head")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("HEAD");
    if head != "HEAD" {
        return Err(ToolError::new(
            "INVALID_PARAMS",
            format!("nur head \"HEAD\" wird unterstuetzt (base..HEAD), erhalten: {head}"),
        ));
    }
    let include_lockfiles = params
        .get("include_lockfiles")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let filter: Vec<String> = params
        .get("paths")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    for f in &filter {
        jail_rel(f)?;
    }

    let mut files = cate_core::scope::changed_files_since(root, base)
        .map_err(|e| ToolError::new("NOT_FOUND", format!("git diff: {e}")))?;
    if !filter.is_empty() {
        files.retain(|f| {
            filter
                .iter()
                .any(|p| f.path == *p || f.path.starts_with(&format!("{p}/")))
        });
    }
    let changed: Vec<Value> = files
        .iter()
        .map(|f| json!({"status": f.status.to_string(), "path": f.path}))
        .collect();

    let inv = if include_lockfiles {
        let i = cate_core::scope::inventory(root);
        json!({"lockfiles": i.lockfiles, "has_cargo_lock": i.has_cargo_lock, "has_package_lock": i.has_package_lock})
    } else {
        json!({"lockfiles": [], "has_cargo_lock": false, "has_package_lock": false})
    };

    // Issues-Geruest: deterministisch aus geaenderten .rs-Dateien.
    let mut issues = Vec::new();
    for f in &files {
        if !f.path.ends_with(".rs") {
            continue;
        }
        let full = root.join(&f.path);
        let Ok(src) = std::fs::read_to_string(&full) else {
            continue;
        };
        let m = analyze_file(&f.path, &src);
        if m.max_nesting_depth > 4 {
            issues.push(json!({
                "id": format!("metrics:nesting:{}:{}", f.path, m.functions.first().map(|x| x.start_line).unwrap_or(1)),
                "rule_id": "nesting-depth",
                "file": f.path,
                "line": m.functions.first().map(|x| x.start_line).unwrap_or(1),
                "severity": "E0",
                "message": format!("nesting_depth {} ueber Richtwert 4", m.max_nesting_depth),
            }));
        }
    }

    Ok(
        json!({"base": base, "head": head, "changed_files": changed, "inventory": inv, "issues": issues}),
    )
}

/// Wanderter strikter Params-Leser (Konvention wie `audit_diff`):
/// Fehlt der Parameter (`params` ohne Feld) gill der Default. Ansonsten
/// wird `Value::as_u64` angewendet — falscher Typ (String, Float, Bool,
/// `null`) oder −/0 oder außerhalb [`min`, `max`] → `INVALID_PARAMS`
/// (kein Clamping, kein stilles Default, kein Ignorieren).
fn strict_u64_range(
    params: &Value,
    name: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, ToolError> {
    let Some(v) = params.get(name) else {
        return Ok(default);
    };
    let bad = |v: &Value| {
        ToolError::new(
            "INVALID_PARAMS",
            format!("params.{name} muss Integer {min}..={max} sein, erhalten: {v}"),
        )
    };
    match v.as_u64() {
        Some(n) if n >= min => {
            if n > max {
                return Err(bad(v));
            }
            Ok(n)
        }
        _ => Err(bad(v)),
    }
}
/// Wurzeln haben Tiefe 0; behalten werden Knoten mit Tiefe < `max_depth`,
/// Kanten nur wenn beide Enden behalten werden. Ohne Wurzeln (Zyklus)
/// startet die Suche an allen Knoten (alle Tiefe 0).
pub fn apply_max_depth(
    nodes: Vec<Value>,
    edges: Vec<Value>,
    max_depth: usize,
) -> (Vec<Value>, Vec<Value>) {
    let key = |n: &Value| {
        n.get("path")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let ids: HashSet<String> = nodes.iter().map(&key).collect();
    let mut incoming: HashSet<&str> = HashSet::new();
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for e in &edges {
        let (f, t) = (
            e.get("from").and_then(Value::as_str).unwrap_or(""),
            e.get("to").and_then(Value::as_str).unwrap_or(""),
        );
        if ids.contains(f) && ids.contains(t) {
            incoming.insert(t);
            adj.entry(f).or_default().push(t);
        }
    }
    let mut depth: HashMap<&str, usize> = HashMap::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    for n in &nodes {
        let p = n.get("path").and_then(Value::as_str).unwrap_or("");
        if !incoming.contains(p) {
            depth.insert(p, 0);
            queue.push_back(p);
        }
    }
    if depth.is_empty() {
        // Zyklus ohne Wurzel: alle Knoten Tiefe 0.
        for n in &nodes {
            let p = n.get("path").and_then(Value::as_str).unwrap_or("");
            depth.insert(p, 0);
        }
    }
    while let Some(cur) = queue.pop_front() {
        let d = depth[&cur];
        if d + 1 >= max_depth {
            continue;
        }
        if let Some(next) = adj.get(cur) {
            for t in next {
                if !depth.contains_key(t) {
                    depth.insert(t, d + 1);
                    queue.push_back(t);
                }
            }
        }
    }
    let keep: HashSet<String> = depth
        .iter()
        .filter(|(_, &d)| d < max_depth)
        .map(|(&p, _)| p.to_string())
        .collect();
    let nodes: Vec<Value> = nodes
        .into_iter()
        .filter(|n| keep.contains(n.get("path").and_then(Value::as_str).unwrap_or("")))
        .collect();
    let edges: Vec<Value> = edges
        .into_iter()
        .filter(|e| {
            let f = e.get("from").and_then(Value::as_str).unwrap_or("");
            let t = e.get("to").and_then(Value::as_str).unwrap_or("");
            keep.contains(f) && keep.contains(t)
        })
        .collect();
    (nodes, edges)
}

/// `get_graph`: cate-graph JSON gemappt auf Spec-Schema.
///
/// `max_depth` (1..=32, Default 8) wird als BFS-Tiefe ab den Wurzeln auf
/// Knoten UND Kanten angewendet. `health` enthaelt bewusst KEIN
/// `total_e2_plus`: cate-graph hat keine Evidence-Daten, ein Hardcode-0
/// waere ein Fake-Wert (gestrichen 2026-10-15, s. `docs/MCP_TOOLS.md` §4).
pub fn catehunt_get_graph(root: &Path, params: &Value) -> Result<Value, ToolError> {
    let raw = params
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if raw.is_empty() {
        return Err(ToolError::new(
            "INVALID_PARAMS",
            "params.path fehlt oder leer",
        ));
    }
    let rel = jail_rel(raw)?;
    // max_depth strikt (P2-Rest): Default 8, sonst Integer 1..=32.
    // 0 (unbegrenzt-Codierung im Plan), negativ, falscher Typ -> INVALID_PARAMS
    // (kein Clamping, kein stilles Ignorieren; Konvention wie audit_diff/head).
    let max_depth = strict_u64_range(params, "max_depth", 8, 1, 32)? as usize;
    let target = root.join(&rel);
    if !target.exists() {
        return Err(ToolError::new(
            "INVALID_PATH",
            format!("Pfad nicht gefunden: {raw}"),
        ));
    }
    let dir: &Path = if target.is_file() {
        target.parent().unwrap_or(root)
    } else {
        &target
    };
    let graph = cate_graph::get_graph(dir).map_err(|e| ToolError::new("INVALID_PATH", e))?;
    let nodes: Vec<Value> = graph
        .nodes
        .iter()
        .map(|n| {
            let m = analyze_file(
                &n.path,
                &std::fs::read_to_string(dir.join(&n.path)).unwrap_or_default(),
            );
            let f0 = m.functions.first();
            json!({
                "path": n.path,
                "kind": "file",
                "metrics": {
                    "function_length": f0.map(|f| f.length).unwrap_or(0),
                    "nesting_depth": m.max_nesting_depth,
                }
            })
        })
        .collect();
    let edges: Vec<Value> = graph
        .edges
        .iter()
        .map(|e| json!({"from": e.from, "to": e.to, "kind": "calls"}))
        .collect();
    let (nodes, edges) = apply_max_depth(nodes, edges, max_depth);
    let avg: u64 = if graph.nodes.is_empty() {
        100
    } else {
        graph.nodes.iter().map(|n| u64::from(n.health)).sum::<u64>() / graph.nodes.len() as u64
    };
    Ok(json!({
        "root": rel,
        "nodes": nodes,
        "edges": edges,
        "health": {"score_0_100": avg.min(100)}
    }))
}

/// `explain_nesting`: Tiefen-Inspektion via cate-core + Patch-Vorschlag (read-only).
pub fn catehunt_explain_nesting(root: &Path, params: &Value) -> Result<Value, ToolError> {
    let raw = params
        .get("file")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if raw.is_empty() {
        return Err(ToolError::new(
            "INVALID_PARAMS",
            "params.file fehlt oder leer",
        ));
    }
    let rel = jail_rel(raw)?;
    let max_allowed = params
        .get("max_allowed")
        .and_then(Value::as_u64)
        .unwrap_or(4)
        .clamp(1, 16) as usize;
    let full = root.join(&rel);
    if !full.is_file() {
        return Err(ToolError::new(
            "INVALID_PATH",
            format!("Datei nicht gefunden: {raw}"),
        ));
    }
    let src =
        std::fs::read_to_string(&full).map_err(|e| ToolError::new("INTERNAL", e.to_string()))?;
    let fns = scan_functions(&src);
    let line = params
        .get("line")
        .and_then(Value::as_u64)
        .map(|l| l as usize);
    let target = match line {
        Some(l) => fns
            .iter()
            .find(|f| f.start_line <= l && l <= f.end_line)
            .or(fns.iter().max_by_key(|f| f.nesting_depth)),
        None => fns.iter().max_by_key(|f| f.nesting_depth),
    };
    let (name, depth) = match target {
        Some(f) => (f.name.clone(), f.nesting_depth),
        None => ("-".to_string(), cate_core::nesting_depth(&src)),
    };
    let exceeds = depth > max_allowed;
    let chain = nesting_chain(&src, target.map(|f| f.start_line));
    let (suggestion, rationale) = if exceeds {
        (
            "Guard-Clauses einfuehren und innere Bedingung in Hilfsfunktion extrahieren".to_string(),
            format!("Tiefe {depth} > Richtwert {max_allowed}: Lesbarkeit/Review-Aufwand steigt, Extract reduziert Tiefe um 1-2"),
        )
    } else {
        (
            "Keine Aenderung noetig; bei Wachstum Guard-Clauses bevorzugen".to_string(),
            format!("Tiefe {depth} <= Richtwert {max_allowed}: im Rahmen"),
        )
    };
    Ok(json!({
        "file": rel,
        "function": name,
        "nesting_depth": depth,
        "max_allowed": max_allowed,
        "exceeds": exceeds,
        "chain": chain,
        "patch_suggestion": suggestion,
        "rationale": rationale,
    }))
}

fn nesting_chain(src: &str, fn_start: Option<usize>) -> Vec<String> {
    let lines: Vec<&str> = src.lines().collect();
    let start = fn_start.unwrap_or(1).saturating_sub(1);
    let mut chain = Vec::new();
    for l in lines.iter().skip(start).take(60) {
        let t = l.trim();
        if t.starts_with("fn ") {
            chain.push(format!("fn {}", t.trim_end_matches('{').trim()));
        } else if t.starts_with("if ") || t.starts_with("if(") {
            chain.push("if ...".to_string());
        } else if t.starts_with("for ") || t.starts_with("while ") || t.starts_with("loop") {
            chain.push(t.split('{').next().unwrap_or(t).trim().to_string());
        } else if t.starts_with("match ") {
            chain.push("match ...".to_string());
        }
        if chain.len() >= 6 {
            break;
        }
    }
    if chain.is_empty() {
        chain.push("fn ?".to_string());
    }
    chain
}

/// `apply_proposal`: Gate + Audit-Log. Ohne `approved_by` (und ohne Vorab-Genehmigung)
/// → APPROVAL_REQUIRED. Jede Entscheidung wird audit-geloggt.
pub fn catehunt_apply_proposal(
    store: &mut ProposalStore,
    params: &Value,
) -> Result<Value, ToolError> {
    let id = params
        .get("proposal_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if id.is_empty() {
        return Err(ToolError::new(
            "INVALID_PARAMS",
            "params.proposal_id fehlt oder leer",
        ));
    }
    let approved_by = params
        .get("approved_by")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match store.approved.get(id) {
        None => Err(ToolError::new(
            "NOT_FOUND",
            format!("unbekannte proposal_id: {id}"),
        )),
        Some(_) => {
            if approved_by.is_none() {
                let audit_id = store.log(id, None, false);
                return Err(ToolError::new(
                    "APPROVAL_REQUIRED",
                    format!("apply_proposal erfordert approved_by (audit: {audit_id})"),
                ));
            }
            let by = approved_by.unwrap_or("");
            store.approved.insert(id.to_string(), true);
            let audit_id = store.log(id, Some(by), true);
            Ok(json!({
                "proposal_id": id,
                "applied": true,
                "audit_log_id": audit_id,
                "files_changed": [],
                "message": "Proposal angewendet und audit-geloggt",
            }))
        }
    }
}

/// Stand der eingebauten Offline-Advisory-DB (YYYY-MM-DD).
/// Produktions-Anbindung (`advisories/*.json`) ist Phase 5+; bis dahin
/// enthaelt die DB nur synthetische Beispiel-Eintraege, die mit keinem
/// realen Paketnamen kollidieren (kein False Alarm moeglich).
pub const ADVISORY_DB_STAND: &str = "2026-10-15";

/// Ein Eintrag der Offline-Advisory-DB: Paket + Versionen < `vulnerable_below`
/// gelten als betroffen, `patched_in` nennt die Fix-Version(en).
struct Advisory {
    package: &'static str,
    ecosystem: &'static str, // "cargo" | "npm"
    advisory_id: &'static str,
    aliases: &'static [&'static str],
    severity: &'static str, // low | moderate | high | critical
    summary: &'static str,
    vulnerable_below: &'static str,
    patched_in: &'static [&'static str],
}

/// Eingebaute Offline-Tabelle (KEIN Netz). Unbekannte Pakete ergeben
/// bewusst kein Advisory (kein False-Safety-Versprechen, kein False Alarm).
const ADVISORY_DB: &[Advisory] = &[
    Advisory {
        package: "sample-vuln-crate",
        ecosystem: "cargo",
        advisory_id: "CATE-SAMPLE-0001",
        aliases: &[],
        severity: "high",
        summary: "Beispiel-Eintrag (offline Sample-DB): Platzhalter-Advisory, nur fuer Tests",
        vulnerable_below: "9.9.9",
        patched_in: &["9.9.9"],
    },
    Advisory {
        package: "sample-vuln-pkg",
        ecosystem: "npm",
        advisory_id: "CATE-SAMPLE-0002",
        aliases: &[],
        severity: "critical",
        summary: "Beispiel-Eintrag (offline Sample-DB): Platzhalter-Advisory, nur fuer Tests",
        vulnerable_below: "2.0.1",
        patched_in: &["2.0.1"],
    },
    Advisory {
        package: "sample-eol-lib",
        ecosystem: "npm",
        advisory_id: "CATE-SAMPLE-0003",
        aliases: &[],
        severity: "moderate",
        summary: "Beispiel-Eintrag (offline Sample-DB): Platzhalter-Advisory, nur fuer Tests",
        vulnerable_below: "1.5.0",
        patched_in: &["1.5.0"],
    },
];

/// Grober Versionsvergleich (numerische Komponenten, `1.2.10` > `1.2.9`;
/// Release > Prerelease bei gleichem Zahlenkern). Heuristik fuer die
/// Sample-DB, kein Ersatz fuer semver-Ranges in Phase 5+.
fn version_lt(a: &str, b: &str) -> bool {
    fn parts(v: &str) -> Vec<(u64, bool, String)> {
        v.split('.')
            .map(|p| {
                let n: String = p.chars().take_while(|c| c.is_ascii_digit()).collect();
                let rest: String = p.chars().skip_while(|c| c.is_ascii_digit()).collect();
                let num = n.parse::<u64>().unwrap_or(0);
                // Leerer Rest = Release (sortiert ueber Prerelease).
                (num, rest.is_empty(), rest)
            })
            .collect()
    }
    let (pa, pb) = (parts(a), parts(b));
    for i in 0..pa.len().max(pb.len()) {
        let x = pa.get(i).cloned().unwrap_or((0, true, String::new()));
        let y = pb.get(i).cloned().unwrap_or((0, true, String::new()));
        if x.0 != y.0 {
            return x.0 < y.0;
        }
        if x.1 != y.1 {
            // Release (true) > Prerelease (false).
            return !x.1 && y.1;
        }
        if x.2 != y.2 {
            return x.2 < y.2;
        }
    }
    false
}

/// Parsed `Cargo.lock` (Stufe 0, ohne TOML-Dependency): sammelt
/// `[[package]]`-Bloecke mit `name` + `version`. Unbekannte/fehlende
/// Felder werden uebersprungen, nicht geraten.
fn parse_cargo_lock(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let (mut name, mut version) = (None::<String>, None::<String>);
    let mut in_pkg = false;
    let flush = |n: &mut Option<String>, v: &mut Option<String>, o: &mut Vec<(String, String)>| {
        if let (Some(n), Some(v)) = (n.take(), v.take()) {
            o.push((n, v));
        }
    };
    let kv = |line: &str| -> Option<(String, String)> {
        let (k, v) = line.split_once('=')?;
        let val = v.trim().trim_matches('"').to_string();
        Some((k.trim().to_string(), val))
    };
    for raw in text.lines() {
        let line = raw.trim();
        if line == "[[package]]" {
            flush(&mut name, &mut version, &mut out);
            in_pkg = true;
            continue;
        }
        if line.starts_with('[') {
            flush(&mut name, &mut version, &mut out);
            in_pkg = false;
            continue;
        }
        if !in_pkg {
            continue;
        }
        if let Some((k, v)) = kv(line) {
            if k == "name" && !v.is_empty() {
                name = Some(v);
            } else if k == "version" && !v.is_empty() {
                version = Some(v);
            }
        }
    }
    flush(&mut name, &mut version, &mut out);
    out
}

/// Parsed `package-lock.json`: LockfileVersion 7+ (`packages`-Map, Keys
/// `node_modules/<name>`, Root-Key `""` ohne Version wird ignoriert),
/// Fallback LockfileVersion 1 (`dependencies`-Map).
fn parse_package_lock(text: &str) -> Result<Vec<(String, String)>, String> {
    let v: Value =
        serde_json::from_str(text).map_err(|e| format!("package-lock.json ungueltig: {e}"))?;
    let mut out = Vec::new();
    if let Some(pkgs) = v.get("packages").and_then(Value::as_object) {
        for (k, e) in pkgs {
            if k.is_empty() {
                continue;
            }
            let Some(name) = k.strip_prefix("node_modules/").filter(|s| !s.contains('/')) else {
                continue;
            };
            if let Some(ver) = e.get("version").and_then(Value::as_str) {
                if !ver.is_empty() {
                    out.push((name.to_string(), ver.to_string()));
                }
            }
        }
        return Ok(out);
    }
    if let Some(deps) = v.get("dependencies").and_then(Value::as_object) {
        for (name, e) in deps {
            if let Some(ver) = e.get("version").and_then(Value::as_str) {
                if !ver.is_empty() {
                    out.push((name.clone(), ver.to_string()));
                }
            }
        }
        return Ok(out);
    }
    Err("package-lock.json enthaelt weder packages- noch dependencies-Map".to_string())
}

/// `check_dependencies`: Lockfile-Inventar + Offline-Advisory-Abgleich.
/// Kein Netz, kein Registry-Zugriff. Antwort enthaelt bewusst KEIN
/// Sicherheits-Urteil ("safe"/"clean"): Unbekanntes heisst nur
/// "kein Advisory bekannt", nie "sicher".
pub fn catehunt_check_dependencies(root: &Path, params: &Value) -> Result<Value, ToolError> {
    let lockfile = params
        .get("lockfile")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if lockfile != "Cargo.lock" && lockfile != "package-lock.json" {
        return Err(ToolError::new(
            "INVALID_PARAMS",
            "params.lockfile muss \"Cargo.lock\" oder \"package-lock.json\" sein",
        ));
    }
    let proj_raw = params
        .get("project_path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(".");
    let proj_rel = jail_rel(proj_raw)?;
    let proj_dir = if proj_rel == "." {
        root.to_path_buf()
    } else {
        root.join(&proj_rel)
    };
    if !proj_dir.is_dir() {
        return Err(ToolError::new(
            "INVALID_PATH",
            format!("Projektpfad nicht gefunden: {proj_raw}"),
        ));
    }
    let lock_path = proj_dir.join(lockfile);
    if !lock_path.is_file() {
        return Err(ToolError::new(
            "NOT_FOUND",
            format!("Lockfile nicht gefunden: {lockfile} unter {proj_raw}"),
        ));
    }
    let text = std::fs::read_to_string(&lock_path)
        .map_err(|e| ToolError::new("INTERNAL", e.to_string()))?;
    let ecosystem = if lockfile == "Cargo.lock" {
        "cargo"
    } else {
        "npm"
    };
    let pkgs = if lockfile == "Cargo.lock" {
        parse_cargo_lock(&text)
    } else {
        parse_package_lock(&text).map_err(|m| ToolError::new("INVALID_PARAMS", m))?
    };
    let mut advisories = Vec::new();
    for (name, ver) in &pkgs {
        for adv in ADVISORY_DB
            .iter()
            .filter(|a| a.ecosystem == ecosystem && a.package == name)
        {
            if version_lt(ver, adv.vulnerable_below) {
                advisories.push(json!({
                    "package": name,
                    "version": ver,
                    "advisory_id": adv.advisory_id,
                    "aliases": adv.aliases,
                    "severity": adv.severity,
                    "summary": adv.summary,
                    "patched_in": adv.patched_in,
                }));
            }
        }
    }
    Ok(json!({
        "lockfile": lockfile,
        "packages_checked": pkgs.len(),
        "advisories": advisories,
        "db_stand": ADVISORY_DB_STAND,
    }))
}

/// `verify_fix`: Sandbox-gated (S1-Prozess-Sandbox `crates/cate-sandbox/`,
/// Spec `docs/SANDBOX_DESIGN.md`). Ohne Runner (keine Sandbox verfuegbar)
/// wird IMMER `NO_SANDBOX` zurueckgegeben — es findet kein Prozess-Spawn
/// und keine Test-Ausfuehrung statt (weder Host noch Container).
/// Das ist die Sicherheitsgarantie: kein Host-Fallback.
///
/// Spaeteres Schema (Phase 4+, unveraendert gueltig): Params werden wie
/// heute validiert (`finding_id`, `fix_commit` Pflicht; `timeout_secs`
/// 1..=600); mit Sandbox folgt Re-Test im Container und nur bei
/// bestandenem Re-Test E3 -> E4 (`verified=true`), sonst bleibt E3.
/// E0/E1/E2-Findings werden dann mit INVALID_PARAMS abgelehnt
/// (kein Stufen-Ueberspringen).
pub fn catehunt_verify_fix(params: &Value) -> Result<Value, ToolError> {
    let finding = params
        .get("finding_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if finding.is_empty() {
        return Err(ToolError::new(
            "INVALID_PARAMS",
            "params.finding_id fehlt oder leer",
        ));
    }
    let commit = params
        .get("fix_commit")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if commit.is_empty() {
        return Err(ToolError::new(
            "INVALID_PARAMS",
            "params.fix_commit fehlt oder leer",
        ));
    }
    if let Some(t) = params.get("timeout_secs") {
        let ok = t.as_u64().is_some_and(|s| (1..=600).contains(&s));
        if !ok {
            return Err(ToolError::new(
                "INVALID_PARAMS",
                "params.timeout_secs muss Integer 1..=600 sein",
            ));
        }
    }
    // Sandbox-Gate: kein Rueckfall, kein Spawn — bewusst verweigert.
    Err(ToolError::new(
        "NO_SANDBOX",
        "verify_fix erfordert eine Sandbox (Phase 4+); ohne Sandbox kein Re-Test, kein E4-Upgrade, keine Host-Ausfuehrung",
    ))
}

/// Ergebnis eines Re-Tests (vom Runner geliefert, nie vom Tool geraten).
#[derive(Debug, Clone)]
pub struct RetestOutcome {
    pub passed: bool,
    pub run_id: String,
    pub log_excerpt: String,
}

/// Re-Test-Runner: injizierbar — Prod nutzt die Sandbox, Unit-Tests einen Mock
/// (kein echter Exec im Unit-Test).
pub trait RetestRunner {
    fn retest(
        &self,
        finding_id: &str,
        fix_commit: &str,
        timeout_secs: u64,
    ) -> Result<RetestOutcome, ToolError>;
}

/// Evidence-Quelle (Finding-ID -> Level). Echte Quelle ist der Triage-Store;
/// Tests nutzen eine Map.
pub trait EvidenceLookup {
    fn evidence_of(&self, finding_id: &str) -> Option<String>;
}

impl EvidenceLookup for HashMap<String, String> {
    fn evidence_of(&self, finding_id: &str) -> Option<String> {
        self.get(finding_id).cloned()
    }
}

/// Prod-Runner: Re-Test als Sandbox-Lauf. `program`/`args` kommen aus der
/// Operator-Konfiguration (argv-Array, nie Shell-String): `params.test_command`
/// wird NICHT als Shell ausgefuehrt (Fail-Closed gegen Command-Injection).
/// Timeout-Kill und Nicht-Null-Exit zaehlen als nicht bestanden (E3 bleibt).
pub struct SandboxRetestRunner {
    pub config: cate_sandbox::SandboxConfig,
    pub program: String,
    pub args: Vec<String>,
}

impl RetestRunner for SandboxRetestRunner {
    fn retest(
        &self,
        _finding_id: &str,
        _fix_commit: &str,
        timeout_secs: u64,
    ) -> Result<RetestOutcome, ToolError> {
        let scratch = cate_sandbox::create_scratch()
            .map_err(|e| ToolError::new("INTERNAL", format!("scratch: {e}")))?;
        let arg_refs: Vec<&str> = self.args.iter().map(String::as_str).collect();
        let req = cate_sandbox::SandboxRequest {
            program: &self.program,
            args: &arg_refs,
            scratch: &scratch,
            timeout_secs,
        };
        let out = cate_sandbox::run_sandboxed(&self.config, &req);
        let _ = cate_sandbox::remove_scratch(&scratch);
        let (res, audit) = out.map_err(|e| match e {
            cate_sandbox::SandboxError::BinaryNotAllowed(m) => {
                ToolError::new("INTERNAL", format!("Runner-Binary nicht erlaubt: {m}"))
            }
            cate_sandbox::SandboxError::TimeoutOutOfRange(t) => {
                ToolError::new("INVALID_PARAMS", format!("timeout ausserhalb: {t}"))
            }
            other => ToolError::new("INTERNAL", other.to_string()),
        })?;
        // S1-Versprechen: Audit-Eintrag pro Run — redigiert auf stderr
        // (Operator-Log), nie mit Secrets.
        let audit_line = cate_core::redact::redact_text(&audit.to_json().to_string());
        eprintln!("sandbox-audit {audit_line}");
        let mut excerpt = if res.timed_out {
            format!("TIMEOUT nach {timeout_secs}s (Kill): {}", res.stderr)
        } else {
            res.stdout.clone()
        };
        if excerpt.len() > 2000 {
            excerpt.truncate(2000);
        }
        Ok(RetestOutcome {
            passed: res.success(),
            run_id: res.run_id,
            log_excerpt: excerpt.replace(|c: char| c.is_control() && c != '\n' && c != '\t', " "),
        })
    }
}

fn verify_fix_params(params: &Value) -> Result<(String, String, u64), ToolError> {
    let finding = params
        .get("finding_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if finding.is_empty() {
        return Err(ToolError::new(
            "INVALID_PARAMS",
            "params.finding_id fehlt oder leer",
        ));
    }
    let commit = params
        .get("fix_commit")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if commit.is_empty() {
        return Err(ToolError::new(
            "INVALID_PARAMS",
            "params.fix_commit fehlt oder leer",
        ));
    }
    let mut timeout = 120u64;
    if let Some(t) = params.get("timeout_secs") {
        let ok = t.as_u64().is_some_and(|s| (1..=600).contains(&s));
        if !ok {
            return Err(ToolError::new(
                "INVALID_PARAMS",
                "params.timeout_secs muss Integer 1..=600 sein",
            ));
        }
        timeout = t.as_u64().unwrap_or(120);
    }
    Ok((finding.to_string(), commit.to_string(), timeout))
}

/// `verify_fix` mit Sandbox-Anbindung (M-6): Params validieren, E3
/// voraussetzen (kein Stufen-Ueberspringen), Re-Test ueber `runner`
/// ausfuehren. E3 -> E4 nur bei bestandenem Re-Test; ohne Runner weiter
/// `NO_SANDBOX` (Fail-Closed). `runner == None` entspricht dem Legacy-Pfad.
pub fn catehunt_verify_fix_with(
    params: &Value,
    runner: Option<&dyn RetestRunner>,
    evidence: &dyn EvidenceLookup,
) -> Result<Value, ToolError> {
    let (finding, commit, timeout) = verify_fix_params(params)?;
    match evidence.evidence_of(&finding) {
        None => {
            return Err(ToolError::new(
                "NOT_FOUND",
                format!("unbekannte finding_id: {finding}"),
            ));
        }
        Some(level) if level != "E3" => {
            return Err(ToolError::new(
                "INVALID_PARAMS",
                format!(
                    "verify_fix erfordert E3 (gefunden: {level}); kein Ueberspringen der Stufen"
                ),
            ));
        }
        _ => {}
    }
    let Some(runner) = runner else {
        return Err(ToolError::new(
            "NO_SANDBOX",
            "verify_fix erfordert eine Sandbox; ohne Sandbox kein Re-Test, kein E4-Upgrade, keine Host-Ausfuehrung",
        ));
    };
    let outcome = runner.retest(&finding, &commit, timeout)?;
    let (verified, evidence_after) = if outcome.passed {
        (true, "E4")
    } else {
        (false, "E3")
    };
    Ok(json!({
        "finding_id": finding,
        "verified": verified,
        "evidence_after": evidence_after,
        "details": {
            "retest_passed": outcome.passed,
            "sandbox_run_id": outcome.run_id,
            "log_excerpt": outcome.log_excerpt,
        }
    }))
}

/// JSON-RPC-2.0-Dispatch ueber stdio. Antwort immer mit passender `id`.
pub fn handle_request(req: &Value, root: &Path, store: &mut ProposalStore) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(json!({}));
    let result = match method {
        "audit_diff" => catehunt_audit_diff(root, &params),
        "get_graph" => catehunt_get_graph(root, &params),
        "explain_nesting" => catehunt_explain_nesting(root, &params),
        "apply_proposal" => catehunt_apply_proposal(store, &params),
        "verify_fix" => catehunt_verify_fix(&params),
        "check_dependencies" => catehunt_check_dependencies(root, &params),
        "ping" => Ok(json!({"ok": true, "echo": params})),
        _ => {
            return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Method not found","data":{"code":"NOT_FOUND","message":format!("unbekannte Methode: {method}")}}});
        }
    };
    match result {
        Ok(v) => json!({"jsonrpc":"2.0","id":id,"result":v}),
        Err(e) => {
            json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":e.message,"data":{"code":e.code,"message":e.message}}})
        }
    }
}
