// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! cate-mcp: JSON-RPC-Server ueber stdio (kein Netz).
//! Tools: `audit_diff`, `get_graph`, `explain_nesting`, `apply_proposal`, `ping`.
use cate_core::{analyze_file, scan_functions};
use serde_json::{json, Value};
use std::collections::HashMap;
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
    let head = params.get("head").and_then(Value::as_str).unwrap_or("HEAD");
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

/// `get_graph`: cate-graph JSON gemappt auf Spec-Schema.
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
    let max_depth = params
        .get("max_depth")
        .and_then(Value::as_u64)
        .unwrap_or(8)
        .clamp(1, 32);
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
    let _ = max_depth; // Tiefenlimit: Filter waere Phase 5+; akzeptiert + validiert.
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
    let avg: u64 = if graph.nodes.is_empty() {
        100
    } else {
        graph.nodes.iter().map(|n| u64::from(n.health)).sum::<u64>() / graph.nodes.len() as u64
    };
    Ok(json!({
        "root": rel,
        "nodes": nodes,
        "edges": edges,
        "health": {"total_e2_plus": 0, "score_0_100": avg.min(100)}
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
