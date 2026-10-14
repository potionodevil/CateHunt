// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! CateHunt-Desktop-Backend: Tauri-Commands ohne Server.
//! Bindet cate-core (Health-Score, EvidenceLevel) und cate-triage
//! (Deny-List-Policy) direkt als Pfad-Dependencies ein.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use cate_triage::{verdict_cap, MaxAction};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

mod fixflow;

/// Ein Review-Befund (JSON-kompatibel zu ui/fixtures/findings.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub cwe: String,
    pub file: String,
    pub start_line: Option<u32>,
    pub message: String,
    pub category: String,
    pub evidence: String,
    #[serde(default)]
    pub deny: bool,
}

/// Health-Antwort (JSON-kompatibel zu ui/fixtures/health.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    pub score_0_100: u8,
    pub total_e2_plus: usize,
    pub by_level: BTreeMap<String, usize>,
}

/// Eingebettete Demo-Daten: greift, wenn keine Datei gefunden wird.
/// Pfad wird zur Laufzeit relativ zum Resource-Verzeichnis gesucht.
const DEMO_FINDINGS: &str = include_str!("../../ui/fixtures/findings.json");
const DEMO_HEALTH: &str = include_str!("../../ui/fixtures/health.json");

/// Deny-Flag serverseitig aus cate-triage ableiten (UI-Button ist nur Kosmetik).
fn deny_for(cwe: &str) -> bool {
    verdict_cap(cwe) == MaxAction::DemoteOnly
}

fn with_deny(mut findings: Vec<Finding>) -> Vec<Finding> {
    for f in &mut findings {
        if deny_for(&f.cwe) {
            f.deny = true;
        }
    }
    findings
}

fn findings_from_file(path: Option<String>) -> Vec<Finding> {
    if let Some(p) = path {
        if let Ok(text) = std::fs::read_to_string(&p) {
            if let Ok(v) = serde_json::from_str::<Vec<Finding>>(&text) {
                return with_deny(v);
            }
        }
    }
    // Fallback: eingebettete Demo-Fixtures (App startet ohne Netz/Datei).
    serde_json::from_str::<Vec<Finding>>(DEMO_FINDINGS)
        .map(with_deny)
        .unwrap_or_default()
}

/// Liste aller Findings; `path` optional (findings.json-Pfad).
#[tauri::command]
fn list_findings(path: Option<String>) -> Vec<Finding> {
    findings_from_file(path)
}

/// Health-Kopf: wird aus den Findings via cate-core berechnet
/// (nur E2+ zaehlen, vgl. cate_core::health_score) und mit dem
/// Demo-Wert aus health.json abgeglichen.
#[tauri::command]
fn health(path: Option<String>) -> Health {
    let findings = findings_from_file(path);
    let scored: Vec<cate_core::ScoredFinding> = findings
        .iter()
        .map(|f| cate_core::ScoredFinding {
            level: "warning".to_string(),
            evidence: f.evidence.parse().unwrap_or_default(),
        })
        .collect();
    let hs = cate_core::health_score(&[], &scored, 0);
    // Demo-Fixture als Referenz (score_0_100 dort = 72 bei anderem Level-Mix).
    let demo: serde_json::Value =
        serde_json::from_str(DEMO_HEALTH).unwrap_or(serde_json::Value::Null);
    let _ = demo;
    let mut by_level = BTreeMap::new();
    for f in &findings {
        if f.evidence.parse::<cate_core::EvidenceLevel>().unwrap_or_default()
            >= cate_core::EvidenceLevel::E2
        {
            *by_level.entry(f.evidence.clone()).or_insert(0) += 1;
        }
    }
    Health {
        score_0_100: hs.security,
        total_e2_plus: hs.total_e2_plus,
        by_level,
    }
}

/// Modulgraph (`cate-graph::get_graph`): Knoten `{id, path, health, color}`
/// + Kanten (use/mod-Abhaengigkeiten). `path` = Repo-Root (optional,
/// Default: Arbeitsverzeichnis). Knoten-Farben folgen `health_color`
/// (gruen > 85, gelb 60–85, rot < 60) — konsistent mit UI-`healthColor`
/// und `cate-core`-Health-Scores. Kann der Graph nicht gebaut werden
/// (kein Verzeichnis/keine .rs-Dateien), bleibt der Fallback:
/// `{"nodes": [], "edges": [], "fallback": true, "reason": ...}`.
#[tauri::command]
fn graph(path: Option<String>) -> serde_json::Value {
    let root = path
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")));
    match cate_graph::get_graph(&root) {
        Ok(g) => {
            let mut v = serde_json::to_value(&g).unwrap_or(serde_json::Value::Null);
            if let Some(obj) = v.as_object_mut() {
                obj.insert("fallback".to_string(), serde_json::Value::Bool(false));
            }
            v
        }
        Err(e) => {
            serde_json::json!({"nodes": [], "edges": [], "fallback": true, "reason": e})
        }
    }
}

/// Fix-Vorschlag anlegen (Status `Proposed`, read-only Default).
/// Gibt das gespeicherte Proposal zurueck.
#[tauri::command]
fn suggest_fix(
    state: tauri::State<Mutex<fixflow::FixStore>>,
    finding_id: String,
    title: String,
    rationale: String,
) -> Result<cate_graph::proposal::Proposal, String> {
    state
        .lock()
        .map_err(|e| format!("store poisoned: {e}"))?
        .suggest(&finding_id, &title, &rationale)
}

/// User-Approval zu einem Proposal (Begruendung Pflicht).
#[tauri::command]
fn approve_fix(
    state: tauri::State<Mutex<fixflow::FixStore>>,
    proposal_id: String,
    rationale: String,
) -> Result<cate_graph::proposal::Proposal, String> {
    state
        .lock()
        .map_err(|e| format!("store poisoned: {e}"))?
        .approve(&proposal_id, &rationale)
}

/// Fix anwenden — NUR nach Approval, sonst `APPROVAL_REQUIRED`.
/// Erfolgreiche Applies landen im Audit-Log (`fix_audit`).
#[tauri::command]
fn apply_fix(
    state: tauri::State<Mutex<fixflow::FixStore>>,
    proposal_id: String,
    approved_by: String,
) -> Result<cate_graph::proposal::Proposal, String> {
    state
        .lock()
        .map_err(|e| format!("store poisoned: {e}"))?
        .apply(&proposal_id, &approved_by)
}

/// Audit-Log aller angewendeten Fixes (append-only).
#[tauri::command]
fn fix_audit(
    state: tauri::State<Mutex<fixflow::FixStore>>,
) -> Result<Vec<cate_graph::proposal::AuditEntry>, String> {
    Ok(state
        .lock()
        .map_err(|e| format!("store poisoned: {e}"))?
        .audit_log())
}

fn main() {
    tauri::Builder::default()
        .manage(Mutex::new(fixflow::FixStore::default()))
        .invoke_handler(tauri::generate_handler![
            list_findings,
            health,
            graph,
            suggest_fix,
            approve_fix,
            apply_fix,
            fix_audit
        ])
        .run(tauri::generate_context!())
        .expect("CateHunt backend failed to start");
}
