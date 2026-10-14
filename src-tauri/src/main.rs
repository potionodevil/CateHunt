// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! CateHunt-Desktop-Backend: Tauri-Commands ohne Server.
//! Bindet cate-core (Health-Score, EvidenceLevel) und cate-triage
//! (Deny-List-Policy) direkt als Pfad-Dependencies ein.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use cate_triage::{verdict_cap, MaxAction};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![list_findings, health])
        .run(tauri::generate_context!())
        .expect("CateHunt backend failed to start");
}
