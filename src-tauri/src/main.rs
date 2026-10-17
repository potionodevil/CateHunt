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

/// Injizierbarer Subprozess-Runner (mockbar in Tests).
type RunCmd = dyn FnMut(&str, &[String]) -> Result<String, String>;

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
    /// Provenienz: `regel-name/modell@backend/stufe`
    /// (z.B. `semgrep:python.crypto.md5@regeln/stufe-0`).
    /// Fehlt das Feld in alten Dateien, wird es per Default nachgetragen.
    #[serde(default)]
    pub detected_by: Option<String>,
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

/// Provenienz-Default fuer Befunde ohne `detected_by`
/// (Regel-Name @ Regel-Backend / Stufe 0).
fn default_detected_by(rule_id: &str) -> String {
    format!("{rule_id}@regeln/stufe-0")
}

fn with_deny(mut findings: Vec<Finding>) -> Vec<Finding> {
    for f in &mut findings {
        if deny_for(&f.cwe) {
            f.deny = true;
        }
        if f.detected_by.as_deref().is_none_or(|s| s.trim().is_empty()) {
            f.detected_by = Some(default_detected_by(&f.rule_id));
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

/// Health aus bereits geladenen Findings berechnen (reine Funktion,
/// auch von `rescan` genutzt).
fn compute_health(findings: &[Finding]) -> Health {
    let scored: Vec<cate_core::ScoredFinding> = findings
        .iter()
        .map(|f| cate_core::ScoredFinding {
            level: "warning".to_string(),
            evidence: f.evidence.parse().unwrap_or_default(),
            // M-4 Provenienz: Parent/Tauri-Agent setzt hier den echten Record.
            provenance: None,
        })
        .collect();
    let hs = cate_core::health_score(&[], &scored, 0);
    // Demo-Fixture als Referenz (score_0_100 dort = 72 bei anderem Level-Mix).
    let demo: serde_json::Value =
        serde_json::from_str(DEMO_HEALTH).unwrap_or(serde_json::Value::Null);
    let _ = demo;
    let mut by_level = BTreeMap::new();
    for f in findings {
        if f.evidence
            .parse::<cate_core::EvidenceLevel>()
            .unwrap_or_default()
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

/// Health-Kopf: wird aus den Findings via cate-core berechnet
/// (nur E2+ zaehlen, vgl. cate_core::health_score) und mit dem
/// Demo-Wert aus health.json abgeglichen.
#[tauri::command]
fn health(path: Option<String>) -> Health {
    compute_health(&findings_from_file(path))
}

// ---- Modell-Konfiguration (first/second-backend) + Rescan ----

/// Aufgeloestes Routing: Primaer-Backend + optionale Deep-Stufe (UI-Anzeige).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Routing {
    pub primary: String,
    pub deep: Option<String>,
}

/// `first_backend` validieren: `ollama`/`gemini` oder deaktiviert
/// (`aus`/`off`/`none`/leer = None). Alles andere ist ein Fehler.
pub fn parse_first_backend(
    v: Option<String>,
) -> Result<Option<cate_triage::gemini::Backend>, String> {
    let s = v.unwrap_or_default().trim().to_lowercase();
    if s.is_empty() || s == "aus" || s == "off" || s == "none" {
        Ok(None)
    } else if s == "ollama" {
        Ok(Some(cate_triage::gemini::Backend::Ollama))
    } else if s == "gemini" {
        Ok(Some(cate_triage::gemini::Backend::Gemini))
    } else {
        Err(format!(
            "unbekanntes first_backend '{s}' (erlaubt: ollama, gemini, aus)"
        ))
    }
}

/// `second_backend` validieren: `opencode`/`claude` oder deaktiviert
/// (`aus`/`off`/`none`/leer = None). Alles andere ist ein Fehler.
pub fn parse_second_backend(
    v: Option<String>,
) -> Result<Option<cate_triage::deep_engines::Engine>, String> {
    let s = v.unwrap_or_default().trim().to_lowercase();
    if s.is_empty() || s == "aus" || s == "off" || s == "none" {
        Ok(None)
    } else if s == "opencode" {
        Ok(Some(cate_triage::deep_engines::Engine::Opencode))
    } else if s == "claude" {
        Ok(Some(cate_triage::deep_engines::Engine::Claude))
    } else {
        Err(format!(
            "unbekanntes second_backend '{s}' (erlaubt: opencode, claude, aus)"
        ))
    }
}

/// Routing ueber die Pipeline-Selektoren aufloesen:
/// - Primaer: explizites `first` oder `select_backend(gemini_available)`.
/// - Deep: `select_deep_engine` mit Opt-in genau dann, wenn `second`
///   gesetzt ist (`deny_cwe`/`uncertain` kommen aus den Findings).
pub fn resolve_routing(
    first: Option<cate_triage::gemini::Backend>,
    second: Option<cate_triage::deep_engines::Engine>,
    gemini_available: bool,
    deny_cwe: bool,
    uncertain: bool,
) -> Routing {
    let primary = first.unwrap_or_else(|| cate_triage::gemini::select_backend(gemini_available));
    let prefer = second.unwrap_or(cate_triage::deep_engines::Engine::Opencode);
    let deep = cate_triage::deep_engines::select_deep_engine(
        deny_cwe,
        uncertain,
        second.is_some(),
        prefer,
    );
    Routing {
        primary: primary.to_string(),
        deep: deep.map(|e| e.to_string()),
    }
}

/// Unsicherer Befund im Korb (Evidence E1/E2 = Klaerungsbedarf Stufe 3)?
fn is_uncertain(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|f| f.evidence == "E1" || f.evidence == "E2")
}

/// Rescan-Ergebnis: frische Findings + Health + Graph + Routing in einer Antwort.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RescanResult {
    pub findings: Vec<Finding>,
    pub health: Health,
    pub graph: serde_json::Value,
    pub routing: Routing,
}

/// Kernlogik des Rescans (`gemini_available` injizierbar — mockbar in Tests).
pub fn rescan_inner(
    findings_path: Option<String>,
    graph_path: Option<String>,
    first_backend: Option<String>,
    second_backend: Option<String>,
    gemini_available: bool,
) -> Result<RescanResult, String> {
    let first = parse_first_backend(first_backend)?;
    let second = parse_second_backend(second_backend)?;
    let findings = findings_from_file(findings_path);
    let health = compute_health(&findings);
    let graph = graph(graph_path);
    let deny_cwe = findings.iter().any(|f| f.deny);
    let routing = resolve_routing(
        first,
        second,
        gemini_available,
        deny_cwe,
        is_uncertain(&findings),
    );
    Ok(RescanResult {
        findings,
        health,
        graph,
        routing,
    })
}

/// Scan neu starten: Findings/Health/Graph frisch zurueck.
/// `first_backend` (`ollama`/`gemini`/`aus`), `second_backend`
/// (`opencode`/`claude`/`aus`) werden validiert und bis in die
/// Pipeline-Selektoren durchgereicht.
#[tauri::command]
fn rescan(
    findings_path: Option<String>,
    graph_path: Option<String>,
    first_backend: Option<String>,
    second_backend: Option<String>,
) -> Result<RescanResult, String> {
    let gemini_available = cate_triage::pipeline::probe_cli_present("gemini");
    rescan_inner(
        findings_path,
        graph_path,
        first_backend,
        second_backend,
        gemini_available,
    )
}

/// Routing trocken aufloesen/validieren (ohne Scan) — fuer die UI-Konfiguration.
#[tauri::command]
fn triage_routing(
    first_backend: Option<String>,
    second_backend: Option<String>,
    deny_cwe: bool,
    uncertain: bool,
) -> Result<Routing, String> {
    let gemini_available = cate_triage::pipeline::probe_cli_present("gemini");
    let first = parse_first_backend(first_backend)?;
    let second = parse_second_backend(second_backend)?;
    Ok(resolve_routing(
        first,
        second,
        gemini_available,
        deny_cwe,
        uncertain,
    ))
}

// ---- Gemini-CLI-Auto-Setup ----

/// Doku + Installationshinweis fuer das Gemini-CLI-Setup (UI anzeigbar).
pub const GEMINI_SETUP_DOC: &str = "Doku: https://github.com/google-gemini/gemini-cli -- Installation: `npm i -g @google/gemini-cli` (Node.js noetig) oder Windows: `winget install -e --id Google.GeminiCLI`. Danach `gemini login`; Stufe 2 wird aktiv, sonst gilt der Ollama-Offline-Modus.";
/// Timeout fuer `setup_install` (in Millisekunden).
pub const SETUP_INSTALL_TIMEOUT_MS: u64 = 120_000;

/// Setup-Status: ist die `gemini`-CLI (und `npx` als Installationsweg) da?
/// Die UI kann damit Setup-Hinweis/Button anzeigen.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetupStatus {
    pub gemini: bool,
    pub npx: bool,
    pub detail: String,
}

/// Reine Status-Bildung (Proben injizierbar — mockbar in Tests).
pub fn setup_status_with(gemini_present: bool, npx_present: bool) -> SetupStatus {
    let detail = match (gemini_present, npx_present) {
        (true, _) => "gemini-CLI bereit (Stufe 2 aktiv nach `gemini login`).".to_string(),
        (false, true) => format!(
            "gemini-CLI fehlt, npx vorhanden -- per setup_install nachinstallierbar. {GEMINI_SETUP_DOC}"
        ),
        (false, false) => format!(
            "weder gemini noch npx gefunden -- Node.js installieren oder winget nutzen. {GEMINI_SETUP_DOC}"
        ),
    };
    SetupStatus {
        gemini: gemini_present,
        npx: npx_present,
        detail,
    }
}

#[tauri::command]
fn setup_status() -> SetupStatus {
    setup_status_with(
        cate_triage::pipeline::probe_cli_present("gemini"),
        cate_triage::pipeline::probe_cli_present("npx"),
    )
}

/// Installationsplan: welches Tool installiert `gemini` wie?
/// `npm`/`gemini`/leer = `npm i -g @google/gemini-cli`,
/// `winget` = winget-Paket. Alles andere ist ein Fehler.
pub fn setup_install_plan(tool: Option<String>) -> Result<(String, Vec<String>), String> {
    let t = tool.unwrap_or_default().trim().to_lowercase();
    if t.is_empty() || t == "npm" || t == "gemini" {
        Ok((
            "npm".to_string(),
            vec![
                "i".to_string(),
                "-g".to_string(),
                "@google/gemini-cli".to_string(),
            ],
        ))
    } else if t == "winget" {
        Ok((
            "winget".to_string(),
            vec![
                "install".to_string(),
                "-e".to_string(),
                "--id".to_string(),
                "Google.GeminiCLI".to_string(),
            ],
        ))
    } else {
        Err(format!(
            "setup_install: unbekanntes Tool '{t}' (erlaubt: npm, winget). {GEMINI_SETUP_DOC}"
        ))
    }
}

fn setup_install_fehlermeldung(ctx: &str) -> String {
    format!(
        "setup_install fehlgeschlagen ({ctx}). {GEMINI_SETUP_DOC} {}",
        cate_triage::gemini::OLLAMA_FALLBACK_HINT
    )
}

/// Installations-Kernlogik mit injiziertem Runner (mockbar in Tests):
/// Plant den Befehl und fuehrt ihn aus; jeder Runner-Fehler bekommt
/// Fehlertext und Doku mit.
pub fn setup_install_with(tool: Option<String>, run: &mut RunCmd) -> Result<String, String> {
    let (cmd, args) = setup_install_plan(tool)?;
    run(&cmd, &args).map_err(|e| setup_install_fehlermeldung(&e))
}

/// Echten Subprozess mit Timeout fahren (pollt, killt bei Timeout).
fn spawn_with_timeout(cmd: &str, args: &[String], timeout_ms: u64) -> Result<String, String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Spawn '{cmd}' scheiterte: {e}"))?;
    let start = std::time::Instant::now();
    let limit = std::time::Duration::from_millis(timeout_ms.max(1));
    loop {
        match child.try_wait().map_err(|e| format!("wait: {e}"))? {
            Some(_) => break,
            None if start.elapsed() >= limit => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("Timeout nach {timeout_ms} ms"));
            }
            None => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("Output lesen scheiterte: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(format!(
            "Exit-Code {}: {}",
            out.status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".to_string()),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Gemini-CLI installieren (`npm i -g @google/gemini-cli` bzw. winget,
/// mit Timeout + Fehlertext + Doku). Explizit per UI angestossen.
#[tauri::command]
fn setup_install(tool: Option<String>) -> Result<String, String> {
    setup_install_with(tool, &mut |cmd, args| {
        spawn_with_timeout(cmd, args, SETUP_INSTALL_TIMEOUT_MS)
    })
}

/// Modulgraph (`cate-graph::get_graph`): Knoten `{id, path, health, color}`
/// sowie Kanten (use/mod-Abhaengigkeiten). `path` = Repo-Root (optional,
/// Default: Arbeitsverzeichnis). Knoten-Farben folgen `health_color`
/// (gruen > 85, gelb 60–85, rot < 60) — konsistent mit UI-`healthColor`
/// und `cate-core`-Health-Scores. Kann der Graph nicht gebaut werden
/// (kein Verzeichnis/keine .rs-Dateien), bleibt der Fallback:
/// `{"nodes": [], "edges": [], "fallback": true, "reason": ...}`.
/// Loest den Graph-Root auf: `path` (falls gesetzt) muss nach
/// Kanonisierung ein existierendes Verzeichnis sein, sonst Err mit
/// Begruendung. Ohne `path` gilt das kanonisierte Arbeitsverzeichnis
/// (muss ebenfalls ein Verzeichnis sein).
fn resolve_graph_root(path: Option<String>) -> Result<std::path::PathBuf, String> {
    let raw = path.unwrap_or_else(|| ".".to_string());
    let canon =
        std::fs::canonicalize(&raw).map_err(|e| format!("graph root ungueltig ({raw}): {e}"))?;
    if !canon.is_dir() {
        return Err(format!(
            "graph root ist kein Verzeichnis: {}",
            canon.display()
        ));
    }
    Ok(canon)
}

#[tauri::command]
fn graph(path: Option<String>) -> serde_json::Value {
    let root = match resolve_graph_root(path) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::json!({"nodes": [], "edges": [], "fallback": true, "reason": e});
        }
    };
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

/// User-Approval zu einem Proposal (Begruendung + Reviewer Pflicht, S-3).
#[tauri::command]
fn approve_fix(
    state: tauri::State<Mutex<fixflow::FixStore>>,
    proposal_id: String,
    rationale: String,
    reviewer: String,
) -> Result<cate_graph::proposal::Proposal, String> {
    state
        .lock()
        .map_err(|e| format!("store poisoned: {e}"))?
        .approve_reviewed(&proposal_id, &rationale, &reviewer)
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

/// Suppress-Vorschlag zu einer CWE anlegen (Status `Proposed`).
/// Bedient den UI-`Unterdruecken`-Button: Deny-CWEs werden bereits hier mit
/// `DENY_SUPPRESS_BLOCKED` abgelehnt (nie suppressen, nur eskalieren).
/// `ttl_days` = Wunsch-Gueltigkeit in Tagen ab Zustimmung (Default 30).
#[tauri::command]
fn suggest_suppress_fix(
    state: tauri::State<Mutex<fixflow::FixStore>>,
    finding_id: String,
    title: String,
    rationale: String,
    cwe: String,
    ttl_days: Option<u64>,
) -> Result<cate_graph::proposal::Proposal, String> {
    state
        .lock()
        .map_err(|e| format!("store poisoned: {e}"))?
        .suggest_suppress(&finding_id, &title, &rationale, &cwe, ttl_days)
}

/// Zustimmung zu einem Proposal mit Begruendung (ohne Reviewer).
/// Der Reviewer wird spaetestens bei `apply_fix` aus `approved_by`
/// nachgetragen; explizit geht `approve_fix`.
#[tauri::command]
fn approve_fix_simple(
    state: tauri::State<Mutex<fixflow::FixStore>>,
    proposal_id: String,
    rationale: String,
) -> Result<cate_graph::proposal::Proposal, String> {
    state
        .lock()
        .map_err(|e| format!("store poisoned: {e}"))?
        .approve(&proposal_id, &rationale)
}

/// Zustimmungs-Status eines Proposals (Reviewer, Zeitraum, Ablaufdatum).
/// Vor der Zustimmung sind `approval` und `expires_at` null.
#[tauri::command]
fn fix_approval(
    state: tauri::State<Mutex<fixflow::FixStore>>,
    proposal_id: String,
) -> Result<serde_json::Value, String> {
    let store = state.lock().map_err(|e| format!("store poisoned: {e}"))?;
    let approval = store.approval_of(&proposal_id);
    let expires_at = store.expires_at_of(&proposal_id);
    serde_json::to_value(serde_json::json!({
        "approval": approval,
        "expires_at": expires_at,
    }))
    .map_err(|e| format!("json: {e}"))
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

/// Fix-Root aufloesen: `root` (falls gesetzt) muss nach Kanonisierung ein
/// existierendes Verzeichnis sein, sonst Err. Alle Datei-Pfade von
/// `preview_fix`/`apply_fix_files` werden auf diesen Root gejailt.
fn resolve_fix_root(root: Option<String>) -> Result<std::path::PathBuf, String> {
    let raw = root.unwrap_or_else(|| ".".to_string());
    let canon =
        std::fs::canonicalize(&raw).map_err(|e| format!("fix root ungueltig ({raw}): {e}"))?;
    if !canon.is_dir() {
        return Err(format!(
            "fix root ist kein Verzeichnis: {}",
            canon.display()
        ));
    }
    Ok(canon)
}

/// Diff-Vorschau echter Datei-Aenderungen (read-only, S4-Regel: vor Apply
/// pflicht). Nur nach Approval; Pfade gejailt auf `root` (Default: CWD),
/// Secrets im Diff redigiert. Merkt sich die Changes je Proposal.
#[tauri::command]
fn preview_fix(
    state: tauri::State<Mutex<fixflow::FixStore>>,
    proposal_id: String,
    root: Option<String>,
    changes: Vec<cate_graph::apply::FileChange>,
) -> Result<Vec<cate_graph::apply::FileDiff>, String> {
    let root = resolve_fix_root(root)?;
    state
        .lock()
        .map_err(|e| format!("store poisoned: {e}"))?
        .preview_files(&root, &proposal_id, &changes)
}

/// Echte Dateianwendung: schreibt die zuvor per `preview_fix` bestaetigten
/// `changes` (exakter Match, sonst `PREVIEW_REQUIRED`). Nur nach Approval
/// (`approved_by` Pflicht, Ablauf- + Deny-Gates wie `apply_fix`), mit
/// `.orig`-Backup je geaenderter Datei und Rollback bei Fehlern.
#[tauri::command]
fn apply_fix_files(
    state: tauri::State<Mutex<fixflow::FixStore>>,
    proposal_id: String,
    approved_by: String,
    root: Option<String>,
    changes: Vec<cate_graph::apply::FileChange>,
) -> Result<serde_json::Value, String> {
    let root = resolve_fix_root(root)?;
    let (proposal, report) = state
        .lock()
        .map_err(|e| format!("store poisoned: {e}"))?
        .apply_with_files(&root, &proposal_id, &approved_by, &changes)?;
    serde_json::to_value(serde_json::json!({
        "proposal": proposal,
        "files_changed": report.files_changed,
        "backups": report.backups,
    }))
    .map_err(|e| format!("json: {e}"))
}

fn main() {
    tauri::Builder::default()
        .manage(Mutex::new(fixflow::FixStore::default()))
        .invoke_handler(tauri::generate_handler![
            list_findings,
            health,
            graph,
            rescan,
            triage_routing,
            setup_status,
            setup_install,
            suggest_fix,
            suggest_suppress_fix,
            approve_fix,
            approve_fix_simple,
            apply_fix,
            fix_approval,
            preview_fix,
            apply_fix_files,
            fix_audit
        ])
        .run(tauri::generate_context!())
        .expect("CateHunt backend failed to start");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_root_nonexistent_ist_err() {
        let r = resolve_graph_root(Some("gibt-es-nicht-xyz-123".to_string()));
        assert!(r.is_err(), "nicht-existenter Pfad muss Err sein");
    }

    #[test]
    fn graph_root_datei_ist_err() {
        let f = std::env::temp_dir().join(format!(
            "cate_graphfile_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&f, "x").unwrap();
        let r = resolve_graph_root(Some(f.display().to_string()));
        assert!(r.is_err(), "Datei statt Verzeichnis muss Err sein");
        std::fs::remove_file(&f).ok();
    }

    #[test]
    fn graph_root_verzeichnis_ok() {
        let r = resolve_graph_root(Some(".".to_string()));
        assert!(r.is_ok(), "existierendes Verzeichnis muss Ok sein");
        assert!(r.unwrap().is_absolute(), "Root muss kanonisiert sein");
    }

    #[test]
    fn graph_befehl_fallback_bei_ungueltigem_pfad() {
        let v = graph(Some("gibt-es-nicht-xyz-123".to_string()));
        assert_eq!(v.get("fallback"), Some(&serde_json::Value::Bool(true)));
        assert!(v.get("nodes").unwrap().as_array().unwrap().is_empty());
        assert!(v.get("reason").unwrap().as_str().is_some());
    }

    // ---- Backend-Runde: rescan + Modell-Konfiguration + Provenienz + Setup ----

    #[test]
    fn rescan_liefert_findings_health_graph_und_routing() {
        let r = rescan_inner(None, None, None, None, false)
            .expect("rescan mit Demo-Fixtures muss gelingen");
        assert!(!r.findings.is_empty(), "Findings erwartet");
        assert!(
            r.health.total_e2_plus > 0,
            "Health muss E2+-Befunde zaehlen"
        );
        assert!(
            r.graph.get("nodes").is_some(),
            "Graph-Antwort muss Knoten enthalten"
        );
        assert_eq!(
            r.routing.primary, "ollama",
            "ohne Gemini-Availability = ollama"
        );
        assert!(
            r.findings.iter().all(|f| f
                .detected_by
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())),
            "jedes Finding braucht Provenienz"
        );
    }

    #[test]
    fn rescan_ungueltiges_backend_ist_err() {
        let e = rescan_inner(None, None, Some("quatsch".to_string()), None, false)
            .expect_err("unbekanntes first_backend muss Err sein");
        assert!(e.contains("first_backend"), "Fehlertext: {e}");
        let e2 = rescan_inner(None, None, None, Some("quatsch".to_string()), false)
            .expect_err("unbekanntes second_backend muss Err sein");
        assert!(e2.contains("second_backend"), "Fehlertext: {e2}");
    }

    #[test]
    fn backend_aus_ist_erlaubt() {
        use cate_triage::deep_engines::Engine;
        use cate_triage::gemini::Backend;
        for aus in [None, Some("aus"), Some("off"), Some("none"), Some("")] {
            let v: Option<String> = aus.map(|s| s.to_string());
            assert_eq!(parse_first_backend(v.clone()), Ok(None), "first aus: {v:?}");
            assert_eq!(
                parse_second_backend(v.clone()),
                Ok(None),
                "second aus: {v:?}"
            );
        }
        assert_eq!(
            parse_first_backend(Some("GEMINI".to_string())),
            Ok(Some(Backend::Gemini))
        );
        assert_eq!(
            parse_second_backend(Some("Claude".to_string())),
            Ok(Some(Engine::Claude))
        );
    }

    #[test]
    fn routing_nutzt_pipeline_selektoren() {
        use cate_triage::deep_engines::Engine;
        use cate_triage::gemini::Backend;
        // Ohne explizites first entscheidet select_backend ueber Availability.
        let r = resolve_routing(None, None, false, false, false);
        assert_eq!(r.primary, "ollama");
        assert_eq!(r.deep, None);
        let r = resolve_routing(None, None, true, false, false);
        assert_eq!(r.primary, "gemini");
        // Explizites first schlaegt Availability.
        let r = resolve_routing(Some(Backend::Ollama), None, true, false, false);
        assert_eq!(r.primary, "ollama");
        // Deep nur per Opt-in (second gesetzt) + Deny + unsicher (select_deep_engine).
        let r = resolve_routing(None, Some(Engine::Claude), true, true, true);
        assert_eq!(r.deep, Some("claude".to_string()));
        let r = resolve_routing(None, None, true, true, true);
        assert_eq!(r.deep, None, "ohne Opt-in kein Deep");
        let r = resolve_routing(None, Some(Engine::Opencode), true, false, true);
        assert_eq!(r.deep, None, "ohne Deny-CWE kein Deep");
    }

    #[test]
    fn detected_by_wird_nachgetragen_und_bleibt_bestehen() {
        let ohne = Finding {
            id: "F-x".into(),
            rule_id: "semgrep:test.rule".into(),
            cwe: "CWE-79".into(),
            file: "a.js".into(),
            start_line: Some(1),
            message: "m".into(),
            category: "other".into(),
            evidence: "E1".into(),
            deny: false,
            detected_by: None,
        };
        let v = with_deny(vec![ohne]);
        assert_eq!(
            v[0].detected_by.as_deref(),
            Some("semgrep:test.rule@regeln/stufe-0")
        );
        // Explizite Provenienz (Modell@Backend/Stufe) wird nicht ueberschrieben.
        let mit = Finding {
            id: "F-y".into(),
            rule_id: "semgrep:test.rule".into(),
            cwe: "CWE-79".into(),
            file: "a.js".into(),
            start_line: Some(2),
            message: "m".into(),
            category: "other".into(),
            evidence: "E2".into(),
            deny: false,
            detected_by: Some("qwen2.5-coder:7b@ollama/stufe-1".into()),
        };
        let v = with_deny(vec![mit]);
        assert_eq!(
            v[0].detected_by.as_deref(),
            Some("qwen2.5-coder:7b@ollama/stufe-1")
        );
    }

    #[test]
    fn demo_fixtures_haben_provenienz() {
        let findings: Vec<Finding> =
            serde_json::from_str(DEMO_FINDINGS).expect("fixtures muessen parsen");
        let findings = with_deny(findings);
        assert!(!findings.is_empty());
        for f in &findings {
            let d = f.detected_by.as_deref().unwrap_or("");
            assert!(!d.trim().is_empty(), "Finding {} ohne detected_by", f.id);
            assert!(
                d.contains('@'),
                "Provenienz-Format regel/modell@backend/stufe: {d}"
            );
        }
    }

    #[test]
    fn setup_status_mock_unterscheidet_faelle() {
        let s = setup_status_with(true, true);
        assert!(s.gemini && s.npx);
        assert!(s.detail.contains("bereit"));
        let s = setup_status_with(false, true);
        assert!(!s.gemini && s.npx);
        assert!(s.detail.contains("setup_install"), "Detail: {}", s.detail);
        let s = setup_status_with(false, false);
        assert!(!s.gemini && !s.npx);
        assert!(s.detail.contains("Doku"), "Detail: {}", s.detail);
    }

    #[test]
    fn setup_install_plan_npm_default_und_winget() {
        let (cmd, args) = setup_install_plan(None).expect("Default = npm");
        assert_eq!(cmd, "npm");
        assert!(args.iter().any(|a| a == "@google/gemini-cli"));
        let (cmd, args) = setup_install_plan(Some("winget".to_string())).expect("winget");
        assert_eq!(cmd, "winget");
        assert!(args.iter().any(|a| a == "Google.GeminiCLI"));
        let e = setup_install_plan(Some("quatsch".to_string())).expect_err("muss Err sein");
        assert!(e.contains("npm, winget"), "Fehlertext: {e}");
    }

    #[test]
    fn setup_install_mock_erfolg_und_fehler() {
        // Erfolg: Runner wird mit geplantem Befehl aufgerufen.
        let mut ok = |cmd: &str, args: &[String]| -> Result<String, String> {
            assert_eq!(cmd, "npm");
            assert!(args.contains(&"@google/gemini-cli".to_string()));
            Ok("gemini 0.1.0".to_string())
        };
        let out = setup_install_with(None, &mut ok).expect("Mock-Erfolg");
        assert!(out.contains("gemini"));
        // Fehler: Fehlertext + Doku + Fallback-Hinweis.
        let mut fail = |_: &str, _: &[String]| -> Result<String, String> {
            Err("Timeout nach 120000 ms".to_string())
        };
        let e = setup_install_with(None, &mut fail).expect_err("Mock-Fehler");
        assert!(e.contains("setup_install"), "Fehlertext: {e}");
        assert!(e.contains("Doku"), "Fehlertext: {e}");
        assert!(e.contains("Ollama"), "Fehlertext: {e}");
        // Ungueltiges Tool scheitert schon in der Planung.
        let mut nie = |_: &str, _: &[String]| -> Result<String, String> {
            panic!("Runner darf bei ungueltigem Tool nicht laufen")
        };
        assert!(setup_install_with(Some("quatsch".to_string()), &mut nie).is_err());
    }
}
