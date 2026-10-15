// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! cate-stages: Stufen-Weiche Stufe 1 -> 2 -> 3 (Masterplan-Kaskade).
//!
//! - Stufe 1 (deterministisch, ohne AI): Clean-Pass-Filter ueber AST-nahe
//!   Heuristiken (Nesting, Funktionslaenge, Imports). Nur geflaggte Dateien
//!   gehen an Stufe 2; cleane sofort durch mit E0-ok.
//! - Stufe 2 (kleines Modell, Ollama): darf bei Architektur/Komplexitaet nach
//!   Stufe 3 eskalieren. `evidence_proposed` nie > E2, Deny-List-Cap bleibt.
//! - Stufe 3 (Deep Audit): Platzhalter-Trait + Noop-/Config-Implementierung,
//!   kein Netz ausser localhost.
//! - Stufe 4 (Human-in-the-Loop) ist ausserhalb dieses Crates (UI/Review).
use serde::{Deserialize, Serialize};

// ---- Stufe 1: Clean-Pass-Filter ----

/// Schwellwerte Stufe 1. Ueberschreitung eines Werts = Flag -> Stufe 2.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Stage1Thresholds {
    /// max. erlaubte Verschachtelungstiefe (strikt groesser = Flag).
    pub max_nesting: usize,
    /// max. erlaubte Funktionslaenge in Zeilen (strikt groesser = Flag).
    pub max_function_length: usize,
    /// max. erlaubte Import-Anzahl pro Datei (strikt groesser = Flag).
    pub max_imports: usize,
}

impl Default for Stage1Thresholds {
    fn default() -> Self {
        Self {
            max_nesting: 3,
            max_function_length: 50,
            max_imports: 20,
        }
    }
}

/// Ergebnis der Stufe-1-Weiche.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage1Outcome {
    /// true = clean, sofort durch mit E0-ok; false = geflaggt -> Stufe 2.
    pub clean: bool,
    /// Evidence: clean immer E0.
    pub evidence: cate_core::EvidenceLevel,
    /// Flag-Gruende (leer wenn clean).
    pub reasons: Vec<String>,
    /// Kennzahlen zum Zeitpunkt der Entscheidung (fuer Audit/Logs).
    pub nesting: usize,
    pub max_fn_len: usize,
    pub imports: usize,
}

/// Zaehlt Import-Zeilen heuristisch (Rust `use`, JS/TS `import`/`require`,
/// Python `import`/`from`, C `#include`). Kommentare/Zeilen-Strings grob ignoriert.
pub fn count_imports(source: &str) -> usize {
    source
        .lines()
        .map(|l| l.trim())
        .filter(|t| {
            t.starts_with("use ")
                || t.starts_with("import ")
                || t.starts_with("from ")
                || t.starts_with("#include")
                || t.starts_with("require(")
                || (t.starts_with("const ") && t.contains("require("))
        })
        .count()
}

/// Stufe-1-Weiche ueber fertige Metriken + Import-Anzahl.
pub fn stage1_route(
    metrics: &cate_core::FileMetrics,
    imports: usize,
    th: &Stage1Thresholds,
) -> Stage1Outcome {
    let mut reasons = Vec::new();
    if metrics.max_nesting_depth > th.max_nesting {
        reasons.push(format!(
            "nesting {} > {}",
            metrics.max_nesting_depth, th.max_nesting
        ));
    }
    let max_fn_len = metrics
        .functions
        .iter()
        .map(|f| f.length)
        .max()
        .unwrap_or(0);
    if max_fn_len > th.max_function_length {
        reasons.push(format!(
            "function_length {max_fn_len} > {}",
            th.max_function_length
        ));
    }
    if imports > th.max_imports {
        reasons.push(format!("imports {imports} > {}", th.max_imports));
    }
    let clean = reasons.is_empty();
    Stage1Outcome {
        clean,
        evidence: cate_core::EvidenceLevel::E0,
        reasons,
        nesting: metrics.max_nesting_depth,
        max_fn_len,
        imports,
    }
}

/// Komfort: analysiert Source direkt (Metriken + Imports) und routet.
pub fn stage1_scan(path: &str, source: &str, th: &Stage1Thresholds) -> Stage1Outcome {
    let m = cate_core::analyze_file(path, source);
    let imports = count_imports(source);
    stage1_route(&m, imports, th)
}

/// Architektur-Keywords fuer `signals_from_source` (kleingeschrieben, Substring).
const ARCH_KEYWORDS: &[&str] = &[
    "auth",
    "password",
    "passwd",
    "secret",
    "token",
    "crypto",
    "cipher",
    "pickle",
    "deserial",
    "subprocess",
    "socket",
    "sql",
    "http",
    "eval",
    "exec(",
    "shell",
];

/// Leitet Eskalations-Signale deterministisch aus Source + CWE ab
/// (kein Netz, kein Modell — Offline-Pfad und Test-Fixtures).
/// - `architecture_hint`: Deny-CWE (Krypto/Auth/Deserialisierung) oder
///   Architektur-Keyword im Code (Auth-, Krypto-, Prozess-, Netz-Bezug).
/// - `complexity_hint`: eine Stufe-1-Schwelle (Default) ist ueberschritten
///   (Nesting, Funktionslaenge oder Import-Anzahl).
pub fn signals_from_source(source: &str, cwe: &str) -> EscalationSignals {
    let deny = cate_triage::verdict_cap(cwe) == cate_triage::MaxAction::DemoteOnly;
    let lower = source.to_ascii_lowercase();
    let architecture_hint = deny || ARCH_KEYWORDS.iter().any(|k| lower.contains(k));
    let th = Stage1Thresholds::default();
    let m = cate_core::analyze_file("signals.rs", source);
    let max_fn_len = m.functions.iter().map(|f| f.length).max().unwrap_or(0);
    let complexity_hint = m.max_nesting_depth > th.max_nesting
        || max_fn_len > th.max_function_length
        || count_imports(source) > th.max_imports;
    EscalationSignals {
        architecture_hint,
        complexity_hint,
    }
}

// ---- Stufe 2 -> 3: Eskalationsregeln ----

/// Signale des kleinen Modells / der Heuristik fuer eine Eskalation nach Stufe 3.
/// Architektur- oder Komplexitaetsgruende rechtfertigen Deep Audit.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct EscalationSignals {
    /// z.B. schichtuebergreifende Aenderung, neue Schnittstelle, Auth-/Krypto-Bezug.
    pub architecture_hint: bool,
    /// z.B. hohe zyklomatische/inhaltliche Komplexitaet trotz E2-Cap.
    pub complexity_hint: bool,
}

/// Routing-Entscheidung der Stufe 2.
#[derive(Debug, Clone)]
pub struct Stage2Routing {
    /// Normalisierter Vorschlag (Cap + Deny-List angewendet).
    pub proposal: cate_triage::ollama::LlmProposal,
    /// true = an Stufe 3 (Deep Audit) weiterreichen.
    pub escalate_to_stage3: bool,
    /// Maschinenlesbarer Grund der Eskalation (leer wenn keine).
    pub escalation_reason: String,
}

/// Kappt Evidence-Vorschlaege auf max E2 (E3/E4 -> E2). Reine Schutzfunktion,
/// falls ein Pfad nicht ueber `parse_proposal` (das bereits cappt) laeuft.
pub fn cap_evidence(level: &cate_core::EvidenceLevel) -> cate_core::EvidenceLevel {
    match level {
        cate_core::EvidenceLevel::E3 | cate_core::EvidenceLevel::E4 => cate_core::EvidenceLevel::E2,
        other => *other,
    }
}

/// Stufe-2-Routing: parst Modell-Output (Cap E2 + Deny-List-Vorrang stecken in
/// `parse_proposal`), eskaliert danach bei Architektur/Komplexitaet.
/// Deny-List greift zuerst: `suppress` auf Deny-CWE -> `escalate` + Override
/// (kommt bereits als `escalate` aus dem Parser) und erhaelt einen
/// Eskalationsgrund Richtung Stufe 3.
pub fn route_stage2(
    model_output: &str,
    cwe: &str,
    signals: &EscalationSignals,
) -> Result<Stage2Routing, String> {
    let proposal = cate_triage::ollama::parse_proposal(model_output, cwe)?;
    debug_assert!(
        proposal.evidence_proposed == "E0"
            || proposal.evidence_proposed == "E1"
            || proposal.evidence_proposed == "E2",
        "evidence_proposed nie > E2"
    );
    let deny = cate_triage::verdict_cap(cwe) == cate_triage::MaxAction::DemoteOnly;
    let mut escalate = false;
    let mut reason = String::new();
    // 1) Deny-List-Vorrang: hochgestufter suppress-Vorschlag -> Stufe 3.
    if proposal.policy_override && proposal.verdict == "escalate" && deny {
        escalate = true;
        reason = "deny-list: suppress auf Deny-CWE hochgestuft".to_string();
    }
    // 2) Modell-Eskalation bei Architektur/Komplexitaet (kleines Modell darf eskalieren).
    if proposal.verdict == "escalate" && (signals.architecture_hint || signals.complexity_hint) {
        escalate = true;
        let mut parts = Vec::new();
        if signals.architecture_hint {
            parts.push("architektur");
        }
        if signals.complexity_hint {
            parts.push("komplexitaet");
        }
        let why = parts.join("+");
        reason = if reason.is_empty() {
            format!("modell-eskalation ({why})")
        } else {
            format!("{reason}; modell-eskalation ({why})")
        };
    }
    Ok(Stage2Routing {
        proposal,
        escalate_to_stage3: escalate,
        escalation_reason: reason,
    })
}

// ---- Stufe 3: Deep-Audit-Platzhalter ----

/// Kontext fuer den Deep Audit (Stufe 3). Evidence ist per Konstruktion <= E2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditContext {
    pub file: String,
    pub cwe: String,
    pub evidence: cate_core::EvidenceLevel,
    pub reason: String,
}

impl AuditContext {
    /// Baut Kontext; E3/E4 werden auf E2 gekappt (Stufe 3 bestaetigt, statt zu erhoehen).
    pub fn new(file: &str, cwe: &str, evidence: cate_core::EvidenceLevel, reason: &str) -> Self {
        Self {
            file: file.to_string(),
            cwe: cwe.to_string(),
            evidence: cap_evidence(&evidence),
            reason: reason.to_string(),
        }
    }
}

/// Ergebnis des Deep Audits (Platzhalter-Semantik: bestaetigt E2 oder
/// delegiert an Human-in-the-Loop / Stufe 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditOutcome {
    /// "confirmed-e2" | "deferred-human-review".
    pub verdict: String,
    pub evidence: cate_core::EvidenceLevel,
    pub note: String,
}

/// Deep-Audit-Trait (Stufe 3). Implementierungen duerfen kein Netz ausser
/// localhost nutzen (s. `check_localhost_only`).
pub trait DeepAudit {
    fn name(&self) -> &str;
    fn audit(&self, ctx: &AuditContext) -> AuditOutcome;
}

/// Prueft Loopback-Only fuer optionale Audit-Anbindungen.
/// Wiederverwendet die Ollama-Regel (http://localhost|127.0.0.1|::1).
pub fn check_localhost_only(url: &str) -> Result<String, String> {
    cate_triage::ollama::check_base_url(url)
}

/// Noop-Implementierung: bestaetigt nichts, delegiert an Human Review (Stufe 4).
pub struct NoopDeepAudit;

impl DeepAudit for NoopDeepAudit {
    fn name(&self) -> &str {
        "noop"
    }
    fn audit(&self, ctx: &AuditContext) -> AuditOutcome {
        let _ = ctx;
        AuditOutcome {
            verdict: "deferred-human-review".to_string(),
            evidence: cate_core::EvidenceLevel::E0,
            note: "stufe-3-platzhalter: kein deep audit, weiter an human-in-the-loop".to_string(),
        }
    }
}

/// Config-gesteuerte Implementierung: deaktiviert -> wie Noop; aktiviert ->
/// bestaetigt E2-max (Platzhalter ohne Netz; base_url muss Loopback sein).
#[derive(Debug, Clone)]
pub struct ConfigDeepAudit {
    pub enabled: bool,
    pub base_url: String,
}

impl ConfigDeepAudit {
    pub fn new(enabled: bool, base_url: &str) -> Result<Self, String> {
        check_localhost_only(base_url)?;
        Ok(Self {
            enabled,
            base_url: base_url.to_string(),
        })
    }
}

impl DeepAudit for ConfigDeepAudit {
    fn name(&self) -> &str {
        "config"
    }
    fn audit(&self, ctx: &AuditContext) -> AuditOutcome {
        if !self.enabled {
            return NoopDeepAudit.audit(ctx);
        }
        let _ = &self.base_url; // Loopback-validiert, kein Netz im Platzhalter.
        AuditOutcome {
            verdict: "confirmed-e2".to_string(),
            evidence: cap_evidence(&ctx.evidence),
            note: "stufe-3-platzhalter (config, aktiviert): E2-max bestaetigt".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal_json(verdict: &str, ev: &str) -> String {
        format!(r#"{{"verdict":"{verdict}","evidence_proposed":"{ev}","reason":"test"}}"#)
    }

    // --- Stufe 1: Weichen-Logik ---
    #[test]
    fn stage1_clean_passes_with_e0_ok() {
        let src = "fn a() {\n let x = 1;\n}\n";
        let out = stage1_scan("a.rs", src, &Stage1Thresholds::default());
        assert!(out.clean, "clean erwartet: {out:?}");
        assert!(out.reasons.is_empty());
        assert_eq!(out.evidence, cate_core::EvidenceLevel::E0);
    }

    #[test]
    fn stage1_flags_nesting_over_3() {
        let src = "fn a() {\n if x {\n while y {\n if z {\n }\n }\n }\n}\n";
        let out = stage1_scan("a.rs", src, &Stage1Thresholds::default());
        assert!(!out.clean);
        assert!(out.reasons.iter().any(|r| r.starts_with("nesting")));
    }

    #[test]
    fn stage1_flags_long_function() {
        let mut src = String::from("fn big() {\n");
        for i in 0..60 {
            src.push_str(&format!(" let x{i} = {i};\n"));
        }
        src.push_str("}\n");
        let out = stage1_scan("a.rs", &src, &Stage1Thresholds::default());
        assert!(!out.clean);
        assert!(out.reasons.iter().any(|r| r.starts_with("function_length")));
    }

    #[test]
    fn stage1_flags_too_many_imports() {
        let mut src = String::new();
        for i in 0..25 {
            src.push_str(&format!("use crate::m{i};\n"));
        }
        src.push_str("fn a() {}\n");
        let out = stage1_scan("a.rs", &src, &Stage1Thresholds::default());
        assert!(!out.clean);
        assert!(out.reasons.iter().any(|r| r.starts_with("imports")));
    }

    #[test]
    fn stage1_boundary_is_clean() {
        // Exakt an der Schwelle (nesting == 3) bleibt clean (nur > flaggt).
        let src = "fn a() {\n if x {\n while y {\n }\n }\n}\n";
        assert_eq!(cate_core::nesting_depth(src), 3);
        let out = stage1_scan("a.rs", src, &Stage1Thresholds::default());
        assert!(out.clean, "grenze nesting==3 muss clean sein: {out:?}");
    }

    // --- Stufe 2 -> 3: Eskalationspfade ---
    #[test]
    fn stage2_no_escalation_without_signals() {
        let r = route_stage2(
            &proposal_json("confirm", "E1"),
            "CWE-79",
            &EscalationSignals::default(),
        )
        .unwrap();
        assert!(!r.escalate_to_stage3);
        assert_eq!(r.proposal.evidence_proposed, "E1");
    }

    #[test]
    fn stage2_escalates_on_architecture_hint() {
        let r = route_stage2(
            &proposal_json("escalate", "E2"),
            "CWE-79",
            &EscalationSignals {
                architecture_hint: true,
                complexity_hint: false,
            },
        )
        .unwrap();
        assert!(r.escalate_to_stage3);
        assert!(r.escalation_reason.contains("architektur"));
    }

    #[test]
    fn stage2_escalates_on_complexity_hint() {
        let r = route_stage2(
            &proposal_json("escalate", "E2"),
            "CWE-79",
            &EscalationSignals {
                architecture_hint: false,
                complexity_hint: true,
            },
        )
        .unwrap();
        assert!(r.escalate_to_stage3);
        assert!(r.escalation_reason.contains("komplexitaet"));
    }

    #[test]
    fn stage2_caps_evidence_never_above_e2() {
        for ev in ["E3", "E4"] {
            let r = route_stage2(
                &proposal_json("confirm", ev),
                "CWE-79",
                &EscalationSignals::default(),
            )
            .unwrap();
            assert_eq!(r.proposal.evidence_proposed, "E2", "cap verletzt bei {ev}");
        }
        assert_eq!(
            cap_evidence(&cate_core::EvidenceLevel::E4),
            cate_core::EvidenceLevel::E2
        );
        assert_eq!(
            cap_evidence(&cate_core::EvidenceLevel::E1),
            cate_core::EvidenceLevel::E1
        );
    }

    // --- Deny-Vorrang ---
    #[test]
    fn stage2_deny_list_beats_suppress_and_escalates() {
        // suppress auf Deny-CWE -> Parser macht escalate + Override; Weiche -> Stufe 3.
        let r = route_stage2(
            &proposal_json("suppress", "E2"),
            "CWE-328",
            &EscalationSignals::default(),
        )
        .unwrap();
        assert_eq!(r.proposal.verdict, "escalate");
        assert!(r.proposal.policy_override);
        assert!(
            r.escalate_to_stage3,
            "deny-hochstufung muss nach stufe 3: {r:?}"
        );
        assert!(r.escalation_reason.contains("deny-list"));
    }

    #[test]
    fn stage2_deny_vorrang_alle_schreibweisen() {
        for variant in ["CWE-502", "cwe-502", "CWE502", "CWE 502"] {
            let r = route_stage2(
                &proposal_json("suppress", "E1"),
                variant,
                &EscalationSignals::default(),
            )
            .unwrap();
            assert_eq!(
                r.proposal.verdict, "escalate",
                "deny-vorrang fehlt bei {variant}"
            );
            assert!(r.escalate_to_stage3);
        }
    }

    #[test]
    fn stage2_non_deny_suppress_stays_without_escalation() {
        let r = route_stage2(
            &proposal_json("suppress", "E1"),
            "CWE-79",
            &EscalationSignals::default(),
        )
        .unwrap();
        assert_eq!(r.proposal.verdict, "suppress");
        assert!(!r.escalate_to_stage3);
    }

    // --- Stufe 3: Platzhalter ---
    #[test]
    fn stage3_noop_defers_to_human() {
        let ctx = AuditContext::new("a.rs", "CWE-79", cate_core::EvidenceLevel::E2, "r");
        let out = NoopDeepAudit.audit(&ctx);
        assert_eq!(out.verdict, "deferred-human-review");
        assert_eq!(out.evidence, cate_core::EvidenceLevel::E0);
    }

    #[test]
    fn stage3_config_disabled_defers_enabled_confirms_e2max() {
        let off = ConfigDeepAudit::new(false, "http://127.0.0.1:11434").unwrap();
        let ctx = AuditContext::new("a.rs", "CWE-79", cate_core::EvidenceLevel::E2, "r");
        assert_eq!(off.audit(&ctx).verdict, "deferred-human-review");
        let on = ConfigDeepAudit::new(true, "http://localhost:11434").unwrap();
        let out = on.audit(&ctx);
        assert_eq!(out.verdict, "confirmed-e2");
        assert!(out.evidence <= cate_core::EvidenceLevel::E2);
        // E3/E4-Input wird gekappt.
        let ctx2 = AuditContext::new("a.rs", "CWE-79", cate_core::EvidenceLevel::E4, "r");
        assert_eq!(ctx2.evidence, cate_core::EvidenceLevel::E2);
        assert!(on.audit(&ctx2).evidence <= cate_core::EvidenceLevel::E2);
    }

    #[test]
    fn stage3_rejects_non_localhost() {
        assert!(ConfigDeepAudit::new(true, "https://example.com").is_err());
        assert!(ConfigDeepAudit::new(true, "http://192.168.1.1:11434").is_err());
        assert!(check_localhost_only("http://127.0.0.1:11434").is_ok());
    }

    // --- Signale aus Source (deterministisch, offline) ---
    #[test]
    fn signale_eval_und_subprocess_sind_architektur() {
        let s = signals_from_source("def calc(expr: str):\n    return eval(expr)\n", "CWE-94");
        assert!(s.architecture_hint, "eval muss Architektur-Hinweis geben");
        assert!(!s.complexity_hint, "kurze Datei ohne Komplexitaet");
        let s2 = signals_from_source(
            "import subprocess\ndef ping(h):\n    return subprocess.run(h, shell=True)\n",
            "CWE-78",
        );
        assert!(s2.architecture_hint);
    }

    #[test]
    fn signale_deny_cwe_immer_architektur() {
        // Auch ohne Keyword: Deny-CWE (z.B. CWE-328) setzt architecture_hint.
        let s = signals_from_source("x = 1\n", "CWE-328");
        assert!(s.architecture_hint);
        let s2 = signals_from_source("x = 1\n", "CWE-79");
        assert!(!s2.architecture_hint);
        assert!(!s2.complexity_hint);
    }

    #[test]
    fn signale_tiefe_verschachtelung_ist_komplexitaet() {
        let src = "fn a() {\n if x {\n while y {\n if z {\n }\n }\n }\n}\n";
        let s = signals_from_source(src, "CWE-79");
        assert!(s.complexity_hint, "nesting 4 > 3 muss Komplexitaet melden");
    }
}
