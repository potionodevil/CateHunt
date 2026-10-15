// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Severity-Leiter (L3 De-Eskalation + S-5 Korrelation).
//!
//! Ein reiner Level-String (`critical > high > medium > low > note`),
//! identisch zum Vokabular von `cate_triage::Verdict::severity_after`
//! bzw. `cate_core::ScoredFinding::level`. Unbekannte Strings werden
//! deterministisch wie `note` gewertet (am niedrigsten).
use serde::{Deserialize, Serialize};

/// Kanonische Namen der Severity-Leiter, aufsteigend nach Rang
/// (`severity_rank(note) == 0`).
pub const SEVERITY_LADDER: [&str; 5] = ["note", "low", "medium", "high", "critical"];

/// Deterministischer Rang einer Severity (hoeher = kritischer).
/// Unbekannte/leere Strings -> 0 (wie `note`).
pub fn severity_rank(severity: &str) -> u8 {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Kanonischer Name zu einem Rang aus [`severity_rank`].
fn canonical(rank: u8) -> &'static str {
    SEVERITY_LADDER[rank as usize]
}

/// Einen Rang genau eine Stufe runterstufen (criticality bottom = `note`).
pub fn demote_severity(severity: &str) -> String {
    let rank = severity_rank(severity);
    if rank == 0 {
        "note".to_string()
    } else {
        canonical(rank - 1).to_string()
    }
}

/// S-5-Ergebnis: zwei Adapter mit Severity-Angaben.
///
/// Regel aus docs/CHECK_LAYERING.md: "deterministisch hoehere gewinnt +
/// `contested:true` (S-5), nie still mitteln". Bei gleichem Rang ist
/// `contested:false`; unterschiedliche Schreibweisen desselben Rangs
/// (`Medium` vs. `medium`) werden auf den kanonischen Namen normiert,
/// unterschiedliche unbekannte Strings (`info` vs. `warning`) werden
/// deterministisch lexikalisch entschieden.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContestedSeverity {
    /// die (deterministisch) gewinnende Severity.
    pub severity: String,
    /// true, wenn die Severities wirklich gegensaetzlich waren.
    pub contested: bool,
}

/// Zwei Adapter-Severities auflösen: hoeherer Rang gewinnt mit
/// `contested:true`; gleicher Rang ohne Konflikt.
pub fn resolve_contested(a: &str, b: &str) -> ContestedSeverity {
    let ra = severity_rank(a);
    let rb = severity_rank(b);
    if ra != rb {
        let (higher, _) = if ra > rb { (a, b) } else { (b, a) };
        return ContestedSeverity {
            severity: canonical(severity_rank(higher)).to_string(),
            contested: true,
        };
    }
    let severity = if ra > 0 {
        canonical(ra).to_string()
    } else {
        // Beide unbekannt (Rang 0): deterministisch lexikalisch.
        let la = a.trim().to_ascii_lowercase();
        let lb = b.trim().to_ascii_lowercase();
        if la <= lb {
            la
        } else {
            lb
        }
    };
    ContestedSeverity {
        severity,
        contested: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rank_ladder_is_deterministic() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("high") > severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("low"));
        assert!(severity_rank("low") > severity_rank("note"));
        assert_eq!(severity_rank("note"), 0);
        assert_eq!(severity_rank("was-ich-nicht-kenn"), 0);
        assert_eq!(severity_rank(""), 0);
        // Gross-/Kleinschreibung und Whitespace sind egal.
        assert_eq!(severity_rank(" HIGH "), severity_rank("high"));
    }

    #[test]
    fn demote_steps_down_one_level() {
        assert_eq!(demote_severity("critical"), "high");
        assert_eq!(demote_severity("high"), "medium");
        assert_eq!(demote_severity("medium"), "low");
        assert_eq!(demote_severity("low"), "note");
    }

    #[test]
    fn demote_bottoms_out_at_note() {
        assert_eq!(demote_severity("note"), "note");
        assert_eq!(demote_severity("unbekannt"), "note");
        // Kein Unterlaufen unter die note-Kategorie.
        assert_eq!(demote_severity("note"), demote_severity("note"));
    }

    #[test]
    fn contested_higher_wins_with_flag() {
        let r = resolve_contested("high", "medium");
        assert_eq!(r.severity, "high");
        assert!(r.contested);
        // Reihenfolge egal (deterministisch, nie still mitteln).
        let flipped = resolve_contested("medium", "high");
        assert_eq!(flipped, r);
    }

    #[test]
    fn equal_ranks_are_not_contested() {
        let r = resolve_contested("medium", "Medium");
        assert_eq!(r.severity, "medium");
        assert!(!r.contested);
        let same = resolve_contested("high", "high");
        assert_eq!(same.severity, "high");
        assert!(!same.contested);
    }

    #[test]
    fn unknown_beats_nothing() {
        let r = resolve_contested("info", "low");
        assert_eq!(r.severity, "low");
        assert!(r.contested);
        // Zwei unbekannte Strings: deterministisch lexikalisch, kein Konflikt.
        let r = resolve_contested("warning", "info");
        assert_eq!(r.severity, "info");
        assert!(!r.contested);
        assert_eq!(
            resolve_contested("info", "warning"),
            resolve_contested("warning", "info")
        );
    }

    #[test]
    fn result_serializes_roundtrip() {
        let r = resolve_contested("high", "low");
        let json = serde_json::to_string(&r).unwrap();
        let back: ContestedSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}
