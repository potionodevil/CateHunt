//! cate-triage: Deny-List-Policy + Verdict-Cache (Phase 2).
//!
//! Prinzip aus VALIDATION.md: Krypto / AuthN / AuthZ / Deserialisierung
//! duerfen per KI nie geschlossen, nur herabgestuft werden.
//! `apply_policy` erzwingt das: ein `close`-Verdict auf einer Deny-CWE
//! wird zu `demote` + `policy_override: true`.
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// moegliche Aktionen eines Triage-Verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictAction {
    Open,
    Demote,
    Close,
}

/// maximales erlaubtes Ergebnis je CWE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxAction {
    Close,
    DemoteOnly,
}

/// Deny-List: CWEs, die nie automatisch geschlossen werden duerfen.
/// Quelle: docs/VALIDATION.md Abschnitt 2.
pub fn verdict_cap(cwe: &str) -> MaxAction {
    let n = normalize_cwe(cwe);
    match n.as_str() {
        // Schwache Krypto
        "327" | "328" | "326" | "331" | "338" |
        // Hardcoded Secrets
        "259" | "798" | "321" |
        // AuthN / Session
        "287" | "384" | "613" | "620" |
        // AuthZ
        "639" | "862" | "863" |
        // Deserialisierung
        "502" | "915" => MaxAction::DemoteOnly,
        _ => MaxAction::Close,
    }
}

/// "CWE-328" -> "328", "cwe-79" -> "79".
pub fn normalize_cwe(cwe: &str) -> String {
    let t = cwe.trim().to_ascii_uppercase();
    t.strip_prefix("CWE-")
        .or_else(|| t.strip_prefix("CWE"))
        .unwrap_or(&t)
        .trim()
        .to_string()
}

/// ein Triage-Verdict vor Policy-Anwendung.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub rule_id: String,
    pub cwe: String,
    pub code_hash: String,
    pub action: VerdictAction,
    pub severity_after: String,
    pub model: String,
    pub prompt_version: String,
    pub tokens_in: u32,
    pub tokens_out: u32,
    pub policy_override: bool,
}

/// wendet die Deny-List an: `close` auf Deny-CWE -> `demote` + Override-Flag.
/// gibt true zurueck, wenn die Policy eingegriffen hat.
pub fn apply_policy(v: &mut Verdict) -> bool {
    if v.action == VerdictAction::Close && verdict_cap(&v.cwe) == MaxAction::DemoteOnly {
        v.action = VerdictAction::Demote;
        v.policy_override = true;
        if v.severity_after == "high" {
            v.severity_after = "medium".to_string();
        }
        return true;
    }
    false
}

/// Fingerprint = hex(hash(rule_id | code_hash | cwe-normalisiert)).
/// Schema: docs/VALIDATION.md 3.1 (dort sha256; hier 64-bit-Stub,
/// Upgrade auf sha256 vor produktivem Benchmark-Einsatz).
pub fn fingerprint(rule_id: &str, code_hash: &str, cwe: &str) -> String {
    let mut h = DefaultHasher::new();
    rule_id.hash(&mut h);
    code_hash.hash(&mut h);
    normalize_cwe(cwe).hash(&mut h);
    format!("{:016x}", h.finish())
}

/// normalisiert Code vor dem Hash (whitespace/comments collapse),
/// damit triviale Umbauten den Cache treffen.
pub fn normalize_code(source: &str) -> String {
    source
        .lines()
        .map(|l| {
            let no_comment = match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            };
            no_comment
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Code-Hash ueber normalisierten Code.
pub fn code_hash(source: &str) -> String {
    let mut h = DefaultHasher::new();
    normalize_code(source).hash(&mut h);
    format!("{:016x}", h.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_list_blocks_close_on_crypto() {
        assert_eq!(verdict_cap("CWE-328"), MaxAction::DemoteOnly);
        assert_eq!(verdict_cap("CWE-798"), MaxAction::DemoteOnly);
        assert_eq!(verdict_cap("CWE-502"), MaxAction::DemoteOnly);
        assert_eq!(verdict_cap("CWE-862"), MaxAction::DemoteOnly);
    }

    #[test]
    fn non_deny_cwe_may_close() {
        assert_eq!(verdict_cap("CWE-79"), MaxAction::Close);
        assert_eq!(verdict_cap("CWE-89"), MaxAction::Close);
        assert_eq!(verdict_cap("CWE-22"), MaxAction::Close);
    }

    #[test]
    fn policy_downgrades_close_to_demote() {
        let mut v = Verdict {
            rule_id: "semgrep:java.crypto.md5".into(),
            cwe: "CWE-328".into(),
            code_hash: "abc".into(),
            action: VerdictAction::Close,
            severity_after: "high".into(),
            model: "test".into(),
            prompt_version: "v1".into(),
            tokens_in: 0,
            tokens_out: 0,
            policy_override: false,
        };
        assert!(apply_policy(&mut v));
        assert_eq!(v.action, VerdictAction::Demote);
        assert!(v.policy_override);
        assert_eq!(v.severity_after, "medium");
    }

    #[test]
    fn policy_leaves_non_deny_close_alone() {
        let mut v = Verdict {
            rule_id: "r".into(),
            cwe: "CWE-79".into(),
            code_hash: "abc".into(),
            action: VerdictAction::Close,
            severity_after: "high".into(),
            model: "test".into(),
            prompt_version: "v1".into(),
            tokens_in: 0,
            tokens_out: 0,
            policy_override: false,
        };
        assert!(!apply_policy(&mut v));
        assert_eq!(v.action, VerdictAction::Close);
    }

    #[test]
    fn fingerprint_stable_and_cwe_case_insensitive() {
        let a = fingerprint("rule", "hash", "CWE-328");
        let b = fingerprint("rule", "hash", "cwe-328");
        assert_eq!(a, b);
        assert_ne!(a, fingerprint("other-rule", "hash", "CWE-328"));
    }

    #[test]
    fn code_normalization_hits_cache_on_trivial_changes() {
        let a = "let x = 1;  // kommentar\n\nlet y = 2;";
        let b = "let x = 1;\nlet y = 2; // anderer kommentar";
        assert_eq!(code_hash(a), code_hash(b));
    }
}
