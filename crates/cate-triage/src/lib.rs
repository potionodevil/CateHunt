// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! cate-triage: Deny-List-Policy + Verdict-Cache (Phase 2).
//!
//! Prinzip aus VALIDATION.md: Krypto / AuthN / AuthZ / Deserialisierung
//! duerfen per KI nie geschlossen, nur herabgestuft werden.
//! `apply_policy` erzwingt das: ein `close`-Verdict auf einer Deny-CWE
//! wird zu `demote` + `policy_override: true`.
pub mod deep_engines;
pub mod gemini;
pub mod ollama;
pub mod pipeline;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::Path;

/// moegliche Aktionen eines Triage-Verdicts.
/// Serialisiert kleingeschrieben (`open|demote|close`), damit JSONL-Cache
/// und Harness-Fixtures dasselbe Vokabular nutzen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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

/// "CWE-328" -> "328", "cwe-79" -> "79", "CWE328"/"CWE 328" -> ebenso.
pub fn normalize_cwe(cwe: &str) -> String {
    let t = cwe.trim().to_ascii_uppercase();
    let rest = t
        .strip_prefix("CWE-")
        .or_else(|| t.strip_prefix("CWE "))
        .or_else(|| t.strip_prefix("CWE"))
        .unwrap_or(&t);
    rest.trim()
        .chars()
        .filter(|c| *c != '-' && *c != ' ')
        .collect()
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
            no_comment.split_whitespace().collect::<Vec<_>>().join(" ")
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

/// Ein Cache-Eintrag = eine JSONL-Zeile im Verdict-Cache.
/// Top-Level-Keys `fingerprint` + `action` (geflattet) bleiben
/// harness-kompatibel (`harness.py` liest genau diese Keys).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheRecord {
    pub fingerprint: String,
    #[serde(flatten)]
    pub verdict: Verdict,
    #[serde(default)]
    pub created_at: String,
}

/// parst Aktions-Aliase aus CLI/Harness-Vokabular:
/// `open|confirm`, `demote|escalate`, `close|suppress`.
pub fn parse_action(s: &str) -> Option<VerdictAction> {
    match s.trim().to_ascii_lowercase().as_str() {
        "open" | "confirm" => Some(VerdictAction::Open),
        "demote" | "escalate" => Some(VerdictAction::Demote),
        "close" | "suppress" => Some(VerdictAction::Close),
        _ => None,
    }
}

/// Cache-Hit ohne Modell-Call: Nachschlagen per Fingerprint.
pub fn lookup<'a>(
    cache: &'a HashMap<String, CacheRecord>,
    fingerprint: &str,
) -> Option<&'a CacheRecord> {
    cache.get(fingerprint)
}

/// laedt den JSONL-Cache; fehlende Datei = leerer Cache (kein Fehler).
/// Leere Zeilen werden uebersprungen, kaputte Zeilen sind Fehler.
pub fn load_cache(path: &Path) -> io::Result<HashMap<String, CacheRecord>> {
    let mut out = HashMap::new();
    if !path.exists() {
        return Ok(out);
    }
    let content = std::fs::read_to_string(path)?;
    for (n, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let rec: CacheRecord = serde_json::from_str(line).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}:{}: {e}", path.display(), n + 1),
            )
        })?;
        out.insert(rec.fingerprint.clone(), rec);
    }
    Ok(out)
}

/// haengt ein Verdict als JSONL-Zeile an; wendet vorher `apply_policy` an
/// (Deny-CWE: `close`/`suppress` -> `demote`/`escalate` + Override-Flag).
/// Rueckgabe: true, wenn die Policy eingegriffen hat.
pub fn store_verdict(path: &Path, record: &CacheRecord) -> io::Result<bool> {
    let mut rec = record.clone();
    let overridden = apply_policy(&mut rec.verdict);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut line = serde_json::to_string(&rec)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    line.push('\n');
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    Ok(overridden)
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

    #[test]
    fn deny_list_blocks_close_on_all_deny_cwes() {
        // Negativ-Test: close auf JEDER Deny-CWE muss zu demote + Override werden.
        let deny = [
            "327", "328", "326", "331", "338", "259", "798", "321", "287", "384", "613", "620",
            "639", "862", "863", "502", "915",
        ];
        assert_eq!(deny.len(), 17);
        for cwe in deny {
            assert_eq!(verdict_cap(&format!("CWE-{cwe}")), MaxAction::DemoteOnly);
            let mut v = Verdict {
                rule_id: "test-rule".into(),
                cwe: format!("CWE-{cwe}"),
                code_hash: "abc".into(),
                action: VerdictAction::Close,
                severity_after: "high".into(),
                model: "test".into(),
                prompt_version: "v1".into(),
                tokens_in: 0,
                tokens_out: 0,
                policy_override: false,
            };
            assert!(apply_policy(&mut v), "policy griff nicht ein bei {cwe}");
            assert_eq!(v.action, VerdictAction::Demote);
            assert!(v.policy_override);
        }
    }

    #[test]
    fn cwe_spellings_normalize_to_same_cap() {
        for variant in [
            "CWE-328",
            "cwe-328",
            "CWE328",
            "cwe328",
            "  CWE-328  ",
            "CWE 328",
        ] {
            assert_eq!(normalize_cwe(variant), "328", "Variante: {variant}");
            assert_eq!(verdict_cap(variant), MaxAction::DemoteOnly);
        }
        // Leere/Unbekannte CWE faellt auf Close-Cap zurueck, crasht aber nicht.
        assert_eq!(verdict_cap(""), MaxAction::Close);
        assert_eq!(verdict_cap("CWE-9999"), MaxAction::Close);
    }

    #[test]
    fn empty_code_is_stable() {
        assert_eq!(normalize_code(""), "");
        assert_eq!(normalize_code("   \n  // nur kommentar\n  "), "");
        assert_eq!(code_hash(""), code_hash(""));
        assert_eq!(code_hash(""), code_hash("// nur kommentar"));
    }

    #[test]
    fn unicode_code_does_not_panic_and_is_stable() {
        let a = "# Gr\u{00fc}\u{00df}e \u{1f510}\npasswort = \"s\u{00fc}\u{00df}\u{00e9}123\"  // Kommentar \u{00e4}\u{00f6}\u{00fc}\n";
        let b = "# Gr\u{00fc}\u{00df}e \u{1f510}\npasswort   =   \"s\u{00fc}\u{00df}\u{00e9}123\" // anderer Kommentar";
        assert_eq!(code_hash(a), code_hash(b));
        assert_ne!(code_hash(a), code_hash(""));
        assert_ne!(code_hash(a), code_hash("v\u{00f6}llig anderer code"));
    }
}
