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
pub mod pins;
pub mod pipeline;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
///
/// `provenance` ist die optionale AI-BOM-Herkunft (Spez: docs/AI_BOM.md).
/// Fehlt das Feld im JSON, wird es per serde-default zu `None`
/// (abwaertskompatibel, alte Cache-Zeilen bleiben lesbar); `None` wird
/// beim Serialisieren weggelassen (`skip_serializing_if`), damit
/// Cache-/Harness-Formate byte-stabil bleiben.
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<cate_core::ProvenanceRecord>,
}

impl Verdict {
    /// Haengt eine Provenienz an (Builder-Stil, fuer CLI/MCP-Verdrahtung).
    pub fn with_provenance(mut self, provenance: cate_core::ProvenanceRecord) -> Self {
        self.provenance = Some(provenance);
        self
    }

    /// Haengt eine Provenienz an (mutable Variante).
    pub fn attach_provenance(&mut self, provenance: cate_core::ProvenanceRecord) {
        self.provenance = Some(provenance);
    }
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

/// Fingerprint = `sha256(rule_id | code_hash | CWE-normalisiert)` als Hex
/// (64 Zeichen), delegiert an `cate_core::fingerprint` (Schema
/// `cate_core::HASH_SCHEME`). CWE wird via `normalize_cwe` auf die Nummer
/// reduziert (`CWE-328` == `cwe-328`); Werte des alten 64-bit-Stubs
/// (16 Hex-Zeichen) treffen nie (`is_legacy_hash`).
pub fn fingerprint(rule_id: &str, code_hash: &str, cwe: &str) -> String {
    cate_core::fingerprint(rule_id, code_hash, &normalize_cwe(cwe))
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

/// Code-Hash ueber normalisierten Code: `sha256(normalize_code(source))`
/// als Hex (64 Zeichen), delegiert an `cate_core::sha256_hex`.
pub fn code_hash(source: &str) -> String {
    cate_core::sha256_hex(&normalize_code(source))
}

/// Cache-Format-Version der JSONL-Persistenz (`cache.jsonl`).
/// 1 = Aera der 64-bit-`DefaultHasher`-Hashes (legacy, nie ein Hit);
/// 2 = sha256 (`cate_core::HASH_SCHEME`). `store_verdict` stempelt neu
/// geschriebene Zeilen mit dieser Version; `load_cache` verwirft Zeilen
/// mit anderer Version (alte Caches werden zum Miss, nie zum stillen Hit).
pub const CACHE_FORMAT_VERSION: u32 = 2;

/// Ein Cache-Eintrag = eine JSONL-Zeile im Verdict-Cache.
/// Top-Level-Keys `fingerprint` + `action` (geflattet) bleiben
/// harness-kompatibel (`harness.py` liest genau diese Keys).
/// `format_version` steuert die Migration: Zeilen ohne Feld (legacy)
/// parsen per Default zu 0 und werden von `load_cache` verworfen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheRecord {
    pub fingerprint: String,
    #[serde(flatten)]
    pub verdict: Verdict,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub format_version: u32,
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
/// Legacy-Anfragen (16-stellige 64-bit-Hashes) oder Records mit Legacy-
/// Fingerprint / fremder `format_version` sind nie ein Hit, sondern Miss.
pub fn lookup<'a>(
    cache: &'a HashMap<String, CacheRecord>,
    fingerprint: &str,
) -> Option<&'a CacheRecord> {
    if cate_core::is_legacy_hash(fingerprint) {
        return None;
    }
    let rec = cache.get(fingerprint)?;
    if cate_core::is_legacy_hash(&rec.fingerprint) {
        return None;
    }
    if rec.format_version != CACHE_FORMAT_VERSION {
        return None;
    }
    Some(rec)
}

/// laedt den JSONL-Cache; fehlende Datei = leerer Cache (kein Fehler).
/// Leere Zeilen werden uebersprungen, kaputte Zeilen sind Fehler.
/// Zeilen mit Legacy-Fingerprint oder fremder `format_version` werden
/// still verworfen (alte Caches = Miss, nie stiller Hit).
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
        if cate_core::is_legacy_hash(&rec.fingerprint) {
            continue;
        }
        if rec.format_version != CACHE_FORMAT_VERSION {
            continue;
        }
        out.insert(rec.fingerprint.clone(), rec);
    }
    Ok(out)
}

/// haengt ein Verdict als JSONL-Zeile an; wendet vorher `apply_policy` an
/// (Deny-CWE: `close`/`suppress` -> `demote`/`escalate` + Override-Flag)
/// und stempelt `format_version = CACHE_FORMAT_VERSION`.
/// Rueckgabe: true, wenn die Policy eingegriffen hat.
pub fn store_verdict(path: &Path, record: &CacheRecord) -> io::Result<bool> {
    let mut rec = record.clone();
    rec.format_version = CACHE_FORMAT_VERSION;
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
            provenance: None,
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
            provenance: None,
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
    fn sha256_known_vektoren() {
        // cate_core::sha256_hex("") (RFC-Leervektor).
        assert_eq!(
            code_hash(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // normalize_code laesst Einzeiler unveraendert: sha256("let x = 1;").
        assert_eq!(
            code_hash("let x = 1;"),
            "aad7378dfeb851703927a534da47d0d02be7f54cf8c1751a37734d515811dafe"
        );
        // fingerprint("r","h","CWE-79") = sha256("r|h|79").
        assert_eq!(
            fingerprint("r", "h", "CWE-79"),
            "3ec6beb0f409ec2cf582b45e0761a4de28f624cc82effdc5a5c34d665b778ece"
        );
        // 64 Hex-Zeichen, kein Legacy-Format.
        for v in [code_hash("x"), fingerprint("r", "h", "CWE-79")] {
            assert_eq!(v.len(), 64);
            assert!(!cate_core::is_legacy_hash(&v));
        }
        // CWE-Schreibweisen (mit/ohne Prefix, Case) landen auf einem Key.
        assert_eq!(
            fingerprint("r", "h", "CWE-79"),
            fingerprint("r", "h", "cwe79")
        );
    }

    #[test]
    fn legacy_lookup_ist_miss_nie_hit() {
        let legacy_fp = "0123456789abcdef";
        assert!(cate_core::is_legacy_hash(legacy_fp));
        let mut cache = HashMap::new();
        cache.insert(
            legacy_fp.to_string(),
            CacheRecord {
                fingerprint: legacy_fp.into(),
                verdict: Verdict {
                    rule_id: "r".into(),
                    cwe: "CWE-79".into(),
                    code_hash: legacy_fp.into(),
                    action: VerdictAction::Close,
                    severity_after: "high".into(),
                    model: "test".into(),
                    prompt_version: "v1".into(),
                    tokens_in: 0,
                    tokens_out: 0,
                    policy_override: false,
                    provenance: None,
                },
                created_at: "2026-10-14T00:00:00Z".into(),
                format_version: 0,
            },
        );
        assert!(lookup(&cache, legacy_fp).is_none());
        let neu = fingerprint("r", "h", "CWE-79");
        assert!(lookup(&cache, &neu).is_none());
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
                provenance: None,
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
