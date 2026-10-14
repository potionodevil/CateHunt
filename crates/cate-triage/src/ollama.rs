// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Ollama-Triage-Client (read-only, localhost only).
//!
//! Regeln (PLAN.md Phase 2):
//! - Nur Prompt mit Finding-Kontext, kein Code-Write, kein Netz ausser localhost.
//! - `evidence_proposed` nie hoeher als E2 (E3/E4 nur via Sandbox/Fix-Verifikation).
//! - Deny-List-Check VOR suppress: `suppress` auf Deny-CWE -> `escalate` + Override.
//! - Cache-Anbindung: Fingerprint-Lookup zuerst, kein Modell-Call bei Hit.
//!
//! Transport bewusst std-only (`TcpStream`), damit keine neue Dependency
//! noetig ist. Read-only: einzige Operation ist `POST /api/generate`.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Prompt-Version (im Verdict persistiert, Cache-Invalidierung bei Wechsel).
pub const PROMPT_VERSION: &str = "v1";
/// Default-Modell (lokal via Ollama).
pub const DEFAULT_MODEL: &str = "qwen2.5-coder:7b";
/// Default-Basis-URL (nur Loopback erlaubt).
pub const DEFAULT_BASE_URL: &str = "http://127.0.0.1:11434";

/// Minimaler Finding-Kontext als Prompt-Input (redigiert vor Versand).
#[derive(Debug, Clone)]
pub struct FindingContext {
    pub rule_id: String,
    pub cwe: String,
    pub file: String,
    pub start_line: Option<u32>,
    pub message: String,
    pub code_snippet: String,
}

impl FindingContext {
    /// Fingerprint ueber (rule_id, code_hash, cwe) — Cache-Key.
    pub fn fingerprint(&self) -> String {
        let ch = crate::code_hash(&self.code_snippet);
        crate::fingerprint(&self.rule_id, &ch, &self.cwe)
    }
}

/// Client-Konfiguration (localhost-only wird in `check_base_url` erzwungen).
#[derive(Debug, Clone)]
pub struct OllamaConfig {
    pub base_url: String,
    pub model: String,
    pub prompt_version: String,
    pub timeout_ms: u64,
}

impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            model: DEFAULT_MODEL.to_string(),
            prompt_version: PROMPT_VERSION.to_string(),
            timeout_ms: 30_000,
        }
    }
}

/// Erlaubt nur http://localhost[:port], http://127.0.0.1[:port], http://[::1][:port].
/// Alles andere (https, Remote-Hosts) wird abgelehnt — Default bleibt offline-lokal.
pub fn check_base_url(url: &str) -> Result<String, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("nur http://localhost erlaubt, https/remote abgelehnt: {url}"))?;
    let host = rest.split('/').next().unwrap_or("");
    // Port abtrennen (Vorsicht IPv6 in Klammern).
    let host_only = if let Some(h) = host.strip_prefix('[') {
        h.split(']').next().unwrap_or("")
    } else {
        host.split(':').next().unwrap_or("")
    };
    match host_only {
        "localhost" | "127.0.0.1" | "::1" => Ok(rest.to_string()),
        _ => Err(format!(
            "kein Loopback-Host (nur localhost/127.0.0.1/::1): {url}"
        )),
    }
}

/// Baut den Prompt aus Finding-Kontext. Secrets werden vorher redigiert
/// (cate-core/redact), damit keine Roh-Secrets ans Modell gehen.
pub fn build_prompt(ctx: &FindingContext, model: &str) -> String {
    let _ = model;
    let msg = cate_core::redact::redact_text(&ctx.message);
    let mut snippet = cate_core::redact::redact_text(&ctx.code_snippet);
    if snippet.len() > 2000 {
        snippet.truncate(2000);
    }
    let line = ctx
        .start_line
        .map(|l| l.to_string())
        .unwrap_or_else(|| "?".to_string());
    format!(
        "Du bist ein Security-Triage-Assistent (read-only, du aenderst keinen Code).\n\
         Befund: rule_id={rule} CWE={cwe} Datei={file} Zeile={line}\n\
         Meldung: {msg}\n\
         Codeausschnitt:\n```\n{snippet}\n```\n\
         Antworte AUSSCHLIESSLICH als JSON: \
         {{\"verdict\": \"confirm|escalate|suppress\", \"evidence_proposed\": \"E0|E1|E2\", \"reason\": \"max 280 Zeichen\"}}.\n\
         Regeln: evidence_proposed NIE hoeher als E2. \
         Krypto/AuthN/AuthZ/Deserialisierung (Deny-List) NIE suppressen, sondern escalate.",
        rule = ctx.rule_id,
        cwe = ctx.cwe,
        file = ctx.file,
        line = line,
        msg = msg,
        snippet = snippet
    )
}

/// Vom Modell vorgeschlagenes Ergebnis (nach Cap/Policy normalisiert).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmProposal {
    /// "confirm" | "escalate" | "suppress" (Vokabular aus PLAN.md §3 Cache-Format).
    pub verdict: String,
    /// Nie hoeher als E2 (E3/E4-Vorschlaege werden auf E2 gekappt).
    pub evidence_proposed: String,
    /// Kurzbegruendung, max 280 Zeichen.
    pub reason: String,
    /// true, wenn die Deny-List einen suppress-Vorschlag hochgestuft hat.
    pub policy_override: bool,
}

/// Parst Modell-Output (reines JSON oder Text mit eingebettetem JSON-Objekt),
/// kappt `evidence_proposed` auf max E2 und wendet den Deny-List-Check an:
/// `suppress` auf Deny-CWE -> `escalate` + `policy_override=true`.
pub fn parse_proposal(raw: &str, cwe: &str) -> Result<LlmProposal, String> {
    let json_str = extract_json_object(raw)
        .ok_or_else(|| "kein JSON-Objekt im Modell-Output gefunden".to_string())?;
    let v: serde_json::Value =
        serde_json::from_str(&json_str).map_err(|e| format!("Modell-JSON ungueltig: {e}"))?;
    let verdict_raw = v
        .get("verdict")
        .and_then(|x| x.as_str())
        .ok_or("Feld 'verdict' fehlt")?
        .trim()
        .to_ascii_lowercase();
    let verdict = match verdict_raw.as_str() {
        "confirm" | "open" => "confirm",
        "escalate" | "demote" => "escalate",
        "suppress" | "close" => "suppress",
        other => return Err(format!("unbekannter verdict: {other}")),
    }
    .to_string();
    let ev_raw = v
        .get("evidence_proposed")
        .and_then(|x| x.as_str())
        .ok_or("Feld 'evidence_proposed' fehlt")?
        .trim()
        .to_ascii_uppercase();
    // Cap: nie hoeher als E2.
    let evidence_proposed = match ev_raw.as_str() {
        "E0" => "E0",
        "E1" => "E1",
        "E2" | "E3" | "E4" => "E2",
        other => return Err(format!("unbekannte evidence_proposed: {other}")),
    }
    .to_string();
    let mut reason = v
        .get("reason")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if reason.len() > 280 {
        reason.truncate(280);
    }
    // Deny-List-Check VOR suppress.
    let mut policy_override = false;
    let mut verdict = verdict;
    if verdict == "suppress" && crate::verdict_cap(cwe) == crate::MaxAction::DemoteOnly {
        verdict = "escalate".to_string();
        policy_override = true;
    }
    Ok(LlmProposal {
        verdict,
        evidence_proposed,
        reason,
        policy_override,
    })
}

/// Sucht das erste `{...}`-Objekt im Text (tolerant gegen Prosa um JSON herum).
fn extract_json_object(s: &str) -> Option<String> {
    let start = s.find('{')?;
    let end = s.rfind('}')?;
    if end <= start {
        return None;
    }
    Some(s[start..=end].to_string())
}

/// Ergebnis eines Triage-Laufs mit Cache-Anbindung.
#[derive(Debug, Clone)]
pub struct TriageOutcome {
    pub cache_hit: bool,
    pub record: crate::CacheRecord,
    pub proposal: LlmProposal,
}

/// Reine Entscheidungsfunktion (ohne Netz): parst Modell-Output, wendet
/// Policy an und baut den Cache-Record. `cache` dient dem Hit-Check:
/// gibt es den Fingerprint schon, wird `cache_hit=true` ohne Modell-Parse
/// zurueckgegeben (Caller ueberspringt dann den Modell-Call).
pub fn decide_with_cache(
    cache: &HashMap<String, crate::CacheRecord>,
    ctx: &FindingContext,
    model_output: &str,
    model: &str,
) -> Result<TriageOutcome, String> {
    let fp = ctx.fingerprint();
    if let Some(hit) = crate::lookup(cache, &fp) {
        let proposal = LlmProposal {
            verdict: match hit.verdict.action {
                crate::VerdictAction::Open => "confirm".to_string(),
                crate::VerdictAction::Demote => "escalate".to_string(),
                crate::VerdictAction::Close => "suppress".to_string(),
            },
            evidence_proposed: "E1".to_string(),
            reason: "cache-hit".to_string(),
            policy_override: hit.verdict.policy_override,
        };
        return Ok(TriageOutcome {
            cache_hit: true,
            record: hit.clone(),
            proposal,
        });
    }
    let proposal = parse_proposal(model_output, &ctx.cwe)?;
    let action = match proposal.verdict.as_str() {
        "confirm" => crate::VerdictAction::Open,
        "escalate" => crate::VerdictAction::Demote,
        _ => crate::VerdictAction::Close,
    };
    let mut verdict = crate::Verdict {
        rule_id: ctx.rule_id.clone(),
        cwe: ctx.cwe.clone(),
        code_hash: crate::code_hash(&ctx.code_snippet),
        action,
        severity_after: "medium".to_string(),
        model: model.to_string(),
        prompt_version: PROMPT_VERSION.to_string(),
        tokens_in: 0,
        tokens_out: 0,
        policy_override: proposal.policy_override,
    };
    // Doppelte Absicherung: Policy auch auf Record-Ebene (close auf Deny -> demote).
    crate::apply_policy(&mut verdict);
    let record = crate::CacheRecord {
        fingerprint: fp,
        verdict,
        created_at: "2026-10-14T00:00:00Z".to_string(),
    };
    Ok(TriageOutcome {
        cache_hit: false,
        record,
        proposal,
    })
}

/// Minimaler HTTP-POST via TcpStream (nur localhost, read-only `POST /api/generate`).
/// Gibt den Antwort-Body zurueck. Ollama-Request: {"model","prompt","stream":false}.
pub fn query_ollama(config: &OllamaConfig, prompt: &str) -> Result<String, String> {
    let rest = check_base_url(&config.base_url)?;
    let (hostport, prefix_path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest.as_str(), String::new()),
    };
    let hostport = if hostport.contains(':') {
        hostport.to_string()
    } else {
        format!("{hostport}:80")
    };
    let host = hostport.split(':').next().unwrap_or("127.0.0.1");
    if host != "localhost" && host != "127.0.0.1" && host != "::1" {
        return Err(format!("kein Loopback-Host: {host}"));
    }
    let addr = (host, port_of(&hostport))
        .to_socket_addrs()
        .map_err(|e| format!("localhost nicht aufloesbar: {e}"))?
        .next()
        .ok_or("keine Loopback-Adresse".to_string())?;
    let timeout = Duration::from_millis(config.timeout_ms);
    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("ollama connect: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("timeout: {e}"))?;
    let body = serde_json::json!({
        "model": config.model,
        "prompt": prompt,
        "stream": false,
    })
    .to_string();
    let path = if prefix_path.is_empty() {
        "/api/generate".to_string()
    } else {
        format!("{}/api/generate", prefix_path.trim_end_matches('/'))
    };
    let req = format!(
        "POST {path} HTTP/1.0\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("ollama send: {e}"))?;
    let mut resp = Vec::new();
    stream
        .read_to_end(&mut resp)
        .map_err(|e| format!("ollama recv: {e}"))?;
    let text = String::from_utf8_lossy(&resp).into_owned();
    // Header abtrennen.
    let body_start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let body_text = &text[body_start..];
    // Ollama antwortet {"response": "<modelltext>", ...} — falls JSON, Feld extrahieren.
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body_text) {
        if let Some(r) = v.get("response").and_then(|x| x.as_str()) {
            return Ok(r.to_string());
        }
    }
    Ok(body_text.to_string())
}

fn port_of(hostport: &str) -> u16 {
    hostport
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(80)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(cwe: &str) -> FindingContext {
        FindingContext {
            rule_id: "semgrep:test.rule".into(),
            cwe: cwe.into(),
            file: "src/auth.py".into(),
            start_line: Some(42),
            message: "hartcodiertes Passwort".into(),
            code_snippet: "password = \"hunter2\"\n".into(),
        }
    }

    #[test]
    fn prompt_enthaelt_kontext() {
        let c = ctx("CWE-798");
        let p = build_prompt(&c, DEFAULT_MODEL);
        assert!(p.contains("semgrep:test.rule"), "rule_id fehlt");
        assert!(p.contains("CWE-798"), "CWE fehlt");
        assert!(p.contains("src/auth.py"), "Datei fehlt");
        assert!(p.contains("E2"), "E2-Cap-Hinweis fehlt");
    }

    #[test]
    fn prompt_redigiert_secrets() {
        let mut c = ctx("CWE-798");
        c.code_snippet = "key = \"sk-abcDEF1234567890ABCDEF12\" // geheim\n".into();
        c.message = "leak ghp_abcdefghij1234567890ABCD in log".into();
        let p = build_prompt(&c, DEFAULT_MODEL);
        assert!(
            !p.contains("sk-abcDEF1234567890ABCDEF12"),
            "Secret im Prompt"
        );
        assert!(
            !p.contains("ghp_abcdefghij1234567890ABCD"),
            "Token im Prompt"
        );
    }

    #[test]
    fn evidence_cap_nie_ueber_e2() {
        for ev in ["E0", "E1", "E2", "E3", "E4"] {
            let raw = format!(
                "{{\"verdict\": \"confirm\", \"evidence_proposed\": \"{ev}\", \"reason\": \"ok\"}}"
            );
            let p = parse_proposal(&raw, "CWE-79").unwrap();
            assert!(
                ["E0", "E1", "E2"].contains(&p.evidence_proposed.as_str()),
                "Cap verletzt bei {ev}: {}",
                p.evidence_proposed
            );
        }
        let p = parse_proposal(
            "{\"verdict\": \"confirm\", \"evidence_proposed\": \"E4\", \"reason\": \"ok\"}",
            "CWE-79",
        )
        .unwrap();
        assert_eq!(p.evidence_proposed, "E2");
    }

    #[test]
    fn deny_list_check_vor_suppress() {
        // CWE-328 (Deny): suppress -> escalate + Override.
        let p = parse_proposal(
            "{\"verdict\": \"suppress\", \"evidence_proposed\": \"E1\", \"reason\": \"fp\"}",
            "CWE-328",
        )
        .unwrap();
        assert_eq!(p.verdict, "escalate");
        assert!(p.policy_override);
        // CWE-79 (non-deny): suppress bleibt.
        let p2 = parse_proposal(
            "{\"verdict\": \"suppress\", \"evidence_proposed\": \"E1\", \"reason\": \"fp\"}",
            "CWE-79",
        )
        .unwrap();
        assert_eq!(p2.verdict, "suppress");
        assert!(!p2.policy_override);
    }

    #[test]
    fn deny_check_gilt_fuer_alle_schreibweisen() {
        for variant in ["CWE-502", "cwe-502", "CWE502", "CWE 502"] {
            let p = parse_proposal(
                "{\"verdict\": \"suppress\", \"evidence_proposed\": \"E2\", \"reason\": \"x\"}",
                variant,
            )
            .unwrap();
            assert_eq!(p.verdict, "escalate", "Variante {variant}");
        }
    }

    #[test]
    fn nur_loopback_urls_erlaubt() {
        assert!(check_base_url("http://127.0.0.1:11434").is_ok());
        assert!(check_base_url("http://localhost:11434").is_ok());
        assert!(check_base_url("http://[::1]:11434").is_ok());
        assert!(check_base_url("https://127.0.0.1:11434").is_err());
        assert!(check_base_url("http://example.com:11434").is_err());
        assert!(check_base_url("http://192.168.1.5:11434").is_err());
    }

    #[test]
    fn cache_hit_ohne_modell_parse() {
        let c = ctx("CWE-79");
        let fp = c.fingerprint();
        let mut cache = HashMap::new();
        cache.insert(
            fp.clone(),
            crate::CacheRecord {
                fingerprint: fp,
                verdict: crate::Verdict {
                    rule_id: c.rule_id.clone(),
                    cwe: c.cwe.clone(),
                    code_hash: crate::code_hash(&c.code_snippet),
                    action: crate::VerdictAction::Open,
                    severity_after: "medium".into(),
                    model: "ollama".into(),
                    prompt_version: PROMPT_VERSION.into(),
                    tokens_in: 0,
                    tokens_out: 0,
                    policy_override: false,
                },
                created_at: "2026-10-14T00:00:00Z".into(),
            },
        );
        // Kaputter Modell-Output duerfte bei Hit nie geparst werden.
        let out = decide_with_cache(&cache, &c, "KEIN JSON!!!", "m").unwrap();
        assert!(out.cache_hit);
    }

    #[test]
    fn decide_baut_record_mit_policy() {
        let c = ctx("CWE-798"); // Deny
        let cache = HashMap::new();
        let out = decide_with_cache(
            &cache,
            &c,
            "{\"verdict\": \"suppress\", \"evidence_proposed\": \"E3\", \"reason\": \"sieht harmlos aus\"}",
            "qwen2.5-coder:7b",
        )
        .unwrap();
        assert!(!out.cache_hit);
        assert_eq!(out.proposal.verdict, "escalate");
        assert_eq!(out.proposal.evidence_proposed, "E2");
        assert_eq!(out.record.verdict.action, crate::VerdictAction::Demote);
    }

    #[test]
    fn reason_wird_auf_280_zeichen_begrenzt() {
        let long = "x".repeat(500);
        let raw = format!(
            "{{\"verdict\": \"confirm\", \"evidence_proposed\": \"E1\", \"reason\": \"{long}\"}}"
        );
        let p = parse_proposal(&raw, "CWE-79").unwrap();
        assert!(p.reason.len() <= 280);
    }

    #[test]
    fn unguelitger_output_ist_fehler() {
        assert!(parse_proposal("nur prose ohne json", "CWE-79").is_err());
        assert!(parse_proposal(
            "{\"verdict\": \"???\", \"evidence_proposed\": \"E1\"}",
            "CWE-79"
        )
        .is_err());
        assert!(parse_proposal("{\"verdict\": \"confirm\"}", "CWE-79").is_err());
    }
}
