// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Deep-Engines Stufe 3 (Opt-in): installierte Coding-Agents headless als Subprozess.
//!
//! - `opencode run "<prompt>" --format json` (Engine::Opencode)
//! - `claude -p "<prompt>" --output-format json` (Engine::Claude)
//!
//! Routing-Doku (Stufenmodell):
//! - Stufe 1 (default, offline): Ollama localhost (`crate::ollama`) — klein/lokal,
//!   keine Kosten, niedrigste Latenz, kein Opt-in noetig.
//! - Stufe 2 (default wenn verfuegbar): Gemini CLI (`crate::gemini`) — User-Credentials.
//! - Stufe 3 (expliziter Opt-in): Deep-Engine fuer schwere Faelle (grosse/unsichere
//!   Befunde, Deny-CWE mit unklarem Proposal). Groessere Modelle = bessere Qualitaet,
//!   aber: **Kosten** (API-Abrechnung des jeweiligen Anbieters), **Latenz** (10s bis
//!   Minuten statt ms), **Netz** (Cloud statt localhost). Deshalb NIE Default:
//!   Caller waehlt Stufe 3 pro Finding (z.B. Flag `--deep` / Config `deep: true`)
//!   und weist im Log Kosten-/Latenz-Hinweis aus (`COST_LATENCY_NOTE`).
//!
//! Regeln wie `ollama`/`gemini`: Prompt vorher redigieren (cate-core/redact),
//! `evidence_proposed` nie hoeher als E2, Deny-Check VOR suppress,
//! Cache-Lookup zuerst. Jede `DeepError`-Nachricht endet mit Ollama-Fallback-Hinweis.
use std::collections::HashMap;
use std::io::ErrorKind;
use std::process::Command;
use std::time::{Duration, Instant};

/// Prompt-Version (im Verdict persistiert, Cache-Invalidierung bei Wechsel).
pub const PROMPT_VERSION: &str = "v1";
/// Kosten-/Latenz-Hinweis fuer Logs/CLI-Ausgabe bei Stufe-3-Nutzung.
pub const COST_LATENCY_NOTE: &str =
    "Stufe 3 (Opt-in): Cloud-Modell — API-Kosten + hohe Latenz moeglich; Default bleibt Ollama/Gemini.";
/// Ollama-Fallback-Hinweis (jede Fehlermeldung).
pub const OLLAMA_FALLBACK_HINT: &str =
    "Fallback: Ollama-Offline-Modus nutzen (cate-triage::ollama, localhost-only).";

/// Deep-Engine-Auswahl.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    Opencode,
    Claude,
}

impl std::fmt::Display for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Opencode => write!(f, "opencode"),
            Self::Claude => write!(f, "claude"),
        }
    }
}

/// Client-Konfiguration (Opt-in: Engine + CLI-Name + optionales Modell + Timeout).
#[derive(Debug, Clone)]
pub struct DeepConfig {
    pub engine: Engine,
    pub cli: String,
    pub model: Option<String>,
    pub timeout_ms: u64,
    pub prompt_version: String,
}

impl DeepConfig {
    pub fn opencode() -> Self {
        Self {
            engine: Engine::Opencode,
            cli: "opencode".to_string(),
            model: None,
            timeout_ms: 180_000,
            prompt_version: PROMPT_VERSION.to_string(),
        }
    }
    pub fn claude() -> Self {
        Self {
            engine: Engine::Claude,
            cli: "claude".to_string(),
            model: None,
            timeout_ms: 180_000,
            prompt_version: PROMPT_VERSION.to_string(),
        }
    }
}

/// Saubere Fehlerfaelle mit Ollama-Fallback-Hinweis (wie Gemini-Wrapper).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeepError {
    CliMissing(String),
    NotLoggedIn(String),
    Timeout(String),
    Parse(String),
    Other(String),
}

impl DeepError {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::CliMissing(_) => "cli-missing",
            Self::NotLoggedIn(_) => "not-logged-in",
            Self::Timeout(_) => "timeout",
            Self::Parse(_) => "parse",
            Self::Other(_) => "other",
        }
    }
    pub fn detail(&self) -> &str {
        match self {
            Self::CliMissing(s)
            | Self::NotLoggedIn(s)
            | Self::Timeout(s)
            | Self::Parse(s)
            | Self::Other(s) => s,
        }
    }
}

impl std::fmt::Display for DeepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "deep-engine {}: {}. {OLLAMA_FALLBACK_HINT}",
            self.kind(),
            self.detail()
        )
    }
}
impl std::error::Error for DeepError {}

/// Gleiches Proposal-Format wie ollama/gemini (E2-Cap, Deny-Check, Cache).
pub use crate::ollama::{FindingContext, LlmProposal, TriageOutcome};

/// Baut den Prompt (redigiert, identische Regeln wie ollama/gemini).
pub fn build_prompt(ctx: &FindingContext, model: &str) -> String {
    crate::ollama::build_prompt(ctx, model)
}

/// CLI-Argumente je Engine:
/// - opencode: `opencode run [-m <model>] --format json "<prompt>"`
/// - claude: `claude -p [--model <model>] --output-format json "<prompt>"`
pub fn build_args(config: &DeepConfig, prompt: &str) -> Vec<String> {
    match config.engine {
        Engine::Opencode => {
            let mut a = vec!["run".to_string()];
            if let Some(m) = config.model.as_deref().filter(|m| !m.is_empty()) {
                a.push("-m".to_string());
                a.push(m.to_string());
            }
            a.push("--format".to_string());
            a.push("json".to_string());
            a.push(prompt.to_string());
            a
        }
        Engine::Claude => {
            let mut a = vec!["-p".to_string()];
            if let Some(m) = config.model.as_deref().filter(|m| !m.is_empty()) {
                a.push("--model".to_string());
                a.push(m.to_string());
            }
            a.push("--output-format".to_string());
            a.push("json".to_string());
            a.push(prompt.to_string());
            a
        }
    }
}

/// Roh-Ergebnis eines CLI-Laufs (mockbar fuer Tests).
#[derive(Debug, Clone)]
pub struct CliOutput {
    pub status_ok: bool,
    pub stdout: String,
    pub stderr: String,
}

fn looks_like_login_error(status_ok: bool, combined: &str) -> bool {
    if status_ok {
        return false;
    }
    let l = combined.to_ascii_lowercase();
    [
        "not logged in",
        "not authenticated",
        "login required",
        "please login",
        "please run",
        "login",
        "api key",
        "apikey",
        "unauthorized",
        "unauthenticated",
        "permission denied",
        "invalid credential",
        "expired credential",
        "billing",
        "quota",
    ]
    .iter()
    .any(|m| l.contains(m))
}

/// Extrahiert den Modelltext aus Engine-JSON. Versteht:
/// - flache Felder: response/output/result/text/content/message/answer
/// - claude-Form: `{"result": "..."}` / `{"content": [{"text": "..."}]}`
/// - opencode-Form: `{"output": "..."}` / `{"response": ...}` / Arrays
/// - reinen String.
pub fn parse_cli_json(stdout: &str) -> Result<String, DeepError> {
    let v: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|e| DeepError::Parse(format!("CLI-JSON ungueltig: {e}")))?;
    if let Some(s) = pick_text(&v) {
        if s.trim().is_empty() {
            return Err(DeepError::Other("CLI-Antwort leer".to_string()));
        }
        return Ok(s);
    }
    Err(DeepError::Parse(
        "kein Modelltext im CLI-JSON gefunden".to_string(),
    ))
}

fn pick_text(v: &serde_json::Value) -> Option<String> {
    if let Some(s) = v.as_str() {
        return Some(s.to_string());
    }
    if let Some(o) = v.as_object() {
        for key in [
            "response", "output", "result", "text", "content", "message", "answer",
        ] {
            if let Some(x) = o.get(key) {
                if let Some(s) = x.as_str() {
                    return Some(s.to_string());
                }
                if x.is_object() || x.is_array() {
                    // content: [{text: ...}] (Claude-Form)
                    if let Some(a) = x.as_array() {
                        let mut acc = String::new();
                        for item in a {
                            if let Some(t) = item.get("text").and_then(|t| t.as_str()) {
                                if !acc.is_empty() {
                                    acc.push('\n');
                                }
                                acc.push_str(t);
                            } else if let Some(s) = pick_text(item) {
                                if !acc.is_empty() {
                                    acc.push('\n');
                                }
                                acc.push_str(&s);
                            }
                        }
                        if !acc.is_empty() {
                            return Some(acc);
                        }
                    } else if let Some(s) = pick_text(x) {
                        return Some(s);
                    }
                }
            }
        }
    }
    if let Some(a) = v.as_array() {
        let mut acc = String::new();
        for x in a {
            if let Some(s) = pick_text(x) {
                if !acc.is_empty() {
                    acc.push('\n');
                }
                acc.push_str(&s);
            }
        }
        if !acc.is_empty() {
            return Some(acc);
        }
    }
    None
}

/// Wertet ein abgeschlossenes CLI-Ergebnis aus.
pub fn interpret_output(out: &CliOutput) -> Result<String, DeepError> {
    let combined = format!("{}\n{}", out.stderr, out.stdout);
    if looks_like_login_error(out.status_ok, &combined) {
        return Err(DeepError::NotLoggedIn(
            combined.trim().chars().take(300).collect(),
        ));
    }
    if !out.status_ok {
        return Err(DeepError::Other(format!(
            "CLI-Exit-Fehler: {}",
            combined.trim().chars().take(300).collect::<String>()
        )));
    }
    parse_cli_json(&out.stdout)
}

/// Proposal-Parse (E2-Cap + Deny-Check, wie ollama/gemini).
pub fn parse_proposal(raw: &str, cwe: &str) -> Result<LlmProposal, String> {
    crate::ollama::parse_proposal(raw, cwe)
}

/// Reine Entscheidung: Cache zuerst, dann Parse + Record.
pub fn decide_with_cache(
    cache: &HashMap<String, crate::CacheRecord>,
    ctx: &FindingContext,
    model_text: &str,
    model_for_record: &str,
) -> Result<TriageOutcome, String> {
    crate::ollama::decide_with_cache(cache, ctx, model_text, model_for_record)
}

/// End-to-end mit injizierbarem Runner (Tests mocken den Subprozess).
pub fn triage_with_runner(
    cache: &HashMap<String, crate::CacheRecord>,
    ctx: &FindingContext,
    config: &DeepConfig,
    runner: impl FnOnce(&str, &[String]) -> Result<CliOutput, DeepError>,
) -> Result<TriageOutcome, DeepError> {
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
    let prompt = build_prompt(
        ctx,
        config
            .model
            .as_deref()
            .unwrap_or(&config.engine.to_string()),
    );
    let args = build_args(config, &prompt);
    let out = runner(&config.cli, &args)?;
    let text = interpret_output(&out)?;
    let model_name = config
        .model
        .clone()
        .unwrap_or_else(|| config.engine.to_string());
    decide_with_cache(cache, ctx, &text, &model_name).map_err(DeepError::Parse)
}

/// Echter Subprozess-Aufruf mit Timeout (Polling via `try_wait`).
pub fn query_deep(config: &DeepConfig, prompt: &str) -> Result<String, DeepError> {
    let args = build_args(config, prompt);
    let mut handle = Command::new(&config.cli)
        .args(args.iter().map(|s| s.as_str()))
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                DeepError::CliMissing(format!("CLI '{}' nicht im PATH ({e})", config.cli))
            } else {
                DeepError::Other(format!("CLI-Start fehlgeschlagen: {e}"))
            }
        })?;
    let timeout = Duration::from_millis(config.timeout_ms);
    let start = Instant::now();
    loop {
        match handle
            .try_wait()
            .map_err(|e| DeepError::Other(format!("wait: {e}")))?
        {
            Some(status) => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                use std::io::Read;
                if let Some(mut o) = handle.stdout.take() {
                    let _ = o.read_to_string(&mut stdout);
                }
                if let Some(mut e) = handle.stderr.take() {
                    let _ = e.read_to_string(&mut stderr);
                }
                return interpret_output(&CliOutput {
                    status_ok: status.success(),
                    stdout,
                    stderr,
                });
            }
            None => {
                if start.elapsed() >= timeout {
                    let _ = handle.kill();
                    let _ = handle.wait();
                    return Err(DeepError::Timeout(format!(
                        "CLI antwortet nicht nach {} ms",
                        config.timeout_ms
                    )));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Routing-Hilfe: klein/lokal zuerst, gross/headless nur per Opt-in.
/// - `deny_cwe`: true bei Deny-List-CWE (Krypto/Auth/Deserialisierung)
/// - `uncertain`: true bei unsicherem/unklarem Vor-Befund
/// - `deep_opt_in`: explizite User-Freigabe (Flag/Config)
///
/// Rueckgabe: `Some(Engine)` nur wenn alle drei zutreffen (sonst `None` = Stufe 1/2).
pub fn select_deep_engine(
    deny_cwe: bool,
    uncertain: bool,
    deep_opt_in: bool,
    prefer: Engine,
) -> Option<Engine> {
    if deny_cwe && uncertain && deep_opt_in {
        Some(prefer)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(cwe: &str) -> FindingContext {
        FindingContext {
            rule_id: "semgrep:test.rule".into(),
            cwe: cwe.into(),
            file: "src/auth.py".into(),
            start_line: Some(7),
            message: "unsichere Deserialisierung".into(),
            code_snippet: "pickle.loads(data)\n".into(),
        }
    }

    fn wrap(inner: &str) -> CliOutput {
        let escaped = inner.replace('\\', "\\\\").replace('"', "\\\"");
        CliOutput {
            status_ok: true,
            stdout: format!("{{\"result\": \"{escaped}\"}}"),
            stderr: String::new(),
        }
    }

    #[test]
    fn opencode_args_format() {
        let cfg = DeepConfig::opencode();
        let args = build_args(&cfg, "P");
        assert_eq!(args[0], "run");
        assert!(args.contains(&"--format".to_string()));
        assert!(args.contains(&"json".to_string()));
        assert!(args.contains(&"P".to_string()));
    }

    #[test]
    fn claude_args_format() {
        let cfg = DeepConfig::claude();
        let args = build_args(&cfg, "P");
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"--output-format".to_string()));
        assert!(args.contains(&"P".to_string()));
    }

    #[test]
    fn claude_content_array_fixture() {
        let fixture = r#"{"content": [{"text": "{\"verdict\": \"confirm\"}"}, {"text": "x"}]}"#;
        let t = parse_cli_json(fixture).unwrap();
        assert!(t.contains("confirm"));
    }

    #[test]
    fn opencode_output_fixture() {
        let t = parse_cli_json(r#"{"output": "hello"}"#).unwrap();
        assert_eq!(t, "hello");
    }

    #[test]
    fn login_und_timeout_mit_hint() {
        let out = CliOutput {
            status_ok: false,
            stdout: String::new(),
            stderr: "API key missing, please login".into(),
        };
        let e = interpret_output(&out).unwrap_err();
        assert_eq!(e.kind(), "not-logged-in");
        assert!(e.to_string().contains("Ollama"));
        assert!(DeepError::Timeout("t".into())
            .to_string()
            .contains("Ollama"));
        assert!(DeepError::CliMissing("x".into())
            .to_string()
            .contains("Ollama"));
    }

    #[test]
    fn full_flow_mock_e2_cap_und_deny() {
        let cfg = DeepConfig::claude();
        let c = ctx("CWE-502");
        let inner =
            "{\"verdict\": \"suppress\", \"evidence_proposed\": \"E4\", \"reason\": \"sieht ok aus\"}";
        let out = triage_with_runner(&HashMap::new(), &c, &cfg, |cli, args| {
            assert_eq!(cli, "claude");
            assert!(args.contains(&"--output-format".to_string()));
            Ok(wrap(inner))
        })
        .unwrap();
        assert!(!out.cache_hit);
        assert_eq!(out.proposal.verdict, "escalate");
        assert_eq!(out.proposal.evidence_proposed, "E2");
        assert_eq!(out.record.verdict.action, crate::VerdictAction::Demote);
    }

    #[test]
    fn cache_hit_ohne_runner() {
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
                    action: crate::VerdictAction::Close,
                    severity_after: "low".into(),
                    model: "claude".into(),
                    prompt_version: PROMPT_VERSION.into(),
                    tokens_in: 0,
                    tokens_out: 0,
                    policy_override: false,
                    provenance: None,
                },
                created_at: "2026-10-14T00:00:00Z".into(),
                format_version: crate::CACHE_FORMAT_VERSION,
            },
        );
        let cfg = DeepConfig::opencode();
        let out = triage_with_runner(&cache, &c, &cfg, |_, _| {
            panic!("Runner darf bei Cache-Hit nicht laufen")
        })
        .unwrap();
        assert!(out.cache_hit);
    }

    #[test]
    fn routing_nur_mit_opt_in() {
        assert_eq!(
            select_deep_engine(true, true, true, Engine::Claude),
            Some(Engine::Claude)
        );
        assert_eq!(select_deep_engine(true, true, false, Engine::Claude), None);
        assert_eq!(
            select_deep_engine(false, true, true, Engine::Opencode),
            None
        );
        assert_eq!(
            select_deep_engine(true, false, true, Engine::Opencode),
            None
        );
    }

    #[test]
    fn prompt_redigiert_secrets() {
        let mut c = ctx("CWE-798");
        c.code_snippet = "password = \"supersecret123\"\n".into();
        assert!(!build_prompt(&c, "claude").contains("supersecret123"));
    }
}
