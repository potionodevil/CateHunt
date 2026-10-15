// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Gemini-CLI-Triage (Primaerweg Stufe 2, headless Subprozess).
//!
//! Routing-Doku (Stufe 2):
//! - **Gemini CLI = Default, wenn verfuegbar**: `gemini` im PATH UND
//!   eingeloggt (User-Credentials, zero-config, kein API-Key im Repo).
//!   Headless-Aufruf: `gemini --output-format json -p "<redigierter Prompt>"`.
//! - **Ollama = Offline-Modus**: localhost-only (`crate::ollama`), kein Netz,
//!   Fallback bei: CLI fehlt, nicht eingeloggt, Timeout/Fehler.
//!   Jede `GeminiError`-Nachricht endet daher mit einem Ollama-Fallback-Hinweis.
//!
//! Regeln (wie `ollama.rs`): Prompt vorher redigieren (cate-core/redact),
//! kein Netz ausser dem CLI-Subprozess (Opt-in: User hat `gemini login`
//! selbst ausgefuehrt), `evidence_proposed` nie hoeher als E2,
//! Deny-List-Check VOR suppress, Cache-Lookup zuerst.
use std::collections::HashMap;
use std::io::ErrorKind;
use std::process::Command;
use std::time::{Duration, Instant};

/// Prompt-Version (im Verdict persistiert, Cache-Invalidierung bei Wechsel).
pub const PROMPT_VERSION: &str = "v1";
/// Default-CLI-Binary (muss im PATH liegen).
pub const DEFAULT_CLI: &str = "gemini";
/// Hinweis, der an jede Fehlermeldung angehaengt wird.
pub const OLLAMA_FALLBACK_HINT: &str =
    "Fallback: Ollama-Offline-Modus nutzen (cate-triage::ollama, localhost-only).";

/// Client-Konfiguration (zero-config: nur CLI-Name, optionales Modell, Timeout).
#[derive(Debug, Clone)]
pub struct GeminiConfig {
    pub cli: String,
    pub model: Option<String>,
    pub timeout_ms: u64,
    pub prompt_version: String,
}

impl Default for GeminiConfig {
    fn default() -> Self {
        Self {
            cli: DEFAULT_CLI.to_string(),
            model: None,
            timeout_ms: 60_000,
            prompt_version: PROMPT_VERSION.to_string(),
        }
    }
}

/// Saubere Fehlerfaelle mit Ollama-Fallback-Hinweis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeminiError {
    /// CLI-Binary nicht gefunden (`gemini` nicht im PATH).
    CliMissing(String),
    /// CLI meldet fehlenden Login / fehlende Credentials.
    NotLoggedIn(String),
    /// Subprozess hat das Timeout ueberschritten.
    Timeout(String),
    /// CLI-JSON konnte nicht geparst werden.
    Parse(String),
    /// Sonstiger CLI-Fehler (Exit-Code != 0, leere Antwort, ...).
    Other(String),
}

impl GeminiError {
    /// Kurze Maschinen-Kennung fuer Tests/Logs.
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

impl std::fmt::Display for GeminiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "gemini {}: {}. {OLLAMA_FALLBACK_HINT}",
            self.kind(),
            self.detail()
        )
    }
}
impl std::error::Error for GeminiError {}

/// Ergebnis eines Triage-Laufs mit Cache-Anbindung.
pub use crate::ollama::TriageOutcome;
/// Minimaler Finding-Kontext: `ollama::FindingContext` wiederverwenden,
/// damit beide Backends dasselbe Proposal-Format teilen.
pub use crate::ollama::{FindingContext, LlmProposal};

/// Baut den Prompt (redigiert, max 2000 Zeichen Snippet).
/// Identische Regeln wie `ollama::build_prompt`, Modell-Name nur fuer
/// Verdict-Persistenz relevant.
pub fn build_prompt(ctx: &FindingContext, model: &str) -> String {
    crate::ollama::build_prompt(ctx, model)
}

/// Baut die CLI-Argumente: `gemini --output-format json [-m <model>] -p <prompt>`.
pub fn build_args(config: &GeminiConfig, prompt: &str) -> Vec<String> {
    let mut args = vec!["--output-format".to_string(), "json".to_string()];
    if let Some(m) = config.model.as_deref().filter(|m| !m.is_empty()) {
        args.push("-m".to_string());
        args.push(m.to_string());
    }
    args.push("-p".to_string());
    args.push(prompt.to_string());
    args
}

/// Roh-Ergebnis eines CLI-Laufs (mockbar fuer Tests).
#[derive(Debug, Clone)]
pub struct CliOutput {
    pub status_ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Erkennt Login-/Auth-Fehler anhand von Exit-Status + stderr/stdout-Text.
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
        "gemini login",
        "api key",
        "apikey",
        "unauthorized",
        "unauthenticated",
        "permission denied",
        "invalid credential",
        "expired credential",
    ]
    .iter()
    .any(|m| l.contains(m))
}

/// Extrahiert den Modelltext aus dem Gemini-CLI-JSON (`--output-format json`).
/// Versteht mehrere Formen (CLI-Versionen driften):
/// - `{"response": "<text>"}`
/// - `{"output": "<text>"}` / `{"result": ...}` / `{"text": ...}` / `{"content": ...}`
/// - `{"candidates": [{"content": {"parts": [{"text": "..."}]}}]}`
/// - Array davon / reiner String / eingebettetes Proposal-JSON (Fallback: roh).
pub fn parse_cli_json(stdout: &str) -> Result<String, GeminiError> {
    let v: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|e| GeminiError::Parse(format!("CLI-JSON ungueltig: {e}")))?;
    if let Some(s) = pick_text(&v) {
        if s.trim().is_empty() {
            return Err(GeminiError::Other("CLI-Antwort leer".to_string()));
        }
        return Ok(s);
    }
    Err(GeminiError::Parse(
        "kein Modelltext im CLI-JSON gefunden".to_string(),
    ))
}

fn pick_text(v: &serde_json::Value) -> Option<String> {
    // Direkter String.
    if let Some(s) = v.as_str() {
        return Some(s.to_string());
    }
    if let Some(o) = v.as_object() {
        // Flache Textfelder.
        for key in [
            "response", "output", "result", "text", "content", "message", "answer",
        ] {
            if let Some(x) = o.get(key) {
                if let Some(s) = x.as_str() {
                    return Some(s.to_string());
                }
                // Verschachtelt (z.B. result: {...}).
                if x.is_object() || x.is_array() {
                    if let Some(s) = pick_text(x) {
                        return Some(s);
                    }
                }
            }
        }
        // candidates[0].content.parts[].text (Vertex-/Gemini-Form).
        if let Some(cands) = o.get("candidates").and_then(|c| c.as_array()) {
            let mut acc = String::new();
            for c in cands {
                let parts = c
                    .get("content")
                    .and_then(|cc| cc.get("parts"))
                    .and_then(|p| p.as_array());
                if let Some(parts) = parts {
                    for p in parts {
                        if let Some(t) = p.get("text").and_then(|t| t.as_str()) {
                            if !acc.is_empty() {
                                acc.push('\n');
                            }
                            acc.push_str(t);
                        }
                    }
                }
                // candidates[].output_text / candidates[] als String.
                if acc.is_empty() {
                    if let Some(t) = c.get("output_text").and_then(|t| t.as_str()) {
                        acc.push_str(t);
                    } else if let Some(t) = c.as_str() {
                        if !acc.is_empty() {
                            acc.push('\n');
                        }
                        acc.push_str(t);
                    }
                }
            }
            if !acc.is_empty() {
                return Some(acc);
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

/// Wertet ein abgeschlossenes CLI-Ergebnis aus: Login-Fehler erkennen,
/// Exit-Code pruefen, Modelltext extrahieren.
pub fn interpret_output(out: &CliOutput) -> Result<String, GeminiError> {
    let combined = format!("{}\n{}", out.stderr, out.stdout);
    if looks_like_login_error(out.status_ok, &combined) {
        return Err(GeminiError::NotLoggedIn(
            combined.trim().chars().take(300).collect(),
        ));
    }
    if !out.status_ok {
        return Err(GeminiError::Other(format!(
            "CLI-Exit-Fehler: {}",
            combined.trim().chars().take(300).collect::<String>()
        )));
    }
    parse_cli_json(&out.stdout)
}

/// Parst Modelltext ins Proposal-Format (E2-Cap + Deny-Check, wie ollama).
pub fn parse_proposal(raw: &str, cwe: &str) -> Result<LlmProposal, String> {
    crate::ollama::parse_proposal(raw, cwe)
}

/// Reine Entscheidungsfunktion (ohne Subprozess): Cache-Lookup zuerst,
/// dann Proposal-Parse + Policy + Record-Bau. `model_for_record` landet
/// im Cache-Record (z.B. "gemini-2.5-flash").
pub fn decide_with_cache(
    cache: &HashMap<String, crate::CacheRecord>,
    ctx: &FindingContext,
    model_text: &str,
    model_for_record: &str,
) -> Result<TriageOutcome, String> {
    crate::ollama::decide_with_cache(cache, ctx, model_text, model_for_record)
}

/// End-to-end mit injizierbarem Runner (Tests mocken hiermit den Subprozess):
/// Cache-Lookup -> Runner (CLI) -> JSON-Extrakt -> Proposal+Record.
/// `runner` erhaelt (cli, args) und liefert `CliOutput` oder `GeminiError`
/// (z.B. Timeout/CLI-fehlt simulieren).
pub fn triage_with_runner(
    cache: &HashMap<String, crate::CacheRecord>,
    ctx: &FindingContext,
    config: &GeminiConfig,
    runner: impl FnOnce(&str, &[String]) -> Result<CliOutput, GeminiError>,
) -> Result<TriageOutcome, GeminiError> {
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
    let prompt = build_prompt(ctx, config.model.as_deref().unwrap_or("gemini"));
    let args = build_args(config, &prompt);
    let out = runner(&config.cli, &args)?;
    let text = interpret_output(&out)?;
    let model_name = config.model.clone().unwrap_or_else(|| "gemini".to_string());
    decide_with_cache(cache, ctx, &text, &model_name).map_err(GeminiError::Parse)
}

/// Echter Subprozess-Aufruf mit Timeout (Polling via `try_wait`).
/// Fehler-Mapping: Binary fehlt -> `CliMissing`, Timeout -> `Timeout`,
/// Login-Hinweise in stderr -> `NotLoggedIn` (via `interpret_output`).
pub fn query_gemini(config: &GeminiConfig, prompt: &str) -> Result<String, GeminiError> {
    let args = build_args(config, prompt);
    let cli = config.cli.clone();
    // Eigentlicher Spawn (getrennt, damit NotFound sauber mappbar ist).
    let mut handle = Command::new(&cli)
        .arg(&args[0])
        .args(&args[1..])
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                GeminiError::CliMissing(format!("CLI '{cli}' nicht im PATH ({e})"))
            } else {
                GeminiError::Other(format!("CLI-Start fehlgeschlagen: {e}"))
            }
        })?;
    let timeout = Duration::from_millis(config.timeout_ms);
    let start = Instant::now();
    loop {
        match handle
            .try_wait()
            .map_err(|e| GeminiError::Other(format!("wait: {e}")))?
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
                    return Err(GeminiError::Timeout(format!(
                        "CLI antwortet nicht nach {} ms",
                        config.timeout_ms
                    )));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Routing-Entscheidung: Gemini-Default wenn verfuegbar+eingeloggt,
/// sonst Ollama-Offline. Reine Funktion, leicht testbar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Gemini,
    Ollama,
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gemini => write!(f, "gemini"),
            Self::Ollama => write!(f, "ollama"),
        }
    }
}

/// `gemini_available_and_logged_in`: true, wenn `gemini --output-format json
/// -p "ping"` erfolgreich Modelltext liefert (Caller prueft das z.B. via
/// `query_gemini` mit kurzem Timeout); sonst Ollama.
pub fn select_backend(gemini_available_and_logged_in: bool) -> Backend {
    if gemini_available_and_logged_in {
        Backend::Gemini
    } else {
        Backend::Ollama
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
            start_line: Some(42),
            message: "hartcodiertes Passwort".into(),
            code_snippet: "password = \"hunter2\"\n".into(),
        }
    }

    fn ok_out(text_json_inner: &str) -> CliOutput {
        // CLI huellt Modelltext in {"response": ...} ein.
        let escaped = text_json_inner.replace('\\', "\\\\").replace('"', "\\\"");
        CliOutput {
            status_ok: true,
            stdout: format!("{{\"response\": \"{escaped}\"}}"),
            stderr: String::new(),
        }
    }

    #[test]
    fn args_headless_json_mit_prompt() {
        let cfg = GeminiConfig::default();
        let args = build_args(&cfg, "PROMPT");
        assert_eq!(
            &args[0..2],
            &["--output-format".to_string(), "json".to_string()]
        );
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"PROMPT".to_string()));
    }

    #[test]
    fn args_mit_modell() {
        let cfg = GeminiConfig {
            model: Some("gemini-2.5-flash".into()),
            ..GeminiConfig::default()
        };
        let args = build_args(&cfg, "P");
        let pos = args.iter().position(|a| a == "-m").expect("-m fehlt");
        assert_eq!(args[pos + 1], "gemini-2.5-flash");
    }

    #[test]
    fn prompt_wird_redigiert() {
        let mut c = ctx("CWE-798");
        c.code_snippet = "password = \"supersecret123\"\n".into();
        let p = build_prompt(&c, "gemini");
        assert!(!p.contains("supersecret123"), "Secret im Prompt");
    }

    #[test]
    fn parse_response_form() {
        let t = parse_cli_json(r#"{"response": "{\"verdict\": \"confirm\"}"}"#).unwrap();
        assert!(t.contains("confirm"));
    }

    #[test]
    fn parse_candidates_form_fixture() {
        let fixture = r#"{
            "candidates": [{"content": {"parts": [{"text": "{\"verdict\": \"suppress\", \"evidence_proposed\": \"E1\", \"reason\": \"fp\"}"}]}}]
        }"#;
        let t = parse_cli_json(fixture).unwrap();
        assert!(t.contains("suppress"));
    }

    #[test]
    fn parse_output_form() {
        let t = parse_cli_json(r#"{"output": "hello"}"#).unwrap();
        assert_eq!(t, "hello");
    }

    #[test]
    fn parse_leeres_json_ist_fehler() {
        assert!(parse_cli_json("{}").is_err());
        assert!(parse_cli_json("kein json").is_err());
    }

    #[test]
    fn cli_fehlt_mit_ollama_hint() {
        let e = GeminiError::CliMissing("x".into());
        let s = e.to_string();
        assert!(s.contains("cli-missing"));
        assert!(s.contains("Ollama"));
        assert_eq!(e.kind(), "cli-missing");
    }

    #[test]
    fn login_fehler_erkannt() {
        let out = CliOutput {
            status_ok: false,
            stdout: String::new(),
            stderr: "Please run `gemini login` to authenticate.".into(),
        };
        let e = interpret_output(&out).unwrap_err();
        assert_eq!(e.kind(), "not-logged-in");
        assert!(e.to_string().contains("Ollama"));
    }

    #[test]
    fn exit_fehler_ohne_login_ist_other() {
        let out = CliOutput {
            status_ok: false,
            stdout: String::new(),
            stderr: "boom".into(),
        };
        assert_eq!(interpret_output(&out).unwrap_err().kind(), "other");
    }

    #[test]
    fn timeout_traegt_hint() {
        let e = GeminiError::Timeout("100 ms".into());
        assert!(e.to_string().contains("Ollama"));
    }

    #[test]
    fn full_flow_mock_runner_e2_cap_und_deny() {
        // Mock: CLI liefert suppress+E3 auf Deny-CWE -> escalate+E2.
        let cfg = GeminiConfig::default();
        let c = ctx("CWE-798");
        let cache = HashMap::new();
        let inner =
            "{\"verdict\": \"suppress\", \"evidence_proposed\": \"E3\", \"reason\": \"harmlos\"}";
        let out = triage_with_runner(&cache, &c, &cfg, |_cli, args| {
            assert!(args.contains(&"--output-format".to_string()));
            Ok(ok_out(inner))
        })
        .unwrap();
        assert!(!out.cache_hit);
        assert_eq!(out.proposal.verdict, "escalate");
        assert_eq!(out.proposal.evidence_proposed, "E2");
        assert!(out.proposal.policy_override);
        assert_eq!(out.record.verdict.action, crate::VerdictAction::Demote);
    }

    #[test]
    fn cache_hit_ohne_runner_call() {
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
                    model: "gemini".into(),
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
        let cfg = GeminiConfig::default();
        let out = triage_with_runner(&cache, &c, &cfg, |_, _| {
            panic!("Runner darf bei Cache-Hit nicht laufen")
        })
        .unwrap();
        assert!(out.cache_hit);
    }

    #[test]
    fn runner_timeout_wird_durchgereicht() {
        let cfg = GeminiConfig::default();
        let c = ctx("CWE-79");
        let e = triage_with_runner(&HashMap::new(), &c, &cfg, |_, _| {
            Err(GeminiError::Timeout("mock".into()))
        })
        .unwrap_err();
        assert_eq!(e.kind(), "timeout");
    }

    #[test]
    fn routing_default_gemini_offline_ollama() {
        assert_eq!(select_backend(true), Backend::Gemini);
        assert_eq!(select_backend(false), Backend::Ollama);
        assert_eq!(Backend::Gemini.to_string(), "gemini");
        assert_eq!(Backend::Ollama.to_string(), "ollama");
    }
}
