// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Pipeline-Verdrahtung: Fallback-Kette Ollama -> Gemini -> Deep.
//!
//! - **Ollama (Stufe 1, Default):** localhost-only, keine Kosten, kein Opt-in.
//! - **Gemini (Stufe 2):** nur wenn CLI vorhanden UND eingeloggt
//!   (`gemini_available_and_logged_in`, s. `crate::gemini::select_backend`).
//!   Jeder Gemini-Fehler faellt auf Ollama zurueck.
//! - **Deep (Stufe 3, Opt-in):** nur bei Deny-CWE + unsicherem Befund +
//!   expliziter User-Freigabe (`crate::deep_engines::select_deep_engine`).
//!   Kosten-/Latenz-Hinweis s. `COST_LATENCY_NOTE`.
//!
//! `plan_stages` baut die Kette, `run_chain` laeuft sie mit injizierten
//! Runnern ab (mockbar, kein Netz in Tests).
//!
//! Neu: `plan_stages_checked` filtert die Kette per `StageAvailability`
//! (offline pruefbar: TCP-Loopback + `--version`-Spawns, kein Modell-Call),
//! `deterministic_triage` ist der Offline-Fallback (rein, kein Netz) und
//! `run_chain_with_fallback` haengt ihn automatisch an jede erschoepfte
//! Kette an. `plan_stages`/`run_chain` bleiben unveraendert (abwaertskompatibel).
use crate::deep_engines::Engine;
use crate::gemini::Backend;
use std::collections::HashMap;

/// Eine Stufe der Fallback-Kette.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Ollama,
    Gemini,
    Deep(Engine),
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ollama => write!(f, "ollama"),
            Self::Gemini => write!(f, "gemini"),
            Self::Deep(e) => write!(f, "deep-{e}"),
        }
    }
}

/// Aufgeloester Pipeline-Plan: Primaer-Backend + optionale Deep-Stufe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelinePlan {
    pub primary: Backend,
    pub deep: Option<Engine>,
    /// Volle Kette in Ausfuehrungsreihenfolge (Ollama -> Gemini -> Deep).
    pub chain: Vec<Stage>,
}

/// Loest die Pipeline auf: `select_backend` (Ollama vs. Gemini) plus
/// `select_deep_engine` (Opt-in-Stufe 3). Die Kette startet immer bei
/// Ollama; Gemini wird nur bei Verfuegbarkeit+Login aufgenommen, Deep
/// nur bei Deny-CWE + Unsicherheit + Opt-in.
pub fn plan_stages(
    gemini_available_and_logged_in: bool,
    deny_cwe: bool,
    uncertain: bool,
    deep_opt_in: bool,
    prefer: Engine,
) -> PipelinePlan {
    // Altes Verhalten = alles verfuegbar ausser Gemini-per-Flag (s. `plan_stages_checked`).
    let avail = StageAvailability {
        ollama_reachable: true,
        gemini_cli_present: gemini_available_and_logged_in,
        deep_cli_present: true,
    };
    plan_stages_checked(deny_cwe, uncertain, deep_opt_in, prefer, &avail)
}

/// Fehler der gesamten Kette: welche Stufen versucht wurden + letzter Fehler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainError {
    pub attempted: Vec<Stage>,
    pub last_error: String,
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<String> = self.attempted.iter().map(|s| s.to_string()).collect();
        write!(
            f,
            "pipeline erschoepft [{}]: {}. {}",
            names.join(" -> "),
            self.last_error,
            crate::gemini::OLLAMA_FALLBACK_HINT
        )
    }
}
impl std::error::Error for ChainError {}

/// Laeuft die Kette ab: erste erfolgreiche Stufe gewinnt. `run` erhaelt
/// die Stufe und liefert das Ergebnis oder einen Fehler-String.
pub fn run_chain<T>(
    stages: &[Stage],
    run: &mut dyn FnMut(&Stage) -> Result<T, String>,
) -> Result<(Stage, T), ChainError> {
    let mut attempted = Vec::new();
    let mut last_error = "keine Stufe konfiguriert".to_string();
    for s in stages {
        attempted.push(*s);
        match run(s) {
            Ok(v) => return Ok((*s, v)),
            Err(e) => last_error = e,
        }
    }
    Err(ChainError {
        attempted,
        last_error,
    })
}

// ---- Availability-Checks + deterministischer Fallback ----

/// Verfuegbarkeit der Stufen. Alles offline pruefbar (TCP-Loopback +
/// `--version`-Spawns, kein Modell-Call, kein Netz ausser localhost).
/// Der Login-Status (Gemini/Deep) ist bewusst KEIN Feld: ohne Netz/Call
/// laesst er sich nicht pruefen; `NotLoggedIn` faellt zur Laufzeit
/// automatisch auf die naechste Stufe zurueck (s. `run_chain`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageAvailability {
    /// Ollama per TCP auf Loopback erreichbar.
    pub ollama_reachable: bool,
    /// `gemini`-CLI im PATH (Stufe 2).
    pub gemini_cli_present: bool,
    /// Deep-CLI (`opencode`/`claude`) im PATH (Stufe 3).
    pub deep_cli_present: bool,
}

impl StageAvailability {
    /// Alles offline: kein Netz, keine CLIs — nur deterministischer Fallback.
    /// Sicherer Default fuer Tests (s. `Default`-Impl).
    pub fn offline() -> Self {
        Self {
            ollama_reachable: false,
            gemini_cli_present: false,
            deep_cli_present: false,
        }
    }
    /// Alles verfuegbar: entspricht dem alten `plan_stages`-Verhalten.
    pub fn all_available() -> Self {
        Self {
            ollama_reachable: true,
            gemini_cli_present: true,
            deep_cli_present: true,
        }
    }
}

impl Default for StageAvailability {
    fn default() -> Self {
        Self::offline()
    }
}

/// Prueft Ollama per TCP-Connect mit kurzem Timeout. Nur Loopback-URLs
/// werden ueberhaupt versucht (alles andere + jeder Connect-Fehler =
/// `false`, nie ein Fehler). Kein Modell-Call.
pub fn probe_ollama_reachable(base_url: &str, timeout_ms: u64) -> bool {
    if crate::ollama::check_base_url(base_url).is_err() {
        return false;
    }
    let rest = base_url.trim_start_matches("http://");
    let hostport = rest.split('/').next().unwrap_or("");
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.trim_matches(['[', ']']), p.parse().unwrap_or(80)),
        None => (hostport, 80),
    };
    if host != "localhost" && host != "127.0.0.1" && host != "::1" {
        return false;
    }
    use std::net::ToSocketAddrs;
    let timeout = std::time::Duration::from_millis(timeout_ms.max(1));
    (host, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .and_then(|addr| std::net::TcpStream::connect_timeout(&addr, timeout).ok())
        .is_some()
}

/// Prueft CLI-Praesenz via `<cli> --version` (kein Netz, kein Login noetig).
/// Heuristik: Exit-Status 0 = vorhanden; alles andere = `false`.
pub fn probe_cli_present(cli: &str) -> bool {
    std::process::Command::new(cli)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Sammelt alle Proben (offline-sicher). `deep_cli` ist der konfigurierte
/// CLI-Name (`opencode`|`claude`).
pub fn probe_availability(
    ollama_base_url: &str,
    gemini_cli: &str,
    deep_cli: &str,
) -> StageAvailability {
    StageAvailability {
        ollama_reachable: probe_ollama_reachable(ollama_base_url, 500),
        gemini_cli_present: probe_cli_present(gemini_cli),
        deep_cli_present: probe_cli_present(deep_cli),
    }
}

/// Wie `plan_stages`, aber nicht-verfuegbare Stufen entfallen aus der Kette:
/// - Ollama nur bei Erreichbarkeit (sonst kein sinnloser Connect-Timeout),
/// - Gemini nur bei vorhandener CLI,
/// - Deep nur bei Routing-Treffer UND vorhandener CLI (`deep` im Plan
///   bleibt dann ebenfalls `None` — ehrliche Anzeige statt toter Stufe).
///
/// Primaer-Backend: Gemini bei CLI-Praesenz, sonst Ollama (Offline-Modus).
/// Ist gar nichts verfuegbar, bleibt `chain` leer — `run_chain_with_fallback`
/// greift dann zum deterministischen Fallback.
pub fn plan_stages_checked(
    deny_cwe: bool,
    uncertain: bool,
    deep_opt_in: bool,
    prefer: Engine,
    avail: &StageAvailability,
) -> PipelinePlan {
    let primary = if avail.gemini_cli_present {
        Backend::Gemini
    } else {
        Backend::Ollama
    };
    let routing = crate::deep_engines::select_deep_engine(deny_cwe, uncertain, deep_opt_in, prefer);
    let deep = match routing {
        Some(e) if avail.deep_cli_present => Some(e),
        _ => None,
    };
    let mut chain = Vec::new();
    if avail.ollama_reachable {
        chain.push(Stage::Ollama);
    }
    if avail.gemini_cli_present {
        chain.push(Stage::Gemini);
    }
    if let Some(e) = deep {
        chain.push(Stage::Deep(e));
    }
    PipelinePlan {
        primary,
        deep,
        chain,
    }
}

/// Risiko-Marker fuer den deterministischen Fallback (kleingeschrieben,
/// Substring-Suche auf dem Snippet).
const RISK_MARKERS: &[&str] = &[
    "eval(",
    "exec(",
    "os.system",
    "subprocess",
    "shell=true",
    "popen",
    "pickle.loads",
    "yaml.load",
    "marshal.loads",
    "select ",
    "execute(",
    ".format(",
    "%s",
    "% (",
    "../",
    "..\\",
    "<script",
    "innerhtml",
    "document.write",
    "password",
    "secret",
    "api_key",
    "apikey",
    "passwd",
    "md5(",
    "sha1(",
];

/// Deterministische Offline-Triage (rein: kein Netz, kein Subprozess, kein Modell).
/// Cache-Lookup zuerst; sonst heuristisches Proposal — bestaetigt oder
/// eskaliert, **schliesst nie** (`suppress` kommt nicht vor; Deny-CWEs werden
/// eskaliert). Durch `decide_with_cache` normalisiert (E2-Cap, Deny-List,
/// Record-Bau, Modell-Label `deterministic-fallback-v1`).
pub fn deterministic_triage(
    cache: &HashMap<String, crate::CacheRecord>,
    ctx: &crate::ollama::FindingContext,
) -> Result<crate::ollama::TriageOutcome, String> {
    let lower = ctx.code_snippet.to_ascii_lowercase();
    let marker = RISK_MARKERS.iter().find(|m| lower.contains(**m));
    let deny = crate::verdict_cap(&ctx.cwe) == crate::MaxAction::DemoteOnly;
    let (verdict, evidence, reason) = match (deny, marker) {
        (true, _) => (
            "escalate",
            "E2",
            format!(
                "deterministischer Fallback (offline): Deny-CWE {} nie schliessen",
                ctx.cwe
            ),
        ),
        (false, Some(m)) => (
            "confirm",
            "E2",
            format!("deterministischer Fallback (offline): Risiko-Muster '{m}'"),
        ),
        (false, None) => (
            "confirm",
            "E1",
            "deterministischer Fallback (offline): kein Modell, manuell pruefen".to_string(),
        ),
    };
    let raw = format!(
        "{{\"verdict\": \"{verdict}\", \"evidence_proposed\": \"{evidence}\", \"reason\": \"{reason}\"}}"
    );
    crate::ollama::decide_with_cache(cache, ctx, &raw, "deterministic-fallback-v1")
}

/// Ergebnis von `run_chain_with_fallback`: Gewinnstufe (`None` = Fallback),
/// Wert, versuchte Stufen (Audit) und letzter Fehler der Kette.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackOutcome<T> {
    pub stage: Option<Stage>,
    pub value: T,
    pub attempted: Vec<Stage>,
    pub used_fallback: bool,
    pub last_error: Option<String>,
}

/// Laeuft die Kette ab (erste erfolgreiche Stufe gewinnt); ist sie erschoepft
/// oder leer, greift `fallback` (deterministisch, z.B. `deterministic_triage`).
/// `used_fallback=true` markiert synthetische Ergebnisse fuer Audit/Logs.
pub fn run_chain_with_fallback<T>(
    stages: &[Stage],
    run: &mut dyn FnMut(&Stage) -> Result<T, String>,
    fallback: impl FnOnce() -> T,
) -> FallbackOutcome<T> {
    let mut attempted = Vec::new();
    let mut last_error: Option<String> = None;
    for s in stages {
        attempted.push(*s);
        match run(s) {
            Ok(v) => {
                return FallbackOutcome {
                    stage: Some(*s),
                    value: v,
                    attempted,
                    used_fallback: false,
                    last_error,
                };
            }
            Err(e) => last_error = Some(e),
        }
    }
    if last_error.is_none() {
        last_error = Some("keine Stufe konfiguriert".to_string());
    }
    FallbackOutcome {
        stage: None,
        value: fallback(),
        attempted,
        used_fallback: true,
        last_error,
    }
}

// ---- S4 Staged Confinement: Stage-Capabilities (ohne S3-CI) ----

/// Capability einer Pipeline-Stufe: Netz-Zugang vs. Zugang zu Roh-Daten
/// (Findings/Secrets). Sandlock-Regel („lethal trifecta“ brechen): Eine
/// Stufe mit Netz sieht nie Roh-Daten, eine Stufe mit Roh-Daten hat nie
/// Netz — `network && data` ist verboten.
///
/// `StageCaps::new` macht die verbotene Kombination per Typ undarstellbar
/// (`None`), `check`/`check_chain_caps` lehnen sie zur Laufzeit ab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageCaps {
    pub network: bool,
    pub data: bool,
}

impl StageCaps {
    /// Nur erlaubte Kombinationen sind darstellbar: (Netz XOR Daten)
    /// oder (weder noch). (Netz UND Daten) ergibt `None`.
    pub const fn new(network: bool, data: bool) -> Option<Self> {
        if network && data {
            None
        } else {
            Some(Self { network, data })
        }
    }

    /// Laufzeit-Check der Invariante (fuer direkt konstruierte Caps).
    pub fn check(&self) -> Result<(), String> {
        if self.network && self.data {
            return Err(
                "S4-Confinement verletzt: Stufe mit Netz darf keine Roh-Daten sehen (network && data)"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// Capability einer Ketten-Stufe:
/// - `Ollama`: Loopback-Netz (`POST /api/generate`), aber nur redigierter
///   Prompt-Kontext (`build_prompt` redigiert via `cate-core/redact`) →
///   Netz JA, Roh-Daten NEIN.
/// - `Gemini`/`Deep`: CLI-Subprozess mit Cloud-Netz, ebenfalls nur
///   redigiert → Netz JA, Roh-Daten NEIN.
pub fn stage_caps(stage: &Stage) -> StageCaps {
    match stage {
        Stage::Ollama | Stage::Gemini | Stage::Deep(_) => StageCaps {
            network: true,
            data: false,
        },
    }
}

/// Capability des deterministischen Fallbacks (`deterministic_triage`):
/// rein lokal (kein Netz, kein Subprozess), volle lokale Daten
/// (Cache + Snippet) → Netz NEIN, Roh-Daten JA.
pub fn fallback_caps() -> StageCaps {
    StageCaps {
        network: false,
        data: true,
    }
}

/// Validiert eine Kette: jede Netz-Stufe ohne Daten, die Daten-Stufe
/// (Fallback) ohne Netz. Verbotene Kombination → `Err`, d.h. die Kette
/// wird abgelehnt.
pub fn check_chain_caps(stages: &[Stage]) -> Result<(), String> {
    for s in stages {
        stage_caps(s).check()?;
    }
    fallback_caps().check()?;
    Ok(())
}

// ---- S-5 Contested: widerspruechliche Severities deterministisch aufloesen --

/// Honorar-Rang hoeherer Verdict gewinnt: `escalate` > `confirm` > `suppress`.
/// (CHECK_LAYERING.md Korrelations-Regel "Widerspruch": zwei Adapter, gleicher
/// Finding, gegensaetzliche Verdicts -> deterministisch der HOEHERE gewinnt +
/// `contested:true` fuer den Merge — **nie** still mitteln.)
fn verdict_rank(verdict: &str) -> u8 {
    match verdict {
        "escalate" => 2,
        "confirm" => 1,
        "suppress" => 0,
        // Unbekannte Werte unter allen bekannten: deterministisch, nie panic.
        _ => 0,
    }
}

/// Ein Adapter-Befund fuer den Contest-Merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContestedInput {
    /// Adapter-Provenienz (z.B. "semgrep", "codeql", "ollama", "gemini").
    pub adapter: String,
    /// Verdict des Adapters: `confirm` | `escalate` | `suppress`.
    pub verdict: String,
    /// Scanner-/Triage-Severity (`critical`|`high`|`medium`|`low`|`info`,
    /// tolerant gegen Beweis-Fehlschlaege: unbekannt = `info`).
    pub severity: String,
    /// Optionale Begruendung (landet im Merge-Reason bei Konflikt).
    pub reason: Option<String>,
}

impl ContestedInput {
    pub fn new(adapter: &str, verdict: &str, severity: &str) -> Self {
        Self {
            adapter: adapter.to_string(),
            verdict: verdict.to_string(),
            severity: severity.to_string(),
            reason: None,
        }
    }
    pub fn with_reason(mut self, reason: &str) -> Self {
        self.reason = Some(reason.to_string());
        self
    }
}

/// Ergebnis des Contest-Merges: hoechster Verdict + Severity + Wer hat
/// gewonnen + `contested`-Flag fuer den Merge (L3/L4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContestedMerge {
    /// Gewinner-Verdict (hoechster; bei Gleichstand: Severity tie-break).
    pub verdict: String,
    /// Hoechste Severity der输入 (kleingeschrieben, normalisiert).
    pub severity: String,
    /// Adapter des Gewinner-Verdicts (deterministisch: erster bei Ranggleich).
    pub winner: String,
    /// Alle Adapter, deren Verdict vom Gewinner abwich (Audit fuer Merge).
    pub dissent: Vec<String>,
    /// true, wenn mind. ein Adapter abwich (Korrelations-Regel S-5).
    pub contested: bool,
}

impl std::fmt::Display for ContestedMerge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let d = self.dissent.join(", ");
        write!(
            f,
            "contested merge: {} ({}) [gewinner: {} | abweichend: {}]",
            self.verdict, self.severity, self.winner, d
        )
    }
}

/// Severity-Rang fuer Tie-Break (hoeher = groesser): `critical` > `high` >
/// `medium` > `low` > `info`; unbekannt = `info` (deterministisch).
fn severity_rank(severity: &str) -> u8 {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "error" => 3,
        "medium" | "warning" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// deterministischer Contest-Merge über N Adapter-Befunde:
///
/// - **kein stiller Mittelwert:** Der Verdict mit dem hoechsten Rang
///   (`escalate` > `confirm` > `suppress`) gewinnt.
/// - **Tie-Break:** Bei Rang-Gleichstand entscheidet die hoehere Severity;
///   bleibt auch die gleich, der **erste in der Liste** (Channel-Order)
///   — der Merge ruft bei gleicher Eingabe bei der Ausgabe das Identische.
/// - **`contested:true`** genau dann, wenn mind. ein Adapter vom Gewinner
///   abstammte (abweichender Verdict UND niedrigerer Rang — Eintraege mit
///   gleichem Rang sind kein Widerspruch).
/// - **nicht deterministisch?** Nein: reine Funktion, kein RNG, keine Zeit,
///   keine Env — `merge_contested(a) == merge_contested(a)`.
pub fn merge_contested(inputs: &[ContestedInput]) -> ContestedMerge {
    if inputs.is_empty() {
        return ContestedMerge {
            verdict: "confirm".to_string(),
            severity: "info".to_string(),
            winner: "leer".to_string(),
            dissent: Vec::new(),
            contested: false,
        };
    }
    // Gewinner-Scan: Hoechster Verdict-Rang gewinnt; bei Rang-Gleichstand
    // entscheidet die hoehere Severity; bleibt auch die gleich, der erste
    // in der Liste (Channel-Order). Kein Mittelwert, kein RNG, keine Zeit.
    let mut best = 0usize;
    for (i, x) in inputs.iter().enumerate().skip(1) {
        let cand = (verdict_rank(&x.verdict), severity_rank(&x.severity));
        let cur = (
            verdict_rank(&inputs[best].verdict),
            severity_rank(&inputs[best].severity),
        );
        if cand > cur {
            best = i;
        }
    }
    // Dissent relativ zum finalen Gewinner: jeder Adapter mit einem
    // abweichenden Verdict niedrigeren Rangs (Audit-Spur fuer den Merge).
    let dissent: Vec<String> = inputs
        .iter()
        .filter(|x| verdict_rank(&x.verdict) < verdict_rank(&inputs[best].verdict))
        .map(|x| x.adapter.clone())
        .collect();
    let contested = !dissent.is_empty();
    ContestedMerge {
        verdict: inputs[best].verdict.clone(),
        severity: severity_name(&inputs[best].severity),
        winner: inputs[best].adapter.clone(),
        dissent,
        contested,
    }
}

/// Severity klein + getrimmt (Merge-Output normalisiert).
fn severity_name(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

/// Redact-Gate fuer gebaute Prompts: `build_prompt` (ollama/gemini/
/// deep_engines) redigiert vor Versand (`cate-core/redact`); dieser
/// Check weist Secret-Material im fertigen Prompt zurueck. Netz-Stufen
/// duerfen nur Prompts passieren, die hier `Ok` sind.
pub fn assert_prompt_secret_free(prompt: &str) -> Result<(), String> {
    if cate_core::redact::has_secret(prompt) {
        return Err(
            "S4-Confinement verletzt: Prompt enthaelt Secret-Material (redact-Check)".to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_nur_ollama() {
        let p = plan_stages(false, false, false, false, Engine::Claude);
        assert_eq!(p.primary, Backend::Ollama);
        assert_eq!(p.deep, None);
        assert_eq!(p.chain, vec![Stage::Ollama]);
    }

    #[test]
    fn gemini_wird_aufgenommen_wenn_verfuegbar() {
        let p = plan_stages(true, false, false, false, Engine::Claude);
        assert_eq!(p.primary, Backend::Gemini);
        assert_eq!(p.chain, vec![Stage::Ollama, Stage::Gemini]);
    }

    #[test]
    fn deep_nur_mit_opt_in_und_deny_und_unsicher() {
        let p = plan_stages(true, true, true, true, Engine::Opencode);
        assert_eq!(
            p.chain,
            vec![Stage::Ollama, Stage::Gemini, Stage::Deep(Engine::Opencode)]
        );
        assert_eq!(
            plan_stages(true, true, true, false, Engine::Opencode).deep,
            None
        );
        assert_eq!(
            plan_stages(true, false, true, true, Engine::Opencode).deep,
            None
        );
    }

    #[test]
    fn kette_ollama_zuerst_dann_fallback() {
        let stages = plan_stages(true, false, false, false, Engine::Claude).chain;
        let mut calls = Vec::new();
        let r = run_chain(&stages, &mut |s: &Stage| {
            calls.push(*s);
            match s {
                Stage::Ollama => Err("ollama down".to_string()),
                Stage::Gemini => Ok("proposal"),
                Stage::Deep(_) => panic!("deep nicht im Plan"),
            }
        });
        assert_eq!(r, Ok((Stage::Gemini, "proposal")));
        assert_eq!(calls, vec![Stage::Ollama, Stage::Gemini]);
    }

    #[test]
    fn kette_erfolg_ollama_kein_weiterer_versuch() {
        let stages = plan_stages(true, false, false, false, Engine::Claude).chain;
        let mut n = 0;
        let r = run_chain(&stages, &mut |_: &Stage| {
            n += 1;
            Ok(42)
        });
        assert_eq!(r, Ok((Stage::Ollama, 42)));
        assert_eq!(n, 1);
    }

    #[test]
    fn kette_erschoepft_meldet_versuche() {
        let stages = plan_stages(false, false, false, false, Engine::Claude).chain;
        let e = run_chain::<u8>(&stages, &mut |_| Err("boom".to_string())).unwrap_err();
        assert_eq!(e.attempted, vec![Stage::Ollama]);
        assert!(e.to_string().contains("ollama"));
        assert!(e.to_string().contains("Ollama"));
    }

    // ---- Availability-Checks + deterministischer Fallback ----

    fn finding_ctx(cwe: &str, snippet: &str) -> crate::ollama::FindingContext {
        crate::ollama::FindingContext {
            rule_id: "testprojekt:fall".into(),
            cwe: cwe.into(),
            file: "fall.py".into(),
            start_line: Some(1),
            message: "test".into(),
            code_snippet: snippet.into(),
        }
    }

    #[test]
    fn checked_entspricht_altem_verhalten() {
        // plan_stages(flag) == plan_stages_checked mit gemappter Availability.
        for flag in [false, true] {
            for (deny, unc, opt) in [
                (false, false, false),
                (true, true, true),
                (true, true, false),
                (true, false, true),
            ] {
                let avail = StageAvailability {
                    ollama_reachable: true,
                    gemini_cli_present: flag,
                    deep_cli_present: true,
                };
                assert_eq!(
                    plan_stages(flag, deny, unc, opt, Engine::Claude),
                    plan_stages_checked(deny, unc, opt, Engine::Claude, &avail),
                    "flag={flag} deny={deny} unc={unc} opt={opt}"
                );
            }
        }
    }

    #[test]
    fn checked_offline_leere_kette() {
        let p = plan_stages_checked(
            true,
            true,
            true,
            Engine::Claude,
            &StageAvailability::offline(),
        );
        assert_eq!(p.primary, Backend::Ollama);
        assert_eq!(p.deep, None);
        assert!(p.chain.is_empty(), "offline keine Stufe: {:?}", p.chain);
    }

    #[test]
    fn checked_ohne_ollama_nur_gemini() {
        let avail = StageAvailability {
            ollama_reachable: false,
            gemini_cli_present: true,
            deep_cli_present: false,
        };
        let p = plan_stages_checked(false, false, false, Engine::Claude, &avail);
        assert_eq!(p.chain, vec![Stage::Gemini]);
    }

    #[test]
    fn checked_deep_entfaellt_ohne_cli() {
        let avail = StageAvailability {
            ollama_reachable: true,
            gemini_cli_present: false,
            deep_cli_present: false,
        };
        let p = plan_stages_checked(true, true, true, Engine::Opencode, &avail);
        assert_eq!(p.deep, None, "deep ohne CLI ehrlich None");
        assert_eq!(p.chain, vec![Stage::Ollama]);
    }

    #[test]
    fn checked_deep_mit_cli_in_kette() {
        let p = plan_stages_checked(
            true,
            true,
            true,
            Engine::Opencode,
            &StageAvailability::all_available(),
        );
        assert_eq!(
            p.chain,
            vec![Stage::Ollama, Stage::Gemini, Stage::Deep(Engine::Opencode)]
        );
    }

    #[test]
    fn proben_sind_offline_sicher() {
        // Kein Netz im Testpfad: Remote-URL + unbekannte CLI = false, kein Panic.
        assert!(!probe_ollama_reachable("https://example.com:11434", 50));
        assert!(!probe_ollama_reachable("http://192.168.1.5:11434", 50));
        assert!(!probe_cli_present("catehunt-gibt-es-nicht-xyz"));
        // Geschlossener Loopback-Port = false statt Fehler.
        assert!(!probe_ollama_reachable("http://127.0.0.1:1", 100));
    }

    #[test]
    fn deterministisch_schliesst_nie() {
        // Risiko-Snippet, Deny-CWE, harmloser Code: nie Close/suppress.
        for (cwe, snippet) in [
            (
                "CWE-89",
                "db.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")",
            ),
            ("CWE-78", "subprocess.run(f\"ping {host}\", shell=True)"),
            ("CWE-22", "open(os.path.join(BASE, filename))"),
            ("CWE-94", "return eval(expr)"),
            ("CWE-328", "hashlib.md5(pw).hexdigest()"),
            ("CWE-79", "print('hallo welt')"),
        ] {
            let out = deterministic_triage(&HashMap::new(), &finding_ctx(cwe, snippet)).unwrap();
            assert!(!out.cache_hit);
            assert!(
                out.proposal.verdict == "confirm" || out.proposal.verdict == "escalate",
                "fallback schliesst nie ({cwe}): {}",
                out.proposal.verdict
            );
            assert!(
                ["E0", "E1", "E2"].contains(&out.proposal.evidence_proposed.as_str()),
                "cap verletzt ({cwe}): {}",
                out.proposal.evidence_proposed
            );
            assert_ne!(
                out.record.verdict.action,
                crate::VerdictAction::Close,
                "record nie Close ({cwe})"
            );
            assert_eq!(out.record.verdict.model, "deterministic-fallback-v1");
        }
    }

    #[test]
    fn deterministisch_deny_wird_eskaliert() {
        let out = deterministic_triage(
            &HashMap::new(),
            &finding_ctx("CWE-328", "hashlib.md5(pw).hexdigest()"),
        )
        .unwrap();
        assert_eq!(out.proposal.verdict, "escalate");
        assert_eq!(out.record.verdict.action, crate::VerdictAction::Demote);
    }

    #[test]
    fn deterministisch_cache_hit_ohne_heuristik() {
        let ctx = finding_ctx("CWE-89", "x = 1");
        let fp = ctx.fingerprint();
        let mut cache = HashMap::new();
        cache.insert(
            fp.clone(),
            crate::CacheRecord {
                fingerprint: fp,
                verdict: crate::Verdict {
                    rule_id: ctx.rule_id.clone(),
                    cwe: ctx.cwe.clone(),
                    code_hash: crate::code_hash(&ctx.code_snippet),
                    action: crate::VerdictAction::Open,
                    severity_after: "medium".into(),
                    model: "m".into(),
                    prompt_version: "v1".into(),
                    tokens_in: 0,
                    tokens_out: 0,
                    policy_override: false,
                    provenance: None,
                },
                created_at: "2026-10-14T00:00:00Z".into(),
                format_version: crate::CACHE_FORMAT_VERSION,
            },
        );
        let out = deterministic_triage(&cache, &ctx).unwrap();
        assert!(out.cache_hit);
        assert_eq!(out.proposal.reason, "cache-hit");
    }

    #[test]
    fn fallback_greift_nur_bei_erschoepfter_kette() {
        // Erfolg: kein Fallback.
        let stages = vec![Stage::Ollama, Stage::Gemini];
        let mut n_fallback = 0;
        let ok = run_chain_with_fallback(
            &stages,
            &mut |s: &Stage| match s {
                Stage::Ollama => Err("down".to_string()),
                _ => Ok("gemini-ok"),
            },
            || {
                n_fallback += 1;
                "fallback"
            },
        );
        assert_eq!(ok.stage, Some(Stage::Gemini));
        assert!(!ok.used_fallback);
        assert_eq!(n_fallback, 0);
        assert_eq!(ok.attempted, vec![Stage::Ollama, Stage::Gemini]);

        // Alles down: Fallback mit Audit-Spuren.
        let out: FallbackOutcome<&str> = run_chain_with_fallback(
            &stages,
            &mut |_| Err::<&str, String>("boom".to_string()),
            || "fallback",
        );
        assert_eq!(out.stage, None);
        assert!(out.used_fallback);
        assert_eq!(out.value, "fallback");
        assert_eq!(out.attempted, stages);
        assert_eq!(out.last_error, Some("boom".to_string()));

        // Leere Kette (offline): Fallback sofort.
        let empty: FallbackOutcome<u8> = run_chain_with_fallback(&[], &mut |_| Ok(1u8), || 99u8);
        assert!(empty.used_fallback);
        assert_eq!(empty.value, 99);
        assert!(empty.attempted.is_empty());
        assert!(empty.last_error.is_some());
    }

    // ---- S4 Staged Confinement ----

    #[test]
    fn s4_verbotene_kombination_undarstellbar() {
        // Typ-Regel: (Netz UND Daten) ist per `new` undarstellbar.
        assert!(StageCaps::new(true, true).is_none());
        assert!(StageCaps::new(true, false).is_some());
        assert!(StageCaps::new(false, true).is_some());
        assert!(StageCaps::new(false, false).is_some());
        // Laufzeit-Regel: direkt konstruierte verbotene Caps scheitern.
        assert!(StageCaps {
            network: true,
            data: true
        }
        .check()
        .is_err());
        assert!(StageCaps {
            network: true,
            data: false
        }
        .check()
        .is_ok());
    }

    #[test]
    fn s4_stufen_matrix_netz_ohne_daten_daten_ohne_netz() {
        // Netz-Stufen: Netz JA, Roh-Daten NEIN.
        for s in [
            Stage::Ollama,
            Stage::Gemini,
            Stage::Deep(Engine::Opencode),
            Stage::Deep(Engine::Claude),
        ] {
            let c = stage_caps(&s);
            assert!(c.network, "{s} ist Netz-Stufe");
            assert!(!c.data, "{s} sieht nie Roh-Daten");
            c.check().unwrap();
        }
        // Daten-Stufe (deterministischer Fallback): Netz NEIN, Daten JA.
        let f = fallback_caps();
        assert!(!f.network, "Fallback hat nie Netz");
        assert!(f.data, "Fallback sieht lokale Daten");
        f.check().unwrap();
    }

    #[test]
    fn s4_kette_wird_validiert() {
        let full = plan_stages_checked(
            true,
            true,
            true,
            Engine::Opencode,
            &StageAvailability::all_available(),
        );
        assert!(check_chain_caps(&full.chain).is_ok());
        let offline = plan_stages_checked(
            false,
            false,
            false,
            Engine::Claude,
            &StageAvailability::offline(),
        );
        assert!(check_chain_caps(&offline.chain).is_ok());
    }

    #[test]
    fn s4_prompts_bleiben_secret_frei() {
        // Roh-Secrets im Finding-Kontext duerfen nie im Prompt landen —
        // fuer alle drei Prompt-Bauer (ollama/gemini/deep_engines).
        let raws = [
            "password = \"supersecret123\"",
            "token ghp_abcdefghijklmnopqrstuvw1234567890",
            "key sk-abcdefghijklmnopqrstuvw1234567890",
        ];
        for raw in raws {
            let ctx = crate::ollama::FindingContext {
                rule_id: "s4-matrix".into(),
                cwe: "CWE-798".into(),
                file: "s4.py".into(),
                start_line: Some(1),
                message: format!("Fundstelle: {raw}"),
                code_snippet: raw.to_string(),
            };
            for (name, prompt) in [
                ("ollama", crate::ollama::build_prompt(&ctx, "m")),
                ("gemini", crate::gemini::build_prompt(&ctx, "m")),
                ("deep", crate::deep_engines::build_prompt(&ctx, "m")),
            ] {
                assert!(
                    assert_prompt_secret_free(&prompt).is_ok(),
                    "{name}: Prompt enthaelt Secret-Material aus {raw:?}"
                );
            }
        }
        // Negativkontrolle: Das Gate beisst bei Roh-Secrets.
        assert!(assert_prompt_secret_free("password = \"supersecret123\"").is_err());
        assert!(assert_prompt_secret_free("harmloser Text ohne Secrets").is_ok());
    }

    // ---- S-5 Contested: deterministischer Merge ----

    fn ci(adapter: &str, verdict: &str, severity: &str) -> ContestedInput {
        ContestedInput::new(adapter, verdict, severity)
    }

    #[test]
    fn s5_konflikt_hoeherer_verdict_gewinnt() {
        // Zwei Scanner, gleicher Finding, gegensaetzliche Verdicts:
        // escalate gewinnt gegen suppress — nie still mitteln.
        let merged = merge_contested(&[
            ci("semgrep", "confirm", "high"),
            ci("codeql", "suppress", "low"),
        ]);
        assert_eq!(merged.verdict, "confirm");
        assert_eq!(merged.winner, "semgrep");
        assert!(merged.contested, "Widerspruch wird markiert");
        assert_eq!(merged.dissent, vec!["codeql"]);
        // Umgekehrte Reihenfolge: gleiches Ergebnis ( escalate gewinnt).
        let merged2 = merge_contested(&[
            ci("scannerA", "suppress", "low"),
            ci("scannerB", "escalate", "medium"),
            ci("scannerC", "confirm", "high"),
        ]);
        assert_eq!(merged2.verdict, "escalate");
        assert_eq!(merged2.winner, "scannerB");
        assert!(merged2.contested);
        assert_eq!(merged2.dissent, vec!["scannerA", "scannerC"]);
    }

    #[test]
    fn s5_zweifach_aufgerufen_identisch() {
        // Determinismus: gleiche Eingabe 2x aufrufen -> byte-gleiche Ausgabe.
        let inputs = [
            ci("ollama", "escalate", "high"),
            ci("gemini", "suppress", "medium"),
            ci("deep", "confirm", "critical"),
        ];
        let a = merge_contested(&inputs);
        let b = merge_contested(&inputs);
        assert_eq!(a, b, "2x aufgerufen muss identisch sein");
        assert_eq!(a.to_string(), b.to_string());
        // Auch in umgekehrter Reihenfolge bleibt der Gewinner deterministisch
        // (Rang-Modell, kein Index-Mittel).
        let rev: Vec<ContestedInput> = inputs.iter().rev().cloned().collect();
        let c = merge_contested(&rev);
        assert_eq!(c.verdict, "escalate");
        assert_eq!(c.winner, "ollama");
    }

    #[test]
    fn s5_tie_break_severity_dann_erster() {
        // Gleichrangige Verdicts: hoehere Severity gewinnt.
        let m = merge_contested(&[ci("x", "confirm", "low"), ci("y", "confirm", "critical")]);
        assert_eq!(m.winner, "y", "Severity-Tie-Break");
        assert!(!m.contested, "gleichrangig ist kein Widerspruch");
        // Sogar bei gleichem Verdict + Severity gewinnt der erste (Channel-
        // Order) — deterministisch, keine Koaleszenz der Adapter-Namen.
        let m2 = merge_contested(&[
            ci("semgrep", "confirm", "high"),
            ci("codeql", "confirm", "high"),
        ]);
        assert_eq!(m2.winner, "semgrep");
        assert!(!m2.contested);
        assert!(m2.dissent.is_empty());
    }

    #[test]
    fn s5_ohne_konflikt_nicht_contested_und_ohne_mittelung() {
        // Identische Befunde: contested bleibt false, Ergebnis = Befund.
        let m = merge_contested(&[ci("semgrep", "suppress", "low")]);
        assert_eq!(m.verdict, "suppress");
        assert_eq!(m.winner, "semgrep");
        assert!(!m.contested);
        assert_eq!(m.dissent, Vec::<String>::new());
        // Leerer Input: deterministischer Default (kein Panic, kein Mittel).
        let e = merge_contested(&[]);
        assert_eq!(e.verdict, "confirm");
        assert!(!e.contested);
        // Severity wird normalisiert (klein + getrimmt) und ist die des
        // Gewinners — nie der Mittelwert ueber die Inputs.
        let mn = merge_contested(&[ci("a", "confirm", "HIGH"), ci("b", "confirm", "error")]);
        assert_eq!(mn.severity, "high", "Gewinner 'a' hat die hoehere Severity");
        assert_eq!(mn.winner, "a");
    }

    #[test]
    fn s5_unbekannte_verdict_werte_sind_deterministisch() {
        // Fremde Verdict-Schreibweise wird nicht gepanickt, sondern
        // deterministisch behandelt (wie bestehende Probe-Tests: tolerant).
        let m = merge_contested(&[ci("a", "unbekannt", "high"), ci("b", "escalate", "low")]);
        assert_eq!(m.verdict, "escalate");
        assert_eq!(m.winner, "b");
        assert!(m.contested);
        assert_eq!(m.dissent, vec!["a"]);
    }
}
