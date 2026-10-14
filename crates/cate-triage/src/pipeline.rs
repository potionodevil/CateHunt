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
use crate::deep_engines::Engine;
use crate::gemini::Backend;

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
    let primary = crate::gemini::select_backend(gemini_available_and_logged_in);
    let deep = crate::deep_engines::select_deep_engine(deny_cwe, uncertain, deep_opt_in, prefer);
    let mut chain = vec![Stage::Ollama];
    if primary == Backend::Gemini {
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
}
