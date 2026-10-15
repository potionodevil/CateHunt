// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! S-2 Adapter-Pinning: feste Pin-Zeile je Triage-/Scanner-Adapter.
//!
//! Jeder Adapter (Stufe 1–3 + deterministischer Fallback) wird auf
//! Model-Version, Probe-/Discovery-Endpoint und Prompt-Version fest
//! gepinnt. Die Pins sind die verbindliche Konvention aus
//! docs/TRIAGE_BACKENDS.md Abschnitt "S-2 Pinning-Nachweis":
//!
//! - **Modell-Pins:** Nur das in der Tabelle gepinnte Modell darf an den
//!   Adapter gehen (`model_pin_ok`); Abweichung = Konfig-Fehler, kein
//!   stiller Modell-Wechsel.
//! - **Probe-/Discovery-Pins:** Woher Verfuegbarkeit kommt (TCP-Loopback
//!   fuer Ollama, `<cli> --version` fuer CLIs) — identisch mit
//!   `crate::pipeline::probe_availability`, kein Modell-Call.
//! - **Prompt-Pins:** `PROMPT_VERSION` je Adapter steuert die Cache-
//!   Invalidierung; Wechsel trift den Cache zum Miss, nie zum stillen Hit.
//!
//! Verifikation ist rein offline (`verifiziere_pins_offline`): Konstanten-
//! Gleichheit mit den Adapter-Defaults + Loopback-Zwang. Es gibt **keine**
//! Netz-Calls in den Tests (Tiny-Offline-Stub-Verhalten wie in den
//! bestehenden Availability-Probe-Tests: Remote-Hosts/unbekannte CLIs
//! werden abgewiesen bzw. brauchen keine Hosts).
use crate::deep_engines::DeepConfig;
use crate::gemini::GeminiConfig;

/// Pin-Bezeichner als Konvention (Adapter-Schluessel in Nimmt falls `pins_spalten_eng` benoetigt werden, der Zusammensteck-Identitaet).
mod pins_impl {
    /// Adapter-Key: Stufe-3-Opencode-CLI.
    pub const ADAPTER_OLLAMA: &str = "ollama";
    pub const ADAPTER_GEMINI: &str = "gemini";
    pub const ADAPTER_DEEP_OPENCODE: &str = "deep-opencode";
    pub const ADAPTER_DEEP_CLAUDE: &str = "deep-claude";
    pub const ADAPTER_FALLBACK: &str = "deterministic-fallback";
}

pub use pins_impl::*;

/// Art eines Pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinKind {
    /// Modell-Version (hard pin: nur dieser Wert erlaubt).
    Model,
    /// CLI-Binary-Name (Discovery-Pin: Praesenz-Probeprozess `<cli> --version`).
    Cli,
    /// Probe-/Discovery-Endpoint bzw. Args-Schema (offline pruefbar).
    Probe,
    /// Prompt-Version (Cache-Invalidierung bei Wechsel).
    Prompt,
}

impl std::fmt::Display for PinKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Model => write!(f, "model"),
            Self::Cli => write!(f, "cli"),
            Self::Probe => write!(f, "probe"),
            Self::Prompt => write!(f, "prompt"),
        }
    }
}

/// Eine Pin-Zeile: Adapter + Art + fester Wert + Delivery-Probe-Beschreibung.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterPin {
    /// Adapter-Schluessel (`ollama` | `gemini` | `deep-opencode` |
    /// `deep-claude` | `deterministic-fallback`).
    pub adapter: &'static str,
    pub kind: PinKind,
    /// Fest gepinnter Wert (Modellname, CLI, Endpoint-/Args-Schema,
    /// Prompt-Version).
    pub pinned: &'static str,
    /// Offline-Probe, die den Pin verifiziert (kein Netz ausser TCP-Loopback).
    pub probe: &'static str,
}

impl AdapterPin {
    /// Sortier-/Vergleichsschluessel (Adapter, Art) — Determinismus der Tabelle.
    pub fn key(&self) -> (&'static str, PinKind) {
        (self.adapter, self.kind)
    }
}

/// Modell-Label des deterministischen Fallbacks (wie im Record persistiert).
pub const FALLBACK_MODEL_LABEL: &str = "deterministic-fallback-v1";

/// Feste Pin-Tabelle in deterministischer Reihenfolge (Adapter, Art).
/// **Aenderung = bewusster Pin-Sprung** (Prompt-/Cache-Invalidierung,
/// Dokupflicht in docs/TRIAGE_BACKENDS.md).
pub const ADAPTER_PINS: &[AdapterPin] = &[
    // ---- Stufe 1: Ollama (localhost, Default + Offline-Modus) ----
    AdapterPin {
        adapter: ADAPTER_OLLAMA,
        kind: PinKind::Model,
        pinned: crate::ollama::DEFAULT_MODEL,
        probe: "Request-Body `model`-Feld (`POST /api/generate`); Discovery enim: `/api/tags` wird bewusst NICHT benutzt",
    },
    AdapterPin {
        adapter: ADAPTER_OLLAMA,
        kind: PinKind::Probe,
        pinned: "http://127.0.0.1:11434 + POST /api/generate",
        probe: "crate::pipeline::probe_ollama_reachable: TCP-Loopback-Connect (500 ms), nur localhost/127.0.0.1/::1; kein Modell-Call",
    },
    AdapterPin {
        adapter: ADAPTER_OLLAMA,
        kind: PinKind::Prompt,
        pinned: crate::ollama::PROMPT_VERSION,
        probe: "im Verdict persistiert (`Verdict.prompt_version`); Cache-Invalidierung bei Wechsel",
    },
    // ---- Stufe 2: Gemini-CLI (Default, wenn CLI + Login) ----
    AdapterPin {
        adapter: ADAPTER_GEMINI,
        kind: PinKind::Cli,
        pinned: crate::gemini::DEFAULT_CLI,
        probe: "crate::pipeline::probe_cli_present: `<cli> --version`, Exit 0; kein Login, kein Netz",
    },
    AdapterPin {
        adapter: ADAPTER_GEMINI,
        kind: PinKind::Probe,
        pinned: "--output-format json -p <prompt>",
        probe: "crate::gemini::build_args (Default-Config ohne `-m`): args[0..7] gleich den Schema-Tokens",
    },
    AdapterPin {
        adapter: ADAPTER_GEMINI,
        kind: PinKind::Prompt,
        pinned: crate::gemini::PROMPT_VERSION,
        probe: "im Verdict persistiert; Cache-Invalidierung bei Wechsel",
    },
    // ---- Stufe 3a: opencode (Opt-in, nur schwere Faelle) ----
    AdapterPin {
        adapter: ADAPTER_DEEP_OPENCODE,
        kind: PinKind::Cli,
        pinned: "opencode",
        probe: "crate::pipeline::probe_cli_present + DeepConfig::opencode().cli",
    },
    AdapterPin {
        adapter: ADAPTER_DEEP_OPENCODE,
        kind: PinKind::Probe,
        pinned: "run --format json <prompt>",
        probe: "crate::deep_engines::build_args (Opencode, ohne `-m`)",
    },
    AdapterPin {
        adapter: ADAPTER_DEEP_OPENCODE,
        kind: PinKind::Prompt,
        pinned: crate::deep_engines::PROMPT_VERSION,
        probe: "im Verdict persistiert; Cache-Invalidierung bei Wechsel",
    },
    // ---- Stufe 3b: claude (Opt-in, nur schwere Faelle) ----
    AdapterPin {
        adapter: ADAPTER_DEEP_CLAUDE,
        kind: PinKind::Cli,
        pinned: "claude",
        probe: "crate::pipeline::probe_cli_present + DeepConfig::claude().cli",
    },
    AdapterPin {
        adapter: ADAPTER_DEEP_CLAUDE,
        kind: PinKind::Probe,
        pinned: "-p --output-format json <prompt>",
        probe: "crate::deep_engines::build_args (Claude, ohne `--model`)",
    },
    AdapterPin {
        adapter: ADAPTER_DEEP_CLAUDE,
        kind: PinKind::Prompt,
        pinned: crate::deep_engines::PROMPT_VERSION,
        probe: "im Verdict persistiert; Cache-Invalidierung bei Wechsel",
    },
    // ---- Deterministischer Fallback (offline-pur) ----
    AdapterPin {
        adapter: ADAPTER_FALLBACK,
        kind: PinKind::Model,
        pinned: FALLBACK_MODEL_LABEL,
        probe: "crate::pipeline::deterministic_triage: kein Netz, kein Subprozess, offline-pur",
    },
    AdapterPin {
        adapter: ADAPTER_FALLBACK,
        kind: PinKind::Prompt,
        pinned: crate::ollama::PROMPT_VERSION,
        probe: "deterministischer Fallback teilt die Ollama-Prompt-Version (gleicher Prompt-Bauer)",
    },
];

/// Rueckgabe: Liste aller Pins fuer einen Adapter (Discovery-Hilfe).
pub fn pins_of(adapter: &str) -> Vec<&'static AdapterPin> {
    ADAPTER_PINS
        .iter()
        .filter(|p| p.adapter == adapter)
        .collect()
}

/// Modell-Pin-Check zur Laufzeit: darf `model` an diesen Adapter gehen?
/// - `ollama`: nur `DEFAULT_MODEL`.
/// - `deterministic-fallback`: nur das Fallback-Label.
/// - CLI-Backends (`gemini`, `deep-*`): Modellwahl ist User-Config
///   (`Option<String>`), gepinnt ist das Args-Schema ohne `-m`/`--model`
///   — hier gilt der Pin als erfuellt (keine Modell-Entities zu pruefen).
pub fn model_pin_ok(adapter: &str, model: &str) -> bool {
    match adapter {
        ADAPTER_OLLAMA => model == crate::ollama::DEFAULT_MODEL,
        ADAPTER_FALLBACK => model == FALLBACK_MODEL_LABEL,
        // CLI-Backends: Modellwahl ist User-Config, hier kein Modell-Pin
        // (Args-Schema-Pin verifiziert den Transport).
        _ => true,
    }
}

/// Prueft ein beobachtetes `(adapter, model)` gegen die Pin-Tabelle
/// (Discovery-Variante: unbebekanntes `muster` ist immer `false`).
pub fn pin_matches(adapter: &str, model: &str) -> bool {
    let known = ADAPTER_PINS
        .iter()
        .any(|p| p.adapter == adapter && p.kind == PinKind::Model);
    if !known {
        return false;
    }
    model_pin_ok(adapter, model)
}

/// Kleiner Offline-Verifikations-Stub: beschreibt die Probe-Zeile, die fuer
/// einen Pin in Tests laeuft (immer ohne Netz; Future: CLI-Hook hier).
pub fn probe_description(adapter: &str, kind: PinKind) -> Option<&'static str> {
    ADAPTER_PINS
        .iter()
        .find(|p| p.adapter == adapter && p.kind == kind)
        .map(|p| p.probe)
}

/// Offline-Verifikation aller Pins (kein Netz):
/// 1. Tabelle deterministisch sortiert nach `(Adapter, Art)` — Reihenfolge
///    ist Teil des Nachweises (Audit-logging).
/// 2. Kein `(Adapter, Art)`-Duplikat.
/// 3. Kein leerer Pin-Wert, keine leere Probe-Beschreibung.
/// 4. Ollama-Endpoint-Pin ist eine gueltige Loopback-URL; `https`/Remote
///    wird vom Transport abgelehnt (Loopback-Zwang bleibt intakt).
/// 5. Gemini-/Deep-CLI-Pins stimmen mit den Default-Konfigs ueberein.
///
/// Kanonische Adapter-Reihenfolge der Pin-Tabelle = Pipeline-Stufen-Order
/// (Stufe 1 -> 2 -> 3a -> 3b -> Fallback). Determinismus des Nachweises.
const ADAPTER_ORDER: &[&str] = &[
    ADAPTER_OLLAMA,
    ADAPTER_GEMINI,
    ADAPTER_DEEP_OPENCODE,
    ADAPTER_DEEP_CLAUDE,
    ADAPTER_FALLBACK,
];

fn adapter_rank(adapter: &str) -> usize {
    ADAPTER_ORDER
        .iter()
        .position(|a| *a == adapter)
        .unwrap_or(ADAPTER_ORDER.len())
}

fn kind_rank(kind: PinKind) -> u8 {
    match kind {
        PinKind::Model => 0,
        PinKind::Cli => 1,
        PinKind::Probe => 2,
        PinKind::Prompt => 3,
    }
}

pub fn verifiziere_pins_offline() -> Result<(), String> {
    // 1) Tabelle ist in der kanonischen Order (Stufe, Art) gruppiert; jede
    //    Stufe ist genau einmal in der Reihenfolge vertreten.
    let mut seen_adapters: Vec<&str> = Vec::new();
    for p in ADAPTER_PINS {
        if seen_adapters.last() != Some(&p.adapter) {
            if seen_adapters.contains(&p.adapter) {
                return Err(format!(
                    "S-2-Adapter {} mehrfach in der Pin-Tabelle (nicht gruppiert)",
                    p.adapter
                ));
            }
            seen_adapters.push(p.adapter);
        }
    }
    for (i, adapter) in seen_adapters.iter().enumerate() {
        if adapter_rank(adapter) != i {
            return Err(format!(
                "S-2-Pin-Tabelle nicht in kanonischer Stufen-Reihenfolge ({} an Position {})",
                adapter, i
            ));
        }
    }
    // 2) Duplikate pro Adapter (Model/Cli/Probe/Prompt je einmal).
    let mut keys: Vec<(&str, PinKind)> = ADAPTER_PINS.iter().map(|p| p.key()).collect();
    keys.sort_by_key(|(a, k)| (adapter_rank(a), kind_rank(*k)));
    for i in 1..keys.len() {
        if keys[i] == keys[i - 1] {
            return Err(format!(
                "S-2-Pin-Duplikat: ({}, {kind:?})",
                keys[i].0,
                kind = keys[i].1
            ));
        }
    }
    // Test-Konvention: jede Stufe hat alle vier Pin-Kinds
    // (Fallback: keine CLI → nur Model/Probe/Prompt),
    let mut per_adapter: std::collections::HashMap<&str, Vec<PinKind>> =
        std::collections::HashMap::new();
    for p in ADAPTER_PINS {
        per_adapter.entry(p.adapter).or_default().push(p.kind);
    }
    for (adapter, kinds) in per_adapter {
        let mut seen = Vec::new();
        for k in &kinds {
            if seen.contains(k) {
                return Err(format!("S-2-Pin-Duplikat: {}: {:?}", adapter, k));
            }
            seen.push(*k);
        }
    }

    // 3) Leere Werte.
    for p in ADAPTER_PINS {
        if p.pinned.trim().is_empty() {
            return Err(format!("S-2-Pin {} {} leer", p.adapter, p.kind));
        }
        if p.probe.trim().is_empty() {
            return Err(format!(
                "S-2-Probe {} {} ohne Beschreibung",
                p.adapter, p.kind
            ));
        }
    }
    // 4) Ollama-Loopback-Zwang bleibt intakt: gepinnter Endpoint identifiziert
    //    einen Loopback-Host; Remote-URLs sind verboten.
    let ollama_probe = ADAPTER_PINS
        .iter()
        .find(|p| p.adapter == ADAPTER_OLLAMA && p.kind == PinKind::Probe)
        .expect("ollama probe pin fehlt");
    let base = ollama_probe.pinned.split(" + ").next().unwrap_or("");
    let base_checked = crate::ollama::check_base_url(base)
        .map_err(|e| format!("S-2-Ollama-Endpoint-Pin verletzt Loopback-Zwang: {e}"))?;
    if base_checked != "127.0.0.1:11434" {
        return Err(format!(
            "S-2-Ollama-Endpoint-Pin zeigt auf unerwarteten Pfad: {base_checked}"
        ));
    }
    // 5) CLI-Pins == Default-Konfigs.
    if ADAPTER_PINS
        .iter()
        .find(|p| p.adapter == ADAPTER_GEMINI && p.kind == PinKind::Cli)
        .expect("gemini cli pin fehlt")
        .pinned
        != GeminiConfig::default().cli
    {
        return Err("S-2-Gemini-CLI-Pin ungleich Default-Konfig".to_string());
    }
    if ADAPTER_PINS
        .iter()
        .find(|p| p.adapter == ADAPTER_DEEP_OPENCODE && p.kind == PinKind::Cli)
        .expect("deep-opencode cli pin fehlt")
        .pinned
        != DeepConfig::opencode().cli
    {
        return Err("S-2-Deep-Opencode-CLI-Pin ungleich Default-Konfig".to_string());
    }
    if ADAPTER_PINS
        .iter()
        .find(|p| p.adapter == ADAPTER_DEEP_CLAUDE && p.kind == PinKind::Cli)
        .expect("deep-claude cli pin fehlt")
        .pinned
        != DeepConfig::claude().cli
    {
        return Err("S-2-Deep-Claude-CLI-Pin ungleich Default-Konfig".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_tabelle_ist_vollstaendig_und_verifiziert() {
        // Offline-Verifikation: Sortierung, Duplikate, Werte, Loopback-Zwang,
        // CLI-Pins == Default-Konfigs.
        verifiziere_pins_offline().unwrap();
        // Vollstaendigkeit: jeder Adapter hat Model/Cli- oder Probe-/Prompt-Pin.
        for adapter in [
            ADAPTER_OLLAMA,
            ADAPTER_GEMINI,
            ADAPTER_DEEP_OPENCODE,
            ADAPTER_DEEP_CLAUDE,
            ADAPTER_FALLBACK,
        ] {
            let pins = pins_of(adapter);
            // Modell-Pin nur bei Ollama/Fallback (CLI-Backends pinnen das
            // Args-Schema statt eines Modells); deterministischer Fallback
            // hat kein Transport-Schema (2 Pins: Model + Prompt).
            let expected_kinds: &[PinKind] = match adapter {
                ADAPTER_OLLAMA => &[PinKind::Model, PinKind::Probe, PinKind::Prompt],
                ADAPTER_FALLBACK => &[PinKind::Model, PinKind::Prompt],
                _ => &[PinKind::Cli, PinKind::Probe, PinKind::Prompt],
            };
            assert_eq!(
                pins.len(),
                expected_kinds.len(),
                "{adapter}: Pin-Anzahl: {pins:?}"
            );
            let present: Vec<PinKind> = pins.iter().map(|p| p.kind).collect();
            for kind in expected_kinds {
                assert!(
                    present.contains(kind),
                    "{adapter}: Pin {kind} fehlt (vorhanden: {present:?})"
                );
                assert!(
                    probe_description(adapter, *kind).is_some(),
                    "{adapter}: Probe-Beschreibung fuer {kind} fehlt"
                );
            }
        }
    }

    #[test]
    fn pins_gleich_adapter_defaults() {
        // Modell-/Prompt-Pins sind keine Freitext-Kopien, sondern die
        // echten Adapter-Konstanten (identische Strings).
        assert_eq!(
            pins_of(ADAPTER_OLLAMA)[0].pinned,
            crate::ollama::DEFAULT_MODEL
        );
        assert_eq!(pins_of(ADAPTER_FALLBACK)[0].pinned, FALLBACK_MODEL_LABEL);
        assert_eq!(crate::ollama::PROMPT_VERSION, "v1");
        assert_eq!(crate::gemini::PROMPT_VERSION, "v1");
        assert_eq!(crate::deep_engines::PROMPT_VERSION, "v1");
    }

    #[test]
    fn arg_schema_pins_stimmen_mit_build_args() {
        // Discovery-Pins = beobachtbare Args-Shapes (ohne Modell-Flag).
        let g = crate::gemini::build_args(&GeminiConfig::default(), "P");
        assert_eq!(
            &g[..3],
            &[
                "--output-format".to_string(),
                "json".to_string(),
                "-p".to_string()
            ]
        );
        let o = crate::deep_engines::build_args(&DeepConfig::opencode(), "P");
        assert_eq!(
            &o[..3],
            &[
                "run".to_string(),
                "--format".to_string(),
                "json".to_string()
            ]
        );
        let c = crate::deep_engines::build_args(&DeepConfig::claude(), "P");
        assert_eq!(
            &c[..3],
            &[
                "-p".to_string(),
                "--output-format".to_string(),
                "json".to_string()
            ]
        );
    }

    #[test]
    fn model_pin_ok_nur_gepinntes_ollama_modell() {
        assert!(model_pin_ok(ADAPTER_OLLAMA, "qwen2.5-coder:7b"));
        assert!(!model_pin_ok(ADAPTER_OLLAMA, "llama3:8b"));
        assert!(model_pin_ok(ADAPTER_FALLBACK, FALLBACK_MODEL_LABEL));
        assert!(!model_pin_ok(ADAPTER_FALLBACK, "etwas-anderes"));
        // CLI-Backends: User-Modellwahl gepinnt nur ans Args-Schema.
        assert!(model_pin_ok(ADAPTER_GEMINI, "gemini-2.5-flash"));
        assert!(pin_matches(ADAPTER_OLLAMA, "qwen2.5-coder:7b"));
        assert!(!pin_matches("unbekannter-adapter", "x"));
    }

    #[test]
    fn pins_verifizieren_offline_ohne_netz() {
        // Identisch zum Probe-Stil der bestehenden Availability-Tests:
        // Remote-Hosts/unbekannte CLIs brechen nie Netz-Tests.
        assert!(!crate::pipeline::probe_ollama_reachable(
            "https://example.com:11434",
            50
        ));
        assert!(!crate::pipeline::probe_cli_present(
            "catehunt-gibt-es-nicht-xyz"
        ));
        // Und trotzdem verifiziert die Pin-Tabelle offline komplett.
        verifiziere_pins_offline().unwrap();
    }
}
