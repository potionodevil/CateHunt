# CateHunt v2 — Plan (MVP Phasen 1–3)

> Evidence Gate für KI-generierten Code. Lokales Desktop-Tool, local-first.
> Sprache: Deutsch. Stand: 2026-10-14. Arbeitsverzeichnis: `E:/CodeCate` (neu, kein git).

## 1. Architektur-Übersicht

```
┌─────────────────────────────────────────────────────────────┐
│ Tauri-UI (Phase 3) — Review-Workbench                       │
│ Evidence-Level E0–E4, Health-Score (nur E2+ zählt als Bug)   │
└──────────────────────────┬──────────────────────────────────┘
                           │ JSON
┌──────────────────────────▼──────────────────────────────────┐
│ Rust-Core (Phase 1)                                         │
│ Stufe 0 Scope/Inventar │ Stufe 1 Tree-sitter-Metriken       │
│ Stufe 2 SARIF-Import (Semgrep/CodeQL) │ Paketprüfung        │
└──────────────────────────┬──────────────────────────────────┘
                           │ Findings
┌──────────────────────────▼──────────────────────────────────┐
│ Triage (Phase 2) — Ollama/Qwen read-only, Verdict-Cache,    │
│ Deny-List (Krypto/Auth/Deserialisierung nie auto-suppress)   │
└─────────────────────────────────────────────────────────────┘
Später: Phase 4 Sandbox (E3-Validierung) → Phase 5 MCP → Phase 6 Ausbau.
```

**Pipeline:** `audit_diff` (Scope aus git diff + Lockfile) → deterministische Metriken → SARIF-Import → Triage mit Cache → UI mit Evidence-Farben → (später) Sandbox E3 + Variant Analysis.

**Evidence-Level (Farben, UI-Verhalten):**

| Level | Bedeutung | Farbe | Verhalten |
|---|---|---|---|
| E0 | Hypothese | grau | eingeklappt |
| E1 | statisch | gelb | aufgeführt |
| E2 | Datenfluss | orange | zählt als Bug |
| E3 | reproduziert (Test/PoC) | rot | oben angepinnt |
| E4 | Fix verifiziert | grün | geschlossen |

Nur E2+ zählt als Bug im Health-Score.

**MCP-Tools (Zielbild, ab Phase 5):** `audit_diff`, `get_graph`, `explain_finding`, `verify_fix`, `check_dependencies`.

**Local-first:** Ollama Standard, Gemini opt-in.

## 2. Phase 1 — Rust-Core + SARIF + Paketprüfung (CLI mit JSON)

### Meilensteine
- [ ] M1.1 Workspace + CLI-Gerüst (`catehunt` Binary, `cargo` Workspace)
- [ ] M1.2 Stufe 0: Scope/Inventar — `git diff` parsen, Lockfile (`Cargo.lock`, `package-lock.json`, `pnpm-lock.yaml`) auswerten
- [ ] M1.3 Stufe 1: deterministische Tree-sitter-Metriken (Rust) pro Datei/Funktion
- [ ] M1.4 Stufe 2: SARIF-Import (Semgrep/CodeQL) → internes Finding-Modell
- [ ] M1.5 Paketprüfung (`check_dependencies` Kern: bekannte advisories gegen Lockfile matchen, offline-DB)
- [ ] M1.6 CLI gibt JSON aus (`findings.json`, `health.json`), Exit-Code ≠ 0 bei E2+

### Dateistruktur Rust-Workspace + Tauri (Zielbild, Phasen 1–3)

```
E:/CodeCate/
├── Cargo.toml                  # Workspace
├── README.md
├── docs/PLAN.md
├── crates/
│   ├── catehunt-core/          # Phase 1: Modelle (Evidence, Finding), Health-Score
│   │   ├── Cargo.toml
│   │   └── src/{lib.rs, evidence.rs, finding.rs, sarif.rs, health.rs}
│   ├── catehunt-scope/         # Phase 1: Stufe 0 git diff + Lockfile/Inventar
│   │   ├── Cargo.toml
│   │   └── src/{lib.rs, git_diff.rs, lockfile.rs}
│   ├── catehunt-metrics/       # Phase 1: Stufe 1 Tree-sitter-Metriken
│   │   ├── Cargo.toml
│   │   └── src/{lib.rs, rust.rs}
│   ├── catehunt-deps/          # Phase 1: Paketprüfung
│   │   ├── Cargo.toml
│   │   └── src/{lib.rs, advisory.rs}
│   ├── catehunt-triage/        # Phase 2: Ollama/Qwen read-only + Cache + Deny-List
│   │   ├── Cargo.toml
│   │   └── src/{lib.rs, ollama.rs, verdict.rs, denylist.rs, cache.rs}
│   └── catehunt-cli/           # Phase 1/2: CLI mit JSON-Output
│       ├── Cargo.toml
│       └── src/main.rs
├── src-tauri/                  # Phase 3: Tauri-Backend (bindet catehunt-core an)
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   └── src/main.rs
├── ui/                         # Phase 3: Frontend (Review-Workbench)
│   ├── package.json
│   └── src/{App.*, views/Review.*, components/EvidenceBadge.*}
└── tests/
    ├── fixtures/sarif/{semgrep.json, codeql.json}
    └── goldens/{findings.json, health.json}
```

### SARIF-Schema (Import-Subset)

Unterstützt SARIF 2.1.0, gelesen werden nur:

```
sarifLog { version, runs[] }
run { tool.driver { name, version, rules[] }, results[] }
result { ruleId, level (error|warning|note), message.text,
         locations[] { physicalLocation {
           artifactLocation.uri, region { startLine, endLine } } },
         partialFingerprints?, fixes? (ignoriert in Phase 1) }
```

Mapping: `ruleId` → Finding-Kategorie, `level=error` → Kandidat E1, `warning/note` → E0/E1. Ohne verwertbare `locations[].physicalLocation` → Finding wird mit `unlocated=true` markiert und nicht in Health-Score übernommen. Semgrep- und CodeQL-SARIF werden über denselben Parser gelesen (CodeQL: `runs[0].tool.driver.name == "CodeQL"` als Provenienz-Tag).

### Evidence-Level-Datenmodell (Rust-Structs)

```rust
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceLevel { E0, E1, E2, E3, E4 }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category { Crypto, Auth, Deserialization, Injection, Other }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file: PathBuf,
    pub start_line: Option<u32>,
    pub end_line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,               // stabil: hash(rule_id + file + start_line)
    pub rule_id: String,
    pub provenance: String,       // "semgrep" | "codeql" | "metrics" | "deps"
    pub category: Category,
    pub evidence: EvidenceLevel,  // Start: E0/E1, Upgrade nur mit Beleg
    pub unlocated: bool,          // true → kein Health-Score
    pub location: Option<Location>,
    pub message: String,
    pub fingerprint: String,      // SARIF partialFingerprints oder eigener Hash
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthScore {
    pub total_e2_plus: u32,        // nur E2+ zählen
    pub by_level: std::collections::BTreeMap<String, u32>,
    pub score_0_100: u8,
}
```

Regeln: nur E2+ zählt als Bug (`total_e2_plus`). E0 grau eingeklappt, E3 rot oben, E4 grün. Upgrade E1→E2 nur mit Datenfluss-Beleg, →E3 nur per Sandbox-Test/PoC (Phase 4), →E4 nur per `verify_fix` (später).

### Akzeptanzkriterien Phase 1
- [ ] `catehunt audit --sarif <file> --diff <base>..HEAD` läuft offline, gibt `findings.json` + `health.json` aus
- [ ] Semgrep- und CodeQL-Fixture-SARIF parsen ohne Fehler, je ≥ 1 Finding mit korrekter Provenienz
- [ ] Finding ohne Location → `unlocated=true`, nicht im Score
- [ ] Health-Score zählt ausschließlich E2+; E0/E1 beeinflussen Score nicht
- [ ] Golden-Tests: `tests/goldens/*.json` byte-stabil bei unverändertem Input
- [ ] `cargo clippy -- -D warnings` und `cargo test` grün

## 3. Phase 2 — Triage + Cache + Benchmark

### Meilensteine
- [ ] M2.1 Ollama/Qwen-Client read-only (nur Prompt mit Finding-Kontext, kein Code-Write, kein Netz außer localhost + opt-in Gemini)
- [ ] M2.2 Verdict-Cache (Datei, s. Format unten) mit Hit-Rate-Logging
- [ ] M2.3 Deny-List: `crypto`, `auth`, `deserialization` → nie auto-suppress, immer menschlicher Review
- [ ] M2.4 Benchmark-Harness: Precision/Recall gegen gelabelte Fixtures, Cache-Hit-Rate

### Verdict-Cache-Format (JSON, Datei `~/.cache/catehunt/verdicts.json` bzw. Projekt-`.catehunt/cache.json`)

```json
{
  "version": 1,
  "verdicts": {
    "<finding_fingerprint>": {
      "verdict": "confirm | suppress | escalate",
      "evidence_proposed": "E0|E1|E2",
      "reason": "kurze Begründung, max 280 Zeichen",
      "model": "qwen2.5-coder:7b",
      "created_at": "2026-10-14T12:00:00Z",
      "denylisted": false
    }
  }
}
```

Regeln: Key ist `Finding.fingerprint` (stabil über Runs). `suppress` bei `denylisted=true` (Deny-List-Kategorie) ist ungültig → wird zu `escalate` hochgestuft. Cache-Einträge sind lesbar/prünfähig, kein binäres Format. `evidence_proposed` darf nie höher als E2 sein (E3/E4 nur via Sandbox/Fix-Verifikation).

### MCP-API-Signaturen (Zielbild, implementiert ab Phase 5, hier fixiert)

```rust
// audit_diff(base: &str, head: &str) -> Vec<Finding>   // Stufe 0+1+2
fn audit_diff(base: &str, head: &str) -> anyhow::Result<Vec<Finding>>;
// get_graph(file: &str) -> Funktions-/Call-Graph als JSON
fn get_graph(file: &str) -> anyhow::Result<serde_json::Value>;
// explain_finding(id: &str) -> natürliche Erklärung + Evidence-Begründung
fn explain_finding(id: &str) -> anyhow::Result<String>;
// verify_fix(id: &str) -> bool, hebt E3→E4 nur bei bestandenem Re-Test
fn verify_fix(id: &str) -> anyhow::Result<bool>;
// check_dependencies(lockfile: &str) -> advisories
fn check_dependencies(lockfile: &str) -> anyhow::Result<Vec<serde_json::Value>>;
```

Alle read-only außer `verify_fix` (führt Tests in Sandbox aus, Phase 4+). Kein automatischer Code-Write durch Triage.

### Akzeptanzkriterien Phase 2
- [ ] Triage läuft vollständig offline mit Ollama/Qwen (localhost), kein ausgehender Netzverkehr im Default
- [ ] Cache-Hit bei identischem Fingerprint ohne erneuten Modell-Call (Log belegt Hit-Rate)
- [ ] Deny-List-Test: Findings der Kategorien Krypto/Auth/Deserialisierung werden nie `suppress` (negativer Testfall vorhanden)
- [ ] `evidence_proposed` nie > E2 aus Triage
- [ ] Benchmark: Precision/Recall auf Fixtures dokumentiert, keine Regression gegenüber Baseline

## 4. Phase 3 — Tauri-UI Review-Workbench

### Meilensteine
- [ ] M3.1 `src-tauri/` + `ui/` Gerüst, Tauri ruft `catehunt-core` direkt (kein separater Server)
- [ ] M3.2 Review-Liste: E3 rot oben, E0 grau eingeklappt, Filter nach Level/Kategorie
- [ ] M3.3 Detailansicht: Finding + Evidence-Begründung + `explain_finding`-Text
- [ ] M3.4 Aktionen: bestätigen / eskalieren / suppressen (Deny-List blockt Suppress in UI)

### Akzeptanzkriterien Phase 3
- [ ] App startet lokal ohne Netz, lädt `findings.json` aus Phase 1/2
- [ ] Sortierung: E3 oben (rot), E4 grün, E0 grau eingeklappt — per Screenshot-/DOM-Test verifiziert
- [ ] Suppress-Button für Deny-List-Kategorien deaktiviert mit Begründung
- [ ] Health-Score-Anzeige stimmt mit `health.json` überein (nur E2+)

## 5. Offene Risiken (aus Masterplan Abschnitt 12)

Aus dem Masterplan lagen nur die Abschnittstitel/Kernpunkte vor (Arbeitsverzeichnis war leer, kein Masterplan-Dokument auffindbar) — folgende Risiken sind aus den Kernpunkten abgeleitet und vor Phase 1 zu klären:

1. **Tree-sitter-Rust-Reife:** unklar, ob Metriken-Aussagekraft für Health-Score ausreicht — Spike in M1.3 mit echten Repos einplanen.
2. **SARIF-Dialekte:** Semgrep vs. CodeQL weichen in `locations`/`fingerprints` ab — Parser tolerant bauen, Fixtures beider Tools pflicht.
3. **Ollama/Qwen-Qualität lokal:** kleine Modelle neigen zu False-Suppress — Deny-List + E2-Cap + Benchmark als Gegenmaßnahme, kein Blindvertrauen.
4. **Verdict-Cache-Invalidierung:** Fingerprint-Stabilität bei Zeilenverschiebung — Hash über normalisierte (rule + Datei + Kontext) statt reiner Zeilennummer.
5. **Sandbox-Sicherheit (Phase 4+):** PoC-Ausführung braucht Isolation — kein Vorgriff in Phasen 1–3, keine `verify_fix`-Automatik vor Sandbox.
6. **Scope-Creep UI:** Review-Workbench darf kein IDE-Ersatz werden — Phase 3 strikt auf Liste/Detail/Aktionen begrenzen.
7. **Gemini opt-in Datenschutz:** sobald aktiviert, verlassen Findings die Maschine — Default offline, Opt-in explizit + Warnung in UI.

## 6. Nächste Schritte
1. `git init` + M1.1 Workspace-Gerüst
2. Fixtures (`tests/fixtures/sarif/`) aus realen Semgrep-/CodeQL-Läufen erzeugen
3. M1.2 → M1.6 sequentiell, je Meilenstein Golden-Test
