<!-- Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung -->
<!-- oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt. -->
# CateHunt v2 — Plan (MVP Phasen 1–3)

> Evidence Gate für KI-generierten Code. Lokales Desktop-Tool, local-first.
> Sprache: Deutsch.
>
> ## Nachtrag Stand 2026-10-15 (Arbeitsverzeichnis `C:/Users/RS990/Desktop/Projekte/CateHunt`, Branch `main`)
>
> Seit 2026-10-14 umgesetzt (Runden 1–5 + 4 Delegations-Runden, uncommittet):
- Phase 1: `cate audit --sarif --diff` (Scope+Metriken+SARIF+Deny, `unlocated`-Regel), Golden byte-stabil (CRLF-tolerant), `cargo test --workspace` grün (402 passed / 0 failed, 39 Test-Targets; Befehl s. TESTING.md §0), `src-tauri` separat 20/0 (Workspace-`exclude`), Clippy `-D warnings` + `cargo fmt --check` als CI-Gates, CI testet zusätzlich `src-tauri`.
- Phase 2: Ollama/Gemini/Deep-Adapter mit Availability-Probes, `plan_stages_checked`, deterministischem Offline-Fallback (`deterministic_triage`, schliesst nie), Verdict-Cache JSONL + CLI, Deny-Negativtests, Korpus 8 Fälle (CWE-22/78/79/89/94/328/502/798), `testprojekt/`-E2E, `harness/trend.py` (M-5), `docs/AI_BOM.md` (M-4, Provenienz an allen Produktions-Literalen verdrahtet).
- Phase 3: Tauri-Commands (list/health/graph + FixFlow suggest/approve/apply/audit mit S-3: Reviewer-Pflicht, 30-Tage-Ablauf, Deny-Suppress-Block), UI rendert Review/Editor/Graph/Settings (Graph als SVG + Tabelle, Health-Farben nach Regel), per Playwright-headless verifiziert (0 Console-Errors).
- Phase 5 (MCP): stdio-Server mit `audit_diff` (strikte Params, `head`≠HEAD abgelehnt), `get_graph`, `explain_nesting`, `apply_proposal` (Approval-Gate + Audit), `check_dependencies` (Offline-DB, nie „safe“), `verify_fix` (immer `NO_SANDBOX` — kein Exec ohne Sandbox), `ping`; 49 MCP-Tests (`cargo test -p cate-mcp`).
- Workspace-Stand 2026-10-17 (alle per Befehl belegt, s. TESTING.md §0/§4.4): 9 Member, 8 Lib-Targets, 2 Binaries (`cate` aus `cate-cli`, `cate-mcp` aus `cate-mcp`), 39 Test-Targets; `src-tauri` via `exclude` ausgenommen, separat getestet.
> - Security: Path-Jails (CLI/MCP/Tauri), Secrets-Redaction (`redact.rs`), Rev-Validierung (`-`-Prefix/NUL/Whitespace blockiert).
>
> Weiter offen (Stand 2026-10-15 spaet, Runde 6): S3-Erstlauf in CI (echter Container-Run nach Push; lokal self-check + dry-run PASS), S-3.1 Health-Schwellen-Rekalibrierung gesamt (Teilweise erledigt: Schwellen-Doku in Tests). Erledigt seit 2026-10-15: Sandbox S1+S2+S4 (StageProfile-System, RedactionOutput, COW/Preview-Capture, TOCTOU-resolve, 23 Tests via `cargo test -p cate-sandbox`), M1.5 Registry-Check real (Offline-DB `cate-registry-db` v1, `--registry-db`, deps-Summary im Scan-Report, 13 deps-Tests: 5 lib + 8 `registry_check`-Fixtures via `cargo test -p cate-deps`; `registry_check_stub` deprecated), ein echter `total_e2_plus` (Evidence >= E2 zaehlt, `crates/cate-core/src/lib.rs:857`), Python-def/Einrückung-Metriken (incl. async, Dedent-Logik), Fingerprint sha256 ✅, Tree-sitter ✅ (Rust+Python, Heuristik-Fallback), MCP `max_depth`-Filter ✅ strikt (1..=32, sonst INVALID_PARAMS), Demo-Seed ✅ (`cate demo [--out <file>]`, byte-stabil), `ui/dist`-Einchecken ✅, `suppress`-Button deutsch ✅, S-2 Adapter-Pinning ✅ (pins.rs + Offline-Probe), S-5 contested ✅ (höherer Verdict + contested:true, nie mittels, deterministisch), L3 Reachability + L4 Chaining ✅ (reach.rs/chain.rs, Kill-Kriterien, 78 Tests in cate-graph via `cargo test -p cate-graph`: 72 lib + 5 approval_e2e + 1 golden).
>
> Historischer Stand 2026-10-14 unten unverändert (Arbeitsverzeichnis damals `E:/CodeCate`).
> REVIEW.md-Nachtrag: 🟡 GELB — M-1 ✅, M-3/M-7 teilweise, M-2/M-4/M-5/M-6/M-8 offen.
> Update 2026-10-15: M-2 ✅ (Spec + `check_dependencies` live, `verify_fix` Sandbox-gated), M-4 ✅ (Typen + Spec + verdrahtet), M-5 ✅ (`trend.py`), M-8 ✅ (`redact.rs` + Tests), M-7 ✅ (Jails + Rev-Validierung), M-3 teilweise (Scope/Inventar + `audit`-Export da, expliziter Confirm-Schritt fehlt), M-6 weiter Design-only.
> Update 2026-10-15 nachmittags: M-6 S1+S2 ✅ (`cate-sandbox` + Haertung, Negativ-Tests), S3-Profile + N1–N4-Gate ✅ (`ci/sandbox/`, CI-Workflow neu), S4 ✅ (StageCaps-Trennung, Prompt-Redact-Gate, Dry-Run-Preview); sha256-Fingerprints ✅ (Core + Triage, Format v2); Tree-sitter ✅ (default-an mit Heuristik-Fallback); `audit --scope-out` ✅; UI deutsch ✅. Update 2026-10-15 spaet (Runde 6): S-2 Adapter-Pinning ✅ (`pins.rs`, Offline-Probe, `verifiziere_pins_offline`), Reachability-/Chaining-Engines ✅ (L3 `reach.rs` BFS + Dep-Use-Pfad, L4 `chain.rs` Kill-Kriterien, Goldens byte-stabil), S-5 contested ✅ (`resolve_contested`, hoeherer Verdict, nie still mitteln), S4 erweitert ✅ (Stufen-Matrix, `RedactionOutput`, Dry-Run-Capture, TOCTOU-Resolve), M1.5 Registry-Check real ✅ (Offline-DB `cate-registry-db` v1, Typosquat-DB-Kopplung, `deps_summary`). Offen: S3-Erstlauf in CI, Health-Schwellen-Rekalibrierung gesamt.

## 0. Ist-Stand vs. Plan (Code-Abgleich 2026-10-14, Commits bis `a542efa`, `cargo test`: 16/16 grün — 3 core + 2 deps + 1 sarif + 10 triage)

### Implementiert (mit Dateipfad)

| Was | Pfad | Status |
|---|---|---|
| Workspace (5 Crates) | `Cargo.toml` | ✅ |
| Evidence E0–E4 (Enum, Display, FromStr, Serde) | `crates/cate-core/src/lib.rs` | ✅ |
| Metrik-Heuristiken (nesting_depth, function_length, duplicate_hashes, scan_functions, analyze_file) | `crates/cate-core/src/lib.rs` | ✅ (Heuristik, kein Tree-sitter) |
| HealthScore-Struct (structure/security/dependencies/total) | `crates/cate-core/src/lib.rs` | ✅ Struct, Berechnung Stub |
| CLI `cate scan --path --format json [--sarif]` + JSON-Report | `crates/cate-cli/src/main.rs` | ✅ |
| Lockfile-Scan im CLI (Cargo.lock, package-lock.json) | `crates/cate-cli/src/main.rs` (`run_scan`) | ✅ |
| SARIF-Minimal-Import → E1-Findings | `crates/cate-sarif/src/lib.rs` (`import_sarif`) | ✅ |
| Lockfile-Parser (Cargo.lock, package-lock v1+v2/v3) | `crates/cate-deps/src/lib.rs` | ✅ |
| Typosquat-Heuristik (Stub, 1-Zeichen-Distanz) | `crates/cate-deps/src/lib.rs` (`looks_like_typosquat`) | ✅ Stub |
| Deny-List (`verdict_cap`, 17 CWEs) + `apply_policy` (close→demote) | `crates/cate-triage/src/lib.rs` | ✅ |
| CWE-Normalisierung (`CWE328`, `CWE 328`, Case/Whitespace) + Negativ-Test über alle 17 Deny-CWEs | `crates/cate-triage/src/lib.rs` (`normalize_cwe`, Test `deny_list_blocks_close_on_all_deny_cwes`) | ✅ (Loop `b10f520`→`a542efa`) |
| Path-Jail Teil 1 (Root kanonisieren, Dir-Pflicht, Symlink-Escape-Skip mit Warnung, Visited-Set gegen Loops) | `crates/cate-cli/src/main.rs` (`run_scan`, `collect_source_files`) | ✅ Teil (REVIEW B-1/B-2 behoben; Redaction fehlt weiter) |
| Fingerprint (64-bit) + normalize_code + code_hash | `crates/cate-triage/src/lib.rs` | ✅ (sha256-Upgrade offen) |
| Benchmark-Harness (Suppression-Rate, HARD GATE >1% = FAILED) | `harness/harness.py` | ✅ Stub (JSONL+CSV) |
| Korpus-Seed (CWE-328, CWE-798, je vuln+fixed) + Erweiterung CWE-89 (non-deny), CWE-502 (deny) | `corpus/{cwe-328,cwe-798,cwe-89,cwe-502}/`, `corpus/manifest.json` (v1, 4 Fälle) | ✅ Seed (4 Fälle) |
| Harness-Fixtures (labels.csv, verdicts_demo.jsonl) + Fail-Fixture für Gate-Negativtest | `harness/tests/fixtures/` (`labels_fail.csv`, `verdicts_fail.jsonl`) | ✅ Demo + Fail |
| VALIDATION.md (Deny-Regeln, Kennzahlen, CI-Gate-Spec) | `docs/VALIDATION.md` | ✅ Spec |

### Stub / Offen

| Was | Pfad | Lücke |
|---|---|---|
| Tree-sitter-Metriken | `crates/cate-core` | Nur `{`/`}`-Heuristik, `fn`/`function`-Heuristik |
| Health-Berechnung | `health_score_stub` | Security/Dependencies fix 100, keine E2+-Zählung |
| Registry-Check | `registry_check_stub` | Kein Netzwerk, exists immer true, age/downloads None |
| Verdict-Cache-Persistenz | `crates/cate-triage` | Nur Fingerprint-Funktion, keine JSONL-Datei, kein Hit-Logging |
| Triage-CLI-Anbindung | `crates/cate-cli` | Kein Triage-Subcommand, kein Ollama-Client |
| Scope/Inventar (git diff) | — | Kein Scope-Crate, kein audit-Befehl |
| Path-Jail | `collect_source_files` | Teil 1 ✅ (kanonischer Root, Symlink-Escape-Skip, Loop-Schutz, Dir-Pflicht); offen: Redaction-Schicht, Fuzz-Test (REVIEW B-3, → Paket B) |
| Secrets-Redaction | — | Keine Redaction vor Logs/Prompts (REVIEW M-8) |
| Harness-Korpus-Anbindung | `harness/harness.py` | Kein Korpus-Lauf, kein CI-Skript |
| MCP-Tools verify_fix/check_dependencies | — | Nur Zielbild-Signaturen in §3, keine Spec |
| Sandbox | — | Kein Design (REVIEW M-6) |
| AI-BOM/Trend/Scope-Export | — | Fehlen (REVIEW M-2…M-5) |

### Korrigierte Dateistruktur (Ist, Phasen 1–2)

```
E:/CodeCate/
├── Cargo.toml                  # Workspace: cate-core, cate-cli, cate-sarif, cate-deps, cate-triage
├── docs/{PLAN.md, REVIEW.md, VALIDATION.md}
├── crates/
│   ├── cate-core/src/lib.rs    # Evidence, Metrik-Heuristiken, HealthScore-Stub
│   ├── cate-cli/src/main.rs    # scan-Befehl, JSON-Report, Path-Jail Teil 1 (Root-Canonicalize, Symlink-Skip, Loop-Schutz)
│   ├── cate-sarif/src/lib.rs   # SARIF-Import → E1
│   ├── cate-deps/src/lib.rs    # Lockfile-Parser, Registry-Stub
│   └── cate-triage/src/lib.rs  # Deny-List, Policy, Fingerprint, CWE-Normalisierung (KEIN Cache, KEIN CLI)
├── harness/
│   ├── harness.py              # Stub: JSONL-Verdicts vs CSV-Labels
│   └── tests/fixtures/{labels.csv, verdicts_demo.jsonl, labels_fail.csv, verdicts_fail.jsonl}
├── corpus/
│   ├── manifest.json           # v1, 4 Fälle (cwe-328-01 deny, cwe-798-01 deny, cwe-89-01 non-deny, cwe-502-01 deny)
│   └── cwe-{328,798,89,502}/{01_vuln.py, 01_fixed.py}
└── target/                     # Build-Artefakte (git-ignoriert)
```

Abweichung zum alten Zielbild: kein `catehunt-scope`/`catehunt-metrics`-Split (alles in `cate-core`),
kein `src-tauri/`/`ui/` (Phase 3 nicht begonnen), kein `tests/`-Ordner (Tests inline `#[cfg(test)]`),
Crate-Namen `cate-*` statt `catehunt-*`.

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
- [x] M1.1 Workspace + CLI-Gerüst (`cate` Binary, `cargo` Workspace)
- [ ] M1.2 Stufe 0: Scope/Inventar — `git diff` parsen, Lockfile auswerten (Lockfile-Teil ✅, git-diff-Teil offen)
- [ ] M1.3 Stufe 1: Tree-sitter-Metriken (aktuell Heuristik-Stub, s. §0)
- [x] M1.4 Stufe 2: SARIF-Import → E1-Findings (Minimal-Subset)
- [ ] M1.5 Paketprüfung (Parser ✅, Registry-Check Stub ohne Netz)
- [x] M1.6 CLI gibt JSON aus (Report inkl. health; Exit-Code-Regel offen)

### Dateistruktur Rust-Workspace + Tauri (Zielbild, Phasen 1–3 — historisch, Ist-Stand s. §0)

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
- [ ] M2.2 Verdict-Cache mit JSONL-Persistenz + Hit-Rate-Logging (Schema ✅ in VALIDATION.md 3.1, Fingerprint ✅, Persistenz offen → Paket A)
- [x] M2.3 Deny-List: `crypto`, `auth`, `deserialization` → nie auto-suppress (`crates/cate-triage/src/lib.rs`, 10 Tests inkl. Negativ-Test über alle 17 Deny-CWEs)
- [ ] M2.4 Benchmark-Harness: Harness-Stub ✅, Korpus-Anbindung + CI-Skript offen (→ Paket C)

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

## 6. Nächste Schritte — 5 Arbeitspakete (Reihenfolge bindend)

### Paket A — Verdict-Cache JSONL-Persistenz + Triage-CLI (Aufwand: M)
- [ ] A1 Ziel: Verdicts über Runs hinweg in JSONL-Datei persistieren, Cache-Hit ohne Modell-Call.
- [ ] A2 Dateien: `crates/cate-triage/src/lib.rs` (neu: `load_cache`/`store_verdict`/`lookup`), `crates/cate-cli/src/main.rs` (neu: Subcommand `triage`), `crates/cate-triage/tests/cache_roundtrip.rs` (neu).
- [ ] A3 Akzeptanz: `cate triage --cache <file> --fingerprint <fp>` schreibt JSONL-Zeile; zweiter Aufruf mit gleichem Fingerprint = Hit (Exit 0, Log `cache_hit=true`); `suppress` auf Deny-CWE wird zu `escalate` hochgestuft (Test mit CWE-328).
- [ ] A4 Tests: `cargo test -p cate-triage` (Roundtrip + Deny-Hochstufung), manueller CLI-Doppelaufruf, `cargo clippy -- -D warnings`.

### Paket B — Path-Jail + Secrets-Redaction (Aufwand: S)
- [ ] B1 Ziel: REVIEW M-7/M-8 schließen — kein Dateizugriff außerhalb Scan-Root, keine Secrets in Logs/Exports/Prompts.
- [ ] B2 Dateien: `crates/cate-cli/src/main.rs` (`collect_source_files`: canonicalize + Symlink-Auflösung + Jail-Check), neu `crates/cate-core/src/redact.rs` (Redaction: `sk-*`, `ghp_*`, `AKIA*`, `-----BEGIN .*PRIVATE KEY-----`, `password\s*=\s*`), Tests inline.
- [ ] B3 Akzeptanz: `../`-Payload + Symlink-außerhalb-Root werden übersprungen (Negativ-Test); Scan-JSON enthält keine Roh-Secrets aus Fixture mit eingebettetem Token; Default bleibt local-only (kein Netz im Test).
- [ ] B4 Tests: `cargo test -p cate-core -p cate-cli` (Jail-Vektoren, Redaction-Vektoren), `cargo clippy -- -D warnings`.

### Paket C — Harness an Korpus anbinden per CI-Skript (Aufwand: M)
- [ ] C1 Ziel: `harness/harness.py` läuft gegen `corpus/` statt nur Demo-Fixtures, als CI-Gate ausführbar.
- [ ] C2 Dateien: `harness/harness.py` (neu: `--corpus`-Modus über vuln/fixed-Paare), neu `harness/run_corpus.sh` (oder `.ps1`), neu CI-Gate (`.github/workflows/harness.yml` oder `ci/harness.ps1` falls kein Remote), `corpus/manifest.json` (auf ≥4 Fälle erweitern: + CWE-79, + CWE-89).
- [ ] C3 Akzeptanz: Skript läuft grün auf Deny-Fällen (vuln nie `close`); Suppression-Rate + FP-Reduktion getrennt ausgegeben; Gate FAILED bei Suppression >1% (Negativ-Check mit manipuliertem Verdict).
- [ ] C4 Tests: Demo-Fixtures → PASSED; Korpus-Lauf end-to-end; CI-Skript trocken ausführbar.

### Paket D — MCP-Tool-Spezifikation verify_fix + check_dependencies (Aufwand: S)
- [ ] D1 Ziel: REVIEW M-2 teilweise schließen — beide Tools exakt spezifiziert (Signatur, Input/Output-Schema, Fehlerfälle), noch keine Implementierung.
- [ ] D2 Dateien: neu `docs/MCP_TOOLS.md` (Spec beider Tools mit JSON-Schemas + Beispiel-Calls), PLAN.md §3-Signaturen bleiben Referenz.
- [ ] D3 Akzeptanz: Spec enthält pro Tool: Parameter, Rückgabe-Schema, Evidence-Regeln (`verify_fix` nur E3→E4 nach bestandenem Re-Test in Sandbox; `check_dependencies` offline-DB, advisory-Format), Fehlercodes; Reviewer kann Spec ohne Rückfragen in Implementierung überführen.
- [ ] D4 Tests: Schema-Beispiele per `python -c "json.load"` validiert (parsebares JSON); kein Code-Test (reine Spec).

### Paket E — Sandbox-Design, nur Design ohne Ausführung (Aufwand: L)
- [ ] E1 Ziel: REVIEW M-6 Design-Beleg — Threat Model + Isolations-Architektur dokumentiert, explizit kein ausführender Code.
- [ ] E2 Dateien: neu `docs/SANDBOX_DESIGN.md` (Threat Model, Isolation: kein Netz, read-only Mounts außer Scratch, CPU/RAM/Timeout-Limits, Kill-Policy, Egress-deny; Negativ-Testplan: Escape-Versuche, die fehlschlagen müssen).
- [ ] E3 Akzeptanz: Dokument deckt REVIEW §4-Zeile Sandbox-Escape ab; enthält ≥3 konkrete Negativ-Tests (z. B. Netz-Egress, `/etc`-Read, Fork-Bombe) mit erwartetem Ergebnis; Vermerk „kein ausführender Code in dieser Phase".
- [ ] E4 Tests: keine Ausführungstests (Design only); Review-Check: jede REVIEW-§4-Sandbox-Anforderung ist im Dokument per Abschnitt referenziert.
