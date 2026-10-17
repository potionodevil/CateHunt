<!-- Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung -->
<!-- oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt. -->
# CateHunt — Testplan entlang der Scan-Kaskade

Stand: 2026-10-14. Arbeitsverzeichnis: `E:/CodeCate`.
Kaskade: **Algorithmus (deterministisch) → AI klein (Ollama/Gemini CLI) → AI gross (headless Agents) → Mensch (UI-Approval)**.
Prinzip: Jede Stufe wird isoliert getestet; Eskalation nur bei Unsicherheit; Deny schlägt alles.

## 0. Ist-Stand (gemessen 2026-10-17)

| Bereich | Befund |
|---|---|
| Unit-/Integration-Tests (`cargo test --workspace`) | **402 passed / 0 failed**, 39 Test-Targets über 9 Workspace-Member (Per-Crate-Aufschlüsselung s. §4.4; Summe 71+22+15+13+110+78+21+49+23 = 402) |
| `src-tauri` (separat, `exclude` im Workspace) | **20 passed / 0 failed** via `cargo test --manifest-path src-tauri/Cargo.toml` (u.a. S-3 Suppress-Gate, FixFlow-Backup/Rollback) |
| `cargo clippy --workspace --all-targets -- -D warnings` | **grün**; `cargo fmt --check` grün |
| Korpus | `corpus/manifest.json`: 8 Fälle (CWE-22/78/79/89/94/328/502/798), je `01_vuln.py` + `01_fixed.py` |
| Harness | `harness/harness.py` + Fixtures (`labels.csv`, `labels_fail.csv`, `verdicts_demo.jsonl`, `verdicts_fail.jsonl`), Gate Suppression-Rate > 1% → FAILED |
| Fehlend | kein `tests/` auf Top-Level, kein Fuzz-Target, keine tarpaulin-Coverage auf Windows (Testzahl-Gate Pfad B aktiv, s. §4.4), kein Kosten-Cap-Test |

Repro:
```powershell
cargo test --workspace   # erwartet: 402 passed / 0 failed, 39 Test-Targets
cargo test --manifest-path src-tauri/Cargo.toml   # erwartet: 20 passed / 0 failed (separat)
cargo clippy --workspace --all-targets -- -D warnings
python harness/harness.py --verdicts harness/tests/fixtures/verdicts_demo.jsonl --labels harness/tests/fixtures/labels.csv
python harness/harness.py --corpus corpus/manifest.json
```

## 1. Stufe 1 — Algorithmus (deterministisch, keine Modelle)

Ziel: Scan ohne Netz, ohne Kosten, reproduzierbar. Alles hier MUSS offline und deterministisch laufen.

### 1.1 Unit-Tests
- **Metriken** (`cate-core`): Verschachtelungstiefe, Funktionslänge, Duplikat-Hashes. Fälle: leerer Input, 1-Funktion, tiefe Verschachtelung (≥5), Duplikat über Dateigrenzen. Assert exakte Werte, keine Snapshots.
- **Weichen** (`cate-stages`, Scope): E0–E4-Einstufung, Scope-In/Out (Path-Jail, `.gitignore`-Respect, Symlink-Escape). Jede Weiche: Positiv + Negativ + Grenze.
- **Policy** (`cate-cli` Policy-Override-Pfad, `policy_override`-Flag): Override nur mit explizitem Schalter; Default = kein Override. Test: ohne Schalter bleibt `policy_override=false`.
- **Deny-Negativ** (Pflicht): Jeder Deny-Fall (CWE-328/798/502) darf NIEMALS `close`/`suppress` liefern — vuln→open UND fixed→open (konservativ). Ein `close` auf Deny = FAILED, auch wenn alle anderen Tests grün sind.
- **SARIF/Health**: SARIF-Export validiert gegen Schema (Pflichtfelder `ruleId`, `level`, `locations`); Health-Score in [0,1], monoton (mehr Findings ≠ höherer Score).

### 1.2 Fuzz-Tests (`cargo fuzz` ODER proptest als Minimum)
- **Path-Jail-Fuzz**: zufällige Pfade (`../`, absolute, UNC `\\?\`, Symlink-Ketten, overlong >260). Invariante: kanonischer Pfad bleibt IMMER im Repo-Root, sonst Reject. Corpus-Seed: bekannte Traversal-Vektoren.
- **Redact-Fuzz**: zufällige Secrets (API-Keys, PEM, Tokens) in Code eingebettet. Invarianten: kein Secret im Output (Regex-Nachscan), kein Panic, Idempotenz (`redact(redact(x)) == redact(x)`).
- **Diff-Parser-Fuzz**: zufällige/garbled Diffs (leere Hunks, Riesenhunks, CRLF-Mix, Binärmarker). Invariante: nie Panic, immer typisierter Fehler ODER valides Ergebnis.
- Laufzeit: CI-Kurzmodus 60 s pro Target; Nightly-Langmodus 10 min. Neue Crash-Inputs werden als Regressionstests eingecheckt (`fuzz/artifacts/`).

### 1.3 Golden-Tests (JSON-Snapshots)
- Artefakte: `findings.json`, `health.json`, Graph-JSON (`cate-graph`). Ablage: `crates/*/tests/golden/*.json` + `insta`- oder handrollierter Vergleich.
- Regel: Golden-Update NUR via `UPDATE_GOLDEN=1` + Review-Diff im PR; stilles `--bless` im CI ist verboten. Jeder Golden-Test nennt Schema-Version im Dateikopf.
- Determinismus: sortierte Keys, keine Timestamps/PIDs/Absolutpfade im Snapshot (ggf. normalisieren).

```powershell
cargo test -p cate-core -p cate-deps -p cate-sarif -p cate-graph
UPDATE_GOLDEN=1 cargo test -p cate-graph --test golden   # nur lokal mit Review
cargo fuzz run path_jail -- -max_total_time=60
```

## 2. Stufe 2 — AI (klein → gross)

Ziel: Modelle verbessern Triage, dürfen aber Deny/Policy NIEMALS kippen. Kosten und Latenz sind Testdimensionen.

### 2.1 Mock-Tests aller Modell-Adapter
- Jeder Adapter (`ollama.rs`, `gemini.rs`, künftige Headless-Agents) bekommt einen Mock-Transport (kein Netz im Test). Fälle pro Adapter: valides Verdict, ungültiges JSON (→ typisierter Fehler, kein Panic), Timeout, 5xx, leere Antwort, überlange Antwort (Truncation).
- Prompt-Freeze: Systemprompt-Hash pro Adapter wird getestet (Änderung = Test rot → bewusstes Review, kein stilles Driften).
- Bestehend: `ollama.rs` (10 Tests), `gemini.rs` (15 Tests), `cache_roundtrip.rs` (2 Tests) — weiter ausbauen, siehe TODO.

### 2.2 E2-Cap / Deny-Vorrang
- **E2-Cap**: Selbst wenn das Modell `close`/`suppress` für einen Deny-Fall vorschlägt, MUSS die Pipeline `open` ausgeben (`policy_override=false`, Grund geloggt). Testmatrix: {deny=true, deny=false} × {Modell sagt open, close, escalate, garbage} = 8 Fälle.
- **Deny-Vorrang-Reihenfolge** (hart codiert, getestet): `Deny-Policy > E2-Cap > Modell-Verdict > Heuristik`. Kein Schalter, keine Config darf Deny abschalten.
- Korpus-Anbindung: Deny-Fälle aus `corpus/manifest.json` (`deny=true`) laufen im CI durch die simulierte Triage (s. Harness §3).

### 2.3 Eskalationspfade (klein → gross → Mensch)
- Unsicherheits-Schwelle: unter Konfidenz-Threshold eskaliert klein→gross, darüber→Mensch. Tests: Schwellen-Grenzen (0.0/1.0/Threshold±ε), Eskalations-Loop-Guard (max N Stufen, kein Ping-Pong), Timeout pro Stufe (gross antwortet nie → Mensch-Queue, kein Hängen).
- Jede Eskalation schreibt Audit-Record (wer, wann, warum, Kosten). Test: Record vorhanden + immutable (kein Überschreiben).

### 2.4 Kosten- / Cache-Hit-Metriken
- Cache-Key = Hash(Prompt + Modellversion + Input-Hash). Tests: identischer Input → Hit (kein Modell-Call), geänderter Input → Miss, Modellwechsel → Miss.
- Budget-Guard: Kosten-Cap pro Run; Überschreitung → harter Stopp mit FAILED (nicht stilles Weiterlaufen). Test mit Fake-Preistabelle.
- Metriken-Assert im CI: Cache-Hit-Rate und Modell-Calls werden geloggt; Regression (Calls +20 % bei gleichem Korpus) = Warnung, +50 % = FAILED.
- Bestehend: `cache_roundtrip.rs` deckt nur Serialisierung ab — Hit/Miss-Logik und Cap fehlen (TODO P1).

```powershell
cargo test -p cate-triage
cargo test -p cate-triage --test cache_roundtrip
```

## 3. Stufe 3 — E2E (Korpus, Harness, UI-Approval)

### 3.1 Korpus-Paare vuln/fixed
- 5 Paare vorhanden (CWE-328/798/502/89/79). Erwartung: Nicht-Deny vuln→open, fixed→close; Deny IMMER open (auch fixed). Neue CWE NUR als Paar (vuln+fixed+Manifest-Eintrag) — Einzeldateien werden vom CI abgelehnt.
- Mindest-Erweiterung: je 1 Paar für CWE-22 (Path Traversal), CWE-78 (Command Injection), CWE-94 (Code Injection) — TODO P1.

### 3.2 Harness-Gates
- Befehle (Demo + Negativcheck + Korpus):
```powershell
python harness/harness.py --verdicts harness/tests/fixtures/verdicts_demo.jsonl --labels harness/tests/fixtures/labels.csv
python harness/harness.py --verdicts harness/tests/fixtures/verdicts_fail.jsonl --labels harness/tests/fixtures/labels_fail.csv  # muss FAILED liefern
python harness/harness.py --corpus corpus/manifest.json
```
- Gates: **Suppression-Rate > 1 % → FAILED (hart)**, unabhängig von FP-Reduktion (VALIDATION.md 1.3). FP-Reduktion wird berichtet, gate-t aber nichts.
- `harness/run_corpus.sh` / `run_corpus.ps1` und `ci/harness.ps1` sind die CI-Einstiege — nicht umgehen.

### 3.3 UI-Approval-Flow (Tauri)
- **Kein Apply ohne Zustimmung**: E2E-Test (Playwright/WebDriver ODER Tauri-Test-Harness) klickt NICHT auf Approve → Assert: keine Datei geändert (Hash-Vergleich vorher/nachher), kein Apply-Log-Eintrag.
- **Approve → Apply**: genau die bestätigten Findings werden angewendet; Teil-Approval (2 von 5) wendet nur 2 an.
- **Auto-Apply nur mit Schalter + Log**: Default AUS. Test: ohne Schalter passiert trotz Konfig nichts; mit Schalter schreibt jeder Apply einen Audit-Eintrag (wer/was/wann/diff-Hash). Schalter-Umgehung = FAILED.
- Rollback-Test: Apply → Undo stellt Original-Bytes wieder her (Hash-identisch).
- **S-3 Suppress-Gate** (`src-tauri/src/fixflow.rs`): Approval braucht Begründung + Reviewer + Ablaufdatum (Default 30 Tage); abgelaufene Approvals → `APPROVAL_EXPIRED` bei `apply`, Deny-CWE-Suppress → `DENY_SUPPRESS_BLOCKED` (Check gegen `cate-triage::verdict_cap`). UI deaktiviert abgelaufene/Deny-Übernehmen-Buttons mit Begründungstext (`ui/dist/index.html`, Editor-Ansicht). Unit-Beleg: `cargo test --manifest-path src-tauri/Cargo.toml` (u.a. `abgelaufene_approval_blockt_apply_mit_expired`, `deny_cwe_kann_nie_suppressen`).

### 3.4 Trend-Report pro Modell/Engine (M-5)
- Befehl: `python harness/trend.py --verdicts <verdict-cache.jsonl> [--audit <audit.jsonl>] [--format table|json|both] [--json-out report.json]`
- Liest Verdict-Cache-JSONL (geflattet ODER `{"verdict": {...}}`, Aliase confirm/suppress/escalate tolerant) + optional Fix-Audit-Logs; Ausgabe: Tabelle pro Modell (Anzahl, Confirm, Suppress, Escalate, Deny-Hochstufungen=`policy_override`) + JSON.
- Fixtures: `harness/tests/fixtures/trend_verdicts.jsonl` (9 Records, 2 Modelle, 2 Deny-Hochstufungen) + `trend_audit.jsonl` (3 Applies: alice=2, bob=1). Reiner Report, kein Gate.

## 4. Abdeckungs-Ziele + CI-Verankerung

### 4.1 Ziele
| Metrik | Ziel | Gate |
|---|---|---|
| Linien-Coverage `cate-core`, `cate-graph`, `cate-sarif` | ≥ 85 % | FAILED darunter |
| Linien-Coverage `cate-triage`, `cate-deps`, `cate-cli` | ≥ 70 % | FAILED darunter |
| Deny-Negativ-Fälle | 100 % (alle Deny-CWEs × alle Verdict-Arten) | FAILED bei 1 Miss |
| Fuzz (CI-Kurzmodus) | 0 Crashes / 60 s pro Target | FAILED bei Crash |
| Harness Suppression-Rate | ≤ 1 % | FAILED darüber |
| Golden-Drift | 0 ohne Review | FAILED bei unangekündigtem Diff |

Messung: `cargo tarpaulin --workspace --exclude-files 'src-tauri/*'` (Linux-CI) ODER `cargo llvm-cov`. Coverage-Artefakt pro PR hochladen.

### 4.2 CI-Jobs (Reihenfolge = Kaskade)
1. `fmt + clippy -D warnings` — Stil/Hygiene.
2. `cargo test` (alle Stufen-1-Unit-Tests) — FAILED = Code rot.
3. `cargo test -p cate-triage` (Adapter-Mocks, E2-Cap, Cache, Prompt-Freeze, Eskalations-Guard) — FAILED = Modell-Integration rot.
4. Harness (Demo + Fail-Fixture + Korpus) — FAILED = Suppression > 1 % ODER Fail-Fixture liefert PASS (Gate defekt).
5. Fuzz-Kurzmodus (60 s/Target) — FAILED = Crash/Hang.
6. Coverage — `ci/coverage_gate.ps1` (s. §4.4) — FAILED = unter Ziel.
7. UI-Approval-E2E (nur bei UI-Änderungen ODER nightly) — FAILED = Apply ohne Zustimmung.

### 4.4 Coverage-Gate (offline-fähig, Stand 2026-10-17)

`ci/coverage_gate.ps1` / `ci/coverage_gate.sh` (Einstieg wie `ci/harness.ps1`):
- **Pfad A** (tarpaulin vorhanden): `cargo tarpaulin --workspace --exclude-files 'src-tauri/*'`,
  Gate `--fail-under 70`, Artefakt unter `target/coverage/`.
- **Pfad B** (tarpaulin offline nicht verfügbar, z.B. Windows): Testzahl-Gate je Crate
  (`cargo test -p <crate>`, Summe aller `test result`-Zeilen, 0 failed Pflicht):

| Crate | min passed | gemessen 2026-10-17 |
|---|---|---|
| cate-core | 65 | 71 |
| cate-cli | 20 | 22 |
| cate-sarif | 14 | 15 |
| cate-deps | 12 | 13 |
| cate-triage | 100 | 110 |
| cate-graph | 70 | 78 |
| cate-stages | 19 | 21 |
| cate-mcp | 45 | 49 |
| cate-sandbox | 21 | 23 |

Gesamt Workspace: **402 passed / 0 failed** (39 Test-Targets). Bei legitimer
Testzahl-Reduktion: MIN im Script + diese Tabelle gemeinsam anpassen.

### 4.3 Was FAILED bedeutet
- FAILED blockiert Merge (Branch Protection, kein Override ohne Security-Review).
- Deny-/Approval-Failures sind **nicht überstimmbar** durch normale Reviewer — nur Security-Owner mit dokumentierter Ausnahme (Issue-Ref im Merge-Commit).
- Flaky-Test-Protokoll: 3× Retry lokal erlaubt zur Diagnose; im CI kein Retry — rot ist rot, Test fixen oder in Quarantäne-Datei mit Issue-Ref (max 7 Tage).

## 5. Lückenliste (TODO, priorisiert)

- [x] **P0 — `cate-cli` kompiliert nicht** → geschlossen 2026-10-17: `cmd_graph` in `crates/cate-cli/src/main.rs:582`
  (`cargo test -p cate-cli`: 22 passed / 0 failed; `cargo test --workspace` grün).
- [x] **P0 — Deny-Negativ-Tests fehlen** → geschlossen 2026-10-17: `deny_list_blocks_close_on_all_deny_cwes`
  (`crates/cate-triage/src/lib.rs:398`, alle 17 Deny-CWEs) + E2-Cap-Matrix `crates/cate-triage/tests/e2cap_cache.rs`
  (`e2_cap_gilt_fuer_alle_adapter`, `deny_cap_suppress_wird_eskaliert_alle_adapter`).
- [x] **P0 — Approval-E2E fehlt komplett** → geschlossen 2026-10-17: `crates/cate-graph/tests/approval_e2e.rs`
  (5 Tests, grün) + src-tauri S-3-Gate-Tests (`cargo test --manifest-path src-tauri/Cargo.toml`: 20/0).
- [ ] **P1 — Fuzz-Targets fehlen**: kein `fuzz/`-Verzeichnis, keine proptest-Dep. Mindestens `path_jail`, `redact`, `diff-parser` anlegen + CI-Kurzmodus.
- [x] **P1 — Golden-Tests fehlen** → geschlossen 2026-10-17: `crates/cate-graph/tests/golden.rs`
  + `tests/golden/graph_v1.json` sowie CLI-Golden-Test `audit_golden_stabil_und_args`.
- [x] **P1 — Cache-Hit/Miss ungetestet** → Hit/Miss-Matrix geschlossen 2026-10-17: `cache_hit_ohne_modell_parse`
  (`ollama.rs`), `cache_hit_ohne_runner_call` (`gemini.rs`), `cache_hit_ohne_runner` (`deep_engines.rs`)
  + `crates/cate-triage/tests/e2cap_cache.rs`. Offen: Budget-Guard/Kosten-Cap (kein Test).
- [x] **P1 — Korpus zu schmal** → geschlossen 2026-10-17: `corpus/manifest.json` mit 8 Fällen
  (CWE-22/78/79/89/94/328/502/798, je vuln+fixed); `python harness/harness.py --corpus corpus/manifest.json` grün (`deny_closed: []`).
- [x] **P1 — `cate-stages` nicht im Workspace** → geschlossen: in `[workspace].members` eingetragen
  (`cargo test -p cate-stages`: 21 passed / 0 failed).
- [x] **P2 — Prompt-Freeze-Hash fehlt** → geschlossen 2026-10-17: `crates/cate-triage/tests/prompt_freeze.rs`
  (FNV-1a-64 `6ce4901fa27c411c` je Adapter + PROMPT_VERSION=v1-Assert + Regel-Anker; Drift = rot).
- [x] **P2 — Eskalations-Loop-Guard ungetestet** → geschlossen 2026-10-17: `crates/cate-triage/tests/escalation_guard.rs`
  (Deep nur bei Opt-in+Deny+unsicher, Plan-Matrix ohne Opt-in/ohne CLI, offline 0 Modell-Calls).
- [x] **P2 — Coverage-Gate fehlt** → geschlossen 2026-10-17: `ci/coverage_gate.ps1` + `.sh`
  (tarpaulin-Pfad A, sonst Testzahl-Gate Pfad B; Doku §4.4).
- [x] **P2 — SARIF-Schema-Validierung fehlt** → geschlossen 2026-10-17: `crates/cate-sarif/tests/sarif_negative.rs`
  (9 Negativfälle: kaputt/leer/locations-los → saubere Fehler + unlocated).
- [x] **P3 — Rollback/Undo-Test fehlt** → geschlossen 2026-10-17: FixFlow mit `.orig`-Backup je geänderter Datei
  + Rollback bei Fehlern (`src-tauri/src/main.rs:250`), abgedeckt in den 20 src-tauri-Tests.
- [ ] **P3 — Flaky-Quarantäne-Prozess fehlt**: Quarantäne-Datei + 7-Tage-Regel einführen.
