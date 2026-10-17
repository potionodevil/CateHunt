<!-- Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung -->
<!-- oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt. -->
# CateHunt v2 — Validation (Stand 17.10.2026)

Rolle: Validator (praezises Reasoning-Modell, sicherheitsfokussiert).
Kern-Risiko: FP-Reduktion vs False Negatives. Referenz: Beste Config unterdrueckte
84.5% echter CWE-328-Funde trotz 6.3% FP-Rate → reine FP-Rate ist KEIN Erfolgskriterium.

## 1. Benchmark-Harness-Konzept

### 1.1 Anbindung OWASP Benchmark (v1.2+)
- Quelle: OWASP BenchmarkJava; Scorecard-Generator als Ground Truth.
- Kategorien: Command Injection, SQLi, XSS, Path Traversal, Crypto (CWE-327/328),
  Hashing, Trust Boundary, Weak Randomness.
- Ablauf: `harness run --bench owasp --catehunt-config <cfg> --out results/owasp.json`
  1. Semgrep-Regeln auf Benchmark-Sourcen laufen lassen (Baseline-Funde).
  2. Jeden Fund durch Triage-Pipeline (Deny-List → Cache → KI-Verdict) schicken.
  3. Verdicts gegen `expectedresults-*.csv` matchen.
- WICHTIG: Scorecard erzeugt TPR/FPR pro Kategorie; CateHunt erweitert um
  Unterdrueckungs-Metrik (s. 1.3).

### 1.2 Anbindung SastBench
- Quelle: SastBench-Datensatz (multilingual, reale CVE-nahen Samples, inkl. Fixes).
- Nutzen: misst Generalisierung ausserhalb synthetischer OWASP-Faelle;
  insbesondere Krypto/AuthN/AuthZ/Deserialisierung.
- Ablauf: `harness run --bench sastbench --split <java|js|py> --out results/sastbench.json`
  1. Pro Sample: Baseline-Fund (Tool) + CateHunt-Verdict erzeugen.
  2. Label: vulnerable / fixed. Fix-Version MUSS als TP erhalten bleiben
     (kein fälschliches Schliessen) bzw. als FP korrekt geschlossen werden.

### 1.3 Kennzahlen (getrennt ausweisen, nie verrechnen)
| Kennzahl | Definition | Ziel / Alarm |
|---|---|---|
| FP-Reduktion | Anteil Baseline-FPs, die korrekt geschlossen/herabgestuft wurden | > 50% anstreben |
| Echte-Funde-Unterdrueckung (Suppression Rate) | Anteil echter Funde (TP), die fälschlich geschlossen wurden | < 1% (HARD GATE, Release-Blocker) |
| Herabstufungs-Quote Deny-List | Anteil Deny-List-Funde, die nur herabgestuft statt geschlossen wurden | = 100% (Audit) |
| TPR / FPR (OWASP Scorecard) | Standard-Scorecard-Werte nach Triage | TPR darf ggü. Baseline nicht sinken |
| Cache-Hit-Rate | Verdicts aus Cache ohne KI-Call | > 70% auf Wiederholungsläufen |
| Kosten/Fund | Tokens + Latenz p50/p95 pro KI-Verdict | s. Kap. 4 |

- Regel: Jede Config, die Suppression Rate > 1% hat, ist FAILED — unabhaengig
  von FP-Reduktion. Die 84.5%-CWE-328-Unterdrueckung bei 6.3% FP-Rate ist das
  Negativbeispiel: nach dieser Metrik FAILED.
- Reporting: `results/summary.md` enthaelt IMMER beide Zahlen nebeneinander;
  CI-Gate parst sie getrennt (s. 1.4).

### 1.4 CI-Gate
```yaml
# Pseudokonfig harness-gate
gates:
  - metric: suppression_rate_overall
    max: 0.01
  - metric: suppression_rate_per_cwe   # je CWE, inkl. CWE-327/328/259/798/918/502
    max: 0.01
  - metric: owasp_tpr_drop_vs_baseline
    max: 0.0   # kein TPR-Verlust
```
- Gate läuft auf OWASP Benchmark + SastBench-Subset bei jedem Regel-/Prompt-Change.
- Artefakte: `results/*.json` + Verdict-Cache-Snapshot committbar (s. Kap. 3).

## 2. Deny-List-Regeln je CWE-Kategorie

Prinzip: Krypto / AuthN / AuthZ / Deserialisierung NIE per KI schliessen,
nur herabstufen (Severity -1, min. low/info) + Pflicht-Begruendung + Human Review.

| Kategorie | CWEs | Regel |
|---|---|---|
| Schwache Krypto | CWE-327 (broken algo), CWE-328 (weak hash), CWE-326, CWE-331 (weak randomness) | nie schliessen; max. Herabstufung; MD5/SHA1/RC4/DES/ECB → immer offen |
| Hardcoded Secrets | CWE-259, CWE-798, CWE-321 | nie schliessen; Rotation-Hinweis Pflicht |
| AuthN / Session | CWE-287, CWE-384, CWE-613, CWE-620 | nie schliessen; nur Herabstufung mit Review-Flag |
| AuthZ | CWE-639, CWE-862, CWE-863, IDOR-Patterns | nie schliessen |
| Deserialisierung | CWE-502, CWE-915 (Java/Python/PHP unserialize, pickle, ObjectInputStream) | nie schliessen |
| Injection (nicht Deny, aber Guardrail) | CWE-78, CWE-89, CWE-94, CWE-918 (SSRF) | Schliessen nur mit Reachability-Nachweis (Sink nicht erreichbar + Test); sonst herabstufen |
| XSS | CWE-79 | Schliessen nur mit Output-Encoding-Nachweis am Sink |
| Path Traversal | CWE-22 | Schliessen nur mit Canonicalisierungs-/Allowlist-Nachweis |

Enforcement:
- `deny_list.rs` (oder `triage/policy.rs`): `fn verdict_cap(cwe) -> MaxAction { Close | DemoteOnly }`.
- KI-Prompt enthaelt Deny-List als System-Constraint; Verdict-Parser verwirft
  `close` bei Deny-CWE → wird zu `demote` + `policy_override: true` geloggt.
- Audit: jede Deny-Entscheidung landet im Verdict-Cache mit `policy: deny-list`.

## 3. Verdict-Cache-Schema + Kostenabschaetzung

### 3.1 Schema (JSONL, committbar unter `data/verdict-cache/`)
```json
{
  "fingerprint": "sha256(rule_id || normalized_code_hash || cwe)",
  "rule_id": "semgrep:java.crypto.md5",
  "cwe": "CWE-328",
  "code_hash": "sha256:<hex> (normalisiert: whitespace/comments/identifier-renamed)",
  "verdict": "open | demote | close",
  "severity_after": "high|medium|low|info",
  "policy": "allow | deny-list",
  "policy_override": false,
  "model": "reasoning-model@2026-10",
  "prompt_version": "v3",
  "tokens_in": 18500,
  "tokens_out": 6500,
  "latency_ms_p50": 9000,
  "created_at": "2026-10-14T00:00:00Z",
  "benchmark_ref": "owasp BenchmarkTest00042"
}
```
- Fingerprint = `sha256(rule_id + "|" + code_hash + "|" + cwe)`; Kollision → neu evaluieren.
- Normalisierung VOR Hash: Formatter + Kommentar-Strip + Identifier-Mapping,
  damit triviale Umbauten Cache treffen.
- Committbar: Cache-Files sind Diffs im PR (Reviewer sieht neue Verdicts);
  `harness` fails bei Cache-Miss auf Deny-CWEs ohne `--allow-new-verdicts`.

### 3.2 Kostenabschaetzung (~25k Tokens/Fund)
- Annahme: ~18–20k Input (Regel + SAST-Evidenz + Code-Slice + Dataflow-Kontext)
  + ~5–7k Output (Reasoning + Verdict-Begruendung) ≈ 25k Tokens/Fund (KI-Pfad).
- Beispielrechnung (Preise Platzhalter, in `harness cost` konfigurierbar):
  - 1.000 Funde, 30% Cache-Hit → 700 KI-Calls × 25k = 17.5M Tokens/Lauf.
  - Bei $3/M Input + $12/M Output (Beispiel): ≈ 700 × (20k×3 + 5k×12)/1M ≈ $168/Lauf.
- Hebel: Cache-Hit-Rate hoch (Ziel > 70%), Code-Slices kuerzen, Deny-Funde
  ohne KI (nur Policy-Demote) = 0 Tokens, Batch-/Nachtläufe, guenstiges
  Reasoning-Modell mit Eskalationsstufe.
- Pflicht: jeder Benchmark-Report enthaelt `total_tokens`, `est_cost_usd`,
  `cache_hit_rate`.

## 4. Sandbox-Sicherheitsanforderungen

- Strikte Isolation: Triage/Sandbox läuft ohne Netzwerk (egress DENY default);
  nur Loopback zum Harness; kein Zugriff auf Secrets/CI-Token.
- Zu analysierender Code wird als DATEN behandelt, nie ausgefuehrt —
  kein `exec`/Build/Test des Targets in der Triage-Sandbox.
- Falls dynamische Bestaetigung noetig (getrennter PoC-Lauf): eigene
  Wegwerf-Sandbox (Container/VM, non-persistent, Timeout ≤ 120s, CPU/RAM-Limits),
  ebenfalls ohne Netzwerk, Ergebnis nur als Text-Log zurueck.
- Prompt-Sicherheit: Target-Code in klar abgegrenztem Block, System-Prompt
  hat Vorrang; keine Tool-Calls ausser Verdict-Schema-Output (kein Shell/File-Zugriff).
- Logging: alle KI-Inputs/Outputs + Policy-Entscheidungen revisionssicher
  (Verdict-Cache), PII/Secrets-Redaction vor Persistenz.
- Dependency-Hygiene: Sandbox-Image gepinnt, SBOM vorhanden, keine
  auto-Updates zur Laufzeit.

## 5. Testkorpus-Plan (absichtlich verbuggter KI-Code)

Ziel: realistische KI-generierte Bugs statt nur synthetischer Benchmarks.

- Generator: aktuelles Code-LLM erzeugt CRUD-/Auth-/Crypto-Snippets
  (Java, JS, Python) aus Aufgaben-Prompts; Seed fixiert, Prompt-Versionen archiviert.
- Bug-Injektion (jeweils mit/ohne Fix-Paar):
  1. MD5/SHA1 Passwort-Hash (CWE-328) — Deny, darf nie geschlossen werden
  2. Hardcoded JWT-Secret (CWE-798) — Deny
  3. Fehlende AuthZ-Pruefung / IDOR (CWE-639/862) — Deny
  4. `pickle.loads` / `ObjectInputStream.readObject` auf User-Input (CWE-502) — Deny
  5. SQL-String-Concat (CWE-89), Command-Exec mit f-String (CWE-78), unescaped XSS (CWE-79)
  6. Path-Join ohne Normalisierung (CWE-22), SSRF auf User-URL (CWE-918)
  7. Schwacher PRNG für Token (CWE-338/331)
- Umfang: ≥ 10 Faelle pro Kategorie, je als vulnerable + fixed Paar
  (`corpus/<cwe>/<nn>_vuln.<ext>`, `..._fixed.<ext>`) + `corpus/manifest.json`
  mit CWE-Label und Deny-Flag.
- Negativ-Kontrollen: sichere Muster (bcrypt/argon2, parametrisierte Queries,
  Allowlist-Paths, random.token_bytes), die geschlossen werden DUERFEN —
  misst Ueber-Oeffnen (zu wenig FP-Reduktion).
- Metrik auf Korpus: Suppression Rate = 0 toleriert bei Deny-Faellen;
  jeder fälschlich geschlossene Deny-Fall = Korpus-FAILED.
- Pflege: Korpus versioniert, neue KI-Bug-Patterns quartalsweise ergänzen.

## 6. Pruefung: crates aus Coding-Agent (Stand 2026-10-14, Nachtrag)

Urspruenglich war `E:/CodeCate` zum Pruefzeitpunkt leer (Race mit
parallelem Coding-Agent). Nachtrag nach Fertigstellung: Workspace enthaelt
`cate-core` (Evidence E0-E4, Metriken, Health-Stub), `cate-cli` (scan JSON),
`cate-sarif` (E1-Import), `cate-deps` (Lockfile-Parser + Stub) sowie neu
`cate-triage` (Deny-List + Verdict-Fingerprint, s. Phase-2-Commit).
Offen bleiben: OWASP-/SastBench-Anbindung (nur Harness-Stub),
Sandbox-Implementierung, Korpus-Ausbau ueber 2 Faelle hinaus.

## 7. AI-BOM / Provenienz (M-4, Stand 2026-10-15)

Spez: `docs/AI_BOM.md`. Jedes KI-erzeugte Finding (`cate_core::ScoredFinding`)
und jeder Triage-Verdict (`cate_triage::Verdict`) traegt optional
`provenance: Option<cate_core::ProvenanceRecord>`
(`tool_name`, `tool_version` aus `CARGO_PKG_VERSION`, `model`,
`commit_sha` aus Buildzeit-`CATE_COMMIT_SHA` mit Fallback `"unknown"`,
UTC-`timestamp`). Regel: **kein Finding ohne Provenienz ab Phase T
(Triage)** — neu erzeugte Records muessen `provenance` tragen;
Legacy-Bestaende ohne Feld bleiben per serde-default lesbar (`None`,
nicht serialisiert). Helper fuer CLI/MCP-Verdrahtung:
`cate_core::provenance_record()` / `provenance_record_for(..)`.

## 8. Scope-Export (M-3, Stand 2026-10-15)

`cate audit --sarif <file> --diff <base> [--path <dir>] --scope-out <datei>`
schreibt neben dem Stdout-Report den ermittelten Scope als JSON-Export —
reproduzierbarer Lauf-Beleg (welcher Stand wurde geprueft?).

Schema (`--scope-out`, Erfolgsfall):

```json
{
  "tool": "cate",
  "version": "0.1.0",
  "command": "audit",
  "base": "abc123",
  "range": "abc123..HEAD",
  "changed_files": [{ "status": "M", "path": "src/x.rs" }],
  "inventory": { "lockfiles": ["Cargo.lock"], "has_cargo_lock": true, "has_package_lock": false },
  "timestamp": "2026-10-15T12:00:00Z",
  "provenance": { "tool_name": "cate", "tool_version": "0.1.0", "model": "audit", "commit_sha": "…", "timestamp": "…" }
}
```

Regeln:
- `base` ist der Base-Teil von `--diff` (Range-Form `base..HEAD` erlaubt);
  `range` haelt immer die ausgewertete Form `base..HEAD` fest.
- Ohne git-Repo (oder unbekannte Rev) kein Abbruch: der Export traegt
  `error` statt `changed_files`; Inventar/Timestamp/Provenienz stehen trotzdem.
- Der Stdout-Report bleibt unveraendert (kein Format-Bruch); der Export ist
  bis auf `timestamp` byte-stabil ueber Wiederholungslaeufe (Test
  `audit_scope_out_schreibt_export_mit_beleg`).
- Quelllage: Scope aus `cate_core::scope::changed_files_since`, Inventar aus
  `cate_core::scope::inventory`, Zeit via `cate_core::utc_now_rfc3339`,
  Provenienz via `ProvenanceRecord::current_with_model("audit")` (M-4).

## 9. Runde 6/7 — Gates, total_e2_plus-Regel, Registry-OfflineDB (Stand 2026-10-17)

Alle Zahlen per ausgefuehrtem Befehl belegt (Befehle s. TESTING.md §0/§4.4):
`cargo test --workspace` = **402 passed / 0 failed** (39 Test-Targets);
`cargo test --manifest-path src-tauri/Cargo.toml` = **20 passed / 0 failed** (separat,
`src-tauri` steht in Workspace-`exclude`);
`cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --check` gruen.

### 9.1 Gates (hart, Release-blockierend)

1. **Suppression-Rate > 1 % → FAILED**, unabhaengig von FP-Reduktion (§1.3):
   `python harness/harness.py --corpus corpus/manifest.json` liefert aktuell
   `deny_closed: []` (8 Korpus-Faelle, kein Deny-Fall geschlossen).
2. **Deny-Vorrang hart codiert, getestet**: `Deny-Policy > E2-Cap > Modell-Verdict > Heuristik`
   (`deny_list_blocks_close_on_all_deny_cwes`, alle 17 Deny-CWEs;
   E2-Cap-Matrix `crates/cate-triage/tests/e2cap_cache.rs`).
3. **Coverage-Gate offline-faehig** (`ci/coverage_gate.ps1`/`.sh`, TESTING.md §4.4):
   Pfad A (tarpaulin, `--fail-under 70`) wo verfuegbar, sonst Pfad B
   (Testzahl-Gate je Crate, Summe 402, 0 failed Pflicht).
4. **S-3 Suppress-Gate** (Begruendung + Reviewer + 30-Tage-Ablauf; Deny-Suppress blockiert):
   20 src-tauri-Tests gruen (u.a. `abgelaufene_approval_blockt_apply_mit_expired`,
   `deny_cwe_kann_nie_suppressen`).

### 9.2 total_e2_plus-Regel (nur E2+ zaehlt als Bug)

- Zaehlung echt, kein Stub: `let total_e2_plus: usize = by_level.values().sum()`
  (`crates/cate-core/src/lib.rs:857`, Feld `:787`); E1/E0 fliessen nie ein
  (Test `audit_unlocated_nicht_im_score`, `health.total_e2_plus == 0` bei reinen E1-Funden).
- Negativ-Abgrenzung MCP: `get_graph` liefert bewusst **kein** `total_e2_plus` —
  cate-graph hat keine Evidence-Daten, ein Hardcode-0 waere ein Fake-Wert
  (`crates/cate-mcp/src/lib.rs:319`, gestrichen 2026-10-15, Spec `docs/MCP_TOOLS.md` §4).
- Health-Farben/Verhalten nach Regel (PLAN.md §1): E0 grau eingeklappt, E3 rot oben, E4 gruen.

### 9.3 Registry-OfflineDB (M1.5) inkl. Stub-Restbestand

- Echte Pruefung ohne Netz: Format `cate-registry-db` v1 (`REGISTRY_DB_FORMAT/VERSION`,
  `crates/cate-deps/src/lib.rs`), `--registry-db`-Flag, `deps_summary` im Scan-Report,
  Typosquat-Kopplung gegen DB-Namen (1-Zeichen-Distanz).
- Semantik mit DB: Treffer fuellt exists/age/downloads/advisory;
  **Miss = nicht-existent + verdaechtig** (`offline_db_miss_means_not_exists_and_suspicious`).
  Ohne DB erzeugt die CLI gar keine Checks mehr (keine fiktiven „safe“-Werte).
- Stub-Restbestand: `registry_check_stub` ist als **deprecated** markiert
  (`since = "0.1.0"`, Verweis auf `registry_check`/`registry_check_offline` mit `OfflineDb`);
  der DB-lose Pfad (`exists: true`, Alter/Downloads None) ist nur noch darueber erreichbar.
  Alle Tests laufen auf der OfflineDb-API: 13 deps-Tests
  (5 lib inkl. `offline_db_hit_fills_fields`, 8 `tests/registry_check.rs`-Fixtures).
- Beleg-Befehle: `cargo test -p cate-deps` (13/0), `cargo clippy -p cate-deps --all-targets -- -D warnings` (gruen, keine Deprecated-Warnung im Tree).
