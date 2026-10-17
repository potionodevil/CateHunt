<!-- Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung -->
<!-- oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt. -->
# CateHunt v2 — Review (Checker)

Stand: 2026-10-14 | Prüfling: `E:/CodeCate` | Perspektive: kritisches Review-Modell (skeptisch)
Ergebnis (Nachtrag): **🟡 GELB — Phase 1 + Triage-Kern steht, Re-Review-Teile offen (s. §1).**
Ursprüngliches Ergebnis zum Prüfzeitpunkt (Race, Workspace leer): 🔴 ROT.

## 1. Ampelstatus

| Bereich | Ampel | Begründung |
|---|---|---|
| Konsistenz Plan vs Code vs Validation | 🔴 | Kein Artefakt vorhanden: kein `docs/PLAN.md`, kein Crate, kein `docs/VALIDATION.md`. Nichts zu vergleichen. |
| Masterplan-Vollständigkeit | 🔴 | Alle 4 Masterplan-Punkte unprüfbar / fehlend (s. §3). |
| Security | 🟡 | Kein Code → keine aktive Lücke, aber auch kein Nachweis für Sandbox/Path-Traversal/Secrets-Handling. Strukturelles Risiko, kein akuter Befund. |
| **Gesamt** | **🟡 GELB** | **M-1 erledigt (Artefakte vorhanden, Build grün). Offen: M-2…M-8 ohne Beleg — Sandbox, MCP-Tools, AI-BOM/Trend, Scope-Export, Secrets-Redaction. Kein MVP-Sign-off vor Belegen.** |

Nachtrag 2026-10-14 (Phase-2-Commit): M-1 ✅ (PLAN.md, 5 Crates inkl. cate-triage, VALIDATION.md vorhanden, `cargo test` grün). M-3 teilweise (Verdict-Cache-Schema + Fingerprint implementiert, JSONL-Persistenz/CLI-Anbindung offen). M-7 teilweise (CLI jailt noch keine Pfade ausserhalb Root — `collect_source_files` folgt Symlinks, kein Canonicalize-Check). Rest offen.

Nachtrag 2026-10-14 (Checker E2E-Repro + Fix): `cargo test` grün (16 Tests: 3 core + 2 deps + 1 sarif + 10 triage), `cate scan` auf `./corpus` (8 Dateien) und `E:/CodeCate` (14 Dateien) ohne Crash, JSON valide, Harness-Demo `PASSED` (suppression_rate 0.0). Bugs B-1 (MUST, Symlink-Escape mit Hang >120s) und B-2 (SHOULD, Datei-als-Pfad still 0/exit 0) in `crates/cate-cli/src/main.rs` behoben: Root wird kanonisiert, Datei-als-Pfad → exit 1, Symlinks ausserhalb Root werden geskipt (Warnung), Loop-Schutz via Visited-Set; Repros erneut verifiziert. Offen: M-2/M-4/M-5/M-6 (Sandbox, MCP, AI-BOM, Trend), Secrets-Redaction (kein Leak — Output enthält keine Inhalte — aber keine Redaction-Schicht), Registry-Check weiter Stub.

Re-Review-Trigger: sobald `docs/PLAN.md` + mind. 1 Crate + `docs/VALIDATION.md` existieren.

## 2. Methodik

- Workspace `E:/CodeCate` zweimal gelistet (mit Wartepause für parallele Subagents): leer außer neu erstelltem `docs/`.
- Daher: kein Plan-Code-Vergleich möglich; Review prüft gegen die in der Checker-Beauftragung genannten Soll-Punkte (Masterplan-Checkliste, Evidence Gate / Proof over Prose, local-first Ollama, read-only default, Phase 4 Sandbox als Alleinstellungsmerkmal).
- Befunde sind als **erwartete Prüfkriterien mit Fail-vorab-Status** formuliert, damit das Re-Review mechanisch abhakbar ist.

## 3. Befunde

### MUST (blockierend — Re-Review bleibt ROT bis alle erfüllt)

1. **M-1: Keine Artefakte vorhanden (Plan/Code/Validation fehlen komplett).** — `E:/CodeCate` leer. Evidence Gate verletzt: keine Behauptung belegbar. Fix: PLAN.md, Crate(s), VALIDATION.md liefern, dann Re-Review.
2. **M-2: MCP-Tools `verify_fix` / `check_dependencies` nicht nachweisbar.** — Soll: Tools existieren, sind im Plan spezifiziert und per Validation-Beleg (Tool-Output, nicht Prosa) bewiesen. Aktuell: weder Spezifikation noch Implementierung noch Beleg.
3. **M-3: Scope-Bestätigung / Export nicht nachweisbar.** — Soll: expliziter Scope-Confirm-Schritt + Export-Format (Beleg: Beispiel-Export + Schema/Fixture). Aktuell: fehlt. Risiko: Scope-Creep, nicht reproduzierbare Läufe (Proof-over-Prose-Verstoß).
4. **M-4: AI-BOM / Commit-Metadaten nicht nachweisbar.** — Soll: jedes Ergebnis trägt Modell-, Prompt-/Tool-Version, Commit-SHA, Timestamp (Beleg: Beispiel-Record). Aktuell: fehlt. Ohne das ist kein Finding auditierbar.
5. **M-5: Trendansicht Agent/Modell nicht nachweisbar.** — Soll: Auswertung pro Agent/Modell über Zeit (Beleg: Beispiel-View/Query + Fixture-Daten). Aktuell: fehlt.
6. **M-6: Phase-4-Sandbox ohne Sicherheitsnachweis.** — Alleinstellungsmerkmal, daher höchstes Risiko: kein Sandbox-Design (Isolation, Resource-Limits, Timeout/Kill, kein Netz/Filesystem-Escape), kein Negativ-Test. Beleg Pflicht: Sandbox-Escape-Versuch schlägt fehl + dokumentierter Threat-Model-Abschnitt. Aktuell: offen.
7. **M-7: Path-Traversal ungeprüft.** — Soll: alle Datei-/Pfad-Eingaben (Scope, Export-Pfad, Artefakt-Upload) kanonisiert + gejailt, Tests mit `../`-Payloads. Aktuell: kein Code, keine Tests.
8. **M-8: Secrets-Handling unspezifiziert.** — Soll: keine Secrets in Logs/Exports/AI-BOM, Redaction-Regeln, local-first Ollama ohne Exfil (kein Cloud-Fallback mit Befunddaten). Aktuell: kein Nachweis; Default muss dokumentiert `read-only` + `local-only` sein.

### SHOULD (sollte vor MVP-Sign-off drin sein)

9. **S-1: Evidence Gate operationalisieren.** — Jedes Finding braucht Status (bewiesen/ungesichert/False Positive) + Repro-Schritte + Tool-Rohoutput. Im Review: Stichprobe von ≥5 Findings auf Belegkette prüfen.
10. **S-2: Scanner-Orchestrierung vs. Nachbau abgrenzen.** — Prüfen, dass Scanner nur orchestriert (Adapter-Pattern, Version-Pinning, Checksummen) und nicht nachgebaut werden. Re-Review: Adapter-Liste + Pinning-Nachweis.
11. **S-3: „Niemals automatisch unterdrücken" enforcebar machen.** — Suppress braucht Begründung + Reviewer + Ablaufdatum; Default: sichtbar. Test: Suppress-ohne-Begründung wird abgelehnt.
12. **S-4: Konkurrenzabgrenzung belegen (Datadog, HackerOne, sast-triage).** — PLAN.md sollte für jede Konkurrenz 1 differenzierenden, testbaren Claim enthalten, sonst Marketing-Prosa.
13. **S-5: Fehler- und Timeout-Verhalten der Scanner-Adapter definieren.** — Timeouts, Teilausfälle, widersprüchliche Befunde: deterministisches Verhalten + Tests.

### Checker-E2E-Befunde 2026-10-14 (mit Repro, Status: behoben bzw. offen)

- **B-1 (MUST, BEHOBEN): Symlink-Escape aus Scan-Root + Hang (DoS).** — `collect_source_files` folgte Symlinks blind; Scan eines Dir-Symlinks auf `C:/Windows` hing >120s (Timeout). Repro: `python -c "import os; os.symlink('C:/Windows','target/evil_win',target_is_directory=True)" && timeout 60 ./target/debug/cate.exe scan --path ./target/evil_win --format json`. Fix (`crates/cate-cli/src/main.rs`): Root kanonisieren, `symlink_metadata`-Check, Ziele ausserhalb Root skippen (Warnung), Visited-Set gegen Loops. Repro nach Fix: `warn: skip symlink outside root`, exit 0 in <2s, nur In-Root-Dateien.
- **B-2 (SHOULD, BEHOBEN): Datei-als-`--path` meldet still Erfolg.** — `cate scan --path ./Cargo.toml --format json` gab `files_scanned: 0`, exit 0 zurück (irreführend). Repro: s. Befehl. Fix: `run_scan` verlangt Verzeichnis (`path is not a directory`, exit 1). Repro nach Fix: exit 1 mit Fehlermeldung.
- **B-3 (SHOULD, OFFEN): Keine Secrets-Redaction-Schicht.** — Aktuell kein Leak (Output enthält nur Metriken/Pfade, keine Inhalte — verifiziert mit `api_key = "AKIA..."`-Probendatei), aber auch keine Redaction-Regeln an Pfaden/Logs; M-8 bleibt offen. Ausser Scope für diesen Fix (kein Gross-Feature).
- **B-4 (SHOULD, OFFEN): Registry-Check ist Stub** (`exists` ohne Netzprüfung), Tree-sitter-Metriken sind Heuristiken — dokumentiert, keine Änderung (keine Gross-Features).

### NICE (nach MVP)

14. **N-1: Review-Checkliste als CI-Gate.** — Diese REVIEW.md-Kriterien als automatisierte Checks (Schema-Validierung Export/AI-BOM, Secret-Scan, `../`-Fuzz).
15. **N-2: Beispiel-Dashboard für Trendansicht.** — Minimaler Sparkline-/Tabellen-Export pro Modell.

## 4. Security-Fokus (vertieft, trotz leerem Stand)

| Vektor | Soll-Maßnahme (prüfen im Re-Review) |
|---|---|
| Sandbox-Escape (Phase 4) | Container/nsjail-ähnliche Isolation, keine Host-Mounts, seccomp/Allowlist, CPU/RAM/Timeout-Limits, Egress-deny; Negativ-Tests einfordern |
| Path-Traversal | Kanonisieren + Jail auf Workspace-Root, Symlink-Auflösung, Deny absoluter Pfade außerhalb Root; `../`-Testvektoren |
| Secrets | Redaction vor Persistenz/Export/LLM-Prompt, Secret-Scan in CI, keine Tokens in AI-BOM/Logs; Ollama-local-only ohne Telemetrie mit Befunddaten |
| Supply Chain | Scanner-Versionen pinnen + Hashes, `cargo audit`-äquivalent, keine ungeprüften Remote-Skripte |
| Read-only default | Schreibende Aktionen nur nach expliziter Scope-Bestätigung; Audit-Log aller Writes |

## 5. Re-Review-Anleitung (an Parent)

1. Artefakte landen lassen, dann Checker erneut mit exakt diesem Auftrag aufrufen.
2. Erwartete Pfade: `docs/PLAN.md`, `docs/VALIDATION.md`, `crates/*` (oder äquivalent), dieses `docs/REVIEW.md`.
3. Re-Review prüft M-1…M-8 mechanisch ab; jeder MUST braucht Dateipfad + Zeilen-/Test-Beleg, keine Prosa-Akzeptanz.

## 6. Top-5-Befunde (Kurzfassung)

1. Workspace leer → Gesamtstatus ROT, kein Sign-off möglich (M-1).
2. Alle 4 Masterplan-Punkte (`verify_fix`/`check_dependencies`, Scope-Export, AI-BOM, Trendansicht) fehlen (M-2…M-5).
3. Phase-4-Sandbox als Alleinstellungsmerkmal ohne jeden Sicherheitsnachweis — höchstes Risiko (M-6).
4. Path-Traversal + Secrets ohne Spezifikation/Tests — klassische Einfallstore (M-7, M-8).
5. Evidence-Gate-/Proof-over-Prose-Konformität derzeit unbelegbar — Re-Review mit Belegpflicht nötig (S-1, §5).

## 7. Nachtrag Runde 6/7 (2026-10-17, Doku-Sync)

Geprueft per ausgefuehrtem Befehl (s. TESTING.md §0/§4.4, VALIDATION.md §9):
`cargo test --workspace` = **402 passed / 0 failed** (39 Test-Targets),
`cargo test --manifest-path src-tauri/Cargo.toml` = **20/0**,
`cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --check` gruen.

### Ampel: 🟡 GELB (kurz vor gruen)

| Bereich | Ampel | Begründung (mit Beleg) |
|---|---|---|
| Build + Workspace-Tests | 🟢 | 402/0, 39 Targets; 9 Member, 2 Binaries, src-tauri separat 20/0 |
| Deny/E2-Cap/Suppress-Gates | 🟢 | 17-CWE-Negativtest, E2-Cap-Matrix, S-3-Gate-Tests, Korpus `deny_closed: []` |
| Registry-Check (M1.5) | 🟢 | Offline-DB v1 real, Stub deprecated, Tests auf OfflineDb (13/0) |
| total_e2_plus / Health | 🟢 | echte E2+-Zaehlung (`lib.rs:857`); MCP-`get_graph` ohne Fake-0 |
| Sandbox (M-6) | 🟡 | S1+S2+S4 + Profile/N1–N4 da (23 Tests); **S3-Erstlauf in CI offen** |
| Scope/Health-Feinschliff | 🟡 | M-3 Confirm-Schritt fehlt weiter; Health-Schwellen-Rekalibrierung gesamt offen |
| Hygiene | 🟡 | Workspace-Clippy gruen, aber **`src-tauri`-Clippy ROT (pre-existing)**: `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` meldet 10 Fehler (ungenutzte Methoden + Doc-Listen-Einrueckung); von diesem Doku-Sync unberuehrt, Fix ausstehend |
| Fuzz | 🔴 | weiter kein `fuzz/`-Target, keine proptest-Dep (P1 offen) |
| **Gesamt** | **🟡 GELB** | **Kein MVP-Sign-off vor: src-tauri-Clippy-Fix, Fuzz-Target, S3-Erstlauf in CI.** |

### Geschlossen seit Runde 6 (Auszug, je mit Test-Beleg)

M-1 ✅ (Artefakte + Build gruen), M-2 ✅ (`check_dependencies` live, `verify_fix` Sandbox-gated),
M-4 ✅ (Provenienz verdrahtet), M-5 ✅ (`trend.py`), M-7 ✅ (Jails + Rev-Validierung),
M-8 ✅ (`redact.rs` + Tests), S-2 ✅ (Adapter-Pinning), S-5 ✅ (contested),
L3/L4 ✅ (Reachability/Chaining, 78 Graph-Tests), P0/P1-Testluecken ✅ (Deny-Negativ, Approval-E2E,
Golden, Cache-Hit/Miss, Korpus-8, Rollback — s. TESTING.md §5).

### Offene Punkte (Rest, priorisiert)

1. `src-tauri`-Clippy rot (10 Fehler, s. Ampel) — Fix ausstehend, kein Doku-Thema.
2. Fuzz-Targets (`path_jail`, `redact`, `diff-parser`) + CI-Kurzmodus.
3. S3-Erstlauf in CI (echter Container-Run); Health-Schwellen-Rekalibrierung gesamt.
4. M-3 Confirm-Schritt (explizit), Budget-Guard/Kosten-Cap-Test, Flaky-Quarantaene-Prozess.
