# CateHunt v2 — Evidence Gate für KI-generierten Code

> © 2026 R.S. — Geistiges Eigentum von R.S. Kopieren, Vervielfältigung oder Veränderung ohne ausdrückliche Genehmigung nicht erlaubt.

Lokales Desktop-Tool, local-first: prüft KI-generierten Code mit Evidence-Leveln statt Bauchgefühl. Standard offline (Ollama), Gemini nur als explizites Opt-in.

## Wie es funktioniert

Jeder Befund bekommt ein Evidence-Level — nur Belegtes zählt:

| Level | Bedeutung | Farbe | Verhalten |
|---|---|---|---|
| E0 | Hypothese | grau | eingeklappt |
| E1 | statisch gefunden | gelb | aufgeführt |
| E2 | Datenfluss belegt | orange | zählt als Bug |
| E3 | reproduziert (Test/PoC) | rot | oben angepinnt |
| E4 | Fix verifiziert | grün | geschlossen |

Pipeline: Scope/Inventar → Metriken → SARIF-Import (Semgrep/CodeQL) → Triage mit Verdict-Cache und Deny-List → Review-Workbench → Sandbox-Validierung.

Sicherheitsgarantie: Krypto-, Auth- und Deserialisierungs-Befunde werden **nie** automatisch unterdrückt (Deny-List), Triage darf maximal E2 vorschlagen — E3/E4 nur per Test/Fix-Verifikation.

## Schnellstart

```sh
cargo build --workspace
cargo test --workspace
# Scannen (JSON-Report):
cargo run -p cate-cli -- scan --path ./corpus/cwe-328 --format json
# Triage (Verdict cachen, 2. Aufruf = Cache-Hit):
cargo run -p cate-cli -- triage --cache /tmp/v.json --fingerprint fp1 --cwe CWE-328 --action suppress
# Benchmark-Gate:
python harness/harness.py --corpus
```

## Projektstruktur

```text
crates/cate-core     Metriken, Evidence-Modell, Health-Score, Secrets-Redaction
crates/cate-cli      CLI: scan + triage (JSON-Output)
crates/cate-sarif    SARIF-Minimal-Import → E1-Findings
crates/cate-deps     Lockfile-Parser, Typosquat-Heuristik
crates/cate-triage   Deny-List, Policy, Verdict-Cache (JSONL)
harness/             Benchmark-Harness + CI-Gate (Suppression >1% = FAILED)
corpus/              5 Faelle (CWE-328/798/502 Deny, CWE-89/79 Guardrail)
docs/                PLAN.md · REVIEW.md · VALIDATION.md · MCP_TOOLS.md · SANDBOX_DESIGN.md
```

## Docs

- [docs/PLAN.md](docs/PLAN.md) — Architektur, Phasen 1–6, Akzeptanzkriterien
- [docs/VALIDATION.md](docs/VALIDATION.md) — Deny-Regeln, Kennzahlen, CI-Gate
- [docs/REVIEW.md](docs/REVIEW.md) — Review-Befunde
- [docs/MCP_TOOLS.md](docs/MCP_TOOLS.md) — verify_fix + check_dependencies (Spec)
- [docs/SANDBOX_DESIGN.md](docs/SANDBOX_DESIGN.md) — Sandbox Threat Model (Design)

## Status

Stand: Pakete A–E fertig, 33 Tests grün, Clippy sauber. Offen: Health-Score E2+-Zählung, Ollama-Client, git-diff-Scope, Tree-sitter-Metriken, Tauri-UI (Phase 3), Sandbox-Ausführung (Phase 4), MCP (Phase 5).

## Lizenz / Urheberrecht

Alle Rechte vorbehalten — © 2026 R.S. Jede Datei trägt einen Urheberrechts-Disclaimer. Kopieren oder Verändern ohne Genehmigung ist nicht erlaubt.
