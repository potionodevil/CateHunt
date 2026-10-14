# CateHunt v2

Evidence Gate für KI-generierten Code — lokales Desktop-Tool, local-first (Ollama Standard, Gemini opt-in).

- Nur E2+ zählt als Bug im Health-Score (E0 Hypothese grau eingeklappt → E1 statisch gelb → E2 Datenfluss orange → E3 reproduziert rot oben → E4 Fix verifiziert grün).
- Pipeline: Scope/Inventar → Tree-sitter-Metriken → SARIF-Import (Semgrep/CodeQL) → agentische Triage (read-only, Verdict-Cache, Deny-List) → Tauri-Review → Sandbox-Validierung.

## Docs

- [docs/PLAN.md](docs/PLAN.md) — Architektur, Phasen 1–3 MVP-Schnitt, Akzeptanzkriterien, Risiken.

## Status

Planung (kein Code, kein git). Roadmap: Phase 1 Rust-Core + SARIF + Paketprüfung (CLI mit JSON) → Phase 2 Triage + Cache + Benchmark → Phase 3 Tauri-UI → Phase 4 Sandbox → Phase 5 MCP → Phase 6 Ausbau.
