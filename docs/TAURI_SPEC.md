# Tauri-UI Phase 3: Spec + Vorschau-Status (Stand 2026-10-14)

> Entscheidung: **kein Voll-Setup** (kein `cargo add tauri`, kein npm-Frontend-Build).
> Grund: offline-Umgebung, Tauri-Abhängigkeiten nicht verifizierbar; stattdessen
> **statische HTML-Vorschau** (`ui/preview.html`) + diese Spec als Baupfad.
> Sobald Netz + `cargo`/`npm` verfügbar: Schritt 1–4 unten ausführen.

## Was läuft (verifiziert)

- `ui/preview.html` im Browser öffnen (Doppelklick oder `python -m http.server` in `ui/`
  wegen `fetch()` auf `fixtures/*.json` bei `file://`-Sperre) → Review-Liste aus
  `ui/fixtures/findings.json`, Health-Anzeige aus `ui/fixtures/health.json`.
- Sortierung: E3 (rot) oben, dann E2, E1, E4 (grün), E0 (grau, eingeklappt).
- Suppress-Button bei `deny=true` deaktiviert + Begründung; Health = nur E2+
  (`total_e2_plus: 5`, Score 72).
- Fixtures: 10 Befunde (E3×2, E2×2, E1×3, E4×1, E0×2), Deny-Fälle F-001..F-003.

## Baupfad zum Voll-Setup (wenn Netz verfügbar)

1. `cargo add tauri --features api-all` in `src-tauri/` (eigener Crate, **nicht**
   Workspace-Member) + `npm create vite ui -- --template vanilla` ersetzen der
   Vorschau durch echten Build; `frontendDist: ../ui/dist`.
2. Commands in `src-tauri/src/main.rs`: `load_findings(path) -> Vec<Finding>`
   (liest `findings.json`), `load_health(path) -> HealthScore`, `submit_verdict`
   (ruft `cate-triage::store_verdict` — Deny-Check serverseitig, UI-Button ist
   nur Kosmetik).
3. Frontend: `preview.html`-Logik nach `ui/src/Review.*` portieren; Farben und
   Sortierung (`ORDER`-Map) übernehmen; DOM-Test: erstes Element `.E3`,
   Deny-Suppress-Button `disabled`.
4. Akzeptanz (PLAN.md §4): App startet ohne Netz, lädt findings.json,
   Suppress bei Deny deaktiviert, Health stimmt mit health.json überein.

## Dateiliste

- `ui/preview.html` — Vorschau (läuft)
- `ui/fixtures/findings.json`, `ui/fixtures/health.json` — Demo-Daten (laufen)
- `src-tauri/tauri.conf.json` — Fenster-/Dist-Konfig (Spec, ungetestet)
- Diese Datei — Spec (Doku)
