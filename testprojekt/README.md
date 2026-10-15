# Testprojekt (Offline-E2E fuer Algos, Scoring, Health)

Absichtlich vulnerables Mini-Projekt, das die Triage-Pipeline **ohne Netz,
ohne Modell und ohne CLIs** end-to-end testbar macht. Alle Stufen laufen
deterministisch: Stufe 1 (Clean-Pass), Signal-Heuristik, deterministischer
Fallback, Deny-List-Cap, Health-Score.

## Struktur

- `samples/` — 4 vulnerable Dateien (CWE-89 SQLi, CWE-78 CMDi, CWE-22 Path,
  CWE-94 Code-Injection), 1 Komplexitaets-Fall (`.rs`, Nesting 4 > 3),
  1 saubere Referenz.
- `expected.json` — Erwartungs-Fixture pro Datei (Stufe-1-Weiche, Signale,
  Fallback-Verdict max E2, Deny-Flag) plus globale Health-Erwartung.
- `run.ps1` / `run.sh` — Runner: fuehrt die E2E-Pruefung aus.

## Ausfuehren

```powershell
# aus Repo-Root oder testprojekt/
.\testprojekt\run.ps1
# oder direkt:
cargo test -p cate-stages --test testprojekt_e2e
```

## Was geprueft wird (`crates/cate-stages/tests/testprojekt_e2e.rs`)

1. Stufe 1 (`stage1_scan`): nur `deep_nesting_cwe79.rs` flaggt.
2. Signale (`signals_from_source`): Architektur-Hinweis bei SQLi/CMDi/Code-Inject,
   Komplexitaet nur beim Nesting-Fall.
3. Fallback (`deterministic_triage`): alle Faelle `confirm` (nie `suppress`/Close),
   Evidence nie ueber E2, Deny-Flags wie Fixture.
4. Kette offline (`plan_stages_checked` + `run_chain_with_fallback`): leere Kette
   faellt ohne einen einzigen Netz-/Modell-Call aufs deterministische Ergebnis.
5. Health (`health_score` + `health_grade`): 3 E2+-Findings (3x error),
   Security 55, Note B.

## Bekannte Luecke (offen)

Stufe 1 erkennt Python-Funktionen (`def`) und Einrueckungs-Nesting nicht
(`scan_functions` kennt nur `fn`/`function`, `nesting_depth` zaehlt `{}`).
Alle `.py`-Samples sind daher Stufe-1-clean — die Befunde kommen erst aus
Signal-Heuristik und Fallback. Fix in `cate-core` ausserhalb dieses Testprojekts.
