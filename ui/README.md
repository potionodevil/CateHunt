# CateHunt UI

Statisches Desktop-Frontend (offline-fähig, keine Netz-Calls). ERP: `R.S. 2026`.

## Dateien

- `dist/index.html` — **kanonische Quelle** der Review-Workbench (Tabs: Review / Editor / Graph / Einstellungen). Es gibt **keinen Build-Schritt** (kein Bundler, kein Transpiler): die Datei wird direkt editiert und ist selbst das `dist`-Artefakt. Fixtures unter `dist/fixtures/*.json` bzw. `fixtures/*.json` spiegeln das Backend-Format (list_findings/health/graph).
- `preview.html` — minimale Phase-3-Vorschau nur für den Review-Tab; lädt `fixtures/findings.json` + `fixtures/health.json`. Wird NICHT vom Tauri-Backend benutzt.
- fixtures: identisch in `ui/fixtures/` (für preview.html) und `ui/dist/fixtures/` (für index.html-Fallback); `dist` hat zusätzlich `graph.json` für den Modulgraph.

## Datenquellen zur Laufzeit

- In Tauri: Tauri-Commands `list_findings` / `health` / `graph`.
- Im Browser (ohne Tauri): Fallback auf `fixtures/*.json`.
- Achtung: `fetch()` auf lokale Dateien braucht einen HTTP-Server — `file://` blockt fetch.

## Lokal anschauen / "Build" (keine Dependencies)

Statischer Server reicht, z.B.:

```bash
cd ui
python -m http.server 8899
# dann im Browser: http://localhost:8899/dist/index.html  (oder /preview.html)
```

"Ausbauen"/Dev-Runde: direkt in `dist/index.html` editieren (UTF-8, deutsche UI-Labels;
`data-act`/`data-ed`-Attribute sind Code-Bezeichner und bleiben Englisch), dann per
Audit-Log-Gegenprobe im Browser testen. Kein Minifizieren nötig — die lesbare Version IST
das Artefakt.

## Suppress / Deny-List (UI-Verhalten)

- Buttons: `Bestätigen` / `Eskalieren` / `Unterdrücken` (deutsche Labels).
- Findings mit `deny: true` (Krypto/Auth/Deserialisierung) bekommen den Suppress-Button
  als `disabled` + Deny-Note; Backend-Logik (verdict_cap → escalate) bleibt im cate-triage-Crate.
