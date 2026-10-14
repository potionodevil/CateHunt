<!-- Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt. -->
# CateHunt-Desktop: Build-Stand (2026-10-14)

## Dateien
- `src-tauri/Cargo.toml` — eigener Crate `catehunt-review` (NICHT Workspace-Member;
  Root-`Cargo.toml` hat `exclude = ["src-tauri"]`), Deps: `tauri 2`, `serde`,
  `serde_json`, `cate-core` + `cate-triage` via Pfad (kein Server).
- `src-tauri/build.rs` — `tauri_build::build()`.
- `src-tauri/src/main.rs` — Commands `list_findings(path?)`, `health(path?)`;
  Deny-Flag serverseitig via `cate_triage::verdict_cap`, Health via
  `cate_core::health_score` (nur E2+). Fallback: eingebettete `ui/fixtures/*.json`.
- `src-tauri/tauri.conf.json` — `productName: CateHunt`, `frontendDist: ../ui/dist`,
  Bundle `targets: ["nsis"]`, Icons `icons/icon.(ico|png)`.
- `src-tauri/icons/icon.png` + `icon.ico` — Platzhalter (32×32, rot).
- `ui/dist/index.html` — statisches Frontend, kein Node-Build nötig. Ansichten:
  Review (E3-rot-oben/E0-grau, Filter, Deny-Block, Health-Kopf), Editor (Diff
  alt/neu, Übernehmen erst nach 2. Klick = explizite Bestätigung, Ablehnen),
  Graph (Platzhalter, Health-Farben grün>85/gelb 60–85/rot<60), Einstellungen
  (Schalter „Automatische Anpassung“, Default AUS; genehmigte Kategorien;
  Audit-Log in localStorage). Inline-Favicon (kein 404).
- `ui/dist/fixtures/{findings,health}.json` — Kopie der Demo-Daten für
  Browser-Fallback (ohne Tauri-Runtime).

## Verifiziert
- `cargo check --workspace --all-targets` (Root) → grün.
- `cargo check` in `src-tauri/` → grün (tauri 2.12.4, ~5 min Erst-Build).
- `ui/dist/index.html`: JS per `node --check`-Äquivalent (vm.Script) OK,
  `tauri.conf.json` valides JSON.

## Was für den Windows-Installer (.exe, NSIS) noch fehlt
Voraussetzungen (einmalig, mit Netz):
1. Tauri-CLI: `cargo install tauri-cli --locked` (legt `~/.cargo/bin/cargo-tauri` an;
   ggf. `~/.cargo/bin` in PATH).
2. WebView2-Runtime (auf Win10/11 meist vorinstalliert; sonst
   Evergreen-Installer von Microsoft).
3. NSIS 3 (`winget install NSIS.NSIS`) — nur für das `.exe`-Setup nötig.
   Stand 2026-10-14 auf dieser Maschine: NICHT installiert.
4. MSVC-Build-Tools (link.exe) für `cargo build`. Stand 2026-10-14 auf dieser
   Maschine: KEIN MSVC-Linker (nur git-bash-`link.exe`-Namensvetter).

Befehle:
- `cd src-tauri && cargo tauri build` → erzeugt u.a.
  `target/release/bundle/nsis/CateHunt_0.1.0_x64-setup.exe`.
- `cargo tauri dev` → Dev-Start (lädt `ui/dist` statisch, kein `devUrl`-Server nötig).

Offen (bewusst Platzhalter): echte Fix-Anwendung im Backend (`suggest_fix`/
`apply_fix`-Commands), echter Call-Graph (cate-graph läuft als Schwester-Crate,
noch nicht eingebunden), signiertes Icon.
