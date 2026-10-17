# CateHunt Icons & Maskottchen (Sprint 3)

## Sprite: 16×16-Pixel-Katzenkopf (eigene Neuzeichnung)

- **Nicht** aus `E:/HermesHarness` kopiert; neu im 16×16-Raster gezeichnet:
  Ohren (außen Umriss + rosa Innenohr), Augen (2×2 px Jagd-Grün mit Pupille),
  Nase (2×3 px Beerenrot), Wangen (je 2 px Rosa).
- **Akzentfarbe:** Jagd-Grün `#3fa46a` (Augen; auch Schwanz des Health-Begleiters).
- **Palette:** Umriss `#232329` · Fell `#f5f0e4` · Innenohr `#e8a0a0` ·
  Augen `#3fa46a` · Pupillen `#0e2a1c` · Nase `#c04357` · Wangen `#f2b8c0`.
- **Einbettung:** `ui/dist/index.html` (Inline-SVG, `shape-rendering: crispEdges`,
  `image-rendering: pixelated`): CateHuntMark 30 px im Header neben Wortmarke,
  Empty-State-Katze 56 px mit Blinzeln (`cate-blink`, 4,2 s), Health-Begleiter
  26 px (Schwanzwedeln `is-alert` bei E3, Schlaf `is-sleep` bei Health 100).
  `prefers-reduced-motion: reduce` → Standbild (alle Animationen aus).

## Tauri-Icons: aus dem Sprite abgeleitet

- **Generator:** `generate.py` in diesem Verzeichnis (Quelle: `MAP` + `PALETTE` dort).
- **Aufruf:** `python generate.py` (Arbeitsverzeichnis = `src-tauri/icons/`).
  Benötigt Pillow (`pip install pillow`).
- **Ergebnis:**
  - `icon.png` — 256×256 Vollfarb-Kachel dunkel (`#1b1b1f`, abgerundet r=56),
    Sprite 12-fach zentriert (192 px Katze auf 256 px Kachel).
  - `icon.ico` — Multi-Size (16/32/48/256) aus derselben Kachel.
  - `sprite.svg.txt` — Pfad-Fragmente zum Einbetten (kein Build-Schritt nötig).
  - `favicon.txt` — 16×16-`data:`-URI (in `ui/dist/index.html` als Favicon verdrahtet).
- `tauri.conf.json` (`bundle.icon`) unverändert — Dateinamen gleich.
