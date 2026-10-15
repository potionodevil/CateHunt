# Tree-sitter-Spike (M1.3, Plan-Risiko 1) — Entscheidungsvorlage

Stand: 2026-10-15 · Branch `main` · Repo `C:/Users/RS990/Desktop/Projekte/CateHunt`
Umsetzung 2026-10-15: ANGENOMMEN (entkoppelt) — Feature `tree-sitter` (default an) in `cate-core`, Heuristik als Fallback (`*_heuristic`), offline baubar.
Bezug: `docs/PLAN.md` §5 Risiko 1 + M1.3; Heuristik in `crates/cate-core/src/lib.rs`
(`scan_functions`, `analyze_file`, `nesting_depth`, `strip_strings_naive`, `guess_function_name`).
**Keine Produktionsumstellung** — reiner Spike, kein Source-Commit.

## 1. Ergebnis in einem Satz

**Empfehlung: ANNEHMEN (bedingt)** — tree-sitter ist baubar, klar überlegen
(42 % der Funktionen entgehen der Heuristik), aber als **Fallback-fähige**
Integration, nicht als harte Pflicht-Dependency.

## 2. Baubarkeit (Offline-Frage)

| Frage | Befund |
|---|---|
| Frisch offline baubar? | **Nein.** `cargo build --offline` scheitert auf leerem Cache (`streaming-iterator` fehlt). `Cargo.lock` enthält kein tree-sitter, Registry-Cache (268 Crates) auch nicht. |
| Online baubar? | **Ja.** Getestet in Scratch-Projekt (außerhalb Repo): `tree-sitter 0.27.1` + `tree-sitter-rust 0.24.2` + `tree-sitter-python 0.25.0`, `cargo build` grün in ~16 s (27 Pakete). |
| Offline nach einmaligem Cachen? | **Ja.** `cargo build --offline` nach dem Erst-Build grün (1,5 s inkrementell). Für CI/Release: einmal `cargo fetch` bzw. `vendor/` einchecken, danach offline-fähig. |
| Zusatz-Toolchain | **C-Compiler nötig** (`cc 1.8.0` kompiliert die Grammatik-C-Quellen; lief hier out-of-the-box). MSRV/Rust-Version unkritisch (1.97.1 getestet), aber Windows-/Linux-CI brauchen eine C-Toolchain im Image. |
| Kosten | Registry-Quellen ~11,6 MB (`tree-sitter` 1,3 MB, `-rust` 6,7 MB, `-python` 3,6 MB); Debug-`target/` des Spike ~126 MB (Artefakt, nicht Release-Größe); Laufzeit Spike-Binär: **0,245 s für 5 Dateien / ~2.300 Zeilen**. |

Fazit: Das „Offline-Setup" ist **einmalig online zu seeden**, danach offline stabil.
Wer strikt ohne Netz auskommen muss, braucht `vendor/` oder gespiegelte Registry.

## 3. Metrik-Vergleich: Heuristik vs. tree-sitter (5 echte Repo-Dateien)

Methode: Scratch-Binär (nicht im Repo) ruft pro Datei `cate_core::analyze_file`
(Heuristik) und tree-sitter-Parsing (`function_item`/`function_definition`,
Nesting = Kontrollfluss-Knoten) auf. Parse-Fehlerknoten: überall **0**.

| Datei (Zeilen) | Funktionen Heuristik | Funktionen tree-sitter | Verpasst (FN) | Nesting Heuristik | Nesting tree-sitter |
|---|---|---|---|---|---|
| `cate-core/src/lib.rs` (569) | 16 | **36** | **20** | 8 | 12 |
| `cate-cli/src/main.rs` (1164) | 30 | 30 | 0 Anzahl, **aber 2 trunkiert** (s. u.) | 6 | 11 |
| `cate-triage/src/lib.rs` (371) | 10 | **22** | **12** | 4 | 5 |
| `harness/harness.py` (173) | 0 | **7** | **7 (100 %)** | 1 (sinnlos) | 7 |
| `corpus/cwe-328/01_vuln.py` (6) | 0 | **1** | **1** | 0 | 1 |
| **Summe** | **56** | **96** | **40 FN ≈ 42 %** | — | — |

### Wo die Heuristik lügt (belegte Beispiele)

1. **`pub fn` ist unsichtbar (größte FN-Quelle).** `guess_function_name`
   matcht nur Zeilen, die nach Trim mit `fn ` beginnen. Ergebnis:
   `lib.rs` 20/36, `triage/lib.rs` 12/22 Funktionen fehlen — darunter
   `pub fn analyze_file`, `pub fn scan_functions`, `pub fn health_score`,
   `pub fn normalize_cwe`, `pub fn apply_policy`, `pub fn fingerprint`.
   Der Health-Score bestraft damit systematisch zu wenig (Funktionslängen-
   Penalty greift für `pub fn` nie).
2. **Raw-Strings sprengen die Klammerbilanz (falsche `end_line`).**
   `strip_strings_naive` kennt nur `"..."`, nicht `r#"..."#`, keine
   Char-Literale (`'{'`/`'}'`), keine `/* */`-Kommentare. Belegt in
   `cate-cli/src/main.rs`: `audit_unlocated_nicht_im_score` endet laut
   Heuristik Zeile 1041, real 1066; `audit_deny_policy_demote_nur_deny_cwe`
   endet laut Heuristik 1068, real 1095 — Ursache sind JSON-Blöcke in
   `r#"..."#`-Strings (Z. 1042–1047, 1071–1080). Folge: falsche
   Funktionslängen + falsche Tiefen pro Funktion.
3. **FP-Muster Char-Literale.** Z. B. `crates/cate-triage/src/ollama.rs:191f`
   (`s.find('{')`, `s.rfind('}')`): `'{'`/`'}'` werden als echte Klammern
   gezählt. Hier zufällig balanciert, bei einseitigem Vorkommen verschiebt
   es die Tiefe dauerhaft.
4. **Python = Totalausfall.** Kein `def`-Support (0 von 8 Funktionen),
   Nesting über `{}` in Python ist bedeutungslos (PLAN-Nachtrag nennt das
   bereits als offen). `harness.py` (173 Zeilen, TS-Nesting 7) meldet
   Heuristik-Nesting 1.
5. **Nesting misst das Falsche.** Die Heuristik zählt *alle* `{}` —
   inkl. `struct`/`enum`/`impl`/`mod`-Rümpfe und Makro-Braces — also kein
   Kontrollfluss-Maß. `lib.rs`: Heuristik 8 vs. Kontrollfluss 12.
   Schwellen im `health_score` (`> 4`) sind damit auf Sand gebaut.

Keine Heuristik-FP bei Funktions*namen* gefunden (nur „NUR tree-sitter"-Diffs,
nie umgekehrt) — das Problem ist einseitig: **massive FNs, keine FPs**.

## 4. Empfehlung

**Tree-sitter übernehmen, aber entkoppelt:**

- Neues Modul (z. B. `cate-core/src/metrics_ts.rs` oder eigenes
  `cate-metrics`-Crate), Feature-Flag/gated: tree-sitter primär,
  **Heuristik bleibt als Fallback** (kein C-Compiler / kein Grammatik-Update
  → alter Pfad, ggf. mit Warnung im Report).
- Scope vorerst: `tree-sitter-rust` + `tree-sitter-python` (beide hier
  verifiziert, 0 Parse-Fehler). JS/TS-Grammatik (`guess_function_name`
  kennt `function`) erst bei Bedarf.
- `health_score`-Schwellen nach Umstellung **rekalibrieren**
  (Kontrollfluss-Nesting ≠ Brace-Counting; Python bekommt erstmals echte Werte).
- Offline-Strategie: `cargo fetch` im Setup-Skript oder `vendor/`-Verzeichnis,
  dokumentiert in CI-Anleitung.

### Aufwand / Risiko

| | Einschätzung |
|---|---|
| Aufwand | **S–M**: Dep-Einträge + Modul (~200–300 Zeilen) + Tests/Goldens + Schwellwert-Rekalibrierung. |
| Risiko niedrig | Laufzeit vernachlässigbar (0,2 s / 2.300 Zeilen); Grammatiken stabil versioniert. |
| Risiko mittel | **C-Toolchain-Pflicht** im Build (CI-Images prüfen); +27 transitive Pakete im Lockfile; Grammatik-Updates brauchen Pflege (Dependabot o. ä.). |
| Risiko bei Ablehnung | Health-Score bleibt auf 42-%-blinder Basis; Python-Metriken bleiben Dummy-Werte — M1.3-Ziel („Metriken-Aussagekraft für Health-Score") nicht erreichbar. |

### Alternative bei Ablehnung (nur falls C-Toolchain tabu ist)

Heuristik reparieren statt ersetzen: `pub fn`/`pub async fn` matchen,
Raw-Strings/Char-Literale/Blockkommentare strippen, Python per
Dedent-Parser (`def` + Einrückung) ergänzen. Kosten ~1 Tag, behebt die
gröbsten FNs, bleibt aber prinzipiell brüchig (Makros, `cfg`-Blöcke).
Dieser Weg ist nur vertretbar, wenn tree-sitter aus Buildgründen ausscheidet —
technisch ist tree-sitter die saubere Lösung.

## 5. Nächste Schritte (kein Code in diesem Spike)

1. Entscheidung (diese Vorlage) abnehmen.
2. Bei Annahme: M1.3-Ticket — `cate-metrics`-Modul/Feature, Goldens für die
   5 Dateien oben als Regressionsanker, `health_score`-Rekalibrierung,
   `cargo fetch`/`vendor` für Offline-Builds dokumentieren.
3. Bei Ablehnung: Decision-Record mit Begründung (C-Toolchain) + Heuristik-Fix
   (`pub fn`, Raw-Strings, Python-Dedent) als Ersatz-Ticket.

## 6. Reproduzierbarkeit

Spike-Code lag **außerhalb des Repos** (Scratch, nicht committed):
Binär mit `tree-sitter 0.27.1`, `tree-sitter-rust 0.24.2`,
`tree-sitter-python 0.25.0`, `cate-core` per Pfad-Dependency; verglichen wurde
`cate_core::analyze_file` gegen manuelles Tree-Walking (Funktionsknoten +
Kontrollfluss-Nesting). Alle Zahlen oben sind echte Tool-Ausgaben, keine
Schätzungen.
