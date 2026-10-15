<!-- Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
     oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt. -->
# Triage-Backend-Routing (Stufen 1–3)

Welches Modell wann — kurz: **klein/lokal zuerst, gross/headless nur per Opt-in**.

| Stufe | Backend | Wann | Kosten / Latenz | Opt-in |
|---|---|---|---|---|
| 1 | Ollama localhost (`cate-triage::ollama`) | Default + Offline-Modus | keine / ms | nein |
| 2 | Gemini CLI (`cate-triage::gemini`, `gemini --output-format json -p`) | Default, wenn verfuegbar + eingeloggt | User-Quota / Sekunden | implizit via `gemini login` |
| 3 | Deep-Engines (`cate-triage::deep_engines`: `opencode run --format json` / `claude -p --output-format json`) | nur schwere Faelle: Deny-CWE + unsicherer Befund + `--deep` | API-Kosten / 10s bis Minuten | **ja, explizit** |

Regeln fuer alle Stufen: Prompt vorher redigieren (Secrets), `evidence_proposed`
nie hoeher als E2, Deny-List-Check vor suppress, Cache-Lookup zuerst.
Jeder Backend-Fehler (CLI fehlt / nicht eingeloggt / Timeout) endet mit
Ollama-Fallback-Hinweis. Stufe 3 loggt zusaetzlich den Kosten-/Latenz-Hinweis
(`COST_LATENCY_NOTE`). Kein Commit/Push durch Engines (read-only Triage).

## S-2 Pinning-Nachweis (Adapter-Versionen fest gepinnt)

Jeder Adapter wird auf Model-Version, Probe-/Discovery-Endpoint und
Prompt-Version fest gepinnt. Die Pin-Tabelle lebt im Code
(`crates/cate-triage/src/pins.rs`, Konstante `ADAPTER_PINS`) und ist
Teil des Nachweises — eine Aenderung ist ein bewusster Pin-Sprung mit
Dokupflicht (hier + `CHECK_LAYERING.md`):

| Stufe | Adapter | Modell-Pin | Probe-/Discovery-Pin | Prompt-Pin |
|---|---|---|---|---|
| 1 | `cate-triage::ollama` | `qwen2.5-coder:7b` (`DEFAULT_MODEL`, Request-Body `model`-Feld; Discovery via `/api/tags` wird bewusst NICHT benutzt) | `http://127.0.0.1:11434` + `POST /api/generate`; Probe = TCP-Loopback-Connect (500 ms), nur localhost/127.0.0.1/::1, kein Modell-Call (`probe_ollama_reachable`) | `v1` (`PROMPT_VERSION`, im Verdict persistiert) |
| 2 | `cate-triage::gemini` | keine Modell-Entity gepinnt (User-Config), gepinnt ist das Args-Schema | CLI-Pin `gemini` (`DEFAULT_CLI`) + Args-Schema `--output-format json -p <prompt>` (`build_args`); Probe = `<cli> --version`, Exit 0, kein Login/Netz (`probe_cli_present`) | `v1` |
| 3a | `cate-triage::deep_engines` (opencode) | dito (Args-Schema) | CLI-Pin `opencode` + `run --format json <prompt>`; Probe wie Stufe 2 | `v1` |
| 3b | `cate-triage::deep_engines` (claude) | dito (Args-Schema) | CLI-Pin `claude` + `-p --output-format json <prompt>`; Probe wie Stufe 2 | `v1` |
| Fallback | `deterministic_triage` | `deterministic-fallback-v1` (Modell-Label im Record) | kein Transport, kein Netz, kein Subprozess | `v1` (teilt den Ollama-Prompt-Bauer) |

Pflichten des Pins, maschinen-geprueft (`pins::tests`, gespiegelt in
`docs/TESTING.md`-Konvention):

- **Modell-Pin:** Nur das gepinnte Modell darf an Stufe 1 gehen
  (`model_pin_ok`); jede Abweichung ist Konfig-Fehler, kein stiller
  Modell-Wechsel. CLI-Backends pinnen statt eines Modells das
  Argument-Schema (Discovery unverwechselbar pro CLI).
- **Probe-Pins:** Verfuegbarkeit kommt ausschliesslich aus den
  gepinnten Proben (TCP-Loopback bzw. `--version`-Spawn). Kein Netz-
  Call ausser Loopback; der Login-Status bleibt bewusst ungeprueft
  (`NotLoggedIn` faellt zur Laufzeit automatisch zur naechsten Stufe).
- **Prompt-Pins:** Prompt-Version steuert die Cache-Invalidierung;
  ein Pin-Sprung trifft den Cache zum Miss, nie zum stillen Hit
  (Format-Version geprueft, Legacy-Fingerprints sind nie ein Hit).
- **Offline-Verifikation:** `verifiziere_pins_offline` prueft ohne Netz:
  kanonische Stufen-Reihenfolge der Tabelle, keine `(Adapter, Art)`-Duplikate,
  keine leeren Pin-Werte, Ollama-Endpoint verletzt den Loopback-Zwang nicht
  (`check_base_url`), CLI-Pins == Default-Konfigs. Die Tests rufen keine
  externen Endpunkte (Tiny-Offline-Stub-Stil wie die bestehenden
  `proben_sind_offline_sicher`-Tests: Remote-Hosts/unbekannte CLIs
  brechen nie etwas, sieverifizieren die Abweisung).

## S-5 Contested (widerspruechliche Severities deterministisch aufloesen)

Treffen zwei Adapter auf denselben Finding (gleicher Sink/Fingerprint)
mit gegensaetzlichen Verdicts/Severities, loest
`crate::pipeline::merge_contested` deterministisch auf — **nie still
mittelnd** (Korrelations-Regel `CHECK_LAYERING.md`):

- **Rang-Modell:** `escalate` > `confirm` > `suppress`; der hoechste
  Verdict gewinnt. Bei Rang-Gleichstand entscheidet die hoehere Severity
  (`critical` > `high`/`error` > `medium`/`warning` > `low` >
  `info`/unbekannt); bleibt auch die gleich, der erste Adapter in der
  Channel-Order. Determinismus: reine Funktion, kein RNG, keine Zeit,
  keine Env.
- **`contested:true`** genau dann, wenn mindestens ein Adapter mit einem
  Verdict niedrigeren Rangs abwich (Audit-Spur: `dissent`-Liste). Drei
  gleiche Verdicts sind kein Widerspruch — `contested` bleibt false.
- **Merge-Protokoll:** Der Gewinner-Verdict + Gewinner-Severity gehen an
  den merge (L3/L4); `contested` + `dissent` erlauben der Korrelations-
  schicht, den Konflikt sichtbar zu machen statt ihn zu verstecken.
- **Tests:** `s5_konflikt_hoeherer_verdict_gewinnt`,
  `s5_zweifach_aufgerufen_identisch` (2x aufrufen, byte-gleiche Ausgabe),
  `s5_tie_break_severity_dann_erster`, `s5_ohne_konflikt_...`,
  `s5_unbekannte_verdict_werte_sind_deterministisch` — alle rein offline.

