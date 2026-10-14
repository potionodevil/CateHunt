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
